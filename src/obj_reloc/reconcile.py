"""发布执行日志对账与一致性恢复 API.

离线发布控制器在目标代理重启、重复上报或跨目标切换中断后，调用本模块
重建每个目标已经持久化的发布状态，并为每个一致性组决定下一步动作
（继续前向、提交、回滚或保持不动）。

本模块只分析调用方提供的结构化数据：先调用现有
``build_release_bundle`` 得到本次规范 ``bundle_id`` 与各 target 的完整
forward/rollback manifest，再重放目标代理保存的追加日志。它不连接
设备、不实际写内存、不伪造执行成功，也不提供 CLI。日志只证明已持久化
的执行事实，不得改变 bundle、chunk、manifest 或 bundle_id。

任何输入错误（未知字段、bool 充当整数、重复身份、非法引用、容量超限、
日志链错误或非法状态转换）都按仓库既有约定以 ``ValueError`` 拒绝整份
输入，不返回部分对账结果。
"""
from .checks import array, fields, ident, integer
from .release_bundle import build_release_bundle

_GROUPS_MAX = 32
_GROUP_TARGETS_MAX = 32
_JOURNALS_MAX = 20_000
_JOURNAL_EVENTS_MAX = 4_096
_EVENTS_TOTAL_MAX = 200_000
_ATTEMPT_MAX = 1_000_000_000
_SEQ_MAX = 1_000_000_000
_ADDRESS_LIMIT = 1_100_000

_POLICIES = frozenset(('atomic', 'independent'))
_EVENT_TYPES = frozenset((
    'forward_applied',
    'commit',
    'rollback_applied',
    'rollback_complete',
))
_APPLIED_EVENTS = frozenset(('forward_applied', 'rollback_applied'))

_STATES = (
    'clean',
    'forward_partial',
    'forward_complete',
    'committed',
    'rollback_partial',
)
_DECISIONS = (
    'stable',
    'finish_forward',
    'commit_all',
    'restore_old',
    'independent_recovery',
)


def _parse_groups(raw, target_ids):
    groups = {}
    owners = {}
    for raw_group in array(raw, 1, _GROUPS_MAX):
        fields(raw_group, ('id', 'targets', 'policy'))
        gid = ident(raw_group['id'])
        if gid in groups:
            raise ValueError('duplicate group id')
        policy = raw_group['policy']
        if policy not in _POLICIES:
            raise ValueError('group policy must be atomic or independent')

        member_ids = []
        for raw_target in array(raw_group['targets'], 1, _GROUP_TARGETS_MAX):
            tid = ident(raw_target)
            if tid not in target_ids:
                raise ValueError('group refers to unknown bundle target')
            if tid in owners:
                raise ValueError('target assigned to multiple groups')
            owners[tid] = gid
            member_ids.append(tid)

        groups[gid] = {
            'id': gid,
            'policy': policy,
            'targets': sorted(member_ids),
        }

    if set(owners) != set(target_ids):
        raise ValueError('every bundle target must belong to exactly one group')
    return groups


def _parse_event(raw_event):
    fields(raw_event, ('seq', 'type', 'unit'))
    seq = integer(raw_event['seq'], 1, _SEQ_MAX)
    event_type = raw_event['type']
    if event_type not in _EVENT_TYPES:
        raise ValueError('unknown journal event type')

    raw_unit = raw_event['unit']
    if event_type in _APPLIED_EVENTS:
        fields(raw_unit, ('base', 'atomic_range'))
        base = integer(raw_unit['base'], 0, _ADDRESS_LIMIT)
        atomic_range = raw_unit['atomic_range']
        if atomic_range is not None:
            atomic_range = ident(atomic_range)
        unit = {'base': base, 'atomic_range': atomic_range}
    elif raw_unit is not None:
        raise ValueError('commit and rollback_complete unit must be null')
    else:
        unit = None

    return {'seq': seq, 'type': event_type, 'unit': unit}


def _parse_journals(raw, target_ids):
    journals = {}
    occurrences = set()
    total_events = 0

    for raw_journal in array(raw, 0, _JOURNALS_MAX):
        fields(raw_journal,
               ('id', 'target', 'bundle_id', 'attempt', 'previous', 'events'))
        jid = ident(raw_journal['id'])
        if jid in journals:
            raise ValueError('duplicate journal id')

        target = ident(raw_journal['target'])
        if target not in target_ids:
            raise ValueError('journal refers to unknown target')
        bundle_id = ident(raw_journal['bundle_id'])
        attempt = integer(raw_journal['attempt'], 1, _ATTEMPT_MAX)

        occurrence = (target, bundle_id, attempt)
        if occurrence in occurrences:
            raise ValueError('duplicate journal attempt identity')
        occurrences.add(occurrence)

        previous = raw_journal['previous']
        if previous is not None:
            previous = ident(previous)
            if previous == jid:
                raise ValueError('journal previous cannot reference itself')

        events = []
        seen_seq = set()
        for raw_event in array(raw_journal['events'], 0, _JOURNAL_EVENTS_MAX):
            event = _parse_event(raw_event)
            if event['seq'] in seen_seq:
                raise ValueError('duplicate event seq within journal')
            seen_seq.add(event['seq'])
            events.append(event)
        total_events += len(events)
        if total_events > _EVENTS_TOTAL_MAX:
            raise ValueError('aggregate journal events exceeded')

        # seq 必须从 1 开始连续递增；重放按 seq 排序，输入数组排列不影响结果。
        events.sort(key=lambda event: event['seq'])
        expected_seq = 1
        for event in events:
            if event['seq'] != expected_seq:
                raise ValueError('event seq must be contiguous from 1')
            expected_seq += 1

        journals[jid] = {
            'id': jid,
            'target': target,
            'bundle_id': bundle_id,
            'attempt': attempt,
            'previous': previous,
            'events': events,
        }

    # previous 引用是结构性约束：必须存在且指向同一 target、同一
    # bundle_id、更小 attempt 的 journal。该约束对全部 journal 生效，
    # 因此当前 bundle 的链不可能断链、跨 target/bundle 或回跳到不小于
    # 当前 attempt 的段落。
    for journal in journals.values():
        previous = journal['previous']
        if previous is None:
            continue
        ancestor = journals.get(previous)
        if ancestor is None:
            raise ValueError('journal previous refers to unknown journal')
        if ancestor['target'] != journal['target']:
            raise ValueError('journal previous crosses target')
        if ancestor['bundle_id'] != journal['bundle_id']:
            raise ValueError('journal previous crosses bundle id')
        if ancestor['attempt'] >= journal['attempt']:
            raise ValueError('journal previous must use a smaller attempt')

    return journals


def _select_chain(journals, target, bundle_id):
    """返回 (选中链升序 journal 列表, 被放弃 journal id 列表)。

    只选择当前 bundle_id 的 journal；其他 bundle_id 的日志属于旧历史，
    既不提供进度也不参与链构造。
    """
    current = [
        journal for journal in journals.values()
        if journal['target'] == target and journal['bundle_id'] == bundle_id
    ]
    if not current:
        return [], []

    head = max(current, key=lambda journal: journal['attempt'])
    chain = []
    cursor = head
    visited = set()
    while True:
        if cursor['id'] in visited:
            # 结构性校验已保证 attempt 严格递减，成环不可能发生；保留
            # 显式防线使审计边界不依赖前置校验的实现细节。
            raise ValueError('journal chain contains a cycle')
        visited.add(cursor['id'])
        chain.append(cursor)
        if cursor['previous'] is None:
            break
        cursor = journals[cursor['previous']]

    chain.reverse()  # 反向往上追溯后恢复为 attempt 升序。
    chain_ids = {journal['id'] for journal in chain}
    abandoned = sorted(
        journal['id'] for journal in current
        if journal['id'] not in chain_ids
    )
    return chain, abandoned


def _manifest_index(units):
    by_identity = {}
    by_base = {}
    for unit in units:
        by_identity[(unit['base'], unit['atomic_range'])] = unit
        by_base[unit['base']] = unit
    return by_identity, by_base


def _replay_chain(chain, forward_units, rollback_units):
    """按 attempt 升序、段内 seq 升序重放一条有效链。

    返回 (applied_by_base, rolled_by_base, phase)。phase 取
    forward/committed/rollback/done 之一。
    """
    fwd_by_identity, fwd_by_base = _manifest_index(forward_units)
    rb_by_identity, rb_by_base = _manifest_index(rollback_units)
    all_fwd_bases = set(fwd_by_base)

    applied = {}
    rolled = {}
    phase = 'forward'

    def resolve(unit, by_identity, by_base, label):
        key = (unit['base'], unit['atomic_range'])
        resolved = by_identity.get(key)
        if resolved is not None:
            return resolved
        # base 存在但 atomic_range 不匹配属于同一 base 身份冲突，
        # 不能只用 base 猜测 atomic 身份。
        if unit['base'] in by_base:
            raise ValueError(f'{label} unit atomic identity conflict')
        raise ValueError(f'{label} event refers to unknown unit')

    for journal in chain:
        for event in journal['events']:
            event_type = event['type']

            if event_type == 'forward_applied':
                if phase in ('committed', 'done'):
                    raise ValueError(
                        'forward_applied after commit or rollback_complete')
                unit = resolve(event['unit'], fwd_by_identity,
                               fwd_by_base, 'forward_applied')
                base = unit['base']
                if phase == 'rollback':
                    # 回滚开始后只允许对已应用且尚未回滚单元的幂等重放。
                    if base in applied and base not in rolled:
                        continue
                    raise ValueError(
                        'illegal forward_applied after rollback started')
                if base in applied:
                    # 同一有效链内的重复上报是幂等重放，不重复计数。
                    continue
                applied[base] = unit

            elif event_type == 'commit':
                if phase != 'forward':
                    raise ValueError('illegal commit state transition')
                if set(applied) != all_fwd_bases:
                    raise ValueError('commit before all forward units applied')
                phase = 'committed'

            elif event_type == 'rollback_applied':
                if phase in ('committed', 'done'):
                    raise ValueError(
                        'rollback_applied after commit or rollback_complete')
                unit = resolve(event['unit'], rb_by_identity,
                               rb_by_base, 'rollback_applied')
                base = unit['base']
                if base not in applied:
                    # 尚未前向应用的单元不得伪造回滚进度。
                    raise ValueError(
                        'rollback_applied without matching forward application')
                if base in rolled:
                    # 重启后的重复回滚上报同样按幂等重放处理。
                    continue
                rolled[base] = unit
                phase = 'rollback'

            else:  # rollback_complete
                if phase not in ('forward', 'rollback'):
                    raise ValueError(
                        'illegal rollback_complete state transition')
                if set(rolled) != set(applied):
                    raise ValueError(
                        'rollback_complete before all applied units rolled back')
                phase = 'done'

    return applied, rolled, phase


def _derive_state(phase, forward_units, applied):
    if phase == 'done':
        return 'clean'
    if phase == 'committed':
        return 'committed'
    if phase == 'rollback':
        return 'rollback_partial'
    if applied:
        return 'forward_complete' if len(applied) == len(forward_units) \
            else 'forward_partial'
    # 没有当前 bundle 有效事件：空 forward manifest 视为初始即完成前向，
    # 但仍需显式 commit 才跨过提交点。
    return 'forward_complete' if not forward_units else 'clean'


def _unit_rows(units):
    return [dict(unit) for unit in units]


def _rebuild_target(target_id, manifest_row, journals, bundle_id):
    forward_units = manifest_row['forward']
    rollback_units = manifest_row['rollback']
    chain, abandoned = _select_chain(journals, target_id, bundle_id)

    applied, rolled, phase = _replay_chain(
        chain, forward_units, rollback_units)
    state = _derive_state(phase, forward_units, applied)

    # rollback_complete 后历史明细仍保留在 applied/rolled 输出中，但
    # 当前已应用集合为空：仍需前向的清单恢复为完整 manifest。
    current_applied = {} if phase == 'done' else applied

    applied_rows = _unit_rows(
        unit for unit in forward_units if unit['base'] in applied
    )
    rolled_rows = _unit_rows(
        unit for unit in rollback_units if unit['base'] in rolled
    )
    pending_forward = _unit_rows(
        unit for unit in forward_units
        if unit['base'] not in current_applied
    )
    # 提交点不可逆：committed 后不存在待回滚清单。其余状态下，待回滚
    # 清单按 rollback manifest 的 base 降序输出，使恢复顺序不依赖
    # 输入日志排列。
    if phase == 'committed':
        pending_rollback = []
    else:
        pending_rollback = _unit_rows(
            unit for unit in sorted(
                rollback_units, key=lambda row: row['base'], reverse=True)
            if unit['base'] in current_applied
            and unit['base'] not in rolled
        )

    head = chain[-1] if chain else None
    return {
        'id': target_id,
        'selected_journal': head['id'] if head else None,
        'attempt': head['attempt'] if head else None,
        'chain_journals': [journal['id'] for journal in chain],
        'abandoned_journals': abandoned,
        'state': state,
        'committed': phase == 'committed',
        'applied': applied_rows,
        'rolled_back': rolled_rows,
        'pending_forward': pending_forward,
        'pending_rollback': pending_rollback,
        '_phase': phase,
    }


def _command(target_row, action, reason, units):
    return {
        'target': target_row['id'],
        'action': action,
        'reason': reason,
        'units': _unit_rows(units),
    }


def _hold(target_row, reason):
    return _command(target_row, 'hold', reason, [])


def _independent_commands(target_row):
    state = target_row['state']
    if state in ('committed', 'clean'):
        reason = ('commit point already persisted'
                  if state == 'committed'
                  else 'target is back on the old release with no pending work')
        return _hold(target_row, reason)
    if state == 'forward_complete':
        return _command(target_row, 'commit',
                        'all forward units applied; explicit commit pending', [])
    if state == 'forward_partial':
        return _command(target_row, 'continue_forward',
                        'resume the remaining forward manifest units',
                        target_row['pending_forward'])
    return _command(target_row, 'continue_rollback',
                    'resume rolling back the still-applied units',
                    target_row['pending_rollback'])


def _atomic_decide(member_rows):
    if any(row['committed'] for row in member_rows):
        # 不可逆提交点已跨过：组内不得存在任何回滚状态。
        if any(row['state'] == 'rollback_partial' for row in member_rows):
            raise ValueError(
                'atomic group rollback conflicts with persisted commit point')
        commands = []
        for row in member_rows:
            state = row['state']
            if state == 'committed':
                commands.append(_hold(
                    row, 'commit point already persisted'))
            elif state == 'forward_complete':
                commands.append(_command(
                    row, 'commit',
                    'peer target committed; finish this target commit', []))
            else:
                # clean 或 forward_partial 都必须补齐前向进度。
                commands.append(_command(
                    row, 'continue_forward',
                    'peer target committed; forward progress is now mandatory',
                    row['pending_forward']))
        return 'finish_forward', commands

    has_rollback = any(row['state'] == 'rollback_partial' for row in member_rows)
    has_progress = any(row['state'] in
                       ('forward_partial', 'forward_complete')
                       for row in member_rows)
    has_clean = any(row['state'] == 'clean' for row in member_rows)
    if has_rollback or (has_progress and has_clean):
        # 不允许组内一部分停在旧版本、另一部分继续候选版本。
        commands = []
        for row in member_rows:
            state = row['state']
            if state == 'clean':
                commands.append(_hold(
                    row, 'target never left the old release'))
            else:
                commands.append(_command(
                    row, 'continue_rollback',
                    'atomic group is restoring the old release on every target',
                    row['pending_rollback']))
        return 'restore_old', commands

    if all(row['state'] == 'forward_complete' for row in member_rows):
        return 'commit_all', [
            _command(row, 'commit',
                     'every group target finished forward application', [])
            for row in member_rows
        ]

    if all(row['state'] == 'clean' for row in member_rows):
        return 'stable', [
            _hold(row, 'no target has current-bundle progress')
            for row in member_rows
        ]

    # 剩余情形：没有 clean/rollback，非 clean 目标全部是 forward_partial
    # （若混入 forward_complete，则完整目标先 commit、其余继续前向，
    # 仍收敛到同一个前向完成决定）。
    commands = []
    for row in member_rows:
        if row['state'] == 'forward_complete':
            commands.append(_command(
                row, 'commit',
                'forward application finished; commit once peers catch up', []))
        else:
            commands.append(_command(
                row, 'continue_forward',
                'finish forward application before the group commit point',
                row['pending_forward']))
    return 'finish_forward', commands


def reconcile_rollout(data):
    """重建发布持久化状态并生成一致性组恢复决定。"""
    fields(data, ('bundle', 'groups', 'journals'))

    # 先构造规范 bundle；其任何 ValueError 直接拒绝整份输入。日志无法
    # 影响 bundle_id、manifest 或 chunk 内容。
    bundle = build_release_bundle(data['bundle'])
    bundle_id = bundle['bundle_id']
    manifest_rows = {row['id']: row for row in bundle['targets']}

    groups = _parse_groups(data['groups'], set(manifest_rows))
    journals = _parse_journals(data['journals'], set(manifest_rows))

    target_rows = {}
    for target_id in sorted(manifest_rows):
        row = _rebuild_target(
            target_id, manifest_rows[target_id], journals, bundle_id)
        target_rows[target_id] = row

    group_rows = []
    state_counts = {state: 0 for state in _STATES}
    decision_counts = {decision: 0 for decision in _DECISIONS}
    for row in target_rows.values():
        state_counts[row['state']] += 1

    for gid in sorted(groups):
        group = groups[gid]
        member_rows = [target_rows[tid] for tid in group['targets']]
        if group['policy'] == 'independent':
            commands = [_independent_commands(row) for row in member_rows]
            decision = ('stable'
                        if all(command['action'] == 'hold'
                               for command in commands)
                        else 'independent_recovery')
        else:
            decision, commands = _atomic_decide(member_rows)
        decision_counts[decision] += 1
        group_rows.append({
            'id': gid,
            'policy': group['policy'],
            'decision': decision,
            'commands': commands,
        })

    target_output = []
    for target_id in sorted(target_rows):
        row = target_rows[target_id]
        target_output.append({
            'id': target_id,
            'group': next(
                gid for gid, group in groups.items()
                if target_id in group['targets']),
            'selected_journal': row['selected_journal'],
            'attempt': row['attempt'],
            'chain_journals': row['chain_journals'],
            'abandoned_journals': row['abandoned_journals'],
            'state': row['state'],
            'committed': row['committed'],
            'applied': row['applied'],
            'rolled_back': row['rolled_back'],
            'pending_forward': row['pending_forward'],
            'pending_rollback': row['pending_rollback'],
        })

    return {
        'bundle': {
            'bundle_id': bundle_id,
            'summary': dict(bundle['summary']),
        },
        'targets': target_output,
        'groups': group_rows,
        'summary': {
            'groups': len(groups),
            'targets': len(target_rows),
            'states': state_counts,
            'decisions': decision_counts,
        },
    }
