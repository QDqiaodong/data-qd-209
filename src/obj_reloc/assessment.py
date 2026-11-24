"""目标计划升级影响评估 API.

在两份各自独立完成链接的结构化目标计划之间，按消费者声明的
``address`` / ``provider`` 契约比较其对象所含重定位绑定，给出可继续
运行、需重新绑定、新增或停用的动作。

本模块同样是离线数据 API：不连接设备、不执行目标代码、不读取读回
capture，也不签发部署认证。任何输入或链接错误都以 ``ValueError``
拒绝整份输入，不返回部分评估结果。
"""
from .checks import fields, array, ident
from .linker import link

_ACTIONS = (
    'keep_running',
    'rebind_required',
    'activate_new',
    'stop_removed',
)
_POLICIES = frozenset(('address', 'provider'))

# (object, id) 是比较身份；以下字段是同一身份两侧需要核对的绑定事实。
_FACT_FIELDS = (
    'section',
    'offset',
    'width',
    'target',
    'address',
    'write_address',
    'value',
    'bytes',
)


def _parse_consumers(raw):
    consumers = []
    consumer_ids = set()
    object_owners = {}
    for item in array(raw, 1, 256):
        fields(item, ('id', 'objects', 'binding_policy'))
        cid = ident(item['id'])
        if cid in consumer_ids:
            raise ValueError('duplicate consumer id')
        consumer_ids.add(cid)

        object_ids = []
        object_id_set = set()
        for raw_oid in array(item['objects'], 1, 32):
            oid = ident(raw_oid)
            if oid in object_id_set:
                raise ValueError('duplicate consumer object id')
            object_id_set.add(oid)
            if oid in object_owners:
                raise ValueError('object assigned to multiple consumers')
            object_owners[oid] = cid
            object_ids.append(oid)

        policy = item['binding_policy']
        if policy not in _POLICIES:
            raise ValueError('binding_policy must be address or provider')

        consumers.append({
            'id': cid,
            # 输出与输入数组排列无关；对象身份也按字典序规范化。
            'objects': sorted(object_ids),
            'binding_policy': policy,
        })
    consumers.sort(key=lambda item: item['id'])
    return consumers


def _plan_object_ids(plan):
    # link 已完整验证 plan；对象允许没有 section，因此身份以输入对象表为准。
    return {ident(obj['id']) for obj in array(plan['objects'], 1, 32)}


def _relocation_index(linked):
    return {(r['object'], r['id']): r for r in linked['relocations']}


def _section_bases(linked):
    return {(s['object'], s['name']): s['base'] for s in linked['sections']}


def _binding_fact(row, bases):
    """返回一侧的完整绑定事实。

    link 结果中的 ``address`` 按既有契约是目标符号地址；实际重定位写入
    地址由 section base + offset 得出，用 ``write_address`` 单独保留。
    """
    return {
        'section': row['section'],
        'offset': row['offset'],
        'width': row['width'],
        'target': dict(row['target']),
        'address': row['address'],
        'write_address': bases[(row['object'], row['section'])] + row['offset'],
        'value': row['value'],
        'bytes': list(row['bytes']),
    }


def _compare_relocations(object_ids, current_index, current_bases,
                         candidate_index, candidate_bases):
    keys = set()
    for oid in object_ids:
        keys.update(k for k in current_index if k[0] == oid)
        keys.update(k for k in candidate_index if k[0] == oid)

    details = []
    for oid, rid in sorted(keys):
        key = (oid, rid)
        old_row = current_index.get(key)
        new_row = candidate_index.get(key)
        old_fact = (_binding_fact(old_row, current_bases)
                    if old_row is not None else None)
        new_fact = (_binding_fact(new_row, candidate_bases)
                    if new_row is not None else None)

        if old_fact is None:
            status = 'added'
            changed_fields = []
            field_differences = {}
        elif new_fact is None:
            status = 'removed'
            changed_fields = []
            field_differences = {}
        else:
            field_differences = {}
            for name in _FACT_FIELDS:
                old_value = old_fact[name]
                new_value = new_fact[name]
                if old_value != new_value:
                    field_differences[name] = {
                        'current': old_value,
                        'candidate': new_value,
                    }
            changed_fields = list(field_differences)
            status = 'changed' if changed_fields else 'unchanged'

        details.append({
            'object': oid,
            'id': rid,
            'status': status,
            'current': old_fact,
            'candidate': new_fact,
            'changed_fields': changed_fields,
            'field_differences': field_differences,
        })
    return details


def _action_for_existing(policy, details):
    identity_changed = any(
        d['status'] == 'added' or d['status'] == 'removed'
        for d in details
    )
    write_or_bytes_changed = any(
        'write_address' in d['field_differences']
        or 'bytes' in d['field_differences']
        for d in details
    )
    provider_changed = (
        policy == 'provider'
        and any('target' in d['field_differences'] for d in details)
    )
    if identity_changed or write_or_bytes_changed or provider_changed:
        return 'rebind_required'
    return 'keep_running'


def assess_upgrade(data):
    fields(data, ('current', 'candidate', 'consumers'))

    # 两次调用完全独立；link 自身不接收另一侧的任何布局或解析状态。
    current_linked = link(data['current'])
    candidate_linked = link(data['candidate'])

    consumers = _parse_consumers(data['consumers'])
    current_objects = _plan_object_ids(data['current'])
    candidate_objects = _plan_object_ids(data['candidate'])

    # 先完成全部引用与混合迁移校验，再构造结果，确保错误不返回部分评估。
    presence = {}
    for consumer in consumers:
        current_only = []
        candidate_only = []
        for oid in consumer['objects']:
            in_current = oid in current_objects
            in_candidate = oid in candidate_objects
            if not in_current and not in_candidate:
                raise ValueError('consumer object reference is absent from both plans')
            if in_current and not in_candidate:
                current_only.append(oid)
            elif in_candidate and not in_current:
                candidate_only.append(oid)
        if current_only and candidate_only:
            raise ValueError('consumer mixes removed and added object identities')
        presence[consumer['id']] = (current_only, candidate_only)

    current_index = _relocation_index(current_linked)
    candidate_index = _relocation_index(candidate_linked)
    current_bases = _section_bases(current_linked)
    candidate_bases = _section_bases(candidate_linked)

    rows = []
    counts = {action: 0 for action in _ACTIONS}
    for consumer in consumers:
        cid = consumer['id']
        object_ids = consumer['objects']
        current_only, candidate_only = presence[cid]
        details = _compare_relocations(
            object_ids,
            current_index, current_bases,
            candidate_index, candidate_bases,
        )

        all_candidate_only = len(candidate_only) == len(object_ids)
        all_current_only = len(current_only) == len(object_ids)
        if all_candidate_only:
            action = 'activate_new'
        elif all_current_only:
            action = 'stop_removed'
        else:
            # 全部对象都在两侧，或部分对象在两侧、其余对象仅在一侧。
            # 后一种情况会通过 added/removed relocation 明细推出重绑定。
            # 同时存在 current-only 与 candidate-only 已在上面拒绝。
            action = _action_for_existing(consumer['binding_policy'], details)

        counts[action] += 1
        rows.append({
            'id': cid,
            'objects': list(object_ids),
            'binding_policy': consumer['binding_policy'],
            'action': action,
            'relocations': details,
        })

    return {
        'current': current_linked['summary'],
        'candidate': candidate_linked['summary'],
        'consumers': rows,
        'summary': {
            **counts,
            'actions': dict(counts),
            'consumers': len(rows),
            # 与既有 certify summary 的 total 命名保持一致。
            'total': len(rows),
        },
    }
