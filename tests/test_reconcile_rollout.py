import copy
import json
import unittest

from obj_reloc import (
    assess_upgrade,
    build_release_bundle,
    certify,
    link,
    process,
    reconcile_rollout,
)


def plan(size=8):
    return {
        'regions': [{'name': 'mem', 'base': 0, 'size': size}],
        'objects': [{
            'id': 'o',
            'sections': [{'name': 's', 'region': 'mem',
                          'size': size, 'alignment': 1}],
            'symbols': [],
            'relocations': [],
        }],
    }


def release(rid, payload, plan_obj=None):
    plan_obj = plan_obj or plan(len(payload))
    return {
        'id': rid,
        'plan': plan_obj,
        'images': [{'object': 'o', 'section': 's', 'bytes': payload}],
    }


def target(tid, current='cur', candidate='cand', atomic_ranges=None):
    return {
        'id': tid,
        'current': current,
        'candidate': candidate,
        'erase_byte': 0xFF,
        'atomic_ranges': atomic_ranges or [],
        'max_batch_bytes': 65536,
    }


def bundle_input(targets, cur_bytes=None, cand_bytes=None, releases=None):
    cur_bytes = [0] * 8 if cur_bytes is None else cur_bytes
    cand_bytes = [1, 0, 0, 0, 0, 0, 0, 2] if cand_bytes is None else cand_bytes
    return {
        'releases': releases or [
            release('cur', cur_bytes),
            release('cand', cand_bytes),
        ],
        'targets': targets,
        'receipts': [],
    }


def journal(jid, tid, attempt, previous, events, bundle_id='BID'):
    return {
        'id': jid, 'target': tid, 'bundle_id': bundle_id,
        'attempt': attempt, 'previous': previous, 'events': events,
    }


def event(seq, etype, unit=None):
    return {'seq': seq, 'type': etype, 'unit': unit}


UNIT_BASE0 = {'base': 0, 'atomic_range': None}
UNIT_BASE7 = {'base': 7, 'atomic_range': None}


class ReconcileFixture(unittest.TestCase):
    """双目标、双前向单元（base 0 与 base 7）的标准对账夹具。"""

    def setUp(self):
        self.targets = [target('t1'), target('t2')]
        self.bundle_input = bundle_input(self.targets)
        self.bundle = build_release_bundle(self.bundle_input)
        self.bid = self.bundle['bundle_id']
        self.assertEqual(
            [u['base'] for u in self.bundle['targets'][0]['forward']],
            [0, 7])
        self.atomic_group = [
            {'id': 'g1', 'targets': ['t1', 't2'], 'policy': 'atomic'}]

    def reconcile(self, groups=None, journals=None, raw=None):
        data = raw if raw is not None else {
            'bundle': self.bundle_input,
            'groups': groups if groups is not None else self.atomic_group,
            'journals': journals or [],
        }
        return reconcile_rollout(data)

    def j(self, jid, tid, attempt, previous, events):
        return journal(jid, tid, attempt, previous, events, self.bid)

    def target_row(self, result, tid):
        return next(row for row in result['targets'] if row['id'] == tid)

    def group_row(self, result, gid='g1'):
        return next(row for row in result['groups'] if row['id'] == gid)

    def commands(self, result, gid='g1'):
        return {cmd['target']: cmd
                for cmd in self.group_row(result, gid)['commands']}

    def assert_rejects(self, data):
        with self.assertRaises(ValueError):
            reconcile_rollout(data)


class ChainReconstructionTests(ReconcileFixture):
    def test_restart_chain_continues_across_attempts(self):
        journals = [
            self.j('j1', 't1', 1, None,
                   [event(1, 'forward_applied', UNIT_BASE0)]),
            self.j('j2', 't1', 2, 'j1', [
                event(1, 'forward_applied', UNIT_BASE7),
                event(2, 'commit', None),
            ]),
        ]
        result = self.reconcile(journals=journals)
        row = self.target_row(result, 't1')
        self.assertEqual(row['state'], 'committed')
        self.assertTrue(row['committed'])
        self.assertEqual(row['selected_journal'], 'j2')
        self.assertEqual(row['attempt'], 2)
        self.assertEqual(row['chain_journals'], ['j1', 'j2'])
        self.assertEqual(row['abandoned_journals'], [])
        self.assertEqual([u['base'] for u in row['applied']], [0, 7])
        self.assertEqual(row['pending_forward'], [])
        self.assertEqual(row['pending_rollback'], [])

    def test_latest_branch_does_not_absorb_abandoned_branch(self):
        journals = [
            # 较早分支已经应用了 base 0，但 attempt 2 从 previous=null
            # 重新开始，是被放弃的尝试。
            self.j('j-old', 't1', 1, None,
                   [event(1, 'forward_applied', UNIT_BASE0)]),
            self.j('j-new', 't1', 2, None, []),
        ]
        result = self.reconcile(journals=journals)
        row = self.target_row(result, 't1')
        self.assertEqual(row['state'], 'clean')
        self.assertEqual(row['selected_journal'], 'j-new')
        self.assertEqual(row['chain_journals'], ['j-new'])
        self.assertEqual(row['abandoned_journals'], ['j-old'])
        self.assertEqual(row['applied'], [])
        self.assertEqual(
            [u['base'] for u in row['pending_forward']], [0, 7])

    def test_duplicate_applied_is_idempotent_within_and_across_journals(self):
        journals = [
            self.j('j1', 't1', 1, None, [
                event(1, 'forward_applied', UNIT_BASE0),
                event(2, 'forward_applied', UNIT_BASE0),
            ]),
            self.j('j2', 't1', 2, 'j1', [
                event(1, 'forward_applied', UNIT_BASE0),
                event(2, 'forward_applied', UNIT_BASE7),
                event(3, 'forward_applied', UNIT_BASE7),
            ]),
        ]
        result = self.reconcile(journals=journals)
        row = self.target_row(result, 't1')
        self.assertEqual(row['state'], 'forward_complete')
        self.assertEqual([u['base'] for u in row['applied']], [0, 7])
        self.assertEqual(row['pending_forward'], [])

    def test_chain_replays_by_attempt_and_seq_regardless_of_array_order(self):
        journals = [
            self.j('j2', 't1', 2, 'j1', [
                # events 数组打乱但 seq 连续，必须按 seq 重放。
                event(2, 'commit', None),
                event(1, 'forward_applied', UNIT_BASE7),
            ]),
            self.j('j1', 't1', 1, None,
                   [event(1, 'forward_applied', UNIT_BASE0)]),
        ]
        result = self.reconcile(journals=journals)
        row = self.target_row(result, 't1')
        self.assertEqual(row['state'], 'committed')
        self.assertEqual(row['chain_journals'], ['j1', 'j2'])

    def test_old_bundle_journals_never_credit_current_progress(self):
        journals = [
            journal('old', 't1', 9, None, [
                # 旧 bundle 中的单元不要求存在于当前 manifest。
                event(1, 'forward_applied',
                      {'base': 900, 'atomic_range': None}),
            ], bundle_id='some-older-bundle'),
        ]
        result = self.reconcile(journals=journals)
        row = self.target_row(result, 't1')
        self.assertEqual(row['state'], 'clean')
        self.assertIsNone(row['selected_journal'])
        self.assertIsNone(row['attempt'])
        self.assertEqual(row['chain_journals'], [])
        self.assertEqual(row['abandoned_journals'], [])
        self.assertEqual(
            [u['base'] for u in row['pending_forward']], [0, 7])

    def test_chain_failures_are_rejected(self):
        good = self.j('j1', 't1', 1, None,
                      [event(1, 'forward_applied', UNIT_BASE0)])

        broken = self.j('j2', 't1', 2, 'missing', [])
        self.assert_rejects({
            'bundle': self.bundle_input, 'groups': self.atomic_group,
            'journals': [broken]})

        cross_target = self.j('jx', 't2', 1, None, [])
        bad_previous = self.j('j2', 't1', 2, 'jx', [])
        self.assert_rejects({
            'bundle': self.bundle_input, 'groups': self.atomic_group,
            'journals': [cross_target, bad_previous]})

        cross_bundle = journal(
            'jo', 't1', 1, None, [], bundle_id='other-bundle')
        bad_bundle_previous = self.j('j2', 't1', 2, 'jo', [])
        self.assert_rejects({
            'bundle': self.bundle_input, 'groups': self.atomic_group,
            'journals': [cross_bundle, bad_bundle_previous]})

        same_attempt = self.j('j2', 't1', 1, 'j1', [])
        self.assert_rejects({
            'bundle': self.bundle_input, 'groups': self.atomic_group,
            'journals': [good, same_attempt]})

    def test_duplicate_journal_identity_and_attempt_are_rejected(self):
        self.assert_rejects({
            'bundle': self.bundle_input, 'groups': self.atomic_group,
            'journals': [
                self.j('j1', 't1', 1, None, []),
                self.j('j1', 't2', 1, None, []),
            ]})
        self.assert_rejects({
            'bundle': self.bundle_input, 'groups': self.atomic_group,
            'journals': [
                self.j('j1', 't1', 1, None, []),
                self.j('j2', 't1', 1, None, []),
            ]})


class StateReconstructionTests(ReconcileFixture):
    def test_forward_partial_lists_exact_pending_and_rollback_units(self):
        journals = [
            self.j('j1', 't1', 1, None,
                   [event(1, 'forward_applied', UNIT_BASE0)]),
        ]
        result = self.reconcile(journals=journals)
        row = self.target_row(result, 't1')
        self.assertEqual(row['state'], 'forward_partial')
        self.assertFalse(row['committed'])
        self.assertEqual([u['base'] for u in row['applied']], [0])
        self.assertEqual(row['rolled_back'], [])
        self.assertEqual([u['base'] for u in row['pending_forward']], [7])
        # 已应用但尚未回滚的单元按 base 降序给出。
        self.assertEqual(
            [u['base'] for u in row['pending_rollback']], [0])
        for unit in row['applied'] + row['pending_forward']:
            self.assertEqual(
                set(unit), {'base', 'size', 'atomic_range', 'chunk_id'})

    def test_partial_rollback_produces_exact_remaining_set_descending(self):
        journals = [
            self.j('j1', 't1', 1, None, [
                event(1, 'forward_applied', UNIT_BASE0),
                event(2, 'forward_applied', UNIT_BASE7),
                event(3, 'rollback_applied', UNIT_BASE0),
            ]),
        ]
        result = self.reconcile(journals=journals)
        row = self.target_row(result, 't1')
        self.assertEqual(row['state'], 'rollback_partial')
        self.assertEqual([u['base'] for u in row['applied']], [0, 7])
        self.assertEqual([u['base'] for u in row['rolled_back']], [0])
        self.assertEqual(
            [u['base'] for u in row['pending_rollback']], [7])

    def test_rollback_complete_returns_clean_but_keeps_history(self):
        journals = [
            self.j('j1', 't1', 1, None, [
                event(1, 'forward_applied', UNIT_BASE0),
                event(2, 'rollback_applied', UNIT_BASE0),
                event(3, 'rollback_complete', None),
            ]),
        ]
        result = self.reconcile(journals=journals)
        row = self.target_row(result, 't1')
        self.assertEqual(row['state'], 'clean')
        self.assertEqual([u['base'] for u in row['applied']], [0])
        self.assertEqual([u['base'] for u in row['rolled_back']], [0])
        self.assertEqual(row['pending_rollback'], [])
        # 当前已应用集合为空，仍需前向的清单恢复为完整 manifest。
        self.assertEqual(
            [u['base'] for u in row['pending_forward']], [0, 7])

    def test_empty_forward_manifest_starts_forward_complete_needs_commit(self):
        same = release('same', [3] * 8)
        raw = {
            'releases': [same],
            'targets': [target('t1', current='same', candidate='same')],
            'receipts': [],
        }
        bid = build_release_bundle(raw)['bundle_id']
        groups = [{'id': 'g1', 'targets': ['t1'], 'policy': 'independent'}]
        result = reconcile_rollout({
            'bundle': raw, 'groups': groups, 'journals': []})
        row = result['targets'][0]
        self.assertEqual(row['state'], 'forward_complete')
        self.assertFalse(row['committed'])
        self.assertEqual(
            result['groups'][0]['commands'][0]['action'], 'commit')

        committed = reconcile_rollout({
            'bundle': raw, 'groups': groups,
            'journals': [journal('j1', 't1', 1, None,
                                 [event(1, 'commit', None)], bid)],
        })
        self.assertEqual(committed['targets'][0]['state'], 'committed')

    def test_rollback_unit_identity_must_match_rollback_manifest(self):
        ar_target = target('t1', atomic_ranges=[
            {'id': 'ar1', 'base': 0, 'size': 8}])
        raw = bundle_input(
            [ar_target], cur_bytes=[0] * 8, cand_bytes=[1] + [0] * 7)
        bid = build_release_bundle(raw)['bundle_id']
        groups = [{'id': 'g1', 'targets': ['t1'], 'policy': 'atomic'}]

        def attempt(events):
            return reconcile_rollout({
                'bundle': raw, 'groups': groups,
                'journals': [journal('j1', 't1', 1, None, events, bid)],
            })

        # 正确的 atomic 身份可以应用并提交。
        ok = attempt([
            event(1, 'forward_applied', {'base': 0, 'atomic_range': 'ar1'}),
            event(2, 'commit', None),
        ])
        self.assertEqual(ok['targets'][0]['state'], 'committed')

        with self.assertRaises(ValueError):
            attempt([event(1, 'forward_applied',
                           {'base': 0, 'atomic_range': 'arX'})])
        with self.assertRaises(ValueError):
            attempt([event(1, 'forward_applied',
                           {'base': 0, 'atomic_range': None})])

    def test_progress_is_not_shared_across_targets(self):
        # 两个 target 的 manifest 单元完全相同（同样 chunk_id），
        # t1 的持久化进度不得抵扣 t2。
        journals = [
            self.j('j1', 't1', 1, None,
                   [event(1, 'forward_applied', UNIT_BASE0)]),
        ]
        result = self.reconcile(journals=journals)
        t1 = self.target_row(result, 't1')
        t2 = self.target_row(result, 't2')
        self.assertEqual(t1['state'], 'forward_partial')
        self.assertEqual(t2['state'], 'clean')
        # 即使 chunk_id 相同，t2 仍持有完整待前向清单，进度不跨目标共享。
        self.assertEqual(
            [u['base'] for u in t1['pending_forward']], [7])
        self.assertEqual(
            [u['base'] for u in t2['pending_forward']], [0, 7])
        self.assertEqual(
            {u['chunk_id'] for u in t1['pending_forward']},
            {u['chunk_id'] for u in t2['pending_forward']
             if u['base'] == 7})
        self.assertEqual(len(t2['pending_forward']), 2)


class IllegalTransitionRejectionTests(ReconcileFixture):
    def test_unknown_unit_is_rejected(self):
        self.assert_rejects({
            'bundle': self.bundle_input, 'groups': self.atomic_group,
            'journals': [self.j('j1', 't1', 1, None, [
                event(1, 'forward_applied',
                      {'base': 5, 'atomic_range': None})])],
        })

    def test_premature_commit_is_rejected(self):
        self.assert_rejects({
            'bundle': self.bundle_input, 'groups': self.atomic_group,
            'journals': [self.j('j1', 't1', 1, None, [
                event(1, 'forward_applied', UNIT_BASE0),
                event(2, 'commit', None),
            ])],
        })

    def test_rollback_without_forward_is_rejected(self):
        self.assert_rejects({
            'bundle': self.bundle_input, 'groups': self.atomic_group,
            'journals': [self.j('j1', 't1', 1, None,
                                [event(1, 'rollback_applied', UNIT_BASE0)])],
        })

    def test_rollback_after_commit_conflicts_and_rejects_whole_input(self):
        self.assert_rejects({
            'bundle': self.bundle_input, 'groups': self.atomic_group,
            'journals': [self.j('j1', 't1', 1, None, [
                event(1, 'forward_applied', UNIT_BASE0),
                event(2, 'forward_applied', UNIT_BASE7),
                event(3, 'commit', None),
                event(4, 'rollback_applied', UNIT_BASE0),
            ])],
        })

    def test_premature_rollback_complete_is_rejected(self):
        self.assert_rejects({
            'bundle': self.bundle_input, 'groups': self.atomic_group,
            'journals': [self.j('j1', 't1', 1, None, [
                event(1, 'forward_applied', UNIT_BASE0),
                event(2, 'rollback_complete', None),
            ])],
        })

    def test_events_after_terminal_events_are_rejected(self):
        self.assert_rejects({
            'bundle': self.bundle_input, 'groups': self.atomic_group,
            'journals': [self.j('j1', 't1', 1, None, [
                event(1, 'forward_applied', UNIT_BASE0),
                event(2, 'rollback_applied', UNIT_BASE0),
                event(3, 'rollback_complete', None),
                event(4, 'forward_applied', UNIT_BASE7),
            ])],
        })
        self.assert_rejects({
            'bundle': self.bundle_input, 'groups': self.atomic_group,
            'journals': [self.j('j1', 't1', 1, None, [
                event(1, 'forward_applied', UNIT_BASE0),
                event(2, 'forward_applied', UNIT_BASE7),
                event(3, 'commit', None),
                event(4, 'forward_applied', UNIT_BASE0),
            ])],
        })

    def test_new_forward_after_rollback_started_is_rejected(self):
        self.assert_rejects({
            'bundle': self.bundle_input, 'groups': self.atomic_group,
            'journals': [self.j('j1', 't1', 1, None, [
                event(1, 'forward_applied', UNIT_BASE0),
                event(2, 'rollback_applied', UNIT_BASE0),
                event(3, 'forward_applied', UNIT_BASE7),
            ])],
        })

    def test_duplicate_rollback_complete_is_rejected(self):
        self.assert_rejects({
            'bundle': self.bundle_input, 'groups': self.atomic_group,
            'journals': [self.j('j1', 't1', 1, None, [
                event(1, 'forward_applied', UNIT_BASE0),
                event(2, 'rollback_applied', UNIT_BASE0),
                event(3, 'rollback_complete', None),
                event(4, 'rollback_complete', None),
            ])],
        })

    def test_duplicate_commit_is_rejected(self):
        self.assert_rejects({
            'bundle': self.bundle_input, 'groups': self.atomic_group,
            'journals': [self.j('j1', 't1', 1, None, [
                event(1, 'forward_applied', UNIT_BASE0),
                event(2, 'forward_applied', UNIT_BASE7),
                event(3, 'commit', None),
                event(4, 'commit', None),
            ])],
        })

    def test_terminal_event_must_carry_null_unit(self):
        self.assert_rejects({
            'bundle': self.bundle_input, 'groups': self.atomic_group,
            'journals': [self.j('j1', 't1', 1, None, [
                event(1, 'forward_applied', UNIT_BASE0),
                event(2, 'forward_applied', UNIT_BASE7),
                event(3, 'commit', UNIT_BASE0),
            ])],
        })

    def test_non_contiguous_seq_and_unknown_fields_are_rejected(self):
        self.assert_rejects({
            'bundle': self.bundle_input, 'groups': self.atomic_group,
            'journals': [self.j('j1', 't1', 1, None,
                                [event(2, 'forward_applied', UNIT_BASE0)])],
        })
        bad = {
            'bundle': self.bundle_input, 'groups': self.atomic_group,
            'journals': [self.j('j1', 't1', 1, None, [])],
        }
        bad['journals'][0]['unexpected'] = True
        self.assert_rejects(bad)
        self.assert_rejects({
            'bundle': self.bundle_input, 'groups': self.atomic_group,
            'journals': [], 'unexpected': True,
        })

    def test_bool_integer_bad_enum_and_bad_references_are_rejected(self):
        self.assert_rejects({
            'bundle': self.bundle_input, 'groups': self.atomic_group,
            'journals': [self.j('j1', 't1', True, None, [])],
        })
        self.assert_rejects({
            'bundle': self.bundle_input,
            'groups': [{'id': 'g1', 'targets': ['t1', 't2'],
                       'policy': 'frozen'}],
            'journals': [],
        })
        self.assert_rejects({
            'bundle': self.bundle_input,
            'groups': [{'id': 'g1', 'targets': ['t1'],
                       'policy': 'atomic'}],
            'journals': [],
        })
        self.assert_rejects({
            'bundle': self.bundle_input,
            'groups': [
                {'id': 'g1', 'targets': ['t1'], 'policy': 'atomic'},
                {'id': 'g2', 'targets': ['t1', 't2'], 'policy': 'atomic'},
            ],
            'journals': [],
        })
        self.assert_rejects({
            'bundle': self.bundle_input, 'groups': self.atomic_group,
            'journals': [self.j('j1', 'unknown-target', 1, None, [])],
        })

    def test_bundle_build_failure_rejects_entire_reconcile(self):
        bad_bundle = copy.deepcopy(self.bundle_input)
        bad_bundle['targets'][0]['erase_byte'] = True
        self.assert_rejects({
            'bundle': bad_bundle, 'groups': self.atomic_group,
            'journals': [],
        })


class AtomicGroupDecisionTests(ReconcileFixture):
    def test_one_committed_target_forces_peers_to_finish_forward(self):
        journals = [
            self.j('j1', 't1', 1, None, [
                event(1, 'forward_applied', UNIT_BASE0),
                event(2, 'forward_applied', UNIT_BASE7),
                event(3, 'commit', None),
            ]),
        ]
        result = self.reconcile(journals=journals)
        self.assertEqual(self.group_row(result)['decision'],
                         'finish_forward')
        commands = self.commands(result)
        self.assertEqual(commands['t1']['action'], 'hold')
        self.assertEqual(commands['t1']['units'], [])
        self.assertEqual(commands['t2']['action'], 'continue_forward')
        self.assertEqual(
            [u['base'] for u in commands['t2']['units']], [0, 7])

    def test_rollback_state_alongside_commit_is_rejected(self):
        journals = [
            self.j('j1', 't1', 1, None, [
                event(1, 'forward_applied', UNIT_BASE0),
                event(2, 'forward_applied', UNIT_BASE7),
                event(3, 'commit', None),
            ]),
            self.j('j2', 't2', 1, None, [
                event(1, 'forward_applied', UNIT_BASE0),
                event(2, 'rollback_applied', UNIT_BASE0),
            ]),
        ]
        self.assert_rejects({
            'bundle': self.bundle_input, 'groups': self.atomic_group,
            'journals': journals,
        })

    def test_progress_next_to_clean_target_restores_old_release(self):
        journals = [
            self.j('j1', 't1', 1, None,
                   [event(1, 'forward_applied', UNIT_BASE0)]),
        ]
        result = self.reconcile(journals=journals)
        self.assertEqual(self.group_row(result)['decision'], 'restore_old')
        commands = self.commands(result)
        self.assertEqual(commands['t1']['action'], 'continue_rollback')
        self.assertEqual(
            [u['base'] for u in commands['t1']['units']], [0])
        self.assertEqual(commands['t2']['action'], 'hold')
        self.assertEqual(commands['t2']['units'], [])

    def test_rollback_partial_anywhere_restores_old_release_for_all(self):
        journals = [
            self.j('j1', 't1', 1, None, [
                event(1, 'forward_applied', UNIT_BASE0),
                event(2, 'forward_applied', UNIT_BASE7),
                event(3, 'rollback_applied', UNIT_BASE7),
            ]),
            self.j('j2', 't2', 1, None,
                   [event(1, 'forward_applied', UNIT_BASE0)]),
        ]
        result = self.reconcile(journals=journals)
        self.assertEqual(self.group_row(result)['decision'], 'restore_old')
        commands = self.commands(result)
        # t1 继续剩余回滚；t2 从其完整已应用集合生成待回滚清单，降序。
        self.assertEqual(
            [u['base'] for u in commands['t1']['units']], [0])
        self.assertEqual(
            [u['base'] for u in commands['t2']['units']], [0])

    def test_all_forward_complete_only_emits_commit_without_fake_commit(self):
        journals = [
            self.j('j1', 't1', 1, None, [
                event(1, 'forward_applied', UNIT_BASE0),
                event(2, 'forward_applied', UNIT_BASE7),
            ]),
            self.j('j2', 't2', 1, None, [
                event(1, 'forward_applied', UNIT_BASE7),
                event(2, 'forward_applied', UNIT_BASE0),
            ]),
        ]
        result = self.reconcile(journals=journals)
        self.assertEqual(self.group_row(result)['decision'], 'commit_all')
        commands = self.commands(result)
        self.assertEqual(commands['t1']['action'], 'commit')
        self.assertEqual(commands['t2']['action'], 'commit')
        self.assertEqual(commands['t1']['units'], [])
        self.assertTrue(all(not row['committed']
                            for row in result['targets']))
        self.assertTrue(all(row['state'] == 'forward_complete'
                            for row in result['targets']))

    def test_all_clean_is_stable(self):
        result = self.reconcile(journals=[])
        self.assertEqual(self.group_row(result)['decision'], 'stable')
        commands = self.commands(result)
        self.assertEqual(commands['t1']['action'], 'hold')
        self.assertEqual(commands['t2']['action'], 'hold')

    def test_all_partial_finishes_forward_with_remaining_units(self):
        journals = [
            self.j('j1', 't1', 1, None,
                   [event(1, 'forward_applied', UNIT_BASE0)]),
            self.j('j2', 't2', 1, None,
                   [event(1, 'forward_applied', UNIT_BASE7)]),
        ]
        result = self.reconcile(journals=journals)
        self.assertEqual(self.group_row(result)['decision'],
                         'finish_forward')
        commands = self.commands(result)
        self.assertEqual(commands['t1']['action'], 'continue_forward')
        self.assertEqual(
            [u['base'] for u in commands['t1']['units']], [7])
        self.assertEqual(commands['t2']['action'], 'continue_forward')
        self.assertEqual(
            [u['base'] for u in commands['t2']['units']], [0])

    def test_complete_next_to_partial_keeps_finish_forward_decision(self):
        # 规格未单列的混合态：一个 forward_complete、一个 forward_partial，
        # 既不能 commit_all 也不能 restore_old，只能继续前向收敛。
        journals = [
            self.j('j1', 't1', 1, None, [
                event(1, 'forward_applied', UNIT_BASE0),
                event(2, 'forward_applied', UNIT_BASE7),
            ]),
            self.j('j2', 't2', 1, None,
                   [event(1, 'forward_applied', UNIT_BASE0)]),
        ]
        result = self.reconcile(journals=journals)
        self.assertEqual(self.group_row(result)['decision'],
                         'finish_forward')
        commands = self.commands(result)
        self.assertEqual(commands['t1']['action'], 'commit')
        self.assertEqual(commands['t2']['action'], 'continue_forward')
        self.assertEqual(
            [u['base'] for u in commands['t2']['units']], [7])


class IndependentGroupDecisionTests(ReconcileFixture):
    def test_mixed_continue_forward_and_rollback(self):
        groups = [
            {'id': 'g1', 'targets': ['t1'], 'policy': 'independent'},
            {'id': 'g2', 'targets': ['t2'], 'policy': 'independent'},
        ]
        journals = [
            self.j('j1', 't1', 1, None,
                   [event(1, 'forward_applied', UNIT_BASE0)]),
            self.j('j2', 't2', 1, None, [
                event(1, 'forward_applied', UNIT_BASE0),
                event(2, 'forward_applied', UNIT_BASE7),
                event(3, 'rollback_applied', UNIT_BASE0),
            ]),
        ]
        result = self.reconcile(groups=groups, journals=journals)
        decisions = {row['id']: row['decision'] for row in result['groups']}
        self.assertEqual(decisions, {
            'g1': 'independent_recovery',
            'g2': 'independent_recovery',
        })
        commands = {
            cmd['target']: cmd
            for group in result['groups'] for cmd in group['commands']}
        self.assertEqual(commands['t1']['action'], 'continue_forward')
        self.assertEqual(
            [u['base'] for u in commands['t1']['units']], [7])
        self.assertEqual(commands['t2']['action'], 'continue_rollback')
        self.assertEqual(
            [u['base'] for u in commands['t2']['units']], [7])

    def test_forward_complete_commits_and_committed_or_clean_holds(self):
        groups = [
            {'id': 'g1', 'targets': ['t1', 't2'],
             'policy': 'independent'},
        ]
        journals = [
            self.j('j1', 't1', 1, None, [
                event(1, 'forward_applied', UNIT_BASE0),
                event(2, 'forward_applied', UNIT_BASE7),
            ]),
            # t2 保持 clean。
        ]
        result = self.reconcile(groups=groups, journals=journals)
        self.assertEqual(result['groups'][0]['decision'],
                         'independent_recovery')
        commands = {
            cmd['target']: cmd for cmd in result['groups'][0]['commands']}
        self.assertEqual(commands['t1']['action'], 'commit')
        self.assertEqual(commands['t2']['action'], 'hold')

        journals[0]['events'].append(event(3, 'commit', None))
        committed = self.reconcile(groups=groups, journals=journals)
        commands = {
            cmd['target']: cmd
            for cmd in committed['groups'][0]['commands']}
        self.assertEqual(commands['t1']['action'], 'hold')
        self.assertEqual(commands['t2']['action'], 'hold')
        self.assertEqual(committed['groups'][0]['decision'], 'stable')


class OutputShapeAndDeterminismTests(ReconcileFixture):
    def test_output_shape_and_summary_counts(self):
        journals = [
            self.j('j1', 't1', 1, None,
                   [event(1, 'forward_applied', UNIT_BASE0)]),
        ]
        result = self.reconcile(journals=journals)
        self.assertEqual(result['bundle']['bundle_id'], self.bid)
        self.assertEqual(result['bundle']['summary'], self.bundle['summary'])
        self.assertEqual([row['id'] for row in result['targets']],
                         ['t1', 't2'])
        self.assertEqual([row['group'] for row in result['targets']],
                         ['g1', 'g1'])
        self.assertEqual(result['summary'], {
            'groups': 1,
            'targets': 2,
            'states': {
                'clean': 1,
                'forward_partial': 1,
                'forward_complete': 0,
                'committed': 0,
                'rollback_partial': 0,
            },
            'decisions': {
                'stable': 0,
                'finish_forward': 0,
                'commit_all': 0,
                'restore_old': 1,
                'independent_recovery': 0,
            },
        })
        command = result['groups'][0]['commands'][0]
        self.assertEqual(
            set(command), {'target', 'action', 'reason', 'units'})

    def test_reordering_inputs_does_not_change_result(self):
        journals = [
            self.j('j2', 't1', 2, 'j1', [
                event(2, 'commit', None),
                event(1, 'forward_applied', UNIT_BASE7),
            ]),
            self.j('j1', 't1', 1, None,
                   [event(1, 'forward_applied', UNIT_BASE0)]),
            self.j('j3', 't2', 1, None,
                   [event(1, 'forward_applied', UNIT_BASE0)]),
        ]
        original = self.reconcile(journals=copy.deepcopy(journals))

        shuffled = {
            'bundle': copy.deepcopy(self.bundle_input),
            'groups': [
                {'id': 'g1', 'targets': ['t2', 't1'],
                 'policy': 'atomic'},
            ],
            'journals': list(reversed(copy.deepcopy(journals))),
        }
        shuffled['bundle']['releases'].reverse()
        shuffled['bundle']['targets'].reverse()
        for j in shuffled['journals']:
            j['events'] = list(reversed(j['events']))

        reordered = reconcile_rollout(shuffled)
        self.assertEqual(
            json.dumps(original, sort_keys=True),
            json.dumps(reordered, sort_keys=True))
        # bundle 身份也不随重排改变。
        self.assertEqual(reordered['bundle']['bundle_id'], self.bid)

    def test_reconcile_does_not_mutate_inputs_or_bundle_contract(self):
        journals = [
            self.j('j1', 't1', 1, None,
                   [event(1, 'forward_applied', UNIT_BASE0)]),
        ]
        raw = {
            'bundle': copy.deepcopy(self.bundle_input),
            'groups': copy.deepcopy(self.atomic_group),
            'journals': copy.deepcopy(journals),
        }
        snapshot = json.dumps(raw, sort_keys=True)
        reconcile_rollout(raw)
        self.assertEqual(json.dumps(raw, sort_keys=True), snapshot)
        # 日志不能改变 bundle 产物：同一 bundle 输入仍构造出相同 id。
        self.assertEqual(
            build_release_bundle(raw['bundle'])['bundle_id'], self.bid)


class ExistingApiContractTests(unittest.TestCase):
    """新模块不得改变既有五个 API 的输入、输出与拒绝边界。"""

    def test_existing_apis_remain_exported_and_callable(self):
        for api in (process, link, certify, assess_upgrade,
                    build_release_bundle, reconcile_rollout):
            self.assertTrue(callable(api))

    def test_process_and_link_basic_contract_still_holds(self):
        plan_obj = {
            'regions': [{'name': 'mem', 'base': 0, 'size': 64}],
            'objects': [{
                'id': 'o',
                'sections': [{'name': 's', 'region': 'mem',
                              'size': 8, 'alignment': 1}],
                'symbols': [{
                    'name': 'sym', 'section': 's', 'offset': 0,
                    'binding': 'strong',
                }],
                'relocations': [{
                    'id': 'r1', 'section': 's', 'offset': 0,
                    'symbol': {'scope': 'local', 'name': 'sym'},
                    'addend': 8, 'width': 2,
                }],
            }],
        }
        linked = link(plan_obj)
        self.assertEqual(
            linked['relocations'][0]['bytes'], [8, 0])
        with self.assertRaises(ValueError):
            link({'regions': [], 'objects': []})

        process_data = {
            'sections': [{'name': 's', 'base': 0, 'size': 8}],
            'symbols': [{
                'name': 'sym', 'section': 's', 'offset': 0,
                'global': True,
            }],
            'relocations': [{
                'id': 'r1', 'section': 's', 'offset': 0, 'symbol': 'sym',
                'addend': 0, 'width': 1,
            }],
        }
        processed = process(process_data)
        self.assertEqual(processed['summary']['relocations'], 1)
        with self.assertRaises(ValueError):
            process({**process_data, 'unexpected': 1})

    def test_build_release_bundle_contract_remains_intact(self):
        raw = bundle_input([target('t1')])
        bundle = build_release_bundle(raw)
        self.assertRegex(bundle['bundle_id'], r'^[0-9a-f]{64}$')
        row = bundle['targets'][0]
        self.assertEqual(
            [u['base'] for u in row['forward']], [0, 7])
        self.assertEqual(
            [u['base'] for u in row['rollback']], [0, 7])
        bad = copy.deepcopy(raw)
        bad['targets'][0]['erase_byte'] = True
        with self.assertRaises(ValueError):
            build_release_bundle(bad)


if __name__ == '__main__':
    unittest.main()
