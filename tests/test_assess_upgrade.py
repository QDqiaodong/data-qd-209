import copy
import json
import random
import unittest
from pathlib import Path

from obj_reloc import assess_upgrade, certify, link, process


def region(name='mem', base=0, size=100000):
    return {'name': name, 'base': base, 'size': size}


def section(name='text', region_name='mem', size=64, alignment=1):
    return {'name': name, 'region': region_name, 'size': size,
            'alignment': alignment}


def symbol(name, section_name='text', offset=0, binding='strong'):
    return {'name': name, 'section': section_name, 'offset': offset,
            'binding': binding}


def relocation(rid, offset=8, name='svc', scope='global', width=4,
               section_name='text', addend=0):
    return {'id': rid, 'section': section_name, 'offset': offset,
            'symbol': {'scope': scope, 'name': name},
            'addend': addend, 'width': width}


def obj(oid, sections=None, symbols=None, relocations=None):
    return {
        'id': oid,
        'sections': sections if sections is not None else [section()],
        'symbols': symbols or [],
        'relocations': relocations or [],
    }


def plan(objects, regions=None):
    return {'regions': regions if regions is not None else [region()],
            'objects': objects}


def consumer(cid, objects, policy='address'):
    return {'id': cid, 'objects': objects, 'binding_policy': policy}


def upgrade_input(current, candidate, consumers):
    return {'current': current, 'candidate': candidate,
            'consumers': consumers}


def by_consumer_id(result):
    return {item['id']: item for item in result['consumers']}


def details_by_identity(consumer_result):
    return {(d['object'], d['id']): d
            for d in consumer_result['relocations']}


class AssessUpgradeActionTests(unittest.TestCase):
    def test_address_and_provider_contracts_split_on_provider_switch(self):
        # 两个完整计划独立链接：pa 与 pb 被布局到同一目标地址，因此除
        # target.object 外，写入位置、目标地址、value 与 bytes 都相同。
        current = plan([
            obj('c', relocations=[relocation('r1')]),
            obj('pa', symbols=[symbol('svc')]),
        ])
        candidate = plan([
            obj('c', relocations=[relocation('r1')]),
            obj('pb', symbols=[symbol('svc')]),
        ])

        address_result = assess_upgrade(upgrade_input(
            current, candidate, [consumer('c1', ['c'], 'address')]))
        address_row = address_result['consumers'][0]
        self.assertEqual(address_row['action'], 'keep_running')

        provider_input = upgrade_input(
            current, candidate, [consumer('c1', ['c'], 'provider')])
        provider_result = assess_upgrade(provider_input)
        provider_row = provider_result['consumers'][0]
        self.assertEqual(provider_row['action'], 'rebind_required')
        # 只改变 binding_policy 时，比较明细必须完全不变，只是动作按新
        # 契约重新推导。
        self.assertEqual(address_row['relocations'],
                         provider_row['relocations'])

        for row in (address_row, provider_row):
            detail = row['relocations'][0]
            self.assertEqual((detail['object'], detail['id']), ('c', 'r1'))
            self.assertEqual(detail['status'], 'changed')
            self.assertEqual(detail['current']['target'],
                             {'object': 'pa', 'name': 'svc'})
            self.assertEqual(detail['candidate']['target'],
                             {'object': 'pb', 'name': 'svc'})
            self.assertEqual(detail['current']['write_address'],
                             detail['candidate']['write_address'])
            self.assertEqual(detail['current']['address'],
                             detail['candidate']['address'])
            self.assertEqual(detail['current']['bytes'],
                             detail['candidate']['bytes'])
            self.assertEqual(detail['changed_fields'], ['target'])
        expected_one = {
            'keep_running': 1, 'rebind_required': 0,
            'activate_new': 0, 'stop_removed': 0,
        }
        self.assertEqual(address_result['summary'], {
            **expected_one,
            'actions': expected_one,
            'consumers': 1, 'total': 1,
        })
        self.assertEqual(provider_result['summary']['rebind_required'], 1)

    def test_layout_move_changes_write_address_without_bytes_change(self):
        def sized_provider(size):
            return plan([
                obj('a', sections=[section(size=size)],
                    symbols=[symbol('base', offset=4)]),
                obj('c', relocations=[
                    relocation('r1', offset=0, name='base')]),
            ])

        current = sized_provider(16)   # c/text base=16, write_address=16
        candidate = sized_provider(32)  # c/text base=32, write_address=32
        for policy in ('address', 'provider'):
            result = assess_upgrade(upgrade_input(
                current, candidate, [consumer('c1', ['c'], policy)]))
            row = result['consumers'][0]
            self.assertEqual(row['action'], 'rebind_required')
            detail = row['relocations'][0]
            self.assertEqual(detail['status'], 'changed')
            self.assertEqual(detail['current']['target'],
                             detail['candidate']['target'])
            self.assertEqual(detail['current']['bytes'],
                             detail['candidate']['bytes'])
            self.assertEqual(detail['current']['write_address'], 16)
            self.assertEqual(detail['candidate']['write_address'], 32)
            self.assertEqual(detail['changed_fields'], ['write_address'])

    def test_bytes_change_requires_rebind_under_both_contracts(self):
        current = plan([obj('c', symbols=[symbol('svc', offset=4)],
                            relocations=[relocation('r1')])])
        candidate = plan([obj('c', symbols=[symbol('svc', offset=8)],
                              relocations=[relocation('r1')])])
        for policy in ('address', 'provider'):
            result = assess_upgrade(upgrade_input(
                current, candidate, [consumer('c1', ['c'], policy)]))
            row = result['consumers'][0]
            self.assertEqual(row['action'], 'rebind_required')
            detail = row['relocations'][0]
            self.assertEqual(detail['status'], 'changed')
            self.assertEqual(detail['current']['bytes'], [4, 0, 0, 0])
            self.assertEqual(detail['candidate']['bytes'], [8, 0, 0, 0])
            self.assertIn('address', detail['changed_fields'])
            self.assertIn('value', detail['changed_fields'])
            self.assertIn('bytes', detail['changed_fields'])

    def test_relocation_added_and_removed_require_rebind(self):
        current = plan([
            obj('c_add', relocations=[
                relocation('same', offset=0),
                relocation('gone', offset=8),
            ]),
            obj('p', symbols=[symbol('svc')]),
        ])
        candidate = plan([
            obj('c_add', relocations=[
                relocation('same', offset=0),
                relocation('fresh', offset=16),
            ]),
            obj('p', symbols=[symbol('svc')]),
        ])
        result = assess_upgrade(upgrade_input(current, candidate, [
            consumer('c-add', ['c_add'], 'address'),
        ]))
        row = result['consumers'][0]
        self.assertEqual(row['action'], 'rebind_required')
        details = details_by_identity(row)
        self.assertEqual(details[('c_add', 'same')]['status'], 'unchanged')
        self.assertEqual(details[('c_add', 'gone')]['status'], 'removed')
        self.assertIsNotNone(details[('c_add', 'gone')]['current'])
        self.assertIsNone(details[('c_add', 'gone')]['candidate'])
        self.assertEqual(details[('c_add', 'fresh')]['status'], 'added')
        self.assertIsNone(details[('c_add', 'fresh')]['current'])
        self.assertIsNotNone(details[('c_add', 'fresh')]['candidate'])

    def test_consumer_activate_stop_and_no_relocation_keep(self):
        current = plan([
            obj('old', relocations=[relocation('old-r', name='old-sym')],
                symbols=[symbol('old-sym')]),
            obj('stable', sections=[section(size=16)]),
        ])
        candidate = plan([
            obj('new', relocations=[relocation('new-r', name='new-sym')],
                symbols=[symbol('new-sym')]),
            obj('stable', sections=[section(size=16)]),
        ])
        result = assess_upgrade(upgrade_input(current, candidate, [
            consumer('new-consumer', ['new']),
            consumer('old-consumer', ['old']),
            consumer('quiet', ['stable'], 'provider'),
        ]))
        rows = by_consumer_id(result)
        self.assertEqual([r['id'] for r in result['consumers']],
                         ['new-consumer', 'old-consumer', 'quiet'])
        self.assertEqual(rows['new-consumer']['action'], 'activate_new')
        self.assertEqual(rows['old-consumer']['action'], 'stop_removed')
        self.assertEqual(rows['quiet']['action'], 'keep_running')
        self.assertEqual(
            [d['id'] for d in rows['new-consumer']['relocations']], ['new-r'])
        self.assertEqual(
            [d['id'] for d in rows['old-consumer']['relocations']], ['old-r'])
        self.assertEqual(rows['quiet']['relocations'], [])
        expected_three = {
            'keep_running': 1, 'rebind_required': 0,
            'activate_new': 1, 'stop_removed': 1,
        }
        self.assertEqual(result['summary'], {
            **expected_three,
            'actions': expected_three,
            'consumers': 3, 'total': 3,
        })

    def test_partial_object_addition_among_shared_objects_requires_rebind(self):
        current = plan([
            obj('shared', relocations=[relocation('r1', name='glob')]),
            obj('p', symbols=[symbol('glob')]),
            obj('old_only'),
        ])
        candidate = plan([
            obj('shared', relocations=[relocation('r1', name='glob')]),
            obj('p', symbols=[symbol('glob')]),
            obj('new_only'),
        ])
        # shared + candidate-only：不是 activate_new；当新对象带新增
        # relocation 身份时必须 rebind。
        with_reloc_candidate = copy.deepcopy(candidate)
        with_reloc_candidate['objects'][2]['relocations'] = [
            relocation('added', offset=0, name='added_sym')]
        with_reloc_candidate['objects'][2]['symbols'] = [
            symbol('added_sym')]
        result = assess_upgrade(upgrade_input(
            current, with_reloc_candidate,
            [consumer('c1', ['shared', 'new_only'], 'address')]))
        self.assertEqual(result['consumers'][0]['action'], 'rebind_required')

        # 新对象没有 relocation 时，relocation 身份集合仍相同，address
        # 契约可继续运行。
        quiet_result = assess_upgrade(upgrade_input(
            current, candidate,
            [consumer('c1', ['shared', 'new_only'], 'address')]))
        self.assertEqual(quiet_result['consumers'][0]['action'],
                         'keep_running')

    def test_mixed_added_and_removed_objects_rejected(self):
        current = plan([obj('old_only'), obj('shared')])
        candidate = plan([obj('new_only'), obj('shared')])
        bad = upgrade_input(current, candidate,
                            [consumer('mixed', ['old_only', 'new_only'])])
        with self.assertRaises(ValueError):
            assess_upgrade(bad)

        bad_with_shared = upgrade_input(current, candidate, [
            consumer('mixed', ['old_only', 'new_only', 'shared'])])
        with self.assertRaises(ValueError):
            assess_upgrade(bad_with_shared)


class AssessUpgradeValidationAndOrderTests(unittest.TestCase):
    def valid_input(self):
        current = plan([
            obj('z', relocations=[relocation('r2', offset=16),
                                  relocation('r1', offset=8)]),
            obj('a', symbols=[symbol('svc')]),
        ])
        candidate = copy.deepcopy(current)
        return upgrade_input(current, candidate, [
            consumer('c2', ['a'], 'provider'),
            consumer('c1', ['z']),
        ])

    def test_current_and_candidate_summaries_come_from_link(self):
        data = self.valid_input()
        result = assess_upgrade(data)
        self.assertEqual(result['current'], link(data['current'])['summary'])
        self.assertEqual(result['candidate'],
                         link(data['candidate'])['summary'])

    def test_relocations_sorted_by_object_and_id(self):
        result = assess_upgrade(self.valid_input())
        row = by_consumer_id(result)['c1']
        self.assertEqual([(d['object'], d['id'])
                          for d in row['relocations']],
                         [('z', 'r1'), ('z', 'r2')])

    def test_input_permutations_do_not_change_output(self):
        data = self.valid_input()
        # 增加一个新增 consumer，使排序与数组重排覆盖更多动作。
        data['candidate']['objects'].append(obj('new'))
        data['consumers'].append(consumer('c3', ['new']))
        baseline = assess_upgrade(copy.deepcopy(data))

        rng = random.Random(20261124)
        for _ in range(5):
            variant = copy.deepcopy(data)
            rng.shuffle(variant['consumers'])
            for c in variant['consumers']:
                rng.shuffle(c['objects'])
            for side in ('current', 'candidate'):
                rng.shuffle(variant[side]['regions'])
                rng.shuffle(variant[side]['objects'])
                for o in variant[side]['objects']:
                    rng.shuffle(o['sections'])
                    rng.shuffle(o['symbols'])
                    rng.shuffle(o['relocations'])
            self.assertEqual(assess_upgrade(variant), baseline)

    def test_consumer_validation_rejects_invalid_inputs(self):
        good = self.valid_input()

        def reject(mutate):
            bad = copy.deepcopy(good)
            mutate(bad)
            with self.assertRaises(ValueError):
                assess_upgrade(bad)

        reject(lambda d: d.update(unknown=1))
        reject(lambda d: d.pop('current'))
        reject(lambda d: d.update(current='not-a-plan'))
        reject(lambda d: d['consumers'].append(
            consumer('c1', ['z'])))  # 重复 consumer id
        reject(lambda d: d['consumers'].append(
            consumer('bad id!', ['z'])))
        reject(lambda d: d['consumers'][0].update(id='bad!'))
        reject(lambda d: d['consumers'][0].update(objects=[]))
        reject(lambda d: d['consumers'][0].update(objects=['z', 'z']))
        reject(lambda d: d['consumers'][0].update(binding_policy='dynamic'))
        reject(lambda d: d['consumers'][0].update(extra=1))
        reject(lambda d: d['consumers'].append(
            consumer('c3', ['nope'])))  # 两侧都不存在
        reject(lambda d: d['consumers'].append(
            consumer('c3', ['a'])))  # a 已属于 c2
        # 跨 consumer 重复归属同样拒绝。
        data = self.valid_input()
        data['consumers'] = [consumer('c1', ['z']),
                             consumer('c2', ['z'], 'provider')]
        with self.assertRaises(ValueError):
            assess_upgrade(data)

    def test_object_cannot_belong_to_two_consumers(self):
        data = upgrade_input(
            plan([obj('z')]), plan([obj('z')]),
            [consumer('c1', ['z']), consumer('c2', ['z'])])
        with self.assertRaises(ValueError):
            assess_upgrade(data)

    def test_either_plan_link_failure_rejects_whole_input(self):
        good = self.valid_input()

        bad_current = copy.deepcopy(good)
        bad_current['current']['regions'][0]['base'] = 10_000_000
        with self.assertRaises(ValueError):
            assess_upgrade(bad_current)

        bad_candidate = copy.deepcopy(good)
        bad_candidate['candidate']['objects'][0]['id'] = 'duped'
        bad_candidate['candidate']['objects'][1]['id'] = 'duped'
        with self.assertRaises(ValueError):
            assess_upgrade(bad_candidate)

        bad_identity = copy.deepcopy(good)
        bad_identity['current']['objects'][0]['id'] = 'bad id!'
        with self.assertRaises(ValueError):
            assess_upgrade(bad_identity)

        bad_reference = copy.deepcopy(good)
        bad_reference['candidate']['objects'][0]['relocations'][0][
            'symbol']['name'] = 'missing'
        with self.assertRaises(ValueError):
            assess_upgrade(bad_reference)

    def test_consumer_capacity_limits(self):
        # link 计划最多 32 个对象，且对象不能跨 consumer 重复归属，因此
        # 可成功评估的唯一对象 consumer 最多为 32；256 是输入数组自身上限。
        current = plan([obj('o%d' % i) for i in range(32)])
        candidate = copy.deepcopy(current)
        consumers = [consumer('c%d' % i, ['o%d' % i]) for i in range(32)]
        result = assess_upgrade(upgrade_input(current, candidate, consumers))
        self.assertEqual(result['summary']['consumers'], 32)
        self.assertEqual(result['summary']['total'], 32)
        self.assertEqual(result['summary']['actions']['keep_running'], 32)

        too_many = [consumer('c%d' % i, ['o0']) for i in range(257)]
        with self.assertRaises(ValueError):
            assess_upgrade(upgrade_input(current, candidate, too_many))

        with self.assertRaises(ValueError):
            assess_upgrade(upgrade_input(
                current, candidate,
                [consumer('wide', ['o%d' % i for i in range(33)])]))


class ExistingApisRemainCompatibleTests(unittest.TestCase):
    def test_process_link_certify_and_assess_exports(self):
        fixture = json.loads(
            Path(__file__).resolve().parents[1].joinpath(
                'fixtures/input.json').read_text())
        processed = process(fixture)
        self.assertEqual(processed['symbols']['msg']['address'], 8194)
        self.assertEqual(processed['relocations'][0]['bytes'], [2, 32])
        with self.assertRaises(ValueError):
            process(dict(fixture, extra=1))

        linked = link({
            'regions': [region()],
            'objects': [obj('fw', symbols=[symbol('entry', offset=4)],
                            relocations=[relocation('r1', name='entry')])],
        })
        self.assertEqual(linked['relocations'][0]['bytes'],
                         [4, 0, 0, 0])

        certification = certify({
            'plan': {
                'regions': [region()],
                'objects': [obj('fw', symbols=[symbol('entry', offset=4)],
                                relocations=[relocation('r1', name='entry')])],
            },
            'collectors': [{'id': 'col1', 'group': 'g1',
                             'valid_from': 0, 'valid_to': 1000}],
            'targets': [{'id': 't1'}],
            'captures': [{
                'id': 'cap1', 'target': 't1', 'collector': 'col1',
                'observed_at': 10,
                'ranges': [{'base': 8, 'bytes': [4, 0, 0, 0]}],
            }],
            'requests': [{'id': 'q1', 'target': 't1', 'as_of': 100,
                          'min_collectors': 1, 'min_groups': 1}],
        })
        self.assertEqual(certification['requests'][0]['status'], 'certified')
        self.assertTrue(callable(assess_upgrade))


if __name__ == '__main__':
    unittest.main()
