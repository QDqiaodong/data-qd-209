import copy
import hashlib
import json
import random
import unittest
from pathlib import Path

from obj_reloc import certify, link, process


def base_plan():
    # section text 基址 0，符号 entry 地址 4，relocation r1 写地址 8，期望字节 [4, 0, 0, 0]
    return {
        'regions': [{'name': 'mem', 'base': 0, 'size': 100000}],
        'objects': [{
            'id': 'fw',
            'sections': [{'name': 'text', 'region': 'mem', 'size': 64, 'alignment': 1}],
            'symbols': [{'name': 'entry', 'section': 'text', 'offset': 4, 'binding': 'strong'}],
            'relocations': [{'id': 'r1', 'section': 'text', 'offset': 8,
                             'symbol': {'scope': 'global', 'name': 'entry'},
                             'addend': 0, 'width': 4}],
        }],
    }


def two_reloc_plan():
    # r1: 地址 8 字节 [4,0,0,0]；r2: 地址 16 字节 [20,0]
    plan = base_plan()
    plan['objects'][0]['symbols'].append(
        {'name': 'msg', 'section': 'text', 'offset': 20, 'binding': 'strong'})
    plan['objects'][0]['relocations'].append(
        {'id': 'r2', 'section': 'text', 'offset': 16,
         'symbol': {'scope': 'global', 'name': 'msg'}, 'addend': 0, 'width': 2})
    return plan


def empty_plan():
    plan = base_plan()
    plan['objects'][0]['relocations'] = []
    return plan


def collector(cid, group='g1', valid_from=0, valid_to=1000):
    return {'id': cid, 'group': group,
            'valid_from': valid_from, 'valid_to': valid_to}


def capture(cid, target, collector_id, observed_at, ranges):
    return {'id': cid, 'target': target, 'collector': collector_id,
            'observed_at': observed_at,
            'ranges': [{'base': b, 'bytes': list(bs)} for b, bs in ranges]}


def request(qid, target='t1', as_of=100, min_collectors=1, min_groups=1):
    return {'id': qid, 'target': target, 'as_of': as_of,
            'min_collectors': min_collectors, 'min_groups': min_groups}


def make_input(plan=None, collectors=None, targets=None, captures=None,
               requests=None):
    return {
        'plan': copy.deepcopy(plan if plan is not None else base_plan()),
        'collectors': collectors if collectors is not None else [collector('c1')],
        'targets': targets if targets is not None else [{'id': 't1'}],
        'captures': captures if captures is not None else [],
        'requests': requests if requests is not None else [request('q1')],
    }


def full_match(cap_id='cap1', cid='c1', observed_at=10, target='t1'):
    return capture(cap_id, target, cid, observed_at, [(8, [4, 0, 0, 0])])


def requests_by_id(result):
    return {q['id']: q for q in result['requests']}


def canonical_certificate_id(cert):
    body = {k: v for k, v in cert.items() if k != 'certificate_id'}
    canonical = json.dumps(body, ensure_ascii=True, sort_keys=True,
                           separators=(',', ':'))
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


class CertifySemanticsTests(unittest.TestCase):
    def test_cross_range_assembly_completes_readback(self):
        # 单份 capture 的多个 ranges 拼成完整读回
        data = make_input(captures=[
            capture('cap1', 't1', 'c1', 50, [(8, [4, 0]), (10, [0, 0])])])
        r = certify(data)
        q = r['requests'][0]
        self.assertEqual(q['status'], 'certified')
        rel = q['relocations'][0]
        self.assertEqual(rel['status'], 'certified')
        self.assertEqual([e['collector'] for e in rel['match']], ['c1'])
        self.assertEqual(rel['match'][0]['observed'], [4, 0, 0, 0])
        self.assertEqual(rel['threshold'],
                         {'min_collectors': 1, 'min_groups': 1,
                          'match_collectors': 1, 'match_groups': 1, 'met': True})
        # plan 段给出 link summary 与预期写入地址/字节
        self.assertEqual(r['plan']['summary'], link(base_plan())['summary'])
        self.assertEqual(r['plan']['relocations'][0]['address'], 8)
        self.assertEqual(r['plan']['relocations'][0]['bytes'], [4, 0, 0, 0])
        # certificate 内容与 certificate_id 规范形
        cert = q['certificate']
        self.assertEqual(cert['request'], 'q1')
        self.assertEqual(cert['target'], 't1')
        self.assertEqual(cert['as_of'], 100)
        self.assertEqual(cert['min_collectors'], 1)
        self.assertEqual(cert['min_groups'], 1)
        self.assertEqual(cert['relocations'][0]['witnesses'],
                         [{'collector': 'c1', 'group': 'g1', 'capture': 'cap1'}])
        self.assertEqual(cert['relocations'][0]['bytes'], [4, 0, 0, 0])
        self.assertEqual(cert['certificate_id'], canonical_certificate_id(cert))
        self.assertEqual(r['summary']['certified'], 1)
        self.assertEqual(r['summary']['requests']['certified'], 1)

    def test_latest_partial_capture_not_backfilled(self):
        # 最新 capture 只有部分覆盖时，不得用旧 complete capture 回填
        data = make_input(captures=[
            capture('cap_old', 't1', 'c1', 10, [(8, [4, 0, 0, 0])]),
            capture('cap_new', 't1', 'c1', 20, [(8, [4, 0])]),
        ])
        r = certify(data)
        q = r['requests'][0]
        self.assertEqual(q['status'], 'insufficient')
        self.assertNotIn('certificate', q)
        rel = q['relocations'][0]
        self.assertEqual(rel['match'], [])
        self.assertEqual([e['capture'] for e in rel['incomplete']], ['cap_new'])
        self.assertEqual(rel['incomplete'][0]['observed'], [4, 0, None, None])

    def test_no_cross_collector_or_cross_capture_assembly(self):
        # 两个 collector 各读一半，不得混拼
        data = make_input(
            collectors=[collector('c1'), collector('c2', 'g2')],
            captures=[
                capture('cap1', 't1', 'c1', 10, [(8, [4, 0])]),
                capture('cap2', 't1', 'c2', 10, [(10, [0, 0])]),
            ])
        r = certify(data)
        self.assertEqual(r['requests'][0]['status'], 'insufficient')
        self.assertEqual(len(r['requests'][0]['relocations'][0]['incomplete']), 2)
        # 同一 collector 的新旧 capture 各读一半，同样不得混拼
        data2 = make_input(captures=[
            capture('cap1', 't1', 'c1', 10, [(8, [4, 0])]),
            capture('cap2', 't1', 'c1', 20, [(10, [0, 0])]),
        ])
        r2 = certify(data2)
        self.assertEqual(r2['requests'][0]['status'], 'insufficient')
        rel = r2['requests'][0]['relocations'][0]
        self.assertEqual([e['capture'] for e in rel['incomplete']], ['cap2'])
        self.assertEqual(rel['incomplete'][0]['observed'], [None, None, 0, 0])

    def test_collector_validity_window_at_as_of(self):
        # 采集时有效，但 as_of 已失效的 collector 不可用
        data = make_input(
            collectors=[collector('c1', valid_from=0, valid_to=100)],
            captures=[full_match(observed_at=50)],
            requests=[request('q_early', as_of=60),
                      request('q_edge', as_of=100),
                      request('q_late', as_of=150)],
        )
        r = certify(data)
        by_id = requests_by_id(r)
        self.assertEqual(by_id['q_early']['status'], 'certified')
        # as_of == valid_to 时已不在 [valid_from, valid_to) 内
        self.assertEqual(by_id['q_edge']['status'], 'insufficient')
        self.assertEqual(by_id['q_late']['status'], 'insufficient')
        late_rel = by_id['q_late']['relocations'][0]
        self.assertEqual(late_rel['match'], [])
        self.assertEqual(late_rel['incomplete'], [])
        self.assertEqual(late_rel['mismatch'], [])

    def test_same_group_collectors_not_independent(self):
        data = make_input(
            collectors=[collector('c1', 'g1'), collector('c2', 'g1')],
            captures=[full_match('cap1', 'c1'), full_match('cap2', 'c2')],
            requests=[request('q1', min_collectors=2, min_groups=2),
                      request('q2', min_collectors=2, min_groups=1)],
        )
        r = certify(data)
        by_id = requests_by_id(r)
        rel = by_id['q1']['relocations'][0]
        self.assertEqual(rel['status'], 'insufficient')
        self.assertEqual(rel['threshold']['match_collectors'], 2)
        self.assertEqual(rel['threshold']['match_groups'], 1)
        self.assertFalse(rel['threshold']['met'])
        self.assertEqual(by_id['q1']['status'], 'insufficient')
        self.assertNotIn('certificate', by_id['q1'])
        self.assertEqual(by_id['q2']['status'], 'certified')
        self.assertEqual(by_id['q2']['certificate']['relocations'][0]['witnesses'],
                         [{'collector': 'c1', 'group': 'g1', 'capture': 'cap1'},
                          {'collector': 'c2', 'group': 'g1', 'capture': 'cap2'}])

    def test_mismatch_blocks_certification(self):
        # 足够 match 中夹有 mismatch -> conflict，不签发
        data = make_input(
            collectors=[collector('c1', 'g1'), collector('c2', 'g2'),
                        collector('c3', 'g3')],
            captures=[
                full_match('cap1', 'c1'),
                full_match('cap2', 'c2'),
                capture('cap3', 't1', 'c3', 10, [(8, [4, 0, 0, 255])]),
            ],
            requests=[request('q1', min_collectors=2, min_groups=2)],
        )
        r = certify(data)
        q = r['requests'][0]
        self.assertEqual(q['status'], 'conflict')
        self.assertNotIn('certificate', q)
        rel = q['relocations'][0]
        self.assertEqual(rel['status'], 'conflict')
        self.assertEqual([e['collector'] for e in rel['match']], ['c1', 'c2'])
        self.assertEqual(len(rel['mismatch']), 1)
        bad = rel['mismatch'][0]
        self.assertEqual(bad['collector'], 'c3')
        self.assertEqual(bad['capture'], 'cap3')
        self.assertEqual(bad["observed"], [4, 0, 0, 255])
        # 只有 mismatch 没有 match -> mismatch
        data2 = make_input(captures=[
            capture('cap1', 't1', 'c1', 10, [(8, [9, 9, 9, 9])])])
        r2 = certify(data2)
        self.assertEqual(r2['requests'][0]['status'], 'mismatch')
        rel2 = r2['requests'][0]['relocations'][0]
        self.assertEqual(rel2['status'], 'mismatch')
        self.assertEqual(rel2['match'], [])
        self.assertEqual(rel2['mismatch'][0]['observed'], [9, 9, 9, 9])
        # 部分覆盖中出现不同字节同样是 mismatch
        data3 = make_input(captures=[
            capture('cap1', 't1', 'c1', 10, [(9, [7])])])
        r3 = certify(data3)
        self.assertEqual(r3['requests'][0]['status'], 'mismatch')
        self.assertEqual(r3['requests'][0]['relocations'][0]
                         ['mismatch'][0]['observed'], [None, 7, None, None])

    def test_zero_relocations_not_certified(self):
        data = make_input(plan=empty_plan(),
                          captures=[full_match()],
                          requests=[request('q1'), request('q2', as_of=5)])
        r = certify(data)
        self.assertEqual(r['plan']['relocations'], [])
        for q in r['requests']:
            self.assertEqual(q['status'], 'no_relocations')
            self.assertEqual(q['relocations'], [])
            self.assertNotIn('certificate', q)
        self.assertEqual(r['summary']['requests']['no_relocations'], 2)
        self.assertEqual(r['summary']['certified'], 0)
        self.assertEqual(r['summary']['total'], 2)

    def test_as_of_selects_historical_captures(self):
        # 同一 collector 不同 as_of 取到不同历史版本
        data = make_input(
            captures=[
                capture('cap_bad', 't1', 'c1', 100, [(8, [9, 9, 9, 9])]),
                capture('cap_good', 't1', 'c1', 200, [(8, [4, 0, 0, 0])]),
            ],
            requests=[request('q1', as_of=150),
                      request('q2', as_of=250),
                      request('q3', as_of=50)],
        )
        r = certify(data)
        by_id = requests_by_id(r)
        self.assertEqual(by_id['q1']['status'], 'mismatch')
        self.assertEqual(by_id['q1']['relocations'][0]['mismatch'][0]['capture'],
                         'cap_bad')
        self.assertEqual(by_id['q2']['status'], 'certified')
        self.assertEqual(by_id['q2']['certificate']['relocations'][0]
                         ['witnesses'][0]['capture'], 'cap_good')
        self.assertEqual(by_id['q3']['status'], 'insufficient')
        self.assertEqual(r['summary']['requests'],
                         {'certified': 1, 'no_relocations': 0,
                          'insufficient': 1, 'mismatch': 1, 'conflict': 0})

    def test_witness_selection_groups_then_fill(self):
        # 先保证 min_groups 个不同 group，再按 (group, collector) 补足 min_collectors
        data = make_input(
            collectors=[collector('c1', 'g1'), collector('c2', 'g1'),
                        collector('c3', 'g2'), collector('c4', 'g3')],
            captures=[full_match('cap1', 'c1'), full_match('cap2', 'c2'),
                      full_match('cap3', 'c3'), full_match('cap4', 'c4')],
            requests=[request('q1', min_collectors=3, min_groups=2)],
        )
        r = certify(data)
        q = r['requests'][0]
        self.assertEqual(q['status'], 'certified')
        witnesses = q['certificate']['relocations'][0]['witnesses']
        self.assertEqual(witnesses,
                         [{'collector': 'c1', 'group': 'g1', 'capture': 'cap1'},
                          {'collector': 'c2', 'group': 'g1', 'capture': 'cap2'},
                          {'collector': 'c3', 'group': 'g2', 'capture': 'cap3'}])
        # 多余 match 不写入证书
        self.assertNotIn('c4', {w['collector'] for w in witnesses})

    def test_every_relocation_must_pass(self):
        data = make_input(
            plan=two_reloc_plan(),
            collectors=[collector('c1', 'g1'), collector('c2', 'g2')],
            captures=[
                capture('cap1', 't1', 'c1', 10, [(8, [4, 0, 0, 0])]),
                capture('cap2', 't1', 'c2', 10, [(16, [20, 0])]),
            ],
        )
        r = certify(data)
        q = r['requests'][0]
        self.assertEqual(q['status'], 'certified')
        rels = {rel['id']: rel for rel in q['relocations']}
        self.assertEqual(rels['r1']['status'], 'certified')
        self.assertEqual(rels['r2']['status'], 'certified')
        # r1 的 witness 是 c1，r2 的 witness 是 c2；另一条 relocation 对彼此是 incomplete
        cert_rels = q['certificate']['relocations']
        self.assertEqual([rel['id'] for rel in cert_rels], ['r1', 'r2'])
        self.assertEqual(cert_rels[0]['witnesses'][0]['collector'], 'c1')
        self.assertEqual(cert_rels[1]['witnesses'][0]['collector'], 'c2')
        self.assertEqual(rels['r1']['incomplete'][0]['collector'], 'c2')
        self.assertEqual(rels['r2']['incomplete'][0]['collector'], 'c1')
        # 任一 relocation 未通过则整单不签发
        data2 = make_input(
            plan=two_reloc_plan(),
            captures=[capture('cap1', 't1', 'c1', 10, [(8, [4, 0, 0, 0])])],
        )
        r2 = certify(data2)
        q2 = r2['requests'][0]
        self.assertEqual(q2['status'], 'insufficient')
        self.assertNotIn('certificate', q2)
        self.assertEqual(q2['relocations'][0]['status'], 'certified')
        self.assertEqual(q2['relocations'][1]['status'], 'insufficient')

    def test_targets_are_isolated(self):
        data = make_input(
            targets=[{'id': 't1'}, {'id': 't2'}],
            captures=[full_match('cap1', 'c1', target='t1')],
            requests=[request('q1', target='t1'), request('q2', target='t2')],
        )
        r = certify(data)
        by_id = requests_by_id(r)
        self.assertEqual(by_id['q1']['status'], 'certified')
        self.assertEqual(by_id['q2']['status'], 'insufficient')
        self.assertEqual(by_id['q2']['relocations'][0]['match'], [])

    def test_empty_ranges_capture_is_incomplete(self):
        data = make_input(captures=[capture('cap1', 't1', 'c1', 10, [])])
        r = certify(data)
        rel = r['requests'][0]['relocations'][0]
        self.assertEqual(r['requests'][0]['status'], 'insufficient')
        self.assertEqual(rel['incomplete'][0]['observed'],
                         [None, None, None, None])

    def test_determinism_under_permutation_and_extra_evidence(self):
        collectors = [
            collector('c1', 'g1'), collector('c2', 'g2'),
            collector('c3', 'g3'),   # 只有 incomplete 证据
            collector('c4', 'g4'),   # 多余 match，不进证书
        ]
        targets = [{'id': 't1'}, {'id': 't2'}]
        captures = [
            capture('cap1', 't1', 'c1', 10, [(8, [4, 0, 0, 0])]),
            capture('cap2', 't1', 'c2', 20, [(8, [4, 0]), (10, [0, 0])]),
            capture('cap3', 't1', 'c3', 30, [(8, [4, 0])]),
            capture('cap4', 't1', 'c4', 40, [(8, [4, 0, 0, 0])]),
            capture('cap5', 't2', 'c1', 50, [(8, [1, 2, 3, 4])]),
            capture('cap6', 't1', 'c1', 5, [(8, [7, 7, 7, 7])]),  # 被 cap1 取代
        ]
        requests = [
            request('q1', target='t1', as_of=100, min_collectors=2, min_groups=2),
            request('q2', target='t2', as_of=100),
        ]
        data = make_input(collectors=collectors, targets=targets,
                          captures=captures, requests=requests)
        baseline = certify(data)
        q1 = requests_by_id(baseline)['q1']
        self.assertEqual(q1['status'], 'certified')
        self.assertEqual([w['collector'] for w in
                          q1['certificate']['relocations'][0]['witnesses']],
                         ['c1', 'c2'])
        self.assertEqual(requests_by_id(baseline)['q2']['status'], 'mismatch')

        # 仅重排各输入数组（含 plan 内部与 capture 的 ranges），结果逐字节一致
        rng = random.Random(20261124)
        for _ in range(3):
            variant = copy.deepcopy(data)
            rng.shuffle(variant['collectors'])
            rng.shuffle(variant['targets'])
            rng.shuffle(variant['captures'])
            rng.shuffle(variant['requests'])
            rng.shuffle(variant['plan']['regions'])
            rng.shuffle(variant['plan']['objects'])
            for o in variant['plan']['objects']:
                rng.shuffle(o['sections'])
                rng.shuffle(o['symbols'])
                rng.shuffle(o['relocations'])
            for cap in variant['captures']:
                rng.shuffle(cap['ranges'])
            self.assertEqual(certify(variant), baseline)

        # 去掉无关/多余证据后 certificate 与 certificate_id 不变
        minimal = make_input(
            collectors=[collector('c1', 'g1'), collector('c2', 'g2')],
            captures=[
                capture('cap1', 't1', 'c1', 10, [(8, [4, 0, 0, 0])]),
                capture('cap2', 't1', 'c2', 20, [(8, [4, 0]), (10, [0, 0])]),
            ],
            requests=[request('q1', target='t1', as_of=100,
                              min_collectors=2, min_groups=2)],
        )
        stripped = certify(minimal)
        self.assertEqual(stripped['requests'][0]['certificate'],
                         q1['certificate'])
        self.assertEqual(stripped['requests'][0]['certificate']['certificate_id'],
                         q1['certificate']['certificate_id'])


class CertifyRejectionTests(unittest.TestCase):
    def assert_rejected(self, data):
        with self.assertRaises(ValueError):
            certify(data)

    def test_top_level_and_plan_rejections(self):
        good = make_input(captures=[full_match()])
        self.assert_rejected(dict(good, extra=1))
        self.assert_rejected({k: v for k, v in good.items() if k != 'plan'})
        self.assert_rejected(make_input(plan=dict(base_plan(), unknown=1)))
        self.assert_rejected(make_input(plan={'regions': [], 'objects': []}))
        bad_plan = base_plan()
        bad_plan['objects'][0]['relocations'][0]['width'] = 1
        bad_plan['objects'][0]['relocations'][0]['addend'] = 300  # link 溢出拒绝
        self.assert_rejected(make_input(plan=bad_plan))
        self.assert_rejected(make_input(plan=None) | {'plan': 'not-a-dict'})

    def test_collector_rejections(self):
        self.assert_rejected(make_input(collectors=[]))
        self.assert_rejected(make_input(
            collectors=[collector('c1'), collector('c1')]))
        self.assert_rejected(make_input(
            collectors=[collector('c1', valid_from=10, valid_to=10)]))
        self.assert_rejected(make_input(
            collectors=[collector('c1', valid_from=20, valid_to=10)]))
        self.assert_rejected(make_input(
            collectors=[collector('c1', valid_from=True)]))
        self.assert_rejected(make_input(
            collectors=[collector('c1', valid_to=1_000_000_001)]))
        self.assert_rejected(make_input(
            collectors=[collector('c1', group='bad group!')]))
        self.assert_rejected(make_input(
            collectors=[dict(collector('c1'), extra=1)]))
        too_many = [collector('c%d' % i, 'g%d' % i) for i in range(65)]
        self.assert_rejected(make_input(collectors=too_many))

    def test_target_rejections(self):
        self.assert_rejected(make_input(targets=[]))
        self.assert_rejected(make_input(targets=[{'id': 't1'}, {'id': 't1'}]))
        self.assert_rejected(make_input(targets=[{'id': 'bad id!'}]))
        self.assert_rejected(make_input(targets=[{'id': 't1', 'x': 1}]))
        too_many = [{'id': 't%d' % i} for i in range(33)]
        self.assert_rejected(make_input(targets=too_many))

    def test_capture_rejections(self):
        ok = full_match()
        self.assert_rejected(make_input(captures=[ok, ok]))  # 重复 id
        self.assert_rejected(make_input(captures=[
            capture('cap1', 'nope', 'c1', 10, [])]))  # 未知 target
        self.assert_rejected(make_input(captures=[
            capture('cap1', 't1', 'nope', 10, [])]))  # 未知 collector
        self.assert_rejected(make_input(
            collectors=[collector('c1', valid_from=0, valid_to=10)],
            captures=[capture('cap1', 't1', 'c1', 10, [])]))  # 超出有效期
        # 同一 (target, collector, observed_at) 不得重复
        self.assert_rejected(make_input(captures=[
            capture('cap1', 't1', 'c1', 10, []),
            capture('cap2', 't1', 'c1', 10, []),
        ]))
        self.assert_rejected(make_input(captures=[
            capture('cap1', 't1', 'c1', True, [])]))  # bool 充当整数
        self.assert_rejected(make_input(captures=[
            capture('cap1', 't1', 'c1', 10, [(True, [1])])]))  # base 为 bool
        self.assert_rejected(make_input(captures=[
            capture('cap1', 't1', 'c1', 10, [(8, [256])])]))  # 非法字节
        self.assert_rejected(make_input(captures=[
            capture('cap1', 't1', 'c1', 10, [(8, [True])])]))  # bool 字节
        self.assert_rejected(make_input(captures=[
            capture('cap1', 't1', 'c1', 10, [(8, [])])]))  # 空 bytes
        self.assert_rejected(make_input(captures=[
            capture('cap1', 't1', 'c1', 10, [(8, [0] * 4097)])]))  # bytes 超长
        self.assert_rejected(make_input(captures=[
            capture('cap1', 't1', 'c1', 10, [(200000, [1])])]))  # 出 plan region
        self.assert_rejected(make_input(captures=[
            capture('cap1', 't1', 'c1', 10, [(99996, [0] * 8)])]))  # 部分越界
        self.assert_rejected(make_input(captures=[
            capture('cap1', 't1', 'c1', 10, [(8, [1, 1]), (9, [1])])]))  # 区间重叠
        self.assert_rejected(make_input(captures=[
            capture('cap1', 't1', 'c1', 10, [(i * 4, [0]) for i in range(129)])]))
        self.assert_rejected(make_input(captures=[
            dict(capture('cap1', 't1', 'c1', 10, []), extra=1)]))
        self.assert_rejected(make_input(captures=[
            {'id': 'cap1', 'target': 't1', 'collector': 'c1', 'observed_at': 10,
             'ranges': [{'base': 8, 'bytes': [1], 'extra': 1}]}]))

    def test_capture_range_must_not_cross_regions(self):
        plan = base_plan()
        plan['regions'] = [{'name': 'mem', 'base': 0, 'size': 1000},
                           {'name': 'mem2', 'base': 1000, 'size': 1000}]
        # 端点相接的两个 region 也不得跨
        self.assert_rejected(make_input(
            plan=plan,
            captures=[capture('cap1', 't1', 'c1', 10, [(500, [0] * 600)])]))
        # 完全落在任一 region 内则合法
        r = certify(make_input(
            plan=plan,
            captures=[capture('cap1', 't1', 'c1', 10, [(500, [0] * 500)])]))
        self.assertEqual(r['requests'][0]['status'], 'insufficient')

    def test_adjacent_ranges_allowed(self):
        # 半开区间端点相接不算重叠
        data = make_input(captures=[
            capture('cap1', 't1', 'c1', 10, [(8, [4, 0]), (10, [0, 0])])])
        self.assertEqual(certify(data)['requests'][0]['status'], 'certified')

    def test_request_rejections(self):
        self.assert_rejected(make_input(requests=[]))
        self.assert_rejected(make_input(
            requests=[request('q1'), request('q1')]))
        self.assert_rejected(make_input(requests=[request('q1', target='nope')]))
        self.assert_rejected(make_input(
            requests=[request('q1', min_collectors=0)]))
        self.assert_rejected(make_input(
            requests=[request('q1', min_collectors=65)]))
        self.assert_rejected(make_input(
            requests=[request('q1', min_collectors=2, min_groups=3)]))
        self.assert_rejected(make_input(requests=[request('q1', as_of=-1)]))
        self.assert_rejected(make_input(requests=[request('q1', as_of=True)]))
        self.assert_rejected(make_input(
            requests=[dict(request('q1'), extra=1)]))
        too_many = [request('q%d' % i) for i in range(2001)]
        self.assert_rejected(make_input(requests=too_many))

    def test_capacity_limits(self):
        # captures 总数上限 20000
        many = [capture('cap%d' % i, 't1', 'c1', i + 1, [])
                for i in range(20001)]
        self.assert_rejected(make_input(
            collectors=[collector('c1', valid_from=0, valid_to=30000)],
            captures=many))
        # 全部 capture bytes 合计上限 4_000_000
        big = [0] * 4096
        captures = []
        for i in range(41):  # 41 * 24 * 4096 = 4_030_464 > 4_000_000
            ranges = [(base, big) for base in range(0, 98304, 4096)]
            captures.append(capture('cap%d' % i, 't1', 'c1', i + 1, ranges))
        self.assert_rejected(make_input(
            collectors=[collector('c1', valid_from=0, valid_to=30000)],
            captures=captures))
        # 恰好 4_000_000 字节则接受
        captures = []
        remaining = 4_000_000
        i = 0
        while remaining:
            take = min(24 * 4096, remaining)
            spans = []
            offset = 0
            left = take
            while left:
                n = min(4096, left)
                spans.append((offset, [0] * n))
                offset += n
                left -= n
            captures.append(capture('cap%d' % i, 't1', 'c1', i + 1, spans))
            remaining -= take
            i += 1
        r = certify(make_input(
            collectors=[collector('c1', valid_from=0, valid_to=30000)],
            captures=captures))
        self.assertEqual(r['summary']['total'], 1)


class ExistingContractTests(unittest.TestCase):
    def test_process_and_link_contracts_still_hold(self):
        fixture = json.loads(Path('fixtures/input.json').read_text())
        r = process(fixture)
        self.assertEqual(r['symbols']['msg']['address'], 8194)
        self.assertEqual(r['relocations'][0]['bytes'], [2, 32])
        with self.assertRaises(ValueError):
            process(dict(fixture, extra=1))
        linked = link(base_plan())
        self.assertEqual(linked['relocations'][0]['bytes'], [4, 0, 0, 0])
        self.assertTrue(callable(certify))


if __name__ == '__main__':
    unittest.main()
