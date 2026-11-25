import copy
import json
import random
import unittest
from pathlib import Path

import obj_reloc
from obj_reloc import (
    assess_upgrade,
    build_release_bundle,
    certify,
    link,
    process,
    reconcile_rollout,
    select_link_sections,
)


def region(name='mem', base=0, size=100000):
    return {'name': name, 'base': base, 'size': size}


def section(name, region_name='mem', size=64, alignment=1):
    return {'name': name, 'region': region_name, 'size': size,
            'alignment': alignment}


def symbol(name, section_name, offset, binding):
    return {'name': name, 'section': section_name, 'offset': offset,
            'binding': binding}


def relocation(rid, section_name, offset, scope, name, addend=0, width=4):
    return {'id': rid, 'section': section_name, 'offset': offset,
            'symbol': {'scope': scope, 'name': name},
            'addend': addend, 'width': width}


def obj(oid, sections, symbols, relocations):
    return {'id': oid, 'sections': sections, 'symbols': symbols,
            'relocations': relocations}


def select(plan, roots):
    return select_link_sections({'plan': plan, 'roots': roots})


def kept_keys(result):
    return {(s['object'], s['section']) for s in result['kept_sections']}


def excluded_keys(result):
    return {(s['object'], s['section']) for s in result['excluded_sections']}


class SelectLinkSectionsTests(unittest.TestCase):
    def assert_justifications(self, result):
        """每条保留 section 的依据都可核查且沿 via 链无环地回到入口。"""
        kept = kept_keys(result)
        roots = {(r['object'], r['section']) for r in result['roots']}
        just = {(j['object'], j['section']): j
                for j in result['justifications']}
        self.assertEqual(set(just), kept)
        symsec = {}
        for o in result['pruned_plan']['objects']:
            for s in o['symbols']:
                symsec[(o['id'], s['name'])] = s['section']
        relocs = {(r['object'], r['id']): r
                  for r in result['pruned_link']['relocations']}
        for key, j in just.items():
            if j['kind'] == 'root':
                self.assertIn(key, roots)
                self.assertIsNone(j['via'])
                continue
            self.assertEqual(j['kind'], 'relocation')
            via = j['via']
            # via 指向上游已保留 section 中一条真实存在的 relocation，
            # 且该 relocation 的解析目标定义正好落在被依据的 section。
            self.assertIn((via['object'], via['section']), kept)
            rel = relocs[(via['object'], via['id'])]
            self.assertEqual(rel['section'], via['section'])
            target = rel['target']
            self.assertEqual((target['object'],
                              symsec[(target['object'], target['name'])]),
                             key)
        for key in kept:
            seen = set()
            cur = key
            while just[cur]['kind'] != 'root':
                self.assertNotIn(cur, seen)
                seen.add(cur)
                via = just[cur]['via']
                cur = (via['object'], via['section'])

    def test_root_only_keeps_root_section(self):
        plan = {
            'regions': [region()],
            'objects': [
                obj('a', [section('text', size=16), section('data', size=8)],
                    [symbol('entry', 'text', 0, 'strong'),
                     symbol('blob', 'data', 0, 'local')], []),
                obj('b', [section('impl', size=16)],
                    [symbol('g', 'impl', 0, 'strong')], []),
            ],
        }
        r = select(plan, [{'object': 'a', 'section': 'text'}])
        self.assertEqual(kept_keys(r), {('a', 'text')})
        self.assertEqual(excluded_keys(r),
                         {('a', 'data'), ('b', 'impl')})
        self.assertEqual(r['roots'], [{'object': 'a', 'section': 'text'}])
        self.assertEqual(r['plan']['summary'],
                         {'regions': 1, 'objects': 2, 'sections': 3,
                          'symbols': 3, 'relocations': 0})
        self.assertEqual(r['summary'],
                         {'regions': 1, 'objects': 2, 'sections': 3,
                          'roots': 1, 'kept_sections': 1,
                          'excluded_sections': 2})
        self.assert_justifications(r)
        json.dumps(r)  # 输出必须可 JSON 序列化

    def test_cross_object_global_and_local_transitive(self):
        plan = {
            'regions': [region()],
            'objects': [
                obj('a', [section('text', size=32), section('data', size=8)],
                    [symbol('entry', 'text', 0, 'strong'),
                     symbol('local_msg', 'data', 1, 'local')],
                    [relocation('r1', 'text', 0, 'global', 'g'),
                     relocation('r2', 'text', 4, 'local', 'local_msg',
                                width=2)]),
                obj('b', [section('impl', size=32),
                          section('impl_aux', size=8)],
                    [symbol('g', 'impl', 0, 'strong'),
                     symbol('aux', 'impl_aux', 0, 'local')],
                    [relocation('r1', 'impl', 8, 'local', 'aux', width=2)]),
                obj('c', [section('other', size=8)],
                    [symbol('w', 'other', 0, 'weak')], []),
            ],
        }
        r = select(plan, [{'object': 'a', 'section': 'text'}])
        self.assertEqual(kept_keys(r), {('a', 'text'), ('a', 'data'),
                                        ('b', 'impl'), ('b', 'impl_aux')})
        self.assertEqual(excluded_keys(r), {('c', 'other')})
        just = {(j['object'], j['section']): j
                for j in r['justifications']}
        self.assertEqual(just[('a', 'data')]['via'],
                         {'object': 'a', 'section': 'text', 'id': 'r2'})
        self.assertEqual(just[('b', 'impl')]['via'],
                         {'object': 'a', 'section': 'text', 'id': 'r1'})
        self.assertEqual(just[('b', 'impl_aux')]['via'],
                         {'object': 'b', 'section': 'impl', 'id': 'r1'})
        self.assert_justifications(r)

    def test_multilevel_chain(self):
        plan = {
            'regions': [region()],
            'objects': [
                obj('a', [section('s1', size=16)],
                    [symbol('f1', 's1', 0, 'strong')],
                    [relocation('r1', 's1', 0, 'global', 'f2'),
                     # 同一 section 的多条引用只保留一次
                     relocation('r2', 's1', 4, 'global', 'f2')]),
                obj('b', [section('s2', size=16)],
                    [symbol('f2', 's2', 0, 'strong')],
                    [relocation('r1', 's2', 0, 'global', 'f3')]),
                obj('c', [section('s3', size=16)],
                    [symbol('f3', 's3', 0, 'strong')],
                    [relocation('r1', 's3', 0, 'global', 'f4')]),
                obj('d', [section('s4', size=16)],
                    [symbol('f4', 's4', 0, 'strong')], []),
            ],
        }
        r = select(plan, [{'object': 'a', 'section': 's1'}])
        self.assertEqual(kept_keys(r), {('a', 's1'), ('b', 's2'),
                                        ('c', 's3'), ('d', 's4')})
        just = {(j['object'], j['section']): j
                for j in r['justifications']}
        self.assertEqual(just[('b', 's2')]['via']['id'], 'r1')
        self.assertEqual(just[('c', 's3')]['via'],
                         {'object': 'b', 'section': 's2', 'id': 'r1'})
        self.assertEqual(just[('d', 's4')]['via'],
                         {'object': 'c', 'section': 's3', 'id': 'r1'})
        self.assert_justifications(r)

    def _cyclic_plan(self):
        return {
            'regions': [region()],
            'objects': [
                obj('a', [section('s1', size=32, alignment=4),
                          section('dead_a', size=8)],
                    [symbol('f1', 's1', 0, 'strong'),
                     symbol('note', 'dead_a', 0, 'local')],
                    [relocation('r1', 's1', 0, 'global', 'f2'),
                     relocation('r2', 's1', 4, 'global', 'f3')]),
                obj('b', [section('s2', size=32, alignment=4)],
                    [symbol('f2', 's2', 4, 'strong')],
                    [relocation('r1', 's2', 0, 'global', 'f3'),
                     relocation('r2', 's2', 8, 'global', 'f1')]),
                obj('c', [section('s3', size=16, alignment=2),
                          section('dead_c', size=8)],
                    [symbol('f3', 's3', 0, 'strong'),
                     symbol('ln', 'dead_c', 0, 'local')],
                    [relocation('r1', 's3', 0, 'global', 'f2'),
                     relocation('r2', 'dead_c', 0, 'local', 'ln')]),
                obj('d', [section('s4', size=16)],
                    [symbol('w', 's4', 0, 'weak')], []),
            ],
        }

    def test_cycle_and_converging_roots(self):
        plan = self._cyclic_plan()
        roots = [{'object': 'a', 'section': 's1'},
                 {'object': 'c', 'section': 's3'}]
        r = select(plan, roots)
        # 环与多入口汇合不改变最终集合；未引用的 weak 胜者 d/s4 不保留
        self.assertEqual(kept_keys(r),
                         {('a', 's1'), ('b', 's2'), ('c', 's3')})
        self.assertEqual(excluded_keys(r),
                         {('a', 'dead_a'), ('c', 'dead_c'), ('d', 's4')})
        just = {(j['object'], j['section']): j
                for j in r['justifications']}
        self.assertEqual(just[('a', 's1')]['kind'], 'root')
        self.assertEqual(just[('c', 's3')]['kind'], 'root')
        # b/s2 可由两个入口到达，依据必须确定：字典序最小的入口先扩展
        self.assertEqual(just[('b', 's2')]['via'],
                         {'object': 'a', 'section': 's1', 'id': 'r1'})
        self.assert_justifications(r)

    def test_strong_winner_kept_shadowed_weak_not(self):
        plan = {
            'regions': [region()],
            'objects': [
                obj('a', [section('text', size=16)],
                    [symbol('entry', 'text', 0, 'strong')],
                    [relocation('r1', 'text', 0, 'global', 'n')]),
                obj('b', [section('impl', size=16)],
                    [symbol('n', 'impl', 0, 'strong')], []),
                obj('c', [section('impl', size=16)],
                    [symbol('n', 'impl', 2, 'weak')], []),
                obj('d', [section('impl', size=16)],
                    [symbol('n', 'impl', 4, 'weak')], []),
            ],
        }
        r = select(plan, [{'object': 'a', 'section': 'text'}])
        # strong 胜者被带入；同名 shadowed weak 不因名称相同被保留
        self.assertEqual(kept_keys(r), {('a', 'text'), ('b', 'impl')})
        self.assertEqual(excluded_keys(r),
                         {('c', 'impl'), ('d', 'impl')})
        glb = {g['name']: g for g in r['pruned_link']['symbols']['globals']}
        self.assertEqual(glb['n']['winner']['object'], 'b')
        self.assert_justifications(r)

        # 移除 strong 定义后，现有 weak 候选中字典序最小者成为胜者
        variant = copy.deepcopy(plan)
        variant['objects'][1]['symbols'] = []  # b 不再定义 n
        r2 = select(variant, [{'object': 'a', 'section': 'text'}])
        self.assertEqual(kept_keys(r2), {('a', 'text'), ('c', 'impl')})
        self.assertEqual(excluded_keys(r2),
                         {('b', 'impl'), ('d', 'impl')})
        glb2 = {g['name']: g
                for g in r2['pruned_link']['symbols']['globals']}
        self.assertEqual(glb2['n']['winner']['object'], 'c')
        # d 的 weak 定义所在 section 被排除后不再出现在 pruned 解析中
        self.assertEqual(glb2['n']['shadowed'], [])
        self.assert_justifications(r2)

    def test_local_same_name_not_mislinked(self):
        plan = {
            'regions': [region()],
            'objects': [
                obj('a', [section('text', size=32),
                          section('rodata', size=8)],
                    [symbol('x', 'rodata', 0, 'local')],
                    [relocation('r1', 'text', 0, 'local', 'x'),
                     relocation('r2', 'text', 4, 'global', 'w')]),
                obj('b', [section('text', size=32),
                          section('rodata', size=8)],
                    [symbol('x', 'rodata', 0, 'local'),
                     symbol('w', 'text', 8, 'weak')],
                    [relocation('r1', 'rodata', 0, 'local', 'x')]),
            ],
        }
        r = select(plan, [{'object': 'a', 'section': 'text'}])
        # a 的 local x 只解析到 a/rodata；b 的同名 local 所在 section 不带入
        self.assertEqual(kept_keys(r),
                         {('a', 'text'), ('a', 'rodata'), ('b', 'text')})
        self.assertEqual(excluded_keys(r), {('b', 'rodata')})
        full = link(plan)
        relocs = {(x['object'], x['id']): x for x in full['relocations']}
        self.assertEqual(relocs[('a', 'r1')]['target'],
                         {'object': 'a', 'name': 'x'})
        self.assertEqual(relocs[('b', 'r1')]['target'],
                         {'object': 'b', 'name': 'x'})
        self.assert_justifications(r)

    def test_pruned_relink_alignment_and_bytes_change(self):
        plan = {
            'regions': [region()],
            'objects': [
                obj('a', [section('junk', size=16), section('text', size=8)],
                    [symbol('entry', 'text', 0, 'strong')],
                    [relocation('r1', 'text', 0, 'global', 'g', width=2)]),
                obj('b', [section('target', size=8, alignment=4)],
                    [symbol('g', 'target', 0, 'strong')], []),
            ],
        }
        full = link(plan)
        full_bases = {(s['object'], s['name']): s['base']
                      for s in full['sections']}
        self.assertEqual(full_bases,
                         {('a', 'junk'): 0, ('a', 'text'): 16,
                          ('b', 'target'): 24})
        self.assertEqual(full['relocations'][0]['bytes'], [24, 0])

        r = select(plan, [{'object': 'a', 'section': 'text'}])
        self.assertEqual(excluded_keys(r), {('a', 'junk')})
        pruned_bases = {(s['object'], s['name']): s['base']
                        for s in r['pruned_link']['sections']}
        # 移除不可达 section 后对齐布局改变，下游 relocation 字节随之改变
        self.assertEqual(pruned_bases,
                         {('a', 'text'): 0, ('b', 'target'): 8})
        self.assertEqual(r['pruned_link']['relocations'][0]['address'], 8)
        self.assertEqual(r['pruned_link']['relocations'][0]['value'], 8)
        self.assertEqual(r['pruned_link']['relocations'][0]['bytes'], [8, 0])
        # 重链结果必须来自 pruned plan 的实际 link，而不是完整结果的裁剪
        self.assertEqual(r['pruned_link'], link(r['pruned_plan']))
        self.assertEqual(r['pruned_link']['summary'],
                         {'regions': 1, 'objects': 2, 'sections': 2,
                          'symbols': 2, 'relocations': 1})
        self.assert_justifications(r)

    def test_section_unit_keeps_all_definitions_and_relocations(self):
        plan = {
            'regions': [region()],
            'objects': [
                obj('a', [section('text', size=32)],
                    [symbol('entry', 'text', 0, 'strong'),
                     symbol('mid', 'text', 8, 'local'),
                     symbol('tail', 'text', 12, 'weak')],
                    [relocation('r1', 'text', 0, 'local', 'mid', width=2),
                     relocation('r2', 'text', 4, 'local', 'tail', width=2),
                     relocation('r3', 'text', 8, 'global', 'entry')]),
                obj('b', [section('gone', size=8)], [], []),
            ],
        }
        r = select(plan, [{'object': 'a', 'section': 'text'}])
        self.assertEqual(kept_keys(r), {('a', 'text')})
        kept_obj = r['pruned_plan']['objects'][0]
        self.assertEqual([s['name'] for s in kept_obj['symbols']],
                         ['entry', 'mid', 'tail'])
        self.assertEqual([x['id'] for x in kept_obj['relocations']],
                         ['r1', 'r2', 'r3'])
        # 没有保留 section 的对象记录不得丢失
        empty_obj = r['pruned_plan']['objects'][1]
        self.assertEqual(empty_obj, {'id': 'b', 'sections': [],
                                     'symbols': [], 'relocations': []})
        self.assertEqual(r['pruned_link']['summary']['objects'], 2)
        self.assertEqual(r['summary']['objects'], 2)
        self.assert_justifications(r)

    def test_permutation_invariance(self):
        plan = self._cyclic_plan()
        roots = [{'object': 'c', 'section': 's3'},
                 {'object': 'a', 'section': 's1'}]
        baseline = select(copy.deepcopy(plan), copy.deepcopy(roots))
        for seed in (20261125, 987654321):
            rng = random.Random(seed)
            variant = copy.deepcopy(plan)
            variant_roots = copy.deepcopy(roots)
            rng.shuffle(variant['regions'])
            rng.shuffle(variant['objects'])
            rng.shuffle(variant_roots)
            for o in variant['objects']:
                rng.shuffle(o['sections'])
                rng.shuffle(o['symbols'])
                rng.shuffle(o['relocations'])
            self.assertEqual(select(variant, variant_roots), baseline)

    def test_duplicate_roots_rejected(self):
        plan = {
            'regions': [region()],
            'objects': [obj('a', [section('text', size=16)], [], [])],
        }
        with self.assertRaises(ValueError):
            select(plan, [{'object': 'a', 'section': 'text'},
                          {'object': 'a', 'section': 'text'}])

    def test_unreachable_errors_still_rejected(self):
        # 不可达 section 中的非法 relocation 不能被分析隐藏
        plan = {
            'regions': [region()],
            'objects': [
                obj('a', [section('text', size=16)],
                    [symbol('entry', 'text', 0, 'strong')], []),
                obj('b', [section('dead', size=16)],
                    [],
                    [relocation('r1', 'dead', 0, 'global', 'missing')]),
            ],
        }
        with self.assertRaises(ValueError):
            select(plan, [{'object': 'a', 'section': 'text'}])
        # 不可达区域中的重复 strong 定义同样拒绝
        plan2 = {
            'regions': [region()],
            'objects': [
                obj('a', [section('text', size=16)],
                    [symbol('entry', 'text', 0, 'strong')], []),
                obj('b', [section('dead', size=16)],
                    [symbol('y', 'dead', 0, 'strong')], []),
                obj('c', [section('dead', size=16)],
                    [symbol('y', 'dead', 0, 'strong')], []),
            ],
        }
        with self.assertRaises(ValueError):
            select(plan2, [{'object': 'a', 'section': 'text'}])

    def test_missing_or_malformed_roots_rejected(self):
        plan = {
            'regions': [region()],
            'objects': [obj('a', [section('text', size=16)],
                            [symbol('entry', 'text', 0, 'strong')], [])],
        }
        good_root = {'object': 'a', 'section': 'text'}
        bad_calls = [
            {'plan': plan, 'roots': []},                       # 空入口
            {'plan': plan, 'roots': [{'object': 'zz',
                                      'section': 'text'}]},    # 未知对象
            {'plan': plan, 'roots': [{'object': 'a',
                                      'section': 'nope'}]},    # 未知 section
            {'plan': plan, 'roots': [{'object': 'a'}]},        # 缺字段
            {'plan': plan, 'roots': [dict(good_root, x=1)]},   # 多字段
            {'plan': plan, 'roots': [{'object': 'a',
                                      'section': 'bad name!'}]},
            {'plan': plan, 'roots': 'text'},                   # 非数组
            {'plan': plan},                                    # 缺 roots
            {'plan': plan, 'roots': [good_root], 'extra': 1},  # 未知顶层字段
        ]
        for data in bad_calls:
            with self.assertRaises(ValueError, msg=repr(data)):
                select_link_sections(copy.deepcopy(data))

    def test_full_plan_link_error_rejected(self):
        with self.assertRaises(ValueError):
            select_link_sections({'plan': {'regions': [], 'objects': []},
                                  'roots': [{'object': 'a',
                                             'section': 'text'}]})

    def test_pruned_plan_illegal_rejected(self):
        # 完整 plan 合法；过滤后地址下移使 relocation 值变为负，整体拒绝
        plan = {
            'regions': [region()],
            'objects': [
                obj('a', [section('text', size=16)],
                    [symbol('entry', 'text', 0, 'strong')],
                    [relocation('r1', 'text', 0, 'global', 'g',
                                addend=-56)]),
                obj('b', [section('aaa_pad', size=40),
                          section('target', size=16)],
                    [symbol('g', 'target', 0, 'strong')], []),
            ],
        }
        full = link(plan)  # g 地址 56，value 0，完整 plan 合法
        self.assertEqual(full['relocations'][0]['value'], 0)
        # 剪除 aaa_pad 后 g 地址变为 16，value 16-56 < 0，重链失败
        with self.assertRaises(ValueError):
            select(plan, [{'object': 'a', 'section': 'text'}])

    def test_existing_apis_regression(self):
        for name in ('process', 'link', 'certify', 'assess_upgrade',
                     'build_release_bundle', 'reconcile_rollout',
                     'select_link_sections'):
            self.assertTrue(callable(getattr(obj_reloc, name)))
        fixture = json.loads(Path('fixtures/input.json').read_text())
        self.assertEqual(process(fixture)['summary'],
                         {'sections': 2, 'symbols': 2, 'relocations': 1})
        plan = {
            'regions': [region()],
            'objects': [obj('fw', [section('text', size=64)],
                            [symbol('entry', 'text', 4, 'strong')],
                            [relocation('r1', 'text', 8, 'global',
                                        'entry')])],
        }
        self.assertEqual(link(plan)['relocations'][0]['bytes'],
                         [4, 0, 0, 0])
        cert = certify({
            'plan': plan,
            'collectors': [{'id': 'c1', 'group': 'g',
                            'valid_from': 0, 'valid_to': 1000}],
            'targets': [{'id': 't1'}],
            'captures': [],
            'requests': [{'id': 'q1', 'target': 't1', 'as_of': 100,
                          'min_collectors': 1, 'min_groups': 1}],
        })
        self.assertEqual(cert['requests'][0]['status'], 'insufficient')
        upgrade = assess_upgrade({
            'current': plan, 'candidate': copy.deepcopy(plan),
            'consumers': [{'id': 'app', 'objects': ['fw'],
                           'binding_policy': 'provider'}],
        })
        self.assertEqual(upgrade['consumers'][0]['action'], 'keep_running')
        image_plan = {
            'regions': [region(size=8)],
            'objects': [obj('o', [section('s', size=8)], [], [])],
        }
        releases = [{'id': rid, 'plan': image_plan,
                     'images': [{'object': 'o', 'section': 's',
                                 'bytes': [0] * 8}]}
                    for rid in ('cur', 'cand')]
        bundle_input = {
            'releases': releases,
            'targets': [{'id': 't1', 'current': 'cur', 'candidate': 'cand',
                         'erase_byte': 255, 'atomic_ranges': [],
                         'max_batch_bytes': 65536}],
            'receipts': [],
        }
        bundle = build_release_bundle(bundle_input)
        self.assertEqual(bundle['targets'][0]['status'], 'up_to_date')
        recon = reconcile_rollout({
            'bundle': bundle_input,
            'groups': [{'id': 'g1', 'targets': ['t1'],
                        'policy': 'independent'}],
            'journals': [],
        })
        # 空 forward manifest 的 target 初始即完成前向，但仍需显式 commit
        self.assertEqual(recon['targets'][0]['state'], 'forward_complete')
        self.assertEqual(recon['groups'][0]['decision'],
                         'independent_recovery')
        self.assertEqual(recon['groups'][0]['commands'][0]['action'],
                         'commit')


if __name__ == '__main__':
    unittest.main()
