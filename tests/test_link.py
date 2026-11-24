import copy
import json
import random
import tempfile
import unittest
from pathlib import Path

from obj_reloc import process, link
from obj_reloc import io as data_io


def region(name='mem', base=0, size=100000):
    return {'name': name, 'base': base, 'size': size}


def section(name, region_name='mem', size=64, alignment=1):
    return {'name': name, 'region': region_name, 'size': size, 'alignment': alignment}


def symbol(name, section_name, offset, binding):
    return {'name': name, 'section': section_name, 'offset': offset, 'binding': binding}


def relocation(rid, section_name, offset, scope, name, addend=0, width=4):
    return {'id': rid, 'section': section_name, 'offset': offset,
            'symbol': {'scope': scope, 'name': name}, 'addend': addend, 'width': width}


def obj(oid, sections, symbols, relocations):
    return {'id': oid, 'sections': sections, 'symbols': symbols, 'relocations': relocations}


class LinkTests(unittest.TestCase):
    def test_single_object_link(self):
        data = {
            'regions': [region(base=0)],
            'objects': [obj('o1',
                            [section('text', size=32, alignment=1),
                             section('data', size=8, alignment=4)],
                            [symbol('entry', 'text', 4, 'strong'),
                             symbol('msg', 'data', 1, 'weak')],
                            [relocation('r1', 'text', 0, 'global', 'msg', width=2)])],
        }
        r = link(data)
        # 同 region 内按 (object.id, section.name) 字典序：data 先于 text
        self.assertEqual([(s['object'], s['name'], s['base']) for s in r['sections']],
                         [('o1', 'data', 0), ('o1', 'text', 8)])
        defs = {(d['object'], d['name']): d for d in r['symbols']['definitions']}
        self.assertEqual(defs[('o1', 'entry')]['address'], 12)
        self.assertEqual(defs[('o1', 'msg')]['address'], 1)
        self.assertEqual(r['relocations'][0]['target'], {'object': 'o1', 'name': 'msg'})
        self.assertEqual(r['relocations'][0]['address'], 1)
        self.assertEqual(r['relocations'][0]['value'], 1)
        self.assertEqual(r['relocations'][0]['bytes'], [1, 0])
        self.assertEqual(r['summary'],
                         {'regions': 1, 'objects': 1, 'sections': 2, 'symbols': 2, 'relocations': 1})

    def _two_object_data(self):
        return {
            'regions': [region()],
            'objects': [
                obj('a', [section('text', size=64)],
                    [symbol('shared', 'text', 0, 'weak')],
                    [relocation('r1', 'text', 16, 'global', 'shared', width=8)]),
                obj('b', [section('text', size=64)],
                    [symbol('shared', 'text', 8, 'strong')], []),
            ],
        }

    def test_strong_overrides_weak(self):
        r = link(self._two_object_data())
        # 布局按 (object.id, section.name)：a 占 0..64，b 从 64 开始
        self.assertEqual([(s['object'], s['base']) for s in r['sections']],
                         [('a', 0), ('b', 64)])
        glb = {g['name']: g for g in r['symbols']['globals']}
        self.assertEqual(glb['shared']['winner'],
                         {'object': 'b', 'name': 'shared', 'address': 72})
        self.assertEqual(glb['shared']['shadowed'],
                         [{'object': 'a', 'name': 'shared', 'address': 0}])
        reloc = r['relocations'][0]
        self.assertEqual(reloc['object'], 'a')
        self.assertEqual(reloc['target'], {'object': 'b', 'name': 'shared'})
        self.assertEqual(reloc['address'], 72)
        self.assertEqual(reloc['value'], 72)
        self.assertEqual(reloc['bytes'], [72, 0, 0, 0, 0, 0, 0, 0])

    def test_weak_only_deterministic_winner(self):
        data = {
            'regions': [region()],
            'objects': [
                obj('b', [section('text', size=16)],
                    [symbol('w', 'text', 0, 'weak')], []),
                obj('a', [section('text', size=16)],
                    [symbol('w', 'text', 2, 'weak')],
                    [relocation('r1', 'text', 4, 'global', 'w', width=4)]),
            ],
        }
        r = link(data)
        glb = r['symbols']['globals'][0]
        self.assertEqual(glb['winner'], {'object': 'a', 'name': 'w', 'address': 2})
        self.assertEqual(glb['shadowed'],
                         [{'object': 'b', 'name': 'w', 'address': 16}])
        self.assertEqual(r['relocations'][0]['target'], {'object': 'a', 'name': 'w'})

    def test_local_symbol_same_name(self):
        data = {
            'regions': [region()],
            'objects': [
                obj('a', [section('text', size=32)],
                    [symbol('x', 'text', 0, 'local')],
                    [relocation('r1', 'text', 8, 'local', 'x', width=4)]),
                obj('b', [section('text', size=32)],
                    [symbol('x', 'text', 4, 'weak')],
                    [relocation('r1', 'text', 8, 'global', 'x', width=4)]),
            ],
        }
        r = link(data)
        relocs = {(x['object'], x['id']): x for x in r['relocations']}
        self.assertEqual(relocs[('a', 'r1')]['target'], {'object': 'a', 'name': 'x'})
        self.assertEqual(relocs[('b', 'r1')]['target'], {'object': 'b', 'name': 'x'})
        glb = {g['name']: g for g in r['symbols']['globals']}
        self.assertEqual(glb['x']['winner']['object'], 'b')
        self.assertEqual(glb['x']['shadowed'], [])  # a 的 local 不进入全局候选
        bindings = {(d['object'], d['name']): d['binding']
                    for d in r['symbols']['definitions']}
        self.assertEqual(bindings[('a', 'x')], 'local')

    def test_undefined_references(self):
        good = {
            'regions': [region()],
            'objects': [obj('a', [section('text', size=32)], [],
                            [relocation('r1', 'text', 0, 'global', 'missing')])],
        }
        with self.assertRaises(ValueError):
            link(good)
        good['objects'][0]['relocations'][0]['symbol']['scope'] = 'local'
        with self.assertRaises(ValueError):
            link(good)

    def test_multiple_strong_rejected(self):
        data = {
            'regions': [region()],
            'objects': [
                obj('a', [section('text', size=16)],
                    [symbol('y', 'text', 0, 'strong')], []),
                obj('b', [section('text', size=16)],
                    [symbol('y', 'text', 0, 'strong')], []),
            ],
        }
        with self.assertRaises(ValueError):
            link(data)

    def test_alignment_layout(self):
        data = {
            'regions': [region(base=100, size=10000)],
            'objects': [
                obj('b', [section('s1', size=10, alignment=8)], [], []),
                obj('a', [section('s2', size=3, alignment=16),
                          section('s1', size=10, alignment=4)], [], []),
            ],
        }
        r = link(data)
        bases = {(s['object'], s['name']): s['base'] for s in r['sections']}
        # 排序后 a/s1 -> 100，a/s2 对齐 16 -> 112，b/s1 对齐 8 -> 120
        self.assertEqual(bases, {('a', 's1'): 100, ('a', 's2'): 112, ('b', 's1'): 120})
        for s in r['sections']:
            self.assertEqual(s['base'] % s['alignment'], 0)

    def test_region_capacity_exceeded(self):
        data = {
            'regions': [region(size=10)],
            'objects': [
                obj('a', [section('s', size=8)], [], []),
                obj('b', [section('s', size=8)], [], []),
            ],
        }
        with self.assertRaises(ValueError):
            link(data)
        data2 = {'regions': [region(size=4)],
                 'objects': [obj('a', [section('s', size=8)], [], [])]}
        with self.assertRaises(ValueError):
            link(data2)

    def test_order_invariance(self):
        data = {
            'regions': [region('mem', 0, 100000), region('rom', 200000, 100000)],
            'objects': [
                obj('a',
                    [section('t', 'mem', 64, 4), section('d', 'rom', 32, 8)],
                    [symbol('f1', 't', 1, 'strong'), symbol('f2', 'd', 2, 'weak')],
                    [relocation('r2', 't', 8, 'global', 'g'),
                     relocation('r1', 't', 4, 'local', 'f1', width=2)]),
                obj('b',
                    [section('t', 'mem', 64, 4)],
                    [symbol('g', 't', 3, 'strong')],
                    [relocation('r1', 't', 12, 'global', 'f1', width=4)]),
            ],
        }
        baseline = link(copy.deepcopy(data))
        rng = random.Random(20261124)
        variant = copy.deepcopy(data)
        rng.shuffle(variant['regions'])
        rng.shuffle(variant['objects'])
        for o in variant['objects']:
            rng.shuffle(o['sections'])
            rng.shuffle(o['symbols'])
            rng.shuffle(o['relocations'])
        self.assertEqual(link(variant), baseline)
        # 再次独立重排，结果仍完全一致
        rng2 = random.Random(987654321)
        variant2 = copy.deepcopy(data)
        rng2.shuffle(variant2['regions'])
        rng2.shuffle(variant2['objects'])
        for o in variant2['objects']:
            rng2.shuffle(o['sections'])
            rng2.shuffle(o['symbols'])
            rng2.shuffle(o['relocations'])
        self.assertEqual(link(variant2), baseline)

    def test_relocation_out_of_bounds_and_overlap(self):
        base = {
            'regions': [region()],
            'objects': [obj('a', [section('text', size=16)],
                            [symbol('x', 'text', 0, 'strong')],
                            [relocation('r1', 'text', 14, 'global', 'x', width=4)])],
        }
        with self.assertRaises(ValueError):
            link(copy.deepcopy(base))
        base['objects'][0]['relocations'][0]['offset'] = 0
        extra = relocation('r2', 'text', 2, 'global', 'x', width=2)
        base['objects'][0]['relocations'].append(extra)
        with self.assertRaises(ValueError):
            link(base)

    def test_relocation_overflow_and_negative(self):
        base = {
            'regions': [region(base=0)],
            'objects': [obj('a', [section('text', size=16)],
                            [symbol('x', 'text', 0, 'strong')],
                            [relocation('r1', 'text', 0, 'global', 'x', width=1)])],
        }
        # 把 x 放到地址 256：region base 256
        base['regions'][0]['base'] = 256
        with self.assertRaises(ValueError):
            link(copy.deepcopy(base))
        base['regions'][0]['base'] = 0
        base['objects'][0]['relocations'][0]['addend'] = -1
        with self.assertRaises(ValueError):
            link(base)

    def test_structural_rejections(self):
        valid = {
            'regions': [region()],
            'objects': [obj('a', [section('text', size=16)],
                            [symbol('x', 'text', 0, 'strong')],
                            [relocation('r1', 'text', 0, 'global', 'x')])],
        }
        bad = copy.deepcopy(valid)
        bad['unknown'] = 1
        with self.assertRaises(ValueError):
            link(bad)
        bad = copy.deepcopy(valid)
        bad['regions'][0]['base'] = True  # bool 不得充当整数
        with self.assertRaises(ValueError):
            link(bad)
        bad = copy.deepcopy(valid)
        bad['regions'][0]['name'] = 'bad name!'
        with self.assertRaises(ValueError):
            link(bad)
        bad = copy.deepcopy(valid)
        bad['regions'].append(region())  # 重名 region
        with self.assertRaises(ValueError):
            link(bad)
        bad = copy.deepcopy(valid)
        bad['regions'].append(region('other', base=50, size=100))  # 与 [0,100000) 重叠
        with self.assertRaises(ValueError):
            link(bad)
        bad = copy.deepcopy(valid)
        bad['objects'].append(copy.deepcopy(valid['objects'][0]))  # 重复对象 id
        with self.assertRaises(ValueError):
            link(bad)
        bad = copy.deepcopy(valid)
        bad['objects'][0]['sections'][0]['alignment'] = 3  # 非二次幂
        with self.assertRaises(ValueError):
            link(bad)
        bad = copy.deepcopy(valid)
        bad['objects'][0]['symbols'][0]['offset'] = 16  # offset == size
        with self.assertRaises(ValueError):
            link(bad)
        bad = copy.deepcopy(valid)
        bad['objects'][0]['symbols'][0]['binding'] = 'glue'
        with self.assertRaises(ValueError):
            link(bad)
        bad = copy.deepcopy(valid)
        bad['objects'][0]['relocations'][0]['symbol']['scope'] = 'elsewhere'
        with self.assertRaises(ValueError):
            link(bad)
        bad = copy.deepcopy(valid)
        bad['regions'] = []  # 空 regions
        with self.assertRaises(ValueError):
            link(bad)
        bad = copy.deepcopy(valid)
        bad['objects'] = []  # 空 objects
        with self.assertRaises(ValueError):
            link(bad)

    def test_duplicate_json_key_and_nonfinite_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            dup = Path(tmp) / 'dup.json'
            dup.write_text('{"regions": [], "regions": [], "objects": []}')
            with self.assertRaises(ValueError):
                data_io.load(str(dup))
            nan = Path(tmp) / 'nan.json'
            nan.write_text('{"regions": [{"name": "m", "base": NaN, "size": 1}], "objects": []}')
            with self.assertRaises(ValueError):
                data_io.load(str(nan))

    def test_aggregate_capacity_rejected(self):
        data = {
            'regions': [region(size=100000)],
            'objects': [
                obj('o%d' % i, [section('s%d' % j, size=1) for j in range(51)], [], [])
                for i in range(2)
            ],
        }
        with self.assertRaises(ValueError):
            link(data)

    def test_process_contract_still_holds(self):
        fixture = json.loads(Path('fixtures/input.json').read_text())
        r = process(fixture)
        self.assertEqual(r['symbols']['msg']['address'], 8194)
        self.assertEqual(r['relocations'][0]['bytes'], [2, 32])
        # process 继续拒绝未知顶层字段，link 为独立入口
        with self.assertRaises(ValueError):
            process(dict(fixture, extra=1))
        self.assertTrue(callable(link))


if __name__ == '__main__':
    unittest.main()
