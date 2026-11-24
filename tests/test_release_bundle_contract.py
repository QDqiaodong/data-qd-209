import copy
import hashlib
import json
import unittest

from obj_reloc import assess_upgrade, build_release_bundle, certify, link, process


def canonical_chunk_id(payload):
    text = json.dumps(payload, ensure_ascii=True, separators=(',', ':'))
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def region(name='mem', base=0, size=4096):
    return {'name': name, 'base': base, 'size': size}


def section(name='s', region_name='mem', size=8, alignment=1):
    return {'name': name, 'region': region_name, 'size': size,
            'alignment': alignment}


def symbol(name='base', section_name='s', offset=0, binding='strong'):
    return {'name': name, 'section': section_name, 'offset': offset,
            'binding': binding}


def relocation(rid='r1', section_name='s', offset=0, name='base',
               scope='local', width=4, addend=0):
    return {
        'id': rid,
        'section': section_name,
        'offset': offset,
        'symbol': {'scope': scope, 'name': name},
        'addend': addend,
        'width': width,
    }


def one_object_plan(object_id='o', sections=None, symbols=None,
                    relocations=None, regions=None):
    return {
        'regions': regions if regions is not None else [region()],
        'objects': [{
            'id': object_id,
            'sections': sections if sections is not None else [section()],
            'symbols': symbols or [],
            'relocations': relocations or [],
        }],
    }


def make_release(rid, plan, contents=None):
    linked = link(plan)
    images = []
    for sec in linked['sections']:
        key = (sec['object'], sec['name'])
        if contents is not None and key in contents:
            payload = list(contents[key])
        else:
            payload = [0] * sec['size']
        images.append({
            'object': sec['object'],
            'section': sec['name'],
            'bytes': payload,
        })
    return {'id': rid, 'plan': plan, 'images': images}


def make_target(tid='t1', current='cur', candidate='cand',
                erase_byte=0xFF, atomic_ranges=None, max_batch_bytes=65536):
    return {
        'id': tid,
        'current': current,
        'candidate': candidate,
        'erase_byte': erase_byte,
        'atomic_ranges': atomic_ranges or [],
        'max_batch_bytes': max_batch_bytes,
    }


def build_simple(cur_bytes, cand_bytes, size=None, atomic_ranges=None,
                 max_batch_bytes=65536, erase_byte=0xFF, target_id='t1'):
    size = size or len(cur_bytes)
    plan = one_object_plan(sections=[section(size=size)])
    current = make_release('cur', plan, {('o', 's'): cur_bytes})
    candidate = make_release('cand', plan, {('o', 's'): cand_bytes})
    target = make_target(
        target_id, 'cur', 'cand', erase_byte=erase_byte,
        atomic_ranges=atomic_ranges, max_batch_bytes=max_batch_bytes)
    return build_release_bundle({
        'releases': [current, candidate],
        'targets': [target],
        'receipts': [],
    })


def target_row(result, tid='t1'):
    return next(row for row in result['targets'] if row['id'] == tid)


def unit_by_base(manifest, base):
    return next(unit for unit in manifest if unit['base'] == base)


class ReleaseDifferentialTests(unittest.TestCase):
    def test_relocation_bytes_overwrite_raw_section_image(self):
        plan = one_object_plan(
            sections=[section(size=8)],
            symbols=[symbol()],
            relocations=[relocation(width=4)],
        )
        current = make_release('cur', plan, {
            ('o', 's'): [0] * 8,
        })
        candidate = make_release('cand', plan, {
            # 前四个原始 image 字节必须被 relocation 的 [0,0,0,0] 覆盖。
            ('o', 's'): [9, 9, 9, 9, 5, 6, 7, 8],
        })
        result = build_release_bundle({
            'releases': [current, candidate],
            'targets': [make_target()],
            'receipts': [],
        })
        row = target_row(result)
        self.assertEqual(len(row['forward']), 1)
        unit = row['forward'][0]
        self.assertEqual((unit['base'], unit['size']), (4, 4))
        chunk = next(c for c in result['chunks']
                     if c['chunk_id'] == unit['chunk_id'])
        self.assertEqual(chunk['bytes'], [5, 6, 7, 8])
        self.assertEqual(unit['chunk_id'], canonical_chunk_id([5, 6, 7, 8]))

    def test_section_move_emits_old_erase_and_new_write(self):
        current_plan = one_object_plan(
            regions=[region(base=0)], sections=[section(size=4)])
        candidate_plan = one_object_plan(
            regions=[region(base=16)], sections=[section(size=4)])
        bundle = build_release_bundle({
            'releases': [
                make_release('cur', current_plan,
                             {('o', 's'): [10, 20, 30, 40]}),
                make_release('cand', candidate_plan,
                             {('o', 's'): [1, 2, 3, 4]}),
            ],
            'targets': [make_target()],
            'receipts': [],
        })
        row = target_row(bundle)
        old = unit_by_base(row['forward'], 0)
        new = unit_by_base(row['forward'], 16)
        self.assertEqual(old['size'], 4)
        self.assertEqual(bundle_chunks(bundle)[old['chunk_id']], [255] * 4)
        self.assertEqual(bundle_chunks(bundle)[new['chunk_id']], [1, 2, 3, 4])

        old_rb = unit_by_base(row['rollback'], 0)
        new_rb = unit_by_base(row['rollback'], 16)
        self.assertEqual(
            bundle_chunks(bundle)[old_rb['chunk_id']], [10, 20, 30, 40])
        # candidate-only 地址在回滚时回到 erase_byte 所表示的擦除态。
        self.assertEqual(
            bundle_chunks(bundle)[new_rb['chunk_id']], [255] * 4)

    def test_reused_absolute_address_uses_one_final_byte_diff(self):
        current_plan = one_object_plan(sections=[section(name='old', size=4)])
        candidate_plan = one_object_plan(sections=[section(name='new', size=4)])
        bundle = build_release_bundle({
            'releases': [
                make_release('cur', current_plan,
                             {('o', 'old'): [1, 2, 3, 4]}),
                make_release('cand', candidate_plan,
                             {('o', 'new'): [5, 6, 7, 8]}),
            ],
            'targets': [make_target()],
            'receipts': [],
        })
        forward = target_row(bundle)['forward']
        self.assertEqual(len(forward), 1)
        self.assertEqual((forward[0]['base'], forward[0]['size']), (0, 4))
        chunks = bundle_chunks(bundle)
        self.assertEqual(chunks[forward[0]['chunk_id']], [5, 6, 7, 8])
        rollback = target_row(bundle)['rollback']
        self.assertEqual(chunks[rollback[0]['chunk_id']], [1, 2, 3, 4])

    def test_atomic_range_carries_complete_forward_and_rollback_content(self):
        bundle = build_simple(
            [0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 7, 0, 0, 0, 0, 0],
            atomic_ranges=[{'id': 'ar1', 'base': 0, 'size': 8}],
        )
        row = target_row(bundle)
        self.assertEqual(len(row['forward']), 1)
        unit = row['forward'][0]
        self.assertEqual(unit['atomic_range'], 'ar1')
        self.assertEqual((unit['base'], unit['size']), (0, 8))
        chunks = bundle_chunks(bundle)
        self.assertEqual(chunks[unit['chunk_id']],
                         [0, 0, 7, 0, 0, 0, 0, 0])
        rb_unit = row['rollback'][0]
        self.assertEqual(rb_unit['atomic_range'], 'ar1')
        self.assertEqual(chunks[rb_unit['chunk_id']], [0] * 8)

    def test_same_payload_deduplicates_across_address_direction_and_target(self):
        plan = one_object_plan(sections=[
            section(name='a', size=2, alignment=1),
            section(name='b', size=2, alignment=16),
        ])
        current = make_release('cur', plan, {
            ('o', 'a'): [0xAA, 0xBB],
            ('o', 'b'): [0xEE, 0xFF],
        })
        candidate = make_release('cand', plan, {
            ('o', 'a'): [0xCC, 0xDD],
            ('o', 'b'): [0xAA, 0xBB],
        })
        data = {
            'releases': [current, candidate],
            'targets': [
                make_target('t1'),
                make_target('t2'),
            ],
            'receipts': [],
        }
        bundle = build_release_bundle(data)
        chunks = bundle_chunks(bundle)
        aa_bb = canonical_chunk_id([0xAA, 0xBB])
        self.assertEqual(set(chunks), {
            aa_bb,
            canonical_chunk_id([0xCC, 0xDD]),
            canonical_chunk_id([0xEE, 0xFF]),
        })
        t1 = target_row(bundle, 't1')
        rb0 = unit_by_base(t1['rollback'], 0)
        fwd16 = unit_by_base(t1['forward'], 16)
        self.assertEqual(rb0['chunk_id'], aa_bb)
        self.assertEqual(fwd16['chunk_id'], aa_bb)
        t2 = target_row(bundle, 't2')
        self.assertEqual(unit_by_base(t2['rollback'], 0)['chunk_id'], aa_bb)
        self.assertEqual(unit_by_base(t2['forward'], 16)['chunk_id'], aa_bb)
        self.assertEqual(bundle['summary']['chunks'], 3)

    def test_oversized_unsplittable_chunk_is_rejected(self):
        with self.assertRaises(ValueError):
            build_simple(
                [0, 0, 0, 0],
                [1, 0, 0, 0],
                atomic_ranges=[{'id': 'ar', 'base': 0, 'size': 4}],
                max_batch_bytes=3,
            )

    def test_identical_current_and_candidate_produce_empty_manifest(self):
        plan = one_object_plan(sections=[section(size=4)])
        release = make_release('same', plan, {('o', 's'): [1, 2, 3, 4]})
        bundle = build_release_bundle({
            'releases': [release],
            'targets': [make_target(current='same', candidate='same',
                                    atomic_ranges=[
                                        {'id': 'ar', 'base': 0, 'size': 4}])],
            'receipts': [],
        })
        row = target_row(bundle)
        self.assertEqual(row['forward'], [])
        self.assertEqual(row['rollback'], [])
        self.assertEqual(row['status'], 'up_to_date')
        self.assertIsNone(row['receipt_id'])
        self.assertEqual(row['pending_batches'], [])
        self.assertEqual(bundle['summary']['up_to_date_targets'], 1)
        self.assertRegex(bundle['bundle_id'], r'^[0-9a-f]{64}$')

    def test_atomic_range_boundary_changes_bundle_id_even_when_empty(self):
        plan = one_object_plan(sections=[section(size=8)])
        release = make_release('same', plan)

        def identify(size):
            result = build_release_bundle({
                'releases': [release],
                'targets': [make_target(
                    current='same', candidate='same',
                    atomic_ranges=[{'id': 'ar', 'base': 0, 'size': size}])],
                'receipts': [],
            })
            return result['bundle_id']

        self.assertNotEqual(identify(4), identify(8))


class ReceiptContinuationTests(unittest.TestCase):
    def test_pending_batches_pack_until_capacity_then_open_next_batch(self):
        bundle = build_simple(
            [0, 0, 0, 0], [1, 0, 2, 0], max_batch_bytes=2)
        row = target_row(bundle)
        self.assertEqual([b['chunk_ids'] for b in row['pending_batches']], [
            row['pending_chunks'][:2],
            row['pending_chunks'][2:],
        ])
        self.assertEqual([b['bytes'] for b in row['pending_batches']], [2, 1])
        for batch in row['pending_batches']:
            self.assertLessEqual(batch['bytes'], 2)

    def test_latest_receipt_wins_and_transfer_resumes(self):
        bundle = build_simple(
            [0, 0, 0, 0], [1, 0, 2, 0], max_batch_bytes=1)
        row = target_row(bundle)
        refs = set(row['pending_chunks'])
        first_chunk = row['pending_batches'][0]['chunk_ids'][0]
        other_chunks = sorted(refs - {first_chunk})
        bundle_id = bundle['bundle_id']

        # 较早 receipt 即使确认了其他 chunk，也不能与最新 receipt 拼接。
        data = build_simple_input(
            [0, 0, 0, 0], [1, 0, 2, 0], max_batch_bytes=1)
        data['receipts'] = [
            {
                'id': 'r-old', 'target': 't1', 'bundle_id': bundle_id,
                'observed_at': 5, 'acked_chunks': other_chunks,
            },
            {
                'id': 'r-new', 'target': 't1', 'bundle_id': bundle_id,
                'observed_at': 10, 'acked_chunks': [first_chunk],
            },
        ]
        resumed = build_release_bundle(data)
        resumed_row = target_row(resumed)
        self.assertEqual(resumed_row['receipt_id'], 'r-new')
        self.assertEqual(resumed_row['acknowledged_chunks'], [first_chunk])
        self.assertEqual(
            resumed_row['pending_chunks'], sorted(refs - {first_chunk}))
        self.assertEqual(len(resumed_row['pending_batches']), 2)
        self.assertEqual(
            resumed_row['pending_batches'][0]['chunk_ids'],
            [sorted(refs - {first_chunk})[0]])
        for batch in resumed_row['pending_batches']:
            self.assertLessEqual(batch['bytes'], 1)
        self.assertEqual(resumed_row['status'], 'transfer_pending')

        # 所有 chunk 均确认后，完整 manifest 仍返回，但状态为 ready。
        data['receipts'] = [{
            'id': 'r-all', 'target': 't1', 'bundle_id': bundle_id,
            'observed_at': 20, 'acked_chunks': sorted(refs),
        }]
        ready = build_release_bundle(data)
        ready_row = target_row(ready)
        self.assertEqual(ready_row['status'], 'ready')
        self.assertEqual(ready_row['pending_chunks'], [])
        self.assertEqual(ready_row['pending_batches'], [])
        self.assertEqual(len(ready_row['forward']), 2)
        self.assertEqual(len(ready_row['rollback']), 2)

    def test_old_bundle_receipt_does_not_credit_current_bundle(self):
        bundle = build_simple([0, 0], [1, 2])
        refs = target_row(bundle)['pending_chunks']
        data = build_simple_input([0, 0], [1, 2])
        data['receipts'] = [{
            'id': 'old',
            'target': 't1',
            'bundle_id': 'old-bundle',
            'observed_at': 1,
            # 旧 bundle id 下的 chunk 不需要存在于当前 bundle。
            'acked_chunks': ['f' * 64],
        }]
        result = build_release_bundle(data)
        row = target_row(result)
        self.assertIsNone(row['receipt_id'])
        self.assertEqual(row['acknowledged_chunks'], [])
        self.assertEqual(row['pending_chunks'], refs)
        self.assertEqual(row['status'], 'transfer_pending')

    def test_receipt_for_other_target_chunk_is_rejected(self):
        first = build_simple([0, 0], [1, 2], target_id='t1')
        # 构造另一个具有不同 payload 的目标。
        plan = one_object_plan(sections=[section(size=2)])
        releases = [
            make_release('cur', plan, {('o', 's'): [9, 9]}),
            make_release('cand', plan, {('o', 's'): [8, 8]}),
        ]
        second_input = {
            'releases': releases,
            'targets': [make_target('t2')],
            'receipts': [],
        }
        second = build_release_bundle(second_input)
        t1_chunk = target_row(first)['forward'][0]['chunk_id']
        bundle_id = second['bundle_id']

        bad = copy.deepcopy(second_input)
        bad['receipts'] = [{
            'id': 'bad-receipt',
            'target': 't2',
            'bundle_id': bundle_id,
            'observed_at': 1,
            'acked_chunks': [t1_chunk],
        }]
        with self.assertRaises(ValueError):
            build_release_bundle(bad)


class DeterminismAndValidationTests(unittest.TestCase):
    def test_older_matching_bundle_receipt_with_bad_chunk_also_rejected(self):
        data = build_simple_input([0, 0], [1, 2])
        bundle_id = build_release_bundle(data)['bundle_id']
        data['receipts'] = [
            {
                'id': 'r-old-bad', 'target': 't1', 'bundle_id': bundle_id,
                'observed_at': 1, 'acked_chunks': ['0' * 64],
            },
            {
                'id': 'r-new-good', 'target': 't1', 'bundle_id': bundle_id,
                'observed_at': 2, 'acked_chunks': [],
            },
        ]
        with self.assertRaises(ValueError):
            build_release_bundle(data)

    def test_input_reorder_does_not_change_bundle_id(self):
        plan = one_object_plan(sections=[
            section(name='a', size=2, alignment=1),
            section(name='b', size=2, alignment=16),
        ])
        current = make_release('cur', plan, {
            ('o', 'a'): [1, 2],
            ('o', 'b'): [3, 4],
        })
        candidate = make_release('cand', plan, {
            ('o', 'a'): [5, 6],
            ('o', 'b'): [7, 8],
        })
        target = make_target('t1', atomic_ranges=[
            {'id': 'ar-a', 'base': 0, 'size': 2},
            {'id': 'ar-b', 'base': 16, 'size': 2},
        ])
        data = {
            'releases': [current, candidate],
            'targets': [target, make_target('t2')],
            'receipts': [{
                'id': 'r1', 'target': 't1',
                # 先用合法形式，bundle_id 在首次构建后替换。
                'bundle_id': 'placeholder', 'observed_at': 1,
                'acked_chunks': [],
            }],
        }
        bundle_id = build_release_bundle(data)['bundle_id']
        data['receipts'][0]['bundle_id'] = bundle_id
        original = build_release_bundle(data)

        reordered = copy.deepcopy(data)
        reordered['releases'].reverse()
        reordered['targets'].reverse()
        reordered['receipts'].reverse()
        for release in reordered['releases']:
            release['images'].reverse()
        for target in reordered['targets']:
            if target['id'] == 't1':
                target['atomic_ranges'].reverse()
        reordered['releases'][0]['plan']['objects'][0]['sections'].reverse()

        reordered_result = build_release_bundle(reordered)
        self.assertEqual(reordered_result['bundle_id'], original['bundle_id'])
        self.assertEqual(
            [r['id'] for r in reordered_result['releases']],
            ['cand', 'cur'])
        self.assertEqual(
            [t['id'] for t in reordered_result['targets']], ['t1', 't2'])

    def test_invalid_inputs_reject_with_value_error(self):
        valid = build_simple_input([0], [1])

        bad = copy.deepcopy(valid)
        bad['unknown'] = True
        with self.assertRaises(ValueError):
            build_release_bundle(bad)

        bad = copy.deepcopy(valid)
        bad['targets'][0]['erase_byte'] = True
        with self.assertRaises(ValueError):
            build_release_bundle(bad)

        bad = copy.deepcopy(valid)
        bad['releases'][1]['images'][0]['bytes'][0] = 256
        with self.assertRaises(ValueError):
            build_release_bundle(bad)

        bad = copy.deepcopy(valid)
        bad['releases'].append(copy.deepcopy(bad['releases'][0]))
        with self.assertRaises(ValueError):
            build_release_bundle(bad)

        bad = copy.deepcopy(valid)
        bad['targets'][0]['current'] = 'missing'
        with self.assertRaises(ValueError):
            build_release_bundle(bad)

        bad = copy.deepcopy(valid)
        bad['releases'][0]['plan']['regions'] = []
        with self.assertRaises(ValueError):
            build_release_bundle(bad)

        bad = copy.deepcopy(valid)
        bad['receipts'] = [{
            'id': 'r', 'target': 't1', 'bundle_id': 'b',
            'observed_at': 1, 'acked_chunks': ['NOT_HEX'],
        }]
        with self.assertRaises(ValueError):
            build_release_bundle(bad)

    def test_existing_apis_remain_importable(self):
        self.assertTrue(callable(process))
        self.assertTrue(callable(link))
        self.assertTrue(callable(certify))
        self.assertTrue(callable(assess_upgrade))


def build_simple_input(cur_bytes, cand_bytes, size=None,
                       max_batch_bytes=65536):
    size = size or len(cur_bytes)
    plan = one_object_plan(sections=[section(size=size)])
    return {
        'releases': [
            make_release('cur', plan, {('o', 's'): cur_bytes}),
            make_release('cand', plan, {('o', 's'): cand_bytes}),
        ],
        'targets': [make_target(max_batch_bytes=max_batch_bytes)],
        'receipts': [],
    }


def bundle_chunks(bundle):
    return {chunk['chunk_id']: chunk['bytes'] for chunk in bundle['chunks']}


if __name__ == '__main__':
    unittest.main()
