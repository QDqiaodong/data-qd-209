import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from obj_reloc.archive import (
    ArchiveCapacityError,
    CredentialError,
    ImageArchive,
    RequestMismatchError,
)


L = 'a-low'
H = 'b-high'
SRC = Path(__file__).resolve().parents[1] / 'src'


class SimulatedInterrupt(RuntimeError):
    """Raised before the atomic commit point."""


class SimulatedNoReply(RuntimeError):
    """Raised after a durable commit but before the caller gets a response."""


def windows_lh():
    return [
        {'id': L, 'base': 240, 'size': 16},
        {'id': H, 'base': 256, 'size': 16},
    ]


def byte_image_object(jid, width):
    return {
        'id': f'{jid}-obj',
        'sections': [{
            'name': 's',
            'region': 'image',
            'size': 8,
            'alignment': 8,
        }],
        'symbols': [{
            'name': 'x',
            'section': 's',
            'offset': 0,
            'binding': 'local',
        }],
        'relocations': [{
            'id': 'r',
            'section': 's',
            'offset': 0,
            'symbol': {'scope': 'local', 'name': 'x'},
            'addend': 0,
            'width': width,
        }],
    }


def byte_job(jid, width, window_ids=(L, H)):
    return {
        'job_id': jid,
        'window_ids': list(window_ids),
        'objects': [byte_image_object(jid, width)],
    }


def acceptance_request():
    # Deliberately reverse job-id order to prove input order is irrelevant.
    return {'request_id': 'req-accept', 'jobs': [byte_job('z', 1), byte_job('a', 2)]}


def trivial_job(jid, window_ids=('w0', 'w1'), width=8):
    return {
        'job_id': jid,
        'window_ids': list(window_ids),
        'objects': [{
            'id': f'{jid}-obj',
            'sections': [{'name': 's', 'region': 'image', 'size': 8, 'alignment': 1}],
            'symbols': [{
                'name': 'x', 'section': 's', 'offset': 0, 'binding': 'local',
            }],
            'relocations': [{
                'id': 'r', 'section': 's', 'offset': 0,
                'symbol': {'scope': 'local', 'name': 'x'},
                'addend': 0, 'width': width,
            }],
        }],
    }


def receipt_map(receipt):
    return {item['job_id']: item for item in receipt['items']}


class ImageArchiveTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.directory = Path(self._temp.name) / 'archive'
        self.archive = ImageArchive.create(self.directory, windows_lh())

    def tearDown(self):
        self.archive.close()
        self._temp.cleanup()

    def reopen(self):
        self.archive.close()
        self.archive = ImageArchive.open(self.directory)
        return self.archive

    def test_acceptance_encoding_selects_a_high_z_low(self):
        receipt = self.archive.allocate(acceptance_request())
        items = receipt_map(receipt)

        self.assertEqual(items['a']['window_id'], H)
        self.assertEqual(items['z']['window_id'], L)
        self.assertEqual(items['a']['link']['relocations'][0]['bytes'], [0, 1])
        self.assertEqual(items['z']['link']['relocations'][0]['bytes'], [240])

        self.assertEqual(
            self.archive.consume(items['a']['credential']), items['a']['link']
        )
        self.assertEqual(
            self.archive.consume(items['z']['credential']), items['z']['link']
        )

    def test_alignment_makes_bare_size_window_unusable(self):
        with tempfile.TemporaryDirectory() as td:
            # tight has bare capacity for size=8, but alignment moves the
            # section from base 101 to 104; 104+8 > 109.
            archive = ImageArchive.create(Path(td) / 'align', [
                {'id': 'ok', 'base': 0, 'size': 16},
                {'id': 'tight', 'base': 101, 'size': 8},
            ])
            job = byte_job('align-job', 4, ['tight'])
            job['objects'][0]['sections'][0]['alignment'] = 8
            req = {'request_id': 'align-only', 'jobs': [job]}
            self.assertEqual(archive.allocate(req)['status'], 'no_capacity')
            with self.assertRaises(ValueError):
                archive.get_receipt('align-only')

            job['window_ids'] = ['ok', 'tight']
            receipt = archive.allocate({
                'request_id': 'align-both', 'jobs': [job],
            })
            self.assertEqual(receipt['items'][0]['window_id'], 'ok')
            archive.close()

    def test_lexicographically_smallest_of_two_complete_plans(self):
        with tempfile.TemporaryDirectory() as td:
            # Alphabetically earlier window is at the higher address.  Width 8
            # makes encoding valid at both, so both one-to-one plans work.
            archive = ImageArchive.create(Path(td) / 'lex', [
                {'id': 'zzz-low', 'base': 240, 'size': 16},
                {'id': 'aaa-high', 'base': 256, 'size': 16},
            ])
            receipt = archive.allocate({
                'request_id': 'lex',
                'jobs': [trivial_job('z', ['zzz-low', 'aaa-high']),
                         trivial_job('a', ['zzz-low', 'aaa-high'])],
            })
            items = receipt_map(receipt)
            self.assertEqual(items['a']['window_id'], 'aaa-high')
            self.assertEqual(items['z']['window_id'], 'zzz-low')
            archive.close()

    def test_backtracking_finds_complete_batch_instead_of_greedy_failure(self):
        with tempfile.TemporaryDirectory() as td:
            archive = ImageArchive.create(Path(td) / 'backtrack', [
                {'id': 'w1', 'base': 0, 'size': 16},
                {'id': 'w2', 'base': 16, 'size': 16},
            ])
            receipt = archive.allocate({'request_id': 'bt', 'jobs': [
                trivial_job('j2', ['w1']),
                trivial_job('j1', ['w1', 'w2']),
            ]})
            items = receipt_map(receipt)
            # Greedily giving j1=w1 would strand j2; lex-first complete plan
            # is j1=w2, j2=w1.
            self.assertEqual(items['j1']['window_id'], 'w2')
            self.assertEqual(items['j2']['window_id'], 'w1')
            archive.close()

    def test_no_complete_plan_has_no_partial_occupancy(self):
        response = self.archive.allocate({'request_id': 'impossible', 'jobs': [
            byte_job('a', 2, [L]),
            byte_job('b', 2, [L]),
        ]})
        self.assertEqual(response['status'], 'no_capacity')
        self.assertTrue(all(w['available'] for w in self.archive.window_usage()))
        with self.assertRaises(ValueError):
            self.archive.get_receipt('impossible')

    def test_whole_window_is_not_split_after_small_linked_section(self):
        req = {'request_id': 'small', 'jobs': [trivial_job('j', [L, H])]}
        receipt = self.archive.allocate(req)
        wid = receipt['items'][0]['window_id']
        second = self.archive.allocate({
            'request_id': 'small-2',
            'jobs': [trivial_job('j2', [wid])],
        })
        self.assertEqual(second['status'], 'no_capacity')

    def test_full_lifecycle_release_retry_reorder_and_conflict(self):
        first_request = acceptance_request()
        first_receipt = self.archive.allocate(first_request)
        first_items = receipt_map(first_receipt)
        a_cred = first_items['a']['credential']
        z_cred = first_items['z']['credential']

        l_only = {
            'request_id': 'req-l-only',
            'jobs': [byte_job('solo', 1, [L])],
        }
        self.assertEqual(self.archive.allocate(l_only)['status'], 'no_capacity')

        released = self.archive.release(z_cred)
        self.assertTrue(released['changed'])
        self.assertFalse(released['already_released'])

        # Close and reopen before the delayed retry/use sequence.
        self.reopen()

        second_receipt = self.archive.allocate(copy.deepcopy(l_only))
        second_item = second_receipt['items'][0]
        second_cred = second_item['credential']
        self.assertEqual(second_item['window_id'], L)
        self.assertEqual(
            second_item['link']['relocations'][0]['bytes'], [240]
        )
        self.assertEqual(
            self.archive.consume(second_cred), second_item['link']
        )
        self.assertEqual(self.archive.consume(a_cred), first_items['a']['link'])
        with self.assertRaises(CredentialError):
            self.archive.consume(z_cred)

        history = self.archive.get_receipt('req-accept')
        self.assertEqual(history, first_receipt)
        self.assertEqual(
            receipt_map(history)['z']['link']['relocations'][0]['bytes'], [240]
        )

        # A delayed old release must be idempotent and cannot evict the new L.
        old_release_again = self.archive.release(z_cred)
        self.assertFalse(old_release_again['changed'])
        self.assertTrue(old_release_again['already_released'])
        self.assertEqual(
            self.archive.consume(second_cred), second_item['link']
        )
        self.assertEqual(
            [w for w in self.archive.window_usage() if w['id'] == L][0]
            ['holder']['credential'],
            second_cred,
        )

        # Reorder jobs, candidate IDs and every object record array.
        reordered = copy.deepcopy(first_request)
        reordered['jobs'] = list(reversed(reordered['jobs']))
        for job in reordered['jobs']:
            job['window_ids'] = list(reversed(job['window_ids']))
            obj = job['objects'][0]
            for array_name in ('sections', 'symbols', 'relocations'):
                obj[array_name] = list(reversed(obj[array_name]))
        replay = self.archive.allocate(reordered)
        self.assertEqual(replay, first_receipt)

        # Replay did not restore old z or change current L holder.
        with self.assertRaises(CredentialError):
            self.archive.consume(z_cred)
        self.assertEqual(self.archive.consume(second_cred), second_item['link'])

        changed = copy.deepcopy(first_request)
        changed['jobs'][0]['objects'][0]['relocations'][0]['addend'] = 7
        with self.assertRaises(RequestMismatchError):
            self.archive.allocate(changed)
        self.assertEqual(self.archive.get_receipt('req-accept'), first_receipt)

        with self.assertRaises(CredentialError):
            self.archive.consume('cred_unknown')
        with self.assertRaises(CredentialError):
            self.archive.release('cred_unknown')

    def test_invalid_reference_rejected_when_windows_are_full(self):
        self.archive.allocate(acceptance_request())
        bad = {
            'request_id': 'bad-ref-full',
            'jobs': [{
                'job_id': 'bad',
                'window_ids': [L],
                'objects': [{
                    'id': 'bad-obj',
                    'sections': [{
                        'name': 's', 'region': 'image',
                        'size': 8, 'alignment': 1,
                    }],
                    'symbols': [],
                    'relocations': [{
                        'id': 'r', 'section': 's', 'offset': 0,
                        'symbol': {'scope': 'global', 'name': 'missing'},
                        'addend': 0, 'width': 4,
                    }],
                }],
            }],
        }
        with self.assertRaises(ValueError):
            self.archive.allocate(bad)
        with self.assertRaises(ValueError):
            self.archive.get_receipt('bad-ref-full')
        self.assertFalse(all(w['available'] for w in self.archive.window_usage()))

    def test_location_independent_request_errors(self):
        valid_object = byte_image_object('j', 4)

        def req(job_id='j', windows=(L,), objects=(valid_object,), rid='r'):
            return {'request_id': rid, 'jobs': [{
                'job_id': job_id,
                'window_ids': list(windows),
                'objects': list(objects),
            }]}

        strong_a = copy.deepcopy(valid_object)
        strong_a['symbols'][0]['binding'] = 'strong'
        strong_b = copy.deepcopy(valid_object)
        strong_b['id'] = 'j-obj-2'
        strong_b['symbols'][0]['binding'] = 'strong'
        strong_b['symbols'][0]['name'] = 'x'
        strong_b['relocations'] = []

        cases = [
            ('unknown-window', req(rid='unknown-window', windows=('nope',))),
            ('duplicate-job', {
                'request_id': 'duplicate-job',
                'jobs': [
                    {'job_id': 'same', 'window_ids': [L], 'objects': [valid_object]},
                    {'job_id': 'same', 'window_ids': [H], 'objects': [valid_object]},
                ],
            }),
            ('duplicate-window', req(
                rid='duplicate-window', windows=[L, L])),
            ('empty-windows', req(rid='empty-windows', windows=[])),
            ('no-sections', req(
                rid='no-sections',
                objects=[{'id': 'o', 'sections': [], 'symbols': [],
                          'relocations': []}])),
            ('undefined-reference', req(
                rid='undefined-reference',
                objects=[{
                    'id': 'o',
                    'sections': [{'name': 's', 'region': 'image',
                                  'size': 8, 'alignment': 1}],
                    'symbols': [],
                    'relocations': [{
                        'id': 'r', 'section': 's', 'offset': 0,
                        'symbol': {'scope': 'global', 'name': 'missing'},
                        'addend': 0, 'width': 4,
                    }],
                }])),
            ('duplicate-strong', req(
                rid='duplicate-strong', objects=[strong_a, strong_b])),
        ]
        for label, bad_request in cases:
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    self.archive.allocate(bad_request)

        self.assertTrue(all(w['available'] for w in self.archive.window_usage()))

    def test_equal_symbol_names_are_independent_between_images(self):
        def strong_job(jid):
            return {
                'job_id': jid,
                'window_ids': [L, H],
                'objects': [{
                    'id': f'{jid}-o',
                    'sections': [{'name': 's', 'region': 'image',
                                  'size': 8, 'alignment': 1}],
                    'symbols': [{'name': 'main', 'section': 's',
                                 'offset': 0, 'binding': 'strong'}],
                    'relocations': [{
                        'id': 'r', 'section': 's', 'offset': 0,
                        'symbol': {'scope': 'global', 'name': 'main'},
                        'addend': 0, 'width': 8,
                    }],
                }],
            }

        receipt = self.archive.allocate({
            'request_id': 'same-symbol',
            'jobs': [strong_job('z'), strong_job('a')],
        })
        items = receipt_map(receipt)
        self.assertEqual(items['a']['window_id'], L)
        self.assertEqual(items['z']['window_id'], H)
        self.assertEqual(
            items['a']['link']['relocations'][0]['target']['object'], 'a-o'
        )
        self.assertEqual(
            items['z']['link']['relocations'][0]['target']['object'], 'z-o'
        )

    def test_all_object_record_array_reorderings_are_equivalent(self):
        def object_table(oid):
            return {
                'id': oid,
                'sections': [
                    {'name': 'b', 'region': 'image', 'size': 1, 'alignment': 1},
                    {'name': 'a', 'region': 'image', 'size': 1, 'alignment': 1},
                ],
                'symbols': [
                    {'name': 'sb', 'section': 'b', 'offset': 0,
                     'binding': 'local'},
                    {'name': 'sa', 'section': 'a', 'offset': 0,
                     'binding': 'local'},
                ],
                'relocations': [
                    {'id': 'rb', 'section': 'b', 'offset': 0,
                     'symbol': {'scope': 'local', 'name': 'sb'},
                     'addend': 0, 'width': 1},
                    {'id': 'ra', 'section': 'a', 'offset': 0,
                     'symbol': {'scope': 'local', 'name': 'sa'},
                     'addend': 0, 'width': 1},
                ],
            }

        request = {
            'request_id': 'record-order',
            'jobs': [{
                'job_id': 'j',
                'window_ids': [H, L],
                'objects': [object_table('o2'), object_table('o1')],
            }],
        }
        receipt = self.archive.allocate(request)

        variant = copy.deepcopy(request)
        job = variant['jobs'][0]
        job['window_ids'].reverse()
        job['objects'].reverse()
        for obj in job['objects']:
            obj['sections'].reverse()
            obj['symbols'].reverse()
            obj['relocations'].reverse()
        self.assertEqual(self.archive.allocate(variant), receipt)

    def test_window_catalog_validation(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ValueError):
                ImageArchive.create(Path(td) / 'overlap', [
                    {'id': 'a', 'base': 0, 'size': 17},
                    {'id': 'b', 'base': 16, 'size': 8},
                ])
            with self.assertRaises(ValueError):
                ImageArchive.create(Path(td) / 'bad-range', [
                    {'id': 'a', 'base': -1, 'size': 8},
                ])

    def test_reopen_rejects_a_silent_catalog_replacement(self):
        with self.assertRaises(ValueError):
            ImageArchive.open(self.directory, [
                {'id': L, 'base': 1, 'size': 16},
                {'id': H, 'base': 256, 'size': 16},
            ])
        reopened = ImageArchive.open(self.directory, windows_lh())
        self.assertEqual(
            [(w['id'], w['base'], w['size']) for w in reopened.window_usage()],
            [(L, 240, 16), (H, 256, 16)],
        )
        reopened.close()

    def test_issued_job_limit_128_rejects_entire_excess_batch(self):
        with tempfile.TemporaryDirectory() as td:
            windows = [
                {'id': f'w{i}', 'base': i * 16, 'size': 16}
                for i in range(8)
            ]
            archive = ImageArchive.create(Path(td) / 'limit', windows)
            first_request = None
            try:
                for batch in range(16):
                    count = 8 if batch < 15 else 7
                    request = {
                        'request_id': f'batch-{batch}',
                        'jobs': [
                            trivial_job(f'j{i}', [f'w{k}' for k in range(8)])
                            for i in range(count)
                        ],
                    }
                    if batch == 0:
                        first_request = copy.deepcopy(request)
                    receipt = archive.allocate(request)
                    for item in receipt['items']:
                        archive.release(item['credential'])

                self.assertEqual(
                    len(json.loads(archive.path.read_text())['credentials']), 127
                )
                too_big = {
                    'request_id': 'over-by-two',
                    'jobs': [trivial_job('x1'), trivial_job('x2')],
                }
                with self.assertRaises(ArchiveCapacityError):
                    archive.allocate(too_big)
                with self.assertRaises(ValueError):
                    archive.get_receipt('over-by-two')
                self.assertTrue(all(w['available'] for w in archive.window_usage()))

                one = archive.allocate({
                    'request_id': 'one-more', 'jobs': [trivial_job('x1')],
                })
                self.assertEqual(len(one['items']), 1)
                with self.assertRaises(ArchiveCapacityError):
                    archive.allocate({
                        'request_id': 'one-too-many',
                        'jobs': [trivial_job('x2')],
                    })

                # History replay and old idempotent release remain available.
                replay = archive.allocate(first_request)
                self.assertEqual(replay['request_id'], 'batch-0')
                old_cred = replay['items'][0]['credential']
                repeat = archive.release(old_cred)
                self.assertTrue(repeat['already_released'])
                self.assertEqual(archive.get_receipt('batch-0'), replay)
            finally:
                archive.close()

    def test_precommit_interruption_is_atomic_and_reopenable(self):
        request = acceptance_request()
        with mock.patch.object(os, 'replace', side_effect=SimulatedInterrupt):
            with self.assertRaises(SimulatedInterrupt):
                self.archive.allocate(request)

        reopened = self.reopen()
        with self.assertRaises(ValueError):
            reopened.get_receipt('req-accept')
        self.assertTrue(all(w['available'] for w in reopened.window_usage()))

        # The same ID is unused and both windows can still be granted.
        receipt = reopened.allocate(copy.deepcopy(request))
        self.assertEqual(len(receipt['items']), 2)

    def test_postcommit_lost_reply_retry_returns_original_receipt(self):
        request = acceptance_request()
        real_commit = self.archive._commit_state

        def commit_then_lose_reply(state):
            real_commit(state)
            raise SimulatedNoReply('caller did not receive the response')

        self.archive._commit_state = commit_then_lose_reply
        with self.assertRaises(SimulatedNoReply):
            self.archive.allocate(request)

        reopened = self.reopen()
        receipt_before_retry = reopened.get_receipt('req-accept')
        self.assertEqual(len(receipt_before_retry['items']), 2)
        self.assertFalse(all(w['available'] for w in reopened.window_usage()))
        credential_count = len(
            json.loads(reopened.path.read_text())['credentials']
        )
        self.assertEqual(credential_count, 2)

        retry_receipt = reopened.allocate(copy.deepcopy(request))
        self.assertEqual(retry_receipt, receipt_before_retry)
        self.assertEqual(
            len(json.loads(reopened.path.read_text())['credentials']), 2
        )

    def test_release_crash_boundaries_and_delayed_retry_protection(self):
        # Pre-commit release: the old credential remains effective.
        solo_request = {
            'request_id': 'solo',
            'jobs': [byte_job('solo', 1, [L])],
        }
        solo_receipt = self.archive.allocate(solo_request)
        solo_cred = solo_receipt['items'][0]['credential']
        with mock.patch.object(os, 'replace', side_effect=SimulatedInterrupt):
            with self.assertRaises(SimulatedInterrupt):
                self.archive.release(solo_cred)

        archive = self.reopen()
        self.assertTrue(archive.credential_info(solo_cred)['effective'])
        archive.consume(solo_cred)
        # Finish that release so the next full acceptance batch can use L.
        self.assertTrue(archive.release(solo_cred)['changed'])

        # Post-commit release: response is lost after durable commit.
        accept = archive.allocate(acceptance_request())
        z_cred = receipt_map(accept)['z']['credential']
        real_commit = archive._commit_state

        def commit_then_lose_reply(state):
            real_commit(state)
            raise SimulatedNoReply

        archive._commit_state = commit_then_lose_reply
        with self.assertRaises(SimulatedNoReply):
            archive.release(z_cred)

        archive = self.reopen()
        info = archive.credential_info(z_cred)
        self.assertFalse(info['effective'])
        self.assertEqual(info['stored_status'], 'released')
        with self.assertRaises(CredentialError):
            archive.consume(z_cred)

        delayed = archive.release(z_cred)
        self.assertTrue(delayed['already_released'])

        new_receipt = archive.allocate({
            'request_id': 'new-l',
            'jobs': [byte_job('new', 1, [L])],
        })
        new_cred = new_receipt['items'][0]['credential']
        self.assertNotEqual(new_cred, z_cred)

        # Delayed old release retries must never clear the new holder.
        for _ in range(2):
            again = archive.release(z_cred)
            self.assertTrue(again['already_released'])
        archive.consume(new_cred)
        archive = self.reopen()
        archive.consume(new_cred)
        self.assertEqual(
            archive.window_usage()[0]['holder']['credential'], new_cred
        )


CHILD_CODE = r'''
import json
import sys

sys.path.insert(0, sys.argv[1])
from obj_reloc.archive import open_archive

directory = sys.argv[2]
action = sys.argv[3]
archive = open_archive(directory)

def obj(jid, width):
    return {
        "id": jid + "-obj",
        "sections": [{"name": "s", "region": "image", "size": 8,
                      "alignment": 8}],
        "symbols": [{"name": "x", "section": "s", "offset": 0,
                     "binding": "local"}],
        "relocations": [{"id": "r", "section": "s", "offset": 0,
                         "symbol": {"scope": "local", "name": "x"},
                         "addend": 0, "width": width}],
    }

def job(jid, width, windows=("a-low", "b-high")):
    return {"job_id": jid, "window_ids": list(windows),
            "objects": [obj(jid, width)]}

if action == "allocate":
    receipt = archive.allocate({"request_id": "cross",
                                "jobs": [job("z", 1), job("a", 2)]})
    items = {i["job_id"]: i for i in receipt["items"]}
    print(json.dumps({"a": items["a"]["credential"],
                      "z": items["z"]["credential"]}))
elif action == "consume-release":
    a_cred, z_cred = sys.argv[4], sys.argv[5]
    a_link = archive.consume(a_cred)
    z_link = archive.consume(z_cred)
    assert a_link["relocations"][0]["bytes"] == [0, 1]
    assert z_link["relocations"][0]["bytes"] == [240]
    archive.release(z_cred)
    print(json.dumps({"ok": True}))
elif action == "reallocate":
    old_z = sys.argv[4]
    try:
        archive.consume(old_z)
    except ValueError:
        pass
    else:
        raise AssertionError("old credential unexpectedly usable")
    receipt = archive.allocate({"request_id": "cross-l",
                                "jobs": [job("solo", 1, ("a-low",))]})
    print(json.dumps({"credential": receipt["items"][0]["credential"]}))
else:
    raise AssertionError(action)
archive.close()
'''


class CrossProcessArchiveTests(unittest.TestCase):
    def test_separate_python_processes_use_same_archive_sequentially(self):
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td) / 'cross'
            ImageArchive.create(directory, windows_lh()).close()

            def run_child(*args):
                env = os.environ.copy()
                pythonpath = str(SRC)
                if env.get('PYTHONPATH'):
                    pythonpath += os.pathsep + env['PYTHONPATH']
                env['PYTHONPATH'] = pythonpath
                completed = subprocess.run(
                    [sys.executable, '-I', '-c', CHILD_CODE,
                     str(SRC), str(directory), *args],
                    check=True, text=True, capture_output=True, env=env,
                )
                return json.loads(completed.stdout.strip().splitlines()[-1])

            credentials = run_child('allocate')
            self.assertIn('a', credentials)
            self.assertIn('z', credentials)
            run_child('consume-release', credentials['a'], credentials['z'])
            second = run_child('reallocate', credentials['z'])
            self.assertNotEqual(second['credential'], credentials['z'])

            archive = ImageArchive.open(directory)
            try:
                self.assertEqual(
                    archive.consume(second['credential'])['relocations'][0]['bytes'],
                    [240],
                )
                self.assertEqual(
                    archive.consume(credentials['a'])['relocations'][0]['bytes'],
                    [0, 1],
                )
            finally:
                archive.close()


if __name__ == '__main__':
    unittest.main()
