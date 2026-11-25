"""Persistent batch allocation of disjoint image address windows.

An :class:`ImageArchive` owns a fixed window catalog in one archive directory.
Each successful batch atomically persists window occupancy, opaque credentials
and the original receipt containing the complete per-window ``link`` result.
The module plans structured address graphs only; it never writes target memory
or reads/writes executable files.
"""
from __future__ import annotations

import copy
import json
import os
import secrets
from collections import defaultdict
from contextlib import suppress
from pathlib import Path

from .checks import array, fields, ident, integer, unique
from .io import constant, pairs
from .linker import (
    LinkPlacementError,
    _check_references,
    _parse_link,
    _resolve_globals,
    link,
)

FORMAT = 'obj-reloc-image-archive'
VERSION = 1
ARCHIVE_FILENAME = 'image_archive.json'

MAX_WINDOWS = 16
MAX_JOBS = 8
MAX_ISSUED_JOBS = 128
DUMMY_REGION_SIZE = 100_000


class ArchiveError(ValueError):
    """Base ValueError for archive requests and credentials."""


class InvalidArchive(ArchiveError):
    """The archive directory or persisted state is not a valid archive."""


class ArchiveCapacityError(ArchiveError):
    """The archive's permanent 128 issued-job history limit would be exceeded."""


class RequestMismatchError(ArchiveError):
    """An existing request ID was reused with a different application."""


class CredentialError(ArchiveError):
    """A credential is unknown or no longer effective."""


def _one_identity(raw, label, names):
    present = [name for name in names if name in raw]
    if not present:
        raise ArchiveError(f'{label} id is required')
    values = [raw[name] for name in present]
    if any(value != values[0] for value in values[1:]):
        raise ArchiveError(f'conflicting {label} ids')
    return ident(values[0])


def _parse_windows(raw):
    windows = []
    for w in array(raw, 1, MAX_WINDOWS):
        fields(w, ('base', 'size'), ('id', 'window_id', 'name'))
        wid = _one_identity(w, 'window', ('id', 'window_id', 'name'))
        base = integer(w['base'], 0, 1_000_000)
        size = integer(w['size'], 1, 100_000)
        windows.append({'id': wid, 'base': base, 'size': size})

    unique([w['id'] for w in windows])
    ordered = sorted(windows, key=lambda w: w['base'])
    for left, right in zip(ordered, ordered[1:]):
        if left['base'] + left['size'] > right['base']:
            raise ArchiveError('overlapping address windows')
    return windows


def _same_window_catalog(left, right):
    key = lambda w: (w['id'], w['base'], w['size'])
    return sorted(left, key=key) == sorted(right, key=key)


def _semantically_validate_objects(objects):
    """Validate every location-independent link input error.

    A maximally sized dummy ``image`` region is used only to enter the existing
    link parser.  Layout/capacity and address-width encoding are deliberately
    not judged here; they are tested separately for each real window.
    """
    probe = {
        'regions': [{'name': 'image', 'base': 0, 'size': DUMMY_REGION_SIZE}],
        'objects': objects,
    }
    _regions, parsed_objects, totals = _parse_link(probe)
    if totals[0] < 1:
        raise ArchiveError('each job requires at least one section')

    # Addresses are unnecessary for duplicate-strong and reference identity
    # checks.  defaultdict(int) only satisfies address-bearing output setup.
    winners, _globals_out = _resolve_globals(parsed_objects, defaultdict(int))
    _check_references(parsed_objects, winners)


def _canonical_objects(objects):
    canonical = copy.deepcopy(objects)
    canonical.sort(key=lambda obj: obj['id'])
    for obj in canonical:
        obj['sections'].sort(key=lambda section: section['name'])
        obj['symbols'].sort(key=lambda symbol: symbol['name'])
        obj['relocations'].sort(key=lambda relocation: relocation['id'])
    return canonical


def _parse_allocation_request(raw, windows_by_id):
    if not isinstance(raw, dict):
        raise ArchiveError('allocation request must be an object')
    fields(raw, (), ('request_id', 'id', 'jobs'))
    request_id = _one_identity(raw, 'request', ('request_id', 'id'))
    jobs_raw = array(raw.get('jobs'), 1, MAX_JOBS)

    seen_jobs = set()
    jobs = []
    for job_raw in jobs_raw:
        if not isinstance(job_raw, dict):
            raise ArchiveError('job must be an object')
        fields(job_raw, (), ('job_id', 'id', 'window_ids', 'windows', 'objects'))
        job_id = _one_identity(job_raw, 'job', ('job_id', 'id'))
        if job_id in seen_jobs:
            raise ArchiveError('duplicate job id')
        seen_jobs.add(job_id)

        if 'window_ids' in job_raw and 'windows' in job_raw:
            if job_raw['window_ids'] != job_raw['windows']:
                raise ArchiveError('conflicting window id lists')
        window_ids_raw = job_raw.get('window_ids', job_raw.get('windows'))
        window_ids = array(window_ids_raw, 1, MAX_WINDOWS)
        for wid in window_ids:
            ident(wid)
        unique(window_ids)
        for wid in window_ids:
            if wid not in windows_by_id:
                raise ArchiveError(f'unknown window id: {wid}')

        objects = array(job_raw.get('objects'), 1, 32)
        # Raises the existing ValueError family for structural/reference errors.
        _semantically_validate_objects(objects)

        jobs.append({
            'job_id': job_id,
            'window_ids': sorted(window_ids),
            'objects': _canonical_objects(objects),
        })

    jobs.sort(key=lambda job: job['job_id'])
    canonical = {'request_id': request_id, 'jobs': jobs}
    return request_id, canonical


def _fsync_directory(directory):
    flags = os.O_RDONLY
    if hasattr(os, 'O_DIRECTORY'):
        flags |= os.O_DIRECTORY
    fd = os.open(str(directory), flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class ImageArchive:
    """A directory-backed archive with a fixed window catalog and receipts."""

    filename = ARCHIVE_FILENAME

    def __init__(self, directory, windows=None):
        self.directory = Path(directory)
        self.path = self.directory / self.filename
        self._closed = False
        if windows is not None:
            supplied = _parse_windows(windows)
            self.directory.mkdir(parents=True, exist_ok=True)
            if self.path.exists():
                state = self._read_state()
                self._validate_state(state)
                if not _same_window_catalog(supplied, state['windows']):
                    raise ArchiveError(
                        'supplied window catalog does not match the fixed archive catalog'
                    )
            else:
                self._commit_state(self._new_state(supplied))

    @staticmethod
    def _new_state(windows):
        return {
            'format': FORMAT,
            'version': VERSION,
            'archive_id': f'arc_{secrets.token_hex(16)}',
            'windows': windows,
            'requests': {},
            'credentials': {},
            'occupancy': {},
            'issued_job_count': 0,
            'next_credential': 1,
        }

    @classmethod
    def create(cls, directory, windows):
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        archive = cls(directory)
        if archive.path.exists():
            raise FileExistsError(f'archive already exists: {archive.path}')

        state = cls._new_state(_parse_windows(windows))
        archive._commit_state(state)
        return archive

    @classmethod
    def open(cls, directory, windows=None):
        archive = cls(directory)
        state = archive._read_state()
        archive._validate_state(state)
        if windows is not None:
            supplied = _parse_windows(windows)
            if not _same_window_catalog(supplied, state['windows']):
                raise ArchiveError(
                    'supplied window catalog does not match the fixed archive catalog'
                )
        archive._closed = False
        return archive

    @classmethod
    def create_or_open(cls, directory, windows):
        """Create a new archive, or open an existing one only if catalogs match."""
        path = Path(directory) / cls.filename
        if path.exists():
            return cls.open(directory, windows)
        return cls.create(directory, windows)

    def close(self):
        self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def _ensure_open(self):
        if self._closed:
            raise ArchiveError('archive is closed')

    def _validate_state(self, state):
        if not isinstance(state, dict):
            raise InvalidArchive('archive state must be an object')
        required = {
            'format', 'version', 'archive_id', 'windows', 'requests',
            'credentials', 'occupancy', 'issued_job_count', 'next_credential',
        }
        if not required.issubset(state):
            raise InvalidArchive('archive state is missing required fields')
        if state['format'] != FORMAT or state['version'] != VERSION:
            raise InvalidArchive('unsupported archive format/version')
        if not isinstance(state['archive_id'], str):
            raise InvalidArchive('invalid archive id')
        try:
            state['windows'] = _parse_windows(state['windows'])
        except ValueError as exc:
            raise InvalidArchive('invalid persisted window catalog') from exc
        for key in ('requests', 'credentials', 'occupancy'):
            if not isinstance(state[key], dict):
                raise InvalidArchive(f'invalid persisted {key}')
        if type(state['issued_job_count']) is not int:
            raise InvalidArchive('invalid issued job count')
        if type(state['next_credential']) is not int:
            raise InvalidArchive('invalid credential sequence')

    def _read_state(self):
        self._ensure_open()
        try:
            raw = self.path.read_bytes()
            state = json.loads(
                raw.decode('utf-8'),
                object_pairs_hook=pairs,
                parse_constant=constant,
            )
        except FileNotFoundError as exc:
            raise InvalidArchive(f'archive not found: {self.path}') from exc
        except (OSError, UnicodeError, ValueError) as exc:
            raise InvalidArchive(f'invalid archive state: {self.path}') from exc
        self._validate_state(state)
        return state

    def _commit_state(self, state):
        self._ensure_open()
        try:
            payload = (json.dumps(
                state,
                ensure_ascii=False,
                sort_keys=True,
                separators=(',', ':'),
                allow_nan=False,
            ) + '\n').encode('utf-8')
        except (TypeError, ValueError) as exc:
            raise ArchiveError('archive state is not JSON serializable') from exc

        self.directory.mkdir(parents=True, exist_ok=True)
        temporary = self.directory / (
            f'.{self.filename}.tmp-{os.getpid()}-{secrets.token_hex(8)}'
        )
        try:
            with open(temporary, 'wb') as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            # The atomic rename is the commit point.
            os.replace(temporary, self.path)
            _fsync_directory(self.directory)
        finally:
            with suppress(FileNotFoundError):
                temporary.unlink()

    @staticmethod
    def _plan_assignment(state, jobs):
        windows_by_id = {w['id']: w for w in state['windows']}
        occupied = set(state['occupancy'])
        options = {}

        for job in jobs:
            jid = job['job_id']
            job_options = []
            for wid in job['window_ids']:
                if wid in occupied:
                    continue
                window = windows_by_id[wid]
                trial = {
                    'regions': [{
                        'name': 'image',
                        'base': window['base'],
                        'size': window['size'],
                    }],
                    'objects': job['objects'],
                }
                try:
                    result = link(trial)
                except LinkPlacementError:
                    # Alignment/capacity or absolute-address encoding failure
                    # for exactly this window.
                    continue
                job_options.append((wid, result))
            options[jid] = job_options

        used_windows = set()
        chosen = []

        def search(index):
            if index == len(jobs):
                return True
            job = jobs[index]
            for wid, result in options[job['job_id']]:
                if wid in used_windows:
                    continue
                used_windows.add(wid)
                chosen.append((job, wid, result))
                if search(index + 1):
                    return True
                chosen.pop()
                used_windows.remove(wid)
            return False

        if search(0):
            return chosen
        return None

    def allocate(self, request):
        """Allocate a complete batch or return ``{'status': 'no_capacity'}``.

        Successful and equivalent idempotent calls return the stored receipt.
        """
        state = self._read_state()
        windows_by_id = {w['id']: w for w in state['windows']}
        request_id, canonical = _parse_allocation_request(request, windows_by_id)

        existing = state['requests'].get(request_id)
        if existing is not None:
            if existing['application'] != canonical:
                raise RequestMismatchError(
                    f'request id {request_id!r} was already used differently'
                )
            return copy.deepcopy(existing['receipt'])

        assignment = self._plan_assignment(state, canonical['jobs'])
        if assignment is None:
            # Intentionally retain neither request id nor partial occupancy.
            return {'status': 'no_capacity', 'request_id': request_id}

        if len(state['credentials']) + len(assignment) > MAX_ISSUED_JOBS:
            raise ArchiveCapacityError(
                f'an archive retains at most {MAX_ISSUED_JOBS} issued jobs'
            )

        receipt_items = []
        for job, wid, result in assignment:
            token = (
                f'cred_{state["next_credential"]:012d}_'
                f'{secrets.token_hex(16)}'
            )
            state['next_credential'] += 1
            jid = job['job_id']
            state['credentials'][token] = {
                'credential': token,
                'archive_id': state['archive_id'],
                'request_id': request_id,
                'job_id': jid,
                'window_id': wid,
                'status': 'active',
                'link': result,
            }
            state['occupancy'][wid] = token
            receipt_items.append({
                'job_id': jid,
                'window_id': wid,
                'credential': token,
                'link': copy.deepcopy(result),
            })

        receipt = {
            'status': 'allocated',
            'archive_id': state['archive_id'],
            'request_id': request_id,
            'job_count': len(receipt_items),
            'items': receipt_items,
            'credentials': {
                item['job_id']: item['credential'] for item in receipt_items
            },
            'windows': {
                item['job_id']: item['window_id'] for item in receipt_items
            },
        }
        state['requests'][request_id] = {
            'application': canonical,
            'receipt': receipt,
        }
        state['issued_job_count'] = len(state['credentials'])
        self._commit_state(state)
        return copy.deepcopy(receipt)

    # Descriptive aliases for callers preferring command-style naming.
    submit_allocation = allocate
    allocate_batch = allocate
    request_allocation = allocate

    def get_receipt(self, request_id):
        state = self._read_state()
        request_id = ident(request_id)
        record = state['requests'].get(request_id)
        if record is None:
            raise ArchiveError(f'unknown request id: {request_id}')
        return copy.deepcopy(record['receipt'])

    receipt = get_receipt
    get_request_receipt = get_receipt

    def consume(self, credential):
        """Return the bound link result only for a currently owned credential."""
        state = self._read_state()
        if not isinstance(credential, str):
            raise CredentialError('credential must be a string')
        record = state['credentials'].get(credential)
        if record is None:
            raise CredentialError('unknown credential')
        if (record.get('status') != 'active' or
                state['occupancy'].get(record['window_id']) != credential):
            raise CredentialError('credential is not currently effective')
        return copy.deepcopy(record['link'])

    use_credential = consume
    access = consume
    fetch = consume
    fetch_link = consume
    get_link_result = consume
    get_credential_result = consume

    def credential_info(self, credential):
        state = self._read_state()
        if not isinstance(credential, str):
            raise CredentialError('credential must be a string')
        record = state['credentials'].get(credential)
        if record is None:
            raise CredentialError('unknown credential')
        wid = record['window_id']
        current = state['occupancy'].get(wid)
        return {
            'credential': credential,
            'request_id': record['request_id'],
            'job_id': record['job_id'],
            'window_id': wid,
            'stored_status': record['status'],
            'effective': (
                record['status'] == 'active' and current == credential
            ),
            'current_holder': current,
        }

    def release(self, credential):
        """Idempotently release one exact credential/window occupancy."""
        state = self._read_state()
        if not isinstance(credential, str):
            raise CredentialError('credential must be a string')
        record = state['credentials'].get(credential)
        if record is None:
            raise CredentialError('unknown credential')

        result = {
            'status': 'released',
            'credential': credential,
            'request_id': record['request_id'],
            'job_id': record['job_id'],
            'window_id': record['window_id'],
        }

        if record['status'] == 'released':
            result['changed'] = False
            result['already_released'] = True
            return result

        wid = record['window_id']
        if state['occupancy'].get(wid) != credential:
            # Defensive boundary: never remove a newer holder's occupancy.
            raise CredentialError('credential does not currently own its window')

        del state['occupancy'][wid]
        record['status'] = 'released'
        state['issued_job_count'] = len(state['credentials'])
        self._commit_state(state)

        result['changed'] = True
        result['already_released'] = False
        return result

    release_credential = release
    release_window = release

    def window_usage(self):
        state = self._read_state()
        usage = []
        for window in state['windows']:
            wid = window['id']
            token = state['occupancy'].get(wid)
            holder = None
            if token is not None:
                record = state['credentials'][token]
                holder = {
                    'request_id': record['request_id'],
                    'job_id': record['job_id'],
                    'credential': token,
                }
            usage.append({
                'id': wid,
                'base': window['base'],
                'size': window['size'],
                'end': window['base'] + window['size'],
                'available': token is None,
                'holder': holder,
            })
        return usage

    windows = window_usage


def create_archive(directory, windows):
    return ImageArchive.create(directory, windows)


def create_or_open_archive(directory, windows):
    return ImageArchive.create_or_open(directory, windows)


def open_archive(directory, windows=None):
    return ImageArchive.open(directory, windows)


Archive = ImageArchive
LocalArchive = ImageArchive
WindowArchive = ImageArchive
AllocationArchive = ImageArchive
AddressArchive = ImageArchive
