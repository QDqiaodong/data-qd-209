"""目标内存差分发布包 API.

该模块在多个已链接 release 的最终绝对地址字节映射之间计算前向/回滚
写入单元，对相同 payload 做跨目标去重，并根据历史传输回执生成续传
批次。它仍是离线结构化数据 API：不连接设备、不实际写内存，也不解析
或执行 ELF/PE/机器码。

任何输入或 ``link(plan)`` 错误都按仓库既有约定转换为 ``ValueError``，
调用方不会收到只构造了一半的 bundle。
"""
from bisect import bisect_right
import hashlib
import json
import re

from .checks import array, fields, ident, integer
from .linker import link

_RELEASES_MAX = 32
_TARGETS_MAX = 64
_RECEIPTS_MAX = 10_000
_IMAGES_BYTES_MAX = 4_000_000
_ATOMIC_RANGES_MAX = 128
_ATOMIC_SIZE_MAX = 65_536
_MAX_BATCH_LIMIT = 1_048_576
_TIME_MAX = 1_000_000_000

# link 契约中 region base <= 1_000_000、size <= 100_000，因此绝对地址
# 半开区间的最大末端为 1_100_000。
_ADDRESS_LIMIT = 1_100_000
_CHUNK_ID_RE = re.compile(r'[0-9a-f]{64}\Z')


def _json_sha256(value, sort_keys):
    text = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=sort_keys,
        separators=(',', ':'),
    )
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def _chunk_id(payload):
    # payload 是 bytes 数组；数组没有需要排序的键，但保持与契约完全
    # 一致的紧凑、ASCII 转义序列化。
    return _json_sha256(list(payload), False)


def _link_or_value_error(plan):
    try:
        return link(plan)
    except ValueError:
        raise
    except Exception as exc:  # 防御性地把畸形嵌套输入统一到既有边界。
        raise ValueError('link(plan) failed') from exc


def _merge_spans(spans):
    """把地址相邻且都被 section 占用的区间合并为最大连续占用区间。"""
    merged = []
    for span in spans:
        if not merged or span['base'] > merged[-1]['end']:
            merged.append({'base': span['base'], 'end': span['end']})
        elif span['end'] > merged[-1]['end']:
            # link 已保证 section 不重叠；这里也容忍末端相接的相邻段。
            merged[-1]['end'] = span['end']

    for row in merged:
        row['size'] = row['end'] - row['base']
    return merged


def _range_covered(address_ranges, base, end):
    if base < 0 or end > _ADDRESS_LIMIT or end < base:
        return False
    starts = [row['base'] for row in address_ranges]
    index = bisect_right(starts, base) - 1
    return index >= 0 and end <= address_ranges[index]['end']


def _parse_releases(raw_releases):
    releases = {}
    total_image_bytes = 0

    for raw in array(raw_releases, 1, _RELEASES_MAX):
        fields(raw, ('id', 'plan', 'images'))
        rid = ident(raw['id'])
        if rid in releases:
            raise ValueError('duplicate release id')

        linked = _link_or_value_error(raw['plan'])
        section_rows = {
            (section['object'], section['name']): section
            for section in linked['sections']
        }
        byte_count = sum(section['size'] for section in linked['sections'])
        total_image_bytes += byte_count
        if total_image_bytes > _IMAGES_BYTES_MAX:
            raise ValueError('aggregate release image bytes exceeded')

        raw_images = array(raw['images'], len(section_rows), len(section_rows))
        buffers = {}
        seen_images = set()
        for image in raw_images:
            fields(image, ('object', 'section', 'bytes'))
            object_id = ident(image['object'])
            section_name = ident(image['section'])
            key = (object_id, section_name)

            if key not in section_rows:
                raise ValueError('image refers to unknown section')
            if key in seen_images:
                raise ValueError('duplicate image for section')
            seen_images.add(key)

            section = section_rows[key]
            payload = array(image['bytes'], section['size'], section['size'])
            for value in payload:
                integer(value, 0, 255)
            buffers[key] = list(payload)

        # array 长度等于 section 数，且所有 key 存在、不重复，因此这里
        # 不可能再缺少 section；该检查保留为契约的显式防线。
        if seen_images != set(section_rows):
            raise ValueError('images do not cover every section exactly once')

        # relocation bytes 是最终写入字节，必须覆盖到 section 原始 image
        # 的对应偏移上，而不能成为独立地址层。
        for relocation in linked['relocations']:
            key = (relocation['object'], relocation['section'])
            offset = relocation['offset']
            width = relocation['width']
            buffers[key][offset:offset + width] = list(relocation['bytes'])

        spans = []
        for key, section in section_rows.items():
            start = section['base']
            size = section['size']
            spans.append({
                'object': key[0],
                'section': key[1],
                'base': start,
                'end': start + size,
                'size': size,
                'bytes': buffers[key],
            })
        spans.sort(key=lambda row: (row['base'], row['object'], row['section']))
        address_ranges = _merge_spans(spans)

        releases[rid] = {
            'id': rid,
            'linked': linked,
            'summary': dict(linked['summary']),
            'spans': spans,
            'address_ranges': address_ranges,
            'byte_count': byte_count,
            'canonical_release': {
                'id': rid,
                'summary': dict(linked['summary']),
                'address_ranges': [dict(row) for row in address_ranges],
                'byte_count': byte_count,
            },
        }

    return releases


def _parse_targets(raw_targets, releases):
    targets = {}

    for raw in array(raw_targets, 1, _TARGETS_MAX):
        fields(raw, (
            'id', 'current', 'candidate', 'erase_byte',
            'atomic_ranges', 'max_batch_bytes',
        ))
        tid = ident(raw['id'])
        if tid in targets:
            raise ValueError('duplicate target id')

        current_id = ident(raw['current'])
        candidate_id = ident(raw['candidate'])
        if current_id not in releases:
            raise ValueError('target refers to unknown current release')
        if candidate_id not in releases:
            raise ValueError('target refers to unknown candidate release')

        erase_byte = integer(raw['erase_byte'], 0, 255)
        max_batch_bytes = integer(
            raw['max_batch_bytes'], 1, _MAX_BATCH_LIMIT)

        atomic_ranges = {}
        for raw_range in array(raw['atomic_ranges'], 0, _ATOMIC_RANGES_MAX):
            fields(raw_range, ('id', 'base', 'size'))
            ar_id = ident(raw_range['id'])
            if ar_id in atomic_ranges:
                raise ValueError('duplicate atomic range id')
            base = integer(raw_range['base'], 0, _ADDRESS_LIMIT)
            size = integer(raw_range['size'], 1, _ATOMIC_SIZE_MAX)
            end = base + size
            if end > _ADDRESS_LIMIT:
                raise ValueError('atomic range outside absolute address space')
            atomic_ranges[ar_id] = {
                'id': ar_id,
                'base': base,
                'size': size,
                'end': end,
            }

        ordered_ranges = sorted(
            atomic_ranges.values(), key=lambda row: (row['base'], row['id']))
        for left, right in zip(ordered_ranges, ordered_ranges[1:]):
            if left['end'] > right['base']:
                raise ValueError('overlapping atomic ranges')

        # atomic range 中每个地址都必须在两侧最终 section 映射内。
        for ar_range in ordered_ranges:
            for release_id in (current_id, candidate_id):
                release = releases[release_id]
                if not _range_covered(
                        release['address_ranges'],
                        ar_range['base'], ar_range['end']):
                    raise ValueError(
                        'atomic range must be covered by both releases')

        targets[tid] = {
            'id': tid,
            'current': current_id,
            'candidate': candidate_id,
            'erase_byte': erase_byte,
            'max_batch_bytes': max_batch_bytes,
            'atomic_ranges': ordered_ranges,
            'canonical_atomic_ranges': [
                {'id': row['id'], 'base': row['base'], 'size': row['size']}
                for row in ordered_ranges
            ],
        }

    return targets


def _parse_receipts(raw_receipts, targets):
    receipts = []
    receipt_ids = set()
    occurrences = set()

    for raw in array(raw_receipts, 0, _RECEIPTS_MAX):
        fields(raw, (
            'id', 'target', 'bundle_id', 'observed_at', 'acked_chunks'))

        rid = ident(raw['id'])
        if rid in receipt_ids:
            raise ValueError('duplicate receipt id')
        receipt_ids.add(rid)

        target_id = ident(raw['target'])
        if target_id not in targets:
            raise ValueError('receipt refers to unknown target')

        # bundle_id 可能是当前 SHA-256，也可能是历史 bundle 的标识；历史
        # 输入只要求它是合法标识符，不能因为旧 id 形式而拒绝整份输入。
        bundle_id = ident(raw['bundle_id'])
        observed_at = integer(raw['observed_at'], 0, _TIME_MAX)

        occurrence = (target_id, bundle_id, observed_at)
        if occurrence in occurrences:
            raise ValueError('duplicate receipt observation')
        occurrences.add(occurrence)

        acked_chunks = array(raw['acked_chunks'], 0, _RECEIPTS_MAX)
        acked = []
        acked_set = set()
        for chunk_id in acked_chunks:
            if not isinstance(chunk_id, str) or _CHUNK_ID_RE.fullmatch(
                    chunk_id) is None:
                raise ValueError('invalid acked chunk id')
            if chunk_id in acked_set:
                raise ValueError('duplicate acked chunk id')
            acked_set.add(chunk_id)
            acked.append(chunk_id)

        receipts.append({
            'id': rid,
            'target': target_id,
            'bundle_id': bundle_id,
            'observed_at': observed_at,
            'acked_chunks': acked,
            'acked_set': acked_set,
        })

    return receipts


def _target_address_maps(target, releases):
    erase = target['erase_byte']
    before = bytearray([erase]) * _ADDRESS_LIMIT
    after = bytearray([erase]) * _ADDRESS_LIMIT

    for release_id, memory in (
            (target['current'], before),
            (target['candidate'], after)):
        for span in releases[release_id]['spans']:
            memory[span['base']:span['end']] = bytes(span['bytes'])

    return before, after


def _build_target_manifest(target, releases, chunk_registry, payload_ids):
    before, after = _target_address_maps(target, releases)
    max_batch_bytes = target['max_batch_bytes']
    forward = []
    rollback = []

    def add_unit(base, forward_bytes, rollback_bytes, atomic_range):
        if (len(forward_bytes) > max_batch_bytes
                or len(rollback_bytes) > max_batch_bytes):
            raise ValueError(
                'unsplittable chunk exceeds target max_batch_bytes')

        forward_key = bytes(forward_bytes)
        rollback_key = bytes(rollback_bytes)
        forward_id = payload_ids.get(forward_key)
        if forward_id is None:
            forward_id = _chunk_id(forward_bytes)
            payload_ids[forward_key] = forward_id
            chunk_registry.setdefault(forward_id, list(forward_bytes))

        rollback_id = payload_ids.get(rollback_key)
        if rollback_id is None:
            rollback_id = _chunk_id(rollback_bytes)
            payload_ids[rollback_key] = rollback_id
            chunk_registry.setdefault(rollback_id, list(rollback_bytes))

        size = len(forward_bytes)
        forward.append({
            'base': base,
            'size': size,
            'atomic_range': atomic_range,
            'chunk_id': forward_id,
        })
        rollback.append({
            'base': base,
            'size': len(rollback_bytes),
            'atomic_range': atomic_range,
            'chunk_id': rollback_id,
        })

    # 只要 atomic range 中有一个字节变化，整个范围都成为不可拆分单元。
    for ar_range in target['atomic_ranges']:
        base = ar_range['base']
        end = ar_range['end']
        forward_bytes = list(after[base:end])
        rollback_bytes = list(before[base:end])
        if forward_bytes != rollback_bytes:
            add_unit(base, forward_bytes, rollback_bytes, ar_range['id'])

    # atomic range 中的所有地址都不参与普通连续区间；即使该 range 没有
    # 变化而未生成单元，也在此处显式跳过其整个地址范围。
    segments = []
    cursor = 0
    for ar_range in target['atomic_ranges']:
        segments.append((cursor, ar_range['base']))
        cursor = ar_range['end']
    segments.append((cursor, _ADDRESS_LIMIT))

    for low, high in segments:
        index = low
        while index < high:
            # 相同大块直接交给 bytearray 的 C 级比较；只有包含差异的块
            # 才进入逐字节游程构造，避免在大型未变化映射上做 Python 循环。
            block_end = min(high, index + 4096)
            if before[index:block_end] == after[index:block_end]:
                index = block_end
                continue

            while index < block_end and before[index] == after[index]:
                index += 1
            if index >= block_end:
                continue

            base = index
            forward_bytes = []
            rollback_bytes = []
            while index < high:
                old_byte = before[index]
                new_byte = after[index]
                if old_byte == new_byte:
                    break
                forward_bytes.append(new_byte)
                rollback_bytes.append(old_byte)
                index += 1

            add_unit(base, forward_bytes, rollback_bytes, None)

    forward.sort(key=lambda unit: unit['base'])
    rollback.sort(key=lambda unit: unit['base'])

    # 同方向单元不得重叠；构造算法已保证，保留显式完整性检查。
    for manifest in (forward, rollback):
        for left, right in zip(manifest, manifest[1:]):
            if left['base'] + left['size'] > right['base']:
                raise ValueError('overlapping manifest units')
        if manifest:
            first = manifest[0]
            if first['base'] < 0 or first['base'] + first['size'] > _ADDRESS_LIMIT:
                raise ValueError('manifest unit outside address space')

    referenced = {unit['chunk_id'] for unit in forward}
    referenced.update(unit['chunk_id'] for unit in rollback)
    return forward, rollback, referenced


def _make_batches(pending_chunk_ids, chunk_registry, max_batch_bytes):
    batches = []
    current_ids = []
    current_bytes = 0

    for chunk_id in pending_chunk_ids:
        size = len(chunk_registry[chunk_id])
        if current_ids and current_bytes + size > max_batch_bytes:
            batches.append({
                'id': len(batches),
                'index': len(batches),
                'number': len(batches) + 1,
                'batch_index': len(batches),
                'batch_id': len(batches),
                'chunk_ids': current_ids,
                'bytes': current_bytes,
                'total_bytes': current_bytes,
            })
            current_ids = []
            current_bytes = 0

        current_ids.append(chunk_id)
        current_bytes += size

    if current_ids:
        index = len(batches)
        batches.append({
            'id': index,
            'index': index,
            'number': index + 1,
            'batch_index': index,
            'batch_id': index,
            'chunk_ids': current_ids,
            'bytes': current_bytes,
            'total_bytes': current_bytes,
        })

    return batches


def build_release_bundle(data):
    """编译确定性的差分发布 bundle，并生成断点续传批次视图。"""
    fields(data, ('releases', 'targets', 'receipts'))

    releases = _parse_releases(data['releases'])
    targets = _parse_targets(data['targets'], releases)
    receipts = _parse_receipts(data['receipts'], targets)

    chunk_registry = {}
    payload_ids = {}
    manifest_cache = {}
    built_targets = {}
    canonical_targets = []

    for tid in sorted(targets):
        target = targets[tid]
        cache_key = (
            target['current'],
            target['candidate'],
            target['erase_byte'],
            tuple(
                (row['id'], row['base'], row['size'])
                for row in target['atomic_ranges']
            ),
        )
        cached = manifest_cache.get(cache_key)
        if cached is None:
            forward, rollback, referenced = _build_target_manifest(
                target, releases, chunk_registry, payload_ids)
            manifest_cache[cache_key] = (
                forward, rollback, set(referenced))
        else:
            cached_forward, cached_rollback, cached_referenced = cached
            # 单元值都是原始标量；复制 dict 即可让各 target 输出互不别名。
            forward = [dict(unit) for unit in cached_forward]
            rollback = [dict(unit) for unit in cached_rollback]
            referenced = set(cached_referenced)
            for chunk_id in referenced:
                if len(chunk_registry[chunk_id]) > target['max_batch_bytes']:
                    raise ValueError(
                        'unsplittable chunk exceeds target max_batch_bytes')

        built_targets[tid] = {
            **target,
            'forward': forward,
            'rollback': rollback,
            'referenced': referenced,
        }
        canonical_targets.append({
            'id': tid,
            'current': target['current'],
            'candidate': target['candidate'],
            'erase_byte': target['erase_byte'],
            'atomic_ranges': target['canonical_atomic_ranges'],
            'forward': forward,
            'rollback': rollback,
        })

    chunk_rows = [
        {
            'chunk_id': chunk_id,
            'bytes': chunk_registry[chunk_id],
            'size': len(chunk_registry[chunk_id]),
        }
        for chunk_id in sorted(chunk_registry)
    ]

    canonical_body = {
        'releases': [
            releases[rid]['canonical_release']
            for rid in sorted(releases)
        ],
        'chunks': chunk_rows,
        'targets': canonical_targets,
    }
    bundle_id = _json_sha256(canonical_body, sort_keys=True)

    receipts_by_target = {}
    for receipt in receipts:
        receipts_by_target.setdefault(receipt['target'], []).append(receipt)

    target_rows = []
    pending_targets = 0
    up_to_date_targets = 0
    forward_units = 0
    rollback_units = 0

    for tid in sorted(built_targets):
        target = built_targets[tid]
        matching = [
            receipt for receipt in receipts_by_target.get(tid, [])
            if receipt['bundle_id'] == bundle_id
        ]
        selected = (
            max(matching, key=lambda receipt: receipt['observed_at'])
            if matching else None
        )

        # 与当前 bundle_id 匹配的所有历史回执都属于同一 manifest；其中
        # 出现非本目标引用的 chunk 是非法引用。只有 observed_at 最新的
        # 一份用于抵扣待传内容。其他 bundle_id 的回执在解析/选择时完全
        # 不做当前 chunk 引用检查。
        for receipt in matching:
            unknown_acked = receipt['acked_set'] - target['referenced']
            if unknown_acked:
                raise ValueError(
                    'receipt acknowledges chunk outside target manifest')

        if selected is not None:
            acknowledged = sorted(selected['acked_set'])
        else:
            acknowledged = []

        pending = sorted(target['referenced'] - set(acknowledged))
        batches = _make_batches(
            pending, chunk_registry, target['max_batch_bytes'])

        if not target['forward']:
            status = 'up_to_date'
            up_to_date_targets += 1
        elif not pending:
            status = 'ready'
        else:
            status = 'transfer_pending'
            pending_targets += 1

        forward_units += len(target['forward'])
        rollback_units += len(target['rollback'])

        row = {
            'id': tid,
            'current': target['current'],
            'candidate': target['candidate'],
            'erase_byte': target['erase_byte'],
            'max_batch_bytes': target['max_batch_bytes'],
            'atomic_ranges': target['canonical_atomic_ranges'],
            'forward': target['forward'],
            'rollback': target['rollback'],
            # 显式别名：调用方也可按完整 manifest 名称访问。
            'forward_manifest': target['forward'],
            'rollback_manifest': target['rollback'],
            'receipt_id': selected['id'] if selected else None,
            'selected_receipt': selected['id'] if selected else None,
            'selected_receipt_id': selected['id'] if selected else None,
            'receipt': selected['id'] if selected else None,
            'acknowledged_chunks': acknowledged,
            'pending_chunks': pending,
            'pending_batches': batches,
            'status': status,
        }
        target_rows.append(row)

    release_rows = []
    for rid in sorted(releases):
        release = releases[rid]
        envelope = None
        if release['address_ranges']:
            first = release['address_ranges'][0]
            last = release['address_ranges'][-1]
            envelope = {
                'base': first['base'],
                'end': last['end'],
                'size': last['end'] - first['base'],
            }
        row = dict(release['canonical_release'])
        row['link_summary'] = release['summary']
        row['occupied_ranges'] = row['address_ranges']
        row['ranges'] = row['address_ranges']
        row['address_range'] = envelope
        row['final_address_range'] = envelope
        row['final_address_ranges'] = row['address_ranges']
        row['occupied_address_ranges'] = row['address_ranges']
        row['byte_count_final'] = release['byte_count']
        row['final_byte_count'] = release['byte_count']
        row['bytes_total'] = release['byte_count']
        row['total_bytes'] = release['byte_count']
        release_rows.append(row)

    return {
        'bundle_id': bundle_id,
        'releases': release_rows,
        'chunks': chunk_rows,
        'targets': target_rows,
        'summary': {
            'releases': len(releases),
            'targets': len(targets),
            'chunks': len(chunk_rows),
            'forward_units': forward_units,
            'rollback_units': rollback_units,
            'payload_bytes': sum(chunk['size'] for chunk in chunk_rows),
            'pending_targets': pending_targets,
            'up_to_date_targets': up_to_date_targets,
        },
    }
