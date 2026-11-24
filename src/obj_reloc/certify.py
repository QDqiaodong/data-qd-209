"""部署重定位读回认证 API.

链接结果交给下游写入目标内存后，发布控制器收到多个采集方在不同时刻
取得的地址区间读回；本模块判断每次发布请求是否已有足够独立、仍受
信任且彼此不冲突的证据，确认所有计划重定位字节确实落在目标地址。

与 process/link 同为离线结构化数据 API：不连接设备、不解析或执行
ELF/PE/机器码。任何输入错误都以 ValueError 拒绝整份输入，不返回
部分 request 或 certificate。
"""
import hashlib
import json
from bisect import bisect_right

from .checks import fields, array, integer, ident
from .linker import link

_TIME_MAX = 1_000_000_000
_ADDRESS_MAX = 1_100_000  # region base <= 1_000_000 且 size <= 100_000
_CAPTURE_BYTES_MAX = 4_000_000
_SEVERITY = {'insufficient': 1, 'mismatch': 2, 'conflict': 3}
_STATUSES = ('certified', 'no_relocations', 'insufficient', 'mismatch', 'conflict')


def _parse_collectors(raw):
    collectors = {}
    for c in array(raw, 1, 64):
        fields(c, ('id', 'group', 'valid_from', 'valid_to'))
        cid = ident(c['id'])
        if cid in collectors:
            raise ValueError('duplicate collector id')
        group = ident(c['group'])
        valid_from = integer(c['valid_from'], 0, _TIME_MAX)
        valid_to = integer(c['valid_to'], 0, _TIME_MAX)
        if valid_from >= valid_to:
            raise ValueError('collector validity interval must be non-empty')
        collectors[cid] = {'id': cid, 'group': group,
                           'valid_from': valid_from, 'valid_to': valid_to}
    return collectors


def _parse_targets(raw):
    targets = set()
    for t in array(raw, 1, 32):
        fields(t, ('id',))
        tid = ident(t['id'])
        if tid in targets:
            raise ValueError('duplicate target id')
        targets.add(tid)
    return targets


def _parse_captures(raw, collectors, targets, regions):
    captures = []
    capture_ids = set()
    occurrences = set()
    total_bytes = 0
    for cap in array(raw, 0, 20000):
        fields(cap, ('id', 'target', 'collector', 'observed_at', 'ranges'))
        cap_id = ident(cap['id'])
        if cap_id in capture_ids:
            raise ValueError('duplicate capture id')
        capture_ids.add(cap_id)
        target = ident(cap['target'])
        if target not in targets:
            raise ValueError('capture refers to unknown target')
        collector = ident(cap['collector'])
        if collector not in collectors:
            raise ValueError('capture refers to unknown collector')
        observed_at = integer(cap['observed_at'], 0, _TIME_MAX)
        col = collectors[collector]
        if not col['valid_from'] <= observed_at < col['valid_to']:
            raise ValueError('capture observed outside collector validity')
        occurrence = (target, collector, observed_at)
        if occurrence in occurrences:
            raise ValueError('duplicate capture occurrence')
        occurrences.add(occurrence)
        ranges = []
        spans = []
        for r in array(cap['ranges'], 0, 128):
            fields(r, ('base', 'bytes'))
            base = integer(r['base'], 0, _ADDRESS_MAX)
            payload = array(r['bytes'], 1, 4096)
            for b in payload:
                integer(b, 0, 255)
            end = base + len(payload)
            if not any(lo <= base and end <= hi for lo, hi in regions):
                raise ValueError('capture range outside plan regions')
            spans.append((base, end))
            ranges.append((base, list(payload)))
            total_bytes += len(payload)
            if total_bytes > _CAPTURE_BYTES_MAX:
                raise ValueError('aggregate capture bytes exceeded')
        spans.sort()
        for left, right in zip(spans, spans[1:]):
            if left[1] > right[0]:
                raise ValueError('overlapping capture ranges')
        captures.append({'id': cap_id, 'target': target, 'collector': collector,
                         'observed_at': observed_at, 'ranges': ranges})
    return captures


def _parse_requests(raw, targets):
    requests = {}
    for q in array(raw, 1, 2000):
        fields(q, ('id', 'target', 'as_of', 'min_collectors', 'min_groups'))
        qid = ident(q['id'])
        if qid in requests:
            raise ValueError('duplicate request id')
        target = ident(q['target'])
        if target not in targets:
            raise ValueError('request refers to unknown target')
        as_of = integer(q['as_of'], 0, _TIME_MAX)
        min_collectors = integer(q['min_collectors'], 1, 64)
        min_groups = integer(q['min_groups'], 1, 64)
        if min_groups > min_collectors:
            raise ValueError('min_groups must not exceed min_collectors')
        requests[qid] = {'id': qid, 'target': target, 'as_of': as_of,
                         'min_collectors': min_collectors,
                         'min_groups': min_groups}
    return requests


def _index_captures(captures):
    # target -> collector -> (observed_at 升序列表, 同序 capture 列表)
    grouped = {}
    for cap in captures:
        grouped.setdefault(cap['target'], {}).setdefault(
            cap['collector'], []).append(cap)
    indexed = {}
    for target, per_collector in grouped.items():
        indexed[target] = {}
        for cid, lst in per_collector.items():
            lst.sort(key=lambda c: c['observed_at'])
            indexed[target][cid] = ([c['observed_at'] for c in lst], lst)
    return indexed


def _latest_captures(indexed, target, collectors, as_of):
    # 仅使用 as_of 时仍有效的 collector；每个 collector 取 observed_at<=as_of 的最新 capture
    latest = {}
    for cid, (times, lst) in indexed.get(target, {}).items():
        col = collectors[cid]
        if not col['valid_from'] <= as_of < col['valid_to']:
            continue
        i = bisect_right(times, as_of) - 1
        if i >= 0:
            latest[cid] = lst[i]
    return latest


def _classify(capture, address, expected):
    # 仅用该 capture 自身 ranges 拼读回；不与其他 capture/collector/target 混拼
    width = len(expected)
    observed = [None] * width
    covered = 0
    for base, payload in capture['ranges']:
        lo = max(base, address)
        hi = min(base + len(payload), address + width)
        for p in range(lo, hi):
            observed[p - address] = payload[p - base]
            covered += 1
    for got, want in zip(observed, expected):
        if got is not None and got != want:
            return 'mismatch', observed
    if covered == width:
        return 'match', observed
    return 'incomplete', observed


def _evaluate_relocation(latest, collectors, address, expected,
                         min_collectors, min_groups):
    buckets = {'match': [], 'incomplete': [], 'mismatch': []}
    for cid in sorted(latest, key=lambda c: (collectors[c]['group'], c)):
        cap = latest[cid]
        verdict, observed = _classify(cap, address, expected)
        buckets[verdict].append({
            'collector': cid, 'group': collectors[cid]['group'],
            'capture': cap['id'], 'observed_at': cap['observed_at'],
            'observed': observed,
        })
    match_groups = len({e['group'] for e in buckets['match']})
    met = (len(buckets['match']) >= min_collectors
           and match_groups >= min_groups)
    if buckets['mismatch']:
        status = 'conflict' if buckets['match'] else 'mismatch'
    elif met:
        status = 'certified'
    else:
        status = 'insufficient'
    threshold = {'min_collectors': min_collectors, 'min_groups': min_groups,
                 'match_collectors': len(buckets['match']),
                 'match_groups': match_groups, 'met': met}
    return status, buckets, threshold


def _witnesses(match_entries, min_collectors, min_groups):
    # 先按 (group, collector) 排序取到 min_groups 个不同 group，再按同一顺序补足 min_collectors
    ordered = sorted(match_entries, key=lambda e: (e['group'], e['collector']))
    picked = []
    seen_groups = set()
    for e in ordered:
        if e['group'] in seen_groups:
            continue
        picked.append(e)
        seen_groups.add(e['group'])
        if len(seen_groups) == min_groups:
            break
    chosen = {e['collector'] for e in picked}
    for e in ordered:
        if len(picked) >= min_collectors:
            break
        if e['collector'] not in chosen:
            picked.append(e)
            chosen.add(e['collector'])
    picked.sort(key=lambda e: (e['group'], e['collector']))
    return [{'collector': e['collector'], 'group': e['group'],
             'capture': e['capture']} for e in picked]


def _certificate(request, plan_relocations, witness_rows):
    body = {
        'request': request['id'],
        'target': request['target'],
        'as_of': request['as_of'],
        'min_collectors': request['min_collectors'],
        'min_groups': request['min_groups'],
        'relocations': [dict(rel, witnesses=w)
                        for rel, w in zip(plan_relocations, witness_rows)],
    }
    canonical = json.dumps(body, ensure_ascii=True, sort_keys=True,
                           separators=(',', ':'))
    body['certificate_id'] = hashlib.sha256(
        canonical.encode('utf-8')).hexdigest()
    return body


def certify(data):
    fields(data, ('plan', 'collectors', 'targets', 'captures', 'requests'))
    linked = link(data['plan'])
    bases = {(s['object'], s['name']): s['base'] for s in linked['sections']}
    plan_relocations = [
        {'object': r['object'], 'id': r['id'], 'section': r['section'],
         'offset': r['offset'], 'width': r['width'],
         'address': bases[(r['object'], r['section'])] + r['offset'],
         'bytes': list(r['bytes'])}
        for r in linked['relocations']
    ]
    regions = [(r['base'], r['base'] + r['size'])
               for r in data['plan']['regions']]
    collectors = _parse_collectors(data['collectors'])
    targets = _parse_targets(data['targets'])
    captures = _parse_captures(data['captures'], collectors, targets, regions)
    requests = _parse_requests(data['requests'], targets)
    indexed = _index_captures(captures)

    request_rows = []
    status_counts = {s: 0 for s in _STATUSES}
    for qid in sorted(requests):
        req = requests[qid]
        row = {'id': qid, 'target': req['target'], 'as_of': req['as_of'],
               'min_collectors': req['min_collectors'],
               'min_groups': req['min_groups']}
        if not plan_relocations:
            row['status'] = 'no_relocations'
            row['relocations'] = []
            status_counts[row['status']] += 1
            request_rows.append(row)
            continue
        latest = _latest_captures(indexed, req['target'], collectors,
                                  req['as_of'])
        reloc_rows = []
        witness_rows = []
        worst = None
        for rel in plan_relocations:
            status, buckets, threshold = _evaluate_relocation(
                latest, collectors, rel['address'], rel['bytes'],
                req['min_collectors'], req['min_groups'])
            reloc_rows.append({
                'object': rel['object'], 'id': rel['id'],
                'address': rel['address'], 'expected': rel['bytes'],
                'status': status,
                'match': buckets['match'],
                'incomplete': buckets['incomplete'],
                'mismatch': buckets['mismatch'],
                'threshold': threshold,
            })
            if status == 'certified':
                witness_rows.append(_witnesses(
                    buckets['match'], req['min_collectors'],
                    req['min_groups']))
            elif worst is None or _SEVERITY[status] > _SEVERITY[worst]:
                worst = status
        if worst is None:
            row['status'] = 'certified'
            row['certificate'] = _certificate(req, plan_relocations,
                                              witness_rows)
        else:
            row['status'] = worst
        status_counts[row['status']] += 1
        row['relocations'] = reloc_rows
        request_rows.append(row)

    return {
        'plan': {'summary': linked['summary'],
                 'relocations': plan_relocations},
        'requests': request_rows,
        'summary': {'requests': status_counts,
                    'certified': status_counts['certified'],
                    'total': len(request_rows)},
    }
