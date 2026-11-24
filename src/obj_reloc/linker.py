"""多对象离线链接数据 API.

调用方提供 regions/objects 结构化记录，本模块完成确定性内存布局、
跨对象符号解析与固定宽度小端重定位编码。不解析或执行 ELF/PE/机器码，
所有错误均以 ValueError 拒绝整份输入，不返回部分结果。
"""
from .checks import fields, array, integer, ident

_BINDINGS = frozenset(('local', 'weak', 'strong'))
_SCOPES = frozenset(('local', 'global'))


def _enum(value, allowed, label):
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f'{label} must be one of {sorted(allowed)}')
    return value


def _parse_regions(raw):
    regions = {}
    for r in raw:
        fields(r, ('name', 'base', 'size'))
        name = ident(r['name'])
        if name in regions:
            raise ValueError('duplicate region')
        base = integer(r['base'], 0, 1_000_000)
        size = integer(r['size'], 1, 100_000)
        regions[name] = {'name': name, 'base': base, 'size': size, 'end': base + size}
    ordered = sorted(regions.values(), key=lambda r: r['base'])
    for left, right in zip(ordered, ordered[1:]):
        if left['end'] > right['base']:
            raise ValueError('overlapping regions')
    return regions


def _parse_sections(raw, regions):
    sections = {}
    for s in raw:
        fields(s, ('name', 'region', 'size', 'alignment'))
        name = ident(s['name'])
        if name in sections:
            raise ValueError('duplicate section')
        region = ident(s['region'])
        if region not in regions:
            raise ValueError('unknown region')
        size = integer(s['size'], 1, 100_000)
        alignment = integer(s['alignment'], 1, 4096)
        if alignment & (alignment - 1):
            raise ValueError('alignment must be a power of two')
        sections[name] = {'name': name, 'region': region, 'size': size, 'alignment': alignment}
    return sections


def _parse_symbols(raw, sections):
    symbols = {}
    for s in raw:
        fields(s, ('name', 'section', 'offset', 'binding'))
        name = ident(s['name'])
        if name in symbols:
            raise ValueError('duplicate symbol')
        section = ident(s['section'])
        if section not in sections:
            raise ValueError('symbol refers to unknown section')
        offset = integer(s['offset'], 0, 100_000)
        if offset >= sections[section]['size']:
            raise ValueError('symbol offset outside section')
        binding = _enum(s['binding'], _BINDINGS, 'binding')
        symbols[name] = {'name': name, 'section': section, 'offset': offset, 'binding': binding}
    return symbols


def _parse_relocations(raw, sections):
    relocations = {}
    writes = []
    for r in raw:
        fields(r, ('id', 'section', 'offset', 'symbol', 'addend', 'width'))
        rid = ident(r['id'])
        if rid in relocations:
            raise ValueError('duplicate relocation id')
        section = ident(r['section'])
        if section not in sections:
            raise ValueError('relocation refers to unknown section')
        offset = integer(r['offset'], 0, 100_000)
        width = integer(r['width'], 1, 8)
        if offset + width > sections[section]['size']:
            raise ValueError('relocation write outside section')
        ref = r['symbol']
        fields(ref, ('scope', 'name'))
        scope = _enum(ref['scope'], _SCOPES, 'symbol scope')
        ref_name = ident(ref['name'])
        addend = integer(r['addend'], -1_000_000, 1_000_000)
        for other_section, other_start, other_end in writes:
            if other_section == section and offset < other_end and other_start < offset + width:
                raise ValueError('overlapping relocation writes')
        writes.append((section, offset, offset + width))
        relocations[rid] = {'id': rid, 'section': section, 'offset': offset, 'width': width,
                            'scope': scope, 'name': ref_name, 'addend': addend}
    return list(relocations.values())


def _layout(objects, regions):
    bases = {}
    rows = []
    for region in sorted(regions.values(), key=lambda r: r['name']):
        cursor = region['base']
        limit = region['base'] + region['size']
        placed = []
        for obj in objects:
            for sec in obj['sections'].values():
                if sec['region'] == region['name']:
                    placed.append((obj['id'], sec['name'], sec))
        placed.sort(key=lambda item: (item[0], item[1]))
        for oid, sec_name, sec in placed:
            alignment = sec['alignment']
            base = ((cursor + alignment - 1) // alignment) * alignment
            end = base + sec['size']
            if end > limit:
                raise ValueError('section exceeds region capacity')
            bases[(oid, sec_name)] = base
            cursor = end
            rows.append({'object': oid, 'name': sec_name, 'region': region['name'],
                         'base': base, 'size': sec['size'], 'alignment': alignment})
    rows.sort(key=lambda row: (row['region'], row['object'], row['name']))
    return bases, rows


def _symbol_addresses(objects, bases):
    addresses = {}
    for obj in objects:
        oid = obj['id']
        for name, sym in obj['symbols'].items():
            addresses[(oid, name)] = bases[(oid, sym['section'])] + sym['offset']
    return addresses


def _definition_rows(objects, addresses):
    rows = []
    for obj in objects:
        oid = obj['id']
        for name in sorted(obj['symbols']):
            sym = obj['symbols'][name]
            rows.append({'object': oid, 'name': name,
                         'address': addresses[(oid, name)], 'binding': sym['binding']})
    rows.sort(key=lambda row: (row['object'], row['name']))
    return rows


def _resolve_globals(objects, addresses):
    candidates = {}
    for obj in objects:
        oid = obj['id']
        for name, sym in obj['symbols'].items():
            if sym['binding'] == 'local':
                continue
            candidates.setdefault(name, []).append(
                (oid, sym['binding'], addresses[(oid, name)]))
    winners = {}
    globals_out = []
    for name in sorted(candidates):
        defs = candidates[name]
        strong = sorted((d for d in defs if d[1] == 'strong'), key=lambda d: d[0])
        if len(strong) > 1:
            raise ValueError('multiple strong definitions')
        if strong:
            winner = strong[0]
            shadowed = sorted((d for d in defs if d[1] == 'weak'), key=lambda d: d[0])
        else:
            weak_all = sorted(defs, key=lambda d: d[0])
            winner = weak_all[0]
            shadowed = weak_all[1:]
        winners[name] = winner
        globals_out.append({
            'name': name,
            'winner': {'object': winner[0], 'name': name, 'address': winner[2]},
            'shadowed': [{'object': oid, 'name': name, 'address': address}
                         for oid, _binding, address in shadowed],
        })
    return winners, globals_out


def link(data):
    fields(data, ('regions', 'objects'))
    regions = _parse_regions(array(data['regions'], 1, 16))

    objects = []
    object_ids = set()
    totals = [0, 0, 0]
    for obj in array(data['objects'], 1, 32):
        fields(obj, ('id', 'sections', 'symbols', 'relocations'))
        oid = ident(obj['id'])
        if oid in object_ids:
            raise ValueError('duplicate object id')
        object_ids.add(oid)
        sections = _parse_sections(array(obj['sections'], 0, 100), regions)
        symbols = _parse_symbols(array(obj['symbols'], 0, 1000), sections)
        relocations = _parse_relocations(array(obj['relocations'], 0, 2000), sections)
        totals[0] += len(sections)
        totals[1] += len(symbols)
        totals[2] += len(relocations)
        if totals[0] > 100 or totals[1] > 1000 or totals[2] > 2000:
            raise ValueError('aggregate object table capacity exceeded')
        objects.append({'id': oid, 'sections': sections,
                        'symbols': symbols, 'relocations': relocations})

    bases, section_rows = _layout(objects, regions)
    addresses = _symbol_addresses(objects, bases)
    definition_rows = _definition_rows(objects, addresses)
    winners, globals_out = _resolve_globals(objects, addresses)

    relocation_rows = []
    for obj in objects:
        oid = obj['id']
        for r in obj['relocations']:
            if r['scope'] == 'local':
                if r['name'] not in obj['symbols']:
                    raise ValueError('undefined local reference')
                target_oid = oid
            else:
                if r['name'] not in winners:
                    raise ValueError('undefined global reference')
                target_oid = winners[r['name']][0]
            target_name = r['name']
            target_address = addresses[(target_oid, target_name)]
            width = r['width']
            value = target_address + r['addend']
            if not 0 <= value < 1 << (8 * width):
                raise ValueError('relocation overflow')
            relocation_rows.append({
                'object': oid, 'id': r['id'], 'section': r['section'],
                'offset': r['offset'], 'width': width,
                'target': {'object': target_oid, 'name': target_name},
                'address': target_address, 'value': value,
                'bytes': [(value >> (8 * i)) & 255 for i in range(width)],
            })
    relocation_rows.sort(key=lambda row: (row['object'], row['id']))

    return {
        'sections': section_rows,
        'symbols': {'definitions': definition_rows, 'globals': globals_out},
        'relocations': relocation_rows,
        'summary': {
            'regions': len(regions),
            'objects': len(objects),
            'sections': totals[0],
            'symbols': totals[1],
            'relocations': totals[2],
        },
    }
