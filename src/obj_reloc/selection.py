"""目标链接段保留计划 API.

离线构建系统给定一份现有 ``link`` 可接受的完整多对象计划与一组显式
入口 section，本模块只依据结构化 relocation 记录计算必须进入目标
产物的 section 可达闭包，并明确哪些 section 可安全排除。section 是
最小保留单位：一个 section 被选中后，其中全部符号定义及 relocation
都随之保留。

本模块不解析或执行 ELF/PE/机器码，不推断未记录在 relocation 中的
隐式引用（运行时反射、手写地址等不在保留承诺范围内），不实际写出
二进制文件，也不提供 CLI。

任何输入错误、完整 plan 的链接错误，或过滤后 pruned plan 不再合法的
情况，都以 ValueError 拒绝整次调用，不返回部分保留结果。
"""
import heapq

from .checks import fields, array, ident
from .linker import link

# link 契约下全部对象合计至多 100 个 section，入口数量以此为上界。
_ROOTS_MAX = 100

# 保留范围声明：结果只对显式入口及记录在 relocation 中的引用负责。
_SCOPE_NOTE = (
    'retention is computed only from the explicit roots and the references '
    'recorded in relocations; unmodeled runtime reflection, hand-written '
    'addresses, or other implicit references are not covered'
)


def _parse_roots(raw):
    roots = []
    seen = set()
    for item in array(raw, 1, _ROOTS_MAX):
        fields(item, ('object', 'section'))
        key = (ident(item['object']), ident(item['section']))
        if key in seen:
            raise ValueError('duplicate root section')
        seen.add(key)
        roots.append(key)
    roots.sort()
    return roots


def _plan_tables(plan):
    # link(plan) 已成功，结构已按 link 契约完整校验，可直接按身份建表。
    objects = {}
    for obj in plan['objects']:
        oid = obj['id']
        sections = {}
        for sec in obj['sections']:
            sections[sec['name']] = dict(sec)
        symbols = {}
        for sym in obj['symbols']:
            symbols[sym['name']] = dict(sym)
        by_section = {}
        for rel in obj['relocations']:
            by_section.setdefault(rel['section'], []).append({
                'id': rel['id'],
                'scope': rel['symbol']['scope'],
                'name': rel['symbol']['name'],
            })
        for lst in by_section.values():
            lst.sort(key=lambda rel: rel['id'])
        objects[oid] = {'sections': sections, 'symbols': symbols,
                        'relocations_by_section': by_section}
    return objects


def _closure(objects, winners, roots):
    """从入口出发沿 relocation 求可达 section 闭包。

    local 引用沿现有 linker 规则解析到同一对象内的本地定义；global 引用
    只跟随完整 plan 链接结果中的胜者，被 shadowed 的定义不因同名被保留。
    每个非入口 section 记录首次把它带入闭包的那条 relocation 身份，
    父指针只指向更早进入闭包的 section，因此依据链天然无环；遍历顺序
    只由排序后的身份决定，与输入数组排列无关。
    """
    kept = set()
    via = {}
    heap = []
    for key in roots:
        kept.add(key)
        heapq.heappush(heap, key)
    while heap:
        oid, sec = heapq.heappop(heap)
        for rel in objects[oid]['relocations_by_section'].get(sec, ()):
            if rel['scope'] == 'local':
                target_oid = oid
            else:
                target_oid = winners[rel['name']]
            target_sec = objects[target_oid]['symbols'][rel['name']]['section']
            key = (target_oid, target_sec)
            if key not in kept:
                kept.add(key)
                via[key] = {'object': oid, 'section': sec, 'id': rel['id']}
                heapq.heappush(heap, key)
    return kept, via


def _prune_plan(plan, kept):
    """按原始身份过滤 plan：只移除未保留 section 及其定义和 relocation。

    对象记录全部保留，即使某对象没有保留 section；regions 原样保留。
    所有数组按身份排序规范化，使输出与输入数组排列无关。
    """
    regions = sorted(
        ({'name': r['name'], 'base': r['base'], 'size': r['size']}
         for r in plan['regions']),
        key=lambda r: r['name'])
    objects = []
    for obj in sorted(plan['objects'], key=lambda o: o['id']):
        oid = obj['id']
        sections = sorted(
            ({'name': s['name'], 'region': s['region'], 'size': s['size'],
              'alignment': s['alignment']}
             for s in obj['sections'] if (oid, s['name']) in kept),
            key=lambda s: s['name'])
        symbols = sorted(
            ({'name': s['name'], 'section': s['section'],
              'offset': s['offset'], 'binding': s['binding']}
             for s in obj['symbols'] if (oid, s['section']) in kept),
            key=lambda s: s['name'])
        relocations = sorted(
            ({'id': r['id'], 'section': r['section'], 'offset': r['offset'],
              'symbol': {'scope': r['symbol']['scope'],
                         'name': r['symbol']['name']},
              'addend': r['addend'], 'width': r['width']}
             for r in obj['relocations'] if (oid, r['section']) in kept),
            key=lambda r: r['id'])
        objects.append({'id': oid, 'sections': sections, 'symbols': symbols,
                        'relocations': relocations})
    return {'regions': regions, 'objects': objects}


def select_link_sections(data):
    fields(data, ('plan', 'roots'))
    # 先验证完整 plan 的链接语义：不可达区域中的非法 relocation 或重复
    # strong 定义同样使整次调用失败，分析不得把非法输入藏在可裁剪区域。
    linked = link(data['plan'])
    roots = _parse_roots(data['roots'])
    objects = _plan_tables(data['plan'])
    for oid, sec in roots:
        if oid not in objects or sec not in objects[oid]['sections']:
            raise ValueError('root section not in plan')

    winners = {g['name']: g['winner']['object']
               for g in linked['symbols']['globals']}
    kept, via = _closure(objects, winners, roots)

    all_sections = sorted((oid, name)
                          for oid, obj in objects.items()
                          for name in obj['sections'])
    excluded = [key for key in all_sections if key not in kept]

    pruned_plan = _prune_plan(data['plan'], kept)
    # 重链必须来自 pruned plan 的实际 link 结果：移除 section 可能改变
    # 对齐布局与后续地址；过滤后不再合法（如重定位值溢出）时整体拒绝。
    pruned_linked = link(pruned_plan)

    justifications = []
    for key in sorted(kept):
        oid, sec = key
        if key in via:
            justifications.append({
                'object': oid, 'section': sec, 'kind': 'relocation',
                'via': dict(via[key]),
            })
        else:
            justifications.append({
                'object': oid, 'section': sec, 'kind': 'root', 'via': None,
            })

    return {
        'plan': {'summary': linked['summary']},
        'roots': [{'object': oid, 'section': sec} for oid, sec in roots],
        'kept_sections': [{'object': oid, 'section': sec}
                          for oid, sec in sorted(kept)],
        'excluded_sections': [{'object': oid, 'section': sec}
                              for oid, sec in excluded],
        'justifications': justifications,
        'pruned_plan': pruned_plan,
        'pruned_link': pruned_linked,
        'summary': {
            'regions': len(pruned_plan['regions']),
            'objects': len(objects),
            'sections': len(all_sections),
            'roots': len(roots),
            'kept_sections': len(kept),
            'excluded_sections': len(excluded),
        },
        'scope': _SCOPE_NOTE,
    }
