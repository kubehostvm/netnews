#!/usr/bin/env python3
"""Validate a manual review ledger, not prove a complete kernel call graph."""
import argparse
import hashlib
import html
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
COMMIT = '5260836abb7056beed3f3f0d0e4262c11f36f0d0'
KINDS = {'direct', 'indirect', 'conditional', 'async', 'summary'}


def evidence_valid(items, kernel, commit=COMMIT):
    if not isinstance(items, list) or not items:
        return False
    for item in items:
        if not isinstance(item, dict):
            return False
        if item.get('commit') != commit or not str(item.get('explanation', '')).strip():
            return False
        path = item.get('file')
        start, end = item.get('start'), item.get('end')
        if not isinstance(path, str) or not path or path.startswith('/') or '..' in Path(path).parts:
            return False
        if type(start) is not int or type(end) is not int or start < 1 or end < start:
            return False
        result = subprocess.run(['git', '-C', str(kernel), 'show', f'{commit}:{path}'], capture_output=True, text=True)
        if result.returncode or end > len(result.stdout.splitlines()):
            return False
    return True


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def internal_arrows(label):
    """Extract adjacent displayed steps; these are not necessarily caller/callee pairs."""
    normalized = label.replace(r'\n', '\n')
    matches = list(re.finditer(r'(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*)\(\)', normalized))
    return [
        (left.group(1), right.group(1))
        for left, right in zip(matches, matches[1:])
        if re.fullmatch(r'\s*(?:→|->)\s*', normalized[left.end():right.start()])
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--strict', action='store_true', help='Fail if manual evidence review is incomplete; never certifies completeness')
    parser.add_argument('--kernel', type=Path, default=Path('/root/g/linux'))
    args = parser.parse_args()
    graph = json.loads(subprocess.check_output(['dot', '-Tjson', str(ROOT / 'diagrams/host-tcp-v6.6.dot')], text=True))
    objects = {obj['_gvid']: obj for obj in graph['objects']}
    path = ROOT / 'diagrams/host-tcp-edge-review.json'
    review = json.loads(path.read_text()) if path.exists() else {'commit': COMMIT}
    assert review['commit'] == COMMIT, 'Baseline changed: create a separate review'
    rows, pending = [], []
    units = {}
    for edge in graph['edges']:
        if edge.get('style') == 'invis':
            continue
        source, target = (objects[edge[key]] for key in ('tail', 'head'))
        key = source['name'] + ' -> ' + target['name']
        assert key not in units, key
        units[key] = {'source': source.get('label', source['name']), 'target': target.get('label', target['name']), 'style': edge.get('style'), 'label': edge.get('label')}
    # Review labels too: arrows inside a node are separate claims from graph edges.
    for obj in graph['objects']:
        if 'nodes' in obj or 'label' not in obj:
            continue
        label = obj['label']
        units['node:' + obj['name']] = {'label': label}
        for index, (source_name, target_name) in enumerate(internal_arrows(label)):
            units[f'node:{obj["name"]}:internal:{index}'] = {
                'source': source_name + '()', 'target': target_name + '()', 'label': label,
                'relation': 'parser v2: adjacent explicit arrow; manual review must distinguish calls from sibling execution',
            }
    ledger = review.setdefault('edges', {})
    archive = review.setdefault('obsolete', {})
    for key in set(ledger) - set(units):
        archive[key] = ledger.pop(key)
    for key, value in units.items():
        digest = fingerprint(value)
        item = ledger.setdefault(key, {'kind': 'unclassified', 'evidence': [], 'reviewed': False})
        item['claim'] = value
        if item.get('fingerprint') != digest:
            item['reviewed'] = False
            # The previous parser truncated identifiers and joined unrelated branches.
            if ':internal:' in key:
                item['kind'] = 'unclassified'
                item['evidence'] = []
        item['fingerprint'] = digest
        valid = item.get('reviewed') is True and item.get('kind') in KINDS and evidence_valid(item.get('evidence'), args.kernel)
        if not valid:
            pending.append(key)
        rows.append('<tr><td>' + html.escape(key) + '</td><td>' + html.escape(json.dumps(value, ensure_ascii=False)) + '</td><td>' + ('人工证据记录有效' if valid else '待审查 / 证据无效') + '</td><td>' + html.escape(json.dumps(item.get('evidence', []), ensure_ascii=False)) + '</td></tr>')
    requirements = ('rx_and_gro', 'tx_and_qdisc', 'tcp_states_and_timers', 'netfilter_tables_and_nat', 'bpf_attachment_and_redirect', 'driver_and_offloads', 'errors_and_drop_paths', 'config_and_scope')
    closure = review.setdefault('closure', {})
    diagram_digest = fingerprint(units)
    incomplete = []
    for name in requirements:
        item = closure.setdefault(name, {'reviewed': False, 'evidence': []})
        if item.get('fingerprint') != diagram_digest:
            item['reviewed'] = False
        item['fingerprint'] = diagram_digest
        if not (item.get('reviewed') is True and evidence_valid(item.get('evidence'), args.kernel)):
            incomplete.append(name)
    path.write_text(json.dumps(review, ensure_ascii=False, indent=2) + '\n')
    text = '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>调用关系人工审查记录</title><style>body{padding:24px;font:15px/1.6 system-ui}table{border-collapse:collapse}td{border:1px solid #ccc;padding:8px;max-width:650px;overflow-wrap:anywhere}</style></head><body><a href="./netfilter-bpf.html">返回专题</a><h1>调用关系人工审查记录（不是完备性证明）</h1>'
    text += f'<p>基线 {COMMIT}；边与节点内部关系审查单元 {len(units)}，待审查 {len(pending)}；路径闭包待审查 {len(incomplete)} 项。</p>'
    text += '<p>检查器只验证人工证据的结构、固定 commit 的文件与行范围，以及图修改后的记录失效。它不理解源码语义，不证明调用成立或没有遗漏。即使 --strict 成功，也只能表示人工证据记录通过，不能宣称全量调用图完备。</p><table>' + ''.join(rows) + '</table></body></html>\n'
    (ROOT / 'kernel-callgraph-review.html').write_text(text)
    print(f'{len(units)} review units; {len(pending)} pending; {len(incomplete)} closure checks pending')
    if args.strict and (pending or incomplete):
        raise SystemExit('FAIL: manual evidence review is incomplete (no completeness proof)')


if __name__ == '__main__':
    main()
