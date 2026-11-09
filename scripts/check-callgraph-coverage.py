#!/usr/bin/env python3
"""Inventory every Graphviz edge; fail --strict until evidence and closure are reviewed."""
import argparse
import html
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
COMMIT = '5260836abb7056beed3f3f0d0e4262c11f36f0d0'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--strict', action='store_true')
    args = parser.parse_args()
    graph = json.loads(subprocess.check_output(['dot', '-Tjson', str(ROOT / 'diagrams/host-tcp-v6.6.dot')], text=True))
    objects = {obj['_gvid']: obj for obj in graph['objects']}
    review_path = ROOT / 'diagrams/host-tcp-edge-review.json'
    review = json.loads(review_path.read_text()) if review_path.exists() else {'commit': COMMIT, 'edges': {}, 'closure': {}}
    assert review['commit'] == COMMIT, 'Kernel baseline changed; invalidate the old review first'
    rows, pending, seen = [], [], set()
    for edge in graph['edges']:
        if edge.get('style') == 'invis':
            continue
        source, target = (objects[edge[key]] for key in ('tail', 'head'))
        key = source['name'] + ' -> ' + target['name']
        assert key not in seen, f'Duplicate edge requires an explicit ID: {key}'
        seen.add(key)
        item = review['edges'].setdefault(key, {'kind': 'unclassified', 'evidence': [], 'reviewed': False})
        valid = item['reviewed'] and item['kind'] in ('direct', 'indirect', 'conditional', 'async', 'summary') and bool(item['evidence'])
        if not valid:
            pending.append(key)
        def label(obj):
            return html.escape(obj.get('label', obj['name'])).replace('\\n', '<br>')
        rows.append(f'<tr><td>{html.escape(key)}</td><td>{label(source)}</td><td>{label(target)}</td><td>{html.escape(item["kind"])}</td><td>{"已审查" if valid else "待源码审查"}</td><td>{html.escape(json.dumps(item["evidence"], ensure_ascii=False))}</td></tr>')
    stale = set(review['edges']) - seen
    assert not stale, f'Remove stale review entries: {sorted(stale)}'
    # Edge evidence is necessary but insufficient: omitted branches also need closure review.
    requirements = ('rx_and_gro', 'tx_and_qdisc', 'tcp_states_and_timers', 'netfilter_tables_and_nat', 'bpf_attachment_and_redirect', 'driver_and_offloads', 'errors_and_drop_paths', 'config_and_scope')
    for name in requirements:
        review['closure'].setdefault(name, {'reviewed': False, 'evidence': []})
    incomplete = [name for name in requirements if not (review['closure'][name]['reviewed'] and review['closure'][name]['evidence'])]
    review_path.write_text(json.dumps(review, ensure_ascii=False, indent=2) + '\n')
    text = '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>函数图完备性审查</title><style>body{padding:24px;font:15px/1.6 system-ui}table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:8px;vertical-align:top}td{max-width:420px;overflow-wrap:anywhere}</style></head><body><a href="./netfilter-bpf.html">返回专题</a><h1>函数图完备性审查：未通过</h1>'
    text += f'<p>基线 {COMMIT}。共 {len(seen)} 条可见边，待审查 {len(pending)} 条；路径闭包待审查 {len(incomplete)} 项。节点存在或符号文本命中不等于调用关系成立。</p>'
    text += '<p>通过标准：每条边标注直接调用/间接回调/条件/异步/概括关系并给出源码证据；另检查配置范围、收发旁路、状态与定时器、丢包错误分支和动态规则。没有这些证据，不得宣称完整。“summary”边只能证明概括关系，不能用于声称全量函数调用图。</p>'
    text += '<p>尚缺：' + html.escape(', '.join(incomplete)) + '</p><table><tr><th>边 ID</th><th>起点</th><th>终点</th><th>关系类型</th><th>状态</th><th>证据</th></tr>' + ''.join(rows) + '</table></body></html>'
    (ROOT / 'kernel-callgraph-review.html').write_text(text)
    print(f'{len(seen)} edges; {len(pending)} unreviewed; {len(incomplete)} closure checks pending')
    if args.strict and (pending or incomplete or any(item['kind'] == 'summary' for item in review['edges'].values())):
        raise SystemExit('FAIL: full-callgraph completeness is not established')


if __name__ == '__main__':
    main()
