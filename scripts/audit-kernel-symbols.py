#!/usr/bin/env python3
"""Index named diagram symbols against a pinned local Git revision (not a call-graph proof)."""
import argparse
import html
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def git(kernel, *args):
    return subprocess.check_output(['git', '-C', str(kernel), *args], text=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, default=Path('/root/g/linux'))
    parser.add_argument('--ref', default='v6.6')
    args = parser.parse_args()
    commit = git(args.kernel, 'rev-parse', args.ref).strip()
    current = git(args.kernel, 'describe', '--always', 'HEAD').strip()
    dot = (ROOT / 'diagrams/host-tcp-v6.6.dot').read_text()
    symbols = sorted(set(re.findall(r'\b([A-Za-z_][A-Za-z_0-9]*)\(\)', dot.replace(r'\n', '\n'))))
    with tempfile.NamedTemporaryFile(mode='w') as patterns:
        patterns.write('\n'.join(symbols) + '\n')
        patterns.flush()
        result = subprocess.run(['git', '-C', str(args.kernel), 'grep', '-n', '-w', '-F', '-f', patterns.name, commit, '--', 'net', 'include', 'drivers/net/ethernet/intel/ixgbe'], text=True, capture_output=True)
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr)
    hits = {symbol: [] for symbol in symbols}
    token = re.compile(r'\b(?:' + '|'.join(map(re.escape, symbols)) + r')\b')
    for line in result.stdout.splitlines():
        _, path, number, content = line.split(':', 3)
        for symbol in set(token.findall(content)):
            hits[symbol].append((path, number, content.strip()))
    rows = []
    for symbol, locations in hits.items():
        # Display occurrences, never claim these are resolved function definitions.
        locations.sort(key=lambda hit: (not bool(re.search(r'\b' + re.escape(symbol) + r'\s*\(', hit[2])), hit[0], int(hit[1])))
        links = []
        for path, number, content in locations[:4]:
            url = f'https://github.com/torvalds/linux/blob/{commit}/{path}#L{number}'
            links.append(f'<a href="{url}">{html.escape(path)}:{number}</a><br><code>{html.escape(content)}</code>')
        rows.append(f'<tr><td><code>{symbol}()</code></td><td>{len(locations)}</td><td>{"<hr>".join(links) or "未找到：需核查图中拼写或版本"}</td></tr>')
    missing = [symbol for symbol, locations in hits.items() if not locations]
    page = '''<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>TCP 图函数源码索引</title><style>body{max-width:1200px;margin:auto;padding:24px;font:16px/1.7 system-ui}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:10px;text-align:left}code{overflow-wrap:anywhere}a{color:#155bb5;overflow-wrap:anywhere}</style></head><body><a href="./netfilter-bpf.html">返回专题</a><h1>TCP 函数图：本地源码交叉索引</h1>'''
    page += f'<p>核验仓库：<code>{html.escape(str(args.kernel))}</code>；图的基线：<code>{html.escape(args.ref)}</code>，commit <code>{commit}</code>。仓库当前 HEAD 为 <code>{html.escape(current)}</code>，本索引通过 git 读取指定版本，不切换工作区。</p>'
    page += f'<p>从图中提取 {len(symbols)} 个带空括号的命名符号，{len(symbols)-len(missing)} 个有源码文本命中，{len(missing)} 个未命中。每个符号最多展示四处命中。可用浏览器查找函数名。</p>'
    page += '<p><strong>核验边界：</strong>这是可复现的文本交叉索引，不是编译器解析的调用图。命中可能是定义、调用、声明、宏或注释；没有命中不能直接证明函数不存在。它不验证图中的调用顺序，也不表示图已包含所有函数。函数指针、内联、条件编译、动态 BPF/规则和驱动配置仍需单独核对。仓库没有 .config 时不能据此还原实际执行路径。</p>'
    page += '<table><thead><tr><th>图中符号</th><th>文本命中数</th><th>固定 commit 源码位置</th></tr></thead><tbody>' + ''.join(rows) + '</tbody></table></body></html>\n'
    (ROOT / 'kernel-symbol-index.html').write_text(page)
    print(f'{len(symbols)} symbols; missing: {missing}; commit: {commit}')


if __name__ == '__main__':
    main()
