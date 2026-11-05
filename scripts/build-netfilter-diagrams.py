#!/usr/bin/env python3
"""Rebuild the two SVG diagrams with Graphviz and check their published links."""
from html.parser import HTMLParser
from pathlib import Path
import subprocess
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def main():
    for name in ('netfilter-bpf-overview', 'host-tcp-v6.6'):
        source = ROOT / 'diagrams' / f'{name}.dot'
        target = source.with_suffix('.svg')
        subprocess.run(['dot', '-Tsvg', str(source), '-o', str(target)], check=True)
        tree = ET.parse(target)
        text = ' '.join(tree.getroot().itertext())
        for required in ('PREROUTING', 'OUTPUT', 'POSTROUTING', 'raw', 'mangle', 'nat', 'filter', 'XDP', 'TC', 'v6.6'):
            assert required in text, (name, required)
        assert 'viewBox' in tree.getroot().attrib, name
    overview = (ROOT / 'diagrams/netfilter-bpf-overview.dot').read_text()
    assert 'FORWARD' in overview and 'INPUT' in overview
    tcp = (ROOT / 'diagrams/host-tcp-v6.6.dot').read_text()
    for required in ('tcp_v4_rcv', 'tcp_sendmsg', 'sk_filter_trim_cap', 'ip_finish_output', 'nf_hook_egress'):
        assert required in tcp, required

    class Links(HTMLParser):
        def __init__(self):
            super().__init__()
            self.ids = set()
            self.anchors = []

        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if 'id' in attrs:
                self.ids.add(attrs['id'])
            for key in ('href', 'src'):
                url = urlsplit(attrs.get(key, ''))
                if url.scheme or url.netloc:
                    continue
                if url.path:
                    assert (ROOT / url.path).is_file(), url.path
                elif url.fragment:
                    self.anchors.append(url.fragment)

    parser = Links()
    parser.feed((ROOT / 'netfilter-bpf.html').read_text())
    assert all(anchor in parser.ids for anchor in parser.anchors)
    print('Built both SVGs; XML, required labels, local links and section anchors checked.')


if __name__ == '__main__':
    main()
