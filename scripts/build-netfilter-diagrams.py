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
    for required in ('FORWARD', 'INPUT', 'BROUTING', 'NF_BR_PRE_ROUTING', 'XFRM', 'AF_PACKET', '2.6.36+', 'MODERN', 'four tables / five chains', 'iptables-legacy', 'iptables-nft', 'native nft'):
        assert required in overview, required
    tcp = (ROOT / 'diagrams/host-tcp-v6.6.dot').read_text()
    for required in ('tcp_v4_rcv', 'tcp_sendmsg', 'sk_filter_trim_cap', 'ip_finish_output', 'nf_hook_egress', 'ipt_do_table', 'nft_do_chain', 'nf_hook_run_bpf', 'tcp_check_req', 'tcp_timewait_state_process', 'tcp_retransmit_timer', 'tcp_recvmsg_locked'):
        assert required in tcp, required
    svg = ET.parse(ROOT / 'diagrams/host-tcp-v6.6.svg')
    nodes = [element for element in svg.iter() if element.get('class') == 'node']
    assert len(nodes) >= 140, f'Function diagram unexpectedly collapsed: {len(nodes)} nodes'
    for required in ('ipv4_conntrack_defrag', 'ipv4_conntrack_in', 'ipv4_conntrack_local', 'nf_confirm', 'nf_conntrack_tcp_packet', 'expr_call_ops_eval', 'ip_packet_match', 'bpf_mt_v1', 'bpf_sk_lookup_run_v4', 'ixgbe_clean_rx_irq', 'ixgbe_tx_map', 'tcp_send_fin', 'tcp_v4_connect', 'inet_csk_accept'):
        assert required in tcp, required
    assert 'nft_expr_eval' not in tcp
    source_links = [element for element in svg.iter() if element.get('{http://www.w3.org/1999/xlink}href', '').startswith('https://github.com/torvalds/linux/blob/v6.6/')]
    assert len(source_links) >= 12, 'Missing clickable kernel source links'

    class Links(HTMLParser):
        def __init__(self):
            super().__init__()
            self.ids = set()
            self.anchors = []

        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if 'id' in attrs:
                self.ids.add(attrs['id'])
            for key in ('href', 'src', 'data'):
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
