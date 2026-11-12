#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('review', Path(__file__).with_name('check-callgraph-coverage.py'))
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)


class EvidenceTests(unittest.TestCase):
    def test_evidence_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(['git', 'init', '-q', directory], check=True)
            root = Path(directory)
            (root / 'sample.c').write_text('void caller(void) { callee(); }\n')
            subprocess.run(['git', '-C', directory, 'add', '.'], check=True)
            subprocess.run(['git', '-C', directory, '-c', 'user.name=Test', '-c', 'user.email=test@example.com', 'commit', '-qm', 'fixture'], check=True)
            commit = subprocess.check_output(['git', '-C', directory, 'rev-parse', 'HEAD'], text=True).strip()
            item = dict(commit=commit, file='sample.c', start=1, end=1, explanation='Review caller body')
            self.assertTrue(review.evidence_valid([item], root, commit))
            for change in ({'file': 'missing.c'}, {'end': 2}, {'start': 0}, {'start': True}, {'commit': 'bad'}, {'explanation': ''}, {'file': '../sample.c'}):
                self.assertFalse(review.evidence_valid([{**item, **change}], root, commit))
            self.assertFalse(review.evidence_valid(['arbitrary string'], root, commit))
            self.assertFalse(review.evidence_valid([], root, commit))

    def test_diagram_regressions(self):
        root = Path(__file__).resolve().parents[1]
        tcp = (root / 'diagrams/host-tcp-v6.6.dot').read_text()
        overview = (root / 'diagrams/netfilter-bpf-overview.dot').read_text()
        for wrong in ('ack -> transmit ', 'early -> route ', 'finish -> receive ', 'bo -> bd'):
            self.assertNotIn(wrong, tcp + overview)
        for required in ('acksend -> transmit2', 'validdst -> delivery', 'validdst -> route', 'GRO_MERGED_FREE', 'UNSPEC / no TCX', 'brtx -> bo; bo -> bpost'):
            self.assertIn(required, tcp + overview)
        for wrong in ('ofo -> queue ', 'neigh -> connected [label="resolved"]', 'neigh -> resolve [label="unresolved"]'):
            self.assertNotIn(wrong, tcp)
        self.assertNotIn('pick -> validateout ', tcp)
        self.assertIn('direct -> validateout [label="validate=true"]', tcp)
        self.assertIn('direct -> validskb [label="validate=false: already validated skb"]', tcp)
        self.assertIn('again -> requeueagain', tcp)
        self.assertIn('txstate -> missed', tcp)
        self.assertIn('result -> busy', tcp)
        self.assertNotIn('direct -> validateout ->', tcp)
        for required in ('synackout -> localout', 'resetout -> localout', 'bpf_run_sk_reuseport()', 'pick -> validatesingle', 'validateout -> again', 'validatesingle -> validskb', 'native -> xdp_run', 'generic -> genericrun', 'rps -> backlogcpu', 'rps -> localcpu', 'backlogcpu -> core', 'flush -> normal', 'stateclass -> establishedpath', 'stateclass -> timepath', 'stateclass -> nosocket', 'establishedpath -> policy', 'requestpath -> requestfilter', 'requestfilter -> policy', 'requestcheck -> req', 'req -> accept', 'accept -> requestcheck', 'hard -> one', 'one -> ndo', 'ipfinishout -> cgout', 'cgout -> cgdrop', 'noutput -> directneigh', 'noutput -> blackhole', 'ixspace -> ixbusy', 'ixspace -> ixsetup', 'ixsetup -> ixdrop', 'ixmap -> ixok', 'outroute -> noroute', 'outroute -> localout', 'localout2 -> l3drop', 'localout2 -> output', 'one -> ndo', 'ndo -> start', 'start -> result'):
            self.assertIn(required, tcp)
        for required in ('ip_list_rcv()', 'NF_HOOK_LIST(PREROUTING)', 'ip_sublist_rcv_finish()', 'subfinish -> dstin', 'ofodrain -> recvqueue', 'READ_ONCE(n->output)', 'event -> devqueue', 'event -> waitarp'):
            self.assertIn(required, tcp)


if __name__ == '__main__':
    unittest.main()
