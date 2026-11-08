"""Phase 12 wiring tests: report/dashboard buckets for panel/waf/dork/tls/nikto.

Keyed on template prefix only; the new stage modules are not imported.

    cd ~/tools/bounty-run && python3 -m pytest tests/test_phase12_wiring.py -q
"""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner import dashboard, report  # noqa: E402


NEW_LABELS = [
    "High-value panels (subdomains)",
    "WAF detections (wafw00f)",
    "Dork hits (OSINT)",
    "TLS/SSL issues (sslyze)",
    "Nikto findings",
]


def _f(template, severity="info", name=None, host="example.com", url=None):
    return {
        "severity": severity, "template": template, "name": name or template,
        "url": url or f"https://{host}/", "host": host, "evidence": "",
    }


def _phase12_findings():
    return [
        _f("panel:cpanel", "low", host="cpanel.example.com"),
        _f("waf:cloudflare", "info", name="WAF detected: Cloudflare (Cloudflare Inc.)"),
        _f("dork:exposed-file", "low", url="https://example.com/backup/db.sql"),
        _f("tls:heartbleed", "critical", url="https://example.com:443"),
        _f("nikto:outdated-software:600050", "low"),
    ]


def _metrics(findings):
    return report.build_metrics(
        "example.com", ["example.com"], [], {}, [], findings, [], 1.0,
    )


class TestBuildMetrics(unittest.TestCase):
    def test_new_buckets_counted(self):
        m = dict(_metrics(_phase12_findings()))
        for label in NEW_LABELS:
            self.assertEqual(m[label], "1", label)

    def test_new_buckets_not_counted_as_nuclei(self):
        labels = [label for label, _ in _metrics(_phase12_findings())]
        self.assertFalse([l for l in labels if l.startswith("Nuclei findings")])

    def test_zero_when_absent(self):
        m = dict(_metrics([]))
        for label in NEW_LABELS:
            self.assertEqual(m[label], "0", label)

    def test_bucket_order(self):
        labels = [label for label, _ in _metrics(_phase12_findings())]
        i = labels.index("Open ports (nmap)")
        self.assertEqual(labels[i + 1:i + 1 + len(NEW_LABELS)], NEW_LABELS)


class TestRunSummary(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def _doc(self, findings):
        path = dashboard.write_run_summary(
            Path(self._tmp.name) / "out", "example.com", findings, [], [],
            run_time="2026-11-08 10:00:00", subdomains=3, live_hosts=2,
            cloudflare=False,
        )
        return path.read_text()

    @staticmethod
    def _card(label, value):
        return ('<div class="card"><div class="card-label">{}</div>'
                '<div class="card-value">{}</div></div>').format(label, value)

    def test_waf_card_lists_names(self):
        doc = self._doc(_phase12_findings())
        self.assertIn(self._card("waf", "Cloudflare"), doc)

    def test_waf_card_none(self):
        doc = self._doc([_f("panel:cpanel", "low")])
        self.assertIn(self._card("waf", "none"), doc)

    def test_waf_card_dedupes_and_sorts(self):
        findings = [
            _f("waf:cloudflare", name="WAF detected: Cloudflare (Cloudflare Inc.)",
               host="a.example.com"),
            _f("waf:cloudflare", name="WAF detected: Cloudflare (Cloudflare Inc.)",
               host="b.example.com"),
            _f("waf:aws-elastic-load-balancer",
               name="WAF detected: AWS Elastic Load Balancer (Amazon)"),
        ]
        doc = self._doc(findings)
        self.assertIn(self._card("waf", "AWS Elastic Load Balancer, Cloudflare"), doc)

    def test_count_cards(self):
        findings = _phase12_findings() + [
            _f("nikto:missing-header:999", "info", url="https://example.com/x"),
        ]
        doc = self._doc(findings)
        self.assertIn(self._card("panels", "1"), doc)
        self.assertIn(self._card("dork hits", "1"), doc)
        self.assertIn(self._card("tls issues", "1"), doc)
        self.assertIn(self._card("nikto", "2"), doc)

    def test_cards_follow_open_ports(self):
        doc = self._doc(_phase12_findings())
        order = ["open ports (nmap)", "waf", "panels", "dork hits", "tls issues", "nikto",
                 "total findings"]
        idx = [doc.index('<div class="card-label">{}</div>'.format(lbl)) for lbl in order]
        self.assertEqual(idx, sorted(idx))

    def test_metric_cards_positional_callers_still_valid(self):
        html = dashboard._summary_metric_cards(1, 1, False, 0, [], 0, 0)
        self.assertIn(self._card("waf", "none"), html)
        self.assertIn(self._card("nikto", "0"), html)


if __name__ == "__main__":
    unittest.main()
