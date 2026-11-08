"""Phase 12 wiring tests: report/dashboard buckets + CLI wiring for
panel/waf/dork/tls/nikto.

Report/dashboard tests key on template prefix only. CLI tests patch every
stage function so no network or real tool is touched.

    cd ~/tools/bounty-run && python3 -m pytest tests/test_phase12_wiring.py -q
"""

import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner import (api_endpoints, cli, dashboard, dork_scan, headi_scan,  # noqa: E402
                    http_headers, metis_check, nikto_scan, nmap_scan, origin_deep,
                    panel_detect, param_scan, report, secret_scan, stages,
                    tech_scan, tls_scan, waf_scan)


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



# ---------------------------------------------------------------- CLI wiring

NEW_TOKENS = ["panel", "waf", "dork", "tls", "nikto"]
SUBS = ["example.com", "a.example.com"]
ROWS = [{"host": "a.example.com", "status": 200, "server": "nginx", "cloudflare": False}]


class TestCliFlags(unittest.TestCase):
    def test_flags_default_false(self):
        a = cli.build_parser().parse_args(["example.com"])
        self.assertFalse(a.tls)
        self.assertFalse(a.nikto)

    def test_flags_set(self):
        a = cli.build_parser().parse_args(["example.com", "--tls", "--nikto"])
        self.assertTrue(a.tls)
        self.assertTrue(a.nikto)

    def test_skip_help_lists_tokens(self):
        skip_action = next(x for x in cli.build_parser()._actions if "--skip" in x.option_strings)
        tokens = [t.strip() for t in skip_action.help.split(":", 1)[1].split(",")]
        for tok in NEW_TOKENS:
            self.assertIn(tok, tokens)
        help_text = cli.build_parser().format_help()
        for tok in NEW_TOKENS:
            self.assertIn(tok, help_text)

    def test_total_stages(self):
        self.assertEqual(cli.TOTAL_STAGES, 20)


class TestCliMain(unittest.TestCase):
    """Run cli.main with every stage patched; inspect which new stages ran."""

    def _run(self, extra, returns=None):
        returns = returns or {}
        calls: list[str] = []

        def rec(name, ret):
            def _side(*a, **k):
                calls.append(name)
                return ret
            return _side

        targets = {
            "subdomain_enum": (stages, "subdomain_enum", list(SUBS)),
            "live_hosts": (stages, "live_hosts", list(ROWS)),
            "cloudflare_detect": (stages, "cloudflare_detect",
                                  {"target": "example.com", "cloudflare": False, "evidence": []}),
            "origin_hunt": (stages, "origin_hunt", []),
            "origin_deep": (origin_deep, "origin_deep", []),
            "nmap_scan": (nmap_scan, "nmap_scan", []),
            "vuln_scan": (stages, "vuln_scan", []),
            "content_discovery": (stages, "content_discovery", []),
            "api_endpoints_scan": (api_endpoints, "api_endpoints_scan", []),
            "param_scan": (param_scan, "param_scan", []),
            "secret_scan": (secret_scan, "secret_scan", []),
            "metis_check": (metis_check, "metis_check", []),
            "security_headers_scan": (http_headers, "security_headers_scan", []),
            "cors_scan": (http_headers, "cors_scan", []),
            "tech_scan": (tech_scan, "tech_scan", []),
            "headi_scan": (headi_scan, "headi_scan", []),
            "write_findings_report": (report, "write_findings_report", 0),
            "write_run_summary": (dashboard, "write_run_summary", None),
            "panel_detect": (panel_detect, "panel_detect", []),
            "waf_scan": (waf_scan, "waf_scan", []),
            "dork_scan": (dork_scan, "dork_scan", []),
            "tls_scan": (tls_scan, "tls_scan", []),
            "nikto_scan": (nikto_scan, "nikto_scan", []),
        }
        mocks = {}
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as st:
            for name, (mod, attr, ret) in targets.items():
                ret = returns.get(name, ret)
                side = ret if callable(ret) else rec(name, ret)
                mocks[name] = st.enter_context(
                    mock.patch.object(mod, attr, side_effect=side))
            st.enter_context(mock.patch.object(cli.utils, "log"))
            st.enter_context(mock.patch.object(cli.utils, "warn"))
            st.enter_context(mock.patch.object(cli.utils, "stage_header"))
            st.enter_context(mock.patch("builtins.print"))
            rc = cli.main(["example.com", "-o", tmp, "--no-banner", "--no-track"] + extra)
        self.assertEqual(rc, 0)
        return mocks, calls

    def test_main_default_gating(self):
        m, _ = self._run([])
        for name in ("panel_detect", "waf_scan", "dork_scan"):
            self.assertEqual(m[name].call_count, 1, name)
        m["tls_scan"].assert_not_called()
        m["nikto_scan"].assert_not_called()
        args, kwargs = m["panel_detect"].call_args
        self.assertEqual(args[0], "example.com")
        self.assertEqual(args[2], SUBS)
        self.assertEqual(m["waf_scan"].call_args.kwargs["max_hosts"], 20)
        self.assertEqual(m["waf_scan"].call_args.kwargs["hosts"], ["a.example.com"])
        self.assertEqual(m["dork_scan"].call_args.args[0], "example.com")

    def test_main_optin_and_skip(self):
        m, _ = self._run(["--tls", "--nikto"])
        m["tls_scan"].assert_called_once()
        m["nikto_scan"].assert_called_once()
        self.assertEqual(m["tls_scan"].call_args.kwargs["max_hosts"], 20)
        self.assertEqual(m["tls_scan"].call_args.kwargs["hosts"], ["a.example.com"])
        self.assertEqual(m["nikto_scan"].call_args.kwargs["max_hosts"], 20)

        m, _ = self._run(["--tls", "--nikto", "--skip", "panel,waf,dork,tls,nikto"])
        for name in ("panel_detect", "waf_scan", "dork_scan", "tls_scan", "nikto_scan"):
            m[name].assert_not_called()

    def test_max_hosts_below_cap_passes_through(self):
        m, _ = self._run(["--tls", "--nikto", "--max-hosts", "5"])
        for name in ("waf_scan", "tls_scan", "nikto_scan"):
            self.assertEqual(m[name].call_args.kwargs["max_hosts"], 5, name)

    def test_panel_runs_on_target_when_subs_skipped(self):
        m, _ = self._run(["--skip", "subs"])
        self.assertEqual(m["panel_detect"].call_args.args[2], ["example.com"])

    def test_stage_order(self):
        _, calls = self._run(["--tls", "--nikto"])
        order = ["subdomain_enum", "panel_detect", "live_hosts", "waf_scan",
                 "dork_scan", "tls_scan", "nikto_scan", "vuln_scan"]
        idx = [calls.index(n) for n in order]
        self.assertEqual(idx, sorted(idx), calls)

    def test_new_findings_reach_report(self):
        finding = _f("waf:cloudflare")
        captured = []

        def grab(outdir, target, findings, content, **kw):
            captured.append(list(findings))
            return 0

        self._run([], returns={"waf_scan": [finding], "write_findings_report": grab})
        # early nuclei report and final report both already contain the waf finding
        self.assertEqual(len(captured), 2)
        for fs in captured:
            self.assertIn(finding, fs)

if __name__ == "__main__":
    unittest.main()
