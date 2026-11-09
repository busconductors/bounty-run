"""Unit tests for runner.dashboard (self-contained HTML findings dashboard).

Stdlib unittest only.  Every test repoints ``tracker.DEFAULT_DB`` at a throwaway
temp file and generates into a throwaway outputs dir, so the real tracker DB and
``outputs/dashboard.html`` are never touched:

    cd ~/tools/bounty-run && python3 -m unittest discover -s tests -v
    # or directly:
    python3 tests/test_dashboard.py -v
"""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner import report, tracker  # noqa: E402
from runner import dashboard as dashboard_mod  # noqa: E402
from runner.dashboard import generate, write_run_summary  # noqa: E402


class DashboardTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_db = tracker.DEFAULT_DB
        tracker.DEFAULT_DB = Path(self._tmp.name) / "tracker.db"
        self.outputs = Path(self._tmp.name) / "outputs"
        self.addCleanup(self._tmp.cleanup)
        self.addCleanup(setattr, tracker, "DEFAULT_DB", self._orig_db)

    def _html(self):
        out_path = generate(self.outputs)
        return out_path.read_text()


class TestGenerate(DashboardTestCase):
    def test_writes_html_with_seeded_finding_title(self):
        tracker.add_target("example.com", program="Acme", scope="*.example.com")
        tracker.add_finding(
            "example.com", "SQLi in search", "high",
            "https://example.com/search?q=x", template="sqli",
        )
        html_doc = self._html()
        self.assertIn("<html", html_doc)
        self.assertIn("SQLi in search", html_doc)
        self.assertIn("example.com", html_doc)

    def test_empty_db_renders_placeholder_without_crash(self):
        html_doc = self._html()
        self.assertIn("<html", html_doc)
        self.assertIn("no data yet", html_doc)


class TestEscaping(DashboardTestCase):
    def test_script_tag_title_is_escaped(self):
        payload = "<script>alert(1)</script>"
        tracker.add_finding("evil.com", payload, "high", "https://evil.com/x")
        html_doc = self._html()
        self.assertNotIn("<script>alert(1)", html_doc)
        self.assertNotIn("<script>alert(1)</script>", html_doc)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html_doc)


class TestNoExternalReferences(DashboardTestCase):
    def test_no_src_or_href_attributes(self):
        tracker.add_finding("example.com", "XSS", "medium", "https://example.com/a")
        html_doc = self._html()
        self.assertNotIn("src=", html_doc)
        self.assertNotIn("href=", html_doc)


class TestRefactorSurface(DashboardTestCase):
    def test_esc_is_public_alias(self):
        self.assertIs(dashboard_mod.esc, dashboard_mod._esc)
        self.assertEqual(dashboard_mod.esc("<x>"), "&lt;x&gt;")

    def test_stylesheet_is_module_constant(self):
        self.assertIsInstance(dashboard_mod.STYLESHEET, str)
        self.assertIn("--bg: #0d1117", dashboard_mod.STYLESHEET)
        self.assertIn("</style>", dashboard_mod.STYLESHEET)


class TestWriteRunSummary(DashboardTestCase):
    """Tests for runner.dashboard.write_run_summary (self-contained summary.html)."""

    def _summary(self, target="example.com", findings=None, content=None,
                 origins=None, run_time="2026-11-07 10:00:00", subdomains=3,
                 live_hosts=2, cloudflare=False):
        out = Path(self._tmp.name) / "summary_out"
        return write_run_summary(
            out, target, findings or [], content or [], origins or [],
            run_time=run_time, subdomains=subdomains, live_hosts=live_hosts,
            cloudflare=cloudflare,
        )

    def test_writes_summary_with_seeded_finding(self):
        finding = {
            "severity": "high", "template": "sqli", "name": "SQLi in search",
            "url": "https://example.com/search?q=x", "host": "example.com",
            "evidence": "payload",
        }
        path = self._summary(findings=[finding])
        self.assertTrue(path.exists())
        doc = path.read_text()
        self.assertIn("<html", doc)
        self.assertIn("SQLi in search", doc)
        self.assertIn("https://example.com/search?q=x", doc)
        self.assertIn("example.com", doc)
        self.assertIn("payload", doc)

    def test_script_alert_title_is_escaped(self):
        payload = "<script>alert(1)</script>"
        finding = {
            "severity": "high", "template": payload, "name": payload,
            "url": "", "host": "evil.com", "evidence": "",
        }
        path = self._summary(findings=[finding])
        doc = path.read_text()
        self.assertNotIn("<script>alert(1)", doc)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", doc)

    def test_no_src_or_href_attributes(self):
        finding = {
            "severity": "medium", "template": "xss", "name": "XSS",
            "url": "https://example.com/a", "host": "example.com", "evidence": "",
        }
        path = self._summary(findings=[finding])
        doc = path.read_text()
        self.assertNotIn("src=", doc)
        self.assertNotIn("href=", doc)
        self.assertNotIn("<script", doc)

    def test_empty_findings_state(self):
        path = self._summary(findings=[], subdomains=0, live_hosts=0,
                             cloudflare=False)
        doc = path.read_text()
        self.assertIn('class="verdict"', doc)
        self.assertIn("No candidates", doc)
        self.assertNotIn('<article class="finding">', doc)

    def test_verdict_line_rendered_for_candidate(self):
        finding = {"severity": "high", "template": "sqli", "name": "SQLi",
                   "url": "https://example.com/x", "host": "example.com",
                   "evidence": ""}
        doc = self._summary(findings=[finding]).read_text()
        self.assertIn('class="verdict"', doc)
        self.assertIn("1 candidate", doc)

    def test_two_tier_structure_present(self):
        finding = {"severity": "high", "template": "sqli", "name": "SQLi",
                   "url": "https://example.com/x", "host": "example.com",
                   "evidence": ""}
        doc = self._summary(findings=[finding]).read_text()
        self.assertIn('class="candidates"', doc)
        self.assertIn('tier-divider', doc)
        self.assertIn('class="surface"', doc)

    def test_candidate_rendered_noise_demoted(self):
        candidate = {"severity": "high", "template": "sqli", "name": "RealVuln",
                     "url": "https://example.com/x", "host": "example.com",
                     "evidence": ""}
        noise = {"severity": "low", "template": "tls:weak", "name": "WeakCipher",
                 "url": "", "host": "example.com", "evidence": ""}
        body = self._summary(findings=[candidate, noise]).read_text().split("</style>")[1]
        self.assertIn('class="candidates"', body)
        self.assertIn("RealVuln", body)
        self.assertIn('class="noise"', body)
        self.assertIn("WeakCipher", body)
        # Candidate sits in the act-now tier; noise is demoted below the divider.
        candidates_block = body.split('tier-divider')[0]
        self.assertIn("RealVuln", candidates_block)
        self.assertNotIn("WeakCipher", candidates_block)

    def test_info_nuclei_in_collapsed_details(self):
        info = {"severity": "info", "template": "some-cve", "name": "InfoOnly",
                "url": "", "host": "example.com", "evidence": ""}
        body = self._summary(findings=[info]).read_text().split("</style>")[1]
        self.assertIn('info-findings', body)
        details_block = body.split('info-findings')[1]
        self.assertIn("InfoOnly", details_block)

    def test_origins_and_content_sections(self):
        origins = [{"ip": "1.2.3.4", "status": 200,
                    "sources": ["www.example.com"]}]
        content = ["/admin", "/login"]
        path = self._summary(origins=origins, content=content)
        doc = path.read_text()
        self.assertIn("Origin candidates", doc)
        self.assertIn("1.2.3.4", doc)
        self.assertIn("Discovered content", doc)
        self.assertIn("/admin", doc)
        self.assertIn("/login", doc)

        # Sections omitted when empty.
        path2 = self._summary(origins=[], content=[])
        doc2 = path2.read_text()
        self.assertNotIn("Origin candidates", doc2)
        self.assertNotIn("Discovered content", doc2)

    def test_open_ports_shown_in_surface(self):
        findings = [
            {"severity": "info", "template": "nmap:80/tcp", "name": "Open port 80",
             "url": "", "host": "1.2.3.4", "evidence": "http"},
            {"severity": "info", "template": "nmap:443/tcp", "name": "Open port 443",
             "url": "", "host": "1.2.3.4", "evidence": "https"},
            {"severity": "high", "template": "sqli", "name": "SQLi",
             "url": "https://example.com/x", "host": "example.com", "evidence": ""},
        ]
        doc = self._summary(findings=findings).read_text()
        surface = doc.split('class="surface"')[1]
        self.assertIn("open ports", surface.lower())
        self.assertIn("2", surface)

    def test_candidate_card_count_matches_candidates(self):
        findings = [
            {"severity": "high", "template": "sqli", "name": "A",
             "url": "https://example.com/x", "host": "example.com",
             "evidence": ""},
            {"severity": "high", "template": "sqli", "name": "A dup",
             "url": "https://example.com/x", "host": "example.com",
             "evidence": ""},
            {"severity": "low", "template": "xss", "name": "B",
             "url": "https://example.com/y", "host": "example.com",
             "evidence": ""},
        ]
        body = self._summary(findings=findings).read_text().split("</style>")[1]
        unique = report.dedupe(findings)
        want = sum(1 for f in unique if dashboard_mod._is_candidate(f))
        candidates_block = body.split('tier-divider')[0]
        self.assertEqual(
            candidates_block.count('<article class="finding">'), want)


class TestIsCandidate(unittest.TestCase):
    """The triage split rule: candidate = crit/high/medium OR panel: (any sev)."""

    def _f(self, severity, template):
        return {"severity": severity, "template": template, "name": "x",
                "url": "", "host": "", "evidence": ""}

    def test_panel_at_info_is_candidate(self):
        self.assertTrue(dashboard_mod._is_candidate(self._f("info", "panel:admin")))

    def test_plain_info_nuclei_is_not_candidate(self):
        self.assertFalse(dashboard_mod._is_candidate(self._f("info", "some-cve")))

    def test_medium_high_critical_are_candidates(self):
        for sev in ("critical", "high", "medium"):
            self.assertTrue(dashboard_mod._is_candidate(self._f(sev, "some-cve")), sev)

    def test_low_non_panel_is_not_candidate(self):
        self.assertFalse(dashboard_mod._is_candidate(self._f("low", "xss")))

    def test_recon_prefixes_are_not_candidates(self):
        for tmpl in ("tls:weak", "nikto:1", "dork:gh", "api-endpoint",
                     "tech-detect:nginx", "nmap:80/tcp", "waf:cf"):
            self.assertFalse(
                dashboard_mod._is_candidate(self._f("info", tmpl)), tmpl)


class TestOrderCandidates(unittest.TestCase):
    """panel: floats to the top, then critical -> high -> medium."""

    def _f(self, severity, template, name):
        return {"severity": severity, "template": template, "name": name,
                "url": "", "host": "", "evidence": ""}

    def test_panel_sorts_ahead_of_higher_severity_non_panel(self):
        high = self._f("high", "sqli", "HIGH")
        panel = self._f("info", "panel:admin", "PANEL")
        ordered = dashboard_mod._order_candidates([high, panel])
        self.assertEqual(ordered[0]["name"], "PANEL")

    def test_non_panel_sorted_by_severity(self):
        medium = self._f("medium", "a", "MED")
        critical = self._f("critical", "b", "CRIT")
        ordered = dashboard_mod._order_candidates([medium, critical])
        self.assertEqual([f["name"] for f in ordered], ["CRIT", "MED"])


class TestVerdictLine(unittest.TestCase):
    """The prose assertion at the top of the report."""

    def _f(self, severity, template="x"):
        return {"severity": severity, "template": template, "name": "n",
                "url": "", "host": "", "evidence": ""}

    def test_counts_candidates_and_top_severity(self):
        line = dashboard_mod._verdict_line(
            [self._f("high"), self._f("medium")], origins=[],
            cloudflare=False, subdomains=10)
        self.assertIn("candidate", line.lower())
        self.assertIn("high", line.lower())

    def test_mentions_exposed_panel(self):
        line = dashboard_mod._verdict_line(
            [self._f("info", "panel:admin")], origins=[],
            cloudflare=False, subdomains=10)
        self.assertIn("panel", line.lower())

    def test_origin_behind_cloudflare_always_surfaces_with_ip(self):
        line = dashboard_mod._verdict_line(
            [], origins=[{"ip": "1.2.3.4", "status": 200, "sources": []}],
            cloudflare=True, subdomains=10)
        self.assertIn("cloudflare", line.lower())
        self.assertIn("1.2.3.4", line)

    def test_quiet_run_fallback(self):
        line = dashboard_mod._verdict_line(
            [], origins=[], cloudflare=False, subdomains=48)
        self.assertIn("no candidates", line.lower())
        self.assertIn("48", line)


if __name__ == "__main__":
    unittest.main(verbosity=2)
