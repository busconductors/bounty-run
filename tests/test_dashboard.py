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
        self.assertIn("No vulnerabilities found.", doc)
        self.assertIn("total findings", doc)
        self.assertNotIn('<article class="finding">', doc)

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

    def test_open_ports_nmap_card(self):
        findings = [
            {"severity": "info", "template": "nmap:80/tcp", "name": "Open port 80",
             "url": "", "host": "1.2.3.4", "evidence": "http"},
            {"severity": "info", "template": "nmap:443/tcp", "name": "Open port 443",
             "url": "", "host": "1.2.3.4", "evidence": "https"},
            {"severity": "high", "template": "sqli", "name": "SQLi",
             "url": "https://example.com/x", "host": "example.com", "evidence": ""},
        ]
        path = self._summary(findings=findings)
        doc = path.read_text()
        self.assertIn("open ports (nmap)", doc)
        # The card value is the count of nmap:* templated findings (2 here).
        self.assertIn(
            '<div class="card-label">open ports (nmap)</div>'
            '<div class="card-value">2</div>',
            doc,
        )

    def test_open_ports_nmap_card_zero_when_absent(self):
        path = self._summary(findings=[])
        doc = path.read_text()
        self.assertIn(
            '<div class="card-label">open ports (nmap)</div>'
            '<div class="card-value">0</div>',
            doc,
        )

    def test_finding_count_equals_dedupe(self):
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
        path = self._summary(findings=findings)
        doc = path.read_text()
        html_count = doc.count('<article class="finding">')
        self.assertEqual(html_count, len(report.dedupe(findings)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
