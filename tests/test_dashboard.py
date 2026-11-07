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

from runner import tracker  # noqa: E402
from runner.dashboard import generate  # noqa: E402


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
