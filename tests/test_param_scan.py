"""Unit tests for runner.param_scan (Wayback CDX param discovery + sqlmap).

No network, no external tools — utils.run / utils.have are monkeypatched. Run with
stdlib unittest:

    cd ~/tools/bounty-run && python3 -m unittest discover -s tests -v
    # or directly:
    python3 tests/test_param_scan.py -v
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# Make the project root importable regardless of cwd / how the test is invoked.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner import utils  # noqa: E402
from runner.param_scan import param_scan  # noqa: E402


def make_cdx(urls):
    """Build the CDX JSON body: a header row followed by one row per URL."""
    return json.dumps([["original"]] + [[u] for u in urls])


class ParamScanTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.outdir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.sqlmap_calls = []

    def _patch(self, cdx_urls, sqlmap_out="", have_sqlmap=True):
        """Monkeypatch utils.run / utils.have for the duration of a test."""

        def fake_run(cmd, outfile=None, timeout=180):
            if "sqlmap" in cmd:
                self.sqlmap_calls.append(cmd)
                return sqlmap_out
            return make_cdx(cdx_urls)

        run_p = mock.patch.object(utils, "run", fake_run)
        have_p = mock.patch.object(utils, "have", return_value=have_sqlmap)
        run_p.start()
        have_p.start()
        self.addCleanup(run_p.stop)
        self.addCleanup(have_p.stop)

    def test_skips_header_row_and_non_query_urls(self):
        self._patch(cdx_urls=[
            "http://example.com/",
            "http://example.com/about",
            "http://example.com/x?a=1",
        ])
        param_scan("example.com", self.outdir)
        urls = (self.outdir / "param_urls.txt").read_text().splitlines()
        self.assertEqual(urls, ["http://example.com/x?a="])

    def test_param_value_stripping_dedupes_endpoints(self):
        self._patch(cdx_urls=[
            "http://example.com/search?a=1",
            "http://example.com/search?a=2",
            "http://example.com/search?a=3&b=x",
        ])
        param_scan("example.com", self.outdir)
        urls = (self.outdir / "param_urls.txt").read_text().splitlines()
        self.assertEqual(urls, [
            "http://example.com/search?a=",
            "http://example.com/search?a=&b=",
        ])
        # a=1 and a=2 collapsed into one sqlmap run; a=3&b=x is a second run.
        self.assertEqual(len(self.sqlmap_calls), 2)

    def test_clean_empty_when_sqlmap_absent(self):
        self._patch(cdx_urls=["http://example.com/x?a=1"], have_sqlmap=False)
        findings = param_scan("example.com", self.outdir)
        self.assertEqual(findings, [])
        self.assertEqual(self.sqlmap_calls, [])

    def test_caps_urls_at_max_urls(self):
        cdx_urls = [f"http://example.com/p?x{i}=1" for i in range(10)]
        self._patch(cdx_urls=cdx_urls)
        param_scan("example.com", self.outdir, max_urls=3)
        lines = (self.outdir / "param_urls.txt").read_text().splitlines()
        self.assertEqual(len(lines), 3)
        self.assertEqual(len(self.sqlmap_calls), 3)

    def test_injectable_stdout_produces_finding(self):
        self._patch(cdx_urls=["http://example.com/id?a=1"],
                    sqlmap_out="Parameter 'a' is vulnerable")
        findings = param_scan("example.com", self.outdir)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0], {
            "severity": "high",
            "template": "sqlmap-sqli",
            "name": "SQL injection",
            "url": "http://example.com/id?a=",
            "host": "example.com",
        })

    def test_injectable_detection_is_case_insensitive(self):
        self._patch(cdx_urls=["http://example.com/x?a=1"],
                    sqlmap_out="PARAMETER 'a' IS VULNERABLE")
        findings = param_scan("example.com", self.outdir)
        self.assertEqual(len(findings), 1)

    def test_non_injectable_stdout_produces_no_finding(self):
        self._patch(cdx_urls=["http://example.com/x?a=1"],
                    sqlmap_out="no injection found")
        findings = param_scan("example.com", self.outdir)
        self.assertEqual(findings, [])

    def test_negative_injectable_message_produces_no_finding(self):
        # "injectable" also appears in sqlmap's NEGATIVE messages, which must
        # NOT be treated as a finding (regression guard for the false-positive bug).
        self._patch(cdx_urls=["http://example.com/x?a=1"],
                    sqlmap_out="Parameter 'a' does not seem to be injectable")
        findings = param_scan("example.com", self.outdir)
        self.assertEqual(findings, [])

    def test_out_of_scope_urls_are_filtered(self):
        self._patch(cdx_urls=[
            "http://example.com/x?a=1",        # in scope (apex)
            "http://sub.example.com/x?a=1",    # in scope (subdomain)
            "http://evil.com/x?a=1",           # out of scope
            "https://not-example.com/x?a=1",   # out of scope (suffix lookalike)
            "ftp://example.com/x?a=1",         # out of scope (non-http scheme)
        ])
        param_scan("example.com", self.outdir)
        urls = (self.outdir / "param_urls.txt").read_text().splitlines()
        self.assertEqual(urls, [
            "http://example.com/x?a=",
            "http://sub.example.com/x?a=",
        ])
        self.assertEqual(len(self.sqlmap_calls), 2)

    def test_writes_both_report_files(self):
        self._patch(cdx_urls=["http://example.com/x?a=1"],
                    sqlmap_out="is vulnerable")
        param_scan("example.com", self.outdir)
        self.assertTrue((self.outdir / "param_urls.txt").exists())
        self.assertTrue((self.outdir / "sqlmap_report.txt").exists())
        report = (self.outdir / "sqlmap_report.txt").read_text()
        self.assertIn("is vulnerable", report)
        self.assertIn("http://example.com/x?a=", report)

    def test_junk_js_fragment_params_are_filtered(self):
        self._patch(cdx_urls=[
            "http://example.com/?0:this.cssPosition=",
            "http://example.com/?a.offsetWidth:a.offsetHeight,e=",
            "http://example.com/?obj.src:oldList=",
            "http://example.com/?d!=",
            "http://example.com/?idcat=",              # sane -> kept
            "http://example.com/?client=&lang=",        # sane -> kept
        ])
        param_scan("example.com", self.outdir)
        urls = (self.outdir / "param_urls.txt").read_text().splitlines()
        self.assertEqual(urls, [
            "http://example.com/?idcat=",
            "http://example.com/?client=&lang=",
        ])
        self.assertEqual(len(self.sqlmap_calls), 2)

    def test_static_asset_urls_are_filtered(self):
        # Wayback CDX floods discovery with static assets (WordPress ?ver=
        # cache-busters). Those have no SQL backend, so they must not reach sqlmap.
        self._patch(cdx_urls=[
            "http://example.com/wp-content/theme/style.css?ver=1",
            "http://example.com/wp-content/theme/app.js?ver=2",
            "http://example.com/wp-content/img/logo.png?ver=3",
            "http://example.com/font.woff2?ver=4",
            "http://example.com/page.php?id=1",          # dynamic -> kept
            "http://example.com/admin/ajax.php?action=x",  # dynamic -> kept
        ])
        param_scan("example.com", self.outdir)
        urls = (self.outdir / "param_urls.txt").read_text().splitlines()
        self.assertEqual(urls, [
            "http://example.com/page.php?id=",
            "http://example.com/admin/ajax.php?action=",
        ])
        self.assertEqual(len(self.sqlmap_calls), 2)

    def test_empty_cdx_returns_empty_without_writing(self):
        self._patch(cdx_urls=[], sqlmap_out="is vulnerable")
        findings = param_scan("example.com", self.outdir)
        self.assertEqual(findings, [])
        self.assertFalse((self.outdir / "param_urls.txt").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
