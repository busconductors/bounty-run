"""Tests for runner.dork_scan (Phase 12, Task 3). No network: requests.get,
time.sleep, utils.log/warn are patched throughout."""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from runner import dork_scan as ds

FIX = Path(__file__).resolve().parent / "fixtures" / "phase12"
MOJEEK = (FIX / "mojeek.html").read_text()
DDG = (FIX / "ddg.html").read_text()
DDG_BLOCKED = (FIX / "ddg_blocked.html").read_text()


class _Resp:
    def __init__(self, text, status_code=200):
        self.text = text
        self.status_code = status_code


def _router(mojeek=MOJEEK, ddg=DDG, mojeek_status=200, ddg_status=200):
    def fake_get(url, *args, **kwargs):
        if "mojeek.com" in url:
            return _Resp(mojeek, mojeek_status)
        if "duckduckgo.com" in url:
            return _Resp(ddg, ddg_status)
        raise AssertionError(f"unexpected URL {url}")
    return fake_get


class DorkScanBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.outdir = Path(self._tmp.name)
        self.log = mock.patch.object(ds.utils, "log").start()
        self.warn = mock.patch.object(ds.utils, "warn").start()
        self.sleep = mock.patch.object(ds.time, "sleep").start()
        self.addCleanup(mock.patch.stopall)
        self.addCleanup(self._tmp.cleanup)


class TestExtract(unittest.TestCase):
    def test_extract_mojeek_drops_engine_links(self):
        urls = ds._extract_mojeek(MOJEEK)
        self.assertIn("https://example.com/backup/db.sql", urls)
        self.assertIn("https://admin.example.com/wp-admin/", urls)
        self.assertIn("https://evilexample.com/backup.sql", urls)
        self.assertFalse(any("mojeek.com" in u for u in urls))
        self.assertEqual(len(urls), len(set(urls)))  # deduped
        self.assertEqual(len(urls), 3)

    def test_extract_ddg_decodes_uddg(self):
        urls = ds._extract_ddg(DDG)
        self.assertEqual(urls, ["https://example.com/backup/db.sql",
                                "https://www.example.com/blog/post"])

    def test_ddg_blocked(self):
        self.assertTrue(ds._ddg_blocked(DDG_BLOCKED))
        self.assertFalse(ds._ddg_blocked(DDG))
        # a genuine "no results" page is not a block
        self.assertFalse(ds._ddg_blocked("<div>No  results.</div>"))


class TestScopeAndClassify(unittest.TestCase):
    def test_scope_filter_rejects_lookalikes(self):
        t = "example.com"
        self.assertTrue(ds._in_scope("https://example.com/x", t))
        self.assertTrue(ds._in_scope("https://a.example.com/", t))
        self.assertTrue(ds._in_scope("https://A.Example.COM./x", t))
        self.assertFalse(ds._in_scope("https://evilexample.com/", t))
        self.assertFalse(ds._in_scope("https://example.com.attacker.net/", t))
        self.assertFalse(ds._in_scope("not a url", t))

    def test_classify(self):
        self.assertEqual(ds._classify("https://example.com/backup/db.sql"),
                         ("dork:exposed-file", "low"))
        self.assertEqual(ds._classify("https://example.com/site.tar.gz"),
                         ("dork:exposed-file", "low"))
        self.assertEqual(ds._classify("https://example.com/wp-admin/"),
                         ("dork:admin-panel", "info"))
        self.assertEqual(ds._classify("https://example.com/Login.php"),
                         ("dork:admin-panel", "info"))
        self.assertIsNone(ds._classify("https://example.com/blog/post"))
        self.assertIsNone(ds._classify("https://example.com/administrators-guide"))


class TestScan(DorkScanBase):
    def test_scan_end_to_end(self):
        with mock.patch.object(ds.requests, "get", side_effect=_router()):
            findings = ds.dork_scan("example.com", self.outdir)
        by_url = {f["url"]: f for f in findings}
        self.assertEqual(set(by_url), {"https://example.com/backup/db.sql",
                                       "https://admin.example.com/wp-admin"})
        sql = by_url["https://example.com/backup/db.sql"]
        self.assertEqual(sql["template"], "dork:exposed-file")
        self.assertEqual(sql["severity"], "low")
        self.assertEqual(sql["host"], "example.com")
        self.assertEqual(sql["name"], "Dork hit: /backup/db.sql (exposed-file)")
        adm = by_url["https://admin.example.com/wp-admin"]
        self.assertEqual(adm["template"], "dork:admin-panel")
        self.assertEqual(adm["severity"], "info")
        self.assertEqual(adm["host"], "admin.example.com")
        for f in findings:
            self.assertEqual(set(f), {"severity", "template", "name", "url",
                                      "host", "evidence"})
        listed = (self.outdir / "dork_urls.txt").read_text().split()
        self.assertEqual(sorted(listed), sorted([
            "https://example.com/backup/db.sql",
            "https://admin.example.com/wp-admin",
            "https://www.example.com/blog/post",
        ]))
        self.assertFalse(any("evilexample" in u for u in listed))
        log_lines = (self.outdir / "dork.txt").read_text().splitlines()
        self.assertEqual(len(log_lines), 8)
        cols = log_lines[0].split("\t")
        self.assertEqual(len(cols), 4)
        self.assertIn(cols[1], ("mojeek", "duckduckgo"))
        self.assertEqual(cols[2], "ok")
        self.warn.assert_not_called()

    def test_rate_limit_and_bounds(self):
        with mock.patch.object(ds.requests, "get", side_effect=_router()) as g:
            ds.dork_scan("example.com", self.outdir, max_queries=4)
        self.assertEqual(g.call_count, 8)
        for c in g.call_args_list:
            self.assertEqual(c.kwargs.get("timeout"), (5, 15))
            self.assertEqual(c.kwargs["headers"]["User-Agent"], ds.DORK_UA)
        self.assertEqual(self.sleep.call_count, 3)
        for c in self.sleep.call_args_list:
            self.assertEqual(c.args, (4,))
        queries = {c.kwargs["params"]["q"] for c in g.call_args_list}
        self.assertEqual(queries, {q.format(t="example.com")
                                   for q in ds.DORK_QUERIES[:4]})

    def test_all_blocked_warns(self):
        def fake_get(url, *a, **kw):
            if "mojeek.com" in url:
                raise ds.requests.ConnectionError("refused")
            return _Resp(DDG_BLOCKED)
        with mock.patch.object(ds.requests, "get", side_effect=fake_get):
            findings = ds.dork_scan("example.com", self.outdir)
        self.assertEqual(findings, [])
        msgs = " ".join(str(c.args[0]) for c in self.warn.call_args_list)
        self.assertIn("blocked", msgs)

    def test_non_200_counts_as_blocked(self):
        with mock.patch.object(ds.requests, "get",
                               side_effect=_router(mojeek_status=429,
                                                   ddg_status=403)):
            findings = ds.dork_scan("example.com", self.outdir, max_queries=1)
        self.assertEqual(findings, [])
        msgs = " ".join(str(c.args[0]) for c in self.warn.call_args_list)
        self.assertIn("blocked", msgs)

    def test_partial_block_warns_partial(self):
        with mock.patch.object(ds.requests, "get",
                               side_effect=_router(ddg=DDG_BLOCKED)):
            findings = ds.dork_scan("example.com", self.outdir, max_queries=1)
        self.assertTrue(findings)  # mojeek still produced results
        msgs = " ".join(str(c.args[0]) for c in self.warn.call_args_list)
        self.assertIn("partial", msgs)

    def test_dedupe_across_engines(self):
        with mock.patch.object(ds.requests, "get", side_effect=_router()):
            findings = ds.dork_scan("example.com", self.outdir, max_queries=1)
        sql = [f for f in findings
               if f["url"] == "https://example.com/backup/db.sql"]
        self.assertEqual(len(sql), 1)
        self.assertIn("mojeek", sql[0]["evidence"])
        self.assertIn("duckduckgo", sql[0]["evidence"])

    def test_missing_requests(self):
        with mock.patch.object(ds, "HAVE_REQUESTS", False):
            self.assertEqual(ds.dork_scan("example.com", self.outdir), [])
        self.warn.assert_called()


if __name__ == "__main__":
    unittest.main()
