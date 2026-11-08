"""Tests for runner/api_endpoints.py (Phase 11)."""
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from runner import api_endpoints


def _jsonl(urls):
    """Build katana-style JSONL output (one request.endpoint per line)."""
    return "\n".join(json.dumps({"request": {"endpoint": u}}) for u in urls)


# A mix of API-like and static URLs katana might surface.
CRAWLED = [
    "https://example.com/api/users",        # keep: /api/
    "https://example.com/graphql",          # keep: /graphql
    "https://example.com/v1/orders",        # keep: /v1/
    "https://example.com/data.json",        # keep: .json
    "https://example.com/xhr/fetch",        # keep: xhr
    "https://example.com/app.js",           # drop: static .js
    "https://example.com/styles.css",       # drop: static .css
    "https://example.com/logo.png",         # drop: static .png
    "https://example.com/about",            # drop: no keyword
]


class TestUrlFilter(unittest.TestCase):
    def test_api_urls_kept(self):
        for u in CRAWLED[:5]:
            self.assertTrue(api_endpoints._is_api_url(u), u)

    def test_static_and_plain_dropped(self):
        for u in CRAWLED[5:]:
            self.assertFalse(api_endpoints._is_api_url(u), u)

    def test_static_ext_beats_keyword(self):
        # path ends in .js -> dropped even though "api" substring is present.
        self.assertFalse(api_endpoints._is_api_url("https://example.com/api/widget.js"))


class TestScan(unittest.TestCase):
    def _run(self, outdir):
        with mock.patch.object(api_endpoints.utils, "have", return_value=True), \
             mock.patch.object(api_endpoints, "_resolve", return_value="93.184.216.34"), \
             mock.patch.object(api_endpoints, "_is_global", return_value=True), \
             mock.patch.object(api_endpoints.utils, "log"), \
             mock.patch.object(api_endpoints.utils, "warn"), \
             mock.patch.object(api_endpoints.utils, "run",
                               return_value=_jsonl(CRAWLED)):
            return api_endpoints.api_endpoints_scan(
                "example.com", outdir, hosts=["example.com"])

    def test_filters_and_finding_shape(self):
        with TemporaryDirectory() as d:
            outdir = Path(d)
            findings = self._run(outdir)

        # 5 API-like URLs survive.
        self.assertEqual(len(findings), 5)
        f = {x["url"]: x for x in findings}["https://example.com/api/users"]
        self.assertEqual(f["severity"], "info")
        self.assertEqual(f["template"], "api-endpoint")
        self.assertEqual(f["name"], "API endpoint: /api/users")
        self.assertEqual(f["host"], "example.com")

    def test_writes_txt_artifact(self):
        with TemporaryDirectory() as d:
            outdir = Path(d)
            self._run(outdir)
            txt = (outdir / "api_endpoints.txt").read_text()
        self.assertIn("https://example.com/api/users", txt)
        self.assertNotIn("app.js", txt)

    def test_dedupes_repeated_urls(self):
        with TemporaryDirectory() as d:
            outdir = Path(d)
            with mock.patch.object(api_endpoints.utils, "have", return_value=True), \
                 mock.patch.object(api_endpoints, "_resolve", return_value="93.184.216.34"), \
                 mock.patch.object(api_endpoints, "_is_global", return_value=True), \
                 mock.patch.object(api_endpoints.utils, "log"), \
                 mock.patch.object(api_endpoints.utils, "warn"), \
                 mock.patch.object(api_endpoints.utils, "run",
                                   return_value=_jsonl(["https://example.com/api/x",
                                                        "https://example.com/api/x"])):
                findings = api_endpoints.api_endpoints_scan(
                    "example.com", outdir, hosts=["example.com"])
        self.assertEqual(len(findings), 1)


class TestGuards(unittest.TestCase):
    def test_missing_katana_returns_empty(self):
        with mock.patch.object(api_endpoints.utils, "have", return_value=False), \
             mock.patch.object(api_endpoints.utils, "warn"), \
             mock.patch.object(api_endpoints.utils, "log"):
            self.assertEqual(
                api_endpoints.api_endpoints_scan("example.com", Path("/tmp"),
                                                 hosts=["example.com"]), [])

    def test_no_hosts_returns_empty(self):
        with mock.patch.object(api_endpoints.utils, "have", return_value=True), \
             mock.patch.object(api_endpoints, "_resolve", return_value="10.0.0.1"), \
             mock.patch.object(api_endpoints, "_is_global", return_value=False), \
             mock.patch.object(api_endpoints.utils, "warn"), \
             mock.patch.object(api_endpoints.utils, "log"):
            self.assertEqual(
                api_endpoints.api_endpoints_scan("example.com", Path("/tmp"),
                                                 hosts=["internal"]), [])


if __name__ == "__main__":
    unittest.main()
