"""Tests for runner/waf_scan.py (Phase 12)."""
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from runner import waf_scan

FIXTURE = Path(__file__).parent / "fixtures" / "phase12" / "wafw00f.json"


def _fake_run_writing(raw: str, calls: list):
    def fake_run(cmd, timeout=180, **kw):
        calls.append((cmd, timeout))
        # Write the fixture where the command's `-o <path>` points.
        parts = cmd.split()
        out = parts[parts.index("-o") + 1].strip("'\"")
        Path(out).write_text(raw)
        return ""
    return fake_run


class TestHelpers(unittest.TestCase):
    def test_slug(self):
        self.assertEqual(waf_scan._slug("AWS Elastic Load Balancer"),
                         "aws-elastic-load-balancer")
        self.assertEqual(waf_scan._slug("Cloudflare"), "cloudflare")
        self.assertEqual(waf_scan._slug("Generic"), "generic")

    def test_parse_garbage(self):
        self.assertEqual(waf_scan._parse_wafw00f_json("nope"), [])
        self.assertEqual(waf_scan._parse_wafw00f_json(""), [])
        self.assertEqual(waf_scan._parse_wafw00f_json('{"a": 1}'), [])

    def test_parse_fixture(self):
        rows = waf_scan._parse_wafw00f_json(FIXTURE.read_text())
        self.assertEqual(len(rows), 4)


class TestScan(unittest.TestCase):
    def _scan(self, outdir, raw, hosts=None, is_global=None, max_hosts=20,
              have=True, calls=None):
        calls = [] if calls is None else calls
        is_global = is_global or (lambda ip: True)
        with mock.patch.object(waf_scan.utils, "have", return_value=have), \
             mock.patch.object(waf_scan, "_resolve", side_effect=lambda h: h), \
             mock.patch.object(waf_scan, "_is_global", side_effect=is_global), \
             mock.patch.object(waf_scan.utils, "log"), \
             mock.patch.object(waf_scan.utils, "warn") as warn, \
             mock.patch.object(waf_scan.utils, "run",
                               side_effect=_fake_run_writing(raw, calls)):
            findings = waf_scan.waf_scan(
                "example.com", outdir,
                hosts if hosts is not None else ["www.cloudflare.com"],
                max_hosts=max_hosts)
        return findings, warn, calls

    def test_detected_only(self):
        with TemporaryDirectory() as d:
            findings, _, _ = self._scan(Path(d), FIXTURE.read_text())
        self.assertEqual({f["template"] for f in findings},
                         {"waf:cloudflare", "waf:generic"})
        self.assertEqual(len(findings), 2)
        for f in findings:
            self.assertEqual(f["severity"], "info")
            self.assertEqual(f["host"], "www.cloudflare.com")
            self.assertEqual(f["url"], "https://www.cloudflare.com")
            self.assertEqual(set(f), {"severity", "template", "name", "url",
                                      "host", "evidence"})
        cf = next(f for f in findings if f["template"] == "waf:cloudflare")
        self.assertEqual(cf["name"], "WAF detected: Cloudflare (Cloudflare Inc.)")
        self.assertEqual(cf["evidence"], "Cloudflare Inc.")

    def test_duplicate_rows_collapse(self):
        row = {"url": "https://a.example.com", "detected": True,
               "firewall": "Cloudflare", "manufacturer": "Cloudflare Inc."}
        # Same WAF twice for one host, incl. an http/https redirect variant.
        row_http = dict(row, url="http://a.example.com")
        raw = json.dumps([row, row, row_http])
        with TemporaryDirectory() as d:
            findings, _, _ = self._scan(Path(d), raw)
        self.assertEqual(len(findings), 1)

    def test_ssrf_and_cap(self):
        with TemporaryDirectory() as d:
            outdir = Path(d)
            self._scan(outdir, "[]",
                       hosts=["internal.example.com", "pub.example.com"],
                       is_global=lambda ip: ip != "internal.example.com")
            lines = (outdir / "wafw00f_targets.txt").read_text().split()
            self.assertNotIn("https://internal.example.com", lines)
            self.assertIn("https://pub.example.com", lines)
            # target was absent from hosts -> included.
            self.assertIn("https://example.com", lines)

        with TemporaryDirectory() as d:
            outdir = Path(d)
            hosts = [f"h{i}.example.com" for i in range(30)]
            self._scan(outdir, "[]", hosts=hosts, max_hosts=5)
            lines = (outdir / "wafw00f_targets.txt").read_text().splitlines()
            self.assertEqual(len(lines), 5)

    def test_no_routable_hosts(self):
        with TemporaryDirectory() as d:
            findings, warn, calls = self._scan(Path(d), "[]",
                                               is_global=lambda ip: False)
        self.assertEqual(findings, [])
        warn.assert_called()
        self.assertEqual(calls, [])

    def test_missing_tool(self):
        with TemporaryDirectory() as d:
            findings, warn, calls = self._scan(Path(d), "[]", have=False)
        self.assertEqual(findings, [])
        warn.assert_called()
        self.assertEqual(calls, [])

    def test_bad_output_warns(self):
        with TemporaryDirectory() as d:
            findings, warn, _ = self._scan(Path(d), "not json{")
        self.assertEqual(findings, [])
        warn.assert_called()

    def test_command_bounded(self):
        calls = []
        with TemporaryDirectory() as d:
            self._scan(Path(d), "[]", calls=calls)
        self.assertEqual(len(calls), 1)
        cmd, timeout = calls[0]
        self.assertIn("-T 10", cmd)
        self.assertIn("-f json", cmd)
        self.assertIn("-a", cmd.split())
        self.assertIn("--no-colors", cmd)
        self.assertEqual(timeout, 300)


if __name__ == "__main__":
    unittest.main()
