"""Tests for runner/nikto_scan.py (Phase 12, Task 5)."""
import json
import re
import shlex
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from runner import nikto_scan, report

FIXTURE = Path(__file__).parent / "fixtures" / "phase12" / "nikto.json"
FIXTURE_RAW = FIXTURE.read_text()


def _out_path(cmd: str) -> Path:
    """Pull the `-o <path>` argument out of a nikto command line."""
    argv = shlex.split(cmd)
    return Path(argv[argv.index("-o") + 1])


def _host_of(cmd: str) -> str:
    argv = shlex.split(cmd)
    return argv[argv.index("-h") + 1].split("://", 1)[1]


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.outdir = Path(self.tmp.name)
        self.calls = []
        patches = [
            mock.patch.object(nikto_scan.utils, "have", return_value=True),
            mock.patch.object(nikto_scan.utils, "log"),
            mock.patch.object(nikto_scan.utils, "warn"),
            mock.patch.object(nikto_scan, "_resolve", return_value="93.184.216.34"),
            mock.patch.object(nikto_scan, "_is_global", return_value=True),
        ]
        self.mocks = [p.start() for p in patches]
        self.have, _, self.warn, self.resolve, self.is_global = self.mocks
        self.run = mock.patch.object(nikto_scan.utils, "run",
                                     side_effect=self._fake_run).start()
        self.addCleanup(mock.patch.stopall)
        self.addCleanup(self.tmp.cleanup)
        self.payloads = {}  # host -> raw JSON text; default fixture

    def _fake_run(self, cmd, timeout=None, **kw):
        self.calls.append((cmd, timeout))
        path = _out_path(cmd)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.payloads.get(_host_of(cmd), FIXTURE_RAW))
        return ""


class TestClassify(unittest.TestCase):
    def test_classify_table(self):
        items = nikto_scan._parse_nikto_json(FIXTURE_RAW)
        got = [nikto_scan._classify(i["msg"]) for i in items]
        self.assertEqual(got, [
            ("outdated-software", "low"),
            ("http-methods", "low"),
            ("directory-indexing", "low"),
            ("default-file", "low"),
            ("missing-header", "info"),
            ("misconfiguration", "info"),
        ])

    def test_classify_real_nikto26_header_msg(self):
        # nikto 2.6.1 phrasing captured from a live run
        self.assertEqual(
            nikto_scan._classify("Suggested security header missing: referrer-policy."),
            ("missing-header", "info"))

    def test_http_method_without_risky_verb_is_misconfig(self):
        self.assertEqual(
            nikto_scan._classify("HTTP method ('Allow' Header): 'GET' is allowed."),
            ("misconfiguration", "info"))


class TestParse(unittest.TestCase):
    def test_parse_list(self):
        self.assertEqual(len(nikto_scan._parse_nikto_json(FIXTURE_RAW)), 6)

    def test_single_object_json(self):
        obj = json.loads(FIXTURE_RAW)[0]
        items = nikto_scan._parse_nikto_json(json.dumps(obj))
        self.assertEqual(len(items), 6)
        self.assertEqual(items[0]["id"], "600050")

    def test_garbage_returns_empty(self):
        for raw in ("", "not json", '[{"host": "a', "42", "null",
                    '[{"vulnerabilities": "nope"}]', '["x", 1]'):
            self.assertEqual(nikto_scan._parse_nikto_json(raw), [], raw)


class TestScan(_Base):
    def test_template_has_id(self):
        findings = nikto_scan.nikto_scan("example.com", self.outdir, ["example.com"])
        self.assertEqual(len(findings), 6)
        for f in findings:
            self.assertRegex(f["template"], r"^nikto:[a-z-]+:\S+$")
        on_root = [f for f in findings if f["url"] == "https://example.com/"]
        self.assertGreaterEqual(len({f["template"] for f in on_root}), 2)
        self.assertEqual(len(report.dedupe(findings)), len(findings))
        self.assertIn("nikto:outdated-software:600050",
                      {f["template"] for f in findings})

    def test_reused_id_does_not_collide(self):
        # nikto 2.6 reports every missing header as id 013587 on "/".
        vulns = [{"id": "013587", "method": "GET", "url": "/",
                  "msg": f"Suggested security header missing: {h}."}
                 for h in ("content-security-policy", "referrer-policy",
                           "permissions-policy")]
        self.payloads["example.com"] = json.dumps(
            [{"host": "example.com", "vulnerabilities": vulns}])
        findings = nikto_scan.nikto_scan("example.com", self.outdir, ["example.com"])
        self.assertEqual(len(findings), 3)
        self.assertEqual(len(report.dedupe(findings)), 3)
        for f in findings:
            self.assertRegex(f["template"], r"^nikto:missing-header:013587\S*$")

    def test_finding_shape_and_name(self):
        findings = nikto_scan.nikto_scan("example.com", self.outdir, ["example.com"])
        for f in findings:
            self.assertEqual(set(f), {"severity", "template", "name", "url",
                                      "host", "evidence"})
            self.assertEqual(f["host"], "example.com")
            self.assertTrue(f["name"].startswith("Nikto: "))
            self.assertLessEqual(len(f["name"]), len("Nikto: ") + 120)
            self.assertEqual(f["name"], "Nikto: " + f["evidence"][:120])

    def test_url_joined(self):
        findings = nikto_scan.nikto_scan("example.com", self.outdir, ["example.com"])
        urls = {f["url"] for f in findings}
        self.assertIn("https://example.com/phpinfo.php", urls)
        self.assertIn("https://example.com/icons/", urls)

    def test_truncated_json_is_skipped(self):
        self.payloads["a.example.com"] = '[{"host": "a'
        findings = nikto_scan.nikto_scan(
            "example.com", self.outdir, ["a.example.com", "b.example.com"])
        hosts = {f["host"] for f in findings}
        self.assertIn("b.example.com", hosts)
        self.assertNotIn("a.example.com", hosts)
        self.assertEqual(sum(f["host"] == "b.example.com" for f in findings), 6)

    def test_missing_output_file_is_skipped(self):
        self.run.side_effect = lambda cmd, timeout=None, **kw: ""
        self.assertEqual(
            nikto_scan.nikto_scan("example.com", self.outdir, ["example.com"]), [])

    def test_command_bounded(self):
        nikto_scan.nikto_scan("example.com", self.outdir, ["example.com"])
        self.assertEqual(len(self.calls), 1)
        cmd, timeout = self.calls[0]
        self.assertIn("-maxtime 300s", cmd)
        self.assertIn("-timeout 10", cmd)
        self.assertIn("-nointeractive", cmd)
        self.assertIn("-ask no", cmd)
        self.assertIn("-Format json", cmd)
        self.assertIn("-h https://example.com", cmd)
        self.assertEqual(timeout, 360)
        self.assertIsInstance(timeout, int)

    def test_artifact_written(self):
        nikto_scan.nikto_scan("example.com", self.outdir, ["example.com"])
        art = self.outdir / "nikto" / "example.com.json"
        self.assertTrue(art.exists())
        self.assertEqual(_out_path(self.calls[0][0]), art)

    def test_missing_tool(self):
        self.have.return_value = False
        self.assertEqual(
            nikto_scan.nikto_scan("example.com", self.outdir, ["example.com"]), [])
        self.run.assert_not_called()
        self.warn.assert_called()

    def test_ssrf_skip_private(self):
        ips = {"example.com": "93.184.216.34", "internal.example.com": "10.0.0.5"}
        self.resolve.side_effect = lambda h: ips.get(h, "")
        self.is_global.side_effect = lambda ip: bool(ip) and not ip.startswith("10.")
        findings = nikto_scan.nikto_scan(
            "example.com", self.outdir, ["internal.example.com", "example.com"])
        scanned = {_host_of(c) for c, _ in self.calls}
        self.assertEqual(scanned, {"example.com"})
        self.assertNotIn("internal.example.com", {f["host"] for f in findings})

    def test_no_routable_hosts(self):
        self.is_global.return_value = False
        self.assertEqual(
            nikto_scan.nikto_scan("example.com", self.outdir, ["example.com"]), [])
        self.run.assert_not_called()
        self.warn.assert_called()

    def test_host_cap(self):
        hosts = [f"h{i}.example.com" for i in range(30)]
        nikto_scan.nikto_scan("example.com", self.outdir, hosts, max_hosts=20)
        self.assertEqual(len(self.calls), 20)

    def test_hosts_normalised_and_deduped(self):
        nikto_scan.nikto_scan("example.com", self.outdir,
                              ["Example.COM.", "example.com", " example.com "])
        self.assertEqual([_host_of(c) for c, _ in self.calls], ["example.com"])

    def test_run_exception_never_raises(self):
        def boom(cmd, timeout=None, **kw):
            if "a.example.com" in cmd:
                raise RuntimeError("boom")
            return self._fake_run(cmd, timeout=timeout)
        self.run.side_effect = boom
        findings = nikto_scan.nikto_scan(
            "example.com", self.outdir, ["a.example.com", "b.example.com"])
        hosts = {f["host"] for f in findings}
        self.assertIn("b.example.com", hosts)
        self.assertNotIn("a.example.com", hosts)

    def test_target_included(self):
        nikto_scan.nikto_scan("example.com", self.outdir, ["a.example.com"])
        self.assertEqual({_host_of(c) for c, _ in self.calls},
                         {"example.com", "a.example.com"})


if __name__ == "__main__":
    unittest.main()
