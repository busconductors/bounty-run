"""Unit tests for runner.stages security fixes.

Hermetic — no network, no external tools. Run with stdlib unittest:

    cd ~/tools/bounty-run && python3 -m unittest discover -s tests -v
    # or directly:
    python3 tests/test_stages.py -v
"""
import ipaddress
import shlex
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# Make the project root importable regardless of cwd / how the test is invoked.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner import stages  # noqa: E402
from runner import utils  # noqa: E402


class FakeResp:
    def __init__(self, headers, status_code=200, url="https://example.com"):
        self.headers = headers
        self.status_code = status_code
        self.url = url
        self.closed = False

    def close(self):
        self.closed = True


class IsGlobalTests(unittest.TestCase):
    def test_public_ip_is_global(self):
        self.assertTrue(stages._is_global("8.8.8.8"))
        self.assertTrue(stages._is_global("1.1.1.1"))

    def test_loopback_and_private_are_not_global(self):
        self.assertFalse(stages._is_global("127.0.0.1"))
        self.assertFalse(stages._is_global("10.0.0.1"))
        self.assertFalse(stages._is_global("192.168.1.1"))
        self.assertFalse(stages._is_global("172.16.0.1"))

    def test_link_local_metadata_is_not_global(self):
        self.assertFalse(stages._is_global("169.254.169.254"))

    def test_invalid_ip_returns_false(self):
        self.assertFalse(stages._is_global("not-an-ip"))
        self.assertFalse(stages._is_global(""))
        self.assertFalse(stages._is_global("999.999.999.999"))


class ProbeHostTests(unittest.TestCase):
    def test_non_global_ip_is_never_probed(self):
        with mock.patch.object(stages.socket, "gethostbyname", return_value="127.0.0.1"), \
             mock.patch.object(stages, "requests", create=True) as req:
            row = stages._probe_host("evil.internal", 5)
        self.assertEqual(row, {"host": "evil.internal", "url": "", "status": 0,
                               "server": "", "cloudflare": False})
        req.get.assert_not_called()

    def test_dns_failure_returns_safe_row(self):
        with mock.patch.object(stages.socket, "gethostbyname",
                               side_effect=Exception("nope")), \
             mock.patch.object(stages, "requests", create=True) as req:
            row = stages._probe_host("does-not-resolve", 5)
        self.assertEqual(row["status"], 0)
        req.get.assert_not_called()

    def test_global_ip_probes_with_no_redirects_and_streams(self):
        resp = FakeResp({"Server": "cloudflare", "cf-ray": "abc"})
        with mock.patch.object(stages.socket, "gethostbyname", return_value="8.8.8.8"), \
             mock.patch.object(stages, "requests", create=True) as req:
            req.get.return_value = resp
            row = stages._probe_host("example.com", 5)
        _, kwargs = req.get.call_args
        self.assertFalse(kwargs["allow_redirects"])
        self.assertTrue(kwargs["stream"])
        self.assertTrue(resp.closed)
        self.assertEqual(row["status"], 200)
        self.assertTrue(row["cloudflare"])


class VerifyOriginTests(unittest.TestCase):
    def test_curl_includes_insecure_flag(self):
        with mock.patch.object(utils, "run") as run:
            run.return_value = "200|1.2.3.4"
            stages._verify_origin("example.com", "1.2.3.4")
        cmd = run.call_args[0][0]
        self.assertIn("-k", cmd)
        self.assertIn("--resolve example.com:443:1.2.3.4", cmd)


class OriginHuntFilterTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.outdir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_private_and_loopback_ips_are_not_recorded(self):
        cf_ranges = [ipaddress.ip_network("1.2.3.0/24")]
        with mock.patch.object(stages, "_resolve", return_value="127.0.0.1"), \
             mock.patch.object(stages, "_cloudflare_ranges", return_value=list(cf_ranges)), \
             mock.patch.object(stages, "_mx_hosts", return_value=[]), \
             mock.patch.object(stages, "_verify_origin") as verify:
            rows = stages.origin_hunt("example.com", self.outdir, {})
        self.assertEqual(rows, [])
        verify.assert_not_called()

    def test_public_origin_is_recorded(self):
        cf_ranges = [ipaddress.ip_network("1.2.3.0/24")]
        with mock.patch.object(stages, "_resolve", return_value="5.6.7.8"), \
             mock.patch.object(stages, "_cloudflare_ranges", return_value=list(cf_ranges)), \
             mock.patch.object(stages, "_mx_hosts", return_value=[]), \
             mock.patch.object(stages, "_verify_origin",
                               return_value={"status": "200", "remote_ip": "5.6.7.8"}):
            rows = stages.origin_hunt("example.com", self.outdir, {})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ip"], "5.6.7.8")


class VulnScanTests(unittest.TestCase):
    def setUp(self):
        # A scratch dir whose path contains a space to exercise shell quoting.
        self._tmp = tempfile.mkdtemp(prefix="bounty run ")
        self.outdir = Path(self._tmp)
        self.addCleanup(lambda: __import__("shutil").rmtree(self._tmp))

    def _run_scan(self, live_rows):
        with mock.patch.object(utils, "have", return_value=True), \
             mock.patch.object(utils, "run", return_value="") as run, \
             mock.patch.object(utils, "log"), \
             mock.patch.object(stages, "_resolve",
                               side_effect=lambda h: {"example.com": "8.8.8.8",
                                                      "internal.example.com": "10.0.0.1"}.get(h, "")):
            stages.vuln_scan("example.com", self.outdir, live_rows)
        return run

    def test_paths_are_shell_quoted(self):
        run = self._run_scan([{"host": "example.com", "status": 200}])
        cmd = run.call_args[0][0]
        self.assertIn(shlex.quote(str(self.outdir / "nuclei.jsonl")), cmd)
        self.assertIn(shlex.quote(str(self.outdir / "nuclei_targets.txt")), cmd)

    def test_non_global_hosts_are_excluded(self):
        self._run_scan([
            {"host": "example.com", "status": 200},
            {"host": "internal.example.com", "status": 200},
        ])
        targets = (self.outdir / "nuclei_targets.txt").read_text().splitlines()
        self.assertEqual(targets, ["example.com"])

    def test_info_field_crash_shapes_do_not_raise(self):
        jl = self.outdir / "nuclei.jsonl"
        jl.write_text("\n".join([
            '{"info": "a string", "template-id": "t1", "matched-at": "https://x", "host": "example.com"}',
            '{"info": {"severity": null, "name": "n2"}, "template-id": "t2"}',
            '{"info": {"severity": ["high"], "name": "n3"}, "template-id": "t3"}',
            '{"info": {"severity": "HIGH", "name": "n4"}, "template-id": "t4"}',
            '{"info": {}}',
            'not-json',
            '["list", "not", "dict"]',
        ]))
        with mock.patch.object(utils, "have", return_value=True), \
             mock.patch.object(utils, "run", return_value=""), \
             mock.patch.object(utils, "log"), \
             mock.patch.object(stages, "_resolve", return_value="8.8.8.8"):
            findings = stages.vuln_scan("example.com", self.outdir,
                                        [{"host": "example.com", "status": 200}])

        sevs = sorted(f["severity"] for f in findings)
        self.assertEqual(sevs, ["['high']", "high", "unknown", "unknown", "unknown"])
        names = sorted(f["name"] for f in findings if f["name"])
        self.assertEqual(names, ["n2", "n3", "n4"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
