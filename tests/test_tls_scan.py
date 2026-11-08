"""Tests for runner/tls_scan.py (Phase 12, Feature 4).

The fixture is a trimmed sslyze 6.3 `--json_out` capture of example.com:443,
edited to trip every check (TLS 1.0 + 3DES accepted, Heartbleed, weak ROBOT
oracle, hostname mismatch, untrusted chain, leaf expiring 2026-11-20).
"""
import copy
import json
import re
import shutil
import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from runner import tls_scan

FIXTURE = Path(__file__).parent / "fixtures" / "phase12" / "sslyze.json"
NOW = datetime(2026, 11, 8, tzinfo=timezone.utc)


def _doc() -> dict:
    return json.loads(FIXTURE.read_text())


def _json_out(cmd: str) -> Path:
    m = re.search(r"--json_out=(\S+)", cmd)
    return Path(m.group(1).strip("'\""))


class TestFindingsFromSslyze(unittest.TestCase):
    def test_severity_map(self):
        out = tls_scan._findings_from_sslyze(_doc(), "example.com", NOW)
        self.assertEqual(
            {f["template"]: f["severity"] for f in out},
            {"tls:heartbleed": "critical", "tls:robot": "medium",
             "tls:tlsv1-enabled": "low", "tls:weak-cipher": "medium",
             "tls:cert-hostname-mismatch": "medium", "tls:cert-untrusted": "low",
             "tls:cert-expiring-soon": "info"})
        for f in out:
            self.assertEqual(set(f), {"severity", "template", "name", "url",
                                      "host", "evidence"})
            self.assertEqual(f["host"], "example.com")

    def test_expired_beats_expiring(self):
        later = datetime(2026, 12, 1, tzinfo=timezone.utc)
        templates = {f["template"] for f in
                     tls_scan._findings_from_sslyze(_doc(), "example.com", later)}
        self.assertIn("tls:cert-expired", templates)
        self.assertNotIn("tls:cert-expiring-soon", templates)

    def test_far_expiry_no_cert_date_finding(self):
        early = datetime(2026, 1, 1, tzinfo=timezone.utc)
        templates = {f["template"] for f in
                     tls_scan._findings_from_sslyze(_doc(), "example.com", early)}
        self.assertNotIn("tls:cert-expired", templates)
        self.assertNotIn("tls:cert-expiring-soon", templates)

    def test_strong_oracle_high(self):
        doc = _doc()
        doc["server_scan_results"][0]["scan_result"]["robot"]["result"][
            "robot_result"] = "VULNERABLE_STRONG_ORACLE"
        sev = {f["template"]: f["severity"] for f in
               tls_scan._findings_from_sslyze(doc, "example.com", NOW)}
        self.assertEqual(sev["tls:robot"], "high")

    def test_weak_cipher_evidence(self):
        out = tls_scan._findings_from_sslyze(_doc(), "example.com", NOW)
        weak = [f for f in out if f["template"] == "tls:weak-cipher"]
        self.assertEqual(len(weak), 1)
        self.assertIn("3DES", weak[0]["evidence"])
        self.assertLessEqual(len(weak[0]["evidence"]), 300)

    def test_weak_cipher_evidence_truncated(self):
        doc = _doc()
        r = doc["server_scan_results"][0]["scan_result"]["tls_1_2_cipher_suites"]["result"]
        for i in range(60):
            r["accepted_cipher_suites"].append(
                {"cipher_suite": {"name": f"TLS_RSA_EXPORT_WITH_RC4_40_MD5_{i}"}})
        weak = [f for f in tls_scan._findings_from_sslyze(doc, "example.com", NOW)
                if f["template"] == "tls:weak-cipher"]
        self.assertLessEqual(len(weak[0]["evidence"]), 300)

    def test_unique_templates_per_host(self):
        out = tls_scan._findings_from_sslyze(_doc(), "example.com", NOW)
        keys = [(f["template"], f["host"], f["url"]) for f in out]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertTrue(all(f["url"] == "https://example.com:443" for f in out))

    def test_hostname_match_via_wildcard_san(self):
        doc = _doc()
        leaf = (doc["server_scan_results"][0]["scan_result"]["certificate_info"]
                ["result"]["certificate_deployments"][0]["received_certificate_chain"][0])
        leaf["subject_alternative_name"]["dns_names"] = ["*.example.com"]
        templates = {f["template"] for f in
                     tls_scan._findings_from_sslyze(doc, "www.example.com", NOW)}
        self.assertNotIn("tls:cert-hostname-mismatch", templates)
        # A wildcard covers exactly one label: the apex does not match.
        templates = {f["template"] for f in
                     tls_scan._findings_from_sslyze(doc, "example.com", NOW)}
        self.assertIn("tls:cert-hostname-mismatch", templates)

    def test_connectivity_error_yields_nothing(self):
        doc = _doc()
        srv = doc["server_scan_results"][0]
        srv["scan_status"] = "ERROR_NO_CONNECTIVITY"
        srv["connectivity_status"] = "ERROR"
        srv["scan_result"] = None
        self.assertEqual(tls_scan._findings_from_sslyze(doc, "example.com", NOW), [])
        # Non-COMPLETED status alone, even with a stale scan_result, gives nothing.
        doc2 = _doc()
        doc2["server_scan_results"][0]["scan_status"] = "ERROR_NO_CONNECTIVITY"
        self.assertEqual(tls_scan._findings_from_sslyze(doc2, "example.com", NOW), [])

    def test_not_completed_command_ignored(self):
        doc = _doc()
        hb = doc["server_scan_results"][0]["scan_result"]["heartbleed"]
        hb["status"] = "ERROR"
        templates = {f["template"] for f in
                     tls_scan._findings_from_sslyze(doc, "example.com", NOW)}
        self.assertNotIn("tls:heartbleed", templates)

    def test_garbage_doc(self):
        for bad in ({}, {"server_scan_results": None}, {"server_scan_results": [None]},
                    {"server_scan_results": [{"scan_status": "COMPLETED",
                                              "scan_result": {"robot": "x"}}]},
                    [], "nope", None):
            self.assertEqual(tls_scan._findings_from_sslyze(bad, "example.com", NOW), [])


class TestTlsScan(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.outdir = Path(self.tmp.name)
        patches = [
            mock.patch.object(tls_scan.utils, "have", return_value=True),
            mock.patch.object(tls_scan.utils, "log"),
            mock.patch.object(tls_scan, "_resolve", return_value="93.184.215.14"),
            mock.patch.object(tls_scan, "_is_global", return_value=True),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.warn = mock.patch.object(tls_scan.utils, "warn").start()
        self.addCleanup(mock.patch.stopall)
        self.addCleanup(self.tmp.cleanup)
        self.calls = []

    def _fake_run(self, skip_host=None):
        def run(cmd, outfile=None, timeout=180):
            self.calls.append((cmd, timeout))
            if skip_host and f"{skip_host}:443" in cmd:
                return ""
            dst = _json_out(cmd)
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(FIXTURE, dst)
            return ""
        return run

    def test_scan_per_host_bounded(self):
        hosts = ["example.com", "a.example.com", "b.example.com"]
        with mock.patch.object(tls_scan.utils, "run", side_effect=self._fake_run()):
            out = tls_scan.tls_scan("example.com", self.outdir, hosts)
        self.assertEqual(len(self.calls), 3)
        for (cmd, timeout), h in zip(sorted(self.calls), sorted(hosts)):
            self.assertEqual(timeout, 180)
            self.assertIn(f"{h}:443", cmd)
            self.assertIn("--json_out=", cmd)
        self.assertEqual({f["host"] for f in out}, set(hosts))
        self.assertTrue((self.outdir / "sslyze" / "a.example.com.json").exists())
        lines = (self.outdir / "tls_scan.txt").read_text().splitlines()
        self.assertIn("example.com\ttls:heartbleed\tcritical", lines)

    def test_missing_json_for_one_host(self):
        hosts = ["example.com", "a.example.com", "b.example.com"]
        with mock.patch.object(tls_scan.utils, "run",
                               side_effect=self._fake_run(skip_host="a.example.com")):
            out = tls_scan.tls_scan("example.com", self.outdir, hosts)
        self.assertEqual({f["host"] for f in out}, {"example.com", "b.example.com"})

    def test_run_exception_for_one_host(self):
        inner = self._fake_run()

        def run(cmd, outfile=None, timeout=180):
            if "b.example.com:443" in cmd:
                raise RuntimeError("boom")
            return inner(cmd, outfile, timeout)
        with mock.patch.object(tls_scan.utils, "run", side_effect=run):
            out = tls_scan.tls_scan("example.com", self.outdir,
                                    ["example.com", "b.example.com"])
        self.assertEqual({f["host"] for f in out}, {"example.com"})

    def test_target_added_and_cap(self):
        hosts = [f"h{i}.example.com" for i in range(30)]
        with mock.patch.object(tls_scan.utils, "run", side_effect=self._fake_run()):
            tls_scan.tls_scan("example.com", self.outdir, hosts, max_hosts=5)
        self.assertEqual(len(self.calls), 5)
        # target is prepended before the cap, so it is always scanned
        self.assertTrue(any(c.endswith(" example.com:443") for c, _ in self.calls))

    def test_missing_tool(self):
        with mock.patch.object(tls_scan.utils, "have", return_value=False), \
                mock.patch.object(tls_scan.utils, "run") as run:
            self.assertEqual(tls_scan.tls_scan("example.com", self.outdir,
                                               ["example.com"]), [])
        run.assert_not_called()
        self.warn.assert_called()

    def test_ssrf_skip_private(self):
        def is_global(ip):
            return ip != "10.0.0.5"

        def resolve(h):
            return "10.0.0.5" if h == "internal.example.com" else "93.184.215.14"
        with mock.patch.object(tls_scan, "_is_global", side_effect=is_global), \
                mock.patch.object(tls_scan, "_resolve", side_effect=resolve), \
                mock.patch.object(tls_scan.utils, "run", side_effect=self._fake_run()):
            tls_scan.tls_scan("example.com", self.outdir,
                              ["example.com", "internal.example.com"])
        self.assertEqual(len(self.calls), 1)
        self.assertNotIn("internal.example.com", self.calls[0][0])

    def test_no_routable_hosts(self):
        with mock.patch.object(tls_scan, "_is_global", return_value=False), \
                mock.patch.object(tls_scan.utils, "run") as run:
            self.assertEqual(tls_scan.tls_scan("example.com", self.outdir,
                                               ["example.com"]), [])
        run.assert_not_called()
        self.warn.assert_called()

    def test_garbage_json_skipped(self):
        def run(cmd, outfile=None, timeout=180):
            dst = _json_out(cmd)
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text("{not json")
            return ""
        with mock.patch.object(tls_scan.utils, "run", side_effect=run):
            self.assertEqual(tls_scan.tls_scan("example.com", self.outdir,
                                               ["example.com"]), [])
        self.assertTrue((self.outdir / "tls_scan.txt").exists())

    def test_invalid_hostname_skipped(self):
        with mock.patch.object(tls_scan.utils, "run", side_effect=self._fake_run()):
            tls_scan.tls_scan("example.com", self.outdir,
                              ["x.example.com;id", "../etc", "EXAMPLE.com."])
        cmds = [c for c, _ in self.calls]
        self.assertEqual(len(cmds), 1, cmds)  # only the (normalised) target
        self.assertTrue(cmds[0].endswith(" example.com:443"))


if __name__ == "__main__":
    unittest.main()
