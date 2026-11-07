"""Unit tests for runner.metis_check + the Metis handoff in runner.report.

No network, no Metis framework — subprocess + shutil are monkeypatched. Run
with stdlib unittest:

    cd ~/tools/bounty-run && python3 -m unittest discover -s tests -v
    # or directly:
    python3 tests/test_metis_check.py -v
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# Make the project root importable regardless of cwd / how the test is invoked.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner import metis_check, report  # noqa: E402

SAMPLE_SHIM_JSON = json.dumps([
    {
        "host": "example.com",
        "module": "auxiliary/scanner/fortinet_cve_2025_64446",
        "name": "FortiWeb Authentication Bypass (CVE-2025-64446)",
        "severity": "critical",
        "detail": "",
    },
    {
        "host": "www.example.com",
        "module": "auxiliary/scanner/redis_cve_2022_0543",
        "name": "Redis Lua sandbox escape (CVE-2022-0543)",
        "severity": "high",
        "detail": "lua sandbox reachable",
    },
])


def _run_completed(stdout, returncode=0, stderr=""):
    return subprocess.CompletedProcess(
        args=["metis-autocheck"], returncode=returncode,
        stdout=stdout, stderr=stderr,
    )


class MetisCheckTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.outdir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def _patch(self, which: str | None = "/fake/metis-autocheck", run=None):
        which_p = mock.patch.object(metis_check.shutil, "which", return_value=which)
        run_p = mock.patch.object(metis_check.subprocess, "run", run)
        which_p.start()
        run_p.start()
        self.addCleanup(which_p.stop)
        self.addCleanup(run_p.stop)

    def test_parses_sample_shim_json_into_findings(self):
        self._patch(run=lambda *a, **k: _run_completed(SAMPLE_SHIM_JSON))
        findings = metis_check.metis_check(
            "example.com", self.outdir, ["example.com", "www.example.com"])
        self.assertEqual(len(findings), 2)

    def test_carries_name_and_severity_through(self):
        self._patch(run=lambda *a, **k: _run_completed(SAMPLE_SHIM_JSON))
        findings = metis_check.metis_check(
            "example.com", self.outdir, ["example.com", "www.example.com"])
        self.assertEqual(findings[0], {
            "severity": "critical",
            "template": "metis:auxiliary/scanner/fortinet_cve_2025_64446",
            "name": "FortiWeb Authentication Bypass (CVE-2025-64446)",
            "url": "https://example.com",
            "host": "example.com",
        })
        self.assertEqual(findings[1]["severity"], "high")
        self.assertEqual(findings[1]["name"], "Redis Lua sandbox escape (CVE-2022-0543)")

    def test_writes_target_list_file_for_shim(self):
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return _run_completed("[]")

        self._patch(run=fake_run)
        metis_check.metis_check(
            "example.com", self.outdir, ["a.example.com", "b.example.com"])
        # The shim is invoked with file:<hosts file> and the file holds the hosts.
        self.assertEqual(captured["cmd"][0], "/fake/metis-autocheck")
        spec = captured["cmd"][1]
        self.assertTrue(spec.startswith("file:"))
        hosts_file = Path(spec[len("file:"):])
        self.assertTrue(hosts_file.exists())
        self.assertEqual(hosts_file.read_text().splitlines(),
                         ["a.example.com", "b.example.com"])

    def test_warns_and_skips_when_shim_missing(self):
        with mock.patch.object(metis_check.utils, "warn") as warn:
            self._patch(which=None)
            findings = metis_check.metis_check(
                "example.com", self.outdir, ["example.com"])
        self.assertEqual(findings, [])
        self.assertGreaterEqual(warn.call_count, 1)

    def test_warns_and_skips_on_nonzero_exit(self):
        with mock.patch.object(metis_check.utils, "warn") as warn:
            self._patch(run=lambda *a, **k: _run_completed(
                "", returncode=3, stderr="metis-autocheck: cannot boot Metis"))
            findings = metis_check.metis_check(
                "example.com", self.outdir, ["example.com"])
        self.assertEqual(findings, [])
        self.assertGreaterEqual(warn.call_count, 1)

    def test_warns_and_skips_on_unparseable_json(self):
        with mock.patch.object(metis_check.utils, "warn") as warn:
            self._patch(run=lambda *a, **k: _run_completed("not json at all"))
            findings = metis_check.metis_check(
                "example.com", self.outdir, ["example.com"])
        self.assertEqual(findings, [])
        self.assertGreaterEqual(warn.call_count, 1)

    def test_skips_when_no_hosts(self):
        self._patch(run=lambda *a, **k: _run_completed(SAMPLE_SHIM_JSON))
        findings = metis_check.metis_check("example.com", self.outdir, [])
        self.assertEqual(findings, [])

    def test_ignores_hits_missing_host_or_module(self):
        malformed = json.dumps([
            {"host": "example.com", "module": "", "name": "x", "severity": "high"},
            {"host": "", "module": "auxiliary/scanner/x", "name": "x", "severity": "high"},
            {"host": "ok.example.com", "module": "auxiliary/scanner/ok",
             "name": "OK", "severity": "high"},
        ])
        self._patch(run=lambda *a, **k: _run_completed(malformed))
        findings = metis_check.metis_check(
            "example.com", self.outdir, ["example.com"])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["host"], "ok.example.com")

    def test_severity_defaults_to_unknown_when_absent(self):
        data = json.dumps([
            {"host": "h.example.com", "module": "auxiliary/scanner/no_sev",
             "name": "No Sev", "severity": "", "detail": ""},
        ])
        self._patch(run=lambda *a, **k: _run_completed(data))
        findings = metis_check.metis_check(
            "example.com", self.outdir, ["h.example.com"])
        self.assertEqual(findings[0]["severity"], "unknown")


class AuxExploitMapTest(unittest.TestCase):
    def test_known_aux_maps_to_exploit(self):
        self.assertEqual(
            metis_check.AUX_EXPLOIT_MAP["auxiliary/scanner/fortinet_cve_2025_64446"],
            "exploits/linux/http/fortiweb_auth_bypass_cve_2025_64446",
        )

    def test_unmapped_cve_has_no_exploit(self):
        self.assertNotIn(
            "auxiliary/scanner/fortios_path_traversal_cve_2018_13379",
            metis_check.AUX_EXPLOIT_MAP,
        )


def finding(template="metis:auxiliary/scanner/fortinet_cve_2025_64446",
            host="example.com", severity="critical",
            name="FortiWeb Authentication Bypass (CVE-2025-64446)",
            url="https://example.com", evidence=None):
    d = {"severity": severity, "template": template, "name": name,
         "url": url, "host": host}
    if evidence is not None:
        d["evidence"] = evidence
    return d


class ReportMetisHandoffTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.outdir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def _render(self, findings):
        report.write_findings_report(self.outdir, "example.com", findings, [])
        return (self.outdir / "FINDINGS.md").read_text()

    def test_renders_escalation_block(self):
        md = self._render([finding()])
        self.assertIn("### [CRITICAL] FortiWeb Authentication Bypass (CVE-2025-64446)", md)
        self.assertIn("    metis> use auxiliary/scanner/fortinet_cve_2025_64446", md)
        self.assertIn("    metis> set RHOSTS example.com", md)
        self.assertIn("    metis> check", md)

    def test_renders_exploit_comment_when_mapped(self):
        md = self._render([finding()])
        self.assertIn(
            "    # exploit: exploits/linux/http/fortiweb_auth_bypass_cve_2025_64446", md)

    def test_no_exploit_comment_when_unmapped(self):
        md = self._render([
            finding(template="metis:auxiliary/scanner/fortios_path_traversal_cve_2018_13379",
                    name="FortiOS Path Traversal (CVE-2018-13379)"),
        ])
        self.assertIn("    metis> use auxiliary/scanner/fortios_path_traversal_cve_2018_13379", md)
        self.assertNotIn("# exploit:", md)

    def test_non_metis_finding_has_no_escalation_block(self):
        md = self._render([
            finding(template="sqlmap-sqli", name="SQL injection", severity="high"),
        ])
        self.assertNotIn("metis> use", md)
        self.assertNotIn("Confirm (manual", md)

    def test_evidence_field_rendered_when_present(self):
        md = self._render([
            finding(template="spyhunt-ssti", name="SSTI", severity="critical",
                    evidence="{{7*7}} reflected as 49"),
        ])
        self.assertIn("- Evidence: {{7*7}} reflected as 49", md)

    def test_no_evidence_line_when_absent(self):
        md = self._render([finding(template="spyhunt-ssti", name="SSTI")])
        self.assertNotIn("- Evidence:", md)


if __name__ == "__main__":
    unittest.main(verbosity=2)
