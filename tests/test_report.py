"""Unit tests for runner.report (dedupe + write_findings_report).

Pure functions only — no network, no external tools. Run with stdlib unittest:

    cd ~/tools/bounty-run && python3 -m unittest discover -s tests -v
    # or directly:
    python3 tests/test_report.py -v
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

# Make the project root importable regardless of cwd / how the test is invoked.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner import report  # noqa: E402


def finding(template="tmpl", host="example.com", severity="info",
            name=None, url="https://example.com/x"):
    return {
        "severity": severity,
        "template": template,
        "name": name or f"Name for {template}",
        "url": url,
        "host": host,
    }


class TestDedupe(unittest.TestCase):
    def test_empty_input_returns_empty_list(self):
        self.assertEqual(report.dedupe([]), [])

    def test_collapses_duplicate_template_host_pairs(self):
        findings = [
            finding(template="t1", host="a.com", severity="high"),
            finding(template="t1", host="a.com", severity="low"),   # dup
            finding(template="t2", host="a.com", severity="medium"),
            finding(template="t1", host="b.com", severity="critical"),  # same template, diff host
        ]
        out = report.dedupe(findings)
        self.assertEqual(len(out), 3)
        keys = [(f["template"], f["host"]) for f in out]
        self.assertEqual(keys, [("t1", "a.com"), ("t2", "a.com"), ("t1", "b.com")])

    def test_keeps_first_occurrence_of_duplicate(self):
        findings = [
            finding(template="t1", host="a.com", severity="critical", url="https://a.com/first"),
            finding(template="t1", host="a.com", severity="info", url="https://a.com/second"),
        ]
        out = report.dedupe(findings)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["url"], "https://a.com/first")
        self.assertEqual(out[0]["severity"], "critical")

    def test_preserves_input_order_of_first_seen(self):
        findings = [
            finding(template="t3", host="a.com"),
            finding(template="t1", host="a.com"),
            finding(template="t2", host="a.com"),
            finding(template="t3", host="a.com"),  # dup of first
            finding(template="t1", host="a.com"),  # dup
        ]
        out = report.dedupe(findings)
        self.assertEqual([f["template"] for f in out], ["t3", "t1", "t2"])

    def test_returns_new_list_not_mutating_input(self):
        findings = [finding(template="t1", host="a.com")]
        report.dedupe(findings)
        self.assertEqual(len(findings), 1)


class TestSeverityOrdering(unittest.TestCase):
    def test_findings_json_is_severity_ordered(self):
        order = ["critical", "high", "medium", "low", "info", "unknown"]
        findings = [
            finding("t-unknown", "a.com", "unknown"),
            finding("t-low", "a.com", "low"),
            finding("t-high", "a.com", "high"),
            finding("t-critical", "a.com", "critical"),
            finding("t-medium", "a.com", "medium"),
            finding("t-info", "a.com", "info"),
        ]
        with tempfile.TemporaryDirectory() as d:
            n = report.write_findings_report(Path(d), "example.com", findings, [])
            self.assertEqual(n, 6)
            data = json.loads((Path(d) / "findings.json").read_text())
            self.assertEqual([f["severity"] for f in data], order)

    def test_unknown_severity_key_sorts_last(self):
        # A severity absent from SEVERITY_ORDER maps to sort key 9 (after "unknown"=5).
        findings = [
            finding("t-bogus", "a.com", "bogus-severity"),
            finding("t-critical", "a.com", "critical"),
            finding("t-unknown", "a.com", "unknown"),
        ]
        with tempfile.TemporaryDirectory() as d:
            report.write_findings_report(Path(d), "example.com", findings, [])
            data = json.loads((Path(d) / "findings.json").read_text())
            self.assertEqual(
                [f["severity"] for f in data],
                ["critical", "unknown", "bogus-severity"],
            )

    def test_sort_is_stable_within_same_severity(self):
        findings = [
            finding("t-a", "a.com", "high"),
            finding("t-b", "a.com", "high"),
            finding("t-c", "a.com", "high"),
        ]
        with tempfile.TemporaryDirectory() as d:
            report.write_findings_report(Path(d), "example.com", findings, [])
            data = json.loads((Path(d) / "findings.json").read_text())
            self.assertEqual([f["template"] for f in data], ["t-a", "t-b", "t-c"])


class TestWriteFindingsReport(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.outdir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_writes_both_files_and_returns_deduped_count(self):
        findings = [
            finding("t1", "a.com", "high"),
            finding("t1", "a.com", "high"),  # dup
            finding("t2", "a.com", "medium"),
        ]
        n = report.write_findings_report(self.outdir, "example.com", findings, [])
        self.assertEqual(n, 2)
        self.assertTrue((self.outdir / "findings.json").exists())
        self.assertTrue((self.outdir / "FINDINGS.md").exists())

    def test_findings_json_content_is_deduped_sorted(self):
        findings = [
            finding("t1", "a.com", "low"),
            finding("t2", "a.com", "critical"),
            finding("t1", "a.com", "critical"),  # dup of t1 (same host)
        ]
        report.write_findings_report(self.outdir, "example.com", findings, [])
        data = json.loads((self.outdir / "findings.json").read_text())
        self.assertEqual(len(data), 2)
        self.assertEqual(
            [(f["template"], f["severity"]) for f in data],
            [("t2", "critical"), ("t1", "low")],
        )

    def test_findings_md_header_and_severity_counts(self):
        findings = [
            finding("t1", "a.com", "high"),
            finding("t2", "a.com", "high"),
            finding("t3", "a.com", "critical"),
            finding("t4", "a.com", "info"),
        ]
        report.write_findings_report(self.outdir, "example.com", findings, [])
        md = (self.outdir / "FINDINGS.md").read_text()
        self.assertIn("# Findings — example.com", md)
        self.assertIn("## Severity", md)
        self.assertIn("- **critical**: 1", md)
        self.assertIn("- **high**: 2", md)
        self.assertIn("- **info**: 1", md)
        self.assertNotIn("**medium**", md)

    def test_findings_md_vulnerability_entries(self):
        findings = [finding("tmpl-1", "a.com", "high", name="Detected Thing", url="https://a.com/x")]
        report.write_findings_report(self.outdir, "example.com", findings, [])
        md = (self.outdir / "FINDINGS.md").read_text()
        self.assertIn("## Vulnerabilities", md)
        self.assertIn("### [HIGH] Detected Thing", md)
        self.assertIn("- URL: https://a.com/x", md)
        self.assertIn("- Template: `tmpl-1`", md)

    def test_findings_md_uses_template_when_name_missing(self):
        findings = [finding("tmpl-only", "a.com", "low", name=None)]
        report.write_findings_report(self.outdir, "example.com", findings, [])
        md = (self.outdir / "FINDINGS.md").read_text()
        self.assertIn("### [LOW] tmpl-only", md)

    def test_empty_findings_md_shows_no_vulns_message(self):
        n = report.write_findings_report(self.outdir, "example.com", [], [])
        self.assertEqual(n, 0)
        md = (self.outdir / "FINDINGS.md").read_text()
        self.assertIn("# Findings — example.com", md)
        self.assertIn("_No vulnerabilities found by nuclei._", md)
        self.assertNotIn("## Severity", md)
        data = json.loads((self.outdir / "findings.json").read_text())
        self.assertEqual(data, [])

    def test_content_paths_appear_sorted(self):
        report.write_findings_report(
            self.outdir, "example.com", [], ["/b", "/a", "/c"]
        )
        md = (self.outdir / "FINDINGS.md").read_text()
        self.assertIn("## Discovered content", md)
        # paths are sorted, so /a must come before /b before /c
        self.assertLess(md.index("- `/a`"), md.index("- `/b`"))
        self.assertLess(md.index("- `/b`"), md.index("- `/c`"))

    def test_no_content_section_when_content_empty(self):
        report.write_findings_report(self.outdir, "example.com", [], [])
        md = (self.outdir / "FINDINGS.md").read_text()
        self.assertNotIn("## Discovered content", md)

    def test_creates_outdir_if_missing(self):
        nested = self.outdir / "a" / "b"
        report.write_findings_report(nested, "example.com", [], [])
        self.assertTrue((nested / "findings.json").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
