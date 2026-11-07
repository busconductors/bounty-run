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
            name: str | None = "__default__", url="https://example.com/x"):
    d = {
        "severity": severity,
        "template": template,
        "url": url,
        "host": host,
    }
    if name == "__default__":
        d["name"] = f"Name for {template}"
    elif name is not None:
        d["name"] = name
    return d


class TestDedupe(unittest.TestCase):
    def test_empty_input_returns_empty_list(self):
        self.assertEqual(report.dedupe([]), [])

    def test_collapses_duplicate_template_host_url_triples(self):
        findings = [
            finding(template="t1", host="a.com", severity="high", url="https://a.com/one"),
            finding(template="t1", host="a.com", severity="low", url="https://a.com/two"),   # same template+host, diff url -> kept
            finding(template="t1", host="a.com", severity="medium", url="https://a.com/one"),  # identical triple -> dropped
            finding(template="t2", host="a.com", severity="medium", url="https://a.com/one"),
            finding(template="t1", host="b.com", severity="critical", url="https://a.com/one"),  # same template, diff host
        ]
        out = report.dedupe(findings)
        self.assertEqual(len(out), 4)
        keys = [(f["template"], f["host"], f["url"]) for f in out]
        self.assertEqual(keys, [
            ("t1", "a.com", "https://a.com/one"),
            ("t1", "a.com", "https://a.com/two"),
            ("t2", "a.com", "https://a.com/one"),
            ("t1", "b.com", "https://a.com/one"),
        ])

    def test_keeps_first_occurrence_of_duplicate(self):
        findings = [
            finding(template="t1", host="a.com", severity="critical", url="https://a.com/first"),
            finding(template="t1", host="a.com", severity="info", url="https://a.com/first"),  # identical triple -> dup
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
        self.assertIn("_No vulnerabilities found._", md)
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

    def test_origins_section_appears_when_origins_passed(self):
        origins = [
            {"ip": "203.0.113.10", "status": "200", "sources": ["apply.example.com", "library.example.com"]},
            {"ip": "203.0.113.11", "status": "404", "sources": ["payments.example.com"]},
        ]
        report.write_findings_report(self.outdir, "example.com", [], [], origins=origins)
        md = (self.outdir / "FINDINGS.md").read_text()
        self.assertIn("## Origin candidates (behind Cloudflare)", md)
        self.assertIn("- `203.0.113.10` — HTTP 200 — via apply.example.com, library.example.com", md)
        self.assertIn("- `203.0.113.11` — HTTP 404 — via payments.example.com", md)

    def test_no_origins_section_when_origins_empty(self):
        report.write_findings_report(self.outdir, "example.com", [], [], origins=[])
        md = (self.outdir / "FINDINGS.md").read_text()
        self.assertNotIn("## Origin candidates", md)

    def test_writes_into_preexisting_nested_outdir(self):
        # write_findings_report assumes outdir already exists (the CLI's main()
        # creates it via outdir.mkdir). It does NOT auto-create directories.
        nested = self.outdir / "a" / "b"
        nested.mkdir(parents=True)
        report.write_findings_report(nested, "example.com", [], [])
        self.assertTrue((nested / "findings.json").exists())


class TestBuildMetrics(unittest.TestCase):
    def _rows(self):
        return [
            {"host": "example.com", "status": 200, "cloudflare": True},
            {"host": "a.example.com", "status": 200, "cloudflare": False},
            {"host": "b.example.com", "status": 0, "cloudflare": False},
            {"host": "c.example.com", "status": 200, "cloudflare": True},
        ]

    def _cf(self):
        return {"target": "example.com", "cloudflare": True, "evidence": []}

    def _findings(self):
        return [
            finding("tmpl-crit", "h", "critical"),
            finding("tmpl-high", "h", "high"),
            finding("secret-exposure", "h", "high"),
            finding("sqlmap-sqli", "h", "high"),
            finding("metis:foo/bar", "h", "medium"),
            finding("tmpl-crit", "h", "critical"),  # dup of first (same template+host+url)
        ]

    def test_tallies_match_dedupe_and_split_scanners(self):
        m = dict(report.build_metrics(
            "example.com", ["example.com", "a.example.com", "b.example.com"],
            self._rows(), self._cf(),
            [{"ip": "1.2.3.4", "status": "200", "sources": ["a.example.com"]}],
            self._findings(), ["/a", "/b", "/c", "/d", "/e"], 10.0,
        ))
        self.assertEqual(m["Target"], "example.com")
        self.assertEqual(m["Scan duration"], "10.0s")
        self.assertEqual(m["Subdomains"], "3")
        self.assertEqual(m["Live hosts"], "3")
        self.assertEqual(m["Cloudflare on target"], "yes")
        self.assertEqual(m["Cloudflare-fronted hosts"], "2")
        self.assertEqual(m["Origin candidates"], "1")
        self.assertEqual(m["Secret-exposure"], "1")
        self.assertEqual(m["sqlmap-sqli"], "1")
        self.assertEqual(m["Metis"], "1")
        self.assertEqual(m["Content discovered"], "5")
        self.assertEqual(m["Total unique findings"], "5")
        self.assertEqual(m["Skipped stages"], "none")

    def test_nuclei_severity_counts_ordered_by_severity_order(self):
        findings = [
            finding("t-unknown", "a.com", "unknown"),
            finding("t-low", "a.com", "low"),
            finding("t-high", "a.com", "high"),
            finding("t-critical", "a.com", "critical"),
            finding("t-medium", "a.com", "medium"),
            finding("t-info", "a.com", "info"),
        ]
        metrics = report.build_metrics(
            "example.com", [], [], {"cloudflare": False}, [], findings, [], 1.0,
        )
        labels = [label for label, _ in metrics if label.startswith("Nuclei findings — ")]
        self.assertEqual(labels, [
            "Nuclei findings — critical",
            "Nuclei findings — high",
            "Nuclei findings — medium",
            "Nuclei findings — low",
            "Nuclei findings — info",
            "Nuclei findings — unknown",
        ])

    def test_severity_counts_use_deduped_findings(self):
        # 3 identical triples collapse to 1; the nuclei tally must count once.
        findings = [
            finding("t1", "a.com", "high"),
            finding("t1", "a.com", "high"),
            finding("t1", "a.com", "high"),
        ]
        m = dict(report.build_metrics(
            "example.com", [], [], {"cloudflare": False}, [], findings, [], 1.0,
        ))
        self.assertEqual(m["Nuclei findings — high"], "1")
        self.assertEqual(m["Total unique findings"], "1")

    def test_cloudflare_off_and_empty_inputs(self):
        m = dict(report.build_metrics(
            "example.com", [], [], {"cloudflare": False}, [], [], [], None,
        ))
        self.assertEqual(m["Cloudflare on target"], "no")
        self.assertEqual(m["Cloudflare-fronted hosts"], "0")
        self.assertEqual(m["Subdomains"], "0")
        self.assertEqual(m["Live hosts"], "0")
        self.assertEqual(m["Total unique findings"], "0")
        self.assertEqual(m["Scan duration"], "n/a")

    def test_skipped_stages_sorted(self):
        m = dict(report.build_metrics(
            "example.com", [], [], {"cloudflare": False}, [], [], [], 1.0,
            skip={"content", "secret", "metis"},
        ))
        self.assertEqual(m["Skipped stages"], "content, metis, secret")


class TestRenderOverview(unittest.TestCase):
    def test_renders_heading_and_table(self):
        metrics = [("Target", "example.com"), ("Live hosts", "3")]
        lines = report.render_overview(metrics)
        self.assertEqual(lines[0], "## Executive Overview")
        self.assertIn("| Metric | Result |", lines)
        self.assertIn("| --- | --- |", lines)
        self.assertIn("| Target | example.com |", lines)
        self.assertIn("| Live hosts | 3 |", lines)

    def test_empty_metrics_still_render_heading(self):
        lines = report.render_overview([])
        self.assertEqual(lines[0], "## Executive Overview")
        self.assertIn("| Metric | Result |", lines)
        self.assertIn("| --- | --- |", lines)


class TestWriteFindingsReportWithMetrics(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.outdir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def _metrics(self):
        return report.build_metrics(
            "example.com", ["example.com"], [{"host": "example.com", "status": 200, "cloudflare": True}],
            {"cloudflare": True}, [], [finding("t1", "a.com", "high")], ["/a"], 1.0,
        )

    def test_metrics_render_overview_at_top(self):
        md = self._write_with_metrics()
        self.assertIn("## Executive Overview", md)
        self.assertIn("| Metric | Result |", md)
        # overview comes after the H1 header and before the Severity section
        self.assertLess(md.index("# Findings — example.com"), md.index("## Executive Overview"))
        self.assertLess(md.index("## Executive Overview"), md.index("## Severity"))

    def test_no_overview_when_metrics_none(self):
        report.write_findings_report(
            self.outdir, "example.com", [finding("t1", "a.com", "high")], [], origins=[],
        )
        md = (self.outdir / "FINDINGS.md").read_text()
        self.assertNotIn("## Executive Overview", md)
        self.assertIn("## Severity", md)

    def test_overview_renders_even_when_no_findings(self):
        report.write_findings_report(
            self.outdir, "example.com", [], [], origins=[], metrics=self._metrics(),
        )
        md = (self.outdir / "FINDINGS.md").read_text()
        self.assertIn("## Executive Overview", md)
        self.assertIn("_No vulnerabilities found._", md)

    def test_findings_json_unaffected_by_metrics(self):
        findings = [finding("t1", "a.com", "high")]
        n = report.write_findings_report(
            self.outdir, "example.com", findings, [], origins=[], metrics=self._metrics(),
        )
        self.assertEqual(n, 1)
        data = json.loads((self.outdir / "findings.json").read_text())
        self.assertEqual(len(data), 1)
        self.assertNotIn("metrics", data[0])

    def _write_with_metrics(self):
        report.write_findings_report(
            self.outdir, "example.com", [finding("t1", "a.com", "high")], [],
            origins=[], metrics=self._metrics(),
        )
        return (self.outdir / "FINDINGS.md").read_text()


if __name__ == "__main__":
    unittest.main(verbosity=2)
