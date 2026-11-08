"""Tests for runner/tech_scan.py (Phase 11)."""
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from runner import tech_scan


# whatweb --log-json shape: array of per-target result objects.
WHATWEB_LOG = [
    {
        "target": "https://example.com",
        "http_status": 200,
        "plugins": {
            "nginx": {"version": ["1.18.0"], "string": ["nginx/1.18.0"]},
            "jQuery": {"version": ["3.6.0"], "confidence": 100},
            "HTML5": {},
            "PHP": {"version": ["8.1"], "string": ["PHP/8.1"]},
        },
    },
]


class TestParse(unittest.TestCase):
    def test_parse_returns_list(self):
        results = tech_scan._parse_whatweb_json(json.dumps(WHATWEB_LOG))
        self.assertEqual(len(results), 1)

    def test_parse_bad_json(self):
        self.assertEqual(tech_scan._parse_whatweb_json("not json"), [])

    def test_version_and_evidence(self):
        self.assertEqual(tech_scan._version({"version": ["1.18.0"]}), "1.18.0")
        self.assertEqual(tech_scan._version({}), "")
        self.assertEqual(tech_scan._evidence({"confidence": 100}), "100")
        self.assertEqual(tech_scan._evidence({"string": ["nginx/1.18.0"]}),
                         "nginx/1.18.0")


class TestScan(unittest.TestCase):
    def _run(self, outdir):
        def fake_run(cmd, timeout=300):
            (outdir / "whatweb.json").write_text(json.dumps(WHATWEB_LOG))
            return ""

        with mock.patch.object(tech_scan.utils, "have", return_value=True), \
             mock.patch.object(tech_scan, "_resolve", return_value="93.184.216.34"), \
             mock.patch.object(tech_scan, "_is_global", return_value=True), \
             mock.patch.object(tech_scan.utils, "log"), \
             mock.patch.object(tech_scan.utils, "warn"), \
             mock.patch.object(tech_scan.utils, "run", side_effect=fake_run):
            return tech_scan.tech_scan("example.com", outdir, hosts=["example.com"])

    def test_one_finding_per_tech(self):
        with TemporaryDirectory() as d:
            findings = self._run(Path(d))
        # 4 plugins -> 4 findings.
        self.assertEqual(len(findings), 4)

    def test_tech_name_in_template_avoids_dedupe_collapse(self):
        from runner import report
        with TemporaryDirectory() as d:
            findings = self._run(Path(d))
        templates = {f["template"] for f in findings}
        self.assertEqual(templates, {"tech-detect:nginx", "tech-detect:jquery",
                                     "tech-detect:html5", "tech-detect:php"})
        # Same host + same URL, distinct templates -> dedupe keeps all four.
        self.assertEqual(len(report.dedupe(findings)), 4)

    def test_finding_shape(self):
        with TemporaryDirectory() as d:
            findings = self._run(Path(d))
        by_tpl = {f["template"]: f for f in findings}
        nginx = by_tpl["tech-detect:nginx"]
        self.assertEqual(nginx["severity"], "info")
        self.assertEqual(nginx["name"], "Technology: nginx 1.18.0")
        self.assertEqual(nginx["url"], "https://example.com")
        self.assertEqual(nginx["host"], "example.com")
        self.assertEqual(nginx["evidence"], "nginx/1.18.0")
        # jQuery carries confidence as evidence.
        self.assertEqual(by_tpl["tech-detect:jquery"]["evidence"], "100")
        # HTML5 has no version -> trailing space trimmed.
        self.assertEqual(by_tpl["tech-detect:html5"]["name"], "Technology: HTML5")


class TestGuards(unittest.TestCase):
    def test_missing_whatweb_returns_empty(self):
        with mock.patch.object(tech_scan.utils, "have", return_value=False), \
             mock.patch.object(tech_scan.utils, "warn"), \
             mock.patch.object(tech_scan.utils, "log"):
            self.assertEqual(
                tech_scan.tech_scan("example.com", Path("/tmp"),
                                    hosts=["example.com"]), [])

    def test_no_hosts_returns_empty(self):
        with mock.patch.object(tech_scan.utils, "have", return_value=True), \
             mock.patch.object(tech_scan, "_resolve", return_value="10.0.0.1"), \
             mock.patch.object(tech_scan, "_is_global", return_value=False), \
             mock.patch.object(tech_scan.utils, "warn"), \
             mock.patch.object(tech_scan.utils, "log"):
            self.assertEqual(
                tech_scan.tech_scan("example.com", Path("/tmp"),
                                    hosts=["internal"]), [])


if __name__ == "__main__":
    unittest.main()
