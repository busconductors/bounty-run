"""Tests for runner/panel_detect.py (Phase 12)."""
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from runner import panel_detect


class PanelDetectTest(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.outdir = Path(self._tmp.name)
        for name in ("log", "warn"):
            p = mock.patch.object(panel_detect.utils, name)
            p.start()
            self.addCleanup(p.stop)

    def tearDown(self):
        self._tmp.cleanup()

    def run_detect(self, subs, target="example.com"):
        return panel_detect.panel_detect(target, self.outdir, subs)

    def test_matches_each_kind(self):
        subs = ["cpanel.example.com", "whm.example.com", "pma.example.com",
                "phpmyadmin.example.com", "webdisk.example.com",
                "webmail.example.com", "cpcalendars.example.com",
                "cpcontacts.example.com"]
        findings = self.run_detect(subs)
        self.assertEqual(len(findings), 8)
        self.assertEqual({f["template"] for f in findings},
                         {"panel:cpanel", "panel:whm", "panel:phpmyadmin",
                          "panel:webdisk", "panel:webmail",
                          "panel:cpcalendars", "panel:cpcontacts"})
        for f in findings:
            self.assertEqual(set(f), {"severity", "template", "name", "url",
                                      "host", "evidence"})

    def test_severity_map(self):
        findings = self.run_detect(["cpanel.example.com",
                                    "webmail.example.com"])
        sev = {f["template"]: f["severity"] for f in findings}
        self.assertEqual(sev["panel:cpanel"], "low")
        self.assertEqual(sev["panel:webmail"], "info")

    def test_finding_shape(self):
        (f,) = self.run_detect(["cpanel.example.com"])
        self.assertEqual(f["name"],
                         "High-value panel subdomain: cpanel.example.com (cpanel)")
        self.assertEqual(f["evidence"], "label 'cpanel' matches cpanel")

    def test_suffix_variants_match(self):
        findings = self.run_detect(["cpanel2.example.com",
                                    "webmail-old.example.com",
                                    "mycpanelblog.example.com",
                                    "www.example.com"])
        hosts = {f["host"] for f in findings}
        self.assertEqual(hosts, {"cpanel2.example.com",
                                 "webmail-old.example.com"})

    def test_target_labels_ignored(self):
        self.assertEqual(self.run_detect(["cpanel.io", "www.cpanel.io"],
                                         target="cpanel.io"), [])

    def test_nested_label(self):
        findings = self.run_detect(["a.webmail.example.com"])
        self.assertEqual([f["template"] for f in findings], ["panel:webmail"])

    def test_normalises_case_and_trailing_dot(self):
        (f,) = self.run_detect(["CPanel.Example.COM."])
        self.assertEqual(f["host"], "cpanel.example.com")
        self.assertEqual(f["url"], "https://cpanel.example.com")

    def test_out_of_scope_and_junk_ignored(self):
        self.assertEqual(self.run_detect(["cpanel.other.com", "", "  ",
                                          None]), [])

    def test_artifact_written(self):
        self.run_detect(["cpanel.example.com"])
        lines = (self.outdir / "panels.txt").read_text().splitlines()
        self.assertIn("cpanel.example.com\tcpanel\tlow", lines)

    def test_artifact_written_when_empty(self):
        self.assertEqual(self.run_detect(["www.example.com"]), [])
        self.assertTrue((self.outdir / "panels.txt").exists())


if __name__ == "__main__":
    unittest.main()
