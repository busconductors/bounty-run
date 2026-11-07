"""Tests for Phase 7b CLI/report wiring."""
import unittest

from runner import cli, report


class TestCliParser(unittest.TestCase):
    def test_skip_includes_new_tokens(self):
        args = cli.build_parser().parse_args(["example.com", "--skip", "headers,cors,headi"])
        self.assertEqual(args.skip, "headers,cors,headi")

    def test_headi_flag_defaults_false(self):
        args = cli.build_parser().parse_args(["example.com"])
        self.assertFalse(args.headi)

    def test_headi_flag_set(self):
        args = cli.build_parser().parse_args(["example.com", "--headi"])
        self.assertTrue(args.headi)


class TestBuildMetrics(unittest.TestCase):
    def _metrics(self, findings):
        return report.build_metrics("example.com", ["example.com"], [], {"cloudflare": False},
                                    [], findings, [], 1.0, set())

    def test_new_templates_own_buckets(self):
        findings = [
            {"template": "missing-security-header:x-frame-options", "severity": "low", "host": "h", "url": "u"},
            {"template": "insecure-security-header:content-security-policy", "severity": "info", "host": "h", "url": "u"},
            {"template": "cors-misconfiguration:reflected", "severity": "high", "host": "h", "url": "u"},
            {"template": "headi:host", "severity": "high", "host": "h", "url": "u"},
        ]
        m = dict(self._metrics(findings))
        self.assertEqual(m["Missing security headers"], "1")
        self.assertEqual(m["Insecure security headers"], "1")
        self.assertEqual(m["CORS misconfigurations"], "1")
        self.assertEqual(m["Header injection (headi)"], "1")
        self.assertFalse(any(k.startswith("Nuclei findings") for k in m))

    def test_nuclei_bucket_unaffected(self):
        findings = [{"template": "tech-detect", "severity": "info", "host": "h", "url": "u"}]
        m = dict(self._metrics(findings))
        self.assertEqual(m["Nuclei findings — info"], "1")
        self.assertEqual(m["Missing security headers"], "0")


if __name__ == "__main__":
    unittest.main()
