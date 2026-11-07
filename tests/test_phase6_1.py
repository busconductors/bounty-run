"""Phase 6.1 tests: --injection flag gates the injection_scan stage.

Stdlib unittest only.  ``cli.main`` is exercised with every heavy stage mocked
out, so no network/DB/nuclei work happens — only the injection gate is probed.
"""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner import cli  # noqa: E402


class InjectionFlagTests(unittest.TestCase):
    def test_injection_flag_defaults_false(self):
        ns = cli.build_parser().parse_args(["example.com"])
        self.assertIs(ns.injection, False)

    def test_injection_flag_true_when_passed(self):
        ns = cli.build_parser().parse_args(["example.com", "--injection"])
        self.assertIs(ns.injection, True)


class InjectionGateTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.outdir = self._tmp.name

    def _run(self, argv):
        """Run cli.main with all stages mocked; return the injection_scan mock."""
        inj_mock = mock.MagicMock(return_value=[])
        patches = [
            mock.patch.object(cli.banner, "print_banner"),
            mock.patch.object(cli.stages, "subdomain_enum", return_value=["example.com"]),
            mock.patch.object(cli.stages, "live_hosts", return_value=[]),
            mock.patch.object(cli.stages, "cloudflare_detect",
                              return_value={"target": "example.com",
                                            "cloudflare": False, "evidence": []}),
            mock.patch.object(cli.stages, "vuln_scan", return_value=[]),
            mock.patch.object(cli.stages, "content_discovery", return_value=[]),
            mock.patch.object(cli.param_scan, "param_scan", return_value=[]),
            mock.patch.object(cli.injection_scan, "injection_scan", inj_mock),
            mock.patch.object(cli.secret_scan, "secret_scan", return_value=[]),
            mock.patch.object(cli.metis_check, "metis_check", return_value=[]),
            mock.patch.object(cli.report, "write_findings_report", return_value=0),
        ]
        for p in patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in patches])
        return cli.main(argv), inj_mock

    def test_run_without_injection_skips_stage(self):
        rc, inj = self._run(["example.com", "--no-track", "--no-banner",
                             "-o", self.outdir])
        self.assertEqual(rc, 0)
        inj.assert_not_called()

    def test_run_with_injection_calls_stage(self):
        rc, inj = self._run(["example.com", "--injection", "--no-track",
                             "--no-banner", "-o", self.outdir])
        self.assertEqual(rc, 0)
        inj.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
