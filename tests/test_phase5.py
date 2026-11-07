"""Phase 5 CLI wiring tests: interactive outdir, end-of-run table, tracker ingest.

Stdlib unittest only.  Ingest tests repoint ``tracker.DEFAULT_DB`` at a temp file.
"""

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner import cli, tracker, utils  # noqa: E402


def _feeder(*answers):
    it = iter(answers)

    def fn(_prompt):
        try:
            return next(it)
        except StopIteration:
            raise EOFError
    return fn


class SanitizeNameTests(unittest.TestCase):
    def test_traversal_stripped(self):
        self.assertEqual(cli._sanitize_name("../../evil", "example.com"), "evil")

    def test_empty_falls_back_to_target(self):
        self.assertEqual(cli._sanitize_name("", "example.com"), "example.com")
        self.assertEqual(cli._sanitize_name("../..", "example.com"), "example.com")

    def test_metacharacters_replaced(self):
        self.assertEqual(cli._sanitize_name("a b;c$(x)", "t.com"), "a-b-c--x")


class OutdirResolutionTests(unittest.TestCase):
    TS = "20260101-000000"

    def test_non_interactive_default(self):
        out = cli._resolve_outdir("example.com", ts=self.TS)
        self.assertEqual(out, cli.REPO_OUTPUTS / "example.com" / self.TS)

    def test_o_wins_and_skips_prompts(self):
        def boom(_):
            raise AssertionError("prompted despite -o")
        out = cli._resolve_outdir("example.com", "/tmp/x", True, input_fn=boom, ts=self.TS)
        self.assertEqual(out, Path("/tmp/x"))

    def test_interactive_empty_answers_use_defaults(self):
        out = cli._resolve_outdir("example.com", None, True, input_fn=_feeder("", ""), ts=self.TS)
        self.assertEqual(out, cli.REPO_OUTPUTS / "example.com" / self.TS)

    def test_interactive_name_and_relative_dir_against_cwd(self):
        with tempfile.TemporaryDirectory() as d:
            old = os.getcwd()
            os.chdir(d)
            try:
                out = cli._resolve_outdir("example.com", None, True,
                                          input_fn=_feeder("runs", "../../evil"), ts=self.TS)
            finally:
                os.chdir(old)
            self.assertEqual(out, Path(d).resolve() / "runs" / "evil" / self.TS)

    def test_interactive_expanduser(self):
        out = cli._resolve_outdir("example.com", None, True,
                                  input_fn=_feeder("~/scans", "eng"), ts=self.TS)
        self.assertEqual(out, Path(os.path.expanduser("~/scans")).resolve() / "eng" / self.TS)

    def test_eof_falls_back_to_defaults(self):
        out = cli._resolve_outdir("example.com", None, True, input_fn=_feeder(), ts=self.TS)
        self.assertEqual(out, cli.REPO_OUTPUTS / "example.com" / self.TS)


class EndTableTests(unittest.TestCase):
    def test_title_name_or_template(self):
        self.assertEqual(cli._finding_title({"name": "SQLi", "template": "sqli-x"}), "SQLi")
        self.assertEqual(cli._finding_title({"name": "", "template": "sqli-x"}), "sqli-x")
        self.assertEqual(cli._finding_title({"template": "tpl"}), "tpl")

    def test_table_output(self):
        findings = [
            {"severity": "high", "template": "t1", "url": "https://a/1"},
            {"severity": "high", "template": "t1", "url": "https://a/1"},  # dup
            {"severity": "critical", "name": "RCE", "template": "t2", "url": "https://a/2"},
        ]
        buf = io.StringIO()
        with redirect_stdout(buf):  # not a TTY -> no ANSI
            cli.print_findings_table(findings)
        out = buf.getvalue()
        self.assertIn("severity", out.splitlines()[0])
        self.assertIn("RCE", out)
        self.assertEqual(out.count("https://a/1"), 1)

    def test_empty_prints_no_findings(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            cli.print_findings_table([])
        self.assertEqual(buf.getvalue().strip(), "no findings")


class SeverityColorTests(unittest.TestCase):
    def test_unknown_severity_falls_back_to_grey(self):
        with mock.patch.object(utils, "_color_enabled", return_value=True):
            self.assertEqual(cli._severity_cell("weird"), "\033[90mweird\033[0m")
            self.assertEqual(cli._severity_cell("critical"), "\033[31mcritical\033[0m")


class IngestTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_db = tracker.DEFAULT_DB
        tracker.DEFAULT_DB = Path(self._tmp.name) / "tracker.db"
        self.addCleanup(self._tmp.cleanup)
        self.addCleanup(setattr, tracker, "DEFAULT_DB", self._orig_db)

    FINDINGS = [
        {"severity": "high", "name": "XSS", "template": "xss-1", "url": "https://a/x"},
        {"severity": "high", "name": "XSS", "template": "xss-1", "url": "https://a/x"},
        {"template": "misc", "url": "https://a/m"},
    ]

    def test_ingest_dedupes_across_runs(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(cli.ingest_findings("example.com", self.FINDINGS), 2)
            self.assertEqual(cli.ingest_findings("example.com", self.FINDINGS), 0)
        rows = tracker.list_findings(target="example.com")
        self.assertEqual(len(rows), 2)
        by_tpl = {r["template"]: r for r in rows}
        self.assertEqual(by_tpl["xss-1"]["title"], "XSS")
        self.assertEqual(by_tpl["misc"]["title"], "misc")
        self.assertEqual(by_tpl["misc"]["severity"], "unknown")

    def test_has_finding_true_prevents_add(self):
        with mock.patch.object(tracker, "has_finding", return_value=True), \
             mock.patch.object(tracker, "add_finding") as add:
            self.assertEqual(cli.ingest_findings("example.com", self.FINDINGS), 0)
        add.assert_not_called()

    def test_db_failure_warns_not_crashes(self):
        buf = io.StringIO()
        with mock.patch.object(tracker, "has_finding", side_effect=RuntimeError("db locked")), \
             redirect_stdout(buf):
            self.assertEqual(cli.ingest_findings("example.com", self.FINDINGS), 0)
        self.assertIn("tracker ingest failed", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
