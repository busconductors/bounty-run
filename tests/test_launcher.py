"""Bare `bounty-run` dispatches to the TUI; everything else stays on the CLI."""
import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from runner import launcher  # noqa: E402


class ShouldLaunchTest(unittest.TestCase):
    def test_bare_interactive_launches(self):
        self.assertTrue(launcher.should_launch_tui([], True))

    def test_bare_non_interactive_does_not(self):
        self.assertFalse(launcher.should_launch_tui([], False))

    def test_any_argument_keeps_cli(self):
        for argv in (["example.com"], ["track"], ["dashboard"], ["-h"], ["--version"],
                     ["example.com", "--nmap"]):
            self.assertFalse(launcher.should_launch_tui(argv, True), argv)


class MaybeExecTest(unittest.TestCase):
    def test_execs_tui_binary_for_bare_call(self):
        with tempfile.TemporaryDirectory() as d:
            tui = Path(d) / "bounty-tui"
            tui.write_text("#!/bin/sh\n")
            tui.chmod(0o755)
            with mock.patch.dict(os.environ, {"BOUNTY_TUI": str(tui)}), \
                    mock.patch.object(launcher.os, "execv") as execv:
                launcher.maybe_exec_tui([], interactive=True)
            execv.assert_called_once_with(str(tui), [str(tui)])

    def test_with_args_never_execs(self):
        with mock.patch.object(launcher.os, "execv") as execv:
            launcher.maybe_exec_tui(["example.com"], interactive=True)
        execv.assert_not_called()

    def test_missing_binary_falls_back_with_hint(self):
        err = io.StringIO()
        with mock.patch.dict(os.environ, {"BOUNTY_TUI": "/nonexistent/bounty-tui"}), \
                mock.patch.object(launcher.os, "execv") as execv, redirect_stderr(err):
            launcher.maybe_exec_tui([], interactive=True)
        execv.assert_not_called()
        self.assertIn("make tui", err.getvalue())

    def test_default_path_is_repo_bin(self):
        self.assertEqual(launcher.DEFAULT_TUI, ROOT / "bin" / "bounty-tui")


class EntrypointTest(unittest.TestCase):
    def test_bare_entrypoint_execs_tui_on_a_tty(self):
        # A pty makes stdin/stdout a terminal; the stand-in TUI just prints a marker.
        import pty
        with tempfile.TemporaryDirectory() as d:
            tui = Path(d) / "bounty-tui"
            tui.write_text("#!/bin/sh\necho TUI-LAUNCHED\n")
            tui.chmod(0o755)
            env = dict(os.environ, BOUNTY_TUI=str(tui))
            out = []
            pid, fd = pty.fork()
            if pid == 0:  # child
                os.execvpe(sys.executable, [sys.executable, str(ROOT / "bounty_run.py")], env)
            try:
                while True:
                    chunk = os.read(fd, 1024)
                    if not chunk:
                        break
                    out.append(chunk)
            except OSError:
                pass
            os.waitpid(pid, 0)
            self.assertIn(b"TUI-LAUNCHED", b"".join(out))

    def test_bare_entrypoint_without_tty_keeps_usage_error(self):
        r = subprocess.run([sys.executable, str(ROOT / "bounty_run.py")],
                           stdin=subprocess.DEVNULL, capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertIn("usage: bounty-run", r.stderr)


if __name__ == "__main__":
    unittest.main()
