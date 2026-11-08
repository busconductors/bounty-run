"""Unit tests for runner.utils.run() — orphan-leak / process-group kill behavior.

Stdlib unittest only:

    cd ~/tools/bounty-run && python3 -m unittest discover -s tests -v
    # or directly:
    python3 tests/test_utils.py -v
"""
import io
import json
import os
import sys
import tempfile
import threading
import time
from contextlib import redirect_stdout
import unittest
from pathlib import Path

# Make the project root importable regardless of cwd / how the test is invoked.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner import events, utils  # noqa: E402


def _pid_alive(pid: int) -> bool:
    """True if a process with `pid` currently exists."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Exists but we can't signal it — still alive for our purposes.
        return True
    return True


class RunProcessGroupKillTest(unittest.TestCase):
    def test_timeout_kills_whole_process_group(self):
        """On timeout, run() must kill the shell AND its grandchild (the real
        tool), not leak it as an orphan."""
        with tempfile.TemporaryDirectory() as d:
            pidfile = Path(d) / "child.pid"
            # The shell (child of run()) backgrounds a long sleep (grandchild,
            # the stand-in for nuclei/nmap), records its PID, then blocks so the
            # shell itself outlives the timeout window.
            cmd = (
                f"sleep 30 & "
                f"echo $! > {pidfile}; "
                f"wait"
            )

            start = time.monotonic()
            out = utils.run(cmd, timeout=1)
            elapsed = time.monotonic() - start

            # Returns empty string on timeout.
            self.assertEqual(out, "")
            # Timed out promptly rather than waiting the full 30s sleep.
            self.assertLess(elapsed, 15)

            # The grandchild PID was recorded.
            self.assertTrue(pidfile.exists(), "child never recorded its PID")
            child_pid = int(pidfile.read_text().strip())

            # Give the kernel a brief, bounded window to reap the killed group.
            deadline = time.monotonic() + 5
            while _pid_alive(child_pid) and time.monotonic() < deadline:
                time.sleep(0.05)

            self.assertFalse(
                _pid_alive(child_pid),
                f"grandchild PID {child_pid} still alive — process group "
                f"was not killed (orphan leak)",
            )



class RunStreamingTest(unittest.TestCase):
    def setUp(self):
        events.reset()
        self._td = tempfile.TemporaryDirectory()
        self.tmp = Path(self._td.name)
        self.path = self.tmp / "events.jsonl"

    def tearDown(self):
        events.reset()
        self._td.cleanup()

    def _events(self):
        if not self.path.exists():
            return []
        return [json.loads(l) for l in self.path.read_text().splitlines()]

    def test_run_return_identical_to_communicate(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(utils.run("printf 'a\\nb\\n'"), "a\nb\n")
            self.assertEqual(utils.run("printf 'a\\nb'"), "a\nb")
            self.assertEqual(utils.run("true"), "")

    def test_run_on_line_called_per_stdout_line(self):
        got = []
        with redirect_stdout(io.StringIO()):
            utils.run("printf 'a\\nb\\n'; printf 'e\\n' 1>&2",
                      on_line=got.append)
        self.assertEqual(got, ["a", "b"])

    def test_run_emits_output_events(self):
        events.init(self.path)
        events._set_current_stage("vuln")
        with redirect_stdout(io.StringIO()):
            utils.run("printf 'x\\n'; printf 'e\\n' 1>&2")
        outs = [
            {k: e[k] for k in ("stage", "tool", "stream", "line")}
            for e in self._events() if e["type"] == "output"
        ]
        self.assertIn(
            {"stage": "vuln", "tool": "printf", "stream": "stdout", "line": "x"},
            outs)
        self.assertIn(
            {"stage": "vuln", "tool": "printf", "stream": "stderr", "line": "e"},
            outs)

    def test_run_streams_invalid_utf8(self):
        with redirect_stdout(io.StringIO()):
            out = utils.run("printf '\\377\\376\\n'")
        self.assertIn("\ufffd", out)

    def test_run_cancel_kills_group_and_raises(self):
        events.init(self.path)
        pidfile = self.tmp / "child.pid"
        cmd = f"sleep 30 & echo $! > {pidfile}; wait"

        def _cancel():
            time.sleep(0.5)
            (self.tmp / "control").write_text("cancel\n")

        t = threading.Thread(target=_cancel)
        t.start()
        start = time.monotonic()
        try:
            with redirect_stdout(io.StringIO()):
                with self.assertRaises(events.RunCancelled):
                    utils.run(cmd, timeout=60)
        finally:
            t.join()
        self.assertLess(time.monotonic() - start, 7)
        self.assertTrue(pidfile.exists(), "child never recorded its PID")
        child_pid = int(pidfile.read_text().strip())
        deadline = time.monotonic() + 5
        while _pid_alive(child_pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertFalse(_pid_alive(child_pid))
        self.assertEqual((self.tmp / "pids").read_text(), "")

    def test_run_skip_raises_stage_skipped(self):
        events.init(self.path)
        events._set_current_stage("vuln")
        (self.tmp / "control").write_text("skip vuln\n")
        start = time.monotonic()
        with redirect_stdout(io.StringIO()):
            with self.assertRaises(events.StageSkipped):
                utils.run("sleep 30", timeout=60)
        self.assertLess(time.monotonic() - start, 7)

    def test_run_on_line_exception_is_warned_not_raised(self):
        def boom(_line):
            raise RuntimeError("bad")
        buf = io.StringIO()
        with redirect_stdout(buf):
            out = utils.run("printf 'a\\n'", on_line=boom)
        self.assertEqual(out, "a\n")
        self.assertIn("bad", buf.getvalue())

    def test_run_concurrent_threads_and_large_output(self):
        from concurrent.futures import ThreadPoolExecutor
        events.init(self.path)
        cmd = "head -c 300000 /dev/zero | tr '\\0' 'x'; echo; " \
              "head -c 300000 /dev/zero | tr '\\0' 'y' 1>&2; echo {i}"
        with redirect_stdout(io.StringIO()):
            with ThreadPoolExecutor(max_workers=6) as ex:
                outs = list(ex.map(lambda i: utils.run(cmd.format(i=i), timeout=30),
                                   range(6)))
        for i, out in enumerate(outs):
            self.assertEqual(out, "x" * 300000 + "\n" + f"{i}\n")
        self.assertEqual((self.tmp / "pids").read_text(), "")

    def test_log_emits_plain_message(self):
        events.init(self.path)
        buf = io.StringIO()
        with redirect_stdout(buf):
            utils.warn("hi")
        self.assertEqual(buf.getvalue(), "[!] hi\n")
        logs = [e for e in self._events() if e["type"] == "log"]
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["level"], "warn")
        self.assertEqual(logs[0]["msg"], "hi")


if __name__ == "__main__":
    unittest.main(verbosity=2)
