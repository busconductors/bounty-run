"""Unit tests for runner.utils.run() — orphan-leak / process-group kill behavior.

Stdlib unittest only:

    cd ~/tools/bounty-run && python3 -m unittest discover -s tests -v
    # or directly:
    python3 tests/test_utils.py -v
"""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

# Make the project root importable regardless of cwd / how the test is invoked.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner import utils  # noqa: E402


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
