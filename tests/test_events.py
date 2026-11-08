"""Unit tests for runner.events (JSONL event emitter)."""
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner import events  # noqa: E402


class TestEvents(unittest.TestCase):
    def setUp(self):
        events.reset()
        self._td = tempfile.TemporaryDirectory()
        self.tmp = Path(self._td.name)
        self.path = self.tmp / "events.jsonl"

    def tearDown(self):
        events.reset()
        self._td.cleanup()

    def _lines(self):
        return [json.loads(l) for l in self.path.read_text().splitlines()]

    def test_disabled_is_noop(self):
        events.log("info", "x")
        self.assertFalse(events.enabled())
        self.assertFalse(self.path.exists())

    def test_emit_line_shape(self):
        events.init(self.path)
        events.stage_start("vuln")
        lines = self._lines()
        self.assertEqual(len(lines), 1)
        o = lines[0]
        self.assertEqual(o["v"], 1)
        self.assertEqual(o["type"], "stage_start")
        self.assertEqual(o["stage"], "vuln")
        self.assertIsInstance(o["t"], int)

    def test_stage_end_omits_none_reason(self):
        events.init(self.path)
        events.stage_end("x", "ok", 5, {})
        events.stage_end("x", "skipped", 5, {}, reason="tool missing: nuclei")
        a, b = self._lines()
        self.assertNotIn("reason", a)
        self.assertEqual(b["reason"], "tool missing: nuclei")

    def test_concurrent_emit_lines_intact(self):
        events.init(self.path)

        def work():
            for i in range(500):
                events.output("s", "tool", "stdout", "line é %d" % i)

        ts = [threading.Thread(target=work) for _ in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(len(self._lines()), 4000)

    def test_current_stage_and_reset(self):
        events._set_current_stage("vuln")
        self.assertEqual(events.current_stage(), "vuln")
        events.reset()
        self.assertIsNone(events.current_stage())

    def test_run_json_fields(self):
        events.init(self.path)
        events.write_run_json("a.com", {"tls": True}, "1.0.0")
        d = json.loads((self.tmp / "run.json").read_text())
        self.assertEqual(set(d), {"pid", "pgid", "pid_start", "target",
                                  "flags", "started", "engine_version"})
        self.assertEqual(d["pid"], os.getpid())
        stat = Path("/proc/self/stat").read_text()
        self.assertEqual(d["pid_start"], int(stat.rsplit(")", 1)[1].split()[19]))
        self.assertEqual(d["flags"], {"tls": True})


if __name__ == "__main__":
    unittest.main()
