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


class TestControl(unittest.TestCase):
    def setUp(self):
        events.reset()
        self.tmp = Path(tempfile.mkdtemp())
        self.path = self.tmp / "events.jsonl"

    def tearDown(self):
        events.reset()

    def _ctl(self, text):
        (self.tmp / "control").write_text(text)

    def test_cancel_raises(self):
        events.init(self.path)
        self._ctl("cancel\n")
        with self.assertRaises(events.RunCancelled):
            events.check_control()

    def test_skip_only_matching_stage(self):
        events.init(self.path)
        events._set_current_stage("nikto")
        self._ctl("skip vuln\n")
        events.check_control()
        events._set_current_stage("vuln")
        with self.assertRaises(events.StageSkipped):
            events.check_control()
        self.assertEqual((self.tmp / "control").read_text(), "")

    def test_skip_is_sticky_across_threads(self):
        events.init(self.path)
        events._set_current_stage("nikto")
        self._ctl("skip nikto\n")
        res = []

        def work():
            try:
                events.check_control()
                res.append("ok")
            except events.StageSkipped:
                res.append("skipped")

        ts = [threading.Thread(target=work) for _ in range(4)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(res, ["skipped"] * 4)

    def test_pids_file_tracks_children(self):
        events.init(self.path)
        events.register_child(101)
        events.register_child(202)
        events.unregister_child(101)
        self.assertEqual((self.tmp / "pids").read_text(), "202\n")

    def test_mark_skipped_and_reset(self):
        events.init(self.path)
        events.mark_skipped("because")
        events.register_child(5)
        events.reset()
        self.assertIsNone(events._skip_reason)
        self.assertEqual(events._children, set())

    def test_check_control_disabled_noop(self):
        cwd = os.getcwd()
        os.chdir(self.tmp)
        try:
            self._ctl("cancel\n")
            events.check_control()
        finally:
            os.chdir(cwd)


if __name__ == "__main__":
    unittest.main()
