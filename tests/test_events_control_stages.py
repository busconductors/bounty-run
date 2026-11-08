"""Phase 13 final review: skip/cancel reach pure-Python stages; partial-report origins.

    cd ~/tools/bounty-run && python3 -m pytest tests/test_events_control_stages.py -q
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner import dork_scan, events, http_headers, secret_scan  # noqa: E402
from tests.test_events_cli import read_events, run_with_events, stage_ends  # noqa: E402

REAL_SECRET_SCAN = secret_scan.secret_scan
REAL_DORK_SCAN = dork_scan.dork_scan
REAL_CORS_SCAN = http_headers.cors_scan


class _EventsBase(unittest.TestCase):
    def setUp(self):
        events.reset()
        self._td = tempfile.TemporaryDirectory()
        self.tmp = Path(self._td.name)
        events.init(self.tmp / "events.jsonl")
        self.addCleanup(events.reset)
        self.addCleanup(self._td.cleanup)

    def _events(self):
        return [json.loads(ln) for ln in (self.tmp / "events.jsonl").read_text().splitlines()]


class TestStageEntryCheck(_EventsBase):
    def test_stage_raises_on_cancel_at_entry(self):
        (self.tmp / "control").write_text("cancel\n")
        ran = []
        with self.assertRaises(events.RunCancelled):
            with events.stage("panel"):
                ran.append(1)
        self.assertEqual(ran, [])
        ends = [e for e in self._events() if e["type"] == "stage_end"]
        self.assertEqual([(e["stage"], e["status"]) for e in ends], [("panel", "cancelled")])


class TestSecretScanCancel(unittest.TestCase):
    def test_cancel_while_iterating_hosts(self):
        fetched = []

        def fake_fetch(url, timeout=3):
            fetched.append(url)
            if len(fetched) == 1:  # cancel arrives while host 1 is being fetched
                (events.run_dir() / "control").write_text("cancel\n")
            return "<html>AKIAABCDEFGHIJKLMNOP</html>"

        def secret_side(target, outdir):
            (Path(outdir) / "live_hosts.txt").write_text("h1.a.com\nh2.a.com\nh3.a.com\n")
            return REAL_SECRET_SCAN(target, outdir)

        with mock.patch.object(secret_scan, "_fetch", side_effect=fake_fetch), \
             mock.patch.object(secret_scan, "_resolve", return_value="8.8.8.8"), \
             mock.patch.object(secret_scan, "_is_global", return_value=True):
            rc, _, tmp, exc = run_with_events({"secret_scan": secret_side})
        self.addCleanup(tmp.cleanup)
        self.assertIsNone(exc)
        self.assertEqual(rc, 130)
        self.assertEqual(fetched, ["https://h1.a.com"])
        evs = read_events(tmp.name)
        ends = stage_ends(evs)
        self.assertEqual(ends["secret"]["status"], "cancelled")
        self.assertNotIn("headers", ends)
        self.assertEqual(evs[-1]["type"], "run_end")
        self.assertEqual(evs[-1]["status"], "cancelled")
        self.assertTrue((Path(tmp.name) / "FINDINGS.md").exists())
        # progress polls control before emitting, so the cancel wins
        progress = [e for e in evs if e["type"] == "progress" and e["stage"] == "secret"]
        self.assertEqual(progress, [])


class TestDorkSkip(unittest.TestCase):
    def test_skip_mid_loop_then_next_stage_runs(self):
        calls = []

        def fake_fetch(url, query):
            calls.append(query)
            if len(calls) == 1:
                (events.run_dir() / "control").write_text("skip dork\n")
            return 200, ""

        def dork_side(target, outdir):
            return REAL_DORK_SCAN(target, outdir, delay=0)

        with mock.patch.object(dork_scan, "_fetch", side_effect=fake_fetch):
            rc, _, tmp, exc = run_with_events({"dork_scan": dork_side})
        self.addCleanup(tmp.cleanup)
        self.assertIsNone(exc)
        self.assertEqual(rc, 0)
        # both engines of the first query, then the skip is honoured
        self.assertEqual(len(calls), 2)
        evs = read_events(tmp.name)
        ends = stage_ends(evs)
        self.assertEqual(ends["dork"]["status"], "skipped")
        self.assertEqual(ends["vuln"]["status"], "ok")
        self.assertEqual(evs[-1]["status"], "ok")


class TestCorsProgress(unittest.TestCase):
    def test_cancel_between_hosts(self):
        sent = []

        def fake_send(url, origin):
            sent.append(url)
            if len(sent) == 1:
                (events.run_dir() / "control").write_text("cancel\n")
            return "", ""

        def cors_side(target, outdir, hosts=None):
            return REAL_CORS_SCAN(target, outdir, ["h1.a.com", "h2.a.com"])

        with mock.patch.object(http_headers, "_send_origin", side_effect=fake_send), \
             mock.patch.object(http_headers, "_resolve", return_value="8.8.8.8"), \
             mock.patch.object(http_headers, "_is_global", return_value=True):
            rc, _, tmp, exc = run_with_events({"cors_scan": cors_side})
        self.addCleanup(tmp.cleanup)
        self.assertIsNone(exc)
        self.assertEqual(rc, 130)
        self.assertTrue(all(u == "https://h1.a.com" for u in sent))
        self.assertEqual(stage_ends(read_events(tmp.name))["cors"]["status"], "cancelled")


class TestFinishMergesOrigins(unittest.TestCase):
    def test_cancel_in_origin_stage_lists_ip_once(self):
        cf = {"target": "a.com", "cloudflare": True, "evidence": []}
        dup = [{"ip": "1.2.3.4", "status": 200, "sources": ["crtsh"]},
               {"ip": "1.2.3.4", "status": 200, "sources": ["dns"]}]
        rc, _, tmp, exc = run_with_events({
            "cloudflare_detect": lambda *a, **k: cf,
            "origin_hunt": lambda *a, **k: list(dup),
            "origin_deep": events.RunCancelled(),
        })
        self.addCleanup(tmp.cleanup)
        self.assertIsNone(exc)
        self.assertEqual(rc, 130)
        summary = (Path(tmp.name) / "SUMMARY.md").read_text()
        self.assertEqual(summary.count("`1.2.3.4`"), 1, summary)
        self.assertIn("via crtsh, dns", summary)


if __name__ == "__main__":
    unittest.main()
