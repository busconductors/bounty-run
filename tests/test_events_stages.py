"""Tests for Phase 13a Task 4: live findings, progress, tool-missing reasons."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner import events, nikto_scan, stages, tls_scan, utils  # noqa: E402


class _EventsBase(unittest.TestCase):
    def setUp(self):
        events.reset()
        self._td = tempfile.TemporaryDirectory()
        self.tmp = Path(self._td.name)
        events.init(self.tmp / "events.jsonl")
        self.addCleanup(events.reset)
        self.addCleanup(self._td.cleanup)

    def _events(self):
        return [json.loads(l) for l in (self.tmp / "events.jsonl").read_text().splitlines()]

    def _events_of_type(self, t):
        return [e for e in self._events() if e["type"] == t]


class TestNucleiLineToFinding(unittest.TestCase):
    def test_nuclei_line_to_finding_matches_parser(self):
        line = ('{"info": {"severity": "medium", "name": "Line finding"}, '
                '"template-id": "CVE-2021-24891", "matched-at": "https://x/a.js", '
                '"host": "example.com"}')
        jl = Path(tempfile.mkdtemp()) / "nuclei.jsonl"
        jl.write_text(line)
        parsed = stages._parse_nuclei_jsonl(jl)
        self.assertEqual(len(parsed), 1)
        direct = stages._nuclei_line_to_finding(line)
        self.assertEqual(direct, parsed[0])


class TestVulnScanLiveFindings(_EventsBase):
    def test_vuln_scan_emits_live_findings(self):
        lines = [
            '{"info": {"severity": "high", "name": "F1"}, "template-id": "t1", '
            '"matched-at": "https://example.com/a", "host": "example.com"}',
            '{"info": {"severity": "low", "name": "F2"}, "template-id": "t2", '
            '"matched-at": "https://example.com/b", "host": "example.com"}',
        ]

        def fake_run(cmd, outfile=None, timeout=180, on_line=None):
            if on_line is not None:
                for l in lines:
                    on_line(l)
            return ""

        outdir = Path(tempfile.mkdtemp())
        with mock.patch.object(utils, "have", return_value=True), \
             mock.patch.object(utils, "run", side_effect=fake_run), \
             mock.patch.object(utils, "log"), \
             mock.patch.object(stages, "_resolve", return_value="8.8.8.8"):
            stages.vuln_scan("example.com", outdir, [{"host": "example.com", "status": 200}])

        findings = self._events_of_type("finding")
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["severity"], "high")
        self.assertEqual(findings[0]["template"], "t1")
        self.assertEqual(findings[0]["host"], "example.com")
        self.assertEqual(findings[0]["url"], "https://example.com/a")
        self.assertEqual(findings[0]["summary"], "F1")


class TestContentDiscoveryLiveFindings(_EventsBase):
    def test_content_discovery_emits_info_findings(self):
        def fake_run(cmd, outfile=None, timeout=600, on_line=None):
            if on_line is not None:
                on_line("admin")
                on_line("")
            return "admin\n"

        outdir = Path(tempfile.mkdtemp())
        wordlist = outdir / "wl.txt"
        wordlist.write_text("admin\n")
        with mock.patch.object(utils, "have", return_value=True), \
             mock.patch.object(utils, "run", side_effect=fake_run), \
             mock.patch.object(utils, "log"):
            stages.content_discovery("a.com", outdir, str(wordlist))

        findings = self._events_of_type("finding")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "info")
        self.assertEqual(findings[0]["template"], "ffuf:path")
        self.assertEqual(findings[0]["url"], "https://a.com/admin")
        self.assertEqual(findings[0]["summary"], "admin")


class TestLiveHostsProgress(_EventsBase):
    def test_live_hosts_progress_final(self):
        hosts = [f"h{i}.example.com" for i in range(25)]

        def fake_probe(sub, timeout):
            return {"host": sub, "url": f"https://{sub}", "status": 200,
                    "server": "", "cloudflare": False}

        with mock.patch.object(stages, "_probe_host", side_effect=fake_probe), \
             mock.patch.object(utils, "log"):
            stages.live_hosts(hosts, Path(tempfile.mkdtemp()))

        progress_events = self._events_of_type("progress")
        self.assertTrue(progress_events)
        last = progress_events[-1]
        self.assertEqual(last["done"], 25)
        self.assertEqual(last["total"], 25)


class TestToolMissingSkipReason(_EventsBase):
    def test_tool_missing_marks_skip_reason(self):
        with mock.patch.object(utils, "have", return_value=False), \
             mock.patch.object(utils, "warn"), \
             mock.patch.object(utils, "log"):
            result = stages.vuln_scan("example.com", Path(tempfile.mkdtemp()),
                                      [{"host": "example.com", "status": 200}])
        self.assertEqual(result, [])
        self.assertEqual(events._skip_reason, "tool missing: nuclei")


class TestProgressRaisesOnSkip(_EventsBase):
    def test_progress_raises_on_skip(self):
        events._set_current_stage("live")
        (self.tmp / "control").write_text("skip live\n")
        with self.assertRaises(events.StageSkipped):
            events.progress("live", 1, 2)


class TestNiktoSkipPropagates(_EventsBase):
    def test_nikto_skip_propagates(self):
        with mock.patch.object(nikto_scan.utils, "have", return_value=True), \
             mock.patch.object(nikto_scan.utils, "log"), \
             mock.patch.object(nikto_scan.utils, "warn"), \
             mock.patch.object(nikto_scan, "_resolve", return_value="93.184.216.34"), \
             mock.patch.object(nikto_scan, "_is_global", return_value=True), \
             mock.patch.object(nikto_scan.utils, "run",
                               side_effect=events.StageSkipped("nikto")):
            with self.assertRaises(events.StageSkipped):
                nikto_scan.nikto_scan("example.com", Path(tempfile.mkdtemp()),
                                      ["example.com"])


class TestTlsSkipPropagates(_EventsBase):
    def test_tls_skip_propagates(self):
        with mock.patch.object(tls_scan.utils, "have", return_value=True), \
             mock.patch.object(tls_scan.utils, "log"), \
             mock.patch.object(tls_scan.utils, "warn"), \
             mock.patch.object(tls_scan, "_resolve", return_value="93.184.215.14"), \
             mock.patch.object(tls_scan, "_is_global", return_value=True), \
             mock.patch.object(tls_scan.utils, "run",
                               side_effect=events.StageSkipped("tls")):
            with self.assertRaises(events.StageSkipped):
                tls_scan.tls_scan("example.com", Path(tempfile.mkdtemp()),
                                  ["example.com"])


class TestDigMissingNotSkipped(_EventsBase):
    def test_dig_missing_does_not_mark_skip(self):
        with mock.patch.object(utils, "have", side_effect=lambda t: t != "dig"), \
             mock.patch.object(utils, "run", return_value=""):
            self.assertEqual(stages._mx_hosts("a.com"), [])
        self.assertIsNone(events._skip_reason)

    def test_origin_hunt_without_dig_keeps_running(self):
        with mock.patch.object(utils, "have", side_effect=lambda t: t != "dig"), \
             mock.patch.object(utils, "log"), \
             mock.patch.object(stages, "_resolve", return_value=""), \
             mock.patch.object(stages, "_cloudflare_ranges", return_value=["x"]):
            stages.origin_hunt("a.com", Path(tempfile.mkdtemp()), {"ip": "1.1.1.1"})
        self.assertIsNone(events._skip_reason)


class TestLiveHostsSkipCancelsQueue(_EventsBase):
    def test_skip_drops_queued_probes(self):
        import time
        events._set_current_stage("live")
        (self.tmp / "control").write_text("skip live\n")
        calls = []

        def slow(sub, timeout):
            calls.append(sub)
            time.sleep(0.05)
            return {"host": sub, "url": "", "status": 200, "server": "",
                    "cloudflare": False}

        hosts = [f"h{i}.example.com" for i in range(300)]
        with mock.patch.object(stages, "_probe_host", side_effect=slow), \
             mock.patch.object(utils, "log"):
            with self.assertRaises(events.StageSkipped):
                stages.live_hosts(hosts, Path(tempfile.mkdtemp()), threads=4)
        self.assertLess(len(calls), 60)


if __name__ == "__main__":
    unittest.main(verbosity=2)
