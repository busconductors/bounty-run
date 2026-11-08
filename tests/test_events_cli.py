"""Phase 13a: cli --events wiring, golden stdout, stage wrapper, partial report.

Every stage entry point is mocked, so no network or real tool is touched.

    cd ~/tools/bounty-run && python3 -m pytest tests/test_events_cli.py -q
"""

import io
import json
import sys
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner import (api_endpoints, cli, dork_scan, events, headi_scan,  # noqa: E402
                    http_headers, metis_check, nikto_scan, nmap_scan, origin_deep,
                    panel_detect, param_scan, secret_scan, stages, tech_scan,
                    tls_scan, waf_scan)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "cli_golden_stdout.txt"
BASE_ARGV = ["a.com", "--no-banner", "--no-track"]


def _f(template, severity, host="a.com", path="/"):
    return {"severity": severity, "template": template, "name": template,
            "url": f"https://{host}{path}", "host": host, "evidence": ""}


ROWS = [
    {"host": "a.com", "status": 200, "server": "nginx", "cloudflare": False},
    {"host": "www.a.com", "status": 301, "server": "nginx", "cloudflare": False},
    {"host": "dead.a.com", "status": None, "server": "", "cloudflare": False},
]

# (module, attribute) -> fixed return value
STAGE_MOCKS = {
    "subdomain_enum": (stages, "subdomain_enum", ["a.com", "www.a.com", "dead.a.com"]),
    "panel_detect": (panel_detect, "panel_detect", [_f("panel:grafana", "low", "www.a.com")]),
    "live_hosts": (stages, "live_hosts", ROWS),
    "cloudflare_detect": (stages, "cloudflare_detect",
                          {"target": "a.com", "cloudflare": False, "evidence": []}),
    "origin_hunt": (stages, "origin_hunt", []),
    "origin_deep": (origin_deep, "origin_deep", []),
    "nmap_scan": (nmap_scan, "nmap_scan", []),
    "waf_scan": (waf_scan, "waf_scan", [_f("waf:cloudflare", "info")]),
    "dork_scan": (dork_scan, "dork_scan", [_f("dork:exposed-file", "medium", path="/backup.sql")]),
    "tls_scan": (tls_scan, "tls_scan", []),
    "nikto_scan": (nikto_scan, "nikto_scan", []),
    "vuln_scan": (stages, "vuln_scan", [_f("CVE-2021-0001", "critical"),
                                        _f("exposed-git", "high", path="/.git/config")]),
    "content_discovery": (stages, "content_discovery", ["https://a.com/admin", "https://a.com/login"]),
    "api_endpoints_scan": (api_endpoints, "api_endpoints_scan", [_f("api:swagger", "info", path="/swagger")]),
    "param_scan": (param_scan, "param_scan", []),
    "secret_scan": (secret_scan, "secret_scan", [_f("secret:aws-key", "high", path="/app.js")]),
    "metis_check": (metis_check, "metis_check", []),
    "security_headers_scan": (http_headers, "security_headers_scan", [_f("header:missing-hsts", "low")]),
    "cors_scan": (http_headers, "cors_scan", []),
    "tech_scan": (tech_scan, "tech_scan", [_f("tech:nginx", "info")]),
    "headi_scan": (headi_scan, "headi_scan", []),
}


def run_cli(extra=(), overrides=None):
    """Run cli.main with every stage mocked; return (rc, stdout, outdir, exc).

    stdout has the temporary outdir replaced by ``<OUT>``. ``overrides`` maps
    a STAGE_MOCKS name to a side_effect (callable or exception instance).
    """
    overrides = overrides or {}
    buf = io.StringIO()
    tmpdir = tempfile.TemporaryDirectory()
    tmp = tmpdir.name
    rc, exc = None, None
    with ExitStack() as st:
        for name, (mod, attr, ret) in STAGE_MOCKS.items():
            side = overrides.get(name)
            if side is None:
                st.enter_context(mock.patch.object(mod, attr, return_value=ret))
            else:
                st.enter_context(mock.patch.object(mod, attr, side_effect=side))
        st.enter_context(mock.patch("time.strftime", return_value="2026-11-08 12:00:00"))
        st.enter_context(mock.patch("time.monotonic", return_value=1000.0))
        st.enter_context(mock.patch.dict("os.environ", {"NO_COLOR": "1"}))
        st.enter_context(redirect_stdout(buf))
        try:
            rc = cli.main(BASE_ARGV + ["-o", tmp] + list(extra))
        except BaseException as e:  # surfaced to the caller
            exc = e
        finally:
            events.reset()
    out = buf.getvalue().replace(tmp, "<OUT>")
    return rc, out, tmpdir, exc


def read_events(outdir: Path) -> list[dict]:
    p = Path(outdir) / "events.jsonl"
    return [json.loads(ln) for ln in p.read_text().splitlines()]


def stage_ends(evs):
    return {e["stage"]: e for e in evs if e["type"] == "stage_end"}


class TestGoldenStdout(unittest.TestCase):
    def test_stdout_unchanged_without_events(self):
        rc, out, tmp, exc = run_cli()
        tmp.cleanup()
        self.assertIsNone(exc)
        self.assertEqual(rc, 0)
        self.assertEqual(out, FIXTURE.read_text())

    def test_stdout_unchanged_with_events(self):
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        rc, out, tmp, exc = run_cli(["--events", str(Path(tmpdir.name) / "events.jsonl")])
        tmp.cleanup()
        self.assertIsNone(exc)
        self.assertEqual(rc, 0)
        self.assertEqual(out, FIXTURE.read_text())
        self.assertTrue((Path(tmpdir.name) / "events.jsonl").exists())


def run_with_events(overrides=None, extra=()):
    """Like run_cli but with --events <outdir>/events.jsonl."""
    holder = {}
    orig_main = cli.main

    def main_wrapper(argv):
        outdir = argv[argv.index("-o") + 1]
        holder["outdir"] = outdir
        return orig_main(argv + ["--events", str(Path(outdir) / "events.jsonl")])

    with mock.patch.object(cli, "main", main_wrapper):
        rc, out, tmp, exc = run_cli(extra, overrides)
    return rc, out, tmp, exc


class TestEventSequence(unittest.TestCase):
    def test_planned_stages(self):
        args = cli.build_parser().parse_args(["a.com"])
        self.assertEqual(cli.PLANNED_STAGES(args, set()), [
            "subs", "panel", "live", "cf", "origin", "waf", "dork", "vuln",
            "content", "api", "param", "secret", "headers", "cors", "tech"])
        args = cli.build_parser().parse_args(
            ["a.com", "--nmap", "--tls", "--nikto", "--metis", "--headi"])
        self.assertEqual(cli.PLANNED_STAGES(args, {"subs", "origin", "vuln"}), [
            "panel", "live", "cf", "nmap", "waf", "dork", "tls", "nikto",
            "content", "api", "param", "secret", "metis", "headers", "cors",
            "tech", "headi"])

    def test_event_sequence_ok_run(self):
        rc, _, tmp, exc = run_with_events()
        self.addCleanup(tmp.cleanup)
        self.assertIsNone(exc)
        self.assertEqual(rc, 0)
        evs = read_events(tmp.name)
        for e in evs:
            self.assertEqual(e["v"], 1)
        types = [e["type"] for e in evs if e["type"] != "log"]
        self.assertEqual(types[0], "run_start")
        self.assertEqual(types[-1], "run_end")
        run_start = evs[0]
        self.assertEqual(run_start["target"], "a.com")
        self.assertNotIn("events", run_start["flags"])
        planned = run_start["stages"]
        args = cli.build_parser().parse_args(["a.com"])
        self.assertEqual(planned, cli.PLANNED_STAGES(args, set()))
        st_evs = [e for e in evs if e["type"] in ("stage_start", "stage_end")]
        expected = []
        for s in planned:
            expected += [("stage_start", s), ("stage_end", s)]
        self.assertEqual([(e["type"], e["stage"]) for e in st_evs], expected)
        ends = stage_ends(evs)
        self.assertEqual(ends["origin"]["status"], "skipped")
        self.assertEqual(ends["origin"]["reason"], "no cloudflare")
        for s in planned:
            if s != "origin":
                self.assertEqual(ends[s]["status"], "ok", s)
                self.assertNotIn("reason", ends[s])
            self.assertIsInstance(ends[s]["duration_ms"], int)
        self.assertEqual(ends["subs"]["counts"], {"subdomains": 3})
        self.assertEqual(ends["live"]["counts"], {"live": 2})
        self.assertEqual(ends["vuln"]["counts"], {"findings": 2})
        self.assertEqual(ends["content"]["counts"], {"content": 2})
        end = evs[-1]
        self.assertEqual(end["status"], "ok")
        self.assertEqual(end["totals"], {"critical": 1, "high": 2, "medium": 1,
                                         "low": 2, "info": 3})
        self.assertEqual(end["report"], str(Path(tmp.name) / "FINDINGS.md"))
        self.assertEqual(end["summary"], str(Path(tmp.name) / "SUMMARY.md"))
        self.assertNotIn("error", end)
        run_json = json.loads((Path(tmp.name) / "run.json").read_text())
        self.assertEqual(run_json["target"], "a.com")
        self.assertNotIn("events", run_json["flags"])

    def test_skip_mid_pipeline_continues(self):
        rc, _, tmp, exc = run_with_events({"vuln_scan": events.StageSkipped("vuln")})
        self.addCleanup(tmp.cleanup)
        self.assertIsNone(exc)
        self.assertEqual(rc, 0)
        evs = read_events(tmp.name)
        ends = stage_ends(evs)
        self.assertEqual(ends["vuln"]["status"], "skipped")
        self.assertEqual(ends["content"]["status"], "ok")
        self.assertEqual(evs[-1]["type"], "run_end")
        self.assertEqual(evs[-1]["status"], "ok")

    def test_tool_missing_reason_reported(self):
        def no_tool(*a, **k):
            events.mark_skipped("tool missing: wafw00f")
            return []
        rc, _, tmp, exc = run_with_events({"waf_scan": no_tool})
        self.addCleanup(tmp.cleanup)
        ends = stage_ends(read_events(tmp.name))
        self.assertEqual(ends["waf"]["status"], "skipped")
        self.assertEqual(ends["waf"]["reason"], "tool missing: wafw00f")
        # the reason must not leak into the next stage
        self.assertEqual(ends["dork"]["status"], "ok")

    def test_cancel_writes_partial_report(self):
        rc, _, tmp, exc = run_with_events({"content_discovery": events.RunCancelled()})
        self.addCleanup(tmp.cleanup)
        self.assertIsNone(exc)
        self.assertEqual(rc, 130)
        evs = read_events(tmp.name)
        ends = stage_ends(evs)
        self.assertEqual(ends["content"]["status"], "cancelled")
        self.assertNotIn("api", ends)
        md = (Path(tmp.name) / "FINDINGS.md").read_text()
        for t in ("panel:grafana", "waf:cloudflare", "dork:exposed-file", "CVE-2021-0001"):
            self.assertIn(t, md)
        self.assertNotIn("secret:aws-key", md)
        self.assertTrue((Path(tmp.name) / "findings.json").exists())
        self.assertTrue((Path(tmp.name) / "SUMMARY.md").exists())
        self.assertEqual(evs[-1]["type"], "run_end")
        self.assertEqual(evs[-1]["status"], "cancelled")

    def test_cancel_in_first_stage(self):
        rc, _, tmp, exc = run_with_events({"subdomain_enum": events.RunCancelled()})
        self.addCleanup(tmp.cleanup)
        self.assertIsNone(exc)
        self.assertEqual(rc, 130)
        evs = read_events(tmp.name)
        self.assertEqual(stage_ends(evs)["subs"]["status"], "cancelled")
        self.assertTrue((Path(tmp.name) / "FINDINGS.md").exists())
        self.assertEqual(evs[-1]["status"], "cancelled")

    def test_unhandled_error_emits_failed(self):
        rc, _, tmp, exc = run_with_events({"dork_scan": ValueError("boom")})
        self.addCleanup(tmp.cleanup)
        self.assertIsInstance(exc, ValueError)
        evs = read_events(tmp.name)
        self.assertEqual(stage_ends(evs)["dork"]["status"], "failed")
        self.assertEqual(evs[-1]["type"], "run_end")
        self.assertEqual(evs[-1]["status"], "failed")
        self.assertIn("ValueError", evs[-1]["error"])

    def test_keyboard_interrupt_emits_failed(self):
        rc, _, tmp, exc = run_with_events({"dork_scan": KeyboardInterrupt()})
        self.addCleanup(tmp.cleanup)
        self.assertIsInstance(exc, KeyboardInterrupt)
        evs = read_events(tmp.name)
        self.assertEqual(stage_ends(evs)["dork"]["status"], "failed")
        self.assertEqual(evs[-1]["type"], "run_end")
        self.assertEqual(evs[-1]["status"], "failed")
        self.assertIn("KeyboardInterrupt", evs[-1]["error"])
        self.assertFalse((Path(tmp.name) / "FINDINGS.md").exists())

    def test_finish_error_emits_failed(self):
        with mock.patch.object(cli.dashboard, "write_run_summary",
                               side_effect=OSError("disk full")):
            rc, _, tmp, exc = run_with_events()
        self.addCleanup(tmp.cleanup)
        self.assertIsInstance(exc, OSError)
        evs = read_events(tmp.name)
        self.assertEqual(evs[-1]["status"], "failed")
        self.assertIn("disk full", evs[-1]["error"])


class TestStageContextManager(unittest.TestCase):
    def tearDown(self):
        events.reset()

    def test_disabled_is_noop(self):
        with events.stage("subs") as sc:
            sc.counts["x"] = 1
        self.assertEqual(sc.counts, {"x": 1})
        with self.assertRaises(ValueError):
            with events.stage("subs"):
                raise ValueError("x")


if __name__ == "__main__":
    unittest.main()
