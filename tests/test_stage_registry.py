"""C5: stage registry parity with the old hard-coded cli lists."""
import argparse

from runner import stage_registry as sr

# The exact literal that lived in cli.py before the registry.
LEGACY_STAGE_IDS = ["subs", "panel", "live", "cf", "origin", "nmap", "waf", "dork", "tls",
                    "nikto", "vuln", "content", "api", "param", "secret", "metis",
                    "headers", "cors", "tech", "headi"]
LEGACY_OPT_IN = {"nmap", "tls", "nikto", "metis", "headi"}


def _args(**kw):
    ns = argparse.Namespace(nmap=False, tls=False, nikto=False, metis=False, headi=False)
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


def _legacy_planned(args, skip):
    return [s for s in LEGACY_STAGE_IDS
            if s not in skip and (s not in LEGACY_OPT_IN or getattr(args, s))]


class TestParity:
    def test_stage_ids_identical(self):
        assert sr.STAGE_IDS == LEGACY_STAGE_IDS

    def test_total_stages(self):
        assert sr.TOTAL_STAGES == 20

    def test_opt_in_set_identical(self):
        assert sr.OPT_IN_STAGES == LEGACY_OPT_IN

    def test_origin_deep_is_child(self):
        assert sr.SPEC["origin_deep"].parent == "origin"
        assert "origin_deep" not in sr.STAGE_IDS

    def test_planned_default(self):
        args, skip = _args(), set()
        assert sr.planned(args, skip) == _legacy_planned(args, skip)

    def test_planned_all_opt_in(self):
        args = _args(nmap=True, tls=True, nikto=True, metis=True, headi=True)
        skip = set()
        assert sr.planned(args, skip) == _legacy_planned(args, skip)

    def test_planned_with_skips(self):
        for skip in (set(), {"subs"}, {"vuln", "secret"}, {"dork", "tls", "nmap"}):
            args = _args(nmap=True, tls=True)
            assert sr.planned(args, skip) == _legacy_planned(args, skip), skip


class TestGate:
    def test_skip_blocks(self):
        ok, reason = sr.stage_allowed(sr.SPEC["subs"], _args(), {"subs"})
        assert ok is False and reason == "skipped"

    def test_opt_in_silently_skipped(self):
        ok, reason = sr.stage_allowed(sr.SPEC["nmap"], _args(), set())
        assert ok is False and reason is None

    def test_opt_in_runs_when_set(self):
        ok, _ = sr.stage_allowed(sr.SPEC["nmap"], _args(nmap=True), set())
        assert ok is True

    def test_oast_is_soft_vuln_still_runs(self):
        ok, _ = sr.stage_allowed(sr.SPEC["vuln"], _args(no_oast=True), set())
        assert ok is True
        assert sr.oast_enabled(_args(no_oast=True)) is False
