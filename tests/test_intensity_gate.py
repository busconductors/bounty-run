"""C7: --intensity / --no-oast / --allow-auth flags."""
import argparse

from runner import cli, stage_registry as sr


def _parse(*argv):
    return cli.build_parser().parse_args(["example.com", *argv])


class TestFlagDefaults:
    def test_default_intensity_is_intrusive(self):
        assert _parse().intensity == "intrusive"

    def test_default_oast_enabled(self):
        assert sr.oast_enabled(_parse()) is True

    def test_no_oast_flag(self):
        assert sr.oast_enabled(_parse("--no-oast")) is False


class TestPlanned:
    def test_passive_plans_only_passive_stages(self):
        args = _parse("--intensity", "passive")
        assert sr.planned(args, set()) == ["subs", "panel", "dork"]

    def test_active_excludes_intrusive(self):
        args = _parse("--intensity", "active", "--nmap", "--nikto", "--metis", "--headi")
        plan = sr.planned(args, set())
        for intrusive in ("nmap", "nikto", "param", "metis", "headi"):
            assert intrusive not in plan

    def test_default_plan_matches_legacy(self):
        args = _parse()
        assert sr.planned(args, set()) == [
            "subs", "panel", "live", "cf", "origin", "waf", "dork",
            "vuln", "content", "api", "param", "secret", "headers", "cors", "tech",
        ]


class TestOptInAboveCeiling:
    def test_opt_in_above_ceiling_blocked_with_reason(self):
        args = _parse("--intensity", "active", "--nmap")
        ok, reason = sr.stage_allowed(sr.SPEC["nmap"], args, set())
        assert ok is False
        assert reason == "intensity: intrusive > active"


class TestNucleiNiFlag:
    def test_no_oast_appends_ni(self, tmp_path, monkeypatch):
        from runner import stages
        cmds = []
        monkeypatch.setattr(stages.utils, "have", lambda tool: True)
        monkeypatch.setattr(stages, "_is_global", lambda ip: True)
        monkeypatch.setattr(stages, "_resolve", lambda h: "1.2.3.4")
        monkeypatch.setattr(stages, "_patience_banner", lambda: None)
        monkeypatch.setattr(stages.utils, "run",
                            lambda cmd, **kw: cmds.append(cmd))
        monkeypatch.setattr(stages, "_parse_nuclei_jsonl", lambda p: [])
        rows = [{"host": "example.com", "status": 200}]
        stages.vuln_scan("example.com", tmp_path, rows, oast=False)
        assert any(" -ni " in c for c in cmds), cmds

    def test_oast_default_no_ni(self, tmp_path, monkeypatch):
        from runner import stages
        cmds = []
        monkeypatch.setattr(stages.utils, "have", lambda tool: True)
        monkeypatch.setattr(stages, "_is_global", lambda ip: True)
        monkeypatch.setattr(stages, "_resolve", lambda h: "1.2.3.4")
        monkeypatch.setattr(stages, "_patience_banner", lambda: None)
        monkeypatch.setattr(stages.utils, "run",
                            lambda cmd, **kw: cmds.append(cmd))
        monkeypatch.setattr(stages, "_parse_nuclei_jsonl", lambda p: [])
        rows = [{"host": "example.com", "status": 200}]
        stages.vuln_scan("example.com", tmp_path, rows, oast=True)
        assert all(" -ni " not in c for c in cmds), cmds
