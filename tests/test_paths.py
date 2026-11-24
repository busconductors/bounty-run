"""Engine paths: data root, bundled resources and the shcheck command when frozen."""
import contextlib
import io
import shlex
import subprocess
import sys
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

from runner import cli, events, paths, tracker

import test_events_cli as ec

REPO = Path(__file__).resolve().parents[1]


def test_data_root_default_is_repo_outputs(monkeypatch):
    monkeypatch.delenv("BOUNTY_RUN_DATA", raising=False)
    assert paths.data_root() == REPO / "outputs"
    monkeypatch.setenv("BOUNTY_RUN_DATA", "")
    assert paths.data_root() == REPO / "outputs"


def test_data_root_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("BOUNTY_RUN_DATA", str(tmp_path / "d"))
    assert paths.data_root() == tmp_path / "d"


def test_tracker_and_subs_cache_follow_data_root(monkeypatch, tmp_path):
    monkeypatch.setenv("BOUNTY_RUN_DATA", str(tmp_path))
    monkeypatch.setattr(tracker, "DEFAULT_DB", None)
    conn = tracker.get_db()
    conn.close()
    assert (tmp_path / "tracker.db").exists()

    assert cli._resolve_dir("") == tmp_path
    assert cli._resolve_outdir("a.com", ts="T") == tmp_path / "a.com" / "T"

    seen = {}

    def fake_subs(target, outdir, **kw):
        seen["cache_dir"] = kw.get("cache_dir")
        return ["a.com"]

    ec.run_cli(overrides={"subdomain_enum": fake_subs})  # -o given; cache dir still follows data root
    assert seen["cache_dir"] == tmp_path / "a.com" / ".cache"


def test_resource_frozen_uses_meipass(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    assert paths.resource("assets/startup_banner.txt") == tmp_path / "assets" / "startup_banner.txt"
    monkeypatch.delattr(sys, "frozen")
    assert paths.resource("assets/x") == REPO / "assets" / "x"


def test_shcheck_command_unfrozen_unchanged(monkeypatch):
    monkeypatch.delattr(sys, "frozen", raising=False)
    assert paths.shcheck_command() == f"python3 {REPO / 'runner' / 'vendor' / 'shcheck.py'}"


def test_shcheck_command_frozen_uses_executable(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", "/opt/My App/bounty-run")
    cmd = paths.shcheck_command()
    assert shlex.split(cmd) == ["/opt/My App/bounty-run", "_shcheck"]


def test_shcheck_dispatch_only_when_frozen():
    r = subprocess.run([sys.executable, str(REPO / "bounty_run.py"), "_shcheck"],
                       capture_output=True, text=True, cwd=REPO, timeout=60)
    assert r.returncode == 2
    assert "invalid target" in r.stderr


def test_fake_run_with_data_env_writes_nothing_under_repo(monkeypatch, tmp_path):
    def snapshot():
        return sorted(str(p) for p in REPO.rglob("*")
                      if ".git" not in p.parts and "__pycache__" not in p.parts
                      and ".pytest_cache" not in p.parts)

    data = tmp_path / "data"
    monkeypatch.setenv("BOUNTY_RUN_DATA", str(data))
    monkeypatch.setattr(tracker, "DEFAULT_DB", None)
    before = snapshot()
    buf = io.StringIO()
    with ExitStack() as st:
        for mod, attr, ret in ec.STAGE_MOCKS.values():
            st.enter_context(mock.patch.object(mod, attr, return_value=ret))
        st.enter_context(contextlib.redirect_stdout(buf))
        try:
            rc = cli.main(["a.com", "--no-banner"])
        finally:
            events.reset()
    assert rc == 0
    assert snapshot() == before
    assert list(data.glob("a.com/*/findings.json"))
    assert (data / "tracker.db").exists()
