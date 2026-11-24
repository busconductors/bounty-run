"""Engine paths: data root, bundled resources and the shcheck command when frozen."""
import contextlib
import io
import shlex
import subprocess
import sys
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

import test_events_cli as ec

from runner import cli, events, paths, tracker

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


def test_ipintel_cache_follows_data_root(monkeypatch, tmp_path):
    from runner import ipintel
    monkeypatch.delenv("BOUNTY_RUN_IPINTEL_DIR", raising=False)
    monkeypatch.delenv("BOUNTY_RUN_DATA", raising=False)
    assert ipintel.cache_dir() == ipintel.DEFAULT_CACHE_DIR
    monkeypatch.setenv("BOUNTY_RUN_DATA", str(tmp_path))
    assert ipintel.cache_dir() == tmp_path / ".cache" / "ipintel"
    monkeypatch.setenv("BOUNTY_RUN_IPINTEL_DIR", str(tmp_path / "x"))
    assert ipintel.cache_dir() == tmp_path / "x"


def test_child_env_only_rewrites_when_frozen(monkeypatch):
    monkeypatch.delattr(sys, "frozen", raising=False)
    assert paths.child_env() is None
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    base = {"LD_LIBRARY_PATH": "/bundle", "LD_LIBRARY_PATH_ORIG": "/orig", "X": "1"}
    assert paths.child_env(base) == {"LD_LIBRARY_PATH": "/orig", "X": "1"}
    assert paths.child_env({"LD_LIBRARY_PATH": "/bundle"}) == {}


def _capture_popen(monkeypatch, module_subprocess):
    seen = {}

    class Boom(Exception):
        pass

    def fake(*a, **kw):
        seen.update(kw)
        raise Boom

    monkeypatch.setattr(module_subprocess, "Popen", fake)
    return seen


def test_introspect_probe_uses_child_env_when_frozen(monkeypatch):
    from runner import introspect
    monkeypatch.setenv("LD_LIBRARY_PATH", "/bundle")
    monkeypatch.setenv("LD_LIBRARY_PATH_ORIG", "/orig")
    seen = _capture_popen(monkeypatch, introspect.subprocess)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    with contextlib.suppress(Exception):
        introspect._probe_output(["/bin/true"])
    assert seen["env"]["LD_LIBRARY_PATH"] == "/orig"
    assert "LD_LIBRARY_PATH_ORIG" not in seen["env"]
    monkeypatch.delattr(sys, "frozen")
    seen.clear()
    with contextlib.suppress(Exception):
        introspect._probe_output(["/bin/true"])
    assert seen["env"] is None


def test_wafw00f_socks_probe_uses_child_env_when_frozen(monkeypatch, tmp_path):
    script = tmp_path / "wafw00f"
    script.write_text("#!/usr/bin/env python3\n")
    monkeypatch.setattr("shutil.which", lambda _n: str(script))
    monkeypatch.setenv("LD_LIBRARY_PATH", "/bundle")
    monkeypatch.setenv("LD_LIBRARY_PATH_ORIG", "/orig")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    seen = {}

    def fake_run(argv, **kw):
        seen.update(kw)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert cli._wafw00f_has_socks() is True
    assert seen["env"]["LD_LIBRARY_PATH"] == "/orig"
