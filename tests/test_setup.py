"""Tests for ``bounty-run setup`` (subprocess.run and shutil.which are mocked)."""
from __future__ import annotations

import json
from types import SimpleNamespace
from unittest import mock

from runner import introspect, setup


def _ok(*_a, **_k):
    return SimpleNamespace(returncode=0, stdout="", stderr="")


def _which_factory(present: set[str]):
    return lambda name, *a, **k: f"/usr/bin/{name}" if name in present else None


def _run(argv, present, run_side_effect=_ok, capsys=None):
    with mock.patch("runner.setup.shutil.which", side_effect=_which_factory(present)), \
         mock.patch("runner.introspect._resolve", side_effect=lambda n: _which_factory(present)(n)), \
         mock.patch("runner.setup.subprocess.run", side_effect=run_side_effect) as run:
        rc = setup.main(argv)
    return rc, run


def _cmds(run):
    return [c.args[0] for c in run.call_args_list]


def _results(capsys):
    return {r["name"]: r for r in json.loads(capsys.readouterr().out)["results"]}


def test_setup_dry_run_lists_without_running(capsys):
    rc, run = _run(["--dry-run", "--all-core"], {"go"})
    assert rc == 0
    run.assert_not_called()
    assert "subfinder" in capsys.readouterr().out


def test_setup_go_tool_runs_go_install(capsys):
    rc, run = _run(["ffuf", "--json"], {"go"})
    assert ["go", "install", "github.com/ffuf/ffuf/v2@latest"] in _cmds(run)


def test_setup_all_core_batches_apt_once(capsys):
    rc, run = _run(["--all-core", "--yes", "--json"], {"go", "pipx"})
    cmds = _cmds(run)
    apt = [c for c in cmds if c[:3] == ["sudo", "apt", "install"]]
    assert len(apt) == 1
    assert "-y" in apt[0]
    for pkg in ("curl", "dnsutils", "sqlmap", "whatweb"):
        assert pkg in apt[0]
    gos = [c for c in cmds if c[:2] == ["go", "install"]]
    assert len(gos) >= 2 and all(len(c) == 3 for c in gos)


def test_setup_dual_method_prefers_pipx_when_present(capsys):
    rc, run = _run(["wafw00f", "--json"], {"pipx"})
    assert ["pipx", "install", "wafw00f"] in _cmds(run)
    assert not [c for c in _cmds(run) if c[:2] == ["sudo", "apt"]]


def test_setup_dual_method_falls_back_to_apt_without_pipx(capsys):
    rc, run = _run(["wafw00f", "nmap", "--json"], set())
    apt = [c for c in _cmds(run) if c[:3] == ["sudo", "apt", "install"]]
    assert len(apt) == 1 and "wafw00f" in apt[0] and "nmap" in apt[0]
    assert not [c for c in _cmds(run) if c[0] == "pipx"]


def test_setup_installed_not_on_path(capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    gobin = tmp_path / "gopath" / "bin"
    gobin.mkdir(parents=True)
    (gobin / "ffuf").write_text("x")

    def side(argv, *a, **k):
        if argv[:3] == ["go", "env", "GOPATH"]:
            return SimpleNamespace(returncode=0, stdout=str(tmp_path / "gopath") + "\n", stderr="")
        return _ok()

    rc, run = _run(["ffuf", "--json"], {"go"}, side)
    r = _results(capsys)["ffuf"]
    assert r["outcome"] == "installed_needs_path"
    assert str(gobin) in r["detail"]
    assert rc == 0


def test_setup_already_ok_skips(capsys):
    rc, run = _run(["curl", "--json"], {"curl"})
    run.assert_not_called()
    assert _results(capsys)["curl"]["outcome"] == "already_ok"


def test_setup_failed_install_exits_nonzero(capsys):
    rc, run = _run(["ffuf", "--json"], {"go"}, lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="boom"))
    assert rc != 0
    assert _results(capsys)["ffuf"]["outcome"] == "failed"


def test_setup_manual_and_go_missing(capsys):
    rc, run = _run(["amass", "ffuf", "--json"], set())
    res = _results(capsys)
    assert res["amass"]["outcome"] == "manual"
    assert res["ffuf"]["outcome"] == "failed" and "go not found" in res["ffuf"]["detail"]
    assert introspect.TOOLS  # sanity
