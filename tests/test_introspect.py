"""Machine-readable engine introspection: stages, doctor (tool probes), version.

Everything runs against fake tools on a temporary PATH; no real tool and no
network is ever touched.
"""
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from runner import __version__, launcher, stage_registry  # noqa: E402

ENTRY = ROOT / "bounty_run.py"
BRIEF_TOOLS = {
    "subfinder", "amass", "findomain", "dnsx", "dig", "curl", "openssl", "nmap",
    "wafw00f", "sslyze", "nikto", "nuclei", "ffuf", "sqlmap", "katana",
    "whatweb", "headi", "metis-autocheck", "shcheck",
}


def run_cli(*args, path=None, cwd=None, extra_env=None, timeout=60):
    env = {k: v for k, v in os.environ.items() if k not in ("HEADI_BIN", "BOUNTY_TUI")}
    if path is not None:
        env["PATH"] = str(path)
    env.update(extra_env or {})
    return subprocess.run([sys.executable, str(ENTRY), "introspect", *args],
                          capture_output=True, text=True, cwd=cwd, env=env,
                          timeout=timeout, stdin=subprocess.DEVNULL)


def fake_tool(bindir: Path, name: str, body: str) -> Path:
    p = bindir / name
    p.write_text("#!/bin/sh\nPATH=/usr/bin:/bin\n" + body + "\n")
    p.chmod(0o755)
    return p


def doctor(path, cwd, **kw):
    r = run_cli("doctor", path=path, cwd=cwd, **kw)
    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout)
    assert data["schema"] == 2
    return {t["name"]: t for t in data["tools"]}, r


def test_stages_match_registry(tmp_path):
    r = run_cli("stages", cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout)
    assert data["schema"] == 2
    stages = data["stages"]
    assert len(stages) == 21 == len(stage_registry.STAGES)
    assert [s["id"] for s in stages] == [s.id for s in stage_registry.STAGES]
    by_id = {s["id"]: s for s in stages}
    assert by_id["origin_deep"]["parent"] == "origin"
    assert by_id["origin"]["parent"] is None
    for spec in stage_registry.STAGES:
        s = by_id[spec.id]
        assert set(s) == {"id", "num", "title", "tier", "caps", "opt_in", "parent"}
        assert s["num"] == spec.num and s["title"] == spec.title
        assert s["tier"] == spec.tier.name.lower()
        assert s["caps"] == sorted(c.value for c in spec.caps)
        assert s["opt_in"] is bool(spec.opt_in_flag)
    assert by_id["vuln"]["caps"] == ["oast"]
    assert by_id["nmap"]["opt_in"] is True and by_id["subs"]["opt_in"] is False


def test_stages_output_is_deterministic(tmp_path):
    assert run_cli("stages", cwd=tmp_path).stdout == run_cli("stages", cwd=tmp_path).stdout


def test_doctor_missing_tool_reports_missing(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    tools, _ = doctor(empty, tmp_path, extra_env={"HOME": str(home), "GOPATH": str(home / "go"), "GOBIN": ""})
    for name in BRIEF_TOOLS - {"shcheck"}:
        t = tools[name]
        assert t["status"] == "missing", name
        assert t["path"] is None and t["version"] is None
        assert set(t) == {"name", "path", "version", "required_by", "optional",
                          "install_hint", "status", "install_methods"}
        assert t["install_hint"]
    # headi has no bundled binary: missing, not an exception
    assert tools["headi"]["status"] == "missing"
    # vendored shcheck needs no PATH entry
    assert tools["shcheck"]["path"].endswith("runner/vendor/shcheck.py")


def test_doctor_off_path_tool_reports_installed_needs_path(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    home = tmp_path / "home"
    gobin = home / "go" / "bin"
    gobin.mkdir(parents=True)
    fake_tool(gobin, "nuclei", 'echo "[INF] Current Version: v1.2.3"')
    local = home / ".local" / "bin"
    local.mkdir(parents=True)
    fake_tool(local, "sqlmap", "echo 1.8")
    tools, _ = doctor(empty, tmp_path, extra_env={"HOME": str(home), "GOPATH": str(home / "go")})
    assert tools["nuclei"]["status"] == "installed_needs_path"
    assert tools["nuclei"]["path"] == str(gobin / "nuclei")
    assert tools["sqlmap"]["status"] == "installed_needs_path"
    assert tools["sqlmap"]["path"] == str(local / "sqlmap")
    assert tools["ffuf"]["status"] == "missing"


def test_doctor_honors_gobin(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    gobin = tmp_path / "custom-gobin"
    gobin.mkdir()
    fake_tool(gobin, "nuclei", 'echo "[INF] Current Version: v1.2.3"')
    tools, _ = doctor(empty, tmp_path, extra_env={"HOME": str(home), "GOPATH": str(home / "go"),
                                                  "GOBIN": str(gobin)})
    assert tools["nuclei"]["status"] == "installed_needs_path"
    assert tools["nuclei"]["path"] == str(gobin / "nuclei")


def test_doctor_reports_version_and_uses_offline_flags(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "argv.log"
    for name in ("subfinder", "nuclei", "katana", "dnsx"):
        fake_tool(bindir, name, f'echo "{name} $*" >> {log}\necho "[INF] Current Version: v1.2.3"')
    fake_tool(bindir, "curl", 'echo "curl 8.1.0 (x86_64) libcurl/8.1.0"')
    fake_tool(bindir, "ffuf", 'echo "ffuf version: 2.3.0"')
    tools, _ = doctor(bindir, tmp_path)
    assert tools["curl"]["status"] == "ok" and tools["curl"]["version"] == "8.1.0"
    assert tools["ffuf"]["version"] == "2.3.0"
    assert tools["nuclei"]["path"] == str(bindir / "nuclei")
    assert tools["nuclei"]["required_by"] == ["vuln"]
    # every ProjectDiscovery probe must disable the update check
    calls = log.read_text().splitlines()
    assert sorted(c.split()[0] for c in calls) == ["dnsx", "katana", "nuclei", "subfinder"]
    for c in calls:
        assert "-duc" in c.split() and "-version" in c.split(), c
    for name in ("subfinder", "nuclei", "katana", "dnsx"):
        assert tools[name]["version"] == "1.2.3"


def test_doctor_does_not_execute_unprobeable_tools(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    marker = tmp_path / "ran"
    for name in ("headi", "metis-autocheck"):
        fake_tool(bindir, name, f"echo {name} >> {marker}")
    tools, _ = doctor(bindir, tmp_path)
    assert not marker.exists()
    for name in ("headi", "metis-autocheck"):
        assert tools[name]["status"] == "unknown_version"
        assert tools[name]["path"] == str(bindir / name)
        assert tools[name]["version"] is None
    assert tools["shcheck"]["status"] == "unknown_version"


def test_doctor_hung_version_probe_times_out(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    pidfile = tmp_path / "child.pid"
    fake_tool(bindir, "dig", f"sleep 120 &\necho $! > {pidfile}\nwait")
    start = time.monotonic()
    tools, _ = doctor(bindir, tmp_path)
    assert time.monotonic() - start < 12
    assert tools["dig"]["status"] == "unknown_version"
    assert tools["dig"]["path"] == str(bindir / "dig")
    pid = int(pidfile.read_text())
    for _ in range(40):  # the whole process group must be gone, no orphan
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        os.kill(pid, 9)
        pytest.fail("probe child survived the timeout")


def test_doctor_probe_is_sandboxed(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    out = tmp_path / "probe.txt"
    # stdin must be closed (read returns at once) and cwd must not accept files
    fake_tool(bindir, "openssl",
              f'read x; echo "stdin_rc=$?" > {out}\n'
              f'(touch stray.txt 2>/dev/null && echo wrote >> {out}) || echo ro >> {out}\n'
              f'pwd >> {out}\necho "OpenSSL 3.0.1 14 Dec 2021"')
    tools, _ = doctor(bindir, work)
    lines = out.read_text().split()
    assert lines[0] == "stdin_rc=1"  # stdin is at EOF, not a terminal
    assert "ro" in lines and "wrote" not in lines
    assert Path(lines[-1]).resolve() != work.resolve()
    assert list(work.iterdir()) == []
    assert tools["openssl"]["version"] == "3.0.1"


def test_doctor_output_is_capped(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake_tool(bindir, "nmap", "yes 'Nmap version 7.9 ( https://nmap.org )' | head -c 200000000")
    start = time.monotonic()
    tools, r = doctor(bindir, tmp_path)
    assert time.monotonic() - start < 12
    assert tools["nmap"]["status"] in ("ok", "unknown_version")
    assert len(r.stdout) < 20000


def test_doctor_no_shell_interpretation(tmp_path):
    bindir = tmp_path / "bin dir; touch pwned"
    bindir.mkdir()
    fake_tool(bindir, "ffuf", "echo 'ffuf version: 1.0.0'")
    tools, _ = doctor(bindir, tmp_path)
    assert tools["ffuf"]["version"] == "1.0.0"
    assert not (tmp_path / "pwned").exists()


def _discover_invoked_tools():
    """Tools the engine resolves or spawns, discovered from the engine source."""
    found = set()
    pats = [
        re.compile(r'\b(?:have|which)\(\s*["\']([A-Za-z0-9_-]+)["\']'),
        re.compile(r'SHIM_NAME\s*=\s*["\']([A-Za-z0-9_-]+)["\']'),
        re.compile(r'\brun\(\s*f?["\']([a-z][a-z0-9_-]+) '),
        re.compile(r'^\s+f?"([a-z][a-z0-9_-]+) -', re.M),
    ]
    for f in (ROOT / "runner").glob("*.py"):
        src = f.read_text()
        for p in pats:
            found.update(p.findall(src))
    vendored = {p.stem for p in (ROOT / "runner" / "vendor").glob("*.py")}
    return found | vendored


def test_doctor_lists_every_invoked_tool(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    tools, _ = doctor(empty, tmp_path)
    discovered = _discover_invoked_tools()
    assert {"nuclei", "headi", "curl", "shcheck"} <= discovered  # discovery works
    assert discovered <= set(tools), f"tools without a doctor entry: {discovered - set(tools)}"
    assert BRIEF_TOOLS <= set(tools)
    stage_ids = {s.id for s in stage_registry.STAGES}
    for t in tools.values():
        assert t["required_by"], t["name"]
        assert set(t["required_by"]) <= stage_ids


def test_version_json(tmp_path):
    r = run_cli("version", cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == {"schema": 2, "engine_version": __version__,
                                    "events_schema": 1}


@pytest.mark.parametrize("sub", ["stages", "doctor", "version"])
def test_stdout_is_pure_json(sub, tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    outputs = ROOT / "outputs"
    before = sorted(p.name for p in outputs.iterdir()) if outputs.exists() else None
    r = run_cli(sub, path=tmp_path, cwd=work)
    assert r.returncode == 0, r.stderr
    assert r.stdout.endswith("\n") and r.stdout.count("\n") == 1
    json.loads(r.stdout)
    assert "Bounty Runner" not in r.stdout
    assert list(work.iterdir()) == []
    after = sorted(p.name for p in outputs.iterdir()) if outputs.exists() else None
    assert before == after


@pytest.mark.parametrize("args", [["bogus"], []])
def test_unknown_subcommand_exits_2(args, tmp_path):
    r = run_cli(*args, cwd=tmp_path)
    assert r.returncode == 2
    assert r.stdout == ""
    assert "introspect" in r.stderr
    assert list(tmp_path.iterdir()) == []


def test_introspect_never_execs_tui(tmp_path):
    # Even on a terminal, any argument keeps the CLI path.
    assert launcher.should_launch_tui(["introspect"], True) is False
    assert launcher.should_launch_tui(["introspect", "stages"], True) is False
    marker = tmp_path / "tui_ran"
    tui = fake_tool(tmp_path, "tui", f"touch {marker}")
    r = run_cli("version", cwd=tmp_path, extra_env={"BOUNTY_TUI": str(tui)})
    assert r.returncode == 0 and not marker.exists()


def test_existing_dispatch_unchanged(tmp_path):
    env = dict(os.environ)
    r = subprocess.run([sys.executable, str(ENTRY), "track", "--help"],
                       capture_output=True, text=True, cwd=tmp_path, env=env,
                       stdin=subprocess.DEVNULL, timeout=60)
    assert r.returncode == 0 and "track" in (r.stdout + r.stderr).lower()
    r = subprocess.run([sys.executable, str(ENTRY), "--help"],
                       capture_output=True, text=True, cwd=tmp_path, env=env,
                       stdin=subprocess.DEVNULL, timeout=60)
    assert r.returncode == 0
    r = subprocess.run([sys.executable, str(ENTRY)],
                       capture_output=True, text=True, cwd=tmp_path, env=env,
                       stdin=subprocess.DEVNULL, timeout=60)
    assert r.returncode == 2  # bare, non-interactive: usage error as before


def test_doctor_adds_install_methods(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    tools, _ = doctor(empty, tmp_path)
    for name, t in tools.items():
        assert t["install_methods"], name
        for m in t["install_methods"]:
            assert m["method"] in {"go", "apt", "pipx", "manual"}, name
            assert m["package"], name
    for name in ("wafw00f", "sslyze"):
        methods = [m["method"] for m in tools[name]["install_methods"]]
        assert methods == ["pipx", "apt"], name
    assert [m["method"] for m in tools["subfinder"]["install_methods"]] == ["go"]
    assert [m["method"] for m in tools["amass"]["install_methods"]] == ["manual"]


def test_doctor_keeps_legacy_fields(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    tools, r = doctor(empty, tmp_path)
    assert json.loads(r.stdout)["schema"] == 2
    for name, t in tools.items():
        assert t["install_hint"] and t["status"], name
