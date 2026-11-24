#!/usr/bin/env python3
"""Smoke test for the frozen engine sidecar.

Usage: python3 packaging/smoke_sidecar.py dist/bounty-run

Checks the introspect subcommands, then performs an offline run against
``smoke.invalid`` (RFC 2606, never resolves) with a hostile environment: only
fake tool shims on PATH, a ``python3`` shim that records its use, an empty
read-only cwd, and HOME / BOUNTY_RUN_DATA pointing at temp dirs. The run must
emit a schema-valid event stream and write nothing outside those temp dirs.
Exits non-zero with a message on the first failure.
"""
from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = "smoke.invalid"
RUN_TIMEOUT_S = 240
INTROSPECT_TIMEOUT_S = 60


class Failure(Exception):
    pass


def check(cond: bool, msg: str) -> None:
    if not cond:
        raise Failure(msg)


def snapshot(root: Path) -> dict[str, tuple[int, int]]:
    out = {}
    for p in sorted(root.rglob("*")):
        st = p.lstat()
        out[str(p.relative_to(root))] = (st.st_mtime_ns, st.st_size)
    return out


def introspect(exe: Path, sub: str, env: dict) -> dict:
    try:
        r = subprocess.run([str(exe), "introspect", sub], capture_output=True, text=True,
                           timeout=INTROSPECT_TIMEOUT_S, env=env, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        raise Failure(f"introspect {sub}: timed out") from None
    check(r.returncode == 0, f"introspect {sub}: exit {r.returncode}: {r.stderr.strip()[:300]}")
    try:
        return json.loads(r.stdout)
    except ValueError as e:
        raise Failure(f"introspect {sub}: invalid JSON: {e}") from None


def load_validator():
    """Reuse the schema validator of tests/test_event_contract.py (no third-party dep)."""
    spec = importlib.util.spec_from_file_location("_event_contract", ROOT / "tests" / "test_event_contract.py")
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(ROOT))
    spec.loader.exec_module(mod)
    return mod.errors, mod.SCHEMA


def write_shim(path: Path, body: str) -> None:
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)


def run_smoke(sidecar: Path) -> None:
    exe = sidecar / "bounty-run"
    check(exe.is_file() and os.access(exe, os.X_OK), f"{exe} is not an executable file")
    before = snapshot(sidecar)

    with tempfile.TemporaryDirectory(prefix="br-smoke-") as tmp_s:
        tmp = Path(tmp_s)
        shims, home, data, cwd, run_dir = (tmp / n for n in ("bin", "home", "data", "cwd", "run"))
        for d in (shims, home, data):
            d.mkdir()
        cwd.mkdir()
        marker = tmp / "python-was-called"
        # Any attempt to reach a system interpreter by name trips the marker.
        for name in ("python3", "python"):
            write_shim(shims / name, f"touch '{marker}'\nexit 97\n")
        ld_probe = tmp / "child-ld-library-path"
        # Records what a spawned tool sees: the bundle's own libs must not leak to system tools.
        write_shim(shims / "subfinder", f"echo \"$LD_LIBRARY_PATH\" > '{ld_probe}'\necho www.{TARGET}\n")
        doctor_ld = tmp / "doctor-ld-library-path"
        # `introspect doctor` probes curl --version: it must not see the bundle libs either.
        write_shim(shims / "curl", f"echo \"$LD_LIBRARY_PATH\" > '{doctor_ld}'\necho 'curl 8.0.0 (fake)'\nexit 0\n")
        write_shim(shims / "dig", "exit 0\n")

        env = {"PATH": str(shims), "HOME": str(home), "BOUNTY_RUN_DATA": str(data),
               "LANG": "C.UTF-8", "TERM": "dumb"}

        # introspect: valid JSON, exit 0, version matches the source, shcheck bundled.
        stages = introspect(exe, "stages", env)
        check(stages.get("stages"), "introspect stages: empty stage list")
        doctor = introspect(exe, "doctor", env)
        shcheck = [t for t in doctor.get("tools", []) if t.get("name") == "shcheck"]
        check(shcheck and shcheck[0].get("path") and shcheck[0].get("status") != "missing",
              f"introspect doctor: shcheck not present: {shcheck}")
        check(doctor_ld.exists(), "introspect doctor never probed the curl shim")
        check(str(sidecar) not in doctor_ld.read_text(),
              f"doctor probes inherited the bundle LD_LIBRARY_PATH: {doctor_ld.read_text().strip()}")
        check(Path(shcheck[0]["path"]).exists(), "introspect doctor: shcheck path does not exist")
        sys.path.insert(0, str(ROOT))
        from runner import __version__
        version = introspect(exe, "version", env)
        check(version.get("engine_version") == __version__,
              f"introspect version: {version.get('engine_version')!r} != runner.__version__ {__version__!r}")

        # The vendored shcheck re-enters the executable; it must not need python3.
        r = subprocess.run([str(exe), "_shcheck", "--help"], capture_output=True, text=True,
                           timeout=INTROSPECT_TIMEOUT_S, env=env, cwd=cwd, stdin=subprocess.DEVNULL)
        check(r.returncode == 0 and "usage" in (r.stdout + r.stderr).lower(),
              f"_shcheck --help: exit {r.returncode}: {r.stderr.strip()[:300]}")

        # Offline run, argv shaped like the desktop app's.
        events_path = run_dir / "events.jsonl"
        argv = [str(exe), TARGET, "-o", str(run_dir), "--events", str(events_path), "--no-banner",
                "--timeout", "2", "--threads", "2", "--no-oast", "--ipintel-offline",
                "--skip", "dork,vuln,content,api,param,secret,cors"]
        cwd.chmod(stat.S_IRUSR | stat.S_IXUSR)  # read-only, empty cwd
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=RUN_TIMEOUT_S,
                               env=env, cwd=cwd, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            raise Failure(f"run: timed out after {RUN_TIMEOUT_S}s") from None
        finally:
            cwd.chmod(stat.S_IRWXU)
        check(r.returncode == 0,
              f"run: exit {r.returncode}\nstdout: {r.stdout[-800:]}\nstderr: {r.stderr[-800:]}")
        check(not marker.exists(), "a python3/python shim was invoked: the build needs a system interpreter")
        check(ld_probe.exists(), "the fake subfinder shim was never run (subs stage did not spawn tools)")
        check(str(sidecar) not in ld_probe.read_text(),
              f"child tools inherited the bundle LD_LIBRARY_PATH: {ld_probe.read_text().strip()}")
        check(not list(cwd.iterdir()), f"run wrote into the cwd: {list(cwd.iterdir())}")

        # Event stream: run_start ... run_end, every line schema-valid.
        check(events_path.is_file(), "run: events.jsonl was not written")
        errors, schema = load_validator()
        records = []
        for n, line in enumerate(events_path.read_text(encoding="utf-8").splitlines(), 1):
            try:
                rec = json.loads(line)
            except ValueError as e:
                raise Failure(f"events.jsonl line {n}: invalid JSON: {e}") from None
            errs = errors(rec, schema)
            check(not errs, f"events.jsonl line {n} violates the schema: {errs[:3]}")
            records.append(rec)
        check(records, "events.jsonl is empty")
        check(records[0]["type"] == "run_start", f"first event is {records[0]['type']!r}, not run_start")
        check(records[-1]["type"] == "run_end", f"last event is {records[-1]['type']!r}, not run_end")

        # Every write landed under the temp dirs; the sidecar tree is untouched.
        after = snapshot(sidecar)
        check(before == after, "the sidecar directory changed during the run: "
              f"{sorted(set(before) ^ set(after) or [k for k in before if before[k] != after.get(k)])[:5]}")
        # Nothing stray in the repo-relative default location either.
        check(not (ROOT / "outputs" / TARGET).exists(), f"run wrote under {ROOT / 'outputs' / TARGET}")
        print(f"smoke: {len(records)} events, run_end status={records[-1].get('status')}")


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        run_smoke(Path(argv[0]).resolve())
    except Failure as e:
        print(f"SMOKE FAIL: {e}", file=sys.stderr)
        return 1
    print("SMOKE PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
