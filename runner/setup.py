"""``bounty-run setup``: install the external tools the engine drives.

Hybrid and batched: ``go``/``pipx`` installs run one by one, every ``apt``
package across all targets goes into a single ``sudo apt install`` so the user
authenticates once. After an install the tool is re-checked on PATH; a binary
that landed in a known directory that is not on PATH is reported as
``installed_needs_path`` rather than a silent success.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys

from . import introspect

SCHEMA = 2
INSTALL_TIMEOUT_S = 900


def _prereq(name: str) -> str | None:
    """Locate an installer prerequisite (go, pipx); these are not engine tools."""
    return shutil.which(name)


def _result(name: str, outcome: str, method: str | None = None, detail: str = "") -> dict:
    return {"name": name, "outcome": outcome, "method": method, "detail": detail}


def _targets(args: argparse.Namespace) -> tuple[list[introspect.ToolSpec], list[str]]:
    by_name = {t.name: t for t in introspect.TOOLS}
    if args.all:
        return list(introspect.TOOLS), []
    if args.all_core:
        return [t for t in introspect.TOOLS if not t.optional], []
    specs = [by_name[n] for n in args.tools if n in by_name]
    return specs, [n for n in args.tools if n not in by_name]


def _pick_method(spec: introspect.ToolSpec) -> tuple[str, str] | None:
    """First viable (method, package) in preference order."""
    for method, package in spec.install_methods:
        if method == "pipx" and not _prereq("pipx"):
            continue
        return method, package
    return None


def _recheck(name: str, method: str) -> dict:
    if shutil.which(name):
        return _result(name, "installed", method)
    found = introspect.probe_known_dirs(name, introspect.known_install_dirs())
    if found:
        d = os.path.dirname(found)
        return _result(name, "installed_needs_path", method,
                       f"installed to {d}; add it to PATH (export PATH=\"$PATH:{d}\")")
    return _result(name, "failed", method, "install finished but the tool is still not found")


def _run(cmd: list[str]) -> tuple[bool, str]:
    try:
        if cmd[0] == "sudo":
            # Inherit stdio so the sudo password and apt's [Y/n] prompt reach the user.
            proc = subprocess.run(cmd, timeout=INSTALL_TIMEOUT_S)
        else:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=INSTALL_TIMEOUT_S)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    if proc.returncode != 0:
        out = getattr(proc, "stderr", None) or getattr(proc, "stdout", None) or ""
        tail = out.strip().splitlines()[-1:] if isinstance(out, str) else []
        return False, tail[0] if tail else f"exit {proc.returncode}"
    return True, ""


def _plan(specs: list[introspect.ToolSpec]) -> tuple[list[dict], list[tuple[str, str, str]]]:
    """Return (settled results, pending installs as (name, method, package))."""
    done: list[dict] = []
    pending: list[tuple[str, str, str]] = []
    for spec in specs:
        if introspect._resolve(spec.name):
            done.append(_result(spec.name, "already_ok"))
            continue
        picked = _pick_method(spec)
        if picked is None:
            done.append(_result(spec.name, "failed", None, "no viable install method"))
        elif picked[0] == "manual":
            done.append(_result(spec.name, "manual", "manual", picked[1]))
        elif picked[0] == "go" and not _prereq("go"):
            done.append(_result(spec.name, "failed", "go", "go not found"))
        else:
            pending.append((spec.name, picked[0], picked[1]))
    return done, pending


def _commands(pending: list[tuple[str, str, str]], yes: bool) -> list[tuple[list[str], list[str]]]:
    """(command, tool names it covers); apt is one batched command."""
    cmds: list[tuple[list[str], list[str]]] = []
    apt = [(n, p) for n, m, p in pending if m == "apt"]
    for name, method, package in pending:
        if method == "go":
            cmds.append((["go", "install", package], [name]))
        elif method == "pipx":
            cmds.append((["pipx", "install", package], [name]))
    if apt:
        cmd = ["sudo", "apt", "install"] + (["-y"] if yes else []) + [p for _, p in apt]
        cmds.append((cmd, [n for n, _ in apt]))
    return cmds


def _emit(results: list[dict], as_json: bool) -> None:
    if as_json:
        print(json.dumps({"schema": SCHEMA, "results": results}))
        return
    for r in results:
        method = f" [{r['method']}]" if r["method"] else ""
        detail = f" - {r['detail']}" if r["detail"] else ""
        print(f"{r['name']}: {r['outcome']}{method}{detail}")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="bounty-run setup", description="Install external tools.")
    ap.add_argument("tools", nargs="*", help="tool names to install")
    ap.add_argument("--all-core", action="store_true", help="every non-optional tool")
    ap.add_argument("--all", action="store_true", help="every tool")
    ap.add_argument("--yes", "-y", action="store_true", help="pass -y to apt")
    ap.add_argument("--dry-run", action="store_true", help="show the plan, install nothing")
    ap.add_argument("--json", action="store_true", help="machine-readable summary")
    args = ap.parse_args(argv)
    if not (args.tools or args.all or args.all_core):
        ap.error("name at least one tool, or pass --all-core / --all")

    specs, unknown = _targets(args)
    results = [_result(n, "skipped", None, "unknown tool") for n in unknown]
    settled, pending = _plan(specs)
    results += settled
    cmds = _commands(pending, args.yes)

    if args.dry_run:
        for cmd, names in cmds:
            print("would run: " + " ".join(cmd), file=sys.stderr if args.json else sys.stdout)
        for name, method, _ in pending:
            results.append(_result(name, "skipped", method, "dry run"))
        _emit(results, args.json)
        return 0

    methods = {n: m for n, m, _ in pending}
    failed = False
    for cmd, names in cmds:
        ok, why = _run(cmd)
        for name in names:
            if ok:
                results.append(_recheck(name, methods[name]))
            else:
                results.append(_result(name, "failed", methods[name], why))
        failed = failed or not ok
    _emit(results, args.json)
    return 1 if failed else 0
