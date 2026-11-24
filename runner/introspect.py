"""Machine-readable engine introspection: ``bounty-run introspect <stages|doctor|version>``.

Every subcommand prints exactly one JSON document on stdout (no banner, no
logging) and creates no files. ``doctor`` must never touch the network, so each
tool is probed with a version command that is known to run offline (adding the
update-check opt-out where the tool has one); a tool whose version command
cannot be shown to be offline is reported ``unknown_version`` and not executed.
"""
from __future__ import annotations

import json
import os
import re
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass

from . import __version__, headi_scan, paths, stage_registry
from .http_headers import SHCHECK

SCHEMA = 1
EVENTS_SCHEMA = 1  # matches the "v" field of every events.jsonl record

PROBE_TIMEOUT_S = 3.0
PROBE_OUTPUT_CAP = 64 * 1024

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_GENERIC = r"(\d+(?:\.\d+)+(?:[-+#][\w.]+)?)"
_LABELLED = r"(?i)version:?\s*v?" + _GENERIC


@dataclass(frozen=True)
class ToolSpec:
    name: str
    required_by: tuple[str, ...]
    install_hint: str
    optional: bool = False
    # Offline version command, or None when none can be shown to be offline.
    probe: tuple[str, ...] | None = None
    version_re: str = _GENERIC


_GO = "go install github.com/{}@latest"
_APT = "sudo apt install {}"
_PD_PROBE = ("-version", "-duc")  # -duc: disable the update check

TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec("subfinder", ("subs",), _GO.format("projectdiscovery/subfinder/v2/cmd/subfinder"),
             probe=_PD_PROBE, version_re=_LABELLED),
    ToolSpec("amass", ("subs",), "see https://github.com/owasp-amass/amass",
             optional=True, probe=("-version",)),
    ToolSpec("findomain", ("subs",), "see https://github.com/Findomain/Findomain",
             optional=True, probe=("--version",)),
    ToolSpec("dnsx", ("subs",), _GO.format("projectdiscovery/dnsx/cmd/dnsx"),
             optional=True, probe=_PD_PROBE, version_re=_LABELLED),
    ToolSpec("dig", ("origin",), _APT.format("dnsutils"), probe=("-v",),
             version_re=r"DiG " + _GENERIC),
    ToolSpec("curl", ("origin", "origin_deep", "param"), _APT.format("curl"),
             probe=("--version",), version_re=r"^curl " + _GENERIC),
    ToolSpec("openssl", ("origin",), _APT.format("openssl"), optional=True,
             probe=("version",), version_re=r"OpenSSL " + _GENERIC),
    ToolSpec("nmap", ("nmap",), _APT.format("nmap"), optional=True, probe=("--version",),
             version_re=r"Nmap version " + _GENERIC),
    ToolSpec("wafw00f", ("waf",), _APT.format("wafw00f") + " (or: pipx install wafw00f)",
             probe=("--version",), version_re=r"WAFW00F you have is \S*?v" + _GENERIC),
    # sslyze has no --version flag; --help is argparse-only and prints "SSLyze version X".
    ToolSpec("sslyze", ("tls",), _APT.format("sslyze") + " (or: pipx install sslyze)",
             optional=True, probe=("--help",), version_re=r"SSLyze version " + _GENERIC),
    ToolSpec("nikto", ("nikto",), _APT.format("nikto"), optional=True, probe=("-Version",),
             version_re=r"Nikto " + _GENERIC),
    ToolSpec("nuclei", ("vuln",), _GO.format("projectdiscovery/nuclei/v3/cmd/nuclei"),
             probe=_PD_PROBE, version_re=_LABELLED),
    ToolSpec("ffuf", ("content",), _GO.format("ffuf/ffuf/v2"), probe=("-V",)),
    ToolSpec("sqlmap", ("param",), _APT.format("sqlmap"), probe=("--version",)),
    ToolSpec("katana", ("api",), _GO.format("projectdiscovery/katana/cmd/katana"),
             probe=_PD_PROBE, version_re=_LABELLED),
    ToolSpec("whatweb", ("tech",), _APT.format("whatweb"), probe=("--version",),
             version_re=r"WhatWeb version " + _GENERIC),
    # headi has no version flag, and an unknown flag on a Go CLI may do real work.
    ToolSpec("headi", ("headi",), _GO.format("mlcsec/headi"), optional=True),
    # Site-specific shim around a local Metis install; its CLI is not known to us.
    ToolSpec("metis-autocheck", ("metis",),
             "provide a metis-autocheck shim on PATH (runs inside a local Metis install)",
             optional=True),
    # Vendored script: resolved by path, carries no version string.
    ToolSpec("shcheck", ("headers",), "vendored (runner/vendor/shcheck.py); nothing to install"),
)


def _resolve(name: str) -> str | None:
    """Resolve a tool exactly as the engine does."""
    if name == "shcheck":
        return str(SHCHECK) if SHCHECK.exists() else None
    if name == "headi":
        return headi_scan._resolve_binary()
    return shutil.which(name)


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _probe_output(argv: list[str]) -> str | None:
    """Run ``argv`` sandboxed; return its (capped) output or None on timeout/failure."""
    sandbox = tempfile.mkdtemp(prefix="br-probe-")
    os.chmod(sandbox, 0o500)  # an empty, read-only cwd cannot receive stray files
    proc = None
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, cwd=sandbox, env=paths.child_env(),
                                start_new_session=True)
        deadline = time.monotonic() + PROBE_TIMEOUT_S
        chunks: list[bytes] = []
        size = 0
        fd = proc.stdout.fileno()
        timed_out = False
        while size < PROBE_OUTPUT_CAP:
            left = deadline - time.monotonic()
            if left <= 0:
                timed_out = True
                break
            ready, _, _ = select.select([fd], [], [], left)
            if not ready:
                timed_out = True
                break
            data = os.read(fd, 8192)
            if not data:
                break
            chunks.append(data)
            size += len(data)
        return None if timed_out else b"".join(chunks).decode("utf-8", "replace")
    except OSError:
        return None
    finally:
        if proc is not None:
            _kill_group(proc)  # also reaps any child the tool left behind
            proc.stdout.close()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        os.chmod(sandbox, 0o700)
        shutil.rmtree(sandbox, ignore_errors=True)


def _version_of(spec: ToolSpec, path: str) -> str | None:
    if spec.probe is None:
        return None
    text = _probe_output([path, *spec.probe])
    if text is None:
        return None
    for line in _ANSI.sub("", text).splitlines():
        m = re.search(spec.version_re, line)
        if m:
            return m.group(1)
    return None


def doctor_report() -> dict:
    tools = []
    for spec in TOOLS:
        path = _resolve(spec.name)
        version = _version_of(spec, path) if path else None
        status = "missing" if not path else ("ok" if version else "unknown_version")
        tools.append({
            "name": spec.name, "path": path, "version": version,
            "required_by": list(spec.required_by), "optional": spec.optional,
            "install_hint": spec.install_hint, "status": status,
        })
    return {"schema": SCHEMA, "tools": tools}


def stages_report() -> dict:
    return {"schema": SCHEMA, "stages": [{
        "id": s.id, "num": s.num, "title": s.title, "tier": s.tier.name.lower(),
        "caps": sorted(c.value for c in s.caps), "opt_in": bool(s.opt_in_flag),
        "parent": s.parent,
    } for s in stage_registry.STAGES]}


def version_report() -> dict:
    return {"schema": SCHEMA, "engine_version": __version__, "events_schema": EVENTS_SCHEMA}


_REPORTS = {"stages": stages_report, "doctor": doctor_report, "version": version_report}


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] not in _REPORTS:
        shown = " ".join(argv) or "(none)"
        print(f"bounty-run introspect: unknown subcommand: {shown} "
              f"(expected one of: {', '.join(_REPORTS)})", file=sys.stderr)
        return 2
    sys.stdout.write(json.dumps(_REPORTS[argv[0]](), separators=(",", ":")) + "\n")
    return 0
