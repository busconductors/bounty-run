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

SCHEMA = 2
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
    # Structured install source of truth, in preference order: (method, package).
    # method is one of go|apt|pipx|manual; package is the exact installer argument
    # (manual: prose guidance). install_hint stays as the human-readable form.
    install_methods: tuple[tuple[str, str], ...] = ()


_GO = "go install github.com/{}@latest"
_APT = "sudo apt install {}"
_GO_PKG = "github.com/{}@latest"
_PD_PROBE = ("-version", "-duc")  # -duc: disable the update check

TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec("subfinder", ("subs",), _GO.format("projectdiscovery/subfinder/v2/cmd/subfinder"),
             install_methods=(("go", _GO_PKG.format("projectdiscovery/subfinder/v2/cmd/subfinder")),),
             probe=_PD_PROBE, version_re=_LABELLED),
    ToolSpec("amass", ("subs",), "see https://github.com/owasp-amass/amass",
             install_methods=(("manual", "see https://github.com/owasp-amass/amass"),),
             optional=True, probe=("-version",)),
    ToolSpec("findomain", ("subs",), "see https://github.com/Findomain/Findomain",
             install_methods=(("manual", "see https://github.com/Findomain/Findomain"),),
             optional=True, probe=("--version",)),
    ToolSpec("dnsx", ("subs",), _GO.format("projectdiscovery/dnsx/cmd/dnsx"),
             install_methods=(("go", _GO_PKG.format("projectdiscovery/dnsx/cmd/dnsx")),),
             optional=True, probe=_PD_PROBE, version_re=_LABELLED),
    ToolSpec("dig", ("origin",), _APT.format("dnsutils"),
             install_methods=(("apt", "dnsutils"),), probe=("-v",),
             version_re=r"DiG " + _GENERIC),
    ToolSpec("curl", ("origin", "origin_deep", "param"), _APT.format("curl"),
             install_methods=(("apt", "curl"),),
             probe=("--version",), version_re=r"^curl " + _GENERIC),
    ToolSpec("openssl", ("origin",), _APT.format("openssl"),
             install_methods=(("apt", "openssl"),), optional=True,
             probe=("version",), version_re=r"OpenSSL " + _GENERIC),
    ToolSpec("nmap", ("nmap",), _APT.format("nmap"),
             install_methods=(("apt", "nmap"),), optional=True, probe=("--version",),
             version_re=r"Nmap version " + _GENERIC),
    ToolSpec("wafw00f", ("waf",), _APT.format("wafw00f") + " (or: pipx install wafw00f)",
             install_methods=(("pipx", "wafw00f"), ("apt", "wafw00f")),
             probe=("--version",), version_re=r"WAFW00F you have is \S*?v" + _GENERIC),
    # sslyze has no --version flag; --help is argparse-only and prints "SSLyze version X".
    ToolSpec("sslyze", ("tls",), _APT.format("sslyze") + " (or: pipx install sslyze)",
             install_methods=(("pipx", "sslyze"), ("apt", "sslyze")),
             optional=True, probe=("--help",), version_re=r"SSLyze version " + _GENERIC),
    ToolSpec("nikto", ("nikto",), _APT.format("nikto"),
             install_methods=(("apt", "nikto"),), optional=True, probe=("-Version",),
             version_re=r"Nikto " + _GENERIC),
    ToolSpec("nuclei", ("vuln",), _GO.format("projectdiscovery/nuclei/v3/cmd/nuclei"),
             install_methods=(("go", _GO_PKG.format("projectdiscovery/nuclei/v3/cmd/nuclei")),),
             probe=_PD_PROBE, version_re=_LABELLED),
    ToolSpec("ffuf", ("content",), _GO.format("ffuf/ffuf/v2"),
             install_methods=(("go", _GO_PKG.format("ffuf/ffuf/v2")),), probe=("-V",)),
    ToolSpec("sqlmap", ("param",), _APT.format("sqlmap"),
             install_methods=(("apt", "sqlmap"),), probe=("--version",)),
    ToolSpec("katana", ("api",), _GO.format("projectdiscovery/katana/cmd/katana"),
             install_methods=(("go", _GO_PKG.format("projectdiscovery/katana/cmd/katana")),),
             probe=_PD_PROBE, version_re=_LABELLED),
    ToolSpec("whatweb", ("tech",), _APT.format("whatweb"),
             install_methods=(("apt", "whatweb"),), probe=("--version",),
             version_re=r"WhatWeb version " + _GENERIC),
    # headi has no version flag, and an unknown flag on a Go CLI may do real work.
    ToolSpec("headi", ("headi",), _GO.format("mlcsec/headi"),
             install_methods=(("go", _GO_PKG.format("mlcsec/headi")),), optional=True),
    # Site-specific shim around a local Metis install; its CLI is not known to us.
    ToolSpec("metis-autocheck", ("metis",),
             "provide a metis-autocheck shim on PATH (runs inside a local Metis install)",
             install_methods=(("manual", "provide a metis-autocheck shim on PATH "
                                         "(runs inside a local Metis install)"),),
             optional=True),
    # Vendored script: resolved by path, carries no version string.
    ToolSpec("shcheck", ("headers",), "vendored (runner/vendor/shcheck.py); nothing to install",
             install_methods=(("manual", "vendored (runner/vendor/shcheck.py); nothing to install"),)),
)


def _resolve(name: str) -> str | None:
    """Resolve a tool exactly as the engine does."""
    if name == "shcheck":
        return str(SHCHECK) if SHCHECK.exists() else None
    if name == "headi":
        return headi_scan._resolve_binary()
    return shutil.which(name)


def known_install_dirs() -> list[str]:
    """Where installers drop binaries that may not be on PATH. No network.

    ``$GOBIN`` wins over ``<GOPATH>/bin`` (as ``go install`` does), then ``~/.local/bin``.
    """
    home = os.path.expanduser("~")
    gobin = os.environ.get("GOBIN", "").strip()
    if gobin:
        go_bin = gobin
    else:
        gopath = os.environ.get("GOPATH", "").split(os.pathsep)[0]
        if not gopath:
            try:
                gopath = subprocess.run(["go", "env", "GOPATH"], capture_output=True, text=True,
                                        timeout=5, stdin=subprocess.DEVNULL).stdout.strip()
            except (OSError, subprocess.SubprocessError):
                gopath = ""
        go_bin = os.path.join(gopath or os.path.join(home, "go"), "bin")
    dirs: list[str] = []
    for d in (go_bin, os.path.join(home, ".local", "bin")):
        if d and d not in dirs:
            dirs.append(d)
    return dirs


def probe_known_dirs(name: str, dirs: list[str]) -> str | None:
    """First executable regular file ``name`` found in ``dirs``."""
    for d in dirs:
        cand = os.path.join(d, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


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
    dirs: list[str] | None = None
    for spec in TOOLS:
        path = _resolve(spec.name)
        off_path = None
        if not path:
            if dirs is None:
                dirs = known_install_dirs()
            off_path = probe_known_dirs(spec.name, dirs)
        version = _version_of(spec, path) if path else None
        if off_path:
            path, status = off_path, "installed_needs_path"
        else:
            status = "missing" if not path else ("ok" if version else "unknown_version")
        tools.append({
            "name": spec.name, "path": path, "version": version,
            "required_by": list(spec.required_by), "optional": spec.optional,
            "install_hint": spec.install_hint, "status": status,
            "install_methods": [{"method": m, "package": p} for m, p in spec.install_methods],
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
