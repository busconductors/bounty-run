"""Metis autocheck wrapper — fresh-CVE coverage via Metis's check()-only sweep.

Feature 3 of Phase 6. Off by default (the CLI lane wires it behind ``--metis``);
this module just provides the callable. It subprocesses the ``metis-autocheck``
shim against the live-host list and parses the shim's JSON into findings:

    {severity, template: "metis:<module_path>", name, url: "https://<host>", host}

Metis's ``autocheck.py`` is a Module subclass (not shell-invokable) whose stdout
is ANSI-wrapped and lacks name/severity, so we shell out to the shim — which
runs inside Metis's venv, boots the framework, and emits clean per-hit JSON —
and parse that structured output, never stdout.

If Metis or the shim is absent, or the sweep errors, this warns and skips
(returns []) — it never crashes the run.

    from runner.metis_check import metis_check
    findings = metis_check("example.com", outdir, ["example.com", "www.example.com"])
"""
import json
import os
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path

from runner import events, utils

SHIM_NAME = "metis-autocheck"

_POLL_S = 0.25        # control-file poll interval while the sweep runs
_TERM_GRACE_S = 5.0   # SIGTERM -> SIGKILL grace on cancel/skip


def _killpg(proc: subprocess.Popen, sig: int) -> None:
    """Signal the sweep's whole process group (shim + its grandchildren)."""
    try:
        os.killpg(proc.pid, sig)
    except (ProcessLookupError, OSError):
        if proc.poll() is None:
            try:
                proc.send_signal(sig)
            except OSError:
                pass


def _run_managed(cmd: list[str], timeout: int) -> subprocess.CompletedProcess:
    """Run the shim under a managed bounty run, honoring skip/cancel.

    Mirrors ``runner.utils.run``: the shim is its own process-group leader
    (``start_new_session=True``); the control file is polled every 250 ms via
    ``events.check_control()`` so a ``skip metis`` / ``cancel`` terminates the
    metis subprocess (``killpg``) mid-sweep instead of waiting for it to finish.
    A ``timeout``-second wall-clock deadline is kept as a hard fallback.

    Returns a ``CompletedProcess`` on normal exit; raises
    ``subprocess.TimeoutExpired`` on the wall-clock deadline and re-raises
    ``events.RunCancelled`` / ``events.StageSkipped`` after killing the group.
    """
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    out_chunks: list[str] = []
    err_chunks: list[str] = []
    readers = [
        threading.Thread(target=lambda: out_chunks.append(proc.stdout.read()),
                         daemon=True),
        threading.Thread(target=lambda: err_chunks.append(proc.stderr.read()),
                         daemon=True),
    ]
    registered = False
    try:
        for t in readers:
            t.start()
        events.register_child(proc.pid)
        registered = True
        deadline = time.monotonic() + timeout
        while True:
            # Done only once the shim exited AND both pipes hit EOF.
            if proc.poll() is not None and not any(t.is_alive() for t in readers):
                break
            events.check_control()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _killpg(proc, signal.SIGKILL)
                proc.wait()
                for t in readers:
                    t.join(_TERM_GRACE_S)
                raise subprocess.TimeoutExpired(cmd, timeout)
            slice_s = min(_POLL_S, remaining)
            if proc.poll() is None:
                try:
                    proc.wait(timeout=slice_s)
                except subprocess.TimeoutExpired:
                    pass
            else:
                alive = [t for t in readers if t.is_alive()]
                if alive:
                    alive[0].join(slice_s)
    except (events.RunCancelled, events.StageSkipped):
        _killpg(proc, signal.SIGTERM)
        try:
            proc.wait(timeout=_TERM_GRACE_S)
        except subprocess.TimeoutExpired:
            pass
        _killpg(proc, signal.SIGKILL)
        proc.wait()
        for t in readers:
            t.join(_TERM_GRACE_S)
        raise
    finally:
        if registered:
            events.unregister_child(proc.pid)

    stdout = "".join(c for c in out_chunks if c)
    stderr = "".join(c for c in err_chunks if c)
    return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)

# Hand-curated AUX -> EXPLOIT bridge. Maps a detected auxiliary scanner path to
# the corresponding exploit module *only* when a real 1:1 (same CVE) module
# exists in Metis. Deliberately minimal — no fabricated mappings. Bounty Runner
# never fires an exploit; this just annotates the escalation block in FINDINGS.md.
AUX_EXPLOIT_MAP = {
    "auxiliary/scanner/fortinet_cve_2025_64446":
        "exploits/linux/http/fortiweb_auth_bypass_cve_2025_64446",
    "auxiliary/scanner/redis_cve_2022_0543":
        "exploits/linux/redis/redis_cve_2022_0543_rce",
    "auxiliary/scanner/inetutils_telnetd_bypass_cve_2026_24061":
        "exploits/linux/telnet/inetutils_telnetd_bypass_cve_2026_24061",
    "auxiliary/scanner/langflow_path_traversal_cve_2026_5027":
        "exploits/multi/http/langflow_path_traversal_rce_cve_2026_5027",
    "auxiliary/scanner/marimo_terminal_ws_detect_cve_2026_39987":
        "exploits/multi/http/marimo_terminal_ws_rce_cve_2026_39987",
    "auxiliary/scanner/react2shell_cve_2025_55182":
        "exploits/multi/http/react2shell_rce_cve_2025_55182",
}


def metis_check(target: str, outdir: Path, hosts: list[str],
                timeout: int = 600, proxy=None) -> list[dict]:
    """Run the Metis autocheck sweep over ``hosts``; return metis:* findings.

    Warn + return [] (never raise) if there are no hosts, the shim is missing,
    the sweep errors, or the output cannot be parsed.
    """
    findings: list[dict] = []
    # Mixed raw-socket protocols: cannot be proxied, so never run it direct
    # under --proxy (fail-closed).
    from runner import proxy as proxymod
    if not proxymod.gate(proxy, "metis"):
        return findings
    hosts = [h for h in (hosts or []) if h and str(h).strip()]
    if not hosts:
        utils.warn("metis: no live hosts to check — skipping")
        return findings

    shim = shutil.which(SHIM_NAME)
    if not shim:
        utils.warn(f"metis: {SHIM_NAME} not found on PATH — skipping metis sweep")
        return findings

    hosts_file = Path(outdir) / "metis_targets.txt"
    try:
        hosts_file.write_text("\n".join(hosts) + "\n")
    except OSError as e:  # noqa: BLE001
        utils.warn(f"metis: could not write target list: {e}")
        return findings

    cmd = [shim, f"file:{hosts_file}"]
    try:
        if events.run_dir() is not None:
            # Inside a managed run: poll the control file so a skip/cancel kills
            # the sweep mid-run (killpg). 600s wall-clock kept as a fallback.
            proc = _run_managed(cmd, timeout)
        else:
            # Standalone (and the unit tests, which patch subprocess.run): a
            # plain blocking call with the same wall-clock timeout is enough.
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )
    except subprocess.TimeoutExpired:
        utils.warn(f"metis: sweep timed out after {timeout}s — skipping")
        return findings
    except (events.RunCancelled, events.StageSkipped):
        # Let the stage wrapper (events.stage) record skipped/cancelled.
        raise
    except OSError as e:  # noqa: BLE001
        utils.warn(f"metis: sweep failed to run: {e}")
        return findings

    if proc.returncode != 0:
        err = (proc.stderr or "").strip().splitlines()
        utils.warn(f"metis: shim exited {proc.returncode}: "
                   f"{(err[0] if err else 'unknown error')[:200]}")
        return findings

    try:
        hits = json.loads(proc.stdout or "")
    except json.JSONDecodeError:
        utils.warn("metis: shim returned unparseable JSON — skipping")
        return findings
    if not isinstance(hits, list):
        utils.warn("metis: shim returned a non-list payload — skipping")
        return findings

    for h in hits:
        if not isinstance(h, dict):
            continue
        module_path = str(h.get("module") or "").strip()
        host = str(h.get("host") or "").strip()
        if not module_path or not host:
            continue
        severity = str(h.get("severity") or "unknown").lower() or "unknown"
        name = str(h.get("name") or "").strip() or module_path
        findings.append({
            "severity": severity,
            "template": f"metis:{module_path}",
            "name": name,
            "url": f"https://{host}",
            "host": host,
        })

    utils.log(f"  metis sweep surfaced {len(findings)} finding(s)")
    return findings
