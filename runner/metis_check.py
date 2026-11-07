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
import shutil
import subprocess
from pathlib import Path

from runner import utils

SHIM_NAME = "metis-autocheck"

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
                timeout: int = 600) -> list[dict]:
    """Run the Metis autocheck sweep over ``hosts``; return metis:* findings.

    Warn + return [] (never raise) if there are no hosts, the shim is missing,
    the sweep errors, or the output cannot be parsed.
    """
    findings: list[dict] = []
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

    try:
        proc = subprocess.run(
            [shim, f"file:{hosts_file}"],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        utils.warn(f"metis: sweep timed out after {timeout}s — skipping")
        return findings
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
