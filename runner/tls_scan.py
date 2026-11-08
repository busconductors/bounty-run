"""TLS/SSL deep-scan stage via sslyze (Phase 12, opt-in `--tls`).

Flow:
  1. Collect hosts: live hostnames plus `target` (prepended if absent),
     normalised, invalid hostnames dropped, SSRF-guarded with
     `_is_global(_resolve(h))`, capped at `max_hosts`.
  2. Per host, in a ThreadPoolExecutor, run the sslyze *CLI* as a bounded
     subprocess via `utils.run(..., timeout=timeout)`:
       sslyze --quiet --json_out=<outdir>/sslyze/<host>.json --certinfo
              --sslv2 --sslv3 --tlsv1 --tlsv1_1 --tlsv1_2 --heartbleed
              --robot <host>:443
     (The in-process API is deliberately not used: it can't be killed by
     utils.run's killpg timeout.) sslyze exits non-zero when it finds problems,
     so the JSON is parsed regardless of exit code.
  3. Parse each JSON into `tls:<issue>` findings (`_findings_from_sslyze`) and
     write `outdir/tls_scan.txt` (`<host>\\t<template>\\t<severity>`).

JSON paths, confirmed against sslyze 6.3 output:
  server_scan_results[].scan_status == "COMPLETED"
  server_scan_results[].scan_result.<cmd>.{status, result}
  <proto>_cipher_suites.result.accepted_cipher_suites[].cipher_suite.name
  heartbleed.result.is_vulnerable_to_heartbleed
  robot.result.robot_result
  certificate_info.result.certificate_deployments[]:
    .path_validation_results[].was_validation_successful
    .received_certificate_chain[0].{not_valid_after ("...Z"), subject,
                                    subject_alternative_name.dns_names}
sslyze 6.x no longer emits `leaf_certificate_subject_matches_hostname`, so the
hostname match is computed from the leaf's SAN DNS names (falling back to the
subject CN when there are none), with single-label wildcard matching. If an
older sslyze still emits that key, it is honoured.

    from runner.tls_scan import tls_scan
    findings = tls_scan("example.com", outdir, live_hosts)
"""
import json
import re
import shlex
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path

from runner import events, utils
from runner.stages import _is_global, _resolve

PORT = 443
EXPIRY_WARN_DAYS = 30
EVIDENCE_MAX = 300

# Accepted cipher suite names that count as weak (any protocol).
WEAK_CIPHER_RE = re.compile(r"RC4|_DES_|3DES|NULL|EXPORT|anon|_MD5")

_HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")

# (scan_result key, template, severity, label)
_PROTOCOLS = [
    ("ssl_2_0_cipher_suites", "tls:sslv2-enabled", "high", "SSLv2"),
    ("ssl_3_0_cipher_suites", "tls:sslv3-enabled", "medium", "SSLv3"),
    ("tls_1_0_cipher_suites", "tls:tlsv1-enabled", "low", "TLS 1.0"),
    ("tls_1_1_cipher_suites", "tls:tlsv1_1-enabled", "low", "TLS 1.1"),
]
_ALL_SUITE_CMDS = [p[0] for p in _PROTOCOLS] + ["tls_1_2_cipher_suites",
                                                 "tls_1_3_cipher_suites"]

_ROBOT_SEVERITY = {"VULNERABLE_STRONG_ORACLE": "high",
                   "VULNERABLE_WEAK_ORACLE": "medium"}


def _norm_host(h: str) -> str:
    return (h or "").strip().lower().rstrip(".")


def _result(scan_result: dict, cmd: str) -> dict | None:
    """`scan_result[cmd].result` if that command COMPLETED, else None."""
    entry = scan_result.get(cmd)
    if not isinstance(entry, dict) or entry.get("status") != "COMPLETED":
        return None
    res = entry.get("result")
    return res if isinstance(res, dict) else None


def _accepted_names(res: dict | None) -> list[str]:
    names = []
    for a in (res or {}).get("accepted_cipher_suites") or []:
        name = ((a or {}).get("cipher_suite") or {}).get("name") if isinstance(a, dict) else None
        if isinstance(name, str) and name:
            names.append(name)
    return names


def _parse_dt(value) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _subject_cn(cert: dict) -> str:
    for attr in (cert.get("subject") or {}).get("attributes") or []:
        if isinstance(attr, dict) and (attr.get("oid") or {}).get("name") == "commonName":
            return str(attr.get("value") or "")
    return ""


def _name_matches(pattern: str, host: str) -> bool:
    pattern = _norm_host(pattern)
    if not pattern:
        return False
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        if not host.endswith(suffix):
            return False
        left = host[: -len(suffix)]
        return bool(left) and "." not in left
    return pattern == host


def _hostname_matches(deployment: dict, cert: dict, host: str) -> bool:
    explicit = deployment.get("leaf_certificate_subject_matches_hostname")
    if isinstance(explicit, bool):
        return explicit
    names = (cert.get("subject_alternative_name") or {}).get("dns_names") or []
    if not names:
        cn = _subject_cn(cert)
        names = [cn] if cn else []
    return any(_name_matches(n, host) for n in names if isinstance(n, str))


def _cert_findings(cert_res: dict | None, host: str, now: datetime) -> list[tuple]:
    out: list[tuple] = []
    if not cert_res:
        return out
    seen: set[str] = set()

    def add(template, severity, name, evidence):
        if template not in seen:
            seen.add(template)
            out.append((template, severity, name, evidence))

    for dep in cert_res.get("certificate_deployments") or []:
        if not isinstance(dep, dict):
            continue
        chain = dep.get("received_certificate_chain") or []
        leaf = chain[0] if chain and isinstance(chain[0], dict) else {}
        cn = _subject_cn(leaf) or "?"
        nva_raw = leaf.get("not_valid_after") or "?"
        evidence = f"CN={cn}, expires {nva_raw}"

        nva = _parse_dt(leaf.get("not_valid_after"))
        if nva is not None:
            if nva < now:
                add("tls:cert-expired", "medium", "TLS: certificate expired", evidence)
            elif nva - now <= timedelta(days=EXPIRY_WARN_DAYS):
                add("tls:cert-expiring-soon", "info",
                    "TLS: certificate expires within 30 days", evidence)

        if leaf and not _hostname_matches(dep, leaf, host):
            add("tls:cert-hostname-mismatch", "medium",
                "TLS: certificate does not match hostname", evidence)

        pv = [p for p in dep.get("path_validation_results") or [] if isinstance(p, dict)]
        if pv and not any(p.get("was_validation_successful") is True for p in pv):
            add("tls:cert-untrusted", "low",
                "TLS: certificate chain not trusted", evidence)

    # Expired supersedes expiring-soon even across deployments.
    if "tls:cert-expired" in seen:
        out = [f for f in out if f[0] != "tls:cert-expiring-soon"]
    return out


def _findings_from_sslyze(doc: dict, host: str, now: datetime) -> list[dict]:
    """Pure: turn one sslyze JSON document into finding dicts for `host`."""
    if not isinstance(doc, dict):
        return []
    url = f"https://{host}:{PORT}"
    raw: list[tuple] = []  # (template, severity, name, evidence)

    for server in doc.get("server_scan_results") or []:
        try:
            if not isinstance(server, dict) or server.get("scan_status") != "COMPLETED":
                continue
            sr = server.get("scan_result")
            if not isinstance(sr, dict):
                continue

            hb = _result(sr, "heartbleed")
            if hb and hb.get("is_vulnerable_to_heartbleed") is True:
                raw.append(("tls:heartbleed", "critical", "TLS: Heartbleed",
                            "is_vulnerable_to_heartbleed=true"))

            robot = _result(sr, "robot")
            verdict = (robot or {}).get("robot_result")
            if verdict in _ROBOT_SEVERITY:
                raw.append(("tls:robot", _ROBOT_SEVERITY[verdict],
                            "TLS: ROBOT (Bleichenbacher oracle)", str(verdict)))

            for cmd, template, severity, label in _PROTOCOLS:
                names = _accepted_names(_result(sr, cmd))
                if names:
                    raw.append((template, severity, f"TLS: {label} enabled",
                                f"{len(names)} accepted cipher suite(s)"))

            weak: list[str] = []
            for cmd in _ALL_SUITE_CMDS:
                for name in _accepted_names(_result(sr, cmd)):
                    if WEAK_CIPHER_RE.search(name) and name not in weak:
                        weak.append(name)
            if weak:
                raw.append(("tls:weak-cipher", "medium", "TLS: weak cipher suites accepted",
                            ", ".join(weak)[:EVIDENCE_MAX]))

            raw.extend(_cert_findings(_result(sr, "certificate_info"), host, now))
        except Exception as e:  # noqa: BLE001 — malformed doc must never raise
            utils.warn(f"sslyze: unparseable result for {host}: {e}")
            continue

    findings: list[dict] = []
    seen: set[str] = set()
    for template, severity, name, evidence in raw:
        if template in seen:
            continue
        seen.add(template)
        findings.append({"severity": severity, "template": template, "name": name,
                         "url": url, "host": host, "evidence": evidence})
    return findings


def _collect_hosts(target: str, hosts: list[str], max_hosts: int) -> list[str]:
    target = _norm_host(target)
    ordered: list[str] = []
    for h in [target] + list(hosts or []):
        h = _norm_host(h)
        if h and h not in ordered and _HOST_RE.match(h):
            ordered.append(h)
    routable = [h for h in ordered if _is_global(_resolve(h))]
    return routable[:max(0, max_hosts)]


def _scan_host(host: str, jsondir: Path, timeout: int, now: datetime) -> list[dict]:
    out = jsondir / f"{host}.json"
    try:
        if out.exists():
            out.unlink()  # never parse a stale result from a previous run
        cmd = (f"sslyze --quiet --json_out={shlex.quote(str(out))} --certinfo "
               f"--sslv2 --sslv3 --tlsv1 --tlsv1_1 --tlsv1_2 --heartbleed --robot "
               f"{shlex.quote(f'{host}:{PORT}')}")
        utils.run(cmd, timeout=int(timeout))
        if not out.exists():
            utils.warn(f"sslyze: no JSON output for {host} (timeout or connect error)")
            return []
        doc = json.loads(out.read_text(errors="replace"))
    except (events.RunCancelled, events.StageSkipped):
        raise
    except Exception as e:  # noqa: BLE001
        utils.warn(f"sslyze: failed for {host}: {e}")
        return []
    return _findings_from_sslyze(doc, host, now)


def tls_scan(target: str, outdir: Path, hosts: list[str], max_hosts: int = 20,
             timeout: int = 180, workers: int = 4) -> list[dict]:
    """Run sslyze per host (bounded, parallel); return `tls:*` findings."""
    utils.log("TLS/SSL analysis (sslyze)")
    if not utils.have("sslyze"):
        utils.warn("sslyze not found — skipping TLS/SSL analysis")
        events.mark_skipped("tool missing: sslyze")
        return []

    targets = _collect_hosts(target, hosts, max_hosts)
    if not targets:
        utils.warn("tls scan: no publicly-routable hosts — skipping")
        return []

    outdir = Path(outdir)
    jsondir = outdir / "sslyze"
    jsondir.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)

    stage = events.current_stage() or "tls"
    total = len(targets)
    results: dict[str, list[dict]] = {}
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(_scan_host, h, jsondir, timeout, now): h for h in targets}
        done = 0
        try:
            for fut in as_completed(futures):
                host = futures[fut]
                results[host] = fut.result()
                done += 1
                events.progress(stage, done, total)
        except (events.RunCancelled, events.StageSkipped):
            pool.shutdown(wait=True, cancel_futures=True)
            raise

    findings: list[dict] = []
    for host in targets:
        findings.extend(results.get(host, []))

    (outdir / "tls_scan.txt").write_text(
        "".join(f"{f['host']}\t{f['template']}\t{f['severity']}\n" for f in findings))
    utils.log(f"tls scan: {len(findings)} TLS/SSL issue(s) across {len(targets)} host(s)")
    return findings
