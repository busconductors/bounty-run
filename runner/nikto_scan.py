"""nikto web-server misconfiguration stage (Phase 12, opt-in `--nikto`).

Flow:
  1. Collect hosts: target + live hostnames, normalised (lowercase, no trailing
     dot), deduped, SSRF-guarded via `_is_global(_resolve(h))`, capped at
     `max_hosts`.
  2. Per host, in a thread pool, run
     `nikto -h https://<host> -Format json -o <outdir>/nikto/<host>.json
      -maxtime <maxtime>s -timeout 10 -nointeractive -ask no`
     through `utils.run(timeout=maxtime + 60)`. Three bounds: per request,
     per host (nikto-internal) and the `killpg` backstop.
  3. Parse each JSON file defensively (list or single object; truncated/empty
     output from a killed run yields nothing for that host only), classify each
     item by its `msg`, and emit `nikto:<category>:<nikto-id>` findings.

nikto 2.6 reuses one id for several messages on the same url (e.g. 013587 for
every missing security header on `/`). When `nikto:<category>:<id>` repeats for
a host+url, a short hash of the msg is appended so `report.dedupe` keeps both.

    from runner.nikto_scan import nikto_scan
    findings = nikto_scan("example.com", outdir, live_hosts)
"""
import hashlib
import json
import re
import shlex
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from runner import utils
from runner.stages import _is_global, _resolve

# (category, compiled rule, severity) — case-insensitive, first match wins.
_RULES = [
    ("outdated-software", re.compile(r"appears to be outdated|is outdated", re.I), "low"),
    ("http-methods", re.compile(r"HTTP method.*\b(PUT|DELETE|TRACE|WebDAV)\b", re.I), "low"),
    ("directory-indexing", re.compile(r"directory indexing", re.I), "low"),
    ("default-file", re.compile(
        r"default (file|account|installation|page)|phpinfo|server-status|server-info",
        re.I), "low"),
    # nikto 2.6 phrasing: "Suggested security header missing: <name>."
    ("missing-header", re.compile(
        r"header is not (present|set|defined)|security header missing", re.I), "info"),
]
_DEFAULT = ("misconfiguration", "info")

_SLUG_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _classify(msg: str) -> tuple[str, str]:
    """Map a nikto message to (category, severity)."""
    for category, rule, severity in _RULES:
        if rule.search(msg or ""):
            return category, severity
    return _DEFAULT


def _parse_nikto_json(raw: str) -> list[dict]:
    """Return the vulnerability items from nikto JSON; `[]` on bad input.

    Accepts a list of host objects or a single host object.
    """
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return []
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return []
    items: list[dict] = []
    for host_obj in data:
        if not isinstance(host_obj, dict):
            continue
        vulns = host_obj.get("vulnerabilities")
        if not isinstance(vulns, list):
            continue
        items.extend(v for v in vulns if isinstance(v, dict) and v.get("msg"))
    return items


def _norm_host(h: str) -> str:
    h = (h or "").strip().lower()
    if "://" in h:
        h = h.split("://", 1)[1]
    return h.split("/", 1)[0].rstrip(".")


def _candidate_hosts(target: str, hosts: list[str], max_hosts: int) -> list[str]:
    """Target + hosts, normalised, deduped, publicly routable, capped."""
    out: list[str] = []
    seen: set[str] = set()
    for raw in [target, *(hosts or [])]:
        h = _norm_host(raw)
        if not h or h in seen:
            continue
        seen.add(h)
        if not _is_global(_resolve(h)):
            continue
        out.append(h)
        if len(out) >= max_hosts:
            break
    return out


def _join_url(host: str, path: str) -> str:
    path = str(path or "/")
    if path.startswith(("http://", "https://")):
        return path
    if not path.startswith("/"):
        path = "/" + path
    return f"https://{host}{path}"


def _findings_for(host: str, items: list[dict]) -> list[dict]:
    findings: list[dict] = []
    used: set[tuple[str, str]] = set()
    for item in items:
        msg = str(item.get("msg", "")).strip()
        category, severity = _classify(msg)
        nid = _SLUG_RE.sub("-", str(item.get("id") or "").strip()) or "0"
        url = _join_url(host, item.get("url"))
        template = f"nikto:{category}:{nid}"
        if (template, url) in used:
            template += "." + hashlib.sha1(msg.encode()).hexdigest()[:8]
        used.add((template, url))
        findings.append({
            "severity": severity,
            "template": template,
            "name": "Nikto: " + msg[:120],
            "url": url,
            "host": host,
            "evidence": msg,
        })
    return findings


def _scan_host(host: str, nikto_dir: Path, maxtime: int) -> list[dict]:
    """Run nikto on one host and return its findings; never raises."""
    out = nikto_dir / f"{host}.json"
    try:
        out.unlink(missing_ok=True)  # never parse a stale file from a prior run
        utils.run(
            f"nikto -h {shlex.quote('https://' + host)} -Format json "
            f"-o {shlex.quote(str(out))} -maxtime {int(maxtime)}s -timeout 10 "
            f"-nointeractive -ask no",
            timeout=int(maxtime) + 60,
        )
        if not out.exists():
            utils.warn(f"nikto produced no output for {host}")
            return []
        items = _parse_nikto_json(out.read_text(errors="replace"))
    except Exception as e:  # noqa: BLE001 — one bad host must not sink the stage
        utils.warn(f"nikto failed for {host}: {e}")
        return []
    if not items and out.stat().st_size:
        utils.warn(f"nikto output for {host} unparseable or empty — skipped")
    return _findings_for(host, items)


def nikto_scan(target: str, outdir: Path, hosts: list[str], max_hosts: int = 20,
               maxtime: int = 300, workers: int = 4) -> list[dict]:
    """Run nikto per host (bounded, parallel) and return classified findings."""
    utils.log("nikto web-server scan")
    if not utils.have("nikto"):
        utils.warn("nikto not found — skipping nikto scan")
        return []

    try:
        targets = _candidate_hosts(target, hosts, max_hosts)
    except Exception as e:  # noqa: BLE001
        utils.warn(f"nikto host collection failed: {e} — skipping")
        return []
    if not targets:
        utils.warn("no routable hosts — skipping nikto scan")
        return []

    nikto_dir = Path(outdir) / "nikto"
    nikto_dir.mkdir(parents=True, exist_ok=True)
    utils.log(f"  scanning {len(targets)} host(s) [maxtime {maxtime}s, {workers} workers]")

    findings: list[dict] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for host_findings in pool.map(lambda h: _scan_host(h, nikto_dir, maxtime), targets):
            findings.extend(host_findings)
    utils.log(f"nikto: {len(findings)} item(s) across {len(targets)} host(s)")
    return findings
