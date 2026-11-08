"""Technology / language fingerprinting via whatweb (Phase 11).

Flow:
  1. Resolve the host list; SSRF-guard to publicly-routable IPs only.
  2. Fingerprint every host in one whatweb invocation, logging JSON.
  3. Parse the JSON log: each entry's `plugins` dict maps a technology name to a
     value carrying version / matched string / confidence.
  4. Emit one `tech-detect:<name>` finding per technology.  The tech name lives
     in the template so the report's dedupe keeps every tech on a host.

    from runner.tech_scan import tech_scan
    findings = tech_scan("example.com", outdir)

Schema (whatweb --log-json): a JSON array of
  {"target": "<url>", "http_status": 200, "plugins": {
       "<Tech>": {"version": [...], "string": [...], "confidence": ..., ...}}}
"""
import json
from pathlib import Path
from urllib.parse import urlsplit

from runner import utils
from runner.stages import _is_global, _resolve


def _read_live_hosts(path) -> list[str]:
    """First tab-separated field of each non-empty line."""
    hosts = []
    for line in Path(path).read_text(errors="replace").splitlines():
        first = line.split("\t", 1)[0].strip()
        if first:
            hosts.append(first)
    return hosts


def _live_hosts(outdir: Path, target: str, hosts: list[str] | None) -> list[str]:
    """Resolve the host list for a scan; SSRF-guard to public IPs only."""
    if hosts:
        src = hosts
    else:
        live_path = Path(outdir) / "live_hosts.txt"
        src = _read_live_hosts(live_path) if live_path.exists() else [target]
    return [h for h in src if _is_global(_resolve(h))]


def _version(info: dict) -> str:
    """Join a plugin's version list into a display string ('' if absent)."""
    versions = info.get("version") or []
    if isinstance(versions, list):
        return " ".join(str(v) for v in versions if v).strip()
    return str(versions).strip()


def _evidence(info: dict) -> str:
    """Confidence if present, else the matched string(s)."""
    conf = info.get("confidence")
    if conf not in (None, "", []):
        return str(conf)
    strings = info.get("string") or []
    if isinstance(strings, list):
        return "; ".join(str(s) for s in strings if s).strip()
    return str(strings).strip()


def _parse_whatweb_json(raw: str) -> list[dict]:
    """Parse the whatweb JSON log into a list of result dicts."""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    return [d for d in data if isinstance(d, dict)] if isinstance(data, list) else []


def tech_scan(target: str, outdir: Path, hosts: list[str] | None = None,
              timeout: int = 300) -> list[dict]:
    """Fingerprint live hosts with whatweb; emit one finding per technology."""
    utils.log("Stage — tech detection (whatweb)")
    if not utils.have("whatweb"):
        utils.warn("whatweb not found — skipping tech detection")
        return []

    live = _live_hosts(outdir, target, hosts)
    if not live:
        utils.warn("no routable hosts — skipping tech detection")
        return []

    log_path = Path(outdir) / "whatweb.json"
    urls = [f"https://{h}" for h in live]
    utils.run(
        f"whatweb -a 3 --log-json={log_path} {' '.join(urls)}",
        timeout=timeout,
    )

    if not log_path.exists():
        utils.warn("whatweb produced no JSON log — skipping tech detection")
        return []

    results = _parse_whatweb_json(log_path.read_text(errors="replace"))

    findings: list[dict] = []
    for result in results:
        url = result.get("target") or target
        host = urlsplit(url).hostname or target
        plugins = result.get("plugins") or {}
        if not isinstance(plugins, dict):
            continue
        for tech, info in plugins.items():
            info = info if isinstance(info, dict) else {}
            version = _version(info)
            name = f"Technology: {tech} {version}".strip()
            findings.append({
                "severity": "info",
                "template": f"tech-detect:{str(tech).lower()}",
                "name": name,
                "url": url,
                "host": host,
                "evidence": _evidence(info),
            })

    utils.log(f"tech detection: {len(findings)} technology finding(s) across {len(results)} host(s)")
    return findings
