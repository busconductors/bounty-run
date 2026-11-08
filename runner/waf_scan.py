"""WAF fingerprinting via wafw00f (Phase 12).

Flow:
  1. Build the host list (live hosts plus `target` if absent), SSRF-guard to
     publicly-routable IPs only, cap at `max_hosts`.
  2. Write `wafw00f_targets.txt` (`https://<h>` per line) and fingerprint every
     host in one bounded wafw00f invocation (`-T 10` per request; the
     `utils.run` timeout bounds the whole run).
  3. Parse `wafw00f.json` and emit one `waf:<slug>` info finding per detected
     (host, firewall).  `-a` and http/https redirects can repeat a WAF for one
     host; those rows collapse into one finding.

    from runner.waf_scan import waf_scan
    findings = waf_scan("example.com", outdir, hosts)

Schema (wafw00f 2.4.2 `-f json`, verified against live CDN hosts): a JSON array
of {"url", "detected", "firewall", "manufacturer", "trigger_url"}.
`trigger_url` is extra to the spec's key list and unused.  Undetected rows carry
`detected: false, firewall: "None"`.  The generic detector reports
`firewall: "Generic", manufacturer: "Unknown"` → `waf:generic`.
"""
import json
import re
import shlex
from pathlib import Path
from urllib.parse import urlsplit

from runner import utils
from runner.stages import _is_global, _resolve


def _slug(name: str) -> str:
    """Lowercase, non-alnum runs → '-', stripped ('AWS ELB' → 'aws-elb')."""
    return re.sub(r"[^a-z0-9]+", "-", str(name).lower()).strip("-")


def _parse_wafw00f_json(raw: str) -> list[dict]:
    """Parse wafw00f's JSON output into a list of row dicts ([] on garbage)."""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    return [d for d in data if isinstance(d, dict)] if isinstance(data, list) else []


def _hosts(target: str, hosts: list[str], max_hosts: int) -> list[str]:
    """Dedupe, add target, SSRF-guard, then cap."""
    src = [h.strip() for h in (hosts or []) if h and h.strip()]
    if target not in src:
        src.append(target)
    seen: set[str] = set()
    ordered = [h for h in src if not (h in seen or seen.add(h))]
    return [h for h in ordered if _is_global(_resolve(h))][:max_hosts]


def waf_scan(target: str, outdir: Path, hosts: list[str], max_hosts: int = 20,
             timeout: int = 300) -> list[dict]:
    """Fingerprint WAFs in front of live hosts; one info finding per WAF/host."""
    utils.log("WAF fingerprinting (wafw00f)")
    if not utils.have("wafw00f"):
        utils.warn("wafw00f not found — skipping WAF fingerprinting")
        return []

    live = _hosts(target, hosts, max_hosts)
    if not live:
        utils.warn("no routable hosts — skipping WAF fingerprinting")
        return []

    outdir = Path(outdir)
    targets_path = outdir / "wafw00f_targets.txt"
    json_path = outdir / "wafw00f.json"
    targets_path.write_text("".join(f"https://{h}\n" for h in live))
    if json_path.exists():
        json_path.unlink()  # never parse a stale result from an earlier run

    utils.run(
        f"wafw00f -a -i {shlex.quote(str(targets_path))} "
        f"-o {shlex.quote(str(json_path))} -f json -T 10 --no-colors",
        timeout=timeout,
    )

    if not json_path.exists():
        utils.warn("wafw00f produced no JSON output — skipping WAF fingerprinting")
        return []
    raw = json_path.read_text(errors="replace")
    rows = _parse_wafw00f_json(raw)
    if not rows:
        if raw.strip() != "[]":
            utils.warn("wafw00f JSON empty or unparseable — skipping WAF fingerprinting")
        return []

    findings: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        firewall = str(row.get("firewall") or "").strip()
        if row.get("detected") is not True or firewall in ("None", ""):
            continue
        url = str(row.get("url") or f"https://{target}")
        host = (urlsplit(url).hostname or target).lower()
        slug = _slug(firewall)
        if not slug or (host, slug) in seen:
            continue
        seen.add((host, slug))
        manufacturer = str(row.get("manufacturer") or "").strip()
        findings.append({
            "severity": "info",
            "template": f"waf:{slug}",
            "name": f"WAF detected: {firewall} ({manufacturer})",
            "url": url,
            "host": host,
            "evidence": manufacturer,
        })

    utils.log(f"WAF fingerprinting: {len(findings)} WAF finding(s) across {len(live)} host(s)")
    return findings
