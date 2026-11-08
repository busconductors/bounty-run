"""Deeper origin discovery for Cloudflare-fronted targets (Phase 4, capability A).

Uses crt.sh certificate-transparency history to find subdomains whose
certificates leaked the real origin IP before Cloudflare was added in front of
them. Each candidate IP is force-connected to the target via ``curl --resolve``
to confirm it actually serves the site.

Manual (NOT automated — needs API keys) fingerprints that also work here:

    shodan search ssl.cert.subject.CN:"<target>"
    shodan search hostname:<target>
    censys search "<target>"

Run these by hand when crt.sh alone does not surface the origin.
"""
import ipaddress
import json
from pathlib import Path

from . import stages, utils


def _is_global(ip: str) -> bool:
    """True if ``ip`` is a global (non-private, non-loopback, etc.) address."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def origin_deep(target: str, outdir: Path, cf_result: dict) -> list[dict]:
    """Discover non-Cloudflare origin IPs for ``target`` via crt.sh SAN history.

    Returns ``list[{"ip", "sources", "status", "remote_ip"}]`` — the same shape
    as :func:`stages.origin_hunt`, so ``cli.py`` can merge the two lists.
    """
    utils.log(f"deep origin discovery via crt.sh ({target})")

    # 1. Query crt.sh for every certificate whose SANs mention <target>.
    crt_url = f"https://crt.sh/?q=%25.{target}&output=json"
    body = utils.run(f"curl -sS --connect-timeout 10 --max-time 30 \"{crt_url}\"", timeout=40)

    if not body.strip():
        utils.warn("  crt.sh returned no data — aborting deep origin discovery")
        return []

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        utils.warn("  crt.sh returned invalid JSON — aborting deep origin discovery")
        return []

    if not isinstance(data, list):
        utils.warn("  crt.sh returned unexpected payload — aborting deep origin discovery")
        return []

    # 2. Split each name_value on newlines; strip "*." and whitespace; keep only
    #    lines that are the target itself or a subdomain of it.
    tgt = target.strip().lower()
    subs = set()
    for item in data:
        if not isinstance(item, dict):
            continue
        name_value = item.get("name_value", "")
        if not isinstance(name_value, str):
            continue
        for line in name_value.splitlines():
            line = line.strip().lower()
            if line.startswith("*."):
                line = line[2:].strip()
            if line == tgt or line.endswith("." + tgt):
                subs.add(line)

    utils.log(f"  {len(subs)} unique subdomain(s) from crt.sh")

    # 4. Load Cloudflare ranges up front — a false positive would poison results.
    ranges = stages._cloudflare_ranges()
    utils.log(f"  loaded {len(ranges)} Cloudflare ranges (AS13335)")
    if not ranges:
        utils.warn("  could not load Cloudflare ranges — aborting deep origin "
                   "discovery (would false-positive)")
        return []

    # 3 + 5. Dedupe (already done via the set), resolve each, keep only IPs that
    #        are NOT Cloudflare. Collect sources keyed by the IP they came from.
    candidates = {}  # ip -> list of subdomains that resolved to it
    for sub in sorted(subs):
        ip = stages._resolve(sub)
        if ip and _is_global(ip) and not stages._is_cloudflare(ip, ranges):
            candidates.setdefault(ip, []).append(sub)

    # 6. Verify each candidate by force-connecting to the origin IP.
    rows = []
    for ip, sources in sorted(candidates.items()):
        out = utils.run(
            f"curl -sS -k --connect-timeout 10 -o /dev/null -w '%{{http_code}}|%{{remote_ip}}' "
            f"--resolve {target}:443:{ip} --max-time 12 https://{target}",
            timeout=20,
        )
        parts = out.strip().split("|")
        rows.append({
            "ip": ip,
            "sources": sources,
            "status": parts[0] if parts else "",
            "remote_ip": parts[1] if len(parts) > 1 else "",
        })

    # 7. Write the artifact + log counts.
    outfile = outdir / "origin_deep.txt"
    lines = [f"{r['ip']}\t{r['status']}\t{','.join(r['sources'])}" for r in rows]
    outfile.write_text("\n".join(lines) + "\n")
    utils.log(f"  {len(rows)} deep origin candidate(s) -> {outfile.name}")
    for r in rows:
        utils.log(f"    {r['ip']}  [{r['status']}]  via {', '.join(r['sources'])}")
    return rows
