"""Deeper origin discovery for Cloudflare-fronted targets (Phase 4, capability A).

Uses crt.sh certificate-transparency history to find subdomains whose
certificates leaked the real origin IP before Cloudflare was added in front of
them. Each surviving candidate IP is graded by :mod:`runner.ipintel` (range
feeds, ASN/WHOIS metadata, active checks with negative controls) exactly like
:func:`stages.origin_hunt`; only CONFIRMED rows are admitted into scan scope.

Manual (NOT automated — needs API keys) fingerprints that also work here:

    shodan search ssl.cert.subject.CN:"<target>"
    shodan search hostname:<target>
    censys search "<target>"

Run these by hand when crt.sh alone does not surface the origin.
"""
import ipaddress
import json
from pathlib import Path

from . import proxy as proxymod
from . import stages, utils


def _is_global(ip: str) -> bool:
    """True if ``ip`` is a global (non-private, non-loopback, etc.) address."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def origin_deep(target: str, outdir: Path, cf_result: dict, proxy=None) -> list[dict]:
    """Discover non-Cloudflare origin IPs for ``target`` via crt.sh SAN history.

    Returns ``list[{"ip", "sources", "status", "remote_ip", "tier", "reason",
    ...}]`` — the same shape as :func:`stages.origin_hunt`, so ``cli.py`` can
    merge the two lists.
    """
    utils.log(f"deep origin discovery via crt.sh ({target})")

    # 1. Query crt.sh for every certificate whose SANs mention <target>.
    crt_url = f"https://crt.sh/?q=%25.{target}&output=json"
    pk = proxymod.run_kw(proxy)
    px = proxy.cli("curl") if proxy is not None else ""
    body = utils.run(f"curl -sS --connect-timeout 10 --max-time 30{px} \"{crt_url}\"",
                     timeout=40, **pk)

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
    ranges = stages._cloudflare_ranges(**pk)
    utils.log(f"  loaded {len(ranges)} Cloudflare ranges (AS13335)")
    if not ranges:
        utils.warn("  could not load Cloudflare ranges — aborting deep origin "
                   "discovery (would false-positive)")
        return []

    # 3 + 5. Dedupe (already done via the set), resolve each (every A record),
    #        keep only IPs that are NOT Cloudflare. Sources keyed by IP.
    candidates = {}  # ip -> list of subdomains that resolved to it
    for sub in sorted(subs):
        for ip in stages._resolve_all(sub):
            if not (_is_global(ip) and not stages._is_cloudflare(ip, ranges)):
                continue
            # A CT name is in the target's zone by construction, but it may
            # CNAME out to a SaaS/CDN (status -> statuspage.io, help -> zendesk,
            # shop -> shopify); that IP is the provider's, not the origin.
            why = stages._third_party_reason(sub, target)
            if why:
                utils.log(f"  skip {ip} ({sub}): {why}")
                continue
            candidates.setdefault(ip, []).append(sub)

    # 6. Grade each candidate (shared ranges, metadata, active verification).
    rows = stages.classify_candidates(target, candidates, proxy)

    # 7. Write the artifact + log counts.
    outfile = outdir / "origin_deep.txt"
    stages.write_origin_file(outfile, rows)
    utils.log(f"  {len(rows)} deep origin candidate(s) -> {outfile.name}")
    stages.log_origin_rows(rows)
    return rows
