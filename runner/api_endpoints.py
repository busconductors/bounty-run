"""API endpoint enumeration via katana crawl (Phase 11).

Flow:
  1. Resolve the host list (target + up to max_hosts live hosts); SSRF-guard to
     publicly-routable IPs only.
  2. Crawl each host with katana in JSONL mode, pulling request endpoints.
  3. Keep only API-like URLs (path contains /api/, /graphql, /v1/, /v2/, /rest/,
     /ajax/, .json, endpoint or xhr) and drop static assets.
  4. Emit one `api-endpoint` finding per surviving URL.

    from runner.api_endpoints import api_endpoints_scan
    findings = api_endpoints_scan("example.com", outdir)

Note: katana's JSON output is gated behind -jsonl (-jc is js-crawl, not JSON),
so the command is `katana -u <url> -d <depth> -jc -jsonl -silent`.  Each JSONL
line carries the crawled URL at request.endpoint.
"""
import json
from pathlib import Path
from urllib.parse import urlsplit

from runner import events, scope, utils
from runner.stages import _is_global, _resolve

# Path substrings that mark a URL as API-like.
API_KEYWORDS = ("/api/", "/graphql", "/v1/", "/v2/", "/rest/", "/ajax/",
                ".json", "endpoint", "xhr")

# Static-asset extensions to drop even when a keyword matches.
STATIC_EXTS = (".js", ".css", ".png", ".ico", ".svg", ".woff", ".woff2",
               ".jpg", ".jpeg", ".gif", ".webp")


def _read_live_hosts(path) -> list[str]:
    """First tab-separated field of each non-empty line."""
    hosts = []
    for line in Path(path).read_text(errors="replace").splitlines():
        first = line.split("\t", 1)[0].strip()
        if first:
            hosts.append(first)
    return hosts


def _live_hosts(outdir: Path, target: str, hosts: list[str] | None,
                max_hosts: int) -> list[str]:
    """Resolve the host list to crawl; SSRF-guard to public IPs, cap at max_hosts.

    The target leads the list so it is always crawled when routable.
    """
    if hosts:
        src = list(hosts)
    else:
        live_path = Path(outdir) / "live_hosts.txt"
        src = _read_live_hosts(live_path) if live_path.exists() else []
    ordered = [target] + [h for h in src if h != target]
    live: list[str] = []
    seen: set[str] = set()
    for h in ordered:
        if h in seen:
            continue
        seen.add(h)
        if _is_global(_resolve(h)):
            live.append(h)
    return live[:max_hosts]


def _is_api_url(url: str) -> bool:
    """True if url's path is API-like and not a static asset."""
    path = urlsplit(url).path.lower()
    if path.endswith(STATIC_EXTS):
        return False
    return any(kw in path for kw in API_KEYWORDS)


def _crawl(url: str, depth: int, timeout: int) -> list[str]:
    """Run katana over one URL in JSONL mode; return the crawled endpoint URLs."""
    raw = utils.run(
        f"katana -u {url} -d {depth} -jc -jsonl -silent",
        timeout=timeout,
    )
    urls: list[str] = []
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        endpoint = ((obj.get("request") or {}).get("endpoint") or "").strip()
        if endpoint:
            urls.append(endpoint)
    return urls


def api_endpoints_scan(target: str, outdir: Path, hosts: list[str] | None = None,
                       depth: int = 3, max_hosts: int = 20,
                       timeout: int = 300) -> list[dict]:
    """Crawl live hosts with katana and emit API-endpoint findings."""
    utils.log("API endpoint enumeration (katana)")
    if not utils.have("katana"):
        utils.warn("katana not found — skipping API endpoint enumeration")
        events.mark_skipped("tool missing: katana")
        return []

    live = _live_hosts(outdir, target, hosts, max_hosts)
    if not live:
        utils.warn("no routable hosts — skipping API endpoint enumeration")
        return []

    sc = scope.for_target(target)
    findings: list[dict] = []
    kept_urls: list[str] = []
    seen: set[str] = set()
    for host in live:
        for url in _crawl(f"https://{host}", depth, timeout):
            if url in seen or not _is_api_url(url):
                continue
            # Scope gap closure: katana can wander off-target; drop those URLs.
            if not sc.url_allowed(url):
                continue
            seen.add(url)
            kept_urls.append(url)
            path = urlsplit(url).path or "/"
            findings.append({
                "severity": "info",
                "template": "api-endpoint",
                "name": f"API endpoint: {path}",
                "url": url,
                "host": urlsplit(url).hostname or host,
            })

    (Path(outdir) / "api_endpoints.txt").write_text("\n".join(kept_urls) + "\n")
    utils.log(f"api endpoints: {len(findings)} endpoint(s) across {len(live)} host(s)")
    return findings
