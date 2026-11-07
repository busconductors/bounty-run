"""Param discovery via Wayback CDX + sqlmap injection testing (Phase 4, capability B).

Flow:
  1. Pull parameterized URLs from the Wayback Machine CDX API.
  2. Normalize each URL to its endpoint (param names kept, values stripped) so we
     don't re-test the same endpoint with many different values.
  3. If sqlmap is not on PATH, warn and skip injection testing.
  4. Run sqlmap against each normalized endpoint; flag anything it calls injectable.
  5. Write outdir/param_urls.txt and outdir/sqlmap_report.txt.

    from runner.param_scan import param_scan
    findings = param_scan("example.com", outdir)
"""
import json
import re
import shlex
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from runner import utils

# A real UA + retries/backoff + --fail so throttled error bodies (429/503 HTML)
# don't get fed to json.loads. --compressed keeps the 500-row payload small.
_CDX_UA = "Mozilla/5.0 (compatible; bounty-run/1.0)"
CDX_URL = (
    'curl -sS -A "' + _CDX_UA + '" --compressed --fail '
    '--retry 3 --retry-delay 2 --retry-all-errors --max-time 45 '
    '"https://web.archive.org/cdx/search/cdx'
    '?url=*.{target}/*&output=json&fl=original&collapse=urlkey&limit=500"'
)

SQLMAP_FLAGS = "--batch --level 1 --risk 1 --smart --flush-session"

# Case-insensitive markers that indicate sqlmap found something injectable.
# NOTE: "injectable" is deliberately excluded — it also matches sqlmap's
# NEGATIVE messages ("does not seem to be injectable"), which caused
# false positives on nearly every endpoint.
VULN_MARKERS = (
    "is vulnerable",
    "identified the following injection point",
)

# A sane query-parameter name: letters, digits, underscore, hyphen, and PHP-style
# array brackets (idcat[], filter[cat]). Wayback frequently mis-parses minified
# JS/JSON fragments into fake params like "0:this.cssPosition" or "obj.src:oldList";
# those contain ":", ".", "/", "," or "!" and are rejected here.
_VALID_PARAM = re.compile(r"^[A-Za-z0-9_\-]+(?:\[[A-Za-z0-9_\-]*\])?$")


def _strip_param_values(url: str) -> str:
    """Blank query-string values while keeping (unique, ordered, sane) param names.

    ``http://x/y?a=1&a=2&b=z`` -> ``http://x/y?a=&b=``
    Returns ``""`` when no parameter name survives the sanity filter.
    """
    parts = urlsplit(url)
    if not parts.query:
        return url
    seen = set()
    names = []
    for key, _value in parse_qsl(parts.query, keep_blank_values=True):
        if not _VALID_PARAM.match(key):
            continue
        if key not in seen:
            seen.add(key)
            names.append(key)
    if not names:
        return ""
    query = "&".join(f"{key}=" for key in names)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def _discover_urls(raw: str) -> list[str]:
    """Parse the CDX JSON body; drop the header row; keep only URLs with a query."""
    if not raw:
        return []
    # A throttled/error response from web.archive.org is an HTML or XML page, not
    # JSON. Detect that up front so we log *why* instead of a bare parse error.
    if raw.lstrip()[:1] == "<":
        snippet = " ".join(raw.split())[:120]
        utils.warn(f"  wayback CDX returned an HTML/XML error body (throttled?): {snippet}")
        return []
    try:
        rows = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        utils.warn("  wayback CDX returned unparseable JSON")
        return []
    if not isinstance(rows, list):
        return []
    out = []
    for i, row in enumerate(rows):
        if not isinstance(row, list) or not row:
            continue
        if i == 0 and row[0] == "original":  # skip the header row
            continue
        url = row[0]
        if isinstance(url, str) and "?" in url:
            out.append(url)
    return out


def _is_injectable(stdout: str) -> bool:
    low = stdout.lower()
    return any(marker in low for marker in VULN_MARKERS)


def _in_scope(url: str, target: str) -> bool:
    """Return True if ``url`` is an http(s) URL on ``target`` or a subdomain.

    ``http://sub.example.com/x`` -> True; ``http://evil.com/x`` -> False.
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return False
    host = (parts.hostname or "").lower()
    target = target.lower()
    return host == target or host.endswith("." + target)


def _read_cached_endpoints(outdir: Path, max_urls: int) -> list[str]:
    """Return endpoints from a previously-written outdir/param_urls.txt, or []."""
    cache = outdir / "param_urls.txt"
    if not cache.exists():
        return []
    lines = [ln.strip() for ln in cache.read_text().splitlines() if ln.strip()]
    return lines[:max_urls]


def discover_endpoints(target: str, outdir: Path, max_urls: int = 50) -> list[str]:
    """Wayback CDX discovery -> _strip_param_values -> _VALID_PARAM filter -> dedupe -> cap.

    Shared by ``param_scan`` (sqlmap) and ``injection_scan`` (SSTI/NoSQLi/CRLF/XSS/
    open-redirect). Writes ``outdir/param_urls.txt`` idempotently; returns the
    normalized endpoint list (empty when nothing discovered, in which case the file
    is not written).
    """
    raw = utils.run(CDX_URL.format(target=target), timeout=60)

    endpoints = []
    seen = set()
    for url in _discover_urls(raw):
        if not _in_scope(url, target):
            continue
        norm = _strip_param_values(url)
        if not norm:  # no sane parameter names survived the filter
            continue
        if norm not in seen:
            seen.add(norm)
            endpoints.append(norm)
        if len(endpoints) >= max_urls:
            break
    endpoints = endpoints[:max_urls]

    if not endpoints:
        cached = _read_cached_endpoints(outdir, max_urls)
        if cached:
            utils.warn(f"  CDX discovery empty — reusing {len(cached)} endpoint(s) "
                       f"from existing param_urls.txt")
            return cached
        utils.warn(f"  no parameterized URLs discovered for {target}")
        return []

    (outdir / "param_urls.txt").write_text("\n".join(endpoints) + "\n")
    utils.log(f"  discovered {len(endpoints)} parameterized endpoint(s) for {target}")
    return endpoints


def param_scan(target: str, outdir: Path, max_urls: int = 50) -> list[dict]:
    """Discover parameterized URLs via Wayback CDX and test them with sqlmap.

    Returns a list of findings; dedupe happens later at the cli.py layer.
    """
    findings: list[dict] = []

    endpoints = discover_endpoints(target, outdir, max_urls)
    if not endpoints:
        return []

    if not utils.have("sqlmap"):
        utils.warn("  sqlmap not found on PATH; skipping injection testing")
        return []

    report_parts = []
    for url in endpoints:
        cmd = f"sqlmap -u {shlex.quote(url)} {SQLMAP_FLAGS}"
        out = utils.run(cmd, timeout=300)
        report_parts.append(f"### {url}\n{out}\n")
        if _is_injectable(out):
            findings.append({
                "severity": "high",
                "template": "sqlmap-sqli",
                "name": "SQL injection",
                "url": url,
                "host": target,
            })

    (outdir / "sqlmap_report.txt").write_text("\n".join(report_parts))
    utils.log(f"  sqlmap flagged {len(findings)} endpoint(s) as injectable")
    return findings
