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
import shlex
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from runner import utils

CDX_URL = (
    'curl -sS "https://web.archive.org/cdx/search/cdx'
    '?url=*.{target}/*&output=json&fl=original&collapse=urlkey&limit=500"'
)

SQLMAP_FLAGS = "--batch --level 1 --risk 1 --smart --flush-session"

# Case-insensitive markers that indicate sqlmap found something injectable.
VULN_MARKERS = (
    "is vulnerable",
    "identified the following injection point",
    "injectable",
)


def _strip_param_values(url: str) -> str:
    """Blank query-string values while keeping (unique, ordered) param names.

    ``http://x/y?a=1&a=2&b=z`` -> ``http://x/y?a=&b=``
    """
    parts = urlsplit(url)
    if not parts.query:
        return url
    seen = set()
    names = []
    for key, _value in parse_qsl(parts.query, keep_blank_values=True):
        if key not in seen:
            seen.add(key)
            names.append(key)
    query = "&".join(f"{key}=" for key in names)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def _discover_urls(raw: str) -> list[str]:
    """Parse the CDX JSON body; drop the header row; keep only URLs with a query."""
    if not raw:
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


def param_scan(target: str, outdir: Path, max_urls: int = 50) -> list[dict]:
    """Discover parameterized URLs via Wayback CDX and test them with sqlmap.

    Returns a list of findings; dedupe happens later at the cli.py layer.
    """
    findings: list[dict] = []

    raw = utils.run(CDX_URL.format(target=target), timeout=60)

    endpoints = []
    seen = set()
    for url in _discover_urls(raw):
        norm = _strip_param_values(url)
        if norm not in seen:
            seen.add(norm)
            endpoints.append(norm)
        if len(endpoints) >= max_urls:
            break
    endpoints = endpoints[:max_urls]

    if not endpoints:
        utils.warn(f"  no parameterized URLs discovered for {target}")
        return []

    (outdir / "param_urls.txt").write_text("\n".join(endpoints) + "\n")
    utils.log(f"  discovered {len(endpoints)} parameterized endpoint(s) for {target}")

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
