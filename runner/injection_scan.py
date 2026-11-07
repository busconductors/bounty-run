"""Injection scanning stage (Phase 6, Feature 1): SSTI / NoSQLi / XSS / redirect.

Reuses the endpoint discovery that param_scan already does (Wayback CDX ->
strip param values -> sane-name filter -> dedupe -> cap), then feeds each
endpoint to the vendored SpyHunt scanners plus fresh reflected-XSS and
open-redirect checks.

Scanner-API reality (see SPEC-PHASE6.md):
  * SSTIScanner.scan(url, param, timeout) and NoSQLInjectionScanner.scan(url,
    param, timeout) require a ``param`` arg.
  * The vendored scanners parse the query with parse_qs, which drops blank
    values -- so we re-derive param NAMES via parse_qsl(keep_blank_values=True)
    and seed a non-blank value (``1``) before calling them.

    from runner.injection_scan import injection_scan
    findings = injection_scan("example.com", outdir)
"""
import ipaddress
import re
import socket
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlsplit, urlunsplit

import requests
import urllib3

from runner import utils
from runner.param_scan import _read_cached_endpoints, discover_endpoints
from runner.vendor.advanced_scanners import NoSQLInjectionScanner, SSTIScanner

urllib3.disable_warnings()

# Template names emitted by this stage.
T_SSTI = "spyhunt-ssti"
T_NOSQLI = "spyhunt-nosqli"
T_XSS = "spyhunt-xss"
T_OPENREDIRECT = "spyhunt-openredirect"

# 16 external hostnames used as absolute ``https://`` open-redirect payloads
# (SPEC-PHASE6.1 item 7: only absolute http(s) redirect targets are accepted).
OPEN_REDIRECT_HOSTS = [
    "evil.com", "evil.net", "attacker.com", "hacker.com",
    "google.com", "example.com", "bing.com", "yahoo.com",
    "yandex.ru", "baidu.com", "paypal.com", "facebook.com",
    "twitter.com", "microsoft.com", "apple.com", "github.com",
]

# Real reflected-XSS payloads (SPEC-PHASE6.1 item 5).
_XSS_SCRIPT_PAYLOAD = "<script>alert(1)</script>"
_XSS_EVENT_PAYLOAD = "<img src=x onerror=alert(1)>"
_XSS_PAYLOADS = (_XSS_SCRIPT_PAYLOAD, _XSS_EVENT_PAYLOAD)

_EVENT_ATTR_RE = re.compile(
    r'\son(?:load|error|click|mouseover|mouseout|focus|blur|submit|change|input|'
    r'keyup|keydown|dblclick|scroll|resize|select|unload)\s*=\s*("[^"]*"|\'[^\']*\'|[^\s>]*)',
    re.IGNORECASE,
)


def _param_names(url: str) -> list[str]:
    """Ordered, unique query-param names (keep blank values so ``a=`` survives)."""
    seen = set()
    names = []
    for key, _value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        if key not in seen:
            seen.add(key)
            names.append(key)
    return names


def _seed_params(url: str, value: str = "1") -> str:
    """Rewrite ``a=&b=`` as ``a=1&b=1`` so the vendored scanners' parse_qs keeps them."""
    parts = urlsplit(url)
    names = [k for k, _ in parse_qsl(parts.query, keep_blank_values=True)]
    query = urlencode([(k, value) for k in names])
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def _is_global_host(host: str) -> bool:
    """True if ``host`` resolves to a publicly-routable address (SSRF guard)."""
    if not host:
        return False
    try:
        ip = socket.gethostbyname(host)
        return ipaddress.ip_address(ip).is_global
    except Exception:  # noqa: BLE001
        return False


def _to_schema(kind: str, hit: dict, target: str) -> dict:
    """Map a scanner hit dict to the shared finding schema.

    Field shapes (SPEC-PHASE6 C1): SSTI hits carry ``template_engine`` +
    ``test_type``; NoSQLi hits carry ``payload_type``. Severity passes through
    from the scanner dict (M4), lowercased -- except NoSQLi, which is pinned to
    ``medium`` (SPEC-PHASE6.1 item 4). ``evidence`` is optional (M3).
    """
    severity = str(hit.get("severity") or "unknown").lower()
    url = hit.get("url", "") or ""

    if kind == "ssti":
        engine = hit.get("template_engine", "unknown")
        test_type = hit.get("test_type", "unknown")
        finding = {
            "severity": severity,
            "template": T_SSTI,
            "name": f"SSTI ({engine}, {test_type})",
            "url": url,
            "host": target,
        }
    elif kind == "nosqli":
        db = hit.get("db_type") or hit.get("payload_type") or "unknown"
        finding = {
            "severity": "medium",
            "template": T_NOSQLI,
            "name": f"NoSQL injection ({db})",
            "url": url,
            "host": target,
        }
    else:  # pragma: no cover - defensive fallback
        finding = {
            "severity": severity,
            "template": "spyhunt-" + kind,
            "name": kind,
            "url": url,
            "host": target,
        }

    evidence = hit.get("evidence")
    if evidence:
        finding["evidence"] = evidence
    return finding


def _xss_payload_reflected(payload: str, body: str) -> bool:
    """Pure: True if ``payload`` is reflected unmodified in an executable context.

    ``payload`` is one of the real XSS payloads (a ``<script>`` element or an
    element carrying an ``on*`` handler). A literal match is the execution
    signal: HTML-escaping (``&lt;script&gt;``) changes the bytes, so an escaped
    reflection never contains the raw payload. Requiring the payload itself to
    be a script tag or event-attribute element guarantees the match lands in an
    executable context rather than plain text.
    """
    if payload not in body:
        return False
    stripped = payload.lstrip().lower()
    if stripped.startswith("<script"):
        return True
    return _EVENT_ATTR_RE.search(payload) is not None


def _redirect_target_differs(target_netloc: str, location: str) -> bool:
    """Pure: True if ``location`` is an absolute http(s) URL to a different host.

    Rejects relative / path-only redirects and protocol-relative ``//host``
    forms (neither carries an ``http``/``https`` scheme), per SPEC-PHASE6.1
    item 7.
    """
    if not location:
        return False
    parsed = urlparse(location)
    if parsed.scheme not in ("http", "https"):
        return False
    if not parsed.netloc:
        return False
    return parsed.netloc != target_netloc


def _xss_reflected(url: str, target: str, timeout: int = 8) -> dict | None:
    """Inject real XSS payloads into each param; flag only unmodified, executable reflection."""
    parts = urlsplit(url)
    names = _param_names(url)
    for name in names:
        for payload in _XSS_PAYLOADS:
            query = urlencode([(k, payload if k == name else "1") for k in names])
            test_url = urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))
            try:
                r = requests.get(test_url, timeout=timeout, verify=False, allow_redirects=False)
            except requests.RequestException:
                continue
            if not _xss_payload_reflected(payload, r.text):
                continue
            return {
                "severity": "medium",
                "template": T_XSS,
                "name": "Reflected XSS",
                "url": test_url,
                "host": target,
                "evidence": f"{payload} reflected unmodified in executable context (manual verification required)",
            }
    return None


def _open_redirect(url: str, target: str, timeout: int = 8) -> dict | None:
    """Inject 16 absolute ``https://host`` payloads; flag only when the redirect
    Location is an absolute http(s) URL to a different host."""
    parts = urlsplit(url)
    original_netloc = parts.netloc
    names = _param_names(url)
    for name in names:
        for host in OPEN_REDIRECT_HOSTS:
            payload = f"https://{host}"
            query = urlencode([(k, payload if k == name else "1") for k in names])
            test_url = urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))
            try:
                r = requests.get(test_url, timeout=timeout, verify=False, allow_redirects=False)
            except requests.RequestException:
                continue
            if r.status_code not in (301, 302, 303, 307, 308):
                continue
            location = r.headers.get("Location", "")
            if not location:
                continue
            if _redirect_target_differs(original_netloc, location):
                return {
                    "severity": "medium",
                    "template": T_OPENREDIRECT,
                    "name": "Open redirect",
                    "url": test_url,
                    "host": target,
                    "evidence": f"Location: {location}",
                }
    return None


def injection_scan(target: str, outdir: Path, max_urls: int = 50, timeout: int = 10) -> list[dict]:
    """Stage: SSTI / NoSQLi / reflected XSS / open redirect over discovered endpoints.

    Re-discovers its own endpoints (shared with param_scan), so it also works when
    the ``param`` stage is skipped. Dedupe happens later at the cli.py layer.
    """
    findings: list[dict] = []
    # Prefer the endpoints param_scan already discovered this run (avoids a second
    # CDX hit, which doubles the throttle risk). Only query CDX ourselves when the
    # param stage was skipped and no param_urls.txt exists yet.
    endpoints = _read_cached_endpoints(outdir, max_urls)
    if endpoints:
        utils.log(f"  reusing {len(endpoints)} endpoint(s) from param_urls.txt")
    else:
        endpoints = discover_endpoints(target, outdir, max_urls)
    if not endpoints:
        return []

    ssti = SSTIScanner()
    nosqli = NoSQLInjectionScanner()

    for url in endpoints:
        host = urlsplit(url).hostname or ""
        if not _is_global_host(host):  # SSRF guard (S3): skip non-global hosts
            utils.warn(f"  skipping non-global endpoint host: {host}")
            continue

        seeded = _seed_params(url)
        for param in _param_names(url):
            for hit in ssti.scan(seeded, param, timeout):
                findings.append(_to_schema("ssti", hit, target))
            for hit in nosqli.scan(seeded, param, timeout):
                findings.append(_to_schema("nosqli", hit, target))

        x = _xss_reflected(url, target, timeout)
        if x:
            findings.append(x)
        o = _open_redirect(url, target, timeout)
        if o:
            findings.append(o)

    utils.log(f"  injection scan flagged {len(findings)} finding(s)")
    return findings
