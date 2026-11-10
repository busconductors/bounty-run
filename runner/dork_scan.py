"""Passive search-engine dorking via Mojeek + DuckDuckGo (Phase 12).

Flow:
  1. Run the first `max_queries` of DORK_QUERIES against both engines with
     `requests.get(..., timeout=(5, 15))` and a generic browser User-Agent.
     `time.sleep(delay)` between queries (not before the first).  The target
     itself is never contacted; only the two search engines are.
  2. Extract result URLs: Mojeek -> every http(s) URL in the HTML minus the
     engine's own links; DuckDuckGo -> the percent-decoded `uddg=` params.
  3. Detect blocking per response (non-200, DDG anomaly/CAPTCHA page, or a DDG
     page with neither results nor "no results").  Warn if every response was
     blocked, or if only some were (partial results).
  4. Scope filter: keep a URL only if its hostname is the target or ends with
     "." + target (rejects lookalikes such as evilexample.com and
     example.com.attacker.net).  Dedupe; normalise the trailing "/".
  5. Classify each kept URL by its path (not by the query that found it) into
     `dork:exposed-file` (low) or `dork:admin-panel` (info); anything else is
     artifact-only.

    from runner.dork_scan import dork_scan
    findings = dork_scan("example.com", outdir)

Artifacts: outdir/dork_urls.txt (every in-scope URL), outdir/dork.txt
(`<query>\\t<engine>\\t<ok|blocked>\\t<in-scope hits>` per engine request).
"""
import html
import re
import time
from pathlib import Path
from urllib.parse import unquote, urlsplit

from runner import events, scope, utils

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

DORK_DELAY = 4  # seconds between queries
DORK_TIMEOUT = (5, 15)  # (connect, read)
DORK_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"

DORK_QUERIES: list[str] = [
    "site:{t} inurl:admin OR inurl:login",
    "site:{t} ext:sql OR ext:log OR ext:bak OR ext:conf OR ext:env",
    'site:{t} intitle:"index of"',
    "site:{t} inurl:phpmyadmin OR inurl:cpanel OR inurl:wp-admin",
]

MOJEEK_URL = "https://www.mojeek.com/search"
DDG_URL = "https://html.duckduckgo.com/html/"

_URL_RE = re.compile(r"""https?://[^\s"'<>]+""", re.I)
_UDDG_RE = re.compile(r"""uddg=([^&"'\s<>]+)""")
_DDG_BLOCK_RE = re.compile(
    r"anomaly|unusual traffic|too many requests|error-lite", re.I)
_DDG_NO_RESULTS_RE = re.compile(r"no\s+results", re.I)

_EXPOSED_EXTS = (".sql", ".log", ".bak", ".conf", ".env", ".old", ".backup",
                 ".swp", ".zip", ".tar.gz")
_ADMIN_RE = re.compile(
    r"/(admin|administrator|wp-admin|phpmyadmin|cpanel|login|signin|dashboard)"
    r"(/|$|\.)", re.I)


def _hostname(url: str) -> str | None:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return host.rstrip(".") if host else None


def _dedupe(urls) -> list[str]:
    seen, out = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _extract_mojeek(page: str) -> list[str]:
    """Every http(s) URL in the page, minus Mojeek's own links."""
    urls = []
    for u in _URL_RE.findall(html.unescape(page or "")):
        host = _hostname(u)
        if not host or host == "mojeek.com" or host.endswith(".mojeek.com"):
            continue
        urls.append(u)
    return _dedupe(urls)


def _extract_ddg(page: str) -> list[str]:
    """Percent-decoded `uddg=` redirect targets."""
    urls = [unquote(m) for m in _UDDG_RE.findall(html.unescape(page or ""))]
    return _dedupe(u for u in urls if _hostname(u))


def _ddg_blocked(page: str) -> bool:
    page = page or ""
    if _DDG_BLOCK_RE.search(page):
        return True
    return "uddg=" not in page and not _DDG_NO_RESULTS_RE.search(page)


def _in_scope(url: str, target: str) -> bool:
    """True if ``url`` is in the active scope (defaults to target + subdomains).

    Thin alias over :func:`runner.scope`; kept as a named attribute because
    tests call it directly.
    """
    t = (target or "").strip().lower().rstrip(".")
    s = scope.active()
    if s.target != t:
        s = scope.default(t)
    return s.url_allowed(url)


def _normalise(url: str) -> str:
    return url.rstrip("/")


def _classify(url: str) -> tuple[str, str] | None:
    try:
        path = urlsplit(url).path or "/"
    except ValueError:
        return None
    if path.lower().endswith(_EXPOSED_EXTS):
        return ("dork:exposed-file", "low")
    if _ADMIN_RE.search(path):
        return ("dork:admin-panel", "info")
    return None


def _fetch(url: str, query: str) -> tuple[int | None, str]:
    """(status, body); (None, "") on any request error."""
    try:
        r = requests.get(url, params={"q": query},
                         headers={"User-Agent": DORK_UA}, timeout=DORK_TIMEOUT)
    except requests.RequestException:
        return None, ""
    return r.status_code, r.text or ""


def dork_scan(target: str, outdir: Path, max_queries: int = 4,
              delay: float = DORK_DELAY) -> list[dict]:
    if not HAVE_REQUESTS:
        utils.warn("requests not installed — skipping dork scan")
        return []
    target = target.strip().lower().rstrip(".")
    outdir = Path(outdir)

    hits: dict[str, set[str]] = {}  # normalised in-scope url -> engines
    log_lines: list[str] = []
    ok = blocked = 0

    queries = DORK_QUERIES[:max(0, max_queries)]
    stage = events.current_stage() or "dork"
    for i, tmpl in enumerate(queries):
        if i:
            time.sleep(delay)
        query = tmpl.format(t=target)
        for engine, url in (("mojeek", MOJEEK_URL), ("duckduckgo", DDG_URL)):
            status, body = _fetch(url, query)
            if engine == "mojeek":
                is_blocked = status != 200
                urls = [] if is_blocked else _extract_mojeek(body)
            else:
                is_blocked = status != 200 or _ddg_blocked(body)
                urls = [] if is_blocked else _extract_ddg(body)
            kept = [_normalise(u) for u in urls if _in_scope(u, target)]
            for u in kept:
                hits.setdefault(u, set()).add(engine)
            if is_blocked:
                blocked += 1
            else:
                ok += 1
            log_lines.append(f"{query}\t{engine}\t"
                             f"{'blocked' if is_blocked else 'ok'}\t{len(kept)}")
        events.progress(stage, i + 1, len(queries))  # also polls skip/cancel

    try:
        (outdir / "dork.txt").write_text(
            "\n".join(log_lines) + ("\n" if log_lines else ""))
        (outdir / "dork_urls.txt").write_text(
            "".join(f"{u}\n" for u in hits))
    except OSError as e:
        utils.warn(f"dork: could not write artifacts: {e}")

    if blocked and not ok:
        utils.warn("every search engine blocked — dork results NOT complete")
        return []
    if blocked:
        utils.warn(f"dork: partial results — {blocked}/{blocked + ok} "
                   "search engine responses blocked")

    findings = []
    for u, engines in hits.items():
        cls = _classify(u)
        if not cls:
            continue
        template, severity = cls
        path = urlsplit(u).path or "/"
        findings.append({
            "severity": severity,
            "template": template,
            "name": f"Dork hit: {path} ({template.split(':', 1)[1]})",
            "url": u,
            "host": _hostname(u),
            "evidence": "indexed by " + ", ".join(sorted(engines)),
        })
    utils.log(f"dork scan: {len(hits)} in-scope URL(s), "
              f"{len(findings)} finding(s)")
    return findings
