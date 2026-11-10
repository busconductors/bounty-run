"""Secret exposure scan over live homepages and their same-origin JS (Feature 2).

Flow:
  1. Read outdir/live_hosts.txt (tab-separated; first column is the host).
  2. SSRF guard: keep only hosts that resolve to a publicly-routable IP.
  3. For each host, fetch the homepage (https, falling back to http), scan it
     against a vendored set of secret regexes, then pull up to MAX_JS_FILES
     same-origin <script src> files and scan those too.
  4. Emit at most one finding per (host, pattern class); the matched value is
     redacted to its last 4 characters in the evidence field.

    from runner.secret_scan import secret_scan
    findings = secret_scan("example.com", outdir)
"""
import re
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from runner import events, utils
from runner.stages import _is_global, _resolve

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

# Secret patterns (stdlib re only). Only high-precision, prefix-anchored provider
# patterns are kept. The generic keyword patterns (api_key / password / token) were
# removed: they matched JS identifiers (capToken, recaptchaToken), minified-code
# literals (password:!0) and publishable client-side keys (Weglot wg_... in a CDN
# URL), yielding a 100% false-positive rate with no real signal. See POSTMORTEM.
PATTERNS = {
    'aws_access_key': r'AKIA[0-9A-Z]{16}',
    'aws_secret_key': r'aws_secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})',
    'jwt': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
    'private_key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
    'github_token': r'gh[pousr]_[a-zA-Z0-9]{36,}',
    'slack_token': r'xox[baprs]-[0-9a-zA-Z]{10,}',
    'stripe_key': r'sk_live_[0-9a-zA-Z]{24,}',
    'google_api': r'AIza[0-9A-Za-z\-_]{35}',
}

MAX_JS_FILES = 5
FETCH_TIMEOUT = 3  # seconds

# Generic, noisy classes — reported as low; everything else is high.
# (Empty now that the generic keyword patterns are gone; kept for the severity hook.)
_LOW_SEVERITY: set[str] = set()

_LABELS = {
    'aws_access_key': "AWS access key",
    'aws_secret_key': "AWS secret key",
    'jwt': "JWT",
    'private_key': "Private key",
    'github_token': "GitHub token",
    'slack_token': "Slack token",
    'stripe_key': "Stripe live key",
    'google_api': "Google API key",
}

_SCRIPT_SRC_RE = re.compile(r'<script\b[^>]*?\bsrc\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)


def secret_scan(target: str, outdir: Path) -> list[dict]:
    """Scan live hosts' homepages + same-origin JS for exposed secrets."""
    utils.log("secret scan (HTML + JS)")
    if not HAVE_REQUESTS:
        utils.warn("requests not installed — skipping secret scan")
        return []

    live_path = Path(outdir) / "live_hosts.txt"
    if not live_path.exists():
        utils.warn(f"{live_path} missing — skipping secret scan")
        return []

    hosts = [h for h in _read_live_hosts(live_path) if _is_global(_resolve(h))]

    findings: list[dict] = []
    stage = events.current_stage() or "secret"
    for i, host in enumerate(hosts):
        findings.extend(_scan_host(host, max_js=MAX_JS_FILES, timeout=FETCH_TIMEOUT))
        events.progress(stage, i + 1, len(hosts))  # also polls skip/cancel

    utils.log(f"secret scan: {len(findings)} finding(s) across {len(hosts)} host(s)")
    return findings


def _read_live_hosts(path) -> list[str]:
    """First tab-separated field of each non-empty line."""
    hosts = []
    for line in Path(path).read_text(errors="replace").splitlines():
        first = line.split("\t", 1)[0].strip()
        if first:
            hosts.append(first)
    return hosts


def _fetch(url: str, timeout=FETCH_TIMEOUT) -> str:
    """GET `url` and return the body text; "" on any failure or non-200."""
    try:
        from runner import httpclient
        r = httpclient.get(url, timeout=(timeout, timeout), allow_redirects=True)
        return r.text if r.status_code == 200 else ""
    except Exception:  # noqa: BLE001
        return ""


def _is_same_origin(src: str, host: str) -> bool:
    """True if a script src is relative/protocol-relative or points at `host`."""
    parts = urlsplit(src)
    if parts.scheme and parts.scheme.lower() not in ("http", "https"):
        return False
    if parts.netloc:
        return (parts.hostname or "").lower() == host.lower()
    return True


def _scan_host(host: str, max_js: int, timeout) -> list[dict]:
    """Scan one host's homepage and up to `max_js` same-origin JS files."""
    homepage_url = f"https://{host}"
    html = _fetch(homepage_url, timeout)
    if not html:
        homepage_url = f"http://{host}"
        html = _fetch(homepage_url, timeout)
    if not html:
        return []

    findings: list[dict] = []
    seen_classes: set[str] = set()

    def scan(text: str, url: str) -> None:
        for cls, pattern in PATTERNS.items():
            if cls in seen_classes:
                continue
            m = re.search(pattern, text, re.IGNORECASE)
            if not m:
                continue
            seen_classes.add(cls)
            findings.append({
                "severity": "low" if cls in _LOW_SEVERITY else "high",
                "template": "secret-exposure",
                "name": f"Exposed {_LABELS.get(cls, cls)}",
                "url": url,
                "host": host,
                "evidence": "..." + m.group(0)[-4:],
            })

    scan(html, homepage_url)

    seen: set[str] = set()
    fetched = 0
    for src in _SCRIPT_SRC_RE.findall(html):
        if fetched >= max_js:
            break
        if not _is_same_origin(src, host):
            continue
        url = urljoin(homepage_url, src)
        if url in seen:
            continue
        seen.add(url)
        fetched += 1
        js = _fetch(url, timeout)
        if js:
            scan(js, url)

    return findings
