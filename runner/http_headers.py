"""Security-header audit + CORS misconfiguration scanning (Phase 7b).

- security_headers_scan: vendor + wrap parrot-recon's shcheck.py (stdlib-only).
- cors_scan: reimplemented 6-origin probe (requests), no tqdm dependency.
"""
import json
import random
import string
from pathlib import Path
from urllib.parse import urlsplit

from runner import events, evidence, utils
from runner.stages import _is_global, _resolve

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

SHCHECK = Path(__file__).resolve().parent / "vendor" / "shcheck.py"

# Headers whose absence is a low-severity finding; everything else is info.
_MISSING_LOW = {
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
}

_CORS_TIMEOUT = 5  # seconds per request


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


def security_headers_scan(target: str, outdir: Path, hosts: list[str] | None = None,
                          include_deprecated: bool = False,
                          proxy=None) -> list[dict]:
    """Invoke vendored shcheck.py and return missing/insecure-header findings."""
    utils.log("security headers (shcheck)")
    if not SHCHECK.exists():
        utils.warn("shcheck.py not vendored — skipping security-header scan")
        return []

    live = _live_hosts(outdir, target, hosts)
    if not live:
        utils.warn("no routable hosts — skipping security-header scan")
        return []

    urls = [f"https://{h}" for h in live]
    cmd = f"python3 {SHCHECK} -j -d -g {' '.join(urls)}"
    if include_deprecated:
        cmd += " -k"
    from runner import proxy as proxymod
    if proxy is not None:
        if not proxymod.gate(proxy, "shcheck"):
            return []
        cmd += proxy.cli("shcheck")
    else:
        # legacy path: proxy configured only on the shared HTTP client
        from runner import httpclient
        proxy_args = httpclient.tool_proxy_args("shcheck")
        if proxy_args:
            cmd += " " + " ".join(proxy_args)
    raw = utils.run(cmd, outfile=str(Path(outdir) / "security_headers.json"), timeout=120,
                    **proxymod.run_kw(proxy))
    data = _parse_shcheck_json(raw)

    findings: list[dict] = []
    for url, result in data.items():
        host = urlsplit(url).netloc or target
        present = result.get("present") or {}
        for hdr in result.get("missing") or []:
            findings.append({
                "severity": "low" if hdr in _MISSING_LOW else "info",
                "template": f"missing-security-header:{hdr.lower()}",
                "name": f"Missing security header: {hdr}",
                "url": url,
                "host": host,
            })
        for hdr, value in present.items():
            sev = _weak_value_severity(hdr, value)
            if sev:
                findings.append({
                    "severity": sev,
                    "template": f"insecure-security-header:{hdr.lower()}",
                    "name": f"Insecure security header: {hdr}",
                    "url": url,
                    "host": host,
                    "evidence": value,
                })

    utils.log(f"security headers: {len(findings)} finding(s) across {len(data)} host(s)")
    return findings


def _parse_shcheck_json(raw: str) -> dict:
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def _weak_value_severity(hdr: str, value: str) -> str | None:
    v = (value or "").lower()
    if hdr == "Referrer-Policy" and "unsafe-url" in v:
        return "low"
    if hdr == "Strict-Transport-Security" and "max-age=0" in v:
        return "low"
    if hdr == "Content-Security-Policy" and ("unsafe-inline" in v or "unsafe-eval" in v):
        return "info"
    return None


def cors_scan(target: str, outdir: Path, hosts: list[str] | None = None,
              threads: int = 10) -> list[dict]:
    """Reimplemented 6-origin CORS probe; return misconfiguration findings."""
    utils.log("CORS misconfiguration")
    if not HAVE_REQUESTS:
        utils.warn("requests not installed — skipping CORS scan")
        return []

    live = _live_hosts(outdir, target, hosts)
    if not live:
        utils.warn("no routable hosts — skipping CORS scan")
        return []

    findings: list[dict] = []
    csv_rows = ["URL,Origin,ACAO,ACAC"]
    stage = events.current_stage() or "cors"
    for i, host in enumerate(live):
        url = f"https://{host}"
        host_findings, host_csv = _probe_cors(url, host)
        findings.extend(host_findings)
        csv_rows.extend(host_csv)
        events.progress(stage, i + 1, len(live))  # also polls skip/cancel

    (Path(outdir) / "cors_results.csv").write_text("\n".join(csv_rows) + "\n")
    utils.log(f"cors: {len(findings)} finding(s) across {len(live)} host(s)")
    return findings


def _probe_cors(base_url: str, host: str) -> tuple[list[dict], list[str]]:
    suffix = "".join(random.choices(string.ascii_lowercase, k=12))
    netloc = urlsplit(base_url).netloc or host
    scheme = urlsplit(base_url).scheme or "https"
    other = "http" if scheme == "https" else "https"

    probes = [
        ("existing", netloc),
        ("null", "null"),
        ("reflected", f"{suffix}.com"),
        ("scheme", f"{other}://{netloc}"),
        ("mangled_front", f"{suffix}{netloc}"),
        ("mangled_rear", f"{host}.random.tld"),
    ]

    findings: list[dict] = []
    csv_lines: list[str] = []
    for kind, origin in probes:
        acao, acac = _send_origin(base_url, origin)
        if not acao and not acac:
            continue
        csv_lines.append(f"{base_url},{origin},{acao},{acac}")
        if kind == "existing":
            if acao == "*" and acac.lower() == "true":
                f = _cors_finding("star-with-credentials", base_url, host,
                                  origin, acao, acac, "info")
                findings.append(f)
                evidence.attach(f, base_url)
            continue
        sev = _classify(kind, acao, acac, origin)
        if sev:
            f = _cors_finding(kind, base_url, host, origin, acao, acac, sev)
            findings.append(f)
            evidence.attach(f, base_url)
    return findings, csv_lines


def _send_origin(url: str, origin: str) -> tuple[str, str]:
    try:
        from runner import httpclient
        r = httpclient.get(url, headers={"Origin": origin},
                           timeout=(_CORS_TIMEOUT, _CORS_TIMEOUT), allow_redirects=True)
    except Exception:  # noqa: BLE001
        return "", ""
    acao = (r.headers.get("Access-Control-Allow-Origin") or "").replace(",", ";")
    acac = (r.headers.get("Access-Control-Allow-Credentials") or "").replace(",", ";")
    return acao, acac


def _strip_scheme(value: str) -> str:
    """Normalize an origin for comparison: drop scheme and trailing slash, lowercase."""
    v = (value or "").strip().lower()
    if "://" in v:
        v = v.split("://", 1)[1]
    return v.rstrip("/")


def _reflects(acao: str, origin: str) -> bool:
    """True if ACAO echoes the probe origin (scheme-insensitive)."""
    return bool(acao) and _strip_scheme(acao) == _strip_scheme(origin)


def _classify(kind: str, acao: str, acac: str, origin: str) -> str | None:
    if kind == "reflected":
        return "high" if _reflects(acao, origin) else None
    if kind == "null":
        return "medium" if acao == "null" else None
    if kind in ("mangled_front", "mangled_rear"):
        # Only flag when the manipulated origin is actually accepted; a server
        # returning its own fixed origin is not reflecting the attacker.
        return "medium" if (acao == "*" or _reflects(acao, origin)) else None
    if kind == "scheme":
        return "low" if acao else None
    return None


def _cors_finding(kind: str, url: str, host: str, origin: str, acao: str, acac: str,
                  severity: str) -> dict:
    return {
        "severity": severity,
        "template": f"cors-misconfiguration:{kind}",
        "name": f"CORS: {kind}",
        "url": url,
        "host": host,
        "evidence": f"Origin {origin} -> ACAO {acao or '-'}; ACAC {acac or '-'}",
    }
