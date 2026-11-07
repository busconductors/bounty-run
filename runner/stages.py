"""Recon stages. Each stage reads prior output and writes its own artifacts."""
import ipaddress
import json
import shlex
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from . import utils

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False


def subdomain_enum(target: str, outdir: Path, skip_amass: bool = True) -> list[str]:
    """Stage 1: passive subdomain discovery via subfinder (+ optional amass)."""
    utils.log(f"Stage 1 — subdomain enumeration ({target})")
    subs = {target}

    if utils.have("subfinder"):
        txt = utils.run(f"subfinder -d {target} -silent",
                        outfile=str(outdir / "subfinder.txt"), timeout=300)
        for line in txt.splitlines():
            line = line.strip().lower()
            if line and not line.startswith(("#", "[", "-", "*")) and (line == target or line.endswith("." + target)):
                subs.add(line)
    else:
        utils.warn("subfinder not found — skipping")

    if not skip_amass and utils.have("amass"):
        txt = utils.run(f"amass enum -passive -d {target}",
                        outfile=str(outdir / "amass.txt"), timeout=300)
        for line in txt.splitlines():
            line = line.strip().lower()
            if line and not line.startswith(("#", "[", "-", "*")) and (line == target or line.endswith("." + target)):
                subs.add(line)

    outfile = outdir / "subdomains.txt"
    outfile.write_text("\n".join(sorted(subs)) + "\n")
    utils.log(f"  {len(subs)} subdomains -> {outfile.name}")
    return sorted(subs)


def _probe_host(sub: str, timeout: int) -> dict:
    """Probe one host over HTTPS then HTTP; return its status row."""
    # SSRF guard: only probe publicly-routable addresses.
    try:
        resolved = socket.gethostbyname(sub)
        if not ipaddress.ip_address(resolved).is_global:
            return {"host": sub, "url": "", "status": 0, "server": "", "cloudflare": False}
    except Exception:  # noqa: BLE001
        return {"host": sub, "url": "", "status": 0, "server": "", "cloudflare": False}

    for scheme in ("https", "http"):
        url = f"{scheme}://{sub}"
        try:
            r = requests.get(url, timeout=timeout, verify=False,
                             allow_redirects=False, stream=True)
            server = r.headers.get("Server", "")
            is_cf = "cf-ray" in r.headers or "cloudflare" in server.lower()
            r.close()
            return {"host": sub, "url": r.url, "status": r.status_code,
                    "server": server, "cloudflare": is_cf}
        except Exception:  # noqa: BLE001
            continue
    return {"host": sub, "url": "", "status": 0, "server": "", "cloudflare": False}


def live_hosts(subdomains: list[str], outdir: Path, timeout: int = 8,
               threads: int = 30, max_hosts: int = 1000) -> list[dict]:
    """Stage 2: probe subdomains concurrently, record status + server + CF."""
    targets = subdomains[:max_hosts]
    utils.log(f"Stage 2 — probing {len(targets)} hosts ({threads} threads)")
    if not HAVE_REQUESTS:
        utils.warn("requests not available — skipping live-host probe")
        return []

    rows = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(_probe_host, s, timeout): s for s in targets}
        for done, fut in enumerate(as_completed(futures), 1):
            rows.append(fut.result())
            if done % 500 == 0:
                utils.log(f"  ... probed {done}/{len(targets)}")

    rows.sort(key=lambda r: (r["status"] == 0, r["host"]))
    outfile = outdir / "live_hosts.txt"
    lines = [f"{r['host']}\t{r['status']}\t{r['server']}\t{'CF' if r['cloudflare'] else ''}" for r in rows]
    outfile.write_text("\n".join(lines) + "\n")
    live = [r for r in rows if r["status"]]
    utils.log(f"  {len(live)}/{len(rows)} responded -> {outfile.name}")
    return rows


def cloudflare_detect(target: str, outdir: Path) -> dict:
    """Stage 3: detect Cloudflare via response headers + resolved IP."""
    utils.log(f"Stage 3 — Cloudflare detection ({target})")
    result = {"target": target, "cloudflare": False, "evidence": []}
    try:
        result["ip"] = socket.gethostbyname(target)
    except Exception as e:  # noqa: BLE001
        result["ip"] = ""
        result["evidence"].append(f"DNS resolution failed: {e}")

    if HAVE_REQUESTS:
        try:
            r = requests.get(f"https://{target}", timeout=10, verify=False, allow_redirects=False)
            h = r.headers
            if "cf-ray" in h:
                result["cloudflare"] = True
                result["evidence"].append(f"cf-ray: {h['cf-ray']}")
            if "cloudflare" in h.get("Server", "").lower():
                result["cloudflare"] = True
                result["evidence"].append(f"server: {h.get('Server')}")
            if "cf-cache-status" in h:
                result["cloudflare"] = True
                result["evidence"].append("cf-cache-status present")
            result["status"] = r.status_code
        except Exception as e:  # noqa: BLE001
            result["evidence"].append(f"request error: {e}")

    outfile = outdir / "cloudflare.json"
    outfile.write_text(json.dumps(result, indent=2))
    if result["cloudflare"]:
        utils.warn(f"  CLOUDFLARE DETECTED — {'; '.join(result['evidence'])}")
    else:
        utils.log("  no Cloudflare signatures found")
    return result


# --- Stage 4: origin hunting (Cloudflare-fronted targets) ---

# Classic subdomains that are commonly left unproxied and leak the origin IP.
LEAK_SUBDOMAINS = [
    "www", "mail", "webmail", "cpanel", "ftp", "direct", "smtp", "pop", "imap",
    "pop3", "cpcalendars", "cpcontacts", "webdisk", "mx", "mx1", "mx2",
    "autodiscover", "remote", "vpn", "portal", "owa", "web", "api",
]


def _resolve(host: str) -> str:
    """Resolve a hostname to an IPv4; empty string on failure."""
    try:
        return socket.gethostbyname(host)
    except Exception:  # noqa: BLE001
        return ""


def _mx_hosts(domain: str) -> list[str]:
    """Return MX hostnames via dig."""
    if not utils.have("dig"):
        return []
    out = utils.run(f"dig +short MX {domain}", timeout=20)
    hosts = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            host = parts[1].rstrip(".")
            if host and host != ".":  # skip null MX ("0 .")
                hosts.append(host)
    return hosts


def _cloudflare_ranges() -> list:
    """Fetch Cloudflare's published IP ranges (AS13335)."""
    ranges = []
    for url in ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"):
        out = utils.run(f"curl -sS {url}", timeout=15)
        for line in out.splitlines():
            line = line.strip()
            if line:
                try:
                    ranges.append(ipaddress.ip_network(line))
                except ValueError:
                    pass
    return ranges


def _is_cloudflare(ip: str, ranges) -> bool:
    """True if `ip` falls inside any Cloudflare range."""
    try:
        a = ipaddress.ip_address(ip)
        return any(a in r for r in ranges)
    except ValueError:
        return False


def _is_global(ip: str) -> bool:
    """True if `ip` is a publicly-routable address; False on parse failure."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _verify_origin(target: str, ip: str) -> dict:
    """Force-connect to `ip` for `target` and check if it serves the site."""
    out = utils.run(
        f"curl -sS -k -o /dev/null -w '%{{http_code}}|%{{remote_ip}}' "
        f"--resolve {target}:443:{ip} --max-time 12 https://{target}",
        timeout=20,
    )
    parts = out.strip().split("|")
    return {"status": parts[0] if parts else "", "remote_ip": parts[1] if len(parts) > 1 else ""}


def origin_hunt(target: str, outdir: Path, cf_result: dict) -> list[dict]:
    """Stage 4: find the origin IP behind Cloudflare via leak subdomains + MX."""
    utils.log(f"Stage 4 — origin hunting ({target})")
    edge_ip = cf_result.get("ip") or _resolve(target)
    utils.log(f"  edge IP (Cloudflare): {edge_ip or 'unknown'}")

    cf_ranges = _cloudflare_ranges()
    utils.log(f"  loaded {len(cf_ranges)} Cloudflare ranges (AS13335)")
    if not cf_ranges:
        utils.warn("  could not load Cloudflare ranges — aborting origin hunt (would false-positive)")
        return []

    candidates = {}  # ip -> list of sources

    def add(ip: str, source: str) -> None:
        if ip and _is_global(ip) and not _is_cloudflare(ip, cf_ranges):
            candidates.setdefault(ip, []).append(source)

    for name in LEAK_SUBDOMAINS:
        host = f"{name}.{target}"
        ip = _resolve(host)
        if ip:
            add(ip, host)

    for mx in _mx_hosts(target):
        ip = _resolve(mx)
        if ip:
            add(ip, f"MX:{mx}")

    rows = []
    for ip, sources in sorted(candidates.items()):
        v = _verify_origin(target, ip)
        rows.append({"ip": ip, "sources": sources, "status": v["status"],
                     "remote_ip": v["remote_ip"]})

    outfile = outdir / "origin_candidates.txt"
    lines = [f"{r['ip']}\t{r['status']}\t{','.join(r['sources'])}" for r in rows]
    outfile.write_text("\n".join(lines) + "\n")
    utils.log(f"  {len(rows)} origin candidate(s) -> {outfile.name}")
    for r in rows:
        utils.log(f"    {r['ip']}  [{r['status']}]  via {', '.join(r['sources'])}")
    return rows


# --- Stage 5 & 6: vulnerability scan + content discovery ---


def vuln_scan(target: str, outdir: Path, live_rows: list[dict], severity: str = "high,critical",
              concurrency: int = 50, timeout: int = 600) -> list[dict]:
    """Stage 5: run nuclei against live hosts, parse JSONL into findings."""
    utils.log("Stage 5 — vulnerability scan (nuclei)")
    if not utils.have("nuclei"):
        utils.warn("nuclei not found — skipping")
        return []
    hosts = sorted({r["host"] for r in live_rows if r["status"]})
    # SSRF guard: drop hosts that resolve to non-public addresses.
    hosts = [h for h in hosts if _is_global(_resolve(h))]
    if not hosts:
        hosts = [target]
    hosts_file = outdir / "nuclei_targets.txt"
    hosts_file.write_text("\n".join(hosts) + "\n")
    utils.log(f"  scanning {len(hosts)} host(s) [{severity}] — this can take a few minutes")
    utils.run(
        f"nuclei -l {shlex.quote(str(hosts_file))} -severity {shlex.quote(severity)} "
        f"-c {concurrency} -jsonl -silent -o {shlex.quote(str(outdir / 'nuclei.jsonl'))}",
        timeout=timeout,
    )
    findings = []
    jl = outdir / "nuclei.jsonl"
    if jl.exists():
        for line in jl.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                j = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(j, dict):
                continue
            info = j.get("info")
            if not isinstance(info, dict):
                info = {}
            severity = str(info.get("severity") or "unknown").lower()
            findings.append({
                "severity": severity,
                "template": j.get("template-id", ""),
                "name": info.get("name", ""),
                "url": j.get("matched-at", ""),
                "host": j.get("host", ""),
            })
    utils.log(f"  {len(findings)} finding(s)")
    return findings


def content_discovery(target: str, outdir: Path, wordlist: str, threads: int = 40) -> list[str]:
    """Stage 6: ffuf content discovery against the main target."""
    utils.log("Stage 6 — content discovery (ffuf)")
    if not utils.have("ffuf"):
        utils.warn("ffuf not found — skipping")
        return []
    if not Path(wordlist).exists():
        utils.warn(f"wordlist not found: {wordlist} — skipping ffuf")
        return []
    out = utils.run(
        f"ffuf -u https://{target}/FUZZ -w {shlex.quote(wordlist)} "
        f"-mc 200,204,301,302,307,401,403 -ac -t {threads} -s",
        timeout=600,
    )
    paths = sorted({line.strip() for line in out.splitlines() if line.strip()})
    outfile = outdir / "content_discovery.txt"
    outfile.write_text("\n".join(paths) + "\n")
    utils.log(f"  {len(paths)} path(s) -> {outfile.name}")
    return paths
