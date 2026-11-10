"""Recon stages. Each stage reads prior output and writes its own artifacts."""
import ipaddress
import json
import shlex
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from . import events, scope, utils

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

# Hard ceiling on a single DNS lookup. socket.setdefaulttimeout() does NOT
# apply to gethostbyname (it's a blocking libc call), so we run the lookup in
# a daemon thread and stop waiting after this many seconds.
DNS_TIMEOUT = 5


def _gethostbyname_bounded(host: str, timeout: float = DNS_TIMEOUT) -> str:
    """socket.gethostbyname with a wall-clock bound; raises on failure/timeout.

    The worker is a daemon thread, so a lookup the resolver never answers can
    neither stall the caller nor block interpreter exit.
    """
    box: dict = {}

    def _worker():
        try:
            box["ip"] = socket.gethostbyname(host)
        except BaseException as e:  # noqa: BLE001
            box["err"] = e

    t = threading.Thread(target=_worker, name=f"dns-{host}", daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise TimeoutError(f"DNS lookup for {host} timed out after {timeout}s")
    if "err" in box:
        raise box["err"]
    return box["ip"]


def subdomain_enum(target: str, outdir: Path, skip_amass: bool = True) -> list[str]:
    """Stage 1: passive subdomain discovery via subfinder (+ optional amass)."""
    utils.log(f"subdomain enumeration ({target})")
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

    in_scope = scope.for_target(target).filter_hosts(sorted(subs))
    outfile = outdir / "subdomains.txt"
    outfile.write_text("\n".join(in_scope) + "\n")
    utils.log(f"  {len(in_scope)} subdomains -> {outfile.name}")
    return in_scope


def _probe_host(sub: str, timeout: int) -> dict:
    """Probe one host over HTTPS then HTTP; return its status row."""
    # SSRF guard: only probe publicly-routable addresses.
    try:
        resolved = _gethostbyname_bounded(sub)
        if not ipaddress.ip_address(resolved).is_global:
            return {"host": sub, "url": "", "status": 0, "server": "", "cloudflare": False}
    except Exception:  # noqa: BLE001
        return {"host": sub, "url": "", "status": 0, "server": "", "cloudflare": False}

    for scheme in ("https", "http"):
        url = f"{scheme}://{sub}"
        try:
            r = requests.get(url, timeout=(timeout, timeout), verify=False,
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
    utils.log(f"probing {len(targets)} hosts ({threads} threads)")
    if not HAVE_REQUESTS:
        utils.warn("requests not available — skipping live-host probe")
        return []

    rows = []
    stage = events.current_stage() or "live"
    total = len(targets)
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(_probe_host, s, timeout): s for s in targets}
        try:
            for done, fut in enumerate(as_completed(futures), 1):
                rows.append(fut.result())
                if done % 500 == 0:
                    utils.log(f"  ... probed {done}/{len(targets)}")
                if done % 10 == 0 or done == total:
                    events.progress(stage, done, total)
        except (events.RunCancelled, events.StageSkipped):
            ex.shutdown(wait=True, cancel_futures=True)
            raise

    rows.sort(key=lambda r: (r["status"] == 0, r["host"]))
    outfile = outdir / "live_hosts.txt"
    lines = [f"{r['host']}\t{r['status']}\t{r['server']}\t{'CF' if r['cloudflare'] else ''}" for r in rows]
    outfile.write_text("\n".join(lines) + "\n")
    live = [r for r in rows if r["status"]]
    utils.log(f"  {len(live)}/{len(rows)} responded -> {outfile.name}")
    return rows


def cloudflare_detect(target: str, outdir: Path) -> dict:
    """Stage 3: detect Cloudflare via response headers + resolved IP."""
    utils.log(f"Cloudflare detection ({target})")
    result = {"target": target, "cloudflare": False, "evidence": []}
    try:
        result["ip"] = _gethostbyname_bounded(target)
    except Exception as e:  # noqa: BLE001
        result["ip"] = ""
        result["evidence"].append(f"DNS resolution failed: {e}")

    if HAVE_REQUESTS:
        try:
            r = requests.get(f"https://{target}", timeout=(10, 10), verify=False, allow_redirects=False)
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
        return _gethostbyname_bounded(host)
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
        out = utils.run(f"curl -sS --connect-timeout 10 --max-time 30 {url}", timeout=40)
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
        f"curl -sS -k --connect-timeout 10 -o /dev/null -w '%{{http_code}}|%{{remote_ip}}' "
        f"--resolve {target}:443:{ip} --max-time 12 https://{target}",
        timeout=20,
    )
    parts = out.strip().split("|")
    return {"status": parts[0] if parts else "", "remote_ip": parts[1] if len(parts) > 1 else ""}


def origin_hunt(target: str, outdir: Path, cf_result: dict) -> list[dict]:
    """Stage 4: find the origin IP behind Cloudflare via leak subdomains + MX."""
    utils.log(f"origin hunting ({target})")
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
    stage = events.current_stage() or "origin"
    sorted_candidates = sorted(candidates.items())
    total = len(sorted_candidates)
    for done, (ip, sources) in enumerate(sorted_candidates, 1):
        v = _verify_origin(target, ip)
        rows.append({"ip": ip, "sources": sources, "status": v["status"],
                     "remote_ip": v["remote_ip"]})
        events.progress(stage, done, total)

    outfile = outdir / "origin_candidates.txt"
    lines = [f"{r['ip']}\t{r['status']}\t{','.join(r['sources'])}" for r in rows]
    outfile.write_text("\n".join(lines) + "\n")
    utils.log(f"  {len(rows)} origin candidate(s) -> {outfile.name}")
    for r in rows:
        utils.log(f"    {r['ip']}  [{r['status']}]  via {', '.join(r['sources'])}")
    return rows


# --- Stage 5 & 6: vulnerability scan + content discovery ---


def _available_ram_mb() -> int:
    """Available RAM in MiB from /proc/meminfo; 0 if unreadable (non-Linux)."""
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) // 1024  # kB -> MiB
    except Exception:  # noqa: BLE001
        pass
    return 0


def _clamp_concurrency(concurrency: int) -> int:
    """Cap nuclei -c by available RAM (~40 MiB/worker) to avoid the OOM-killer.

    nuclei RSS scales with template concurrency; on a ~3.8 GB box, -c 50 reached
    ~590 MB anon-rss and got OOM-killed. Floor of 10 so it still makes progress.
    """
    mem = _available_ram_mb()
    if mem <= 0:
        return concurrency  # unknown (non-Linux) — leave the caller's value alone
    cap = max(10, mem // 40)
    if concurrency > cap:
        utils.warn(f"  clamping nuclei -c {concurrency} -> {cap} "
                   f"({mem} MiB available, ~40 MiB/worker)")
        return cap
    return concurrency


def _patience_banner() -> None:
    """Print a bold, highly-visible 'be patient' banner before the nuclei sweep.

    ANSI bold/colour is gated by the same stdout-is-tty logic as the rest of the
    CLI (utils._color_enabled), so piped/redirected output stays plain text.
    """
    bold = _color_enabled = getattr(utils, "_color_enabled", None)
    on = bool(_color_enabled()) if callable(_color_enabled) else False

    def b(text: str) -> str:
        return f"\033[1m{text}\033[0m" if on else text

    art = [
        "    .-----.   ",
        "    \\     /   ",
        "     )   (    ",
        "    (     )   ",
        "    /     \\   ",
        "    `-----'   ",
    ]
    print(b("=" * 60), flush=True)
    for line in art:
        print(b(line), flush=True)
    print(b("nuclei is scanning ALL templates and origin IPs — "
            "this can take 15-30+ minutes. Be patient."), flush=True)
    print(b("=" * 60), flush=True)


def _nuclei_line_to_finding(line: str) -> dict | None:
    """Map one nuclei JSONL line to a finding dict; `None` if not parseable."""
    line = line.strip()
    if not line:
        return None
    try:
        j = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(j, dict):
        return None
    info = j.get("info")
    if not isinstance(info, dict):
        info = {}
    return {
        "severity": str(info.get("severity") or "unknown").lower(),
        "template": j.get("template-id", ""),
        "name": info.get("name", ""),
        "url": j.get("matched-at", ""),
        "host": j.get("host", ""),
    }


def _parse_nuclei_jsonl(path: Path) -> list[dict]:
    """Parse one nuclei JSONL output file into finding dicts (defensively)."""
    findings = []
    if not path.exists():
        return findings
    for line in path.read_text().split("\n"):
        f = _nuclei_line_to_finding(line)
        if f is not None:
            findings.append(f)
    return findings


def _emit_nuclei_finding_from_line(line: str) -> None:
    f = _nuclei_line_to_finding(line)
    if f is not None:
        events.finding(f["severity"], f["template"], f["host"], f["url"], f["name"])


def vuln_scan(target: str, outdir: Path, live_rows: list[dict], severity: str = "info,low,medium,high,critical",
              concurrency: int = 25, timeout: int = 1800, origins: list[dict] = None,
              oast: bool = True) -> list[dict]:
    """Stage 5: run nuclei against live hosts, parse JSONL into findings.

    `origins` is an optional list of dicts (each with an 'ip' key) for origin
    servers discovered behind Cloudflare.  nuclei (v3) has no static
    hostname->IP map / custom-DNS flag, so each origin IP is scanned in a
    SEPARATE nuclei pass over https://<ip> and http://<ip> while forcing
    SNI=<target> (-sni) and Host=<target> (-H).  That connects to the real
    origin server while presenting the correct virtual host, instead of the
    403/404-blocked Cloudflare edge.  Findings from every pass are merged.
    """
    utils.log("vulnerability scan (nuclei)")
    if not utils.have("nuclei"):
        utils.warn("nuclei not found — skipping")
        events.mark_skipped("tool missing: nuclei")
        return []
    _patience_banner()
    concurrency = _clamp_concurrency(concurrency)
    hosts = sorted({r["host"] for r in live_rows if r["status"]})
    # SSRF guard: drop hosts that resolve to non-public addresses.
    hosts = [h for h in hosts if _is_global(_resolve(h))]
    # Engagement scope: drop hosts outside the allow/deny rules.
    hosts = scope.for_target(target).filter_hosts(hosts)
    if not hosts:
        hosts = [target]
    # OAST (interactsh) is on by default; --no-oast degrades to -ni (no-interactsh).
    ni = "" if oast else " -ni"
    hosts_file = outdir / "nuclei_targets.txt"
    hosts_file.write_text("\n".join(hosts) + "\n")
    utils.log(f"  scanning {len(hosts)} host(s) [{severity}] — this can take a few minutes")
    utils.run(
        f"nuclei -l {shlex.quote(str(hosts_file))} -severity {shlex.quote(severity)} "
        f"-c {concurrency}{ni} -jsonl -silent -o {shlex.quote(str(outdir / 'nuclei.jsonl'))}",
        timeout=timeout,
        on_line=_emit_nuclei_finding_from_line,
    )
    findings = _parse_nuclei_jsonl(outdir / "nuclei.jsonl")

    # Origin passes: one nuclei invocation per unique, public origin IP that
    # reaches the origin directly (SNI + Host = target), merged into findings.
    done = set()
    for o in (origins or []):
        ip = (o or {}).get("ip")
        # SSRF guard: only scan public origin IPs; dedupe.
        if not ip or ip in done or not _is_global(ip):
            continue
        done.add(ip)
        origin_targets = outdir / f"nuclei_origin_{ip}.txt"
        origin_targets.write_text(f"https://{ip}\nhttp://{ip}\n")
        origin_jsonl = outdir / f"nuclei_origin_{ip}.jsonl"
        utils.log(f"  scanning origin {ip} as {target} (SNI+Host) — behind Cloudflare")
        utils.run(
            f"nuclei -l {shlex.quote(str(origin_targets))} -severity {shlex.quote(severity)} "
            f"-sni {shlex.quote(target)} -H {shlex.quote('Host: ' + target)} "
            f"-c {concurrency}{ni} -jsonl -silent -o {shlex.quote(str(origin_jsonl))}",
            timeout=timeout,
            on_line=_emit_nuclei_finding_from_line,
        )
        findings.extend(_parse_nuclei_jsonl(origin_jsonl))

    utils.log(f"  {len(findings)} finding(s)")
    return findings


def content_discovery(target: str, outdir: Path, wordlist: str, threads: int = 40) -> list[str]:
    """Stage 6: ffuf content discovery against the main target."""
    utils.log("content discovery (ffuf)")
    if not utils.have("ffuf"):
        utils.warn("ffuf not found — skipping")
        events.mark_skipped("tool missing: ffuf")
        return []
    if not Path(wordlist).exists():
        utils.warn(f"wordlist not found: {wordlist} — skipping ffuf")
        return []

    def _on_line(line: str) -> None:
        line = line.strip()
        if line:
            events.finding("info", "ffuf:path", target, f"https://{target}/{line}", line)

    out = utils.run(
        f"ffuf -u https://{target}/FUZZ -w {shlex.quote(wordlist)} "
        f"-mc 200,204,301,302,307,401,403 -ac -t {threads} -s",
        timeout=600,
        on_line=_on_line,
    )
    paths = sorted({line.strip() for line in out.splitlines() if line.strip()})
    outfile = outdir / "content_discovery.txt"
    outfile.write_text("\n".join(paths) + "\n")
    utils.log(f"  {len(paths)} path(s) -> {outfile.name}")
    return paths
