"""Recon stages. Each stage reads prior output and writes its own artifacts."""
import ipaddress
import json
import shlex
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from . import events, ipintel, scope, subdomains, utils
from . import proxy as proxymod

try:
    # Shared, pooled client stand-in; TLS warnings are silenced in Client.__init__.
    from .httpclient import compat as requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

# Hard ceiling on a single DNS lookup. socket.setdefaulttimeout() does NOT
# apply to gethostbyname (it's a blocking libc call), so we run the lookup in
# a daemon thread and stop waiting after this many seconds.
DNS_TIMEOUT = 5


def _bounded_lookup(fn, host: str, timeout: float = DNS_TIMEOUT):
    """Run the blocking resolver call `fn(host)` with a wall-clock bound.

    The worker is a daemon thread, so a lookup the resolver never answers can
    neither stall the caller nor block interpreter exit. Raises on
    failure/timeout.
    """
    box: dict = {}

    def _worker():
        try:
            box["res"] = fn(host)
        except BaseException as e:  # noqa: BLE001
            box["err"] = e

    t = threading.Thread(target=_worker, name=f"dns-{host}", daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise TimeoutError(f"DNS lookup for {host} timed out after {timeout}s")
    if "err" in box:
        raise box["err"]
    return box["res"]


def _gethostbyname_bounded(host: str, timeout: float = DNS_TIMEOUT) -> str:
    """socket.gethostbyname with a wall-clock bound; raises on failure/timeout."""
    return _bounded_lookup(socket.gethostbyname, host, timeout)


def subdomain_enum(target: str, outdir: Path, skip_amass: bool = True, *,
                   findomain: bool = False,
                   active: bool = False,
                   resolvers: str | None = None,
                   dns_rate: int = 500,
                   cache_dir=None,
                   proxy=None) -> list[str]:
    """Stage 1: passive subdomain discovery via subfinder (+ optional sources).

    With every keyword argument at its default this reproduces the legacy
    behaviour exactly: subfinder-only, no cache, no resolution, and the exact
    sorted in-scope union written to ``subdomains.txt`` and returned.

    Opt-in extras (all behind defaults-off kwargs):
      * ``findomain`` — add findomain's passive sources.
      * ``cache_dir`` — union a per-target cache that only grows.
      * ``active`` — when set and dnsx is present, resolve the union and split
        it into resolved / internal / dangling sidecars. ``subdomains.txt``
        itself keeps union semantics (Phase 2), so downstream stages are
        unchanged. ``active`` is gated by the caller on the intensity ceiling,
        keeping the stage zero-packet under ``--intensity passive``.

    Extra per-source stats land in ``subs_stats.json`` (never in the stage's
    event counts, which stay ``{"subdomains": N}``).
    """
    t = (target or "").strip().lower().rstrip(".")
    utils.log(f"subdomain enumeration ({t})")
    t0 = time.monotonic()
    stats: dict = {"sources": {}, "skipped": {}}
    subs = {t}

    pk = proxymod.run_kw(proxy)  # passive sources go via the proxy; DNS stays direct
    found = subdomains.passive_subfinder(t, outdir, **pk)
    stats["sources"]["subfinder"] = len(found)
    subs |= found

    if not skip_amass:
        amass_names = subdomains.passive_amass(t, outdir, **pk)
        stats["sources"]["amass"] = len(amass_names)
        subs |= amass_names

    if findomain:
        fd = subdomains.passive_findomain(t, outdir, **pk)
        stats["sources"]["findomain"] = len(fd)
        subs |= fd

    if cache_dir:
        cached = subdomains.cache_load(cache_dir, t)
        stats["sources"]["cache"] = len(cached)
        subs |= cached

    if active and utils.have("dnsx"):
        res_path = subdomains.resolvers_file(cache_dir, resolvers)
        rr = subdomains.resolve(subs, outdir, t, res_path, rate=dns_rate)
        stats["resolved"] = len(rr.resolved)
        stats["internal"] = len(rr.internal)
        stats["dangling"] = len(rr.dangling)
    elif not active:
        stats["skipped"]["resolve"] = "intensity below active"
    else:
        stats["skipped"]["resolve"] = "dnsx not found"

    in_scope = scope.for_target(t).filter_hosts(sorted(subs))

    # Union of every source + cache (incl. unresolved names). resolve() already
    # wrote this file from the pre-scope union; refresh it to the in-scope set.
    (outdir / "subdomains_all.txt").write_text("\n".join(in_scope) + "\n")
    outfile = outdir / "subdomains.txt"
    outfile.write_text("\n".join(in_scope) + "\n")

    if cache_dir:
        subdomains.cache_save(cache_dir, t, set(in_scope))

    stats["count"] = len(in_scope)
    stats["elapsed_s"] = round(time.monotonic() - t0, 2)
    try:
        (outdir / "subs_stats.json").write_text(
            json.dumps(stats, indent=2, sort_keys=True) + "\n")
    except OSError:
        pass

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


def _in_domain(name: str, domain: str) -> bool:
    """True if `name` is `domain` itself or a subdomain of it (case/dot-insensitive)."""
    n = name.strip().lower().rstrip(".")
    d = domain.strip().lower().rstrip(".")
    return bool(n) and bool(d) and (n == d or n.endswith("." + d))


def _canonical_name(host: str) -> str:
    """Final name after following the CNAME chain for `host`; "" on failure.

    gethostbyname_ex returns (canonical, aliases, ips); with glibc the canonical
    name is the last CNAME target (== `host` when there is no CNAME).
    """
    try:
        return _bounded_lookup(socket.gethostbyname_ex, host)[0].lower().rstrip(".")
    except Exception:  # noqa: BLE001
        return ""


def _third_party_reason(host: str, target: str) -> str:
    """Why `host` should NOT be treated as the target's own infra; "" if owned.

    The name we queried may be in the target's zone, but if its CNAME chain ends
    outside the target's domain (autodiscover -> outlook.com, mail ->
    ghs.googlehosted.com, status -> statuspage.io, www -> a CDN) the IP belongs
    to that provider, not to the target. Fails closed: if ownership cannot be
    established the host is excluded, since a wrong guess means scanning a
    third party.
    """
    if not _in_domain(host, target):
        return f"{host} is outside {target}"
    canon = _canonical_name(host)
    if not canon:
        return f"could not determine canonical name for {host}"
    if not _in_domain(canon, target):
        return f"{host} is a CNAME to third-party {canon}"
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


def _cloudflare_ranges(proxy=None) -> list:
    """Fetch Cloudflare's published IP ranges (AS13335)."""
    ranges = []
    px = proxy.cli("curl") if proxy is not None else ""
    for url in ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"):
        out = utils.run(f"curl -sS --connect-timeout 10 --max-time 30{px} {url}", timeout=40,
                        **proxymod.run_kw(proxy))
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
    """Force-connect to `ip` for `target` (SNI + Host = target, -k).

    Returns {status, remote_ip, headers, body, error}: the Layer-3 target
    probe used by :func:`ipintel.classify`.
    """
    return ipintel.http_probe(target, ip)


def _resolve_all(host: str) -> list[str]:
    """Every IPv4 address `host` resolves to (gethostbyname_ex); [] on failure.

    A host with several A records is judged on all of them, not on whichever
    one gethostbyname happened to return.
    """
    try:
        ips = _bounded_lookup(socket.gethostbyname_ex, host)[2]
    except Exception:  # noqa: BLE001
        return []
    return sorted(set(ips))


# Status recorded for origin candidates when verification is skipped under a
# proxy: `curl --resolve` through a proxy would "verify" the CF edge (the proxy
# resolves the name), and running it direct would leak. Owner decision: skip.
UNVERIFIED_PROXY = "unverified(proxy)"


def classify_candidates(target: str, candidates: dict, proxy=None) -> list[dict]:
    """Grade ``{ip: [sources]}`` with :mod:`runner.ipintel`; one row per IP.

    Runs after the global / Cloudflare / in-domain / CNAME filters. Under
    ``--proxy`` the active layer is skipped (a direct probe would leave the
    proxy), so no row can reach CONFIRMED there; Layers 1-2 still run from
    cache and still mark known shared front-ends SHARED.
    """
    if not candidates:
        return []
    intel = ipintel.get(proxy)
    intel.prefetch_asn(list(candidates))
    probe = None
    baseline = None
    if proxy is None:
        probe = ipintel.Probe(target_http=lambda host, ip: _verify_origin(host, ip))
        baseline = probe.baseline(target)
        why = ipintel.baseline_invalid(baseline)
        if why:
            utils.warn(f"  origin baseline unusable ({why}) — content not compared, "
                       "nothing can grade above LIKELY")
    else:
        utils.warn("  origin verification skipped under --proxy (candidates kept "
                   "unverified; none will be scanned)")
    rows = []
    stage = events.current_stage() or "origin"
    total = len(candidates)
    for done, (ip, sources) in enumerate(sorted(candidates.items()), 1):
        if probe is not None:
            probe.last_hit = {}
        v = ipintel.classify(ip, target, intel, baseline, probe,
                             unverified_reason=UNVERIFIED_PROXY)
        hit = probe.last_hit if probe is not None else {}
        status = UNVERIFIED_PROXY if proxy is not None else str(hit.get("status", "") or "")
        rows.append({"ip": ip, "sources": sources, "status": status,
                     "remote_ip": hit.get("remote_ip", "") or "", **v.row()})
        events.progress(stage, done, total)
    return rows


def write_origin_file(path: Path, rows: list[dict]) -> None:
    """``ip  status  sources  tier  reason`` per candidate (first three columns
    unchanged from the legacy format); SHARED IPs only as ``#`` comment lines
    so they stay visible as an audit trail without looking like candidates."""
    lines = []
    for r in rows:
        if r.get("tier") == ipintel.SHARED:
            lines.append(f"# SHARED\t{r['ip']}\t{r.get('reason', '')}\t{','.join(r['sources'])}")
        else:
            lines.append(f"{r['ip']}\t{r['status']}\t{','.join(r['sources'])}"
                         f"\t{r.get('tier', '')}\t{r.get('reason', '')}")
    path.write_text("\n".join(lines) + "\n")


def log_origin_rows(rows: list[dict]) -> None:
    for r in rows:
        utils.log(f"    {r['ip']}  [{r.get('tier', '?')}]  {r.get('reason', '')}  "
                  f"via {', '.join(r['sources'])}")
    confirmed = [r["ip"] for r in rows if r.get("tier") == ipintel.CONFIRMED]
    review = [r["ip"] for r in rows if r.get("tier") == ipintel.LIKELY]
    if review:
        utils.warn(f"  {len(review)} LIKELY origin(s) for manual review (not scanned): "
                   f"{', '.join(review)}")
    if confirmed:
        utils.log(f"  {len(confirmed)} CONFIRMED origin(s) admitted to scan scope: "
                  f"{', '.join(confirmed)}")


def origin_hunt(target: str, outdir: Path, cf_result: dict, proxy=None) -> list[dict]:
    """Stage 4: find the origin IP behind Cloudflare via leak subdomains + MX.

    Every surviving IP is graded by :func:`ipintel.classify`; only CONFIRMED
    rows are later admitted into the scan scope (see ``cli._pipeline``).
    """
    utils.log(f"origin hunting ({target})")
    edge_ip = cf_result.get("ip") or _resolve(target)
    utils.log(f"  edge IP (Cloudflare): {edge_ip or 'unknown'}")

    cf_ranges = _cloudflare_ranges(**proxymod.run_kw(proxy))
    utils.log(f"  loaded {len(cf_ranges)} Cloudflare ranges (AS13335)")
    if not cf_ranges:
        utils.warn("  could not load Cloudflare ranges — aborting origin hunt (would false-positive)")
        return []

    candidates = {}  # ip -> list of sources

    def add(host: str, ip: str, source: str) -> None:
        if not (ip and _is_global(ip) and not _is_cloudflare(ip, cf_ranges)):
            return
        # Only the target's own infra is an origin candidate: drop hosts outside
        # the target's domain (e.g. MX -> aspmx.l.google.com, Mimecast) and
        # in-zone names that CNAME out to a provider.
        why = _third_party_reason(host, target)
        if why:
            utils.log(f"  skip {ip} ({source}): {why}")
            return
        candidates.setdefault(ip, []).append(source)

    for name in LEAK_SUBDOMAINS:
        host = f"{name}.{target}"
        for ip in _resolve_all(host):
            add(host, ip, host)

    for mx in _mx_hosts(target):
        if not _in_domain(mx, target):
            # Hosted mail (Google Workspace, Microsoft 365, Mimecast, Proofpoint)
            # is the provider's server, never the web origin. Don't even resolve.
            utils.log(f"  skip MX:{mx}: third-party mail host outside {target}")
            continue
        for ip in _resolve_all(mx):
            add(mx, ip, f"MX:{mx}")

    rows = classify_candidates(target, candidates, proxy)
    outfile = outdir / "origin_candidates.txt"
    write_origin_file(outfile, rows)
    utils.log(f"  {len(rows)} origin candidate(s) -> {outfile.name}")
    log_origin_rows(rows)
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
    _color_enabled = getattr(utils, "_color_enabled", None)
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
    """Parse one nuclei JSONL output file into finding dicts (defensively).

    Streamed line by line: nuclei.jsonl reaches hundreds of MB / GB on a large
    host set, so ``read_text().split("\\n")`` would hold the whole file as one
    string plus a list of every line (~2-3x the file size) on top of the finding
    dicts — a multi-GB transient spike. Iterating the open file keeps only one
    line resident at a time.
    """
    findings = []
    if not path.exists():
        return findings
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
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
              oast: bool = True, proxy=None) -> list[dict]:
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
    if not proxymod.gate(proxy, "nuclei"):
        return []
    # Under a proxy: HTTP templates + nuclei's own OAST/update traffic go via
    # -proxy/-proxy-internal; non-HTTP templates (tcp/ssl/js/ws) connect direct
    # by owner decision (the VPN covers them).
    px = proxy.cli("nuclei") if proxy is not None else ""
    pk = proxymod.run_kw(proxy)
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
        f"-c {concurrency}{ni}{px} -jsonl -silent -o {shlex.quote(str(outdir / 'nuclei.jsonl'))}",
        timeout=timeout,
        on_line=_emit_nuclei_finding_from_line,
        # nuclei streams the same JSONL to stdout (consumed per-line above) AND to
        # -o nuclei.jsonl; retaining stdout in RAM too would balloon the engine on
        # a large host set. Stream it (return unused; findings parsed from the file).
        capture=False,
        **pk,
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
            f"-c {concurrency}{ni}{px} -jsonl -silent -o {shlex.quote(str(origin_jsonl))}",
            timeout=timeout,
            on_line=_emit_nuclei_finding_from_line,
            capture=False,  # see the main nuclei pass above
            **pk,
        )
        findings.extend(_parse_nuclei_jsonl(origin_jsonl))

    utils.log(f"  {len(findings)} finding(s)")
    return findings


def content_discovery(target: str, outdir: Path, wordlist: str, threads: int = 40,
                      proxy=None) -> list[str]:
    """Stage 6: ffuf content discovery against the main target."""
    utils.log("content discovery (ffuf)")
    if not utils.have("ffuf"):
        utils.warn("ffuf not found — skipping")
        events.mark_skipped("tool missing: ffuf")
        return []
    if not Path(wordlist).exists():
        utils.warn(f"wordlist not found: {wordlist} — skipping ffuf")
        return []
    if not proxymod.gate(proxy, "ffuf"):
        return []
    px = proxy.cli("ffuf") if proxy is not None else ""

    def _on_line(line: str) -> None:
        line = line.strip()
        if line:
            events.finding("info", "ffuf:path", target, f"https://{target}/{line}", line)

    out = utils.run(
        f"ffuf -u https://{target}/FUZZ -w {shlex.quote(wordlist)} "
        # 302/307 excluded: wildcard-redirect sites answer every path with a
        # temporary redirect, which -ac can't filter, flooding the count.
        f"-mc 200,204,301,401,403 -ac -t {threads} -s{px}",
        timeout=600,
        on_line=_on_line,
        **proxymod.run_kw(proxy),
    )
    paths = sorted({line.strip() for line in out.splitlines() if line.strip()})
    outfile = outdir / "content_discovery.txt"
    outfile.write_text("\n".join(paths) + "\n")
    utils.log(f"  {len(paths)} path(s) -> {outfile.name}")
    return paths
