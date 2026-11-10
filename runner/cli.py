"""Bounty Runner CLI — orchestrate the recon pipeline."""
import argparse
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import (__version__, api_endpoints, banner, dashboard, dork_scan, events,
               finding, headi_scan, http_headers, metis_check, nikto_scan, nmap_scan,
               origin_deep, panel_detect, param_scan, report, secret_scan, stages,
               tech_scan, tls_scan, tracker, utils, waf_scan)

REPO_OUTPUTS = Path(__file__).resolve().parent.parent / "outputs"

# Total number of pipeline stages, for the stage-transition headers.
TOTAL_STAGES = 20

# Event stage ids, in pipeline order (same names as --skip).
STAGE_IDS = ["subs", "panel", "live", "cf", "origin", "nmap", "waf", "dork", "tls",
             "nikto", "vuln", "content", "api", "param", "secret", "metis",
             "headers", "cors", "tech", "headi"]
# Stages that only run when their opt-in flag (same name) is set.
OPT_IN_STAGES = {"nmap", "tls", "nikto", "metis", "headi"}
# argparse severity choices, derived from runner.finding (excludes "unknown").
SEVERITIES = tuple(
    s.value for s in finding.Severity if s is not finding.Severity.UNKNOWN
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bounty-run",
        description="Recon orchestrator for bug bounty — chains your arsenal into one sweep.",
    )
    p.add_argument("target", help="target domain (e.g. example.com)")
    p.add_argument("-o", "--output-dir", help="output directory (default: <repo>/outputs/<target>/<ts>)")
    p.add_argument("--amass", action="store_true", help="also run amass passive enum (needs API keys to be useful)")
    p.add_argument("--timeout", type=_positive_int, default=8, help="HTTP probe timeout in seconds (default 8)")
    p.add_argument("--threads", type=_positive_int, default=30, help="concurrent HTTP probe threads (default 30)")
    p.add_argument("--max-hosts", type=_positive_int, default=1000, help="cap on hosts to probe (default 1000)")
    p.add_argument("--wordlist", default="/usr/share/wordlists/dirb/common.txt",
                   help="ffuf content-discovery wordlist (default: dirb/common.txt)")
    p.add_argument("--skip", help="comma-separated stages to skip: subs,live,cf,origin,origin_deep,vuln,content,param,secret,headers,cors,tech,api,metis,headi,nmap,panel,waf,dork,tls,nikto")
    p.add_argument("--metis", action="store_true", help="also run the Metis autocheck CVE sweep (off by default)")
    p.add_argument("--headi", action="store_true", help="also run the headi header-injection scan (off by default; intrusive)")
    p.add_argument("--nmap", action="store_true", help="also run the nmap port scan (off by default; intrusive)")
    p.add_argument("--tls", action="store_true",
                   help="also run the sslyze TLS/SSL deep scan (off by default; slow)")
    p.add_argument("--nikto", action="store_true",
                   help="also run the nikto web-server scan (off by default; intrusive, slow)")
    p.add_argument("--nmap-full", action="store_true", help="with --nmap, scan all 65535 ports (-p-) instead of top-1000")
    p.add_argument("--max-param-urls", type=_positive_int, default=50,
                   help="cap on sqlmap param URLs (default 50)")
    p.add_argument("--nuclei-severity", default="info,low,medium,high,critical",
                   help="nuclei severity filter (default: info,low,medium,high,critical — "
                        "info carries tech-detection and missing-header output)")
    p.add_argument("--nuclei-c", type=_positive_int, default=25,
                   help="nuclei concurrency (default 25; auto-clamped by available RAM)")
    p.add_argument("--nuclei-timeout", type=_positive_int, default=1800,
                   help="nuclei timeout in seconds (default 1800 — a full all-templates "
                        "sweep across origin IPs can take 15-30+ minutes)")
    p.add_argument("--interactive", action="store_true",
                   help="prompt for output directory + engagement name (-o skips the prompts)")
    p.add_argument("--no-banner", action="store_true", help="suppress the startup banner")
    p.add_argument("--no-track", action="store_true", help="do not ingest findings into the tracker DB")
    p.add_argument("--events", metavar="PATH",
                   help="write a JSON-lines event log to PATH (for monitoring the run)")
    return p


def PLANNED_STAGES(args, skip: set[str]) -> list[str]:
    """Ordered stage ids that will run (origin included provisionally)."""
    return [s for s in STAGE_IDS
            if s not in skip and (s not in OPT_IN_STAGES or getattr(args, s))]


def _positive_int(value: str) -> int:
    """argparse type: integer that must be >= 1."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("must be >= 1")
    if n < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return n


def write_summary(outdir: Path, target: str, subs: list[str], rows: list[dict], cf: dict, origins: list[dict]) -> None:
    live = [r for r in rows if r["status"]]
    cf_hosts = [r["host"] for r in live if r["cloudflare"]]
    lines = [
        f"# Bounty Runner — {target}",
        "",
        f"- Run time: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- Subdomains: {len(subs)}",
        f"- Live hosts: {len(live)}",
        f"- Cloudflare on target: {'**YES**' if cf['cloudflare'] else 'no'}",
    ]
    if cf_hosts:
        lines.append(f"- Cloudflare-fronted hosts ({len(cf_hosts)}): {', '.join(cf_hosts[:10])}")
    lines += [
        "",
        "## Live hosts",
        "",
    ]
    lines += [f"- `{r['host']}` — {r['status']} — {r['server']}" for r in live]
    if origins:
        lines += [
            "",
            "## Origin candidates (behind Cloudflare)",
            "",
        ]
        lines += [f"- `{r['ip']}` — HTTP {r['status']} — via {', '.join(r['sources'])}" for r in origins]
    lines.append("")
    (outdir / "SUMMARY.md").write_text("\n".join(lines))
    utils.log(f"summary -> {outdir / 'SUMMARY.md'}")


def _normalize_target(raw: str) -> str:
    """Coerce user input to a bare hostname; return '' if invalid."""
    t = raw.strip().lower()
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0].split(":", 1)[0].rstrip(".")
    if not re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+", t):
        return ""
    return t


def _merge_origins_by_ip(origins: list[dict]) -> list[dict]:
    """Merge origin entries sharing the same ip, concatenating their sources."""
    merged: dict[str, dict] = {}
    order: list[str] = []
    for o in origins:
        ip = o.get("ip")
        if ip is None:
            continue
        if ip in merged:
            for src in o.get("sources", []):
                if src not in merged[ip]["sources"]:
                    merged[ip]["sources"].append(src)
        else:
            merged[ip] = dict(o)
            merged[ip]["sources"] = list(o.get("sources", []))
            order.append(ip)
    return [merged[ip] for ip in order]


def _sanitize_name(name: str, target: str) -> str:
    """Make an engagement name safe as a single folder name; fall back to target."""
    clean = re.sub(r"[^A-Za-z0-9._-]", "-", name or "").strip(".-")
    return clean or target


def _resolve_dir(raw: str) -> Path:
    """Empty => <repo>/outputs; otherwise expanduser, relative paths against CWD."""
    raw = (raw or "").strip()
    if not raw:
        return REPO_OUTPUTS
    return Path(os.path.expanduser(raw)).resolve()


def _resolve_outdir(target: str, output_dir=None, interactive: bool = False,
                    input_fn=input, ts=None) -> Path:
    """Compute the run output directory.

    -o wins outright (exact path, no prompts, nothing appended).  With
    --interactive, prompt for directory + engagement name; EOFError => defaults.
    """
    if output_dir:
        return Path(os.path.expanduser(output_dir))
    ts = ts or time.strftime("%Y%m%d-%H%M%S")
    if not interactive:
        return REPO_OUTPUTS / target / ts
    raw_dir, raw_name = "", ""
    try:
        raw_dir = input_fn("Output directory [outputs]: ")
        raw_name = input_fn(f"Engagement name [{target}]: ")
    except EOFError:
        pass
    return _resolve_dir(raw_dir) / _sanitize_name(raw_name, target) / ts


def _finding_title(f: dict) -> str:
    return f.get("name") or f.get("template") or ""


def _severity_cell(sev: str) -> str:
    return utils.colorize(sev, utils.SEVERITY_COLOR.get(sev, "90"))


def print_findings_table(findings: list[dict]) -> None:
    """Print a `severity | title | url` table of deduped findings."""
    unique = report.dedupe(findings)
    if not unique:
        print("no findings")
        return
    rows = [(f.get("severity", "unknown") or "unknown", _finding_title(f), f.get("url", "") or "")
            for f in unique]
    w_sev = max(len("severity"), *(len(r[0]) for r in rows))
    w_title = max(len("title"), *(len(r[1]) for r in rows))
    print(f"{'severity'.ljust(w_sev)} | {'title'.ljust(w_title)} | url")
    print(f"{'-' * w_sev}-+-{'-' * w_title}-+-{'-' * 3}")
    for sev, title, url in rows:
        # pad before colorizing so ANSI escapes don't break alignment
        print(f"{_severity_cell(sev) + ' ' * (w_sev - len(sev))} | {title.ljust(w_title)} | {url}")


def ingest_findings(target: str, findings: list[dict]) -> int:
    """Add deduped findings to the tracker, skipping ones already recorded.

    Returns the number added.  Never raises — DB failures are warned and swallowed.
    """
    added = 0
    try:
        for f in report.dedupe(findings):
            template = f.get("template", "") or ""
            url = f.get("url", "") or ""
            if tracker.has_finding(target, template, url):
                continue
            tracker.add_finding(target, f.get("name") or template,
                                f.get("severity", "unknown"), url, template=template)
            added += 1
    except Exception as e:  # never crash a completed scan
        utils.warn(f"tracker ingest failed: {e}")
    return added


@dataclass
class RunState:
    """Results gathered so far; enough for a (partial) report at any point."""
    target: str
    subs: list = field(default_factory=list)
    rows: list = field(default_factory=list)
    cf: dict = field(default_factory=dict)
    origins: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    content: list = field(default_factory=list)
    start: float = field(default_factory=lambda: time.monotonic())
    summary_written: bool = False

    def __post_init__(self):
        self.subs = self.subs or [self.target]
        self.cf = self.cf or {"target": self.target, "cloudflare": False, "evidence": []}


def _emit_findings(findings: list[dict]) -> None:
    """Emit one `finding` event per finding dict (no-op when events are off)."""
    for f in findings:
        events.finding(str(f.get("severity") or "unknown").lower(),
                       f.get("template") or "", f.get("host") or "",
                       f.get("url") or "",
                       f.get("name") or f.get("template") or "")


def _pipeline(args, target: str, outdir: Path, skip: set[str], st: RunState) -> None:
    if "subs" not in skip:
        with events.stage("subs") as sc:
            utils.stage_header(1, TOTAL_STAGES, "SUBDOMAIN ENUMERATION")
            st.subs = stages.subdomain_enum(target, outdir, skip_amass=not args.amass)
            sc.counts["subdomains"] = len(st.subs)
    if "panel" not in skip:
        with events.stage("panel") as sc:
            utils.stage_header(2, TOTAL_STAGES, "PANEL DETECTION")
            new = panel_detect.panel_detect(target, outdir, st.subs)
            st.findings += new
            _emit_findings(new)
            sc.counts["findings"] = len(new)
    if "live" not in skip:
        with events.stage("live") as sc:
            utils.stage_header(3, TOTAL_STAGES, "LIVE HOST PROBING")
            st.rows = stages.live_hosts(st.subs, outdir, timeout=args.timeout,
                                        threads=args.threads, max_hosts=args.max_hosts)
            sc.counts["live"] = len([r for r in st.rows if r["status"]])
    live = [r["host"] for r in st.rows if r["status"]] or [target]
    if "cf" not in skip:
        with events.stage("cf") as sc:
            utils.stage_header(4, TOTAL_STAGES, "CLOUDFLARE DETECTION")
            st.cf = stages.cloudflare_detect(target, outdir)
            sc.counts["cloudflare"] = int(bool(st.cf["cloudflare"]))

    if "origin" not in skip:
        if st.cf["cloudflare"]:
            with events.stage("origin") as sc:
                utils.stage_header(5, TOTAL_STAGES, "ORIGIN HUNTING")
                st.origins = stages.origin_hunt(target, outdir, st.cf)
                if "origin_deep" not in skip:
                    st.origins = st.origins + origin_deep.origin_deep(target, outdir, st.cf)
                sc.counts["origins"] = len(_merge_origins_by_ip(st.origins))
        elif events.enabled():
            with events.stage("origin"):
                events.mark_skipped("no cloudflare")
    st.origins = _merge_origins_by_ip(st.origins)

    def scan(stage_id, num, title, fn, *a, **kw):
        with events.stage(stage_id) as sc:
            utils.stage_header(num, TOTAL_STAGES, title)
            new = fn(*a, **kw)
            st.findings += new
            _emit_findings(new)
            sc.counts["findings"] = len(new)

    if "nmap" not in skip and args.nmap:
        scan("nmap", 6, "PORT SCAN (NMAP)", nmap_scan.nmap_scan,
             target, outdir, st.rows, st.origins, full=args.nmap_full)

    host_cap = min(args.max_hosts, 20)
    if "waf" not in skip:
        scan("waf", 7, "WAF FINGERPRINT (WAFW00F)", waf_scan.waf_scan,
             target, outdir, hosts=live, max_hosts=host_cap)
    if "dork" not in skip:
        scan("dork", 8, "SEARCH-ENGINE DORKING (OSINT)", dork_scan.dork_scan, target, outdir)
    if "tls" not in skip and args.tls:
        scan("tls", 9, "TLS/SSL ANALYSIS (SSLYZE)", tls_scan.tls_scan,
             target, outdir, hosts=live, max_hosts=host_cap)
    if "nikto" not in skip and args.nikto:
        scan("nikto", 10, "WEB-SERVER SCAN (NIKTO)", nikto_scan.nikto_scan,
             target, outdir, hosts=live, max_hosts=host_cap)

    write_summary(outdir, target, st.subs, st.rows, st.cf, st.origins)
    st.summary_written = True

    if "vuln" not in skip:
        with events.stage("vuln") as sc:
            utils.stage_header(11, TOTAL_STAGES, "VULNERABILITY SCAN (NUCLEI)")
            new = stages.vuln_scan(target, outdir, st.rows, severity=args.nuclei_severity,
                                   concurrency=args.nuclei_c, timeout=args.nuclei_timeout,
                                   origins=st.origins)
            st.findings += new
            sc.counts["findings"] = len(new)
            report.write_findings_report(outdir, target, st.findings, [], origins=st.origins)

    if "content" not in skip:
        with events.stage("content") as sc:
            utils.stage_header(12, TOTAL_STAGES, "CONTENT DISCOVERY")
            st.content = stages.content_discovery(target, outdir, args.wordlist)
            sc.counts["content"] = len(st.content)

    if "api" not in skip:
        scan("api", 13, "API ENDPOINT ENUMERATION", api_endpoints.api_endpoints_scan,
             target, outdir, max_hosts=min(args.max_hosts, 20))
    if "param" not in skip:
        scan("param", 14, "PARAMETER / SQLi SCAN", param_scan.param_scan,
             target, outdir, args.max_param_urls)
    if "secret" not in skip:
        scan("secret", 15, "SECRET SCAN", secret_scan.secret_scan, target, outdir)
    if "metis" not in skip and args.metis:
        scan("metis", 16, "METIS CVE SWEEP", metis_check.metis_check, target, outdir, live)

    if "headers" not in skip:
        scan("headers", 17, "SECURITY HEADERS", http_headers.security_headers_scan,
             target, outdir, live)
    if "cors" not in skip:
        scan("cors", 18, "CORS MISCONFIGURATION", http_headers.cors_scan, target, outdir, live)
    if "tech" not in skip:
        scan("tech", 19, "TECH DETECTION", tech_scan.tech_scan, target, outdir, live)
    if "headi" not in skip and args.headi:
        scan("headi", 20, "HEADER INJECTION (HEADI)", headi_scan.headi_scan,
             target, outdir, st.rows)


def _finish(args, target: str, outdir: Path, skip: set[str], st: RunState) -> int:
    """Write the final (or partial) report, summary and tracker entries."""
    # a cancel inside the origin stage leaves st.origins unmerged
    st.origins = _merge_origins_by_ip(st.origins)
    subs, rows, cf, origins = st.subs, st.rows, st.cf, st.origins
    findings, content = st.findings, st.content
    if not st.summary_written:  # only on a run cancelled before the summary point
        write_summary(outdir, target, subs, rows, cf, origins)
        st.summary_written = True

    duration_s = time.monotonic() - st.start
    m = report.build_metrics(target, subs, rows, cf, origins, findings, content, duration_s, skip)
    n_findings = report.write_findings_report(outdir, target, findings, content, origins=origins, metrics=m)
    dashboard.write_run_summary(outdir, target, findings, content, origins,
                                run_time=time.strftime('%Y-%m-%d %H:%M:%S'),
                                subdomains=len(subs),
                                live_hosts=len([r for r in rows if r['status']]),
                                cloudflare=cf['cloudflare'])

    print_findings_table(findings)

    if not args.no_track:
        added = ingest_findings(target, findings)
        if added:
            utils.log(f"tracker: {added} new finding(s) recorded")

    if n_findings:
        utils.log(f"{n_findings} unique finding(s) -> {outdir / 'FINDINGS.md'}")
    if cf["cloudflare"]:
        if origins:
            utils.log(f"origin candidates found — check {outdir / 'origin_candidates.txt'} and {outdir / 'origin_deep.txt'}")
        else:
            utils.warn("no origin candidates surfaced — try crt.sh history + Shodan next")

    utils.log(f"results -> {outdir}")
    utils.log(f"  subdomains {len(subs)} | live {len([r for r in rows if r['status']])} | findings {n_findings} | content {len(content)}")
    utils.log("done.")
    return 0


def _totals(findings: list[dict]) -> dict:
    """Unique findings counted by severity."""
    totals = dict.fromkeys(SEVERITIES, 0)
    for f in report.dedupe(findings):
        sev = f.get("severity")
        if sev in totals:
            totals[sev] += 1
    return totals


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    target = _normalize_target(args.target)
    if not target:
        print("error: invalid target — use a bare domain (e.g. example.com)",
              file=__import__("sys").stderr)
        return 2

    if not args.no_banner:
        banner.print_banner()

    outdir = _resolve_outdir(target, args.output_dir, args.interactive)
    outdir.mkdir(parents=True, exist_ok=True)
    skip = set(x.strip() for x in (args.skip or "").split(",") if x.strip())

    if args.events:
        events_path = Path(args.events)
        events_path.parent.mkdir(parents=True, exist_ok=True)
        events.init(events_path)
        flags = {k: v for k, v in vars(args).items() if k != "events"}
        events.write_run_json(target, flags, __version__)
        events.run_start(target, flags, PLANNED_STAGES(args, skip))

    try:
        return _run(args, target, outdir, skip)
    finally:
        if args.events:
            events.reset()


def _run(args, target: str, outdir: Path, skip: set[str]) -> int:
    utils.log(f"Bounty Runner v{__version__} — target: {target}")
    utils.log(f"output dir: {outdir}")

    st = RunState(target, start=time.monotonic())
    report_path, summary_path = str(outdir / "FINDINGS.md"), str(outdir / "SUMMARY.md")
    try:
        try:
            _pipeline(args, target, outdir, skip, st)
        except events.RunCancelled:
            # partial report from whatever the finished stages gathered
            _finish(args, target, outdir, skip, st)
            events.run_end("cancelled", _totals(st.findings), report_path, summary_path)
            return 130
        rc = _finish(args, target, outdir, skip, st)
    except BaseException as e:  # incl. Ctrl-C / SystemExit: no partial report
        events.run_end("failed", _totals(st.findings), report_path, summary_path, error=repr(e))
        raise
    events.run_end("ok", _totals(st.findings), report_path, summary_path)
    return rc
