"""Bounty Runner CLI — orchestrate the recon pipeline."""
import argparse
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import (__version__, api_endpoints, banner, categories, dashboard, dork_scan,
               events, evidence, finding, headi_scan, http_headers, httpclient,
               metis_check, nikto_scan, nmap_scan, origin_deep, panel_detect,
               param_scan, report, scope, secret_scan, stage_registry, stages,
               tech_scan, tls_scan, tracker, utils, waf_scan)

REPO_OUTPUTS = Path(__file__).resolve().parent.parent / "outputs"

# Pipeline stage metadata lives in runner.stage_registry; re-exported here so the
# existing names (and the Go TUI parity test) keep working unchanged.
TOTAL_STAGES = stage_registry.TOTAL_STAGES
# Event stage ids, in pipeline order (same names as --skip).
STAGE_IDS = stage_registry.STAGE_IDS
# Stages that only run when their opt-in flag (same name) is set.
OPT_IN_STAGES = stage_registry.OPT_IN_STAGES
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
    p.add_argument("--intensity", choices=("passive", "active", "intrusive"), default="intrusive",
                   help="capability ceiling: passive (OSINT only), active (normal probes), "
                        "intrusive (fuzz/inject/portscan; default — reproduces today's run)")
    p.add_argument("--no-oast", action="store_true",
                   help="disable out-of-band (interactsh) interaction in nuclei (adds -ni)")
    p.add_argument("--allow-auth", action="store_true",
                   help="permit authenticated-request stages (reserved; none use it yet)")
    p.add_argument("--scope-allow", action="append", metavar="PATTERN", default=[],
                   help="in-scope rule (repeatable): host, *.wildcard, CIDR, or re:<regex>")
    p.add_argument("--scope-deny", action="append", metavar="PATTERN", default=[],
                   help="out-of-scope rule (repeatable); deny wins over allow")
    p.add_argument("--scope-file", metavar="PATH",
                   help="scope rules file, one per line; a leading '!' marks a deny rule")
    p.add_argument("--proxy", metavar="URL",
                   help="route in-process HTTP(S) through this proxy (e.g. http://127.0.0.1:8080)")
    p.add_argument("--user-agent", metavar="STR", help="override the HTTP User-Agent header")
    p.add_argument("--header", action="append", metavar="K: V", default=[],
                   help="extra HTTP header to send on every in-process request (repeatable)")
    p.add_argument("--rate-limit", type=float, metavar="RPS",
                   help="max in-process requests per second per host")
    p.add_argument("--retries", type=_nonneg_int, default=0, metavar="N",
                   help="retry transient HTTP failures N times (default 0)")
    p.add_argument("--verify-tls", action="store_true",
                   help="verify TLS certificates on in-process requests (off by default)")
    p.add_argument("--no-evidence", action="store_true",
                   help="do not capture request/response evidence under evidence/")
    p.add_argument("--evidence-unredacted", action="store_true",
                   help="store evidence without redacting secrets/auth headers (use with care)")
    p.add_argument("--evidence-max-body", type=_positive_int, default=256_000, metavar="N",
                   help="cap stored response bodies at N bytes (default 256000)")
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
    return stage_registry.planned(args, skip)


def _positive_int(value: str) -> int:
    """argparse type: integer that must be >= 1."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("must be >= 1")
    if n < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return n


def _nonneg_int(value: str) -> int:
    """argparse type: integer that must be >= 0."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("must be >= 0")
    if n < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return n


def _redact_flags(flags: dict) -> dict:
    """Strip credentials from flags before they reach run.json.

    Removes ``user:pass@`` from a proxy URL and masks ``Authorization``/``Cookie``
    header values.
    """
    out = dict(flags)
    proxy = out.get("proxy")
    if isinstance(proxy, str) and "@" in proxy:
        scheme, _, rest = proxy.partition("://")
        if "@" in rest:
            rest = rest.split("@", 1)[1]
        out["proxy"] = f"{scheme}://{rest}" if scheme else rest
    headers = out.get("header")
    if isinstance(headers, list):
        masked = []
        for h in headers:
            if isinstance(h, str) and ":" in h:
                k, _, _v = h.partition(":")
                if k.strip().lower() in ("authorization", "cookie"):
                    masked.append(f"{k}: ***")
                    continue
            masked.append(h)
        out["header"] = masked
    return out


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
    SPEC = stage_registry.SPEC

    def ok(sid: str) -> bool:
        """Whether a stage runs under the current skip set, opt-in flags and gate."""
        return stage_registry.stage_allowed(SPEC[sid], args, skip)[0]

    def _hdr(sid: str) -> None:
        spec = SPEC[sid]
        utils.stage_header(spec.num, TOTAL_STAGES, spec.title)

    def keep(new, stage_id):
        """Drop findings outside the active scope; log the drops.

        Only enforced when ``cli.main`` set an explicit scope, so direct-call
        tests are unaffected. ``dork:`` findings are the target's own pages
        found via search, so they are checked on URL only.
        """
        if not scope.is_active():
            return new
        s = scope.active()
        kept = []
        for f in new:
            template = f.get("template")
            if categories.classify(template).key == "dork":
                allowed = s.url_allowed(f.get("url") or "")
            else:
                host, url = f.get("host"), f.get("url")
                allowed = s.host_allowed(host) if host else True
                if allowed and url and str(url).split("://", 1)[0] in ("http", "https"):
                    allowed = s.url_allowed(url)
            if allowed:
                kept.append(f)
            else:
                scope.log().record("finding", f.get("url") or f.get("host") or "", stage_id)
        return kept

    # An opt-in stage explicitly requested but blocked by the intensity ceiling
    # is reported (never silently dropped). Only reachable below the default
    # intrusive ceiling, so default stdout/events are unaffected.
    for sid in STAGE_IDS:
        spec = SPEC[sid]
        if not (spec.opt_in_flag and getattr(args, spec.opt_in_flag, False)):
            continue
        allowed, reason = stage_registry.stage_allowed(spec, args, skip)
        if not allowed and reason and reason.startswith("intensity:"):
            utils.warn(f"{sid}: {reason} — skipping")
            if events.enabled():
                with events.stage(sid):
                    events.mark_skipped(reason)

    if ok("subs"):
        with events.stage("subs") as sc:
            _hdr("subs")
            st.subs = stages.subdomain_enum(target, outdir, skip_amass=not args.amass)
            sc.counts["subdomains"] = len(st.subs)
    if ok("panel"):
        with events.stage("panel") as sc:
            _hdr("panel")
            new = keep(panel_detect.panel_detect(target, outdir, st.subs), "panel")
            st.findings += new
            _emit_findings(new)
            sc.counts["findings"] = len(new)
    if ok("live"):
        with events.stage("live") as sc:
            _hdr("live")
            st.rows = stages.live_hosts(st.subs, outdir, timeout=args.timeout,
                                        threads=args.threads, max_hosts=args.max_hosts)
            sc.counts["live"] = len([r for r in st.rows if r["status"]])
    live = [r["host"] for r in st.rows if r["status"]] or [target]
    if ok("cf"):
        with events.stage("cf") as sc:
            _hdr("cf")
            st.cf = stages.cloudflare_detect(target, outdir)
            sc.counts["cloudflare"] = int(bool(st.cf["cloudflare"]))

    if ok("origin"):
        if st.cf["cloudflare"]:
            with events.stage("origin") as sc:
                _hdr("origin")
                st.origins = stages.origin_hunt(target, outdir, st.cf)
                if ok("origin_deep"):
                    st.origins = st.origins + origin_deep.origin_deep(target, outdir, st.cf)
                sc.counts["origins"] = len(_merge_origins_by_ip(st.origins))
        elif events.enabled():
            with events.stage("origin"):
                events.mark_skipped("no cloudflare")
    st.origins = _merge_origins_by_ip(st.origins)
    # Admit discovered origin IPs into scope so their nmap/nuclei findings
    # (host = origin IP) are not dropped by the in-scope finding guard.
    if scope.is_active():
        origin_ips = [o.get("ip") for o in st.origins if isinstance(o, dict) and o.get("ip")]
        if origin_ips:
            scope.set_active(scope.active().with_hosts(origin_ips))

    def scan(stage_id, fn, *a, **kw):
        spec = SPEC[stage_id]
        with events.stage(stage_id) as sc:
            utils.stage_header(spec.num, TOTAL_STAGES, spec.title)
            new = keep(fn(*a, **kw), stage_id)
            st.findings += new
            _emit_findings(new)
            sc.counts["findings"] = len(new)

    if ok("nmap"):
        scan("nmap", nmap_scan.nmap_scan,
             target, outdir, st.rows, st.origins, full=args.nmap_full)

    host_cap = min(args.max_hosts, 20)
    if ok("waf"):
        scan("waf", waf_scan.waf_scan,
             target, outdir, hosts=live, max_hosts=host_cap)
    if ok("dork"):
        scan("dork", dork_scan.dork_scan, target, outdir)
    if ok("tls"):
        scan("tls", tls_scan.tls_scan,
             target, outdir, hosts=live, max_hosts=host_cap)
    if ok("nikto"):
        scan("nikto", nikto_scan.nikto_scan,
             target, outdir, hosts=live, max_hosts=host_cap)

    write_summary(outdir, target, st.subs, st.rows, st.cf, st.origins)
    st.summary_written = True

    if ok("vuln"):
        with events.stage("vuln") as sc:
            _hdr("vuln")
            new = keep(stages.vuln_scan(target, outdir, st.rows, severity=args.nuclei_severity,
                                        concurrency=args.nuclei_c, timeout=args.nuclei_timeout,
                                        origins=st.origins, oast=stage_registry.oast_enabled(args)),
                       "vuln")
            st.findings += new
            sc.counts["findings"] = len(new)
            report.write_findings_report(outdir, target, st.findings, [], origins=st.origins)

    if ok("content"):
        with events.stage("content") as sc:
            _hdr("content")
            st.content = stages.content_discovery(target, outdir, args.wordlist)
            sc.counts["content"] = len(st.content)

    if ok("api"):
        scan("api", api_endpoints.api_endpoints_scan,
             target, outdir, max_hosts=min(args.max_hosts, 20))
    if ok("param"):
        scan("param", param_scan.param_scan,
             target, outdir, args.max_param_urls)
    if ok("secret"):
        scan("secret", secret_scan.secret_scan, target, outdir)
    if ok("metis"):
        scan("metis", metis_check.metis_check, target, outdir, live)

    if ok("headers"):
        scan("headers", http_headers.security_headers_scan,
             target, outdir, live)
    if ok("cors"):
        scan("cors", http_headers.cors_scan, target, outdir, live)
    if ok("tech"):
        scan("tech", tech_scan.tech_scan, target, outdir, live)
    if ok("headi"):
        scan("headi", headi_scan.headi_scan,
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

    store = evidence.active()
    if store is not None:
        evidence.ingest_nuclei(store, outdir)
        evidence.link_tool_artifacts(store, report.dedupe(findings), outdir)
        store.flush()

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

    try:
        active_scope = scope.from_args(
            target, getattr(args, "scope_allow", None),
            getattr(args, "scope_deny", None), getattr(args, "scope_file", None))
    except re.error as e:
        print(f"error: invalid scope regex: {e}", file=__import__("sys").stderr)
        return 2
    except OSError as e:
        print(f"error: cannot read scope file: {e}", file=__import__("sys").stderr)
        return 2
    if active_scope.denies_host(target):
        print(f"error: target {target} is excluded by a --scope-deny rule",
              file=__import__("sys").stderr)
        return 2
    scope.set_active(active_scope)

    # Configure the process-wide HTTP client (no network I/O here) and enforce
    # scope on every request hop (redirects included).
    httpclient.configure(httpclient.HttpConfig.from_args(args))
    httpclient.client().add_request_hook(scope.request_hook)

    if not args.no_banner:
        banner.print_banner()

    outdir = _resolve_outdir(target, args.output_dir, args.interactive)
    outdir.mkdir(parents=True, exist_ok=True)
    skip = set(x.strip() for x in (args.skip or "").split(",") if x.strip())

    if args.events:
        events_path = Path(args.events)
        events_path.parent.mkdir(parents=True, exist_ok=True)
        events.init(events_path)
        flags = _redact_flags({k: v for k, v in vars(args).items() if k != "events"})
        events.write_run_json(target, flags, __version__)
        events.run_start(target, flags, PLANNED_STAGES(args, skip))

    try:
        return _run(args, target, outdir, skip)
    finally:
        httpclient.client().close()
        evidence.reset()
        scope.reset()
        if args.events:
            events.reset()


def _run(args, target: str, outdir: Path, skip: set[str]) -> int:
    utils.log(f"Bounty Runner v{__version__} — target: {target}")
    utils.log(f"output dir: {outdir}")

    st = RunState(target, start=time.monotonic())
    evidence.activate(evidence.EvidenceStore(
        outdir, redact=not args.evidence_unredacted,
        max_body=args.evidence_max_body, enabled=not args.no_evidence))
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
