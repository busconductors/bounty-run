"""Bounty Runner CLI — orchestrate the recon pipeline."""
import argparse
import os
import re
import time
from pathlib import Path

from . import (__version__, banner, dashboard, headi_scan, http_headers, metis_check,
               nmap_scan, origin_deep, param_scan, report, secret_scan, stages, tracker,
               utils)

REPO_OUTPUTS = Path(__file__).resolve().parent.parent / "outputs"


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
    p.add_argument("--skip", help="comma-separated stages to skip: subs,live,cf,origin,origin_deep,vuln,content,param,secret,headers,cors,metis,headi,nmap")
    p.add_argument("--metis", action="store_true", help="also run the Metis autocheck CVE sweep (off by default)")
    p.add_argument("--headi", action="store_true", help="also run the headi header-injection scan (off by default; intrusive)")
    p.add_argument("--nmap", action="store_true", help="also run the nmap port scan (off by default; intrusive)")
    p.add_argument("--max-param-urls", type=_positive_int, default=50,
                   help="cap on sqlmap param URLs (default 50)")
    p.add_argument("--nuclei-severity", default="low,medium,high,critical",
                   help="nuclei severity filter (default: low,medium,high,critical)")
    p.add_argument("--nuclei-c", type=_positive_int, default=25,
                   help="nuclei concurrency (default 25; auto-clamped by available RAM)")
    p.add_argument("--nuclei-timeout", type=_positive_int, default=600,
                   help="nuclei timeout in seconds (default 600)")
    p.add_argument("--interactive", action="store_true",
                   help="prompt for output directory + engagement name (-o skips the prompts)")
    p.add_argument("--no-banner", action="store_true", help="suppress the startup banner")
    p.add_argument("--no-track", action="store_true", help="do not ingest findings into the tracker DB")
    return p


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

    utils.log(f"Bounty Runner v{__version__} — target: {target}")
    utils.log(f"output dir: {outdir}")

    skip = set(x.strip() for x in (args.skip or "").split(",") if x.strip())
    start = time.monotonic()

    subs = [target]
    rows = []
    cf = {"target": target, "cloudflare": False, "evidence": []}

    if "subs" not in skip:
        subs = stages.subdomain_enum(target, outdir, skip_amass=not args.amass)
    if "live" not in skip:
        rows = stages.live_hosts(subs, outdir, timeout=args.timeout,
                                 threads=args.threads, max_hosts=args.max_hosts)
    if "cf" not in skip:
        cf = stages.cloudflare_detect(target, outdir)

    origins = []
    if cf["cloudflare"] and "origin" not in skip:
        origins = stages.origin_hunt(target, outdir, cf)
        if "origin_deep" not in skip:
            origins += origin_deep.origin_deep(target, outdir, cf)
    origins = _merge_origins_by_ip(origins)

    write_summary(outdir, target, subs, rows, cf, origins)

    findings = []
    if "vuln" not in skip:
        findings = stages.vuln_scan(target, outdir, rows, severity=args.nuclei_severity,
                                    concurrency=args.nuclei_c, timeout=args.nuclei_timeout)
        report.write_findings_report(outdir, target, findings, [], origins=origins)

    content = []
    if "content" not in skip:
        content = stages.content_discovery(target, outdir, args.wordlist)

    if "param" not in skip:
        findings += param_scan.param_scan(target, outdir, args.max_param_urls)

    if "secret" not in skip:
        findings += secret_scan.secret_scan(target, outdir)

    live = [r["host"] for r in rows if r["status"]] or [target]
    if "metis" not in skip and args.metis:
        findings += metis_check.metis_check(target, outdir, live)

    if "headers" not in skip:
        findings += http_headers.security_headers_scan(target, outdir, live)
    if "cors" not in skip:
        findings += http_headers.cors_scan(target, outdir, live)
    if "nmap" not in skip and args.nmap:
        findings += nmap_scan.nmap_scan(target, outdir, rows, origins)
    if "headi" not in skip and args.headi:
        findings += headi_scan.headi_scan(target, outdir, rows)

    duration_s = time.monotonic() - start
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
