"""Bounty Runner CLI — orchestrate the recon pipeline."""
import argparse
import time
from pathlib import Path

from . import __version__, stages, utils


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bounty-run",
        description="Recon orchestrator for bug bounty — chains your arsenal into one sweep.",
    )
    p.add_argument("target", help="target domain (e.g. example.com)")
    p.add_argument("-o", "--output-dir", help="output directory (default: ~/.bounty-run/<target>/<ts>)")
    p.add_argument("--amass", action="store_true", help="also run amass passive enum (needs API keys to be useful)")
    p.add_argument("--timeout", type=int, default=8, help="HTTP probe timeout in seconds (default 8)")
    p.add_argument("--threads", type=int, default=30, help="concurrent HTTP probe threads (default 30)")
    p.add_argument("--max-hosts", type=int, default=1000, help="cap on hosts to probe (default 1000)")
    p.add_argument("--skip", help="comma-separated stages to skip: subs,live,cf,origin")
    return p


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


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    target = args.target.strip().rstrip("/").lower()
    if not target:
        print("error: empty target", file=__import__("sys").stderr)
        return 2

    if args.output_dir:
        outdir = Path(args.output_dir)
    else:
        outdir = Path.home() / ".bounty-run" / target / time.strftime("%Y%m%d-%H%M%S")
    outdir.mkdir(parents=True, exist_ok=True)

    utils.log(f"Bounty Runner v{__version__} — target: {target}")
    utils.log(f"output dir: {outdir}")

    skip = set(x.strip() for x in (args.skip or "").split(",") if x.strip())

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

    write_summary(outdir, target, subs, rows, cf, origins)

    if cf["cloudflare"]:
        if origins:
            utils.log(f"origin candidates found — check {outdir / 'origin_candidates.txt'}")
        else:
            utils.warn("no origin candidates surfaced — try crt.sh history + Shodan next (Phase 3)")
    utils.log("done.")
    return 0
