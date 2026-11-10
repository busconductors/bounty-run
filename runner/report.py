"""Findings dedupe + report generation."""
import json
from collections import Counter
from pathlib import Path

from . import categories, finding
from .metis_check import AUX_EXPLOIT_MAP

# Single source of truth lives in runner.finding; re-exported for callers.
SEVERITY_ORDER = finding.SEVERITY_ORDER


def dedupe(findings: list[dict]) -> list[dict]:
    """Drop duplicate findings (same template on the same host for the same URL)."""
    seen, unique = set(), []
    for f in findings:
        key = (f.get("template"), f.get("host"), f.get("url"))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def _metis_module_path(finding: dict) -> str | None:
    """Return the Metis module path for a `metis:<path>` finding, else None."""
    template = finding.get("template") or ""
    if not isinstance(template, str) or not template.startswith("metis:"):
        return None
    return template[len("metis:"):]


def _render_finding_lines(f: dict) -> list[str]:
    """Render one finding's FINDINGS.md block (header + body + blank line)."""
    severity = (f.get("severity") or "unknown").upper()
    lines = [
        f"### [{severity}] {f.get('name') or f.get('template')}",
        f"- URL: {f.get('url')}",
        f"- Template: `{f.get('template')}`",
    ]
    if f.get("evidence"):
        lines.append(f"- Evidence: {f.get('evidence')}")

    module_path = _metis_module_path(f)
    if module_path:
        host = f.get("host") or ""
        lines.append("- Confirm (manual, authorized scope only):")
        lines.append(f"    metis> use {module_path}")
        lines.append(f"    metis> set RHOSTS {host}")
        lines.append("    metis> check")
        exploit = AUX_EXPLOIT_MAP.get(module_path)
        if exploit:
            lines.append(f"    # exploit: {exploit}")
    lines.append("")
    return lines


def build_metrics(target: str, subs: list[str], rows: list[dict], cf: dict,
                  origins: list[dict] | None, findings: list[dict], content: list[str],
                  duration_s: float | None, skip: set[str] | None = None) -> list[tuple[str, str]]:
    """Build the ordered ``(label, value)`` pairs for the executive overview.

    Tallies run over ``report.dedupe(findings)`` so they match the report exactly.
    Category routing is delegated to :mod:`runner.categories`; nuclei findings
    are everything not claimed by a named category, and their severity tally is
    lowercased and emitted in ``SEVERITY_ORDER``.
    """
    findings = dedupe(findings)
    live = [r for r in rows if r.get("status")]
    cf_hosts = [r for r in live if r.get("cloudflare")]

    counts: Counter = Counter()
    sev: Counter = Counter()
    for f in findings:
        cat = categories.classify(f.get("template"))
        if cat is categories.NUCLEI:
            sev[finding.normalize_severity(f.get("severity"))] += 1
        else:
            counts[cat.key] += 1

    def c(key: str) -> str:
        return str(counts.get(key, 0))

    metrics: list[tuple[str, str]] = [
        ("Target", target),
        ("Scan duration", f"{duration_s:.1f}s" if duration_s is not None else "n/a"),
        ("Subdomains", str(len(subs or []))),
        ("Live hosts", str(len(live))),
        ("Cloudflare on target", "yes" if (cf or {}).get("cloudflare") else "no"),
        ("Cloudflare-fronted hosts", str(len(cf_hosts))),
        ("Origin candidates", str(len(origins or []))),
    ]
    for severity in SEVERITY_ORDER:
        if sev.get(severity):
            metrics.append((f"Nuclei findings — {severity}", str(sev[severity])))
    metrics += [
        ("Missing security headers", c("headers_missing")),
        ("Insecure security headers", c("headers_insecure")),
        ("CORS misconfigurations", c("cors")),
        ("Header injection (headi)", c("headi")),
        ("Open ports (nmap)", c("nmap")),
        ("High-value panels (subdomains)", c("panel")),
        ("WAF detections (wafw00f)", c("waf")),
        ("Dork hits (OSINT)", c("dork")),
        ("TLS/SSL issues (sslyze)", c("tls")),
        ("Nikto findings", c("nikto")),
        ("Technologies (whatweb)", c("tech")),
        ("API endpoints (katana)", c("api")),
        ("Secret-exposure", c("secret")),
        ("sqlmap-sqli", c("sqli")),
        ("Metis", c("metis")),
        ("Content discovered", str(len(content or []))),
        ("Total unique findings", str(len(findings))),
        ("Skipped stages", ", ".join(sorted(skip)) if skip else "none"),
    ]
    return metrics


def render_overview(metrics: list[tuple[str, str]]) -> list[str]:
    """Render the ``## Executive Overview`` two-column table from metric pairs."""
    lines = ["## Executive Overview", "", "| Metric | Result |", "| --- | --- |"]
    lines += [f"| {label} | {value} |" for label, value in metrics]
    return lines


def write_findings_report(outdir: Path, target: str, findings: list[dict], content: list[str],
                          origins: list[dict] | None = None, *,
                          metrics: list[tuple[str, str]] | None = None) -> int:
    """Write deduped findings to findings.json + FINDINGS.md; return count."""
    findings = dedupe(findings)
    findings.sort(key=lambda f: finding.severity_rank(f.get("severity", "unknown")))
    (outdir / "findings.json").write_text(json.dumps(findings, indent=2))

    sev = Counter(f.get("severity", "unknown") for f in findings)
    lines = [f"# Findings — {target}", ""]
    if metrics is not None:
        lines += render_overview(metrics)
        lines.append("")
    if not findings:
        lines.append("_No vulnerabilities found._")
    else:
        lines += ["## Severity", ""]
        for s in ("critical", "high", "medium", "low", "info", "unknown"):
            if sev.get(s):
                lines.append(f"- **{s}**: {sev[s]}")
        lines += ["", "## Vulnerabilities", ""]
        for f in findings:
            lines += _render_finding_lines(f)
    if origins:
        lines += ["", "## Origin candidates (behind Cloudflare)", ""]
        lines += [
            f"- `{o.get('ip', '')}` — HTTP {o.get('status', '')} — via {', '.join(o.get('sources', []))}"
            for o in origins
        ]
        lines.append("")
    if content:
        lines += ["## Discovered content", ""]
        lines += [f"- `{p}`" for p in sorted(content)]
    (outdir / "FINDINGS.md").write_text("\n".join(lines))
    return len(findings)
