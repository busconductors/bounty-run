"""Findings dedupe + report generation."""
import json
from collections import Counter
from pathlib import Path

from .metis_check import AUX_EXPLOIT_MAP

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


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


def write_findings_report(outdir: Path, target: str, findings: list[dict], content: list[str],
                          origins: list[dict] | None = None) -> int:
    """Write deduped findings to findings.json + FINDINGS.md; return count."""
    findings = dedupe(findings)
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity", "unknown"), 9))
    (outdir / "findings.json").write_text(json.dumps(findings, indent=2))

    sev = Counter(f.get("severity", "unknown") for f in findings)
    lines = [f"# Findings — {target}", ""]
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
