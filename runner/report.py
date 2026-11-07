"""Findings dedupe + report generation."""
import json
from collections import Counter
from pathlib import Path

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


def write_findings_report(outdir: Path, target: str, findings: list[dict], content: list[str]) -> int:
    """Write deduped findings to findings.json + FINDINGS.md; return count."""
    findings = dedupe(findings)
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity", "unknown"), 9))
    (outdir / "findings.json").write_text(json.dumps(findings, indent=2))

    sev = Counter(f.get("severity", "unknown") for f in findings)
    lines = [f"# Findings — {target}", ""]
    if not findings:
        lines.append("_No vulnerabilities found by nuclei._")
    else:
        lines += ["## Severity", ""]
        for s in ("critical", "high", "medium", "low", "info", "unknown"):
            if sev.get(s):
                lines.append(f"- **{s}**: {sev[s]}")
        lines += ["", "## Vulnerabilities", ""]
        for f in findings:
            lines.append(f"### [{f['severity'].upper()}] {f.get('name') or f.get('template')}")
            lines.append(f"- URL: {f.get('url')}")
            lines.append(f"- Template: `{f.get('template')}`")
            lines.append("")
    if content:
        lines += ["## Discovered content", ""]
        lines += [f"- `{p}`" for p in sorted(content)]
    (outdir / "FINDINGS.md").write_text("\n".join(lines))
    return len(findings)
