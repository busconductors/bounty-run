"""High-value panel subdomain detection (Phase 12).

Flow:
  1. Normalise each discovered subdomain (strip, lowercase, drop trailing dot)
     and keep only those strictly under the target.
  2. Split off the target suffix; match each remaining label against
     PANEL_PATTERNS (cPanel / WHM / phpMyAdmin / WebDisk / webmail / ...).
  3. Emit one `panel:<kind>` finding per (subdomain, kind); the first matching
     label wins per kind.
  4. Write `outdir/panels.txt` (`<sub>\\t<kind>\\t<severity>`), even when empty.

Pure function: no network, no subprocess.

    from runner.panel_detect import panel_detect
    findings = panel_detect("example.com", outdir, subdomains)
"""
import re
from pathlib import Path

from runner import utils


def _pattern(*aliases: str) -> re.Pattern:
    alt = "|".join(re.escape(a) for a in aliases)
    return re.compile(rf"^(?:{alt})(\d+)?([-_].*)?$", re.I)


# kind -> (compiled label regex, severity). Ordered: report order follows this.
# low = admin/DB/file-access surfaces; info = user-facing mail/calendar.
PANEL_PATTERNS: dict[str, tuple[re.Pattern, str]] = {
    "cpanel": (_pattern("cpanel"), "low"),
    "whm": (_pattern("whm"), "low"),
    "phpmyadmin": (_pattern("phpmyadmin", "pma"), "low"),
    "webdisk": (_pattern("webdisk"), "low"),
    "webmail": (_pattern("webmail"), "info"),
    "cpcalendars": (_pattern("cpcalendars"), "info"),
    "cpcontacts": (_pattern("cpcontacts"), "info"),
}


def _norm(name) -> str:
    if not isinstance(name, str):
        return ""
    return name.strip().lower().rstrip(".")


def _labels_left_of(sub: str, target: str) -> list[str]:
    """Labels of `sub` left of `.target`; [] if sub is not strictly under it."""
    suffix = "." + target
    if not target or not sub.endswith(suffix):
        return []
    return [lbl for lbl in sub[: -len(suffix)].split(".") if lbl]


def panel_detect(target: str, outdir: Path, subdomains: list[str]) -> list[dict]:
    target = _norm(target)
    findings: list[dict] = []
    rows: list[str] = []
    seen: set[str] = set()

    for raw in subdomains or []:
        sub = _norm(raw)
        if not sub or sub in seen:
            continue
        seen.add(sub)
        labels = _labels_left_of(sub, target)
        if not labels:
            continue
        for kind, (regex, severity) in PANEL_PATTERNS.items():
            label = next((lbl for lbl in labels if regex.match(lbl)), None)
            if label is None:
                continue
            findings.append({
                "severity": severity,
                "template": f"panel:{kind}",
                "name": f"High-value panel subdomain: {sub} ({kind})",
                "url": f"https://{sub}",
                "host": sub,
                "evidence": f"label '{label}' matches {kind}",
            })
            rows.append(f"{sub}\t{kind}\t{severity}")

    try:
        Path(outdir).mkdir(parents=True, exist_ok=True)
        (Path(outdir) / "panels.txt").write_text(
            "\n".join(rows) + ("\n" if rows else ""))
    except OSError as exc:
        utils.warn(f"panel detection: could not write panels.txt: {exc}")

    utils.log(f"panel detection: {len(findings)} high-value panel subdomain(s)")
    return findings
