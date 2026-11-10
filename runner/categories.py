"""The single finding-category registry.

One source of truth for the template-prefix router that previously lived,
duplicated, in :func:`report.build_metrics` and across ``dashboard.py``. Each
:class:`Category` carries the exact label string the executive overview emits
(tests pin these byte-for-byte) plus the metadata the dashboard needs
(candidate rule, recon-vs-vuln).
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from functools import lru_cache

from . import finding


@dataclass(frozen=True)
class Category:
    key: str              # stable slug: "panel", "tls", "nuclei", ...
    label: str            # EXACT existing build_metrics label string
    match: str            # prefix (incl. trailing colon) or exact template
    exact: bool = False
    candidate_any_sev: bool = False   # panel: a candidate at any severity
    recon: bool = False               # tech/api/nmap/waf: surface, not a vuln

    def matches(self, template: str) -> bool:
        if self.exact:
            return template == self.match
        return template.startswith(self.match)


# In classification order (report.build_metrics lines 76-111). Prefixes keep the
# trailing colon so "tech-detect" without one stays a nuclei finding.
CATEGORIES: tuple[Category, ...] = (
    Category("metis", "Metis", "metis:"),
    Category("secret", "Secret-exposure", "secret-exposure", exact=True),
    Category("sqli", "sqlmap-sqli", "sqlmap-sqli", exact=True),
    Category("headers_missing", "Missing security headers", "missing-security-header:"),
    Category("headers_insecure", "Insecure security headers", "insecure-security-header:"),
    Category("cors", "CORS misconfigurations", "cors-misconfiguration:"),
    Category("headi", "Header injection (headi)", "headi:"),
    Category("nmap", "Open ports (nmap)", "nmap:", recon=True),
    Category("tech", "Technologies (whatweb)", "tech-detect:", recon=True),
    Category("api", "API endpoints (katana)", "api-endpoint", exact=True, recon=True),
    Category("panel", "High-value panels (subdomains)", "panel:", candidate_any_sev=True),
    Category("waf", "WAF detections (wafw00f)", "waf:", recon=True),
    Category("dork", "Dork hits (OSINT)", "dork:"),
    Category("tls", "TLS/SSL issues (sslyze)", "tls:"),
    Category("nikto", "Nikto findings", "nikto:"),
)

# Fallback bucket. Not in CATEGORIES; counted per lowercased severity as
# "Nuclei findings — <sev>".
NUCLEI = Category("nuclei", "Nuclei findings", "", recon=False)

BY_KEY: dict[str, Category] = {c.key: c for c in CATEGORIES}
BY_KEY[NUCLEI.key] = NUCLEI


@lru_cache(maxsize=4096)
def _classify_str(template: str) -> Category:
    for cat in CATEGORIES:
        if cat.matches(template):
            return cat
    return NUCLEI


def classify(template) -> Category:
    """Return the Category for a template; non-str / unmatched → NUCLEI."""
    if not isinstance(template, str):
        return NUCLEI
    return _classify_str(template)


def _template_of(f) -> str:
    if hasattr(f, "template"):
        return f.template
    return f.get("template")


def _severity_of(f) -> str:
    if hasattr(f, "severity"):
        return f.severity
    return f.get("severity")


def count_by_category(findings) -> Counter:
    """Count findings by category key; nuclei findings keyed by ``nuclei``."""
    counts: Counter = Counter()
    for f in findings:
        counts[classify(_template_of(f)).key] += 1
    return counts


def by_category(findings, key: str) -> list:
    """Return findings whose category key equals ``key`` (order preserved)."""
    return [f for f in findings if classify(_template_of(f)).key == key]


_CANDIDATE_SEVERITIES = ("critical", "high", "medium")


def is_candidate(f) -> bool:
    """Triage split: candidate = critical/high/medium severity, or a panel hit."""
    cat = classify(_template_of(f))
    if cat.candidate_any_sev:
        return True
    return finding.normalize_severity(_severity_of(f)) in _CANDIDATE_SEVERITIES
