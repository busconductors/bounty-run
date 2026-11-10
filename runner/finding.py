"""Typed finding model and the single source of truth for severity + fingerprints.

This is a leaf module (stdlib only). The severity ordering, severity
normalisation, URL normalisation and the finding fingerprint all live here so
that report, dashboard, evidence and export agree on one definition.

Producers keep returning plain dicts; :class:`Finding` is used inside the
reporting/evidence/export layers via :func:`coerce`.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlsplit, urlunsplit


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


# Canonical severity ordering (lower rank = more severe).
SEVERITY_ORDER: dict[str, int] = {
    Severity.CRITICAL.value: 0,
    Severity.HIGH.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 3,
    Severity.INFO.value: 4,
    Severity.UNKNOWN.value: 5,
}

# Rank used for severities that are not in the canonical set (e.g. metis
# free-form strings). Sorts after every known severity.
_UNRANKED = 9


def normalize_severity(raw) -> str:
    """Lowercase a severity string; ``None``/empty become ``"unknown"``.

    Unknown strings are kept as-is (lowercased) so free-form metis severities
    survive the round-trip.
    """
    if raw is None:
        return Severity.UNKNOWN.value
    s = str(raw).strip().lower()
    return s or Severity.UNKNOWN.value


def severity_rank(raw) -> int:
    """Sort key for a severity: known severities by order, others last."""
    return SEVERITY_ORDER.get(normalize_severity(raw), _UNRANKED)


def normalize_url(url: str) -> str:
    """Canonicalise a URL for fingerprinting.

    Lowercases the scheme and host, strips a default port (80/http, 443/https)
    and strips a trailing ``/`` when the path is empty. Non-URL / unparsable
    input is returned stripped and lowercased as a best effort.
    """
    if not url:
        return ""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return url.strip().lower()
    if not parts.scheme and not parts.netloc:
        return url.strip().lower()
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    port = parts.port
    default_port = {"http": 80, "https": 443}.get(scheme)
    netloc = host
    if parts.username is not None or parts.password is not None:
        auth = parts.username or ""
        if parts.password is not None:
            auth += ":" + parts.password
        netloc = auth + "@" + netloc
    if port is not None and port != default_port:
        netloc += ":" + str(port)
    path = parts.path
    if path == "/":
        path = ""
    return urlunsplit((scheme, netloc, path, parts.query, parts.fragment))


def fingerprint_of(template, host, url) -> str:
    """The single 12-hex-char id for a finding.

    Used by evidence directories, summary anchors, export ids and SARIF
    partialFingerprints.
    """
    key = "\x1f".join((
        template or "",
        host or "",
        normalize_url(url or ""),
    ))
    return hashlib.sha1(key.encode("utf-8", "surrogatepass")).hexdigest()[:12]


@dataclass(frozen=True, slots=True)
class Finding:
    """A typed view over the plain finding dicts producers emit.

    The base five fields (``severity, template, name, url, host``) plus
    optional ``evidence`` reproduce today's dicts exactly via :meth:`to_dict`.
    The extended fields (``stage``, ``target``, ``evidence_refs``) are never
    emitted unless ``extended=True`` is requested, so default output stays
    byte-identical to the legacy dicts.
    """

    severity: str
    template: str
    name: str
    url: str
    host: str | None
    evidence: str | None = None
    # Extended fields — never emitted by to_dict() unless extended=True.
    stage: str | None = None
    target: str | None = None
    evidence_refs: tuple[str, ...] = ()

    @property
    def level(self) -> Severity:
        """The canonical :class:`Severity` for this finding (UNKNOWN fallback)."""
        try:
            return Severity(normalize_severity(self.severity))
        except ValueError:
            return Severity.UNKNOWN

    @property
    def category(self):
        """The registry :class:`~runner.categories.Category` (lazy import)."""
        from . import categories
        return categories.classify(self.template)

    @property
    def fingerprint(self) -> str:
        """The single 12-hex id shared by evidence, summary, export and SARIF."""
        return fingerprint_of(self.template, self.host, self.url)

    def to_dict(self, *, extended: bool = False) -> dict:
        """Reproduce the legacy producer dict.

        Base five keys in today's order; ``evidence`` only when not ``None``.
        ``extended=True`` additionally emits ``stage``, ``target``,
        ``fingerprint`` and ``evidence_refs``.
        """
        d: dict = {
            "severity": self.severity,
            "template": self.template,
            "name": self.name,
            "url": self.url,
            "host": self.host,
        }
        if self.evidence is not None:
            d["evidence"] = self.evidence
        if extended:
            d["stage"] = self.stage
            d["target"] = self.target
            d["fingerprint"] = self.fingerprint
            d["evidence_refs"] = list(self.evidence_refs)
        return d

    @classmethod
    def from_dict(cls, d: Mapping) -> "Finding":
        """Build a Finding from a (possibly partial) mapping, tolerantly.

        A missing ``name`` falls back to ``template``; a non-string
        ``template`` becomes ``""``; the original severity string is kept.
        """
        template = d.get("template")
        if not isinstance(template, str):
            template = ""
        name = d.get("name")
        if name is None:
            name = template
        refs = d.get("evidence_refs") or ()
        return cls(
            severity=d.get("severity", "unknown"),
            template=template,
            name=name,
            url=d.get("url", ""),
            host=d.get("host"),
            evidence=d.get("evidence"),
            stage=d.get("stage"),
            target=d.get("target"),
            evidence_refs=tuple(refs),
        )


def coerce(x: "Finding | Mapping") -> Finding:
    """Return ``x`` if it is already a :class:`Finding`, else build one."""
    if isinstance(x, Finding):
        return x
    return Finding.from_dict(x)


def as_dicts(xs) -> list[dict]:
    """Coerce an iterable of findings/mappings to legacy dicts."""
    return [coerce(x).to_dict() for x in xs]
