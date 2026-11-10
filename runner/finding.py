"""Typed finding model and the single source of truth for severity + fingerprints.

This is a leaf module (stdlib only). The severity ordering, severity
normalisation, URL normalisation and the finding fingerprint all live here so
that report, dashboard, evidence and export agree on one definition.

Producers keep returning plain dicts; :class:`Finding` is used inside the
reporting/evidence/export layers via :func:`coerce`.
"""
from __future__ import annotations

import hashlib
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
