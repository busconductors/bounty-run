"""Per-stage capability tiers and the intensity/capability gate.

The pipeline's stage set used to be hard-coded in ``cli.py`` as parallel lists
(``STAGE_IDS``, ``OPT_IN_STAGES``) plus ~20 inline ``if "x" not in skip``
conditions. This module is the single declarative source: each stage carries a
tier (passive/active/intrusive), optional orthogonal capabilities (OAST, auth),
its opt-in flag and parent, so the CLI can gate with one predicate.

The five "tiers" from the brief (passive/active/intrusive/oast/auth) are modelled
as 3 ordered tiers plus 2 orthogonal capabilities, because OAST and auth are not
"more intrusive than intrusive" — a stage can be active and use OAST at once.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, IntEnum


class Tier(IntEnum):
    PASSIVE = 0      # no packets to target-owned infra (third-party sources only)
    ACTIVE = 1       # normal requests / non-invasive probes
    INTRUSIVE = 2    # fuzzing, injection, brute, port scanning


class Cap(str, Enum):
    OAST = "oast"    # out-of-band interaction server (nuclei interactsh)
    AUTH = "auth"    # authenticated requests (reserved; no stage uses it yet)


@dataclass(frozen=True)
class StageSpec:
    id: str
    num: int
    title: str
    tier: Tier
    caps: frozenset = frozenset()
    opt_in_flag: str | None = None
    parent: str | None = None


STAGES: tuple[StageSpec, ...] = (
    StageSpec("subs", 1, "SUBDOMAIN ENUMERATION", Tier.PASSIVE),
    StageSpec("panel", 2, "PANEL DETECTION", Tier.PASSIVE),
    StageSpec("live", 3, "LIVE HOST PROBING", Tier.ACTIVE),
    StageSpec("cf", 4, "CLOUDFLARE DETECTION", Tier.ACTIVE),
    StageSpec("origin", 5, "ORIGIN HUNTING", Tier.ACTIVE),
    StageSpec("origin_deep", 5, "ORIGIN HUNTING", Tier.ACTIVE, parent="origin"),
    StageSpec("nmap", 6, "PORT SCAN (NMAP)", Tier.INTRUSIVE, opt_in_flag="nmap"),
    StageSpec("waf", 7, "WAF FINGERPRINT (WAFW00F)", Tier.ACTIVE),
    StageSpec("dork", 8, "SEARCH-ENGINE DORKING (OSINT)", Tier.PASSIVE),
    StageSpec("tls", 9, "TLS/SSL ANALYSIS (SSLYZE)", Tier.ACTIVE, opt_in_flag="tls"),
    StageSpec("nikto", 10, "WEB-SERVER SCAN (NIKTO)", Tier.INTRUSIVE, opt_in_flag="nikto"),
    StageSpec("vuln", 11, "VULNERABILITY SCAN (NUCLEI)", Tier.ACTIVE, caps=frozenset({Cap.OAST})),
    StageSpec("content", 12, "CONTENT DISCOVERY", Tier.ACTIVE),
    StageSpec("api", 13, "API ENDPOINT ENUMERATION", Tier.ACTIVE),
    StageSpec("param", 14, "PARAMETER / SQLi SCAN", Tier.INTRUSIVE),
    StageSpec("secret", 15, "SECRET SCAN", Tier.ACTIVE),
    StageSpec("metis", 16, "METIS CVE SWEEP", Tier.INTRUSIVE, opt_in_flag="metis"),
    StageSpec("headers", 17, "SECURITY HEADERS", Tier.ACTIVE),
    StageSpec("cors", 18, "CORS MISCONFIGURATION", Tier.ACTIVE),
    StageSpec("tech", 19, "TECH DETECTION", Tier.ACTIVE),
    StageSpec("headi", 20, "HEADER INJECTION (HEADI)", Tier.INTRUSIVE, opt_in_flag="headi"),
)

SPEC: dict[str, StageSpec] = {s.id: s for s in STAGES}

# Top-level stages (origin_deep is a child of origin). Identical list to the old
# cli.STAGE_IDS, which the Go TUI parity test pins.
STAGE_IDS: list[str] = [s.id for s in STAGES if s.parent is None]

OPT_IN_STAGES: set[str] = {s.id for s in STAGES if s.opt_in_flag and s.parent is None}

TOTAL_STAGES: int = len(STAGE_IDS)

_TIER_BY_NAME = {
    "passive": Tier.PASSIVE,
    "active": Tier.ACTIVE,
    "intrusive": Tier.INTRUSIVE,
}


def _ceiling(args) -> Tier:
    return _TIER_BY_NAME.get(getattr(args, "intensity", "intrusive"), Tier.INTRUSIVE)


def cap_permitted(cap: Cap, args) -> bool:
    """Whether a hard capability is permitted by the current flags.

    OAST is a *soft* capability (handled by degrading nuclei to ``-ni``), so it
    is always "permitted" here and never blocks a stage.
    """
    if cap is Cap.OAST:
        return True
    if cap is Cap.AUTH:
        return bool(getattr(args, "allow_auth", False))
    return True


def oast_enabled(args) -> bool:
    """Whether OAST is enabled for this run (nuclei interactsh)."""
    return not getattr(args, "no_oast", False)


def stage_allowed(spec: StageSpec, args, skip) -> tuple[bool, str | None]:
    """Return ``(ok, reason)`` — whether a stage runs and, if not, why.

    A stage runs only when it is not skipped, its opt-in flag (if any) is set,
    its tier is within the intensity ceiling, and every *hard* capability it
    needs is permitted.
    """
    if spec.id in skip:
        return (False, "skipped")
    if spec.opt_in_flag and not getattr(args, spec.opt_in_flag, False):
        return (False, None)   # silently not opted in
    ceiling = _ceiling(args)
    if spec.tier > ceiling:
        return (False, f"intensity: {spec.tier.name.lower()} > {ceiling.name.lower()}")
    for cap in spec.caps:
        if not cap_permitted(cap, args):
            return (False, f"requires --allow-{cap.value}")
    return (True, None)


def planned(args, skip) -> list[str]:
    """Ordered top-level stage ids that will run under the current flags."""
    return [s.id for s in STAGES
            if s.parent is None and stage_allowed(s, args, skip)[0]]
