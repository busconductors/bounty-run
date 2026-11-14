"""Subdomain discovery helpers for the ``subs`` stage.

``stages.subdomain_enum`` stays thin and backward compatible; everything it does
beyond the legacy subfinder parse lives here: the passive collectors, the
per-target union cache, the trickest resolver fetch, and the dnsx-based
resolution that splits names into resolved / internal / dangling buckets.

All tool invocations go through ``utils.run`` / ``utils.have`` *via the module
attribute* so the existing test mocks (which patch ``utils.have`` / ``utils.run``
on the shared module object) apply here too. No function reaches the network
unless its tool is present and the caller opted into an active pass, so the
no-network unit tests stay hermetic.
"""
from __future__ import annotations

import ipaddress
import json
import shlex
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from . import proxy as proxymod
from . import scope, utils

# trickest/resolvers — a large, frequently-updated public resolver list.
TRICKEST_RESOLVERS_URL = (
    "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
)
# Small, hand-picked trusted set for puredns-style re-validation (Phase 3).
BUILTIN_TRUSTED = ("1.1.1.1", "8.8.8.8", "8.8.4.4", "9.9.9.9")
RESOLVERS_TTL_S = 24 * 60 * 60
MIN_RESOLVERS = 1000


# --------------------------------------------------------------------------- #
# normalization
# --------------------------------------------------------------------------- #
def _norm(line: str, target: str) -> str | None:
    """Normalize one output line to an in-zone hostname, or return ``None``.

    Lowercases, strips a leading ``*.`` wildcard label and a trailing dot, and
    keeps the name only when it is the apex or a subdomain of ``target``.
    Decoration lines (tool banners, ``[info]`` noise) are rejected.
    """
    s = (line or "").strip().lower()
    if not s:
        return None
    if s.startswith("*."):
        s = s[2:]
    if s.startswith(("#", "[", "-", "*")):
        return None
    s = s.rstrip(".")
    target = (target or "").strip().lower().rstrip(".")
    if not s or not target:
        return None
    if s == target or s.endswith("." + target):
        return s
    return None


def _collect(txt: str, target: str) -> set[str]:
    out: set[str] = set()
    for line in (txt or "").splitlines():
        n = _norm(line, target)
        if n:
            out.add(n)
    return out


# --------------------------------------------------------------------------- #
# passive collectors
# --------------------------------------------------------------------------- #
def passive_subfinder(target: str, outdir: Path, proxy=None) -> set[str]:
    """Run subfinder with hardened flags; parse stdout, fall back to the file.

    Uses ``-all -duc -timeout 60 -max-time 5`` under a 360 s wrapper so slow
    sources (crt.sh) finish and flush. subfinder writes its own ``subfinder.txt``
    via ``-o``; if the wrapper times out with empty stdout we read that file back.
    """
    if not utils.have("subfinder"):
        utils.warn("subfinder not found — skipping")
        return set()
    sub_out = Path(outdir) / "subfinder.txt"
    cmd = (
        f"subfinder -d {shlex.quote(target)} -all -silent -duc "
        f"-timeout 60 -max-time 5 -o {shlex.quote(str(sub_out))}"
    )
    if proxy is not None:
        cmd += proxy.cli("subfinder")
    txt = utils.run(cmd, timeout=360, **proxymod.run_kw(proxy))
    found = _collect(txt, target)
    if not found and sub_out.exists():
        try:
            found = _collect(sub_out.read_text(), target)
        except OSError:
            pass
    return found


def passive_amass(target: str, outdir: Path, proxy=None) -> set[str]:
    """Run amass v5 passive enum, then read names out of its asset DB.

    amass v5 dropped the v4-style ``-passive`` flag and stores results in a
    ``-dir`` asset DB, so a single ``enum -passive`` prints nothing. We run
    ``enum`` to populate the DB, then ``subs -names`` to list the zone.
    """
    if not utils.have("amass"):
        return set()
    if not proxymod.gate(proxy, "amass", mark=False):
        return set()
    amass_dir = Path(outdir) / "amass"
    qt = shlex.quote(target)
    qd = shlex.quote(str(amass_dir))
    cmd = (
        f"amass enum -d {qt} -timeout 5 -dir {qd} && "
        f"amass subs -names -d {qt} -dir {qd}"
    )
    txt = utils.run(cmd, outfile=str(Path(outdir) / "amass.txt"), timeout=300,
                    **proxymod.run_kw(proxy))
    return _collect(txt, target)


def passive_findomain(target: str, outdir: Path, proxy=None) -> set[str]:
    """Run findomain (its own crt.sh/certspotter clients); opt-in add-on."""
    if not utils.have("findomain"):
        utils.warn("findomain not found — skipping")
        return set()
    if not proxymod.gate(proxy, "findomain", mark=False):
        return set()
    cmd = f"findomain -t {shlex.quote(target)} -q"
    txt = utils.run(cmd, outfile=str(Path(outdir) / "findomain.txt"), timeout=180)
    return _collect(txt, target)


# --------------------------------------------------------------------------- #
# per-target union cache ({name: {first_seen, last_seen}})
# --------------------------------------------------------------------------- #
def _cache_path(cache_dir, target: str) -> Path:
    return Path(cache_dir) / f"{(target or '').strip().lower().rstrip('.')}.json"


def cache_load(cache_dir, target: str) -> set[str]:
    """Return the set of names remembered for ``target`` (empty if no cache)."""
    if not cache_dir:
        return set()
    p = _cache_path(cache_dir, target)
    if not p.exists():
        return set()
    try:
        data = json.loads(p.read_text())
    except (OSError, ValueError):
        return set()
    if isinstance(data, dict):
        return {k for k in data.keys() if isinstance(k, str)}
    return set()


def cache_save(cache_dir, target: str, names) -> None:
    """Merge ``names`` into the union cache, preserving each ``first_seen``."""
    if not cache_dir:
        return
    p = _cache_path(cache_dir, target)
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    data: dict = {}
    if p.exists():
        try:
            loaded = json.loads(p.read_text())
            if isinstance(loaded, dict):
                data = loaded
        except (OSError, ValueError):
            data = {}
    for name in names:
        rec = data.get(name)
        if isinstance(rec, dict) and "first_seen" in rec:
            rec["last_seen"] = now
        else:
            data[name] = {"first_seen": now, "last_seen": now}
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    except OSError as e:  # noqa: BLE001
        utils.warn(f"  subs cache write failed: {e}")


# --------------------------------------------------------------------------- #
# resolvers
# --------------------------------------------------------------------------- #
def _valid_resolvers(path: Path) -> bool:
    try:
        lines = [ln.strip() for ln in path.read_text().splitlines() if ln.strip()]
    except OSError:
        return False
    if len(lines) < MIN_RESOLVERS:
        return False
    for ln in lines:
        try:
            ipaddress.ip_address(ln)
        except ValueError:
            return False
    return True


def _fetch_resolvers(dest: Path) -> None:
    with urllib.request.urlopen(TRICKEST_RESOLVERS_URL, timeout=30) as r:  # noqa: S310
        body = r.read().decode("utf-8", "replace")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(body)


def resolvers_file(cache_dir, override: str | None = None) -> Path | None:
    """Return a path to a usable resolver list, or ``None``.

    ``override`` wins when it exists. Otherwise fetch trickest/resolvers into the
    cache with a 24 h TTL, validate it (>1000 lines, all IPs), and fall back to a
    stale copy if the refresh fails. Returns ``None`` when nothing usable exists.
    """
    if override:
        p = Path(override)
        return p if p.exists() else None
    if not cache_dir:
        return None
    p = Path(cache_dir) / "resolvers.txt"
    fresh = p.exists() and (time.time() - p.stat().st_mtime) < RESOLVERS_TTL_S
    if not fresh:
        try:
            _fetch_resolvers(p)
        except Exception as e:  # noqa: BLE001
            utils.warn(f"  resolver fetch failed ({e}); using stale/builtin list")
    if p.exists() and _valid_resolvers(p):
        return p
    return None


# --------------------------------------------------------------------------- #
# resolution
# --------------------------------------------------------------------------- #
@dataclass
class ResolveResult:
    resolved: set[str] = field(default_factory=set)   # at least one public IP
    internal: set[str] = field(default_factory=set)   # only private/loopback IPs
    dangling: set[str] = field(default_factory=set)   # CNAME -> NXDOMAIN/SERVFAIL


def _is_global(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def resolve(names, outdir: Path, target: str, resolvers, rate: int = 500) -> ResolveResult:
    """Resolve ``names`` with dnsx (JSON) and bucket them.

    Writes ``subdomains_all.txt`` (the resolution input), ``subs_resolved.jsonl``
    (dnsx records), ``subs_internal.txt`` (private-only names — report only,
    never probed) and ``subs_dangling.txt`` (CNAMEs pointing at NXDOMAIN/
    SERVFAIL — takeover candidates). A no-op when dnsx is absent.
    """
    result = ResolveResult()
    names = sorted(set(names))
    if not names or not utils.have("dnsx"):
        return result

    outdir = Path(outdir)
    all_file = outdir / "subdomains_all.txt"
    all_file.write_text("\n".join(names) + "\n")
    r = f"-r {shlex.quote(str(resolvers))} " if resolvers else ""
    qin = shlex.quote(str(all_file))

    # Pass 1: A/AAAA/CNAME resolution.
    resolved_jsonl = outdir / "subs_resolved.jsonl"
    cmd = (
        f"dnsx -l {qin} -a -aaaa -cname -j -or {r}-t 100 -rl {int(rate)} "
        f"-retry 2 -silent -o {shlex.quote(str(resolved_jsonl))}"
    )
    txt = utils.run(cmd, timeout=600)
    for line in (txt or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        n = _norm(rec.get("host", ""), target)
        if not n:
            continue
        ips = (rec.get("a") or []) + (rec.get("aaaa") or [])
        if any(_is_global(ip) for ip in ips):
            result.resolved.add(n)
        elif ips:
            result.internal.add(n)

    # Pass 2: dangling CNAMEs (CNAME present, final rcode NXDOMAIN/SERVFAIL).
    dangling_jsonl = outdir / "subs_dangling.jsonl"
    cmd2 = (
        f"dnsx -l {qin} -cname -rc nxdomain,servfail -j -or {r}"
        f"-silent -o {shlex.quote(str(dangling_jsonl))}"
    )
    txt2 = utils.run(cmd2, timeout=600)
    for line in (txt2 or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        n = _norm(rec.get("host", ""), target)
        if n and (rec.get("cname") or []):
            result.dangling.add(n)

    # Internal names must never leak into the probe set.
    result.resolved -= result.internal

    s = scope.for_target(target)
    _write_lines(outdir / "subs_internal.txt", s.filter_hosts(sorted(result.internal)))
    _write_lines(outdir / "subs_dangling.txt", s.filter_hosts(sorted(result.dangling)))
    return result


def _write_lines(path: Path, lines) -> None:
    try:
        Path(path).write_text("\n".join(lines) + ("\n" if lines else ""))
    except OSError:
        pass
