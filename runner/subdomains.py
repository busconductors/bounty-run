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
import re
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


# --------------------------------------------------------------------------- #
# Phase 3: active brute force (puredns, dnsx fallback)
# --------------------------------------------------------------------------- #
# Every Phase 3/4 command redirects stdin from /dev/null: alterx (and other
# ProjectDiscovery tools) read stdin when it is not a TTY even with -l, and
# block forever on an inherited pipe.
_NOSTDIN = " </dev/null"

SECLISTS_DNS = Path("/usr/share/seclists/Discovery/DNS")
BRUTE_TIERS = {
    "fast": SECLISTS_DNS / "subdomains-top1million-20000.txt",        # ~20k
    "standard": SECLISTS_DNS / "bitquark-subdomains-top100000.txt",   # ~100k
    "deep": SECLISTS_DNS / "n0kovo_subdomains.txt",                   # ~3M
}
PERMUTE_MAX_SEEDS = 300
PERMUTE_LIMIT = 50_000
TRUSTED_RATE = 200


def wordlist_for(brute: str) -> Path | None:
    """Map a ``--brute`` value (tier name or path) to an existing wordlist."""
    p = BRUTE_TIERS.get(brute) or Path(brute)
    return p if p.is_file() else None


def _count_lines(path: Path) -> int:
    n = 0
    try:
        with open(path, "rb") as fh:
            for _ in fh:
                n += 1
    except OSError:
        return 0
    return n


def _dns_timeout(n_queries: int, rate: int) -> int:
    """Wrapper timeout: ~3x the ideal query time plus validation headroom."""
    return max(300, int(n_queries / max(1, rate) * 3) + 180)


def _resolver_files(outdir: Path, resolvers) -> tuple[Path, Path]:
    """(public, trusted) resolver files; the builtin trusted set backs both."""
    outdir = Path(outdir)
    trusted = outdir / "resolvers_trusted.txt"
    trusted.write_text("\n".join(BUILTIN_TRUSTED) + "\n")
    if resolvers:
        return Path(resolvers), trusted
    return trusted, trusted


def _read_names(path: Path, target: str) -> set[str]:
    try:
        return _collect(Path(path).read_text(errors="replace"), target)
    except OSError:
        return set()


def _puredns_ok() -> bool:
    return utils.have("puredns") and utils.have("massdns")


def brute(target: str, outdir: Path, wordlist: Path, resolvers=None,
          rate: int = 500) -> tuple[set[str], set[str], str]:
    """Brute-force ``target`` with ``wordlist``.

    puredns (massdns + wildcard filter + trusted re-validation) when both are
    installed, else ``dnsx -d -w`` with a manual wildcard filter. Returns
    ``(hits, wildcard_roots, engine)``; engine is ``""`` when no tool exists.
    Writes ``subs_brute.txt`` and (puredns) ``subs_brute_wildcards.txt``.
    """
    outdir = Path(outdir)
    out = outdir / "subs_brute.txt"
    wild = outdir / "subs_brute_wildcards.txt"
    for f in (out, wild):
        f.unlink(missing_ok=True)  # never parse a stale result
    qt, qw = shlex.quote(target), shlex.quote(str(wordlist))
    timeout = _dns_timeout(_count_lines(wordlist), rate)
    if _puredns_ok():
        pub, trusted = _resolver_files(outdir, resolvers)
        cmd = (f"puredns bruteforce {qw} {qt} -r {shlex.quote(str(pub))} "
               f"--resolvers-trusted {shlex.quote(str(trusted))} "
               f"--rate-limit {int(rate)} --rate-limit-trusted {TRUSTED_RATE} -n 5 "
               f"--write {shlex.quote(str(out))} --write-wildcards {shlex.quote(str(wild))} -q"
               + _NOSTDIN)
        txt = utils.run(cmd, timeout=timeout)
        hits = _read_names(out, target) or _collect(txt, target)
        return hits, _read_names(wild, target), "puredns"
    if utils.have("dnsx"):
        pub, _ = _resolver_files(outdir, resolvers)
        cmd = (f"dnsx -d {qt} -w {qw} -r {shlex.quote(str(pub))} "
               f"-rl {min(int(rate), 300)} -wd {qt} -silent "
               f"-o {shlex.quote(str(out))}" + _NOSTDIN)
        txt = utils.run(cmd, timeout=timeout)
        return (_read_names(out, target) or _collect(txt, target)), set(), "dnsx"
    utils.warn("subs: --brute needs puredns+massdns or dnsx — skipping brute pass")
    return set(), set(), ""


# --------------------------------------------------------------------------- #
# Phase 4: permutation (alterx, capped)
# --------------------------------------------------------------------------- #
def _under(name: str, roots) -> bool:
    return any(name == r or name.endswith("." + r) for r in roots)


def select_seeds(names, target: str, wildcard_roots=(),
                 cap: int = PERMUTE_MAX_SEEDS) -> list[str]:
    """Resolved, non-wildcard, non-apex seeds; deepest/most varied first."""
    pool = sorted({n for n in names if n != target and not _under(n, wildcard_roots)})
    # deepest first, then interleave by first label so one family can't fill the cap
    pool.sort(key=lambda n: (-n.count("."), n))
    seen_first: set[str] = set()
    primary, rest = [], []
    for n in pool:
        first = n.split(".", 1)[0].rstrip("0123456789-")
        (rest if first in seen_first else primary).append(n)
        seen_first.add(first)
    return (primary + rest)[:max(0, cap)]


_EST_RE = re.compile(r"Estimated Payloads[^:]*:\s*([0-9]+)")


def _estimate(txt: str) -> int | None:
    """Parse alterx's ``-es`` line (printed on stderr, hence the ``2>&1``)."""
    m = _EST_RE.search(txt or "")
    return int(m.group(1)) if m else None


def permute(seeds, outdir: Path, target: str, known, resolvers=None,
            rate: int = 500, limit: int = PERMUTE_LIMIT) -> set[str]:
    """One capped alterx pass over ``seeds``; return the candidates that resolve.

    ``alterx -es`` estimates first: ``-enrich`` is only used when the enriched
    estimate fits under ``limit``. ``-limit`` is always applied, never
    recursive. Known names are dropped before resolution, which uses puredns
    (wildcard-filtered, trusted re-validation) or plain dnsx.
    """
    outdir = Path(outdir)
    seeds = list(seeds)
    if not seeds:
        return set()
    if not utils.have("alterx"):
        utils.warn("subs: --permute needs alterx — skipping permutation pass")
        return set()
    seeds_f = outdir / "subs_permute_seeds.txt"
    cand_f = outdir / "subs_permute_cand.txt"
    res_f = outdir / "subs_permute.txt"
    seeds_f.write_text("\n".join(seeds) + "\n")
    for f in (cand_f, res_f):
        f.unlink(missing_ok=True)
    qs = shlex.quote(str(seeds_f))

    est = _estimate(utils.run(f"alterx -l {qs} -enrich -es -duc 2>&1" + _NOSTDIN, timeout=120))
    enrich = "-enrich " if est is not None and est <= limit else ""
    utils.run(f"alterx -l {qs} {enrich}-limit {int(limit)} -silent -duc "
              f"-o {shlex.quote(str(cand_f))}" + _NOSTDIN, timeout=300)
    cands = _read_names(cand_f, target) - set(known)
    if not cands:
        return set()
    cand_f.write_text("\n".join(sorted(cands)) + "\n")
    qc = shlex.quote(str(cand_f))
    timeout = _dns_timeout(len(cands), rate)
    if _puredns_ok():
        pub, trusted = _resolver_files(outdir, resolvers)
        txt = utils.run(
            f"puredns resolve {qc} -r {shlex.quote(str(pub))} "
            f"--resolvers-trusted {shlex.quote(str(trusted))} --rate-limit {int(rate)} "
            f"--rate-limit-trusted {TRUSTED_RATE} -w {shlex.quote(str(res_f))} -q" + _NOSTDIN,
            timeout=timeout)
    elif utils.have("dnsx"):
        pub, _ = _resolver_files(outdir, resolvers)
        txt = utils.run(
            f"dnsx -l {qc} -r {shlex.quote(str(pub))} -rl {int(rate)} -silent "
            f"-o {shlex.quote(str(res_f))}" + _NOSTDIN, timeout=timeout)
    else:
        utils.warn("subs: no resolver tool (puredns/dnsx) for permutation candidates — skipping")
        return set()
    return (_read_names(res_f, target) or _collect(txt, target)) & cands
