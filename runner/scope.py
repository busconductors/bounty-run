"""Request scoping: allow/deny rules over hosts and URLs.

One module replaces the suffix checks scattered across ``cli._normalize_target``,
``subdomain_enum``, ``origin_deep``, ``dork_scan._in_scope``,
``param_scan._in_scope`` and ``secret_scan._is_same_origin``. The default scope
(no allow rules) reproduces the old rule exactly: the target plus any subdomain.

This is engagement scope, not the SSRF guard. ``stages._is_global``/``_resolve``
stay as they are; scope never touches them.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Rule:
    raw: str
    kind: Literal["wildcard", "regex", "cidr", "exact"]
    pattern: object
    url_regex: bool = False   # regex rule matched against the whole URL

    def match_host(self, host: str) -> bool:
        host = (host or "").lower().rstrip(".")
        if not host:
            return False
        if self.kind == "exact":
            return host == self.pattern
        if self.kind == "wildcard":
            # label-wise wildcard: matches subdomains, NOT the apex.
            return host.endswith("." + self.pattern)
        if self.kind == "cidr":
            try:
                return ipaddress.ip_address(host) in self.pattern
            except ValueError:
                return False
        if self.kind == "regex":
            if self.url_regex:
                return False
            return self.pattern.fullmatch(host) is not None
        return False

    def match_url(self, url: str) -> bool:
        if self.kind == "regex" and self.url_regex:
            return self.pattern.fullmatch(url) is not None
        host = (urlsplit(url).hostname or "")
        return self.match_host(host)


def parse_rule(s: str) -> Rule:
    """Parse one scope rule string into a :class:`Rule`."""
    raw = s.strip()
    if raw.startswith("re:"):
        body = raw[len("re:"):]
        return Rule(raw, "regex", re.compile(body), url_regex="/" in body)
    if raw.startswith("*."):
        return Rule(raw, "wildcard", raw[len("*."):].lower().rstrip("."))
    if "/" in raw:
        try:
            net = ipaddress.ip_network(raw, strict=False)
            return Rule(raw, "cidr", net)
        except ValueError:
            pass
    return Rule(raw, "exact", raw.lower().rstrip("."))


@dataclass(frozen=True)
class Scope:
    target: str
    allow: tuple[Rule, ...] = ()
    deny: tuple[Rule, ...] = ()
    extra_hosts: frozenset = frozenset()

    def _denied(self, *, host: str | None = None, url: str | None = None) -> bool:
        for r in self.deny:
            if url is not None and r.match_url(url):
                return True
            if host is not None and url is None and r.match_host(host):
                return True
        return False

    def denies_host(self, host) -> bool:
        """True if an explicit deny rule matches ``host`` (used to refuse a run)."""
        return self._denied(host=(host or "").lower().rstrip("."))

    def host_allowed(self, host) -> bool:
        host = (host or "").lower().rstrip(".")
        if not host:
            return False
        if self._denied(host=host):
            return False
        if host in self.extra_hosts:
            return True
        if not self.allow:
            return host == self.target or host.endswith("." + self.target)
        return any(r.match_host(host) for r in self.allow)

    def url_allowed(self, url) -> bool:
        try:
            parts = urlsplit(url)
        except ValueError:
            return False
        if parts.scheme not in ("http", "https"):
            return False
        host = (parts.hostname or "").lower().rstrip(".")
        if not host:
            return False
        if self._denied(url=url):
            return False
        if host in self.extra_hosts:
            return True
        if not self.allow:
            return host == self.target or host.endswith("." + self.target)
        return any(r.match_url(url) for r in self.allow)

    def filter_hosts(self, hosts) -> list:
        return [h for h in hosts if self.host_allowed(h)]

    def filter_urls(self, urls) -> list:
        return [u for u in urls if self.url_allowed(u)]

    def with_hosts(self, hosts) -> "Scope":
        """Return a new Scope that also admits ``hosts`` (e.g. origin IPs)."""
        extra = set(self.extra_hosts)
        for h in hosts:
            h = (h or "").lower().rstrip(".")
            if h:
                extra.add(h)
        return Scope(self.target, self.allow, self.deny, frozenset(extra))


def _rules_from_file(path: str) -> tuple[list[str], list[str]]:
    allow, deny = [], []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("!"):
                deny.append(line[1:].strip())
            else:
                allow.append(line)
    return allow, deny


def from_args(target, allow=None, deny=None, scope_file=None) -> Scope:
    """Build a Scope from CLI args. A bad regex raises ``re.error``."""
    allow = list(allow or [])
    deny = list(deny or [])
    if scope_file:
        fa, fd = _rules_from_file(scope_file)
        allow += fa
        deny += fd
    target = (target or "").strip().lower().rstrip(".")
    return Scope(
        target=target,
        allow=tuple(parse_rule(a) for a in allow),
        deny=tuple(parse_rule(d) for d in deny),
    )


def default(target) -> Scope:
    """The implicit scope: the target plus any subdomain."""
    return Scope(target=(target or "").strip().lower().rstrip("."))


def for_target(target) -> Scope:
    """The active scope if it is for ``target``, else a default scope.

    Lets stage functions enforce scope whether or not ``cli.main`` set an
    active scope (direct-call tests get the legacy target+subdomain rule).
    """
    t = (target or "").strip().lower().rstrip(".")
    s = active()
    return s if s.target == t else default(t)


# --- module-global active scope (same pattern as events.current_stage) --------

_active: Scope | None = None


def set_active(s: Scope) -> None:
    global _active
    _active = s


def active() -> Scope:
    return _active if _active is not None else default("")


def is_active() -> bool:
    """Whether an explicit scope has been set (by ``cli.main``)."""
    return _active is not None


def reset() -> None:
    global _active
    _active = None
    _log.clear()


class OutOfScopeLog:
    """Records hosts/URLs dropped by scope, for the summary section."""

    def __init__(self):
        self._items: list[dict] = []

    def record(self, kind: str, value: str, stage: str | None = None) -> None:
        self._items.append({"kind": kind, "value": value, "stage": stage})

    def items(self) -> list[dict]:
        return list(self._items)

    def clear(self) -> None:
        self._items.clear()


_log = OutOfScopeLog()


def log() -> OutOfScopeLog:
    return _log


def request_hook(prep, ctx) -> None:
    """httpclient request hook (H5): block out-of-scope hops.

    Raises ``httpclient.OutOfScope`` unless the request is scope-exempt or its
    URL is allowed by the active scope.
    """
    if ctx.get("scope_exempt"):
        return
    url = getattr(prep, "url", None)
    if url and not active().url_allowed(url):
        from . import httpclient
        _log.record("url", url, ctx.get("stage"))
        raise httpclient.OutOfScope(f"out of scope: {url}")
