"""Run-level proxy for the HTTP stages (``--proxy`` / ``BOUNTY_RUN_PROXY``).

One validated :class:`ProxyConfig` describes the proxy; every consumer derives
what it needs from it (tool flags, child env, requests ``proxies=``, redacted
display form). :data:`SUPPORT` is the per-tool capability matrix as data — the
single source of truth for which tool can carry which proxy kind.

Leak policy is fail-closed: when a proxy is set, an HTTP stage either goes
through it or does not run (:func:`gate` warns and marks the stage skipped).
nmap and every DNS lookup stay direct by design (out of scope).
"""
from __future__ import annotations

import ipaddress
import os
import re
import shlex
import socket
from dataclasses import dataclass
from urllib.parse import quote, unquote

from . import events, utils

ENV_VAR = "BOUNTY_RUN_PROXY"

# scheme -> kind
_SCHEMES = {"http": "http", "https": "https", "socks5": "socks5", "socks5h": "socks5"}

_ALL = frozenset({"http", "https", "socks5"})
_HTTP = frozenset({"http"})
_NONE: frozenset = frozenset()

# Which proxy kinds each tool can carry without leaking direct traffic.
SUPPORT: dict[str, frozenset] = {
    "requests": _ALL,        # in-process (httpclient); socks needs PySocks
    "subfinder": _ALL,       # -proxy (Go transport)
    "amass": _ALL,           # env only — best effort, logged as partial
    "findomain": _NONE,      # no proxy option
    "nuclei": _ALL,          # -proxy + -proxy-internal
    "ffuf": _ALL,            # -x
    "katana": _ALL,          # -proxy
    "sqlmap": _ALL,          # --proxy + --proxy-cred
    "curl": _ALL,            # --proxy
    "wafw00f": _ALL,         # --proxy (requests)
    "sslyze": _HTTP,         # --https_tunnel (HTTP CONNECT only)
    "nikto": _HTTP,          # -useproxy (no SOCKS, no TLS-to-proxy, no auth)
    "whatweb": _HTTP,        # --proxy host:port
    "shcheck": frozenset({"http", "socks5"}),  # urllib; SOCKS via vendored patch
    "headi": _NONE,          # no proxy option (static Go binary)
    "metis": _NONE,          # mixed raw-socket protocols
}

# Tools whose traffic is only partially proxied (env-based, unverified).
PARTIAL = frozenset({"amass"})

_GO_TOOLS = frozenset({"subfinder", "nuclei", "ffuf", "katana"})

_HOST_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
# RFC 3986 userinfo: unreserved / pct-encoded / sub-delims / ":"
_USERINFO_RE = re.compile(r"^([A-Za-z0-9._~!$&'()*+,;=:-]|%[0-9A-Fa-f]{2})+$")
_PORT_RE = re.compile(r"^[0-9]{1,5}$")

SCHEME_HELP = "http://, https://, socks5:// or socks5h://"


@dataclass(frozen=True)
class ProxyConfig:
    scheme: str
    host: str
    port: int
    username: str | None = None
    password: str | None = None

    # -- forms -------------------------------------------------------------
    @property
    def kind(self) -> str:
        return _SCHEMES[self.scheme]

    @property
    def hostport(self) -> str:
        h = f"[{self.host}]" if ":" in self.host else self.host
        return f"{h}:{self.port}"

    @property
    def userpass(self) -> str | None:
        if self.username is None:
            return None
        return f"{self.username}:{self.password or ''}"

    def _url(self, scheme: str, creds: bool) -> str:
        auth = ""
        if creds and self.username is not None:
            auth = quote(self.username, safe="")
            if self.password is not None:
                auth += ":" + quote(self.password, safe="")
            auth += "@"
        return f"{scheme}://{auth}{self.hostport}"

    @property
    def url(self) -> str:
        """Full URL including credentials — only ever handed to tools/requests."""
        return self._url(self.scheme, True)

    @property
    def url_nocreds(self) -> str:
        return self._url(self.scheme, False)

    @property
    def redacted(self) -> str:
        """The only form ever logged or persisted."""
        if self.username is None:
            return self.url_nocreds
        return f"{self.scheme}://{quote(self.username, safe='')}:***@{self.hostport}"

    @property
    def requests_proxies(self) -> dict:
        return {"http": self.url, "https": self.url}

    def env(self) -> dict:
        """Child-process env: every proxy var set; NO_PROXY cleared on purpose
        so an ambient ``NO_PROXY=.target`` cannot silently exempt the target."""
        u = self.url
        return {"http_proxy": u, "https_proxy": u, "HTTP_PROXY": u,
                "HTTPS_PROXY": u, "all_proxy": u, "ALL_PROXY": u,
                "no_proxy": "", "NO_PROXY": ""}

    @property
    def secrets(self) -> tuple:
        """Strings that must never reach a log line (longest first)."""
        out = {self.url}
        if self.password:
            out |= {self.password, quote(self.password, safe="")}
        if self.username is not None and self.password:
            out |= {self.userpass,
                    f"{quote(self.username, safe='')}:{quote(self.password, safe='')}"}
        return tuple(sorted((s for s in out if s), key=len, reverse=True))

    # -- per-tool ----------------------------------------------------------
    def supports(self, tool: str) -> bool:
        return self.args_for(tool) is not None

    def args_for(self, tool: str) -> list[str] | None:
        """Proxy CLI args for ``tool``; ``None`` when it cannot carry this kind
        (the caller must then skip the tool, never run it direct)."""
        if self.kind not in SUPPORT.get(tool, _NONE):
            return None
        # Go's socks5 dialer already resolves remotely; older Go builds only
        # know the "socks5" scheme, so hand them that spelling.
        go_url = self._url("socks5" if self.scheme == "socks5h" else self.scheme, True)
        if tool == "nuclei":
            return ["-proxy", go_url, "-proxy-internal"]
        if tool == "ffuf":
            return ["-x", go_url]
        if tool in ("katana", "subfinder"):
            return ["-proxy", go_url]
        if tool == "sqlmap":
            scheme = "socks5" if self.scheme == "socks5h" else self.scheme
            a = ["--proxy", self._url(scheme, False)]
            if self.userpass is not None:
                a += ["--proxy-cred", self.userpass]
            return a
        if tool in ("curl", "wafw00f", "shcheck"):
            return ["--proxy", self.url]
        if tool == "sslyze":
            return [f"--https_tunnel={self.url}"]
        if tool == "nikto":
            if self.username is not None:
                return None  # -useproxy takes no credentials
            return ["-useproxy", self.url_nocreds]
        if tool == "whatweb":
            a = ["--proxy", self.hostport]
            if self.userpass is not None:
                a += ["--proxy-user", self.userpass]
            return a
        if tool in ("amass", "requests"):
            return []  # env / in-process only
        return None

    def cli(self, tool: str) -> str:
        """``args_for`` as a shell-quoted string with a leading space ("" if none)."""
        a = self.args_for(tool)
        return (" " + " ".join(shlex.quote(x) for x in a)) if a else ""

    def unsupported_reason(self, tool: str) -> str | None:
        if self.supports(tool):
            return None
        if tool == "nikto" and self.kind == "http" and self.username is not None:
            return f"proxy: {tool} cannot authenticate to a proxy"
        return f"proxy: {tool} unsupported for {self.kind}"


# --------------------------------------------------------------------------- #
# parsing
# --------------------------------------------------------------------------- #
def parse(raw: str) -> ProxyConfig:
    """Validate a proxy URL; raise ``ValueError`` with a user-facing message."""
    s = (raw or "").strip()
    if not s:
        raise ValueError("empty proxy URL")
    if any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7f for c in s):
        raise ValueError("proxy URL must not contain whitespace or control characters")
    if "://" not in s:
        raise ValueError(f"proxy needs a scheme: {SCHEME_HELP}")
    scheme, rest = s.split("://", 1)
    scheme = scheme.lower()
    if scheme not in _SCHEMES:
        raise ValueError(f"unsupported proxy scheme {scheme!r} (use {SCHEME_HELP})")
    if "?" in rest or "#" in rest:
        raise ValueError("proxy URL must not have a query or fragment")
    netloc, slash, path = rest.partition("/")
    if slash and path:
        raise ValueError("proxy URL must not have a path")
    userinfo, at, hostport = netloc.rpartition("@")
    username = password = None
    if at:
        if not userinfo or not _USERINFO_RE.match(userinfo):
            raise ValueError("invalid proxy credentials (percent-encode @ : and other "
                             "special characters)")
        u, colon, p = userinfo.partition(":")
        if not u:
            raise ValueError("proxy credentials need a username")
        username = unquote(u)
        password = unquote(p) if colon else None
    if hostport.startswith("["):
        end = hostport.find("]")
        if end < 0:
            raise ValueError("invalid proxy host: unterminated IPv6 literal")
        host, tail = hostport[1:end], hostport[end + 1:]
        try:
            if ipaddress.ip_address(host).version != 6:
                raise ValueError
        except ValueError:
            raise ValueError("invalid proxy host: bad IPv6 literal") from None
        if not tail.startswith(":"):
            raise ValueError("proxy URL needs a port (host:port)")
        port_s = tail[1:]
    else:
        host, colon, port_s = hostport.rpartition(":")
        if not colon:
            raise ValueError("proxy URL needs a port (host:port)")
        if not host:
            raise ValueError("proxy URL needs a host")
        if re.fullmatch(r"[0-9.]+", host):
            try:
                ipaddress.IPv4Address(host)
            except ValueError:
                raise ValueError(f"invalid proxy host {host!r}") from None
        elif not _HOST_RE.match(host):
            raise ValueError(f"invalid proxy host {host!r}")
        host = host.lower()
    if not _PORT_RE.match(port_s) or not 1 <= int(port_s) <= 65535:
        raise ValueError("proxy port must be 1-65535")
    return ProxyConfig(scheme, host, int(port_s), username, password)


def from_env(environ=None) -> ProxyConfig | None:
    """Parse ``BOUNTY_RUN_PROXY`` (``None`` when unset/empty)."""
    raw = (environ if environ is not None else os.environ).get(ENV_VAR, "").strip()
    return parse(raw) if raw else None


def from_args(args) -> ProxyConfig | None:
    """The run's proxy from parsed args (``args.proxy`` holds the URL string)."""
    raw = getattr(args, "proxy", None)
    if isinstance(raw, ProxyConfig):
        return raw
    return parse(raw) if raw else None


_AMBIENT = ("http_proxy", "https_proxy", "all_proxy",
            "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")


def ambient_env(environ=None) -> list[str]:
    """Names of proxy env vars already set in the caller's shell."""
    env = environ if environ is not None else os.environ
    return [k for k in _AMBIENT if env.get(k)]


def have_socks() -> bool:
    try:
        import socks  # noqa: F401
    except ImportError:
        return False
    return True


def redact(text: str, cfg: ProxyConfig | None) -> str:
    if not cfg or not text:
        return text
    for s in cfg.secrets:
        text = text.replace(s, "***")
    return text


# --------------------------------------------------------------------------- #
# fail-closed gate + preflight
# --------------------------------------------------------------------------- #
def run_kw(cfg: ProxyConfig | None) -> dict:
    """``utils.run`` kwargs for a proxied tool ({} when no proxy, so proxy-less
    calls keep their exact legacy signature)."""
    return {"proxy": cfg} if cfg is not None else {}


def gate(cfg: ProxyConfig | None, tool: str, mark: bool = True) -> bool:
    """True when ``tool`` may run under ``cfg``. Otherwise warn, mark the stage
    skipped with a ``proxy:`` reason (``mark=False`` for a sub-tool whose stage
    carries on without it), and return False (never run it direct)."""
    if cfg is None:
        return True
    reason = cfg.unsupported_reason(tool)
    if reason is None:
        if tool in PARTIAL:
            utils.warn(f"{tool}: only partially proxied (env-based) under {cfg.redacted}")
        return True
    utils.warn(f"{tool}: cannot use a {cfg.kind} proxy — skipped to avoid a direct leak")
    if mark:
        events.mark_skipped(reason)
    return False


def preflight(cfg: ProxyConfig, target: str, connect_timeout: float = 5,
              request_timeout: float = 10) -> str | None:
    """Prove the proxy works before the run starts; return an error or ``None``.

    A dead proxy would otherwise yield a fast, empty, plausible-looking report.
    1. TCP connect to the proxy. 2. One request to the target through it (any
    HTTP status passes; 407, proxy/TLS errors fail). Errors are redacted.
    """
    try:
        with socket.create_connection((cfg.host, cfg.port), timeout=connect_timeout):
            pass
    except OSError as e:
        return redact(f"cannot connect to proxy {cfg.redacted}: {e}", cfg)
    import requests
    last = None
    with requests.Session() as s:
        s.trust_env = False
        for scheme in ("https", "http"):
            try:
                r = s.get(f"{scheme}://{target}", proxies=cfg.requests_proxies,
                          timeout=request_timeout, verify=False, allow_redirects=False)
            except Exception as e:  # noqa: BLE001
                last = e
                continue
            r.close()
            if r.status_code == 407:
                return f"proxy {cfg.redacted} rejected authentication (HTTP 407)"
            return None
    return redact(f"request to {target} through proxy {cfg.redacted} failed: {last}", cfg)


def banner_line(cfg: ProxyConfig) -> str:
    return f"proxy: {cfg.redacted} (HTTP stages) · nmap + DNS: DIRECT"
