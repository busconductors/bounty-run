"""Shared HTTP client: one pooled, hookable session for every in-process request.

Previously five ``requests.get`` call sites configured timeouts, TLS verification
and (not) retries independently. This module centralises that behaviour behind a
process-wide :class:`Client` so proxy, user-agent, retries, rate-limiting and the
scope/evidence hooks apply everywhere at once.

The :data:`compat` namespace is a drop-in stand-in for the ``requests`` module so
module-level patch targets (``mock.patch.object(mod.requests, "get")``) keep
intercepting — a plain ``requests.get`` would build a fresh Session per call and
bypass pooling and hooks.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Callable, Mapping
from urllib.parse import urlsplit

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from . import __version__, events


@dataclass(frozen=True)
class HttpConfig:
    user_agent: str = f"bounty-run/{__version__}"
    proxy: str | None = None               # applied to http+https
    verify: bool = False                   # today's behaviour; --verify-tls flips it
    timeout: tuple = (8, 8)
    retries: int = 0                       # DEFAULT 0: dork test pins call_count==8
    backoff: float = 0.5
    status_forcelist: tuple = (429, 502, 503, 504)
    rate_per_host: float | None = None     # DEFAULT None: dork test pins exactly 3 sleeps
    pool_maxsize: int = 30                 # = --threads
    extra_headers: Mapping = field(default_factory=dict)

    @classmethod
    def from_args(cls, args) -> "HttpConfig":
        headers = {}
        for h in getattr(args, "header", None) or []:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()
        return cls(
            user_agent=getattr(args, "user_agent", None) or cls.user_agent,
            proxy=getattr(args, "proxy", None),
            verify=bool(getattr(args, "verify_tls", False)),
            retries=int(getattr(args, "retries", 0) or 0),
            rate_per_host=getattr(args, "rate_limit", None),
            pool_maxsize=int(getattr(args, "threads", 30) or 30),
            extra_headers=headers,
        )


class OutOfScope(requests.RequestException):
    """Raised by a request hook to block an out-of-scope request/redirect hop.

    Subclasses ``RequestException`` so existing ``except`` handlers treat it as a
    normal request failure.
    """


RequestHook = Callable[[requests.PreparedRequest, dict], None]
ResponseHook = Callable[[requests.Response, dict], None]


class HostRateLimiter:
    """Simple per-host minimum-interval throttle; injectable clock for tests."""

    def __init__(self, rate: float | None, clock=time.monotonic, sleep=time.sleep):
        self.rate = rate
        self._clock = clock
        self._sleep = sleep
        self._next: dict[str, float] = {}
        self._lock = threading.Lock()

    def acquire(self, host: str) -> None:
        if not self.rate or self.rate <= 0:
            return
        interval = 1.0 / self.rate
        with self._lock:
            now = self._clock()
            earliest = self._next.get(host, 0.0)
            wait = earliest - now
            self._next[host] = max(now, earliest) + interval
        if wait > 0:
            self._sleep(wait)


class _HookedSession(requests.Session):
    """A Session whose ``send`` runs scope hooks and rate-limiting per hop."""

    def __init__(self):
        super().__init__()
        self._req_hooks: list = []
        self._resp_hooks: list = []
        self._limiter: HostRateLimiter | None = None
        self._ctx = threading.local()

    def _current_ctx(self) -> dict:
        return getattr(self._ctx, "value", None) or {}

    def send(self, request, **kw):
        ctx = self._current_ctx()
        for hook in self._req_hooks:
            hook(request, ctx)  # may raise OutOfScope to block
        if self._limiter is not None:
            host = urlsplit(request.url).hostname or ""
            self._limiter.acquire(host)
        resp = super().send(request, **kw)
        for hook in self._resp_hooks:
            hook(resp, ctx)
        return resp


class Client:
    def __init__(self, cfg: HttpConfig):
        self.cfg = cfg
        if not cfg.verify:
            urllib3.disable_warnings()
        self._req_hooks: list = []
        self._resp_hooks: list = []
        self._limiter = HostRateLimiter(cfg.rate_per_host)
        self._sessions: dict[int, _HookedSession] = {}
        self._lock = threading.Lock()
        self._sessions[cfg.retries] = self._build_session(cfg.retries)

    def _build_session(self, retries: int) -> _HookedSession:
        s = _HookedSession()
        s._req_hooks = self._req_hooks
        s._resp_hooks = self._resp_hooks
        s._limiter = self._limiter
        s.verify = self.cfg.verify
        s.headers.update({"User-Agent": self.cfg.user_agent})
        s.headers.update(dict(self.cfg.extra_headers))
        if self.cfg.proxy:
            s.proxies.update({"http": self.cfg.proxy, "https": self.cfg.proxy})
        retry = Retry(
            total=retries, connect=retries, read=retries,
            backoff_factor=self.cfg.backoff, status_forcelist=self.cfg.status_forcelist,
            allowed_methods={"GET", "HEAD", "OPTIONS"},
            respect_retry_after_header=True, raise_on_status=False,
        )
        adapter = HTTPAdapter(
            pool_connections=self.cfg.pool_maxsize,
            pool_maxsize=self.cfg.pool_maxsize,
            max_retries=retry,
        )
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        return s

    def _session_for(self, retries: int | None) -> _HookedSession:
        n = self.cfg.retries if retries is None else retries
        with self._lock:
            sess = self._sessions.get(n)
            if sess is None:
                sess = self._build_session(n)
                self._sessions[n] = sess
            return sess

    def add_request_hook(self, fn: RequestHook) -> None:
        self._req_hooks.append(fn)

    def add_response_hook(self, fn: ResponseHook) -> None:
        self._resp_hooks.append(fn)

    def request(self, method, url, *, timeout=None, headers=None, retries=None,
                scope_exempt=False, purpose="target", **kw) -> requests.Response:
        sess = self._session_for(retries)
        ctx = {"scope_exempt": scope_exempt, "purpose": purpose,
               "stage": events.current_stage()}
        sess._ctx.value = ctx
        try:
            return sess.request(
                method, url,
                timeout=self.cfg.timeout if timeout is None else timeout,
                headers=headers, **kw)
        finally:
            sess._ctx.value = None

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def head(self, url, **kw):
        return self.request("HEAD", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)

    def close(self) -> None:
        with self._lock:
            for s in self._sessions.values():
                try:
                    s.close()
                except Exception:
                    pass
            self._sessions.clear()


# --- process-wide client ------------------------------------------------------

_client: Client | None = None
_client_lock = threading.Lock()


def configure(cfg: HttpConfig) -> Client:
    global _client
    with _client_lock:
        if _client is not None:
            _client.close()
        _client = Client(cfg)
    return _client


def client() -> Client:
    global _client
    if _client is None:
        with _client_lock:
            if _client is None:
                _client = Client(HttpConfig())
    return _client


def get(url, **kw):
    return client().request("GET", url, **kw)


def head(url, **kw):
    return client().request("HEAD", url, **kw)


def post(url, **kw):
    return client().request("POST", url, **kw)


def request(method, url, **kw):
    return client().request(method, url, **kw)


_TOOL_PROXY = {
    "curl": lambda p: ["-x", p],
    "nuclei": lambda p: ["-proxy", p],
    "ffuf": lambda p: ["-x", p],
    "sqlmap": lambda p: [f"--proxy={p}"],
    "shcheck": lambda p: ["--proxy", p],
}


def tool_proxy_args(tool: str) -> list[str]:
    """Return the proxy CLI args for an external tool, or [] when no proxy."""
    proxy = client().cfg.proxy
    if not proxy:
        return []
    fn = _TOOL_PROXY.get(tool)
    return fn(proxy) if fn else []


# --- compat namespace: a stand-in for the `requests` module -------------------

def _compat_request(method, url, **kw):
    return client().request(method, url, **kw)


compat = SimpleNamespace(
    get=lambda url, **kw: client().request("GET", url, **kw),
    head=lambda url, **kw: client().request("HEAD", url, **kw),
    post=lambda url, **kw: client().request("POST", url, **kw),
    request=_compat_request,
    RequestException=requests.RequestException,
    ConnectionError=requests.ConnectionError,
    Timeout=requests.Timeout,
    HTTPError=requests.HTTPError,
    OutOfScope=OutOfScope,
)
