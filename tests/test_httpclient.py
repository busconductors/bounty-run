"""C11: shared HTTP client — session, retries, proxy, UA, rate limit, hooks."""
import io
import threading

import pytest
import requests
from requests.adapters import HTTPAdapter
from urllib3.response import HTTPResponse

from runner import httpclient
from runner.httpclient import Client, HttpConfig, HostRateLimiter, OutOfScope


def _make_response(request, status=200, headers=None, body=b"ok"):
    raw = HTTPResponse(body=io.BytesIO(body), status=status,
                       headers=headers or {}, preload_content=False)
    return HTTPAdapter().build_response(request, raw)


class FakeAdapter(HTTPAdapter):
    def __init__(self, responder):
        super().__init__()
        self.responder = responder
        self.sent = []

    def send(self, request, **kw):
        self.sent.append(request)
        return self.responder(request)


def _mount(client, responder):
    adapter = FakeAdapter(responder)
    for sess in client._sessions.values():
        sess.mount("http://", adapter)
        sess.mount("https://", adapter)
    return adapter


class TestHeaders:
    def test_user_agent_and_extra_headers(self):
        c = Client(HttpConfig(user_agent="UA/1", extra_headers={"X-Test": "1"}))
        seen = {}

        def hook(prep, ctx):
            seen.update(prep.headers)
        c.add_request_hook(hook)
        _mount(c, lambda r: _make_response(r))
        c.get("http://example.com/")
        assert seen.get("User-Agent") == "UA/1"
        assert seen.get("X-Test") == "1"
        c.close()


class TestProxy:
    def test_proxy_applied(self):
        c = Client(HttpConfig(proxy="http://127.0.0.1:8080"))
        assert c._sessions[0].proxies["http"] == "http://127.0.0.1:8080"
        assert c._sessions[0].proxies["https"] == "http://127.0.0.1:8080"
        c.close()


class TestRetry:
    def test_retry_config(self):
        c = Client(HttpConfig(retries=3, backoff=0.5))
        adapter = c._sessions[3].get_adapter("https://x/")
        retry = adapter.max_retries
        assert retry.total == 3 and retry.connect == 3 and retry.read == 3
        assert retry.backoff_factor == 0.5
        assert retry.status_forcelist == (429, 502, 503, 504)
        assert retry.raise_on_status is False
        c.close()

    def test_default_retries_zero(self):
        c = Client(HttpConfig())
        assert c._sessions[0].get_adapter("https://x/").max_retries.total == 0
        c.close()


class TestHooks:
    def test_raising_pre_hook_blocks_send(self):
        c = Client(HttpConfig())
        adapter = _mount(c, lambda r: _make_response(r))

        def block(prep, ctx):
            raise OutOfScope("nope")
        c.add_request_hook(block)
        with pytest.raises(OutOfScope):
            c.get("http://example.com/")
        assert adapter.sent == []   # never reached the adapter
        c.close()

    def test_scope_exempt_passed_in_ctx(self):
        c = Client(HttpConfig())
        ctxs = []
        c.add_request_hook(lambda prep, ctx: ctxs.append(dict(ctx)))
        _mount(c, lambda r: _make_response(r))
        c.get("http://example.com/", scope_exempt=True, purpose="osint")
        assert ctxs[0]["scope_exempt"] is True
        assert ctxs[0]["purpose"] == "osint"
        c.close()

    def test_response_hook_runs(self):
        c = Client(HttpConfig())
        got = []
        c.add_response_hook(lambda resp, ctx: got.append(resp.status_code))
        _mount(c, lambda r: _make_response(r, status=201))
        c.get("http://example.com/")
        assert got == [201]
        c.close()

    def test_request_hook_runs_per_redirect_hop(self):
        c = Client(HttpConfig())
        seen = []
        c.add_request_hook(lambda prep, ctx: seen.append(prep.url))

        def responder(request):
            if request.url == "http://example.com/":
                return _make_response(request, status=302,
                                      headers={"Location": "http://example.com/next"})
            return _make_response(request, status=200)
        _mount(c, responder)
        c.get("http://example.com/", allow_redirects=True)
        assert "http://example.com/" in seen
        assert "http://example.com/next" in seen
        c.close()


class TestOutOfScope:
    def test_is_request_exception(self):
        assert issubclass(OutOfScope, requests.RequestException)


class TestRateLimiter:
    def test_injected_clock_spaces_requests(self):
        slept = []
        t = [0.0]
        lim = HostRateLimiter(rate=2.0, clock=lambda: t[0], sleep=slept.append)
        lim.acquire("h")   # first: no wait
        lim.acquire("h")   # second: must wait ~0.5s
        assert slept and abs(slept[0] - 0.5) < 1e-6

    def test_none_rate_never_sleeps(self):
        slept = []
        lim = HostRateLimiter(rate=None, sleep=slept.append)
        for _ in range(5):
            lim.acquire("h")
        assert slept == []


class TestThreadSafety:
    def test_eight_threads(self):
        c = Client(HttpConfig())
        _mount(c, lambda r: _make_response(r))
        errors = []

        def work():
            try:
                for _ in range(5):
                    c.get("http://example.com/")
            except Exception as e:  # pragma: no cover
                errors.append(e)
        threads = [threading.Thread(target=work) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
        c.close()


class TestFromArgs:
    def test_from_args(self):
        import argparse
        args = argparse.Namespace(
            proxy="http://p:1", user_agent="Z", verify_tls=True, retries=2,
            rate_limit=5.0, threads=50, header=["X-A: 1", "Authorization: Bearer x"])
        cfg = HttpConfig.from_args(args)
        assert cfg.proxy == "http://p:1"
        assert cfg.user_agent == "Z"
        assert cfg.verify is True
        assert cfg.retries == 2
        assert cfg.rate_per_host == 5.0
        assert cfg.pool_maxsize == 50
        assert cfg.extra_headers == {"X-A": "1", "Authorization": "Bearer x"}


class TestToolProxyArgs:
    def test_proxy_args_present_only_when_configured(self):
        httpclient.configure(HttpConfig(proxy="http://p:1"))
        assert httpclient.tool_proxy_args("curl") == ["-x", "http://p:1"]
        assert httpclient.tool_proxy_args("nuclei") == ["-proxy", "http://p:1"]
        assert httpclient.tool_proxy_args("sqlmap") == ["--proxy=http://p:1"]
        httpclient.configure(HttpConfig())
        assert httpclient.tool_proxy_args("curl") == []
