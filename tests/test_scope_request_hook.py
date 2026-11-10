"""C15: scope enforced on every HTTP request hop via the request hook."""
import io
from unittest import mock

import pytest
import requests
from requests.adapters import HTTPAdapter
from urllib3.response import HTTPResponse

from runner import httpclient, scope
from runner.httpclient import Client, HttpConfig, OutOfScope


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


class TestRequestHook:
    def setup_method(self):
        scope.reset()
        scope.set_active(scope.from_args("example.com"))

    def teardown_method(self):
        scope.reset()
        httpclient.configure(HttpConfig())

    def test_off_scope_request_blocked(self):
        c = Client(HttpConfig())
        c.add_request_hook(scope.request_hook)
        adapter = _mount(c, lambda r: _make_response(r))
        with pytest.raises(OutOfScope):
            c.get("https://evil.com/x")
        assert adapter.sent == []
        c.close()

    def test_in_scope_request_allowed(self):
        c = Client(HttpConfig())
        c.add_request_hook(scope.request_hook)
        _mount(c, lambda r: _make_response(r))
        resp = c.get("https://example.com/x")
        assert resp.status_code == 200
        c.close()

    def test_scope_exempt_bypasses(self):
        c = Client(HttpConfig())
        c.add_request_hook(scope.request_hook)
        _mount(c, lambda r: _make_response(r))
        resp = c.get("https://evil.com/x", scope_exempt=True, purpose="osint")
        assert resp.status_code == 200
        c.close()

    def test_redirect_to_off_scope_host_blocked(self):
        c = Client(HttpConfig())
        c.add_request_hook(scope.request_hook)

        def responder(request):
            if request.url == "https://example.com/":
                return _make_response(request, status=302,
                                      headers={"Location": "https://evil.com/"})
            return _make_response(request, status=200)
        _mount(c, responder)
        with pytest.raises(OutOfScope):
            c.get("https://example.com/", allow_redirects=True)
        c.close()

    def test_secret_fetch_returns_empty_on_block(self):
        # secret_scan._fetch swallows request errors (incl. OutOfScope) -> "".
        from runner import secret_scan
        httpclient.configure(HttpConfig())
        httpclient.client().add_request_hook(scope.request_hook)
        _mount(httpclient.client(), lambda r: _make_response(r))
        assert secret_scan._fetch("https://evil.com/.env") == ""
