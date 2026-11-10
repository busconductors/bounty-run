"""C18: capture in-process exchanges for CORS and secret findings."""
import io

from requests.adapters import HTTPAdapter
from urllib3.response import HTTPResponse

from runner import evidence, http_headers, httpclient
from runner.evidence import EvidenceStore
from runner.httpclient import HttpConfig


def _make_response(request, status=200, headers=None, body=b"ok"):
    raw = HTTPResponse(body=io.BytesIO(body), status=status,
                       headers=headers or {}, preload_content=False)
    return HTTPAdapter().build_response(request, raw)


class _FakeAdapter(HTTPAdapter):
    def __init__(self, responder):
        super().__init__()
        self.responder = responder

    def send(self, request, **kw):
        return self.responder(request)


def _mount(client, responder):
    adapter = _FakeAdapter(responder)
    for sess in client._sessions.values():
        sess.mount("http://", adapter)
        sess.mount("https://", adapter)


class TestCorsCapture:
    def teardown_method(self):
        evidence.reset()
        httpclient.configure(HttpConfig())

    def test_cors_finding_records_origin_header(self, tmp_path):
        httpclient.configure(HttpConfig())
        httpclient.client().add_response_hook(evidence.response_hook)
        store = EvidenceStore(tmp_path)
        evidence.activate(store)

        def responder(request):
            origin = request.headers.get("Origin", "")
            return _make_response(request, headers={
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            })
        _mount(httpclient.client(), responder)

        findings, _ = http_headers._probe_cors("https://example.com/", "example.com")
        assert findings
        store.flush()
        reqs = list((tmp_path / "evidence").glob("*/*/request.http"))
        assert reqs
        assert any("Origin:" in p.read_text() for p in reqs)


class TestStreamedProbe:
    def test_streamed_response_stores_headers_only(self, tmp_path):
        store = EvidenceStore(tmp_path)

        class _Req:
            url = "https://example.com/"
            method = "GET"
            headers = {"User-Agent": "UA"}
            body = None

        class _StreamResp:
            status_code = 200
            headers = {"Server": "nginx"}
            url = "https://example.com/"
            request = _Req()
            closed = True

            @property
            def content(self):
                raise RuntimeError("streamed body not read")

        finding = {"template": "", "host": "example.com", "url": "https://example.com/"}
        eid = store.record(_Req(), _StreamResp(), finding=finding)
        assert eid is not None
        resp_dir = next((tmp_path / "evidence").glob("*/1"))
        text = (resp_dir / "response.http").read_text()
        assert "Server: nginx" in text
