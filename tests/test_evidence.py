"""C16: evidence store, curl builder, redaction."""
import json
import os
import shlex
import stat
import threading

from runner import evidence, finding
from runner.evidence import EvidenceStore, build_curl, redact_headers


class _Req:
    def __init__(self, url="https://example.com/x", method="GET", headers=None, body=None):
        self.url = url
        self.method = method
        self.headers = headers or {"User-Agent": "UA", "Authorization": "Bearer secret"}
        self.body = body


class _Resp:
    def __init__(self, status=200, headers=None, body=b"<html>ok</html>", url=None, request=None):
        self.status_code = status
        self.headers = headers or {"Content-Type": "text/html"}
        self._content = body
        self.url = url or (request.url if request else "https://example.com/x")
        self.request = request or _Req()

    @property
    def content(self):
        return self._content


FINDING = {"severity": "high", "template": "cors-misconfiguration:reflected",
           "name": "CORS", "url": "https://example.com/x", "host": "example.com"}


class TestBuildCurl:
    def test_shlex_round_trip(self):
        headers = {"User-Agent": "a b", "X-Weird": "v$(whoami)'q\"z"}
        curl = build_curl("POST", "https://x.com/a b?q=1",
                          headers, b"line1\nline2", redact=False)
        argv = shlex.split(curl)
        assert argv[0] == "curl"
        assert "https://x.com/a b?q=1" in argv
        assert "-X" in argv and "POST" in argv
        assert "--data-raw" in argv

    def test_binary_body_uses_data_binary(self):
        curl = build_curl("POST", "https://x/", {}, b"\x00\x01\x02")
        assert "--data-binary" in shlex.split(curl)

    def test_compressed_only_when_accept_encoding(self):
        with_ae = build_curl("GET", "https://x/", {"Accept-Encoding": "gzip"}, None)
        without = build_curl("GET", "https://x/", {}, None)
        assert "--compressed" in shlex.split(with_ae)
        assert "--compressed" not in shlex.split(without)


class TestRedactHeaders:
    def test_redacts_sensitive(self):
        out = dict(redact_headers({"Authorization": "x", "Cookie": "y", "X-Ok": "z"}))
        assert out["Authorization"] == "<redacted>"
        assert out["Cookie"] == "<redacted>"
        assert out["X-Ok"] == "z"

    def test_no_redact_when_off(self):
        out = dict(redact_headers({"Authorization": "secret"}, redact=False))
        assert out["Authorization"] == "secret"


class TestRecord:
    def test_layout_and_index(self, tmp_path):
        store = EvidenceStore(tmp_path)
        eid = store.record(_Req(), _Resp(), finding=FINDING)
        fp = finding.fingerprint_of(FINDING["template"], FINDING["host"], FINDING["url"])
        assert eid == f"{fp}-1"
        d = tmp_path / "evidence" / fp / "1"
        assert (d / "request.http").exists()
        assert (d / "response.http").exists()
        assert (d / "meta.json").exists()
        assert (d / "repro.sh").exists()
        store.flush()
        idx = json.loads((tmp_path / "evidence" / "index.json").read_text())
        assert idx[fp] == [eid]

    def test_auth_header_redacted_in_request(self, tmp_path):
        store = EvidenceStore(tmp_path)
        store.record(_Req(), _Resp(), finding=FINDING)
        fp = finding.fingerprint_of(FINDING["template"], FINDING["host"], FINDING["url"])
        req = (tmp_path / "evidence" / fp / "1" / "request.http").read_text()
        assert "Bearer secret" not in req
        assert "<redacted>" in req

    def test_unredacted_opt_in(self, tmp_path):
        store = EvidenceStore(tmp_path, redact=False)
        store.record(_Req(), _Resp(), finding=FINDING)
        fp = finding.fingerprint_of(FINDING["template"], FINDING["host"], FINDING["url"])
        req = (tmp_path / "evidence" / fp / "1" / "request.http").read_text()
        assert "Bearer secret" in req

    def test_truncation(self, tmp_path):
        store = EvidenceStore(tmp_path, max_body=10)
        big = b"A" * 100
        store.record(_Req(), _Resp(body=big), finding=FINDING)
        fp = finding.fingerprint_of(FINDING["template"], FINDING["host"], FINDING["url"])
        meta = json.loads((tmp_path / "evidence" / fp / "1" / "meta.json").read_text())
        assert meta["truncated"] is True

    def test_binary_body_to_bin_with_sha256(self, tmp_path):
        store = EvidenceStore(tmp_path)
        store.record(_Req(), _Resp(headers={"Content-Type": "application/octet-stream"},
                                   body=b"\x00\x01binary"), finding=FINDING)
        fp = finding.fingerprint_of(FINDING["template"], FINDING["host"], FINDING["url"])
        d = tmp_path / "evidence" / fp / "1"
        meta = json.loads((d / "meta.json").read_text())
        assert meta["binary"] is True
        assert meta["sha256_body"]
        assert (d / "response.body.bin").exists()

    def test_repro_is_executable(self, tmp_path):
        store = EvidenceStore(tmp_path)
        store.record(_Req(), _Resp(), finding=FINDING)
        fp = finding.fingerprint_of(FINDING["template"], FINDING["host"], FINDING["url"])
        repro = tmp_path / "evidence" / fp / "1" / "repro.sh"
        mode = stat.S_IMODE(os.stat(repro).st_mode)
        assert mode == 0o700

    def test_eight_threads_unique_ids(self, tmp_path):
        store = EvidenceStore(tmp_path)
        ids = []
        lock = threading.Lock()

        def work():
            eid = store.record(_Req(), _Resp(), finding=FINDING)
            with lock:
                ids.append(eid)
        threads = [threading.Thread(target=work) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(set(ids)) == 8


class TestAttach:
    def teardown_method(self):
        evidence.reset()

    def test_attach_noop_without_store(self):
        evidence.reset()
        assert evidence.attach(FINDING) is None

    def test_attach_never_mutates(self, tmp_path):
        store = EvidenceStore(tmp_path)
        evidence.activate(store)
        before = dict(FINDING)
        evidence.response_hook(_Resp(request=_Req()), {})
        evidence.attach(FINDING)
        assert FINDING == before

    def test_response_hook_then_attach(self, tmp_path):
        store = EvidenceStore(tmp_path)
        evidence.activate(store)
        evidence.response_hook(_Resp(request=_Req(url="https://example.com/x")), {})
        eid = evidence.attach(FINDING, "https://example.com/x")
        assert eid is not None
