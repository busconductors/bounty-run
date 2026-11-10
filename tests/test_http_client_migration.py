"""C13: migrated modules use the shared client / proxy forwarding."""
from unittest import mock

from runner import http_headers, httpclient


class TestShcheckProxy:
    def teardown_method(self):
        httpclient.configure(httpclient.HttpConfig())

    def _run_scan(self, tmp_path):
        fake_shcheck = tmp_path / "shcheck.py"
        fake_shcheck.write_text("# stub")
        captured = {}
        with mock.patch.object(http_headers, "SHCHECK", fake_shcheck), \
             mock.patch.object(http_headers.utils, "log"), \
             mock.patch.object(http_headers.utils, "warn"), \
             mock.patch.object(http_headers.utils, "run",
                               side_effect=lambda cmd, **kw: captured.setdefault("cmd", cmd) or "{}"), \
             mock.patch.object(http_headers, "_live_hosts", return_value=["example.com"]):
            http_headers.security_headers_scan("example.com", tmp_path)
        return captured["cmd"]

    def test_proxy_forwarded_to_shcheck(self, tmp_path):
        httpclient.configure(httpclient.HttpConfig(proxy="http://127.0.0.1:8080"))
        assert "--proxy http://127.0.0.1:8080" in self._run_scan(tmp_path)

    def test_no_proxy_no_flag(self, tmp_path):
        httpclient.configure(httpclient.HttpConfig())
        assert "--proxy" not in self._run_scan(tmp_path)
