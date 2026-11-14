"""C12: HTTP flags wired into httpclient.configure + credential redaction."""
import json
from unittest import mock

from runner import cli, httpclient


class TestRedactFlags:
    def test_proxy_credentials_stripped(self):
        out = cli._redact_flags({"proxy": "http://user:pass@127.0.0.1:8080"})
        assert out["proxy"] == "http://127.0.0.1:8080"

    def test_proxy_without_creds_unchanged(self):
        out = cli._redact_flags({"proxy": "http://127.0.0.1:8080"})
        assert out["proxy"] == "http://127.0.0.1:8080"

    def test_auth_and_cookie_headers_masked(self):
        out = cli._redact_flags({"header": ["Authorization: Bearer secret",
                                            "Cookie: session=abc",
                                            "X-Trace: 1"]})
        assert out["header"] == ["Authorization: ***", "Cookie: ***", "X-Trace: 1"]

    def test_none_proxy_ok(self):
        assert cli._redact_flags({"proxy": None})["proxy"] is None


class TestFlagsParse:
    def test_http_flags(self):
        args = cli.build_parser().parse_args([
            "example.com", "--proxy", "http://p:1", "--user-agent", "UA",
            "--header", "X-A: 1", "--rate-limit", "5", "--retries", "2", "--verify-tls"])
        assert args.proxy == "http://p:1"
        assert args.user_agent == "UA"
        assert args.header == ["X-A: 1"]
        assert args.rate_limit == 5.0
        assert args.retries == 2
        assert args.verify_tls is True

    def test_retries_rejects_negative(self):
        import pytest
        with pytest.raises(SystemExit):
            cli.build_parser().parse_args(["example.com", "--retries", "-1"])


class TestRunJsonRedaction:
    def test_proxy_creds_absent_from_run_json(self, tmp_path):
        events_path = tmp_path / "events.jsonl"
        # The proxy preflight (fail-closed on a dead proxy) is stubbed: this
        # test is about redaction, and nothing listens on 127.0.0.1:8080.
        with mock.patch.object(cli, "_run", return_value=0), \
             mock.patch.object(cli, "_resolve_outdir", return_value=tmp_path), \
             mock.patch.object(cli.proxy, "preflight", return_value=None), \
             mock.patch.object(cli.banner, "print_banner"):
            cli.main(["example.com", "--no-banner", "--events", str(events_path),
                      "--proxy", "http://user:pass@127.0.0.1:8080"])
        run_json = json.loads((tmp_path / "run.json").read_text())
        assert "user:pass" not in json.dumps(run_json)
        assert run_json["flags"]["proxy"] == "http://127.0.0.1:8080"


class TestConfigureCalled:
    def test_configure_runs_without_network(self, tmp_path):
        with mock.patch.object(cli, "_run", return_value=0), \
             mock.patch.object(cli, "_resolve_outdir", return_value=tmp_path), \
             mock.patch.object(cli.banner, "print_banner"), \
             mock.patch.object(httpclient, "configure", wraps=httpclient.configure) as conf:
            rc = cli.main(["example.com", "--no-banner", "--user-agent", "ZZ"])
        assert rc == 0
        assert conf.called
        assert conf.call_args[0][0].user_agent == "ZZ"
