"""C10: scope enforcement at subs, katana, nuclei hosts and the finding guard."""
from unittest import mock

from runner import api_endpoints, scope, stages


class TestSubsFilter:
    def setup_method(self):
        scope.reset()

    def teardown_method(self):
        scope.reset()

    def test_subs_filtered_by_active_scope(self, tmp_path):
        scope.set_active(scope.from_args("example.com", deny=["bad.example.com"]))
        with mock.patch.object(stages.utils, "have", side_effect=lambda t: t == "subfinder"), \
             mock.patch.object(stages.utils, "run",
                               return_value="example.com\nok.example.com\nbad.example.com\n"), \
             mock.patch.object(stages.utils, "log"):
            subs = stages.subdomain_enum("example.com", tmp_path)
        assert "ok.example.com" in subs
        assert "bad.example.com" not in subs

    def test_default_scope_keeps_target_subs(self, tmp_path):
        with mock.patch.object(stages.utils, "have", side_effect=lambda t: t == "subfinder"), \
             mock.patch.object(stages.utils, "run",
                               return_value="example.com\na.example.com\n"), \
             mock.patch.object(stages.utils, "log"):
            subs = stages.subdomain_enum("example.com", tmp_path)
        assert subs == ["a.example.com", "example.com"]


class TestKatanaFilter:
    def setup_method(self):
        scope.reset()

    def teardown_method(self):
        scope.reset()

    def test_off_scope_katana_urls_dropped(self, tmp_path):
        urls = [
            "https://example.com/api/v1?x=1",
            "https://evil.com/api/v1?x=1",   # off scope
        ]
        with mock.patch.object(api_endpoints.utils, "have", return_value=True), \
             mock.patch.object(api_endpoints.utils, "log"), \
             mock.patch.object(api_endpoints, "_live_hosts", return_value=["example.com"]), \
             mock.patch.object(api_endpoints, "_crawl", return_value=urls), \
             mock.patch.object(api_endpoints, "_is_api_url", return_value=True):
            findings = api_endpoints.api_endpoints_scan("example.com", tmp_path)
        hosts = {f["host"] for f in findings}
        assert "example.com" in hosts
        assert "evil.com" not in hosts
