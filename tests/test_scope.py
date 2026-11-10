"""C8: allow/deny scope rules."""
import re

import pytest

from runner import scope


class TestDefault:
    def test_target_and_subdomains(self):
        s = scope.default("example.com")
        assert s.host_allowed("example.com")
        assert s.host_allowed("a.example.com")
        assert s.host_allowed("a.b.example.com")

    def test_rejects_other(self):
        s = scope.default("example.com")
        assert not s.host_allowed("evil.com")
        assert not s.host_allowed("notexample.com")

    def test_empty_host(self):
        assert not scope.default("example.com").host_allowed("")
        assert not scope.default("example.com").host_allowed(None)


class TestWildcard:
    def test_wildcard_matches_subdomains_not_apex(self):
        s = scope.from_args("x", allow=["*.ex.com"])
        assert s.host_allowed("a.ex.com")
        assert s.host_allowed("a.b.ex.com")
        assert not s.host_allowed("ex.com")  # apex needs an explicit rule


class TestRegex:
    def test_regex_fullmatch_on_host(self):
        s = scope.from_args("x", allow=["re:.*\\.ex\\.com"])
        assert s.host_allowed("a.ex.com")
        assert not s.host_allowed("a.ex.com.evil.com")  # fullmatch, not search

    def test_regex_on_url_when_slash_present(self):
        s = scope.from_args("x", allow=["re:https://ex\\.com/api/.*"])
        assert s.url_allowed("https://ex.com/api/v1")
        assert not s.url_allowed("https://ex.com/other")

    def test_bad_regex_raises(self):
        with pytest.raises(re.error):
            scope.from_args("x", allow=["re:("])


class TestCidr:
    def test_cidr_matches_ip_hosts(self):
        s = scope.from_args("x", allow=["10.0.0.0/8"])
        assert s.host_allowed("10.1.2.3")
        assert not s.host_allowed("11.0.0.1")

    def test_cidr_ignores_non_ip(self):
        s = scope.from_args("x", allow=["10.0.0.0/8"])
        assert not s.host_allowed("example.com")


class TestExact:
    def test_exact_host(self):
        s = scope.from_args("x", allow=["api.ex.com"])
        assert s.host_allowed("api.ex.com")
        assert not s.host_allowed("other.ex.com")


class TestDeny:
    def test_deny_wins_over_allow(self):
        s = scope.from_args("x", allow=["*.ex.com"], deny=["secret.ex.com"])
        assert s.host_allowed("a.ex.com")
        assert not s.host_allowed("secret.ex.com")

    def test_deny_over_default(self):
        s = scope.from_args("ex.com", deny=["admin.ex.com"])
        assert s.host_allowed("a.ex.com")
        assert not s.host_allowed("admin.ex.com")


class TestUrlAllowed:
    def test_http_https_only(self):
        s = scope.default("ex.com")
        assert s.url_allowed("https://ex.com/x")
        assert s.url_allowed("http://a.ex.com/x")
        assert not s.url_allowed("ftp://ex.com/x")
        assert not s.url_allowed("file:///etc/passwd")

    def test_off_scope_host(self):
        assert not scope.default("ex.com").url_allowed("https://evil.com/x")


class TestWithHosts:
    def test_with_hosts_admits_origin_ips(self):
        s = scope.default("ex.com").with_hosts(["203.0.113.9"])
        assert s.host_allowed("203.0.113.9")
        assert s.url_allowed("https://203.0.113.9/x")

    def test_original_unchanged(self):
        base = scope.default("ex.com")
        base.with_hosts(["203.0.113.9"])
        assert not base.host_allowed("203.0.113.9")


class TestScopeFile:
    def test_bang_prefix_is_deny(self, tmp_path):
        p = tmp_path / "scope.txt"
        p.write_text("*.ex.com\n# comment\n!secret.ex.com\n")
        s = scope.from_args("x", scope_file=str(p))
        assert s.host_allowed("a.ex.com")
        assert not s.host_allowed("secret.ex.com")


class TestActive:
    def test_set_get_reset(self):
        scope.reset()
        assert scope.active().target == ""
        scope.set_active(scope.default("ex.com"))
        assert scope.active().target == "ex.com"
        scope.reset()
        assert scope.active().target == ""


class TestLegacyParity:
    """Default scope must match the old suffix rule used by _in_scope."""

    def _legacy(self, url, target):
        from urllib.parse import urlsplit
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            return False
        host = (parts.hostname or "").lower()
        target = target.lower()
        return host == target or host.endswith("." + target)

    def test_parity_table(self):
        target = "example.com"
        urls = [
            "http://example.com/x",
            "https://sub.example.com/y?a=1",
            "http://evil.com/x",
            "ftp://example.com/x",
            "http://notexample.com/x",
            "https://a.b.example.com/",
        ]
        s = scope.default(target)
        for u in urls:
            assert s.url_allowed(u) == self._legacy(u, target), u
