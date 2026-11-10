"""C9: scope flags in CLI + _in_scope alias parity."""
from runner import cli, dork_scan, param_scan, scope


def _legacy_in_scope(url, target):
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return False
    host = (parts.hostname or "").lower().rstrip(".")
    target = target.lower().rstrip(".")
    return host == target or host.endswith("." + target)


class TestAliasParity:
    def setup_method(self):
        scope.reset()

    def teardown_method(self):
        scope.reset()

    def test_dork_and_param_match_legacy(self):
        target = "example.com"
        urls = [
            "https://example.com/x",
            "https://a.example.com/",
            "http://evil.com/x",
            "https://example.com.attacker.net/",
            "ftp://example.com/x",
        ]
        for u in urls:
            assert dork_scan._in_scope(u, target) == _legacy_in_scope(u, target), u
            assert param_scan._in_scope(u, target) == _legacy_in_scope(u, target), u

    def test_active_scope_allow_deny_applies(self):
        scope.set_active(scope.from_args("example.com", deny=["blocked.example.com"]))
        assert param_scan._in_scope("https://ok.example.com/x", "example.com")
        assert not param_scan._in_scope("https://blocked.example.com/x", "example.com")


class TestScopeFlags:
    def test_flags_parse(self):
        args = cli.build_parser().parse_args(
            ["example.com", "--scope-allow", "*.ex.com",
             "--scope-deny", "secret.ex.com"])
        assert args.scope_allow == ["*.ex.com"]
        assert args.scope_deny == ["secret.ex.com"]

    def test_target_denied_exits_2(self):
        rc = cli.main(["example.com", "--scope-deny", "example.com", "--no-banner"])
        assert rc == 2

    def test_bad_regex_exits_2(self):
        rc = cli.main(["example.com", "--scope-allow", "re:(", "--no-banner"])
        assert rc == 2
