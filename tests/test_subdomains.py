"""Phase 1-2 subdomain discovery: _norm, cache, resolvers, dnsx resolution.

All tests mock ``utils.run`` / ``utils.have`` on the shared module object and
touch no network. They are additive to the legacy exact-match tests in
``test_scope_enforcement.py``.
"""
import json
from unittest import mock

import pytest

from runner import scope, stages, subdomains


@pytest.fixture(autouse=True)
def _reset_scope():
    scope.reset()
    yield
    scope.reset()


# --------------------------------------------------------------------------- #
# _norm
# --------------------------------------------------------------------------- #
class TestNorm:
    def test_wildcard_prefix_stripped(self):
        assert subdomains._norm("*.a.example.com", "example.com") == "a.example.com"

    def test_trailing_dot_stripped(self):
        assert subdomains._norm("a.example.com.", "example.com") == "a.example.com"

    def test_uppercase_lowered(self):
        assert subdomains._norm("A.Example.COM", "example.com") == "a.example.com"

    def test_apex_kept(self):
        assert subdomains._norm("example.com", "example.com") == "example.com"

    def test_off_target_rejected(self):
        assert subdomains._norm("evil.com", "example.com") is None
        assert subdomains._norm("notexample.com", "example.com") is None

    def test_decoration_rejected(self):
        assert subdomains._norm("[INF] scanning", "example.com") is None
        assert subdomains._norm("# comment", "example.com") is None
        assert subdomains._norm("", "example.com") is None


# --------------------------------------------------------------------------- #
# cache
# --------------------------------------------------------------------------- #
class TestCache:
    def test_cache_none_writes_nothing(self, tmp_path):
        subdomains.cache_save(None, "example.com", {"a.example.com"})
        assert list(tmp_path.iterdir()) == []

    def test_union_and_first_seen_preserved(self, tmp_path):
        subdomains.cache_save(tmp_path, "example.com", {"a.example.com"})
        loaded = json.loads((tmp_path / "example.com.json").read_text())
        first = loaded["a.example.com"]["first_seen"]

        # A later run adds a new name; the original first_seen must survive.
        subdomains.cache_save(tmp_path, "example.com", {"b.example.com"})
        names = subdomains.cache_load(tmp_path, "example.com")
        assert names == {"a.example.com", "b.example.com"}

        loaded2 = json.loads((tmp_path / "example.com.json").read_text())
        assert loaded2["a.example.com"]["first_seen"] == first

    def test_cache_feeds_union_in_subdomain_enum(self, tmp_path):
        subdomains.cache_save(tmp_path, "example.com", {"cached.example.com"})
        with mock.patch.object(stages.utils, "have", side_effect=lambda t: t == "subfinder"), \
             mock.patch.object(stages.utils, "run", return_value="fresh.example.com\n"), \
             mock.patch.object(stages.utils, "log"), \
             mock.patch.object(stages.utils, "warn"):
            subs = stages.subdomain_enum("example.com", tmp_path, cache_dir=tmp_path)
        assert "cached.example.com" in subs
        assert "fresh.example.com" in subs

    def test_corrupt_cache_tolerated(self, tmp_path):
        (tmp_path / "example.com.json").write_text("{not json")
        assert subdomains.cache_load(tmp_path, "example.com") == set()


# --------------------------------------------------------------------------- #
# intensity gate — active off means no dnsx/resolver work
# --------------------------------------------------------------------------- #
class TestIntensityGate:
    def test_passive_never_calls_dnsx(self, tmp_path):
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            return "a.example.com\n"

        # have() reports dnsx present, but active=False must keep it unused.
        with mock.patch.object(stages.utils, "have", side_effect=lambda t: t in ("subfinder", "dnsx")), \
             mock.patch.object(stages.utils, "run", side_effect=fake_run), \
             mock.patch.object(stages.utils, "log"), \
             mock.patch.object(stages.utils, "warn"):
            stages.subdomain_enum("example.com", tmp_path, active=False)
        assert not any(c.startswith("dnsx ") for c in calls)

    def test_active_calls_dnsx(self, tmp_path):
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            if "dnsx" in cmd:
                return ""
            return "a.example.com\n"

        with mock.patch.object(stages.utils, "have", side_effect=lambda t: t in ("subfinder", "dnsx")), \
             mock.patch.object(stages.utils, "run", side_effect=fake_run), \
             mock.patch.object(stages.utils, "log"), \
             mock.patch.object(stages.utils, "warn"), \
             mock.patch.object(subdomains, "resolvers_file", return_value=None):
            stages.subdomain_enum("example.com", tmp_path, active=True)
        assert any(c.startswith("dnsx -l") for c in calls)


# --------------------------------------------------------------------------- #
# dnsx JSON parsing / bucketing
# --------------------------------------------------------------------------- #
class TestResolve:
    def _fake_run(self, resolved_recs, dangling_recs):
        def run(cmd, **kw):
            if "-rc nxdomain" in cmd:
                return "\n".join(json.dumps(r) for r in dangling_recs)
            if cmd.startswith("dnsx -l"):
                return "\n".join(json.dumps(r) for r in resolved_recs)
            return ""
        return run

    def test_rfc1918_goes_internal_not_resolved(self, tmp_path):
        resolved = [
            {"host": "ok.example.com", "a": ["93.184.216.34"]},
            {"host": "int.example.com", "a": ["10.0.0.5"]},
        ]
        with mock.patch.object(subdomains.utils, "have", return_value=True), \
             mock.patch.object(subdomains.utils, "run", side_effect=self._fake_run(resolved, [])), \
             mock.patch.object(subdomains.utils, "log"), \
             mock.patch.object(subdomains.utils, "warn"):
            rr = subdomains.resolve(["ok.example.com", "int.example.com"],
                                    tmp_path, "example.com", None)
        assert "ok.example.com" in rr.resolved
        assert "int.example.com" in rr.internal
        assert "int.example.com" not in rr.resolved
        assert "int.example.com" in (tmp_path / "subs_internal.txt").read_text()

    def test_cname_nxdomain_is_dangling(self, tmp_path):
        dangling = [{"host": "gone.example.com", "cname": ["x.s3.amazonaws.com"]}]
        with mock.patch.object(subdomains.utils, "have", return_value=True), \
             mock.patch.object(subdomains.utils, "run", side_effect=self._fake_run([], dangling)), \
             mock.patch.object(subdomains.utils, "log"), \
             mock.patch.object(subdomains.utils, "warn"):
            rr = subdomains.resolve(["gone.example.com"], tmp_path, "example.com", None)
        assert "gone.example.com" in rr.dangling
        assert "gone.example.com" in (tmp_path / "subs_dangling.txt").read_text()

    def test_no_dnsx_is_noop(self, tmp_path):
        with mock.patch.object(subdomains.utils, "have", return_value=False), \
             mock.patch.object(subdomains.utils, "run") as run:
            rr = subdomains.resolve(["a.example.com"], tmp_path, "example.com", None)
        run.assert_not_called()
        assert rr.resolved == set() and rr.internal == set() and rr.dangling == set()


# --------------------------------------------------------------------------- #
# shell-quoting of the target
# --------------------------------------------------------------------------- #
class TestQuoting:
    def test_target_with_semicolon_is_quoted(self, tmp_path):
        calls = []
        with mock.patch.object(subdomains.utils, "have", return_value=True), \
             mock.patch.object(subdomains.utils, "run", side_effect=lambda cmd, **kw: calls.append(cmd) or ""), \
             mock.patch.object(subdomains.utils, "log"), \
             mock.patch.object(subdomains.utils, "warn"):
            subdomains.passive_subfinder("evil.com;id", tmp_path)
        assert calls, "subfinder should have been invoked"
        assert "'evil.com;id'" in calls[0]
        assert "-d evil.com;id" not in calls[0]


# --------------------------------------------------------------------------- #
# scope enforcement on resolution buckets
# --------------------------------------------------------------------------- #
class TestResolveScope:
    def test_internal_bucket_respects_deny(self, tmp_path):
        scope.set_active(scope.from_args("example.com", deny=["bad.example.com"]))
        resolved = [
            {"host": "ok.example.com", "a": ["10.0.0.1"]},
            {"host": "bad.example.com", "a": ["10.0.0.2"]},
        ]
        def run(cmd, **kw):
            if cmd.startswith("dnsx -l") and "-rc" not in cmd:
                return "\n".join(json.dumps(r) for r in resolved)
            return ""
        with mock.patch.object(subdomains.utils, "have", return_value=True), \
             mock.patch.object(subdomains.utils, "run", side_effect=run), \
             mock.patch.object(subdomains.utils, "log"), \
             mock.patch.object(subdomains.utils, "warn"):
            subdomains.resolve(["ok.example.com", "bad.example.com"],
                               tmp_path, "example.com", None)
        internal_file = (tmp_path / "subs_internal.txt").read_text()
        assert "ok.example.com" in internal_file
        assert "bad.example.com" not in internal_file
