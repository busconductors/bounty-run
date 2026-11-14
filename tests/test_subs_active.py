"""Phase 3-4 subdomain discovery: brute force (puredns / dnsx fallback) and
alterx permutation — intensity gating, commands, caps, and CLI wiring.

utils.run / utils.have are mocked on the shared module object; no network.
One test drives the real alterx binary (local only) when it is installed.
"""
import shutil
from pathlib import Path
from unittest import mock

import pytest

from runner import cli, scope, stages, subdomains


@pytest.fixture(autouse=True)
def _reset_scope():
    scope.reset()
    yield
    scope.reset()


@pytest.fixture
def wordlist(tmp_path):
    p = tmp_path / "wl.txt"
    p.write_text("www\napi\ndev\n")
    return p


def _arg_after(cmd, flag):
    parts = cmd.split()
    return parts[parts.index(flag) + 1]


class FakeTools:
    """utils.run stand-in: records commands, writes the files tools would."""

    def __init__(self, have, brute_hits=(), resolved=(), est=10, perm_cands=(), perm_ok=()):
        self.have_set = set(have)
        self.calls = []
        self.brute_hits, self.resolved = list(brute_hits), list(resolved)
        self.est, self.perm_cands, self.perm_ok = est, list(perm_cands), list(perm_ok)

    def have(self, t):
        return t in self.have_set

    def run(self, cmd, **kw):
        self.calls.append(cmd)
        if cmd.startswith("subfinder"):
            # dnsx only ever resolves names already in the union
            return "\n".join(["example.com", *self.resolved]) + "\n"
        if cmd.startswith("puredns bruteforce") or cmd.startswith("dnsx -d"):
            flag = "--write" if cmd.startswith("puredns") else "-o"
            Path(_arg_after(cmd, flag).strip("'")).write_text("\n".join(self.brute_hits) + "\n")
            return ""
        if cmd.startswith("dnsx -l") and "-j" in cmd:
            import json
            return "\n".join(json.dumps({"host": h, "a": ["93.184.216.34"]}) for h in self.resolved)
        if cmd.startswith("dnsx -l") or cmd.startswith("puredns resolve"):
            flag = "-w" if cmd.startswith("puredns") else "-o"
            Path(_arg_after(cmd, flag).strip("'")).write_text("\n".join(self.perm_ok) + "\n")
            return ""
        if cmd.startswith("alterx") and "-es" in cmd:
            return f"[INF] Estimated Payloads (including duplicates): {self.est}\n"
        if cmd.startswith("alterx"):
            Path(_arg_after(cmd, "-o").strip("'")).write_text("\n".join(self.perm_cands) + "\n")
            return ""
        return ""


def _enum(tmp_path, tools, **kw):
    with mock.patch.object(stages.utils, "have", side_effect=tools.have), \
         mock.patch.object(stages.utils, "run", side_effect=tools.run), \
         mock.patch.object(stages.utils, "log"), \
         mock.patch.object(stages.utils, "warn") as warn, \
         mock.patch.object(subdomains, "resolvers_file", return_value=None):
        subs = stages.subdomain_enum("example.com", tmp_path, **kw)
    return subs, warn


ALL = ("subfinder", "dnsx", "puredns", "massdns", "alterx")


# --------------------------------------------------------------------------- #
# intensity gate
# --------------------------------------------------------------------------- #
def test_passive_never_runs_active_tools(tmp_path, wordlist):
    t = FakeTools(ALL, brute_hits=["x.example.com"])
    subs, _ = _enum(tmp_path, t, active=False, brute=str(wordlist), permute=True)
    assert subs == ["example.com"]
    assert all(c.startswith("subfinder") for c in t.calls)
    stats = __import__("json").loads((tmp_path / "subs_stats.json").read_text())
    assert stats["skipped"]["brute"] == "intensity below active"
    assert stats["skipped"]["permute"] == "intensity below active"


def test_defaults_unchanged_no_active_extras(tmp_path):
    t = FakeTools(ALL)
    _enum(tmp_path, t, active=True)
    assert not any(c.startswith(("puredns", "alterx", "dnsx -d")) for c in t.calls)


# --------------------------------------------------------------------------- #
# brute
# --------------------------------------------------------------------------- #
def test_brute_puredns_command_and_hits_merged(tmp_path, wordlist):
    t = FakeTools(("subfinder", "puredns", "massdns"),
                  brute_hits=["api.example.com", "evil.com", "*.dev.example.com"])
    subs, _ = _enum(tmp_path, t, active=True, brute=str(wordlist), dns_rate=300)
    (cmd,) = [c for c in t.calls if c.startswith("puredns")]
    assert cmd.startswith(f"puredns bruteforce {wordlist} example.com ")
    for frag in ("-r ", "--resolvers-trusted ", "--rate-limit 300 ", "--rate-limit-trusted 200",
                 "-n 5", "--write ", "--write-wildcards ", "-q"):
        assert frag in cmd
    assert cmd.endswith("</dev/null")
    assert subs == ["api.example.com", "dev.example.com", "example.com"]
    assert "1.1.1.1" in (tmp_path / "resolvers_trusted.txt").read_text()


def test_brute_dnsx_fallback(tmp_path, wordlist):
    t = FakeTools(("subfinder", "dnsx"), brute_hits=["api.example.com"])
    subs, _ = _enum(tmp_path, t, active=True, brute=str(wordlist), dns_rate=1000)
    (cmd,) = [c for c in t.calls if c.startswith("dnsx -d")]
    assert "-w " in cmd and "-wd example.com" in cmd
    assert "-rl 300" in cmd          # fallback rate is capped
    assert "api.example.com" in subs


def test_brute_no_tool_warns_and_skips(tmp_path, wordlist):
    t = FakeTools(("subfinder",))
    subs, warn = _enum(tmp_path, t, active=True, brute=str(wordlist))
    assert subs == ["example.com"]
    assert any("--brute needs" in c[0][0] for c in warn.call_args_list)
    stats = __import__("json").loads((tmp_path / "subs_stats.json").read_text())
    assert "brute" in stats["skipped"]


def test_brute_missing_wordlist_skips(tmp_path):
    t = FakeTools(ALL)
    _enum(tmp_path, t, active=True, brute=str(tmp_path / "nope.txt"))
    assert not any(c.startswith("puredns") for c in t.calls)


def test_brute_hits_respect_scope_deny(tmp_path, wordlist):
    t = FakeTools(("subfinder", "puredns", "massdns"),
                  brute_hits=["api.example.com", "secret.example.com"])
    scope.set_active(scope.from_args("example.com", [], ["secret.example.com"], None))
    subs, _ = _enum(tmp_path, t, active=True, brute=str(wordlist))
    assert "secret.example.com" not in subs and "api.example.com" in subs


def test_brute_quotes_target(tmp_path, wordlist):
    t = FakeTools(("puredns", "massdns"))
    with mock.patch.object(subdomains.utils, "have", side_effect=t.have), \
         mock.patch.object(subdomains.utils, "run", side_effect=t.run):
        subdomains.brute("a.com;id", tmp_path, wordlist)
    assert "'a.com;id'" in t.calls[0]


def test_wordlist_tiers_and_path(tmp_path, wordlist):
    assert subdomains.wordlist_for(str(wordlist)) == wordlist
    assert subdomains.wordlist_for(str(tmp_path / "missing")) is None
    assert set(subdomains.BRUTE_TIERS) == {"fast", "standard", "deep"}
    if subdomains.BRUTE_TIERS["fast"].is_file():
        assert subdomains.wordlist_for("fast") == subdomains.BRUTE_TIERS["fast"]


def test_dns_timeout_scales():
    assert subdomains._dns_timeout(100, 500) == 300
    assert subdomains._dns_timeout(3_000_000, 500) > 3600


# --------------------------------------------------------------------------- #
# permute
# --------------------------------------------------------------------------- #
def test_select_seeds_cap_wildcards_and_depth():
    names = [f"h{i}.example.com" for i in range(500)] + ["a.b.c.example.com",
                                                         "x.wild.example.com", "example.com"]
    seeds = subdomains.select_seeds(names, "example.com", wildcard_roots={"wild.example.com"})
    assert len(seeds) == subdomains.PERMUTE_MAX_SEEDS
    assert seeds[0] == "a.b.c.example.com"           # deepest first
    assert "x.wild.example.com" not in seeds and "example.com" not in seeds


def test_permute_pipeline_limit_and_known_dropped(tmp_path):
    t = FakeTools(ALL, resolved=["api.example.com", "dev.example.com"], est=10,
                  perm_cands=["api-dev.example.com", "api.example.com", "staging.example.com"],
                  perm_ok=["api-dev.example.com", "nope.other.com"])
    subs, _ = _enum(tmp_path, t, active=True, permute=True)
    alterx = [c for c in t.calls if c.startswith("alterx")]
    assert "-es" in alterx[0] and "2>&1" in alterx[0]
    assert "-limit 50000" in alterx[1] and "-enrich" in alterx[1]   # estimate fits
    assert all(c.endswith("</dev/null") for c in alterx)
    seeds = (tmp_path / "subs_permute_seeds.txt").read_text().split()
    assert seeds == ["api.example.com", "dev.example.com"]
    cands = (tmp_path / "subs_permute_cand.txt").read_text().split()
    assert "api.example.com" not in cands          # known names never re-resolved
    assert any(c.startswith("puredns resolve") for c in t.calls)
    assert "api-dev.example.com" in subs and "nope.other.com" not in subs


def test_permute_drops_enrich_when_estimate_too_big(tmp_path):
    t = FakeTools(ALL, resolved=["api.example.com"], est=10_000_000)
    _enum(tmp_path, t, active=True, permute=True)
    gen = [c for c in t.calls if c.startswith("alterx") and "-es" not in c][0]
    assert "-enrich" not in gen and "-limit 50000" in gen


def test_permute_needs_dnsx_seeds(tmp_path):
    t = FakeTools(("subfinder", "alterx", "puredns", "massdns"))
    _, warn = _enum(tmp_path, t, active=True, permute=True)
    assert not any(c.startswith("alterx") for c in t.calls)
    assert any("--permute needs" in c[0][0] for c in warn.call_args_list)


def test_permute_without_alterx_skips(tmp_path):
    t = FakeTools(("subfinder", "dnsx"), resolved=["api.example.com"])
    _enum(tmp_path, t, active=True, permute=True)
    assert not any(c.startswith("alterx") for c in t.calls)


def test_estimate_parse():
    assert subdomains._estimate("\x1b[34mINF\x1b[0m] Estimated Payloads (including duplicates): 1392") == 1392
    assert subdomains._estimate("nothing") is None


@pytest.mark.skipif(not shutil.which("alterx"), reason="alterx not installed")
def test_real_alterx_generates_capped_candidates(tmp_path):
    """Real alterx (offline): the </dev/null redirect keeps it from blocking on
    an inherited stdin, the estimate parses, and -limit caps the output."""
    with mock.patch.object(subdomains, "_puredns_ok", return_value=False), \
         mock.patch.object(subdomains.utils, "have",
                           side_effect=lambda t: t == "alterx"), \
         mock.patch.object(subdomains.utils, "log"), \
         mock.patch.object(subdomains.utils, "warn"):
        out = subdomains.permute(["www.example.com", "api.example.com"], tmp_path,
                                 "example.com", known=set(), limit=25)
    assert out == set()   # no resolver tool in this test, by design
    cands = (tmp_path / "subs_permute_cand.txt").read_text().split()
    assert 0 < len(cands) <= 25
    assert all(c.endswith(".example.com") for c in cands)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _pipeline_subs_kwargs(argv, tmp_path):
    args = cli.build_parser().parse_args(argv)
    with mock.patch.object(cli.stages, "subdomain_enum", return_value=[]) as se, \
         mock.patch.object(cli.utils, "warn") as warn, \
         mock.patch.object(cli.utils, "stage_header"):
        cli._pipeline(args, args.target, tmp_path,
                      set(cli.STAGE_IDS) - {"subs"} | {"origin_deep"}, cli.RunState(args.target))
    return se.call_args.kwargs, warn


def test_cli_brute_defaults_to_fast():
    a = cli.build_parser().parse_args(["example.com", "--brute"])
    assert a.brute == "fast" and a.permute is False
    assert cli.build_parser().parse_args(["example.com", "--brute", "deep"]).brute == "deep"
    assert cli.build_parser().parse_args(["example.com"]).brute is None


def test_cli_brute_path_and_invalid(wordlist):
    assert cli.build_parser().parse_args(["example.com", "--brute", str(wordlist)]).brute == str(wordlist)
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["example.com", "--brute", "/no/such/list"])


def test_cli_passes_brute_permute_when_active(tmp_path):
    kw, _ = _pipeline_subs_kwargs(["example.com", "--intensity", "active", "--brute",
                                   "--permute"], tmp_path)
    assert kw["brute"] == "fast" and kw["permute"] is True and kw["active"] is True


def test_cli_passive_warns_and_drops(tmp_path):
    kw, warn = _pipeline_subs_kwargs(["example.com", "--intensity", "passive", "--brute",
                                      "--permute"], tmp_path)
    assert "brute" not in kw and "permute" not in kw and kw["active"] is False
    msgs = [c[0][0] for c in warn.call_args_list]
    assert any("--brute needs --intensity active" in m for m in msgs)
    assert any("--permute needs --intensity active" in m for m in msgs)


def test_cli_without_flags_passes_no_new_kwargs(tmp_path):
    kw, _ = _pipeline_subs_kwargs(["example.com"], tmp_path)
    assert "brute" not in kw and "permute" not in kw
