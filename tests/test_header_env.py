"""BOUNTY_RUN_HEADERS: secret request headers supplied through the environment.

Every stage is mocked and HTTP goes through a fake adapter: nothing listens and
no target is contacted.
"""
import json
import os
from unittest import mock

import pytest

from runner import cli, evidence, httpclient, utils
from runner.evidence import EvidenceStore
from runner.httpclient import HttpConfig
from tests.test_events_cli import read_events, run_cli
from tests.test_evidence_capture import _make_response, _mount

SECRET = "s3cr3t-h34der-v4lue"
ENV = "BOUNTY_RUN_HEADERS"


@pytest.fixture(autouse=True)
def _clean_globals():
    yield
    evidence.reset()
    utils.set_secrets(())
    httpclient.configure(HttpConfig())


def _set_env(monkeypatch, *headers):
    monkeypatch.setenv(ENV, json.dumps(list(headers)))


def _stage(responder=None, then=None):
    """A subdomain stage that sends one request through the shared client."""
    def run(*_a, **_k):
        _mount(httpclient.client(), responder or (lambda r: _make_response(r)))
        resp = httpclient.get("https://a.com/")
        evidence.attach({"severity": "low", "template": "t", "host": "a.com",
                         "url": "https://a.com/"}, "https://a.com/")
        if then:
            then(resp)
        return ["a.com"]
    return run


def _capture():
    sent = []

    def responder(request):
        sent.append(request)
        return _make_response(request)
    return sent, responder


def _tree_text(root):
    out = []
    for p in root.rglob("*"):
        if p.is_file():
            out.append(p.read_bytes().decode("utf-8", "replace"))
    return "\n".join(out)


def _run(tmp_path, stage=None, extra=()):
    argv = ["-o", str(tmp_path / "out"), "--events", str(tmp_path / "ev" / "events.jsonl"),
            *extra]
    overrides = {"subdomain_enum": stage} if stage else None
    rc, out, tmp, exc = run_cli(argv, overrides)
    tmp.cleanup()
    assert exc is None
    return rc, out


class TestDelivery:
    def test_env_headers_are_sent(self, tmp_path, monkeypatch):
        _set_env(monkeypatch, f"X-Session: {SECRET}")
        sent, responder = _capture()
        assert _run(tmp_path, _stage(responder))[0] == 0
        assert sent[0].headers["X-Session"] == SECRET

    def test_env_header_wins_case_insensitively(self, tmp_path, monkeypatch):
        _set_env(monkeypatch, f"x-session: {SECRET}")
        sent, responder = _capture()
        _run(tmp_path, _stage(responder), ["--header", "X-Session: from-cli"])
        names = [k for k in sent[0].headers if k.lower() == "x-session"]
        assert names == ["x-session"]
        assert sent[0].headers["X-Session"] == SECRET

    def test_cli_header_still_sent_beside_env_header(self, tmp_path, monkeypatch):
        _set_env(monkeypatch, f"X-Session: {SECRET}")
        sent, responder = _capture()
        _run(tmp_path, _stage(responder), ["--header", "X-Trace: 1"])
        assert sent[0].headers["X-Trace"] == "1"
        assert sent[0].headers["X-Session"] == SECRET

    def test_env_header_not_sent_to_scope_exempt_host(self, tmp_path, monkeypatch):
        _set_env(monkeypatch, f"X-Session: {SECRET}")
        sent, responder = _capture()

        def stage(*_a, **_k):
            _mount(httpclient.client(), responder)
            httpclient.get("https://search.example/", scope_exempt=True, purpose="osint")
            return ["a.com"]
        _run(tmp_path, stage)
        assert "X-Session" not in sent[0].headers

    def test_client_forgets_env_headers_after_run(self, tmp_path, monkeypatch):
        _set_env(monkeypatch, f"X-Session: {SECRET}")
        _run(tmp_path, _stage())
        assert "X-Session" not in httpclient.client().cfg.extra_headers


class TestNoLeak:
    def test_env_headers_absent_from_run_json_and_events(self, tmp_path, monkeypatch):
        _set_env(monkeypatch, f"X-Session: {SECRET}")
        _run(tmp_path, _stage())
        run_json = (tmp_path / "ev" / "run.json").read_text()
        assert SECRET not in run_json
        assert "X-Session" not in run_json
        assert SECRET not in (tmp_path / "ev" / "events.jsonl").read_text()

    def test_env_header_value_scrubbed_from_logs(self, tmp_path, monkeypatch):
        _set_env(monkeypatch, f"X-Session: {SECRET}")

        def stage(*_a, **_k):
            utils.log(f"saw {SECRET}")
            utils.warn(f"saw {SECRET}")
            utils.run(f"echo {SECRET}")
            return ["a.com"]
        _, out = _run(tmp_path, stage)
        assert SECRET not in out
        evs = read_events(tmp_path / "ev")
        assert any(e["type"] == "log" and "saw ***" in e.get("msg", "") for e in evs)
        assert SECRET not in json.dumps(evs)

    def test_failed_run_error_is_scrubbed(self, tmp_path, monkeypatch):
        _set_env(monkeypatch, f"X-Session: {SECRET}")
        rc, _out, tmp, exc = run_cli(
            ["-o", str(tmp_path / "out"), "--events", str(tmp_path / "ev" / "events.jsonl")],
            {"subdomain_enum": RuntimeError(f"boom {SECRET}")})
        tmp.cleanup()
        assert isinstance(exc, RuntimeError)
        assert SECRET not in (tmp_path / "ev" / "events.jsonl").read_text()

    def test_env_var_removed_before_children_spawn(self, tmp_path, monkeypatch):
        _set_env(monkeypatch, f"X-Session: {SECRET}")
        seen = {}

        def stage(*_a, **_k):
            seen["parent"] = os.environ.get(ENV)
            seen["child"] = utils.run(f'printenv {ENV} || echo unset')
            return ["a.com"]
        _run(tmp_path, stage)
        assert seen["parent"] is None
        assert seen["child"].strip() == "unset"


class TestSecretLifetime:
    def test_header_secrets_merge_with_proxy_and_clear(self, tmp_path, monkeypatch):
        _set_env(monkeypatch, f"X-Session: {SECRET}")
        during = {}

        def stage(*_a, **_k):
            during["secrets"] = utils._secrets
            return ["a.com"]
        with mock.patch.object(cli.proxy, "preflight", return_value=None):
            _run(tmp_path, stage, ["--proxy", "http://user:prox-pass@127.0.0.1:8080"])
        assert SECRET in during["secrets"]
        assert "prox-pass" in during["secrets"]
        assert utils._secrets == ()

    def test_secrets_cleared_when_preflight_fails(self, tmp_path, monkeypatch):
        _set_env(monkeypatch, f"X-Session: {SECRET}")
        with mock.patch.object(cli.proxy, "preflight", return_value="down"):
            rc, _ = _run(tmp_path, None, ["--proxy", "http://127.0.0.1:8080"])
        assert rc == 2
        assert utils._secrets == ()

    def test_secrets_cleared_when_setup_raises(self, tmp_path, monkeypatch):
        _set_env(monkeypatch, f"X-Session: {SECRET}")
        with mock.patch.object(cli, "_resolve_outdir", side_effect=OSError("nope")), \
                pytest.raises(OSError):
            cli.main(["a.com", "--no-banner", "--no-track"])
        assert utils._secrets == ()
        assert "X-Session" not in httpclient.client().cfg.extra_headers

    def test_next_run_without_env_has_no_header(self, tmp_path, monkeypatch):
        _set_env(monkeypatch, f"X-Session: {SECRET}")
        _run(tmp_path / "one", _stage())
        monkeypatch.delenv(ENV, raising=False)
        sent, responder = _capture()
        _run(tmp_path / "two", _stage(responder))
        assert "X-Session" not in sent[0].headers


class TestEvidence:
    def _evidence_text(self, tmp_path):
        return _tree_text(tmp_path / "out" / "evidence")

    def test_custom_header_masked_in_evidence_and_repro(self, tmp_path, monkeypatch):
        _set_env(monkeypatch, f"X-Session: {SECRET}")
        _run(tmp_path, _stage())
        repro = list((tmp_path / "out" / "evidence").glob("*/*/repro.sh"))
        assert repro
        assert "X-Session: <redacted>" in repro[0].read_text()
        assert SECRET not in self._evidence_text(tmp_path)

    def test_reflected_value_masked_in_stored_response(self, tmp_path, monkeypatch):
        _set_env(monkeypatch, f"X-Session: {SECRET}")

        def reflect(request):
            return _make_response(request, headers={"X-Echo": SECRET,
                                                    "Content-Type": "text/plain"},
                                  body=f"you sent {SECRET}".encode())
        _run(tmp_path, _stage(reflect))
        text = self._evidence_text(tmp_path)
        assert "you sent <redacted>" in text
        assert SECRET not in text

    def test_reflected_value_masked_in_binary_body(self, tmp_path, monkeypatch):
        _set_env(monkeypatch, f"X-Session: {SECRET}")

        def reflect(request):
            return _make_response(request, headers={"Content-Type": "application/octet-stream"},
                                  body=b"\x00\x01" + SECRET.encode())
        _run(tmp_path, _stage(reflect))
        assert list((tmp_path / "out" / "evidence").glob("*/*/response.body.bin"))
        assert SECRET not in self._evidence_text(tmp_path)

    def test_evidence_unredacted_keeps_value(self, tmp_path, monkeypatch):
        _set_env(monkeypatch, f"X-Session: {SECRET}")
        _run(tmp_path, _stage(), ["--evidence-unredacted"])
        assert f"X-Session: {SECRET}" in self._evidence_text(tmp_path)

    def test_store_scrubs_raw_and_linked_repro(self, tmp_path):
        store = EvidenceStore(tmp_path, secret_headers={"X-Session": SECRET})
        f = {"template": "t", "host": "a.com", "url": "https://a.com/"}
        store.record_raw(f, f"GET /\nX-Session: {SECRET}", f"echo {SECRET}",
                         curl=f"curl -H 'X-Session: {SECRET}' https://a.com/")
        store.link(f, [], repro=f"curl -H 'X-Session: {SECRET}' https://a.com/")
        assert SECRET not in _tree_text(tmp_path / "evidence")

    def test_mask_in_unquoted_repro_is_shell_safe(self, tmp_path):
        store = EvidenceStore(tmp_path, secret_headers={"X-Session": SECRET})
        f = {"template": "t", "host": "a.com", "url": "https://a.com/"}
        store.link(f, [], repro=f"sqlmap -u https://a.com/{SECRET} --batch")
        repro = next((tmp_path / "evidence").glob("*/*/repro.sh")).read_text()
        assert SECRET not in repro
        assert "<" not in repro and ">" not in repro

    def test_store_without_secret_headers_is_unchanged(self, tmp_path):
        store = EvidenceStore(tmp_path)
        f = {"template": "t", "host": "a.com", "url": "https://a.com/"}
        store.record_raw(f, "GET /\nX-Session: plain", "ok")
        assert "X-Session: plain" in _tree_text(tmp_path / "evidence")


class TestValidation:
    @pytest.mark.parametrize("raw", [
        f"not json {SECRET}",
        "",
        "[" * 100_000,
        json.dumps({"X-Session": SECRET}),
        json.dumps(SECRET),
        json.dumps([1]),
        json.dumps([f"X-Ok: {SECRET}", None]),
        json.dumps(["   "]),
        json.dumps([f"nocolon{SECRET}"]),
        json.dumps([f": {SECRET}"]),
        json.dumps([f"   : {SECRET}"]),
        json.dumps([f"X-A: {SECRET}\r\nX-B: 1"]),
        json.dumps([f"X-A: {SECRET}\n"]),
        json.dumps([f"X-A\r: {SECRET}"]),
        json.dumps([f"Bad Name{SECRET}: v"]),
        json.dumps([f"X-A: {SECRET}☃"]),
        json.dumps([f"X-A: {SECRET}\x00"]),
    ])
    def test_malformed_env_headers_exit_2_without_echo(self, raw, tmp_path, monkeypatch, capfd):
        monkeypatch.setenv(ENV, raw)
        out_dir, ev_dir = tmp_path / "out", tmp_path / "ev"
        with mock.patch.object(cli, "_run") as pipeline:
            rc = cli.main(["a.com", "--no-banner", "--no-track", "-o", str(out_dir),
                           "--events", str(ev_dir / "events.jsonl")])
        captured = capfd.readouterr()
        assert rc == 2
        pipeline.assert_not_called()
        assert ENV in captured.err
        assert SECRET not in captured.err + captured.out
        assert not out_dir.exists()
        assert not ev_dir.exists()
        assert ENV not in os.environ
        assert utils._secrets == ()

    def test_empty_array_is_valid(self, tmp_path, monkeypatch):
        monkeypatch.setenv(ENV, "[]")
        assert _run(tmp_path, _stage())[0] == 0

    def test_empty_value_is_valid(self, tmp_path, monkeypatch):
        _set_env(monkeypatch, "X-Empty:")
        sent, responder = _capture()
        _run(tmp_path, _stage(responder))
        assert sent[0].headers["X-Empty"] == ""
