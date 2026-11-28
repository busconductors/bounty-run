from types import SimpleNamespace

import pytest

from runner import events, httpclient, noauth_scan


def test_check_auth_401_403_walled():
    assert noauth_scan._check_auth(401, "", {}) is True
    assert noauth_scan._check_auth(403, "", {}) is True


def test_check_auth_www_authenticate_header():
    assert noauth_scan._check_auth(200, "", {"WWW-Authenticate": "Basic"}) is True


def test_check_auth_login_redirect():
    assert noauth_scan._check_auth(200, "", {}, final_url="https://x/login") is True


def test_check_auth_password_form():
    assert noauth_scan._check_auth(200, '<input type="password">', {}) is True


def test_check_auth_two_text_hints_no_positive():
    assert noauth_scan._check_auth(200, "please sign in. login required.", {}) is True


def test_check_auth_open_dashboard():
    assert noauth_scan._check_auth(200, "<h1>dashboard</h1>", {}) is False


def test_sensitive_secret_hit():
    r = noauth_scan._sensitive("aws_secret_access_key = x")
    assert r["secret_pattern_hits"] >= 1


def test_sensitive_json_and_stacktrace():
    assert noauth_scan._sensitive('{"a":1}')["looks_json"] is True
    assert noauth_scan._sensitive("Traceback (most recent call last):")["stacktrace"] is True


def test_classify_tech_grafana():
    assert "Grafana" in noauth_scan._classify_tech("Grafana", "", "/", "", 200)


def _resp(**kw):
    base = {"title": "", "body": "", "url": "", "sensitive": {}}
    base.update(kw)
    return base


def test_score_private_root_is_low():
    s, sev, _ = noauth_scan._score("10.0.0.5", 80, _resp(), [], ["/"])
    assert s == 0 and sev == "low"


def test_score_public_actuator_secret_json_critical():
    resp = _resp(sensitive={"secret_pattern_hits": 1, "looks_json": True, "stacktrace": False})
    s, sev, reasons = noauth_scan._score("93.184.216.34", 443, resp, [], ["/actuator/env"])
    assert s == 78 and sev == "critical"
    assert "secret_like_content" in reasons


def test_score_band_boundaries():
    assert noauth_scan._severity_for(20) == "medium"
    assert noauth_scan._severity_for(40) == "high"
    assert noauth_scan._severity_for(60) == "critical"
    assert noauth_scan._severity_for(19) == "low"


# ---- stage orchestrator ----

def _r(status, body="", final=None, headers=None):
    return SimpleNamespace(status_code=status, text=body, content=body.encode(),
                           headers=headers or {}, url=final, history=[])


def _patch_scope(monkeypatch):
    monkeypatch.setattr(noauth_scan, "_is_global", lambda ip: True)
    monkeypatch.setattr(noauth_scan, "_resolve", lambda h: "8.8.8.8")


def _stub_get(monkeypatch, host, port, responses):
    """responses: {path: resp}; unknown paths answer 404."""
    def fake(url, **kw):
        rest = url.split("//", 1)[1]
        path = "/" + rest.split("/", 1)[1] if "/" in rest else "/"
        r = responses.get(path, _r(404))
        if r.url is None:
            r.url = url
        return r
    monkeypatch.setattr(httpclient, "get", fake)
    _patch_scope(monkeypatch)


def _stub_get_raises(monkeypatch, exc):
    def fake(url, **kw):
        raise exc()
    monkeypatch.setattr(httpclient, "get", fake)
    _patch_scope(monkeypatch)


def _port_paths():
    return noauth_scan._port_paths()


def test_root_walled_subpath_open_is_found(monkeypatch, tmp_path):
    responses = {"/": _r(302, final="https://h/login"),
                 "/actuator/env": _r(200, body='{"password":"x"}')}
    _stub_get(monkeypatch, "h", 443, responses)
    out = noauth_scan.noauth_scan("h", tmp_path, ["h"], ports=[443])
    assert len(out) == 1
    f = out[0]
    assert f["template"].startswith("noauth:actuator") and f["host"] == "h"
    assert f["severity"] in ("high", "critical")


def test_fully_walled_host_emits_nothing(monkeypatch, tmp_path):
    _stub_get(monkeypatch, "h", 443, {p: _r(401) for p in _port_paths()})
    assert noauth_scan.noauth_scan("h", tmp_path, ["h"], ports=[443]) == []


def test_out_of_scope_redirect_is_not_fatal(monkeypatch, tmp_path):
    _stub_get_raises(monkeypatch, httpclient.OutOfScope)
    assert noauth_scan.noauth_scan("h", tmp_path, ["h"], ports=[443]) == []


def test_connection_error_skips_host(monkeypatch, tmp_path):
    _stub_get_raises(monkeypatch, ConnectionError)
    assert noauth_scan.noauth_scan("h", tmp_path, ["h"], ports=[443]) == []


def test_dead_port_probes_root_only(monkeypatch, tmp_path):
    calls = []

    def fake(url, **kw):
        calls.append(url)
        raise ConnectionError()
    monkeypatch.setattr(httpclient, "get", fake)
    _patch_scope(monkeypatch)
    assert noauth_scan.noauth_scan("h", tmp_path, ["h"], ports=[8080]) == []
    assert len(calls) == 1


def test_cancel_via_check_control_propagates(monkeypatch, tmp_path):
    _stub_get(monkeypatch, "h", 443, {"/": _r(200, body="hello")})

    def boom():
        raise events.RunCancelled()
    monkeypatch.setattr(events, "check_control", boom)
    monkeypatch.setattr(events, "progress", lambda *a, **k: None)
    with pytest.raises(events.RunCancelled):
        noauth_scan.noauth_scan("h", tmp_path, ["h"], ports=[443])


def test_interface_error_does_not_sink_stage(monkeypatch, tmp_path):
    responses = {"/actuator/env": _r(200, body='{"password":"x"}')}
    _stub_get(monkeypatch, "h", 443, responses)
    real = noauth_scan._score

    def flaky(host, *a, **kw):
        if host == "bad":
            raise ValueError("boom")
        return real(host, *a, **kw)
    monkeypatch.setattr(noauth_scan, "_score", flaky)
    out = noauth_scan.noauth_scan("good", tmp_path, ["bad"], ports=[443])
    assert [f["host"] for f in out] == ["good"]


def test_cancellation_propagates(monkeypatch, tmp_path):
    _stub_get_raises(monkeypatch, events.RunCancelled)
    with pytest.raises(events.RunCancelled):
        noauth_scan.noauth_scan("h", tmp_path, ["h", "h2"], ports=[443])


def test_noauth_registered_optin_last():
    from runner.stage_registry import STAGE_IDS, OPT_IN_STAGES
    assert "noauth" in STAGE_IDS and STAGE_IDS[-1] == "noauth"
    assert "noauth" in OPT_IN_STAGES


def test_noauth_planned_only_when_opted_in():
    from runner.cli import build_parser, PLANNED_STAGES
    args = build_parser().parse_args(["x.com", "--noauth"])
    assert "noauth" in PLANNED_STAGES(args, skip=set())
    args2 = build_parser().parse_args(["x.com"])
    assert "noauth" not in PLANNED_STAGES(args2, skip=set())
