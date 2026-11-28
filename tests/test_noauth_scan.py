from runner import noauth_scan


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
