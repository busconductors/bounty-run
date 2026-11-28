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
