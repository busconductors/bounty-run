"""Tests for runner/http_headers.py (Phase 7b, Features 1+2)."""
import unittest
from pathlib import Path
from unittest import mock

from runner import http_headers


SAMPLE_SHCHECK_JSON = (
    '{"https://example.com": {'
    '"present": {"X-Content-Type-Options": "nosniff", '
    '"Content-Security-Policy": "default-src \'self\'"}, '
    '"missing": ["Strict-Transport-Security", "Permissions-Policy"]}}'
)

INSECURE_SHCHECK_JSON = (
    '{"https://example.com": {'
    '"present": {"Content-Security-Policy": "default-src \'self\'; script-src \'unsafe-inline\'"}, '
    '"missing": []}}'
)


class TestSecurityHeadersScan(unittest.TestCase):
    def _run(self, hosts=("example.com",), shcheck_exists=True, raw=SAMPLE_SHCHECK_JSON):
        if shcheck_exists:
            shcheck_path = Path("/tmp/shcheck_vendored.py")
            shcheck_path.write_text("# stub")
        else:
            shcheck_path = Path("/nonexistent/shcheck.py")
        with mock.patch.object(http_headers, "_live_hosts", return_value=list(hosts)), \
             mock.patch.object(http_headers.utils, "log"), \
             mock.patch.object(http_headers.utils, "warn"), \
             mock.patch.object(http_headers.utils, "run", return_value=raw), \
             mock.patch.object(http_headers, "SHCHECK", shcheck_path):
            return http_headers.security_headers_scan("example.com", Path("/tmp"), list(hosts))

    def test_missing_headers_become_findings(self):
        findings = self._run()
        self.assertEqual(len(findings), 2)
        self.assertEqual({f["template"] for f in findings},
                         {"missing-security-header:strict-transport-security",
                          "missing-security-header:permissions-policy"})

    def test_missing_severity_map(self):
        findings = self._run()
        by_name = {f["name"]: f["severity"] for f in findings}
        self.assertEqual(by_name["Missing security header: Strict-Transport-Security"], "low")
        self.assertEqual(by_name["Missing security header: Permissions-Policy"], "info")

    def test_insecure_header_emitted(self):
        findings = self._run(raw=INSECURE_SHCHECK_JSON)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["template"], "insecure-security-header:content-security-policy")
        self.assertEqual(findings[0]["severity"], "info")

    def test_missing_shcheck_returns_empty(self):
        self.assertEqual(self._run(shcheck_exists=False), [])

    def test_weak_value_severity(self):
        self.assertEqual(http_headers._weak_value_severity("Referrer-Policy", "unsafe-url"), "low")
        self.assertEqual(http_headers._weak_value_severity("Strict-Transport-Security", "max-age=0"), "low")
        self.assertEqual(http_headers._weak_value_severity("Content-Security-Policy", "unsafe-inline"), "info")
        self.assertIsNone(http_headers._weak_value_severity("X-Frame-Options", "DENY"))


class TestCorsScan(unittest.TestCase):
    def test_classify_reflected_high(self):
        self.assertEqual(http_headers._classify("reflected", "abc.com", "false", "abc.com"), "high")

    def test_classify_null_medium(self):
        self.assertEqual(http_headers._classify("null", "null", "false", "null"), "medium")

    def test_classify_mangled_medium(self):
        self.assertEqual(http_headers._classify("mangled_front", "x.com", "false", "x.com"), "medium")

    def test_classify_mangled_wildcard_medium(self):
        self.assertEqual(
            http_headers._classify("mangled_front", "*", "", "attacker-mangled-origin.com"), "medium")

    def test_classify_mangled_own_fixed_origin_safe(self):
        self.assertIsNone(
            http_headers._classify("mangled_front", "https://own-origin.com", "",
                                   "attacker-mangled-origin.com"))

    def test_classify_mangled_reflected_medium(self):
        self.assertEqual(
            http_headers._classify("mangled_front", "attacker-mangled-origin.com", "",
                                   "attacker-mangled-origin.com"), "medium")

    def test_classify_mangled_rear_reflected_with_scheme_medium(self):
        self.assertEqual(
            http_headers._classify("mangled_rear", "https://h.random.tld", "", "h.random.tld"),
            "medium")

    def test_classify_reflected_with_scheme_high(self):
        self.assertEqual(
            http_headers._classify("reflected", "https://abc.com", "false", "abc.com"), "high")

    def test_classify_reflected_other_origin_none(self):
        self.assertIsNone(
            http_headers._classify("reflected", "https://site.com", "false", "abc.com"))

    def test_classify_scheme_low(self):
        self.assertEqual(http_headers._classify("scheme", "http://h", "false", "http://h"), "low")

    def test_probe_cors_reflected(self):
        def fake_send(url, origin):
            if origin.endswith(".com"):
                return (origin, "false")
            return ("", "")

        with mock.patch.object(http_headers, "_send_origin", side_effect=fake_send):
            findings, _ = http_headers._probe_cors("https://example.com", "example.com")
        reflected = [f for f in findings if f["name"] == "CORS: reflected"]
        self.assertEqual(len(reflected), 1)
        self.assertEqual(reflected[0]["severity"], "high")


class TestLiveHosts(unittest.TestCase):
    def test_ssrf_skip_private(self):
        def fake_resolve(h):
            return "127.0.0.1" if "local" in h else "93.184.216.34"

        with mock.patch.object(http_headers, "_resolve", side_effect=fake_resolve):
            hosts = http_headers._live_hosts(Path("/tmp"), "example.com", ["example.com", "localhost"])
        self.assertEqual(hosts, ["example.com"])


if __name__ == "__main__":
    unittest.main()
