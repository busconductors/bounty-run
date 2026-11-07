"""Unit tests for runner.secret_scan.

Hermetic — _fetch, _resolve and _is_global are always stubbed; no network.

    cd ~/tools/bounty-run && python3 -m unittest discover -s tests -v
"""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# Make the project root importable regardless of cwd / how the test is invoked.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner import secret_scan as ss  # noqa: E402
from runner import stages, utils  # noqa: E402,F401

HOST = "app.example.com"
HOME = f"https://{HOST}"


class SecretScanBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.outdir = Path(self._tmp.name)
        for p in (
            mock.patch.object(utils, "log"),
            mock.patch.object(utils, "warn"),
        ):
            p.start()
            self.addCleanup(p.stop)
        self.resolve = mock.patch.object(ss, "_resolve", return_value="8.8.8.8").start()
        self.addCleanup(mock.patch.stopall)
        self.is_global = mock.patch.object(ss, "_is_global", return_value=True).start()

    def write_hosts(self, *hosts):
        (self.outdir / "live_hosts.txt").write_text(
            "".join(f"{h}\t200\tTitle\n" for h in hosts)
        )

    def run_scan(self, pages: dict):
        """Run secret_scan with _fetch serving `pages` (url -> body; missing -> "")."""
        self.write_hosts(HOST)
        fetch = mock.patch.object(
            ss, "_fetch", side_effect=lambda url, timeout=ss.FETCH_TIMEOUT: pages.get(url, "")
        ).start()
        return ss.secret_scan(HOST, self.outdir), fetch

    def assert_single(self, findings, name, severity, evidence, url=HOME):
        self.assertEqual(len(findings), 1, findings)
        self.assertEqual(findings[0], {
            "severity": severity,
            "template": "secret-exposure",
            "name": name,
            "url": url,
            "host": HOST,
            "evidence": evidence,
        })


class TestPatterns(SecretScanBase):
    def test_aws_access_key_high(self):
        f, _ = self.run_scan({HOME: "<html>key=AKIAIOSFODNN7EXAMPLE</html>"})
        self.assert_single(f, "Exposed AWS access key", "high", "...MPLE")

    def test_token_high(self):
        f, _ = self.run_scan({HOME: "<p>token: abcdefghijklmnopqrstuvwx1234567890</p>"})
        self.assert_single(f, "Exposed Token", "high", "...7890")

    def test_jwt_high(self):
        jwt = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
               "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
        f, _ = self.run_scan({HOME: f"<div data-x='{jwt}'></div>"})
        self.assert_single(f, "Exposed JWT", "high", "..." + jwt[-4:])

    def test_private_key_high(self):
        f, _ = self.run_scan({HOME: "<pre>-----BEGIN RSA PRIVATE KEY-----\nMIIE...</pre>"})
        self.assert_single(f, "Exposed Private key", "high", "...----")

    def test_generic_api_key_and_password_low(self):
        body = 'var cfg = {api_key = "abcdefghijklmnopqrstuvwx"}; password = "Sup3rSecret!"'
        f, _ = self.run_scan({HOME: body})
        by_name = {x["name"]: x for x in f}
        self.assertEqual(set(by_name), {"Exposed API key", "Exposed Password"})
        for x in f:
            self.assertEqual(x["severity"], "low")
            self.assertEqual(x["url"], HOME)
            self.assertEqual(x["host"], HOST)
        self.assertEqual(by_name["Exposed API key"]["evidence"], "...uvwx")
        self.assertEqual(by_name["Exposed Password"]["evidence"], "...ret!")

    def test_no_secrets_returns_empty(self):
        f, fetch = self.run_scan({HOME: "<html><body><h1>Hello world</h1></body></html>"})
        self.assertEqual(f, [])
        fetch.assert_called_once_with(HOME, ss.FETCH_TIMEOUT)

    def test_http_fallback_when_https_empty(self):
        http_home = f"http://{HOST}"
        f, _ = self.run_scan({http_home: "AKIAIOSFODNN7EXAMPLE"})
        self.assert_single(f, "Exposed AWS access key", "high", "...MPLE", url=http_home)


class TestJsExtraction(SecretScanBase):
    def test_same_origin_scripts_fetched_and_scanned(self):
        jwt = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
               "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
        html = '<script src="app.js"></script><SCRIPT type="x" src=\'/lib/x.js\'></SCRIPT>'
        app_url, lib_url = f"{HOME}/app.js", f"{HOME}/lib/x.js"
        f, fetch = self.run_scan({
            HOME: html,
            app_url: 'const token = "abcdefghijklmnopqrstuvwx1234567890";',
            lib_url: f"let t='{jwt}';",
        })
        self.assertEqual([c.args[0] for c in fetch.call_args_list], [HOME, app_url, lib_url])
        by_name = {x["name"]: x for x in f}
        self.assertEqual(set(by_name), {"Exposed Token", "Exposed JWT"})
        self.assertEqual(by_name["Exposed Token"]["url"], app_url)
        self.assertEqual(by_name["Exposed Token"]["evidence"], "...7890")
        self.assertEqual(by_name["Exposed JWT"]["url"], lib_url)
        self.assertEqual(by_name["Exposed JWT"]["evidence"], "..." + jwt[-4:])

    def test_cross_origin_script_not_fetched(self):
        html = ('<script src="https://cdn.evil.com/x.js"></script>'
                '<script src="javascript:alert(1)"></script>')
        f, fetch = self.run_scan({
            HOME: html,
            "https://cdn.evil.com/x.js": "AKIAIOSFODNN7EXAMPLE",
        })
        self.assertEqual(f, [])
        fetch.assert_called_once_with(HOME, ss.FETCH_TIMEOUT)

    def test_js_fetch_capped(self):
        html = "".join(f'<script src="/js/{i}.js"></script>' for i in range(8))
        _, fetch = self.run_scan({HOME: html})
        self.assertEqual(ss.MAX_JS_FILES, 5)
        self.assertEqual(fetch.call_count, 1 + ss.MAX_JS_FILES)
        self.assertEqual([c.args[0] for c in fetch.call_args_list[1:]],
                         [f"{HOME}/js/{i}.js" for i in range(5)])

    def test_one_finding_per_class_homepage_first(self):
        html = 'AKIAIOSFODNN7EXAMPLE <script src="app.js"></script>'
        f, fetch = self.run_scan({HOME: html, f"{HOME}/app.js": "AKIAABCDEFGHIJKLMNOP"})
        self.assertEqual(fetch.call_count, 2)  # JS still fetched
        self.assert_single(f, "Exposed AWS access key", "high", "...MPLE", url=HOME)

    def test_is_same_origin_helper(self):
        self.assertTrue(ss._is_same_origin("app.js", HOST))
        self.assertTrue(ss._is_same_origin("//APP.example.com:8443/a.js", HOST))
        self.assertTrue(ss._is_same_origin(f"https://{HOST}/a.js", HOST))
        self.assertFalse(ss._is_same_origin("https://cdn.evil.com/a.js", HOST))
        self.assertFalse(ss._is_same_origin("data:text/javascript,alert(1)", HOST))


class TestGuards(SecretScanBase):
    def test_non_global_host_skipped(self):
        self.resolve.return_value = "127.0.0.1"
        self.is_global.side_effect = stages._is_global  # real check
        f, fetch = self.run_scan({HOME: "AKIAIOSFODNN7EXAMPLE"})
        self.assertEqual(f, [])
        fetch.assert_not_called()
        self.resolve.assert_called_once_with(HOST)

    def test_missing_live_hosts_returns_empty(self):
        fetch = mock.patch.object(ss, "_fetch").start()
        self.assertEqual(ss.secret_scan(HOST, self.outdir), [])
        fetch.assert_not_called()
        utils.warn.assert_called_once()

    def test_read_live_hosts_parses_first_column(self):
        p = self.outdir / "live_hosts.txt"
        p.write_text("a.example.com\t200\n\n  \nb.example.com\nc.example.com\t301\tx\n")
        self.assertEqual(ss._read_live_hosts(p),
                         ["a.example.com", "b.example.com", "c.example.com"])


if __name__ == "__main__":
    unittest.main()
