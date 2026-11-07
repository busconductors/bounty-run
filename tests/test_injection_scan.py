"""Unit tests for runner.injection_scan (Phase 6, Feature 1).

No network, no external tools -- utils.run and the vendored scanners are
monkeypatched. Run with stdlib unittest:

    cd ~/tools/bounty-run && python3 -m unittest discover -s tests -v
    # or directly:
    python3 tests/test_injection_scan.py -v
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# Make the project root importable regardless of cwd / how the test is invoked.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner import injection_scan, utils  # noqa: E402
from runner.injection_scan import (  # noqa: E402
    _param_names,
    _redirect_target_differs,
    _seed_params,
    _to_schema,
    _xss_payload_reflected,
    injection_scan as run_injection_scan,
)
from runner.vendor.advanced_scanners import (  # noqa: E402
    NoSQLInjectionScanner,
    SSTIScanner,
)


def make_cdx(urls):
    """Build the CDX JSON body: a header row followed by one row per URL."""
    return json.dumps([["original"]] + [[u] for u in urls])


class VendorImportTest(unittest.TestCase):
    def test_import_clean_no_colorama(self):
        import runner.vendor.advanced_scanners as adv
        self.assertTrue(hasattr(adv, "SSTIScanner"))
        self.assertTrue(hasattr(adv, "NoSQLInjectionScanner"))
        self.assertFalse(hasattr(adv, "CRLFScanner"))
        src = Path(adv.__file__).read_text()
        self.assertNotIn("import colorama", src)
        self.assertNotIn("from colorama", src)
        self.assertNotIn("Fore", src)
        self.assertNotIn("Style", src)

    def test_ssti_payloads_have_no_rce_or_config(self):
        for engine, payloads in SSTIScanner().payloads.items():
            for test_type, payload, _expected in payloads:
                self.assertNotIn("os.popen", payload)
                self.assertNotIn("Execute", payload)
                self.assertNotIn("`id`", payload)
                self.assertNotIn("{php}", payload)
                self.assertNotIn("{{config}}", payload)
                self.assertNotIn("config", test_type)
                self.assertNotIn("rce", test_type)
        # arithmetic echo probe now uses the unique canary
        jinja = {payload: expected for _, payload, expected in SSTIScanner().payloads["jinja2"]}
        self.assertEqual(jinja["{{7777777*7777777}}"], "60493827160493827")
        # non-executing fingerprint probe still present
        twig_types = {t for t, _, _ in SSTIScanner().payloads["twig"]}
        self.assertIn("env", twig_types)

    def test_nosql_payloads_have_no_sleep_or_js_injection(self):
        flat = []
        for db, payloads in NoSQLInjectionScanner().payloads.items():
            for ptype, payload in payloads:
                flat.append((ptype, payload))
        types = {t for t, _ in flat}
        self.assertNotIn("where_sleep", types)
        self.assertNotIn("js_injection", types)
        for _, payload in flat:
            self.assertNotIn("sleep(5000)", payload)


class SstiUniqueCanaryTest(unittest.TestCase):
    """SPEC-PHASE6.1 item 3: unique canary, no 49-substring false positives."""

    def test_math_payloads_use_unique_canary(self):
        for engine, payloads in SSTIScanner().payloads.items():
            for test_type, payload, expected in payloads:
                if test_type != "math":
                    continue
                self.assertIn("7777777*7777777", payload)
                self.assertNotIn("{{7*7}}", payload)
                self.assertNotIn("${7*7}", payload)
                self.assertEqual(expected, "60493827160493827")

    def test_no_false_positive_on_number_49(self):
        scanner = SSTIScanner()
        fake_resp = mock.Mock()
        fake_resp.text = "search returned 49 results on page 49 of 49"
        with mock.patch("requests.get", return_value=fake_resp):
            findings = scanner.scan("http://example.com/search?a=1", "a")
        self.assertEqual(findings, [])

    def test_flags_on_unique_canary(self):
        scanner = SSTIScanner()
        fake_resp = mock.Mock()
        fake_resp.text = "computed: 60493827160493827"
        with mock.patch("requests.get", return_value=fake_resp):
            findings = scanner.scan("http://example.com/search?a=1", "a")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["severity"], "critical")
        self.assertIn("60493827160493827", findings[0]["evidence"])


class ToSchemaTest(unittest.TestCase):
    def test_ssti_confirmed_critical_passthrough(self):
        hit = {"severity": "critical", "template_engine": "jinja2", "test_type": "math",
               "url": "http://x/y?a={{7777777*7777777}}", "evidence": "expected 60493827160493827 found"}
        f = _to_schema("ssti", hit, "example.com")
        self.assertEqual(f["severity"], "critical")
        self.assertEqual(f["template"], "spyhunt-ssti")
        self.assertEqual(f["host"], "example.com")
        self.assertEqual(f["url"], "http://x/y?a={{7777777*7777777}}")
        self.assertEqual(f["evidence"], "expected 60493827160493827 found")

    def test_ssti_template_error_high(self):
        hit = {"severity": "high", "template_engine": "twig", "test_type": "env",
               "url": "http://x/y?a={{_self.env}}"}
        f = _to_schema("ssti", hit, "example.com")
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["template"], "spyhunt-ssti")

    def test_nosqli_mapped_to_medium(self):
        hit = {"severity": "high", "db_type": "mongodb", "payload_type": "ne_bypass",
               "url": "http://x/y?a=1"}
        f = _to_schema("nosqli", hit, "example.com")
        self.assertEqual(f["template"], "spyhunt-nosqli")
        self.assertEqual(f["severity"], "medium")

    def test_evidence_omitted_when_absent(self):
        hit = {"severity": "high", "db_type": "mongodb", "payload_type": "x", "url": "u"}
        f = _to_schema("nosqli", hit, "example.com")
        self.assertNotIn("evidence", f)

    def test_severity_normalized_to_lowercase(self):
        hit = {"severity": "CRITICAL", "template_engine": "jinja2", "test_type": "math", "url": "u"}
        f = _to_schema("ssti", hit, "example.com")
        self.assertEqual(f["severity"], "critical")


class PureFunctionTest(unittest.TestCase):
    def test_script_payload_reflected_unescaped_flagged(self):
        self.assertTrue(_xss_payload_reflected(
            "<script>alert(1)</script>", "<html><script>alert(1)</script></html>"))

    def test_script_payload_html_escaped_not_flagged(self):
        self.assertFalse(_xss_payload_reflected(
            "<script>alert(1)</script>", "<html>&lt;script&gt;alert(1)&lt;/script&gt;</html>"))

    def test_event_payload_reflected_flagged(self):
        self.assertTrue(_xss_payload_reflected(
            "<img src=x onerror=alert(1)>", "<html><img src=x onerror=alert(1)></html>"))

    def test_payload_absent_not_flagged(self):
        self.assertFalse(_xss_payload_reflected(
            "<script>alert(1)</script>", "<html><div>safe</div></html>"))

    def test_plain_text_token_not_flagged(self):
        self.assertFalse(_xss_payload_reflected(
            "zzzrandom", "<html>zzzrandom</html>"))

    def test_redirect_absolute_external_flagged(self):
        self.assertTrue(_redirect_target_differs("example.com", "https://evil.com"))

    def test_redirect_absolute_http_external_flagged(self):
        self.assertTrue(_redirect_target_differs("example.com", "http://evil.com"))

    def test_redirect_protocol_relative_not_flagged(self):
        self.assertFalse(_redirect_target_differs("example.com", "//evil.com"))

    def test_redirect_same_netloc_not_flagged(self):
        self.assertFalse(_redirect_target_differs("example.com", "https://example.com/login"))

    def test_redirect_relative_not_flagged(self):
        self.assertFalse(_redirect_target_differs("example.com", "/login"))

    def test_redirect_non_http_scheme_not_flagged(self):
        self.assertFalse(_redirect_target_differs("example.com", "ftp://evil.com"))

    def test_redirect_empty_not_flagged(self):
        self.assertFalse(_redirect_target_differs("example.com", ""))

    def test_param_names_keep_blank_and_dedupe(self):
        self.assertEqual(_param_names("http://x/y?a=&b=&a="), ["a", "b"])

    def test_seed_params_gives_nonblank_values(self):
        self.assertEqual(_seed_params("http://x/y?a=&b="), "http://x/y?a=1&b=1")


class InjectionScanTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.outdir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_end_to_end_schema_mapping(self):
        cdx = make_cdx(["http://example.com/search?a=1"])
        ssti_hit = {"severity": "critical", "template_engine": "jinja2",
                    "test_type": "math", "url": "http://example.com/search?a={{7777777*7777777}}",
                    "evidence": "60493827160493827 found"}
        nosqli_hit = {"severity": "high", "db_type": "mongodb",
                      "payload_type": "ne_bypass", "url": "http://example.com/search?a=1"}

        def fake_run(cmd, outfile=None, timeout=180):
            return cdx

        with mock.patch.object(utils, "run", fake_run), \
             mock.patch.object(injection_scan, "_is_global_host", return_value=True), \
             mock.patch.object(SSTIScanner, "scan", return_value=[ssti_hit]), \
             mock.patch.object(NoSQLInjectionScanner, "scan", return_value=[nosqli_hit]), \
             mock.patch.object(injection_scan, "_xss_reflected", return_value=None), \
             mock.patch.object(injection_scan, "_open_redirect", return_value=None):
            findings = run_injection_scan("example.com", self.outdir)

        by_t = {f["template"]: f for f in findings}
        self.assertEqual(set(by_t), {"spyhunt-ssti", "spyhunt-nosqli"})
        self.assertEqual(by_t["spyhunt-ssti"]["severity"], "critical")
        self.assertEqual(by_t["spyhunt-ssti"]["evidence"], "60493827160493827 found")
        self.assertEqual(by_t["spyhunt-nosqli"]["severity"], "medium")
        for f in findings:
            self.assertEqual(f["host"], "example.com")

    def test_scanner_args_seeded_url_and_param(self):
        cdx = make_cdx(["http://example.com/search?a=1&b=2"])
        calls = {"ssti": [], "nosqli": []}

        def ssti_scan(self, url, param, timeout=10):
            calls["ssti"].append((url, param))
            return []

        def nosqli_scan(self, url, param, timeout=10):
            calls["nosqli"].append((url, param))
            return []

        def fake_run(cmd, outfile=None, timeout=180):
            return cdx

        with mock.patch.object(utils, "run", fake_run), \
             mock.patch.object(injection_scan, "_is_global_host", return_value=True), \
             mock.patch.object(SSTIScanner, "scan", ssti_scan), \
             mock.patch.object(NoSQLInjectionScanner, "scan", nosqli_scan), \
             mock.patch.object(injection_scan, "_xss_reflected", return_value=None), \
             mock.patch.object(injection_scan, "_open_redirect", return_value=None):
            run_injection_scan("example.com", self.outdir)

        # SSTI + NoSQLi get (seeded_url, param) for each of a and b
        self.assertEqual([p for _, p in calls["ssti"]], ["a", "b"])
        self.assertEqual([p for _, p in calls["nosqli"]], ["a", "b"])
        for url, _ in calls["ssti"] + calls["nosqli"]:
            self.assertEqual(url, "http://example.com/search?a=1&b=1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
