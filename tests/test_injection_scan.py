"""Unit tests for runner.injection_scan (Phase 6, Feature 1).

No network, no external tools — utils.run and the vendored scanners are
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
    _reflected_in_script_context,
    _seed_params,
    _to_schema,
    injection_scan as run_injection_scan,
)
from runner.vendor.advanced_scanners import (  # noqa: E402
    CRLFScanner,
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
        self.assertTrue(hasattr(adv, "CRLFScanner"))
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
        # arithmetic echo probe still present
        jinja = {payload: expected for _, payload, expected in SSTIScanner().payloads["jinja2"]}
        self.assertEqual(jinja["{{7*7}}"], "49")
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


class ToSchemaTest(unittest.TestCase):
    def test_ssti_confirmed_critical_passthrough(self):
        hit = {"severity": "critical", "template_engine": "jinja2", "test_type": "math",
               "url": "http://x/y?a={{7*7}}", "evidence": "expected 49 found"}
        f = _to_schema("ssti", hit, "example.com")
        self.assertEqual(f["severity"], "critical")
        self.assertEqual(f["template"], "spyhunt-ssti")
        self.assertEqual(f["host"], "example.com")
        self.assertEqual(f["url"], "http://x/y?a={{7*7}}")
        self.assertEqual(f["evidence"], "expected 49 found")

    def test_ssti_template_error_high(self):
        hit = {"severity": "high", "template_engine": "twig", "test_type": "env",
               "url": "http://x/y?a={{_self.env}}"}
        f = _to_schema("ssti", hit, "example.com")
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["template"], "spyhunt-ssti")

    def test_nosqli_uses_payload_type_field(self):
        hit = {"severity": "high", "db_type": "mongodb", "payload_type": "ne_bypass",
               "url": "http://x/y?a=1"}
        f = _to_schema("nosqli", hit, "example.com")
        self.assertEqual(f["template"], "spyhunt-nosqli")
        self.assertEqual(f["severity"], "high")

    def test_crlf_uses_payload_type_field(self):
        hit = {"severity": "high", "payload_type": "url_encoded_rn", "url": "http://x/y"}
        f = _to_schema("crlf", hit, "example.com")
        self.assertEqual(f["template"], "spyhunt-crlf")
        self.assertEqual(f["severity"], "high")

    def test_evidence_omitted_when_absent(self):
        hit = {"severity": "high", "payload_type": "x", "url": "u"}
        f = _to_schema("crlf", hit, "example.com")
        self.assertNotIn("evidence", f)

    def test_severity_normalized_to_lowercase(self):
        hit = {"severity": "CRITICAL", "template_engine": "jinja2", "test_type": "math", "url": "u"}
        f = _to_schema("ssti", hit, "example.com")
        self.assertEqual(f["severity"], "critical")


class PureFunctionTest(unittest.TestCase):
    def test_reflected_inside_script_tag_flagged(self):
        self.assertTrue(_reflected_in_script_context(
            "ZZTOK", '<html><script>var x = "ZZTOK";</script></html>'))

    def test_reflected_plain_text_not_flagged(self):
        self.assertFalse(_reflected_in_script_context(
            "ZZTOK", '<html><div>ZZTOK</div></html>'))

    def test_reflected_event_handler_flagged(self):
        self.assertTrue(_reflected_in_script_context(
            "ZZTOK", '<img src=x onerror="alert(\'ZZTOK\')">'))

    def test_token_absent_not_flagged(self):
        self.assertFalse(_reflected_in_script_context(
            "ZZTOK", '<script>var x = 1;</script>'))

    def test_redirect_netloc_differs_flagged(self):
        self.assertTrue(_redirect_target_differs("example.com", "//evil.com"))

    def test_redirect_same_netloc_not_flagged(self):
        self.assertFalse(_redirect_target_differs("example.com", "//example.com/login"))

    def test_redirect_relative_not_flagged(self):
        self.assertFalse(_redirect_target_differs("example.com", "/login"))

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
                    "test_type": "math", "url": "http://example.com/search?a={{7*7}}",
                    "evidence": "49 found"}
        nosqli_hit = {"severity": "high", "db_type": "mongodb",
                      "payload_type": "ne_bypass", "url": "http://example.com/search?a=1"}
        crlf_hit = {"severity": "high", "payload_type": "url_encoded_rn",
                    "url": "http://example.com/search?a=1", "param": "a"}

        def fake_run(cmd, outfile=None, timeout=180):
            return cdx

        with mock.patch.object(utils, "run", fake_run), \
             mock.patch.object(injection_scan, "_is_global_host", return_value=True), \
             mock.patch.object(SSTIScanner, "scan", return_value=[ssti_hit]), \
             mock.patch.object(NoSQLInjectionScanner, "scan", return_value=[nosqli_hit]), \
             mock.patch.object(CRLFScanner, "scan", return_value=[crlf_hit]), \
             mock.patch.object(injection_scan, "_xss_reflected", return_value=None), \
             mock.patch.object(injection_scan, "_open_redirect", return_value=None):
            findings = run_injection_scan("example.com", self.outdir)

        by_t = {f["template"]: f for f in findings}
        self.assertEqual(set(by_t), {"spyhunt-ssti", "spyhunt-nosqli", "spyhunt-crlf"})
        self.assertEqual(by_t["spyhunt-ssti"]["severity"], "critical")
        self.assertEqual(by_t["spyhunt-ssti"]["evidence"], "49 found")
        self.assertEqual(by_t["spyhunt-nosqli"]["severity"], "high")
        self.assertEqual(by_t["spyhunt-crlf"]["severity"], "high")
        for f in findings:
            self.assertEqual(f["host"], "example.com")

    def test_scanner_args_seeded_url_and_param(self):
        cdx = make_cdx(["http://example.com/search?a=1&b=2"])
        calls = {"ssti": [], "nosqli": [], "crlf": []}

        def ssti_scan(self, url, param, timeout=10):
            calls["ssti"].append((url, param))
            return []

        def nosqli_scan(self, url, param, timeout=10):
            calls["nosqli"].append((url, param))
            return []

        def crlf_scan(self, url, timeout=10):
            calls["crlf"].append(url)
            return []

        def fake_run(cmd, outfile=None, timeout=180):
            return cdx

        with mock.patch.object(utils, "run", fake_run), \
             mock.patch.object(injection_scan, "_is_global_host", return_value=True), \
             mock.patch.object(SSTIScanner, "scan", ssti_scan), \
             mock.patch.object(NoSQLInjectionScanner, "scan", nosqli_scan), \
             mock.patch.object(CRLFScanner, "scan", crlf_scan), \
             mock.patch.object(injection_scan, "_xss_reflected", return_value=None), \
             mock.patch.object(injection_scan, "_open_redirect", return_value=None):
            run_injection_scan("example.com", self.outdir)

        # CRLF gets the seeded URL (both params non-blank), no param arg
        self.assertEqual(calls["crlf"], ["http://example.com/search?a=1&b=1"])
        # SSTI + NoSQLi get (seeded_url, param) for each of a and b
        self.assertEqual([p for _, p in calls["ssti"]], ["a", "b"])
        self.assertEqual([p for _, p in calls["nosqli"]], ["a", "b"])
        for url, _ in calls["ssti"] + calls["nosqli"]:
            self.assertEqual(url, "http://example.com/search?a=1&b=1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
