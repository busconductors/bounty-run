"""Tests for the single category registry."""
from runner import categories, report


class TestClassify:
    def test_each_prefix_and_exact(self):
        cases = {
            "metis:auxiliary/x": "metis",
            "secret-exposure": "secret",
            "sqlmap-sqli": "sqli",
            "missing-security-header:csp": "headers_missing",
            "insecure-security-header:hsts": "headers_insecure",
            "cors-misconfiguration:reflected": "cors",
            "headi:x-forwarded-host": "headi",
            "nmap:80": "nmap",
            "tech-detect:nginx": "tech",
            "api-endpoint": "api",
            "panel:grafana": "panel",
            "waf:cloudflare": "waf",
            "dork:github": "dork",
            "tls:weak-cipher": "tls",
            "nikto:osvdb-1234": "nikto",
        }
        for template, key in cases.items():
            assert categories.classify(template).key == key, template

    def test_non_str_is_nuclei(self):
        assert categories.classify(None) is categories.NUCLEI
        assert categories.classify(123) is categories.NUCLEI

    def test_tech_detect_without_colon_is_nuclei(self):
        # Guards test_phase7b_wiring.py:49.
        assert categories.classify("tech-detect") is categories.NUCLEI

    def test_unmatched_is_nuclei(self):
        assert categories.classify("CVE-2021-1234") is categories.NUCLEI


class TestLabels:
    def test_labels_match_legacy_build_metrics(self):
        # These label strings are pinned byte-for-byte by TestBuildMetrics.
        expected = {
            "metis": "Metis",
            "secret": "Secret-exposure",
            "sqli": "sqlmap-sqli",
            "headers_missing": "Missing security headers",
            "headers_insecure": "Insecure security headers",
            "cors": "CORS misconfigurations",
            "headi": "Header injection (headi)",
            "nmap": "Open ports (nmap)",
            "tech": "Technologies (whatweb)",
            "api": "API endpoints (katana)",
            "panel": "High-value panels (subdomains)",
            "waf": "WAF detections (wafw00f)",
            "dork": "Dork hits (OSINT)",
            "tls": "TLS/SSL issues (sslyze)",
            "nikto": "Nikto findings",
        }
        assert {c.key: c.label for c in categories.CATEGORIES} == expected


class TestCounting:
    def test_count_by_category(self):
        fs = [
            {"template": "panel:x", "severity": "info"},
            {"template": "panel:y", "severity": "info"},
            {"template": "tls:weak", "severity": "low"},
            {"template": "CVE-x", "severity": "high"},
        ]
        counts = categories.count_by_category(fs)
        assert counts["panel"] == 2
        assert counts["tls"] == 1
        assert counts["nuclei"] == 1

    def test_by_category(self):
        fs = [{"template": "panel:x"}, {"template": "tls:y"}]
        assert categories.by_category(fs, "panel") == [fs[0]]


class TestIsCandidate:
    def test_panel_is_candidate_at_any_severity(self):
        assert categories.is_candidate({"template": "panel:x", "severity": "info"})

    def test_high_med_crit_are_candidates(self):
        for sev in ("critical", "high", "medium"):
            assert categories.is_candidate({"template": "CVE", "severity": sev})

    def test_low_info_not_candidates(self):
        assert not categories.is_candidate({"template": "CVE", "severity": "low"})
        assert not categories.is_candidate({"template": "CVE", "severity": "info"})

    def test_non_str_template_no_crash(self):
        assert not categories.is_candidate({"template": None, "severity": "low"})


class TestBuildMetricsParity:
    """build_metrics output must stay byte-identical after the registry swap."""

    def test_mixed_findings(self):
        fs = [
            {"template": "secret-exposure", "severity": "high"},
            {"template": "panel:grafana", "severity": "info"},
            {"template": "metis:aux/x", "severity": "critical"},
            {"template": "CVE-1", "severity": "high"},
            {"template": "CVE-2", "severity": "high"},
            {"template": "tls:weak", "severity": "low"},
        ]
        m = dict(report.build_metrics("ex.com", [], [], {}, None, fs, [], 1.0))
        assert m["Secret-exposure"] == "1"
        assert m["High-value panels (subdomains)"] == "1"
        assert m["Metis"] == "1"
        assert m["TLS/SSL issues (sslyze)"] == "1"
        assert m["Nuclei findings — high"] == "2"
        assert m["Total unique findings"] == "6"
