"""Tests for runner.finding: severity order, normalisation, fingerprints."""
import hashlib

from runner import finding


class TestSeverityOrder:
    def test_order_matches_legacy_tuple(self):
        # Legacy report/cli used this exact ordering.
        assert finding.SEVERITY_ORDER == {
            "critical": 0, "high": 1, "medium": 2,
            "low": 3, "info": 4, "unknown": 5,
        }

    def test_severity_enum_values(self):
        assert [s.value for s in finding.Severity] == [
            "critical", "high", "medium", "low", "info", "unknown",
        ]

    def test_display_order_excludes_unknown(self):
        # dashboard._SEVERITY_ORDER / cli.SEVERITIES derive from this.
        display = tuple(
            s.value for s in finding.Severity if s is not finding.Severity.UNKNOWN
        )
        assert display == ("critical", "high", "medium", "low", "info")


class TestNormalizeSeverity:
    def test_none_and_empty_become_unknown(self):
        assert finding.normalize_severity(None) == "unknown"
        assert finding.normalize_severity("") == "unknown"
        assert finding.normalize_severity("   ") == "unknown"

    def test_lowercases(self):
        assert finding.normalize_severity("HIGH") == "high"
        assert finding.normalize_severity("Critical") == "critical"

    def test_metis_freeform_severity_preserved(self):
        # metis passes free-form text through; it must survive lowercased.
        assert finding.normalize_severity("Needs manual review") == "needs manual review"


class TestSeverityRank:
    def test_known_severities(self):
        assert finding.severity_rank("critical") == 0
        assert finding.severity_rank("info") == 4
        assert finding.severity_rank("unknown") == 5

    def test_unknown_string_sorts_last(self):
        assert finding.severity_rank("totally-made-up") == 9

    def test_none_is_unknown(self):
        assert finding.severity_rank(None) == 5


class TestNormalizeUrl:
    def test_empty(self):
        assert finding.normalize_url("") == ""

    def test_lowercases_scheme_and_host(self):
        assert finding.normalize_url("HTTP://Example.COM/Path") == "http://example.com/Path"

    def test_strips_default_ports(self):
        assert finding.normalize_url("http://example.com:80/") == "http://example.com"
        assert finding.normalize_url("https://example.com:443/") == "https://example.com"

    def test_keeps_nondefault_port(self):
        assert finding.normalize_url("http://example.com:8080/") == "http://example.com:8080"

    def test_strips_trailing_slash_only_when_path_empty(self):
        assert finding.normalize_url("https://example.com/") == "https://example.com"
        assert finding.normalize_url("https://example.com/a/") == "https://example.com/a/"

    def test_preserves_query_and_fragment(self):
        assert finding.normalize_url("https://x.com/p?q=1#f") == "https://x.com/p?q=1#f"

    def test_bare_host_best_effort(self):
        assert finding.normalize_url("Example.com") == "example.com"


class TestFingerprint:
    def test_stable_12_hex(self):
        fp = finding.fingerprint_of("tls:weak-cipher", "example.com", "https://example.com/")
        assert len(fp) == 12
        assert all(c in "0123456789abcdef" for c in fp)

    def test_matches_manual_sha1(self):
        key = "\x1f".join(("t", "h", finding.normalize_url("https://H.com/")))
        expected = hashlib.sha1(key.encode("utf-8", "surrogatepass")).hexdigest()[:12]
        assert finding.fingerprint_of("t", "h", "https://H.com/") == expected

    def test_url_normalisation_collapses_trailing_slash(self):
        a = finding.fingerprint_of("t", "h", "https://example.com/")
        b = finding.fingerprint_of("t", "h", "https://example.com")
        assert a == b

    def test_none_fields_tolerated(self):
        assert len(finding.fingerprint_of(None, None, None)) == 12
