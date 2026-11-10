"""Round-trip tests for the Finding dataclass against real producer shapes."""
from runner.finding import Finding, as_dicts, coerce

# Representative producer dict shapes drawn from the exact-dict tests in §0.
SECRET = {
    "severity": "high", "template": "secret-exposure", "name": "AWS key",
    "url": "https://example.com/.env", "host": "example.com", "evidence": "AKIA…1234",
}
SQLMAP = {
    "severity": "high", "template": "sqlmap-sqli", "name": "SQL injection",
    "url": "http://example.com/id?a=", "host": "example.com",
}
METIS = {
    "severity": "critical",
    "template": "metis:auxiliary/scanner/fortinet_cve_2025_64446",
    "name": "FortiWeb Authentication Bypass (CVE-2025-64446)",
    "url": "https://example.com", "host": "example.com",
}
NUCLEI = {
    "severity": "info", "template": "tech-detect:nginx", "name": "nginx",
    "url": "https://example.com", "host": "example.com",
}
DORK_NONE_HOST = {
    "severity": "info", "template": "dork:github", "name": "exposed repo",
    "url": "https://example.com/x", "host": None,
}

ALL_SHAPES = [SECRET, SQLMAP, METIS, NUCLEI, DORK_NONE_HOST]


class TestRoundTrip:
    def test_all_producer_shapes_round_trip(self):
        for shape in ALL_SHAPES:
            assert Finding.from_dict(shape).to_dict() == shape

    def test_key_order_preserved(self):
        d = Finding.from_dict(SECRET).to_dict()
        assert list(d.keys()) == ["severity", "template", "name", "url", "host", "evidence"]

    def test_evidence_omitted_when_none(self):
        d = Finding.from_dict(SQLMAP).to_dict()
        assert "evidence" not in d
        assert list(d.keys()) == ["severity", "template", "name", "url", "host"]

    def test_host_none_preserved(self):
        assert Finding.from_dict(DORK_NONE_HOST).to_dict()["host"] is None


class TestFromDictTolerance:
    def test_missing_name_falls_back_to_template(self):
        f = Finding.from_dict({"template": "t", "url": "u", "host": "h"})
        assert f.name == "t"

    def test_non_str_template_becomes_empty(self):
        f = Finding.from_dict({"template": 123, "name": "n", "url": "u", "host": "h"})
        assert f.template == ""

    def test_metis_freeform_severity_kept(self):
        f = Finding.from_dict({"severity": "Needs review", "template": "metis:x",
                               "name": "n", "url": "u", "host": "h"})
        assert f.severity == "Needs review"
        assert f.level.value == "unknown"

    def test_missing_severity_defaults_unknown(self):
        assert Finding.from_dict({"template": "t"}).severity == "unknown"


class TestExtended:
    def test_extended_adds_fields(self):
        f = Finding.from_dict(SECRET)
        f = Finding(severity=f.severity, template=f.template, name=f.name,
                    url=f.url, host=f.host, evidence=f.evidence,
                    stage="secret", target="example.com")
        d = f.to_dict(extended=True)
        assert d["stage"] == "secret"
        assert d["target"] == "example.com"
        assert d["fingerprint"] == f.fingerprint
        assert d["evidence_refs"] == []

    def test_level_property(self):
        assert Finding.from_dict(SECRET).level.value == "high"

    def test_fingerprint_stable(self):
        f = Finding.from_dict(SECRET)
        assert len(f.fingerprint) == 12


class TestCoerce:
    def test_coerce_passthrough(self):
        f = Finding.from_dict(SECRET)
        assert coerce(f) is f

    def test_coerce_mapping(self):
        assert isinstance(coerce(SECRET), Finding)

    def test_as_dicts_round_trip(self):
        mixed = [SECRET, coerce(SQLMAP)]
        assert as_dicts(mixed) == [SECRET, SQLMAP]
