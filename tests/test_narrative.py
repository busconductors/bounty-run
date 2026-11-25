import json

from runner.finding import fingerprint_of
from runner.narrative import FALLBACK_COPY, extract_nuclei_narrative, narrative_for


def test_extract_nuclei_narrative_reads_info_block(tmp_path):
    recs = [
        {
            "template-id": "cve-2021-1",
            "host": "a.example.com",
            "matched-at": "https://a.example.com/x",
            "info": {
                "description": "Bad thing.",
                "reference": ["https://ref/1", "https://ref/2"],
                "classification": {"cvss-score": 9.8, "cwe-id": ["CWE-79"]},
            },
        },
        {
            "template-id": "misc-2",
            "host": "b.example.com",
            "matched-at": "https://b.example.com/",
            "info": {
                "description": "Other.",
                "reference": "https://ref/3",
                "classification": {"cvss-score": "5.3", "cwe-id": "CWE-200"},
            },
        },
    ]
    (tmp_path / "nuclei0.jsonl").write_text("\n".join(json.dumps(r) for r in recs) + "\n")
    out = extract_nuclei_narrative(tmp_path)
    fp1 = fingerprint_of("cve-2021-1", "a.example.com", "https://a.example.com/x")
    fp2 = fingerprint_of("misc-2", "b.example.com", "https://b.example.com/")
    assert set(out) == {fp1, fp2}
    assert out[fp1] == {"description": "Bad thing.",
                        "reference": ["https://ref/1", "https://ref/2"],
                        "cvss": 9.8, "cwe": ["CWE-79"]}
    assert out[fp2] == {"description": "Other.", "reference": ["https://ref/3"],
                        "cvss": 5.3, "cwe": ["CWE-200"]}


def test_extract_nuclei_narrative_missing_info_yields_empty_fields(tmp_path):
    rec = {"template-id": "t", "host": "h", "matched-at": "https://h/"}
    (tmp_path / "nuclei0.jsonl").write_text(json.dumps(rec) + "\n\nnot json\n")
    out = extract_nuclei_narrative(tmp_path)
    fp = fingerprint_of("t", "h", "https://h/")
    assert out == {fp: {"description": None, "reference": [], "cvss": None, "cwe": []}}


def test_narrative_for_prefers_metadata():
    f = {"template": "cors-misconfiguration:reflect", "severity": "high"}
    meta = {"description": "Nuclei says.", "reference": ["https://ref/1"],
            "cvss": 7.5, "cwe": ["CWE-942"],
            "impact": "Custom impact.", "remediation": "Custom fix."}
    out = narrative_for(f, meta)
    assert out == {"description": "Nuclei says.", "impact": "Custom impact.",
                   "remediation": "Custom fix.", "reference": ["https://ref/1"],
                   "cvss": 7.5, "cwe": ["CWE-942"]}


def test_narrative_for_metadata_without_impact_uses_category_fallback():
    f = {"template": "cors-misconfiguration:reflect"}
    meta = {"description": "D.", "reference": [], "cvss": None, "cwe": []}
    out = narrative_for(f, meta)
    assert out["description"] == "D."
    assert out["impact"] == FALLBACK_COPY["cors"]["impact"]
    assert out["remediation"] == FALLBACK_COPY["cors"]["remediation"]


def test_narrative_for_falls_back_by_category():
    f = {"template": "missing-security-header:content-security-policy"}
    out = narrative_for(f, None)
    assert out["impact"] == FALLBACK_COPY["headers_missing"]["impact"] != ""
    assert out["remediation"] == FALLBACK_COPY["headers_missing"]["remediation"] != ""
    assert out["description"] == ""
    assert out["reference"] == [] and out["cwe"] == [] and out["cvss"] is None


def test_narrative_for_unknown_category_returns_empty():
    out = narrative_for({"template": "some-random-template"}, None)
    assert out == {"description": "", "impact": "", "remediation": "",
                   "reference": [], "cvss": None, "cwe": []}
    assert narrative_for({}, None)["impact"] == ""


def test_fallback_copy_keys_are_real_categories():
    from runner.categories import BY_KEY
    assert set(FALLBACK_COPY) <= set(BY_KEY)
    assert all(v["impact"] and v["remediation"] for v in FALLBACK_COPY.values())
