"""findings.index.json: fingerprints parallel to findings.json."""
import json
from unittest import mock

from runner import evidence, finding, report
from runner.evidence import EvidenceStore


def _f(template, severity, url, host="a.com"):
    return {"severity": severity, "template": template, "name": template,
            "url": url, "host": host, "evidence": ""}


FINDINGS = [
    _f("low-one", "low", "https://a.com/low"),
    _f("crit-one", "critical", "HTTPS://A.com:443/"),
    _f("low-one", "low", "https://a.com/low"),  # duplicate
    _f("high-one", "high", "https://a.com/high?x=1"),
]


def _write(outdir, findings=None):
    report.write_findings_report(outdir, "a.com", list(findings or FINDINGS), [])
    return (json.loads((outdir / "findings.json").read_text()),
            json.loads((outdir / "findings.index.json").read_text()))


def test_findings_json_bytes_unchanged(tmp_path):
    report.write_findings_report(tmp_path, "a.com", list(FINDINGS), [])
    expected = report.dedupe(list(FINDINGS))
    expected.sort(key=lambda f: finding.severity_rank(f.get("severity", "unknown")))
    assert (tmp_path / "findings.json").read_text() == json.dumps(expected, indent=2)


def test_index_parallel_to_findings(tmp_path):
    stored, index = _write(tmp_path)
    assert len(index) == len(stored) == 3
    assert index == [evidence.finding_fp(f) for f in stored]


def test_index_matches_evidence_dirs(tmp_path):
    store = EvidenceStore(tmp_path)
    for f in FINDINGS:
        store.record_raw(f, "GET /", "ok")
    _, index = _write(tmp_path)
    dirs = {p.name for p in (tmp_path / "evidence").iterdir() if p.is_dir()}
    assert set(index) == dirs


def test_index_empty_when_no_findings(tmp_path):
    report.write_findings_report(tmp_path, "a.com", [], [])
    assert json.loads((tmp_path / "findings.index.json").read_text()) == []


def test_index_survives_unparsable_url(tmp_path):
    bad = _f("bad-port", "low", "https://a.com:notaport/")
    stored, index = _write(tmp_path, [bad, FINDINGS[0]])
    assert len(index) == len(stored) == 2
    assert index[0] is None
    assert index[1] == evidence.finding_fp(FINDINGS[0])


def test_index_written_atomically_in_same_dir(tmp_path):
    real = report.os.replace
    calls = []

    def spy(src, dst):
        calls.append((str(src), str(dst)))
        real(src, dst)
    with mock.patch.object(report.os, "replace", side_effect=spy):
        report.write_findings_report(tmp_path, "a.com", list(FINDINGS), [])
    assert len(calls) == 1
    src, dst = calls[0]
    assert dst == str(tmp_path / "findings.index.json")
    assert src != dst and src.startswith(str(tmp_path))
    assert [p.name for p in tmp_path.glob("*.tmp")] == []
