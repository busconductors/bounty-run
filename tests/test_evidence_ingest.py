"""C17: nuclei raw ingest + tool-artifact linking."""
import json
import shutil
from pathlib import Path

from runner import evidence, finding
from runner.evidence import EvidenceStore

FIXTURE = Path(__file__).parent / "fixtures" / "nuclei_raw.jsonl"


class TestIngestNuclei:
    def test_ingests_raw_and_links_omitted(self, tmp_path):
        shutil.copy(FIXTURE, tmp_path / "nuclei.jsonl")
        store = EvidenceStore(tmp_path)
        n = evidence.ingest_nuclei(store, tmp_path)
        assert n == 2
        # first finding has raw request/response
        fp = finding.fingerprint_of("CVE-2021-1234", "example.com",
                                    "https://example.com/vuln")
        d = tmp_path / "evidence" / fp / "1"
        assert (d / "request.http").exists()
        req = (d / "request.http").read_text()
        assert "supersecret" not in req   # redacted
        assert "<redacted>" in req

    def test_omit_raw_links_jsonl(self, tmp_path):
        shutil.copy(FIXTURE, tmp_path / "nuclei.jsonl")
        store = EvidenceStore(tmp_path)
        evidence.ingest_nuclei(store, tmp_path)
        # second finding (tech-detect) had no request/response -> linked jsonl
        fp = finding.fingerprint_of("tech-detect", "example.com", "https://example.com")
        meta = json.loads((tmp_path / "evidence" / fp / "1" / "meta.json").read_text())
        assert any("nuclei.jsonl" in a for a in meta["artifacts"])


class TestLinkToolArtifacts:
    def test_links_nmap_and_nikto(self, tmp_path):
        (tmp_path / "nmap.xml").write_text("<nmaprun/>")
        (tmp_path / "nmap_open_ports.txt").write_text("80\n")
        (tmp_path / "nikto").mkdir()
        (tmp_path / "nikto" / "example.com.json").write_text("{}")
        findings = [
            {"template": "nmap:80", "host": "example.com", "url": ""},
            {"template": "nikto:osvdb-1", "host": "example.com", "url": "https://example.com"},
        ]
        store = EvidenceStore(tmp_path)
        linked = evidence.link_tool_artifacts(store, findings, tmp_path)
        assert linked == 2
        # relative paths only
        store.flush()
        for fp_dir in (tmp_path / "evidence").glob("*/1/meta.json"):
            meta = json.loads(fp_dir.read_text())
            for a in meta["artifacts"]:
                assert not a.startswith("/")

    def test_missing_artifact_not_linked(self, tmp_path):
        findings = [{"template": "nmap:80", "host": "h", "url": ""}]
        store = EvidenceStore(tmp_path)
        assert evidence.link_tool_artifacts(store, findings, tmp_path) == 0
