"""CLI parser: engagement identity flags for the report cover page."""
import json
from pathlib import Path

from runner import cli


def test_parse_engagement_identity_args():
    p = cli.build_parser()
    d = p.parse_args(["example.com"])
    assert d.client is None and d.engagement is None
    assert d.prepared_by is None and d.team is None
    a = p.parse_args(["example.com", "--client", "Acme Corp",
                      "--engagement", "Q4 External Assessment",
                      "--prepared-by", "J. Doe", "--team", "STRASSER"])
    assert a.client == "Acme Corp"
    assert a.engagement == "Q4 External Assessment"
    assert a.prepared_by == "J. Doe"
    assert a.team == "STRASSER"


def test_finish_threads_context_into_summary(tmp_path):
    import argparse
    from types import SimpleNamespace
    from runner import evidence, scope

    outdir = tmp_path
    try:
        f = {"template": "exposed-panel", "host": "a.example.com",
             "url": "https://a.example.com/admin", "severity": "high",
             "name": "Exposed admin panel"}
        fp = cli.finding.fingerprint_of(f["template"], f["host"], f["url"])
        (outdir / "nuclei.jsonl").write_text(json.dumps({
            "template-id": f["template"], "host": f["host"], "matched-at": f["url"],
            "info": {"description": "Admin console reachable without auth"}}) + "\n")
        st = cli.RunState("example.com", findings=[f])
        st.provenance[fp] = "nuclei"
        scope.log().clear()
        scope.log().record("host", "evil.other.net", "dork")
        evidence.reset()
        store = evidence.EvidenceStore(outdir)
        evidence.activate(store)
        req = SimpleNamespace(method="GET", url=f["url"], headers={}, body=None)
        resp = SimpleNamespace(url=f["url"], status_code=200, headers={},
                               content=b"admin", text="admin")
        store.record(req, resp, finding=f)
        args = argparse.Namespace(client=None, engagement=None, prepared_by=None,
                                  team=None, no_track=True)
        rc = cli._finish(args, "example.com", outdir, set(), st)
        assert rc == 0
        html = (outdir / "summary.html").read_text()
        assert "nuclei" in html                 # provenance appendix
        assert "evil.other.net" in html         # out-of-scope drop
        assert "Stages executed" in html
        assert "curl" in html                   # evidence repro
        assert "Admin console reachable without auth" in html  # narrative
    finally:
        evidence.reset()
        scope.log().clear()
