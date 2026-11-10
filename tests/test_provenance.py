"""C19: stage provenance recorded by fingerprint, findings dicts unchanged."""
from unittest import mock

from runner import cli, finding, scope


def test_provenance_maps_fingerprint_to_stage(tmp_path):
    scope.reset()
    st = cli.RunState("example.com")

    panel_finding = {"severity": "high", "template": "panel:grafana", "name": "Grafana",
                     "url": "https://example.com", "host": "example.com"}
    secret_finding = {"severity": "high", "template": "secret-exposure", "name": "AWS key",
                      "url": "https://example.com/.env", "host": "example.com",
                      "evidence": "...1234"}

    args = cli.build_parser().parse_args(["example.com"])

    def fake_pipeline(a, target, outdir, skip, state):
        # Simulate panel + secret stages through the real _pipeline helpers by
        # calling the module's scan path indirectly: just stamp via RunState.
        pass

    # Drive _pipeline directly with mocked stage functions.
    with mock.patch.object(cli.stages, "subdomain_enum", return_value=[]), \
         mock.patch.object(cli.panel_detect, "panel_detect", return_value=[panel_finding]), \
         mock.patch.object(cli.stages, "live_hosts", return_value=[]), \
         mock.patch.object(cli.stages, "cloudflare_detect",
                           return_value={"cloudflare": False}), \
         mock.patch.object(cli.secret_scan, "secret_scan", return_value=[secret_finding]), \
         mock.patch.object(cli.stages, "vuln_scan", return_value=[]), \
         mock.patch.object(cli.stages, "content_discovery", return_value=[]), \
         mock.patch.object(cli.api_endpoints, "api_endpoints_scan", return_value=[]), \
         mock.patch.object(cli.param_scan, "param_scan", return_value=[]), \
         mock.patch.object(cli.http_headers, "security_headers_scan", return_value=[]), \
         mock.patch.object(cli.http_headers, "cors_scan", return_value=[]), \
         mock.patch.object(cli.tech_scan, "tech_scan", return_value=[]), \
         mock.patch.object(cli.waf_scan, "waf_scan", return_value=[]), \
         mock.patch.object(cli.dork_scan, "dork_scan", return_value=[]), \
         mock.patch.object(cli.utils, "stage_header"), \
         mock.patch.object(cli.utils, "log"), \
         mock.patch.object(cli, "write_summary"):
        cli._pipeline(args, "example.com", tmp_path, set(), st)

    panel_fp = finding.fingerprint_of("panel:grafana", "example.com", "https://example.com")
    secret_fp = finding.fingerprint_of("secret-exposure", "example.com",
                                       "https://example.com/.env")
    assert st.provenance[panel_fp] == "panel"
    assert st.provenance[secret_fp] == "secret"
    # dicts unchanged (no stage key leaked in)
    assert "stage" not in panel_finding
