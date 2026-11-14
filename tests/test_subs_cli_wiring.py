"""Phase 1-2 CLI wiring: subs flags flow into stages.subdomain_enum kwargs."""
from unittest import mock

import pytest

from runner import cli, scope, stage_registry


@pytest.fixture(autouse=True)
def _reset_scope():
    scope.reset()
    yield
    scope.reset()


def _drive(argv, tmp_path):
    """Run _pipeline with every stage mocked; return the subdomain_enum mock."""
    args = cli.build_parser().parse_args(argv)
    st = cli.RunState(args.target)
    with mock.patch.object(cli.stages, "subdomain_enum", return_value=[]) as subs, \
         mock.patch.object(cli.panel_detect, "panel_detect", return_value=[]), \
         mock.patch.object(cli.stages, "live_hosts", return_value=[]), \
         mock.patch.object(cli.stages, "cloudflare_detect", return_value={"cloudflare": False}), \
         mock.patch.object(cli.stages, "vuln_scan", return_value=[]), \
         mock.patch.object(cli.stages, "content_discovery", return_value=[]), \
         mock.patch.object(cli.api_endpoints, "api_endpoints_scan", return_value=[]), \
         mock.patch.object(cli.param_scan, "param_scan", return_value=[]), \
         mock.patch.object(cli.secret_scan, "secret_scan", return_value=[]), \
         mock.patch.object(cli.http_headers, "security_headers_scan", return_value=[]), \
         mock.patch.object(cli.http_headers, "cors_scan", return_value=[]), \
         mock.patch.object(cli.tech_scan, "tech_scan", return_value=[]), \
         mock.patch.object(cli.waf_scan, "waf_scan", return_value=[]), \
         mock.patch.object(cli.dork_scan, "dork_scan", return_value=[]), \
         mock.patch.object(cli.utils, "stage_header"), \
         mock.patch.object(cli.utils, "log"), \
         mock.patch.object(cli.utils, "warn"), \
         mock.patch.object(cli, "write_summary"):
        cli._pipeline(args, args.target, tmp_path, set(), st)
    return subs


def _kwargs(subs_mock):
    assert subs_mock.called
    return subs_mock.call_args.kwargs


def test_default_intrusive_is_active(tmp_path):
    subs = _drive(["example.com"], tmp_path)
    kw = _kwargs(subs)
    assert kw["active"] is True            # default intensity is intrusive
    assert kw["findomain"] is False
    assert kw["dns_rate"] == 500
    assert kw["cache_dir"] is not None     # cache on by default


def test_passive_intensity_disables_active(tmp_path):
    subs = _drive(["example.com", "--intensity", "passive"], tmp_path)
    assert _kwargs(subs)["active"] is False


def test_active_intensity_is_active(tmp_path):
    subs = _drive(["example.com", "--intensity", "active"], tmp_path)
    assert _kwargs(subs)["active"] is True


def test_findomain_flag_passed(tmp_path):
    subs = _drive(["example.com", "--findomain"], tmp_path)
    assert _kwargs(subs)["findomain"] is True


def test_no_subs_cache_disables_cache(tmp_path):
    subs = _drive(["example.com", "--no-subs-cache"], tmp_path)
    assert _kwargs(subs)["cache_dir"] is None


def test_dns_rate_and_resolvers_forwarded(tmp_path):
    subs = _drive(["example.com", "--dns-rate", "300", "--resolvers", "/tmp/r.txt"], tmp_path)
    kw = _kwargs(subs)
    assert kw["dns_rate"] == 300
    assert kw["resolvers"] == "/tmp/r.txt"


def test_ceiling_helper_matches_intensity():
    args = cli.build_parser().parse_args(["example.com", "--intensity", "active"])
    assert stage_registry.ceiling(args) == stage_registry.Tier.ACTIVE
