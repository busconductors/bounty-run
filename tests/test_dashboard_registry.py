"""C4: dashboard category checks route through the registry.

Regression: a non-string template used to crash write_run_summary via the
unguarded ``.startswith`` calls in the dashboard copy of the router.
"""
import tempfile
from pathlib import Path

from runner import dashboard


def test_non_str_template_does_not_crash_summary():
    findings = [
        {"severity": "high", "template": None, "name": "weird", "url": "u", "host": "h"},
        {"severity": "info", "template": 123, "name": "weirder", "url": "u", "host": "h"},
        {"severity": "high", "template": "panel:grafana", "name": "panel", "url": "u", "host": "h"},
    ]
    with tempfile.TemporaryDirectory() as d:
        out = dashboard.write_run_summary(
            d, "example.com", findings, [], [],
            run_time="1.0s", subdomains=[], live_hosts=[], cloudflare={})
        assert Path(out).exists()
        assert out.read_text()


def test_is_candidate_wrapper_matches_registry():
    from runner import categories
    f = {"template": "panel:x", "severity": "info"}
    assert dashboard._is_candidate(f) == categories.is_candidate(f) is True
