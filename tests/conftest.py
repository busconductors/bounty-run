"""Shared pytest fixtures.

Origin-IP classification (runner.ipintel) reads a user cache and can reach the
network (feed refresh, ASN/RDAP/PTR lookups, TLS + negative-control probes).
Every test gets an empty, private cache and those primitives stubbed out, so
the suite stays hermetic. Tests that exercise a primitive's real
implementation mark themselves ``@pytest.mark.ipintel_real`` and mock
``utils.run`` themselves.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner import ipintel  # noqa: E402


def pytest_configure(config):
    config.addinivalue_line("markers", "ipintel_real: use real ipintel network primitives")
    config.addinivalue_line("markers", "network: live network smoke test (opt-in)")


@pytest.fixture(autouse=True)
def _hermetic_ipintel(request, tmp_path_factory, monkeypatch):
    cache = tmp_path_factory.mktemp("ipintel-cache")
    monkeypatch.setenv("BOUNTY_RUN_IPINTEL_DIR", str(cache))
    ipintel.reset()
    if request.node.get_closest_marker("ipintel_real") is None and \
            request.node.get_closest_marker("network") is None:
        monkeypatch.setattr(ipintel, "_fetch", lambda *a, **k: False)
        monkeypatch.setattr(ipintel, "_dig_txt", lambda name: [])
        monkeypatch.setattr(ipintel, "_ptr_lookup", lambda ip: "")
        monkeypatch.setattr(ipintel, "_rdap_fetch", lambda ip, proxy=None: None)
        monkeypatch.setattr(ipintel, "tls_cert", lambda ip, servername=None: {
            "error": "stubbed", "client_cert_required": False, "subject": "",
            "issuer": "", "cn": "", "org": "", "sans": []})
        monkeypatch.setattr(ipintel, "control_probe", lambda ip: {
            "host": "stub.invalid", "http": {}, "nosni_cert": {}})
        monkeypatch.setattr(ipintel, "baseline_probe", lambda target: {})
        # Multi-A resolution goes through whatever single-IP `_resolve` the
        # test patched, so legacy origin tests keep their fake resolvers.
        from runner import stages

        def _resolve_all_via_resolve(host):
            ip = stages._resolve(host)
            return [ip] if ip else []
        monkeypatch.setattr(stages, "_resolve_all", _resolve_all_via_resolve)
    yield
    ipintel.reset()
