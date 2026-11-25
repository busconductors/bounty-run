"""CLI parser: engagement identity flags for the report cover page."""
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
