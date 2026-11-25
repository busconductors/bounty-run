"""Tests for the engagement-report template, stylesheet and render helpers."""

import re

from runner import engagement_report as er


def test_stylesheet_is_self_contained():
    css = er.ENGAGEMENT_STYLESHEET
    assert "http://" not in css and "https://" not in css
    assert "@media print" in css
    assert "data:font" in css
    for tok in ("--sev-critical:#ff3d81", "--sev-high:#ff8a3d", "--sev-medium:#f2c230",
                "--sev-low:#6aa8ff", "--sev-info:#a3a3a0"):
        assert tok in css


def test_cover_embeds_logo_both_themes():
    html = er.render_cover("app.acme.com", client="Acme", engagement="Ext", prepared_by="me",
                           team=None, run_time="2026-11-24")
    assert len(re.findall(r'data:image/svg\+xml;base64,', html)) == 2
    assert 'class=rev' in html and 'class=ink' in html
    assert 'html[data-pdf-theme="dark"]' in er.ENGAGEMENT_STYLESHEET
    assert ".coverlogo .ink{display:none;}" in er.ENGAGEMENT_STYLESHEET
    assert "STRASSER" in html
    assert "None" not in html


def test_cover_degrades_without_optional_fields():
    html = er.render_cover("t.example", client=None, engagement=None, prepared_by=None,
                           team="", run_time=None)
    assert "None" not in html and "t.example" in html


def test_repro_wraps():
    css = er.ENGAGEMENT_STYLESHEET
    m = re.search(r"\.repro\{[^}]*\}", css)
    assert "white-space:pre-wrap" in m.group(0)
    assert "word-break:break-all" in m.group(0)


def test_render_finding_escapes_scan_text():
    html = er.render_finding(
        {"name": "<script>x", "severity": "high", "url": "http://a/<b>"},
        {"description": "<img src=x>", "impact": "", "remediation": "", "reference": [],
         "cvss": "7.5", "cwe": ["CWE-79"]},
        [{"curl": "curl 'x' <y>", "request": "", "response": ""}],
    )
    assert "&lt;script&gt;x" in html
    assert "<script>" not in html and "<img src=x>" not in html
    assert "&lt;y&gt;" in html and "CWE-79" in html


def test_exec_summary_and_scope_and_appendix():
    s = er.render_exec_summary({"critical": 1, "high": 2, "info": 0}, [{"title": "<b>SQLi"}])
    assert "sev-critical" in s and "&lt;b&gt;SQLi" in s
    sc = er.render_scope_methodology("a.com", ["nuclei", "<x>"], [{"target": "legacy", "reason": "deny"}])
    assert "nuclei" in sc and "&lt;x&gt;" in sc and "legacy" in sc
    ap = er.render_appendix({"run_id": "r<1>"}, "<div>raw</div>")
    assert "r&lt;1&gt;" in ap and "<div>raw</div>" in ap


def test_render_document_is_self_contained():
    doc = er.render_document(title="T <1>", body="<p>hi</p>")
    assert doc.startswith("<!doctype html>") and "<p>hi</p>" in doc
    assert "T &lt;1&gt;" in doc
    assert "http://" not in doc and "https://" not in doc
