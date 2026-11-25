"""Engagement report ("Command Deck") stylesheet, template and render helpers.

Fully self-contained: inline CSS, fonts and logo as ``data:`` URIs, no network
references.  Dark on screen; light under ``@media print`` unless the document
root carries ``data-pdf-theme="dark"``.  All scan text is escaped with the
engine's shared ``esc``.
"""

from runner import _report_assets as _a
from runner.dashboard import esc

_SEVERITIES = ("critical", "high", "medium", "low", "info")


def _font_face(family, weight, b64):
    return (
        f'@font-face{{font-family:"{family}";font-weight:{weight};font-style:normal;'
        f"font-display:swap;src:url(data:font/woff2;base64,{b64}) format(\"woff2\");}}\n"
    )


_FONTS = (
    _font_face("Barlow", 400, _a.FONT_BARLOW_400)
    + _font_face("Barlow", 500, _a.FONT_BARLOW_500)
    + _font_face("Barlow Semi Condensed", 600, _a.FONT_BARLOW_SC_600)
    + _font_face("JetBrains Mono", 400, _a.FONT_JBMONO_400)
)

_CSS = r"""
:root{color-scheme:dark;
--bg-0:#0a0a0b;--bg-1:#0f0f10;--bg-2:#151516;--bg-3:#1b1b1d;--bg-4:#232325;
--line-1:#262628;--line-2:#333336;--line-3:#46464a;
--tx-hi:#f2f2f0;--tx:#d6d6d3;--tx-mid:#a3a3a0;--tx-lo:#838385;--tx-off:#55555a;
--red-400:#ff4d42;--red-500:#ec2f26;--red-600:#c4211a;--red-tint:rgba(236,47,38,.12);
--sev-critical:#ff3d81;--sev-high:#ff8a3d;--sev-medium:#f2c230;--sev-low:#6aa8ff;--sev-info:#a3a3a0;
--font-body:'Barlow',sans-serif;--font-label:'Barlow Semi Condensed','Barlow',sans-serif;--font-mono:'JetBrains Mono',monospace;}
*{box-sizing:border-box;}
html{-webkit-print-color-adjust:exact;print-color-adjust:exact;}
body{margin:0;background:var(--bg-0);color:var(--tx);font:400 13px/18px var(--font-body);}
code,.mono{font-family:var(--font-mono);font-size:12px;}
a{color:var(--red-400);}

.wrap{max-width:940px;margin:0 auto;padding:0 0 60px;}
.cover{padding:40px 48px 40px;background:radial-gradient(1200px 400px at 0% 0%,rgba(236,47,38,.10),transparent 60%),var(--bg-1);border-bottom:1px solid var(--line-2);}
.coverlogo{display:flex;align-items:center;justify-content:space-between;margin-bottom:28px;}
.coverlogo img{height:34px;width:auto;} .coverlogo .ink{display:none;}
.coverlogo .conf{font-family:var(--font-mono);font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--tx-off);}
.kicker{font-family:var(--font-mono);font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:var(--red-400);}
.cover h1{font-family:var(--font-label);font-weight:600;font-size:42px;line-height:44px;margin:16px 0 6px;color:var(--tx-hi);}
.cover .client{font-family:var(--font-label);font-size:20px;color:var(--tx-mid);margin-bottom:28px;}
.coverfacts{display:flex;flex-wrap:wrap;gap:0 48px;font-size:13px;}
.coverfacts div{padding:6px 0;} .coverfacts .k{display:block;font-family:var(--font-label);font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--tx-off);}
.coverfacts .v{color:var(--tx);} .coverfacts code{color:var(--tx);}
.body{padding:0 48px;}
h2.sec{font-family:var(--font-label);font-weight:600;font-size:22px;color:var(--tx-hi);margin:44px 0 16px;}
h2.sec small{font-family:var(--font-mono);font-size:11px;color:var(--red-400);letter-spacing:.1em;display:block;margin-bottom:2px;text-transform:uppercase;}
.deck{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:18px 0 10px;}
.tile{background:var(--bg-2);border:1px solid var(--line-1);padding:16px 14px;position:relative;overflow:hidden;}
.tile::after{content:'';position:absolute;left:0;right:0;bottom:0;height:3px;background:var(--c);}
.tile b{display:block;font-family:var(--font-mono);font-size:30px;line-height:32px;color:var(--tx-hi);}
.tile span{font-family:var(--font-label);font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--tx-mid);}
.tile.sev-critical{--c:var(--sev-critical);} .tile.sev-high{--c:var(--sev-high);} .tile.sev-medium{--c:var(--sev-medium);} .tile.sev-low{--c:var(--sev-low);} .tile.sev-info{--c:var(--sev-info);}
.heat{display:flex;height:10px;margin:8px 0 18px;border:1px solid var(--line-1);}
.heat i{display:block;} .heat .sev-critical{background:var(--sev-critical);} .heat .sev-high{background:var(--sev-high);}
.heat .sev-medium{background:var(--sev-medium);} .heat .sev-low{background:var(--sev-low);} .heat .sev-info{background:var(--sev-info);}
.lede{color:var(--tx-mid);font-size:15px;line-height:23px;max-width:70ch;}
.meth{display:flex;gap:40px;flex-wrap:wrap;} .meth .k{font-family:var(--font-label);font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--tx-off);margin-bottom:6px;}
.meth ul{margin:0;padding-left:16px;color:var(--tx-mid);line-height:22px;}
.card{background:var(--bg-1);border:1px solid var(--line-1);margin-bottom:16px;position:relative;}
.card::before{content:'';position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--c);}
.card.sev-critical{--c:var(--sev-critical);} .card.sev-high{--c:var(--sev-high);} .card.sev-medium{--c:var(--sev-medium);} .card.sev-low{--c:var(--sev-low);} .card.sev-info{--c:var(--sev-info);}
.chead{display:flex;align-items:flex-start;gap:14px;padding:18px 22px 10px;}
.chead h3{font-family:var(--font-label);font-weight:600;font-size:20px;margin:0;color:var(--tx-hi);flex:1;line-height:24px;}
.chip{font-family:var(--font-label);font-weight:600;font-size:10px;letter-spacing:.1em;padding:4px 9px;color:#0a0a0b;white-space:nowrap;}
.chip.sev-critical{background:var(--sev-critical);} .chip.sev-high{background:var(--sev-high);} .chip.sev-medium{background:var(--sev-medium);} .chip.sev-low{background:var(--sev-low);} .chip.sev-info{background:var(--sev-info);color:#0a0a0b;}
.cbody{padding:0 22px 20px;} .meta{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;}
.pill{font-family:var(--font-mono);font-size:11px;padding:3px 9px;background:var(--bg-3);color:var(--tx-mid);border:1px solid var(--line-2);}
.asset{margin-bottom:14px;} .k{display:block;font-family:var(--font-label);font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--tx-off);margin-bottom:4px;}
.field{margin-bottom:14px;} .field p{margin:0;color:var(--tx);line-height:20px;}
.repro{background:var(--bg-0);border:1px solid var(--line-2);border-left:3px solid var(--red-500);padding:12px 14px;margin:0;font-family:var(--font-mono);font-size:12px;color:var(--tx);overflow:auto;white-space:pre-wrap;word-break:break-all;}
.repro-h{display:block;font-size:9px;letter-spacing:.14em;text-transform:uppercase;color:var(--tx-off);margin-bottom:6px;}
.appendix{color:var(--tx-mid);line-height:21px;}
footer{margin:48px 48px 0;border-top:1px solid var(--line-1);padding-top:14px;font-family:var(--font-mono);font-size:10px;color:var(--tx-off);letter-spacing:.06em;}
@media print{
 :root{color-scheme:light;} body{background:#fff;color:#1a1a1a;font-size:11px;}
 .cover{background:#fff;border-color:#ccc;padding:0 0 28px;} .cover h1{color:#111;} .cover .client{color:#444;} .kicker{color:#b3261e;}
 .coverlogo .rev{display:none;} .coverlogo .ink{display:inline;} .coverlogo .conf{color:#999;}
 .coverfacts .v,.coverfacts code{color:#222;} .coverfacts .k{color:#888;}
 .body,.wrap{padding-left:0;padding-right:0;} footer{margin-left:0;margin-right:0;color:#999;border-color:#ddd;}
 h2.sec{color:#111;} h2.sec small{color:#b3261e;}
 .tile{background:#fafafa;border-color:#ddd;} .tile b{color:#111;} .tile span{color:#555;}
 .heat{border-color:#ccc;}
 .lede{color:#333;} .meth ul{color:#333;} .meth .k,.k{color:#777;}
 .card{background:#fff;border-color:#ddd;page-break-inside:avoid;} .chead h3{color:#111;}
 .pill{background:#f2f2f2;border-color:#ddd;color:#555;} .field p{color:#222;}
 .repro{background:#f5f5f5;border-color:#ddd;color:#222;}
 a{color:#b3261e;}
}

html[data-pdf-theme="dark"]{color-scheme:dark;}
@media print{
 html[data-pdf-theme="dark"] body{background:var(--bg-0);color:var(--tx);font-size:13px;}
 html[data-pdf-theme="dark"] .cover{background:radial-gradient(1200px 400px at 0% 0%,rgba(236,47,38,.10),transparent 60%),var(--bg-1);border-color:var(--line-2);padding:40px 48px;}
 html[data-pdf-theme="dark"] .cover h1,html[data-pdf-theme="dark"] h2.sec,html[data-pdf-theme="dark"] .chead h3,html[data-pdf-theme="dark"] .tile b{color:var(--tx-hi);}
 html[data-pdf-theme="dark"] .cover .client,html[data-pdf-theme="dark"] .tile span,html[data-pdf-theme="dark"] .lede,html[data-pdf-theme="dark"] .meth ul,html[data-pdf-theme="dark"] .pill,html[data-pdf-theme="dark"] .appendix{color:var(--tx-mid);}
 html[data-pdf-theme="dark"] .kicker,html[data-pdf-theme="dark"] h2.sec small,html[data-pdf-theme="dark"] a{color:var(--red-400);}
 html[data-pdf-theme="dark"] .coverlogo .rev{display:inline;} html[data-pdf-theme="dark"] .coverlogo .ink{display:none;}
 html[data-pdf-theme="dark"] .coverlogo .conf,html[data-pdf-theme="dark"] .coverfacts .k,html[data-pdf-theme="dark"] .meth .k,html[data-pdf-theme="dark"] .k,html[data-pdf-theme="dark"] footer{color:var(--tx-off);}
 html[data-pdf-theme="dark"] .coverfacts .v,html[data-pdf-theme="dark"] .coverfacts code,html[data-pdf-theme="dark"] .field p{color:var(--tx);}
 html[data-pdf-theme="dark"] .body{padding:0 48px;} html[data-pdf-theme="dark"] footer{margin:48px 48px 0;border-color:var(--line-1);}
 html[data-pdf-theme="dark"] .tile{background:var(--bg-2);border-color:var(--line-1);}
 html[data-pdf-theme="dark"] .heat{border-color:var(--line-1);}
 html[data-pdf-theme="dark"] .card{background:var(--bg-1);border-color:var(--line-1);}
 html[data-pdf-theme="dark"] .pill{background:var(--bg-3);border-color:var(--line-2);}
 html[data-pdf-theme="dark"] .repro{background:var(--bg-0);border-color:var(--line-2);color:var(--tx);}
}
"""

ENGAGEMENT_STYLESHEET = _FONTS + _CSS

_LOGO_REV = "data:image/svg+xml;base64," + _a.LOGO_REVERSED_SVG
_LOGO_INK = "data:image/svg+xml;base64," + _a.LOGO_INK_SVG

ENGAGEMENT_TEMPLATE = (
    "<!doctype html><html lang=en><head><meta charset=utf-8>"
    '<meta name=viewport content="width=device-width,initial-scale=1">'
    "<title>{title}</title><style>\n{stylesheet}</style></head><body>"
    "<div class=wrap>{body}</div></body></html>"
)


def _sev(value):
    s = str(value or "info").strip().lower()
    return s if s in _SEVERITIES else "info"


def render_cover(target, *, client=None, engagement=None, prepared_by=None, team=None, run_time=None):
    team_name = (team or "").strip() or "STRASSER"
    title = (engagement or "").strip() or "Engagement Report"
    facts = []
    if client:
        facts.append(("Client", esc(client)))
    facts.append(("Scope", esc(target)))
    if run_time:
        facts.append(("Window", esc(run_time)))
    prep = " \u00b7 ".join(esc(x) for x in (prepared_by, team_name) if x)
    facts.append(("Prepared by", prep))
    fact_html = "".join(f"<div><span class=k>{k}</span><span class=v>{v}</span></div>" for k, v in facts)
    client_html = f"<div class=client>{esc(client)}</div>" if client else ""
    return (
        f'<div class=cover><div class=coverlogo><img class=rev src="{_LOGO_REV}" alt="STRASSER">'
        f'<img class=ink src="{_LOGO_INK}" alt="STRASSER"><span class=conf>Confidential</span></div>'
        f"<div class=kicker>Bounty Run \u00b7 Engagement Report</div>"
        f"<h1>{esc(title)}</h1>{client_html}<div class=coverfacts>{fact_html}</div></div>"
    )


def _section(num, name):
    return f"<h2 class=sec><small>Section {num}</small>{name}</h2>"


def render_exec_summary(sev_counts, headline):
    counts = {s: int((sev_counts or {}).get(s, 0) or 0) for s in _SEVERITIES}
    tiles = "".join(
        f'<div class="tile sev-{s}"><b>{counts[s]}</b><span>{s}</span></div>' for s in _SEVERITIES
    )
    heat = "".join(
        f'<i class="sev-{s}" style="flex:{counts[s]}"></i>' for s in _SEVERITIES if counts[s] > 0
    )
    total = sum(counts.values())
    items = "".join(
        f"<li>{esc(h.get('title') or h.get('name') or '')}</li>" for h in (headline or [])
    )
    lede = (
        f"<p class=lede>{total} finding{'' if total == 1 else 's'} across the in-scope assets.</p>"
        + (f"<div class=meth><div><div class=k>Headline findings</div><ul>{items}</ul></div></div>" if items else "")
    )
    return (
        _section("01", "Executive summary")
        + f"<div class=deck>{tiles}</div><div class=heat>{heat}</div>{lede}"
    )


def render_scope_methodology(scope, stages, out_of_scope):
    if isinstance(scope, (list, tuple)):
        scope = ", ".join(str(x) for x in scope)
    stage_li = "".join(f"<li>{esc(s)}</li>" for s in (stages or []))
    oos_li = "".join(
        f"<li>{esc(o.get('target') or o.get('url') or '')} \u2014 {esc(o.get('reason') or '')}</li>"
        for o in (out_of_scope or [])
    )
    oos = f"<div><div class=k>Out of scope (dropped)</div><ul>{oos_li}</ul></div>" if oos_li else ""
    return (
        _section("02", "Scope &amp; methodology")
        + f"<p class=lede>Scope: <code>{esc(scope)}</code></p>"
        + f"<div class=meth><div><div class=k>Stages executed</div><ul>{stage_li}</ul></div>{oos}</div>"
    )


def _field(label, text):
    if not text:
        return ""
    return f"<div class=field><span class=k>{label}</span><p>{esc(text)}</p></div>"


def render_finding(finding, narrative, evidence):
    narrative = narrative or {}
    sev = _sev(finding.get("severity"))
    name = finding.get("name") or finding.get("title") or "(untitled)"
    asset = finding.get("url") or finding.get("asset") or finding.get("host") or ""
    pills = []
    if narrative.get("cvss"):
        pills.append(f'<span class="pill">CVSS {esc(narrative["cvss"])}</span>')
    for c in narrative.get("cwe") or []:
        pills.append(f'<span class="pill">{esc(c)}</span>')
    tmpl = finding.get("template") or finding.get("template_id")
    if tmpl:
        pills.append(f'<span class="pill tmpl mono">{esc(tmpl)}</span>')
    meta = f"<div class=meta>{''.join(pills)}</div>" if pills else ""
    asset_html = f"<div class=asset><span class=k>Asset</span> <code>{esc(asset)}</code></div>" if asset else ""
    curls = [e.get("curl") for e in (evidence or []) if e.get("curl")]
    repro = ""
    if curls:
        blocks = "".join(
            f'<pre class="repro"><span class="repro-h">reproduce</span>{esc(c)}</pre>' for c in curls
        )
        repro = f"<div class=field><span class=k>Steps to reproduce</span>{blocks}</div>"
    refs = "".join(f"<li>{esc(r)}</li>" for r in narrative.get("reference") or [])
    refs_html = f"<div class=field><span class=k>References</span><ul class=meth>{refs}</ul></div>" if refs else ""
    return (
        f'<div class="card sev-{sev}"><div class=chead><span class="chip sev-{sev}">{sev.upper()}</span>'
        f"<h3>{esc(name)}</h3></div><div class=cbody>{meta}{asset_html}"
        + _field("Description", narrative.get("description"))
        + repro
        + _field("Impact", narrative.get("impact"))
        + _field("Remediation", narrative.get("remediation"))
        + refs_html
        + "</div></div>"
    )


def render_appendix(provenance, raw_panels):
    items = "".join(
        f"<li><b>{esc(k)}</b>: {esc(v)}</li>" for k, v in (provenance or {}).items()
    )
    prov = f"<div class=meth><div><div class=k>Provenance</div><ul>{items}</ul></div></div>" if items else ""
    return _section("04", "Appendix") + prov + (raw_panels or "")


def render_document(*, title, body):
    """Assemble the full self-contained HTML document."""
    return ENGAGEMENT_TEMPLATE.format(
        title=esc(title), stylesheet=ENGAGEMENT_STYLESHEET, body=body
    )
