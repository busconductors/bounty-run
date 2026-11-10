"""HTML findings dashboard — a self-contained, single-file report.

``generate(outputs_root)`` reads the tracker DB plus the latest run's SUMMARY.md
and writes ``outputs_root / "dashboard.html"``.  The output is fully static:
inline CSS + JS, zero external requests, and every interpolated value is
HTML-escaped.  Findings are rendered as server-side rows carrying ``data-*``
attributes (no JSON embedded in a ``<script>`` tag) and the client-side code
only reads those attributes / toggles visibility — it never injects attacker
data into the DOM.
"""

import html
from collections import Counter
from pathlib import Path

from . import categories, finding, report, tracker

# Canonical severity ordering for display / filter dropdowns. Derived from the
# single source of truth in runner.finding (excludes the "unknown" sentinel).
_SEVERITY_ORDER = tuple(
    s.value for s in finding.Severity if s is not finding.Severity.UNKNOWN
)


def _esc(value) -> str:
    """HTML-escape any value (None/numbers coerced to str), quote-aware."""
    return html.escape("" if value is None else str(value), quote=True)

# Public alias so callers don't reach for the private helper.
esc = _esc


def _latest_summary(outputs_root: Path) -> str:
    """Return the newest run's SUMMARY.md text ('' when there are no runs)."""
    matches = sorted(outputs_root.glob("*/*/SUMMARY.md"))
    if not matches:
        return ""
    latest = max(matches, key=lambda p: p.parent.name)
    try:
        return latest.read_text()
    except OSError:
        return ""


def _severity_choices(findings):
    """Ordered, deduped severity values present in the data."""
    present = {f["severity"] for f in findings if f["severity"]}
    ordered = [s for s in _SEVERITY_ORDER if s in present]
    ordered += sorted(present - set(_SEVERITY_ORDER))
    return ordered


def _status_choices(stats):
    present = set(stats["statuses"])
    ordered = [s for s in tracker.CANONICAL_STATUSES if s in present]
    ordered += sorted(present - set(tracker.CANONICAL_STATUSES))
    return ordered


def _finding_rows(findings):
    """Build (row, detail) HTML string pairs for every finding, escaped."""
    parts = []
    for f in findings:
        sev = f["severity"] or "unknown"
        title = f["title"] or "(untitled)"
        status = f["status"] or "new"
        target = f["domain"] or ""
        url = f["url"] or ""
        template = f["template"] or ""
        notes = f["notes"] or ""
        created = f["created"] or ""
        bounty = f["bounty"] or 0

        parts.append(
            '<tr class="row" data-severity="{}" data-status="{}" '
            'data-target="{}" data-title="{}" data-url="{}">'
            '<td class="sev sev-{}">{}</td>'
            "<td>{}</td>"
            '<td><span class="pill">{}</span></td>'
            "<td>{}</td>"
            '<td class="num">{}</td>'
            '<td class="url">{}</td>'
            "</tr>".format(
                _esc(sev), _esc(status), _esc(target), _esc(title), _esc(url),
                _esc(sev), _esc(sev),
                _esc(title),
                _esc(status),
                _esc(target),
                _esc(_fmt_bounty(bounty)),
                _esc(url),
            )
        )
        parts.append(
            '<tr class="detail"><td colspan="6"><dl>'
            "<dt>template</dt><dd>{}</dd>"
            "<dt>url</dt><dd>{}</dd>"
            "<dt>notes</dt><dd>{}</dd>"
            "<dt>created</dt><dd>{}</dd>"
            "</dl></td></tr>".format(
                _esc(template), _esc(url), _esc(notes), _esc(created),
            )
        )
    return "".join(parts)


def _fmt_bounty(value) -> str:
    try:
        return f"{float(value):g}"
    except (TypeError, ValueError):
        return "0"


def _metric_cards(stats, sev_counts):
    cards = [
        ("findings", stats["total_findings"], ""),
        ("bounty", f"${_fmt_bounty(stats['total_bounty'])}", ""),
    ]
    for s in _SEVERITY_ORDER:
        n = sev_counts.get(s, 0)
        if n:
            cards.append((f"sev {s}", n, f"sev-{s}"))
    return cards


def _status_badges(stats, statuses):
    out = []
    for s in statuses:
        out.append(
            '<span class="pill pill-{}">{}: {}</span>'.format(
                _esc(s), _esc(s), stats["statuses"].get(s, 0)
            )
        )
    return "".join(out)


def _targets_html(targets):
    if not targets:
        return '<p class="empty">no targets yet</p>'
    rows = []
    for t in targets:
        rows.append(
            '<tr><td>{}</td><td>{}</td><td>{}</td></tr>'.format(
                _esc(t["domain"]),
                _esc(t.get("program") or ""),
                _esc(t.get("scope") or ""),
            )
        )
    return "<table><thead><tr><th>domain</th><th>program</th><th>scope</th></tr></thead><tbody>{}</tbody></table>".format(
        "".join(rows)
    )


def _filter_options(choices):
    opts = ['<option value="">all</option>']
    for c in choices:
        opts.append('<option value="{}">{}</option>'.format(_esc(c), _esc(c)))
    return "".join(opts)


def _build_html(outputs_root, findings, stats, targets, summary_text):
    sev_counts = Counter(f["severity"] for f in findings)
    sev_choices = _severity_choices(findings)
    status_choices = _status_choices(stats)
    target_choices = sorted({t["domain"] for t in targets if t["domain"]})

    metric_cards = _metric_cards(stats, sev_counts)
    metrics_html = "".join(
        '<div class="card {}"><div class="card-label">{}</div>'
        '<div class="card-value">{}</div></div>'.format(cls, _esc(label), val)
        for label, val, cls in metric_cards
    )
    status_badges = _status_badges(stats, status_choices)

    if findings:
        findings_html = (
            '<div class="filters">'
            '<select id="f-sev">{}</select>'
            '<select id="f-status">{}</select>'
            '<select id="f-target">{}</select>'
            '<input id="f-search" type="text" placeholder="search title or url…">'
            "</div>"
            '<table id="findings">'
            "<thead><tr><th>sev</th><th>title</th><th>status</th>"
            "<th>target</th><th>bounty</th><th>url</th></tr></thead>"
            "<tbody>{}</tbody></table>"
        ).format(
            _filter_options(sev_choices),
            _filter_options(status_choices),
            _filter_options(target_choices),
            _finding_rows(findings),
        )
    else:
        findings_html = '<p class="empty">no findings yet</p>'

    summary_html = (
        "<pre>{}</pre>".format(_esc(summary_text))
        if summary_text
        else '<p class="empty">no scans yet</p>'
    )

    empty_note = (
        '<p class="empty">no data yet — run a sweep or add a finding to '
        "populate the dashboard.</p>"
        if not (findings or targets or summary_text)
        else ""
    )

    return _TEMPLATE.format(
        stylesheet=STYLESHEET,
        empty_note=empty_note,
        metrics=metrics_html,
        status_badges=status_badges,
        findings=findings_html,
        targets=_targets_html(targets),
        summary=summary_html,
    )


STYLESHEET = """<style>
:root {
  --bg: #0d1117;
  --panel: #161b22;
  --border: #30363d;
  --text: #e6edf3;
  --muted: #8b949e;
  --accent: #22d3ee;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
header {
  padding: 24px 32px; border-bottom: 1px solid var(--border);
  background: var(--panel);
}
header h1 { margin: 0; font-size: 22px; }
header h1 span { color: var(--accent); }
main { max-width: 1080px; margin: 0 auto; padding: 24px 32px 64px; }
section { margin-bottom: 32px; }
h2 { font-size: 16px; text-transform: uppercase; letter-spacing: .06em;
     color: var(--muted); border-bottom: 1px solid var(--border);
     padding-bottom: 8px; }
.metrics { display: flex; flex-wrap: wrap; gap: 12px; }
.card {
  background: var(--panel); border: 1px solid var(--border);
  border-radius: 8px; padding: 14px 18px; min-width: 120px;
}
.card-label { color: var(--muted); font-size: 12px; text-transform: uppercase; }
.card-value { font-size: 26px; font-weight: 600; margin-top: 2px; }
.card.sev-critical .card-value { color: #ff7b72; }
.card.sev-high .card-value { color: #ffa657; }
.card.sev-medium .card-value { color: #e3b341; }
.card.sev-low .card-value { color: #8b949e; }
.card.sev-info .card-value { color: #58a6ff; }
.badges { display: flex; flex-wrap: wrap; gap: 8px; margin: 8px 0; }
.pill {
  display: inline-block; padding: 2px 10px; border-radius: 999px;
  border: 1px solid var(--border); font-size: 12px; color: var(--muted);
}
.filters { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }
select, input {
  background: var(--panel); color: var(--text);
  border: 1px solid var(--border); border-radius: 6px; padding: 6px 10px;
  font-size: 13px;
}
input { flex: 1; min-width: 200px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border);
  vertical-align: top; }
th { color: var(--muted); text-transform: uppercase; font-size: 11px;
  letter-spacing: .04em; }
tr.row { cursor: pointer; }
tr.row:hover { background: #161b22; }
tr.detail { display: none; background: #10151c; }
tr.detail td { padding: 4px 16px 14px; }
dl { display: grid; grid-template-columns: 90px 1fr; gap: 2px 12px; margin: 0; }
dt { color: var(--muted); }
dd { margin: 0; word-break: break-all; }
.sev { font-weight: 600; text-transform: uppercase; font-size: 11px; }
.sev-critical { color: #ff7b72; }
.sev-high { color: #ffa657; }
.sev-medium { color: #e3b341; }
.sev-low { color: #8b949e; }
.sev-info { color: #58a6ff; }
.sev-unknown { color: #8b949e; }
.num { text-align: right; white-space: nowrap; }
.url { color: var(--muted); word-break: break-all; max-width: 320px; }
pre {
  background: var(--panel); border: 1px solid var(--border);
  border-radius: 8px; padding: 16px; overflow-x: auto;
  font: 12px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace;
  white-space: pre-wrap; word-break: break-word;
}
.empty { color: var(--muted); font-style: italic; }
</style>"""


_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bounty Runner — Dashboard</title>
{stylesheet}
</head>
<body>
<header><h1>Bounty Runner <span>— Dashboard</span></h1></header>
<main>
  {empty_note}
  <section>
    <h2>Metrics</h2>
    <div class="metrics">{metrics}</div>
    <div class="badges">{status_badges}</div>
  </section>
  <section>
    <h2>Findings</h2>
    {findings}
  </section>
  <section>
    <h2>Targets</h2>
    {targets}
  </section>
  <section>
    <h2>Latest scan</h2>
    {summary}
  </section>
</main>
<script>
(function () {{
  var rows = Array.prototype.slice.call(
    document.querySelectorAll('#findings tbody tr.row'));
  var detailFor = function (row) {{
    var n = row.nextElementSibling;
    return (n && n.classList.contains('detail')) ? n : null;
  }};
  rows.forEach(function (row) {{
    row.addEventListener('click', function () {{
      var d = detailFor(row);
      if (d) {{
        d.style.display = (d.style.display === 'table-row') ? 'none' : 'table-row';
      }}
    }});
  }});
  var sevEl = document.getElementById('f-sev');
  var statusEl = document.getElementById('f-status');
  var targetEl = document.getElementById('f-target');
  var searchEl = document.getElementById('f-search');
  var apply = function () {{
    var sev = sevEl ? sevEl.value : '';
    var status = statusEl ? statusEl.value : '';
    var target = targetEl ? targetEl.value : '';
    var q = searchEl ? searchEl.value.trim().toLowerCase() : '';
    rows.forEach(function (row) {{
      var d = row.dataset;
      var ok = true;
      if (sev && d.severity !== sev) ok = false;
      if (status && d.status !== status) ok = false;
      if (target && d.target !== target) ok = false;
      if (q && d.title.toLowerCase().indexOf(q) === -1
           && d.url.toLowerCase().indexOf(q) === -1) ok = false;
      row.style.display = ok ? '' : 'none';
      var det = detailFor(row);
      if (det) det.style.display = 'none';
    }});
  }};
  if (sevEl) sevEl.addEventListener('change', apply);
  if (statusEl) statusEl.addEventListener('change', apply);
  if (targetEl) targetEl.addEventListener('change', apply);
  if (searchEl) searchEl.addEventListener('input', apply);
}})();
</script>
</body>
</html>
"""


def generate(outputs_root: Path) -> Path:
    """Render the dashboard and write it to ``outputs_root / "dashboard.html"``.

    Returns the written Path.  Raises (does not swallow) any OSError from the
    write so the caller can report a non-zero exit.
    """
    findings = tracker.list_findings()
    stats = tracker.stats()
    targets = tracker.list_targets()
    summary_text = _latest_summary(outputs_root)

    html_doc = _build_html(outputs_root, findings, stats, targets, summary_text)

    outputs_root.mkdir(parents=True, exist_ok=True)
    out_path = outputs_root / "dashboard.html"
    out_path.write_text(html_doc)
    return out_path


def _sev_class(sev) -> str:
    """Map a severity string to a known CSS class (unknown-safe)."""
    sev = (sev or "unknown").lower()
    if sev in ("critical", "high", "medium", "low", "info", "unknown"):
        return "sev-" + sev
    return "sev-unknown"


def _waf_name(name: str) -> str:
    """``"WAF detected: Cloudflare (Cloudflare Inc.)"`` → ``"Cloudflare"``."""
    if name.startswith("WAF detected: "):
        name = name[len("WAF detected: "):]
    if name.endswith(")") and " (" in name:
        name = name[:name.rindex(" (")]
    return name.strip()


def _is_candidate(f) -> bool:
    """Triage split rule: candidate = critical/high/medium OR ``panel:`` (any sev).

    Thin wrapper over :func:`categories.is_candidate` (the single source of
    truth); kept as a named module attribute because tests call it directly.
    """
    return categories.is_candidate(f)


def _order_candidates(findings):
    """``panel:`` hits float to the top, then by severity (crit -> high -> medium)."""
    def key(f):
        is_panel = 0 if categories.classify(f.get("template")).key == "panel" else 1
        return (is_panel, finding.severity_rank(f.get("severity")))
    return sorted(findings, key=key)


def _verdict_line(candidates, origins, cloudflare, subdomains) -> str:
    """One prose assertion summarising the run, highest-value facts first."""
    clauses = []

    if candidates:
        sev_counts = Counter(
            (f.get("severity") or "unknown").lower() for f in candidates)
        bits = []
        for sev in _SEVERITY_ORDER:
            n = sev_counts.get(sev, 0)
            if n:
                bits.append("{} {}".format(n, sev))
        n = len(candidates)
        noun = "candidate" if n == 1 else "candidates"
        if bits:
            clauses.append("{} {} ({})".format(n, noun, ", ".join(bits)))
        else:
            clauses.append("{} {}".format(n, noun))

        panels = sum(
            1 for f in candidates if categories.classify(f.get("template")).key == "panel")
        if panels:
            clauses.append(
                "exposed admin panel" if panels == 1
                else "{} exposed panels".format(panels))

    # Origin-behind-Cloudflare always surfaces when it occurs (WAF-bypass story).
    if origins and cloudflare:
        ip = next((o.get("ip") for o in origins if o.get("ip")), None)
        if ip:
            clauses.append(
                "origin IP {} leaked behind Cloudflare — WAF bypass likely".format(ip))
        else:
            clauses.append("origin IP leaked behind Cloudflare — WAF bypass likely")

    if not candidates and not clauses:
        return "No candidates; {} subdomains mapped, nothing exposed.".format(
            subdomains)
    if not candidates:
        # No real candidates but something worth surfacing (e.g. origin leak).
        clauses.insert(0, "No candidates")

    return ". ".join(clauses) + "."


def _summary_hero_cards(live_hosts, open_ports, origin_status) -> str:
    """Three high-signal numbers that lead the attack-surface tier."""
    cards = [
        ("live hosts", live_hosts),
        ("open ports", open_ports),
        ("origin status", origin_status),
    ]
    return "".join(
        '<div class="card"><div class="card-label">{}</div>'
        '<div class="card-value">{}</div></div>'.format(esc(label), esc(value))
        for label, value in cards
    )


def _summary_surface_rows(subdomains, live_hosts, cloudflare, technologies,
                          api_endpoints, open_ports, *, waf=(), panels=0,
                          dork_hits=0, tls_issues=0, nikto=0,
                          origin_leaked=False) -> str:
    """Attack surface grouped by meaning, as compact key:value rows."""
    groups = [
        ("Reachability", "{} subdomains · {} live · {} ports".format(
            subdomains, live_hosts, open_ports)),
        ("Edge", "Cloudflare {} · WAF: {} · origin {}".format(
            "yes" if cloudflare else "no",
            ", ".join(waf) if waf else "none",
            "leaked" if origin_leaked else "not found")),
        ("Stack", "{} · {} API endpoints".format(
            ", ".join(technologies) if technologies else "no tech detected",
            api_endpoints)),
        ("Scanners", "{} tls · {} nikto · {} dork · {} panels".format(
            tls_issues, nikto, dork_hits, panels)),
    ]
    return "".join(
        '<div class="surface-row"><span class="surface-label">{}</span>'
        '<span class="surface-value">{}</span></div>'.format(esc(label), esc(value))
        for label, value in groups
    )


def _summary_noise_html(noise, info) -> str:
    """Low-severity + recon findings (expanded), info nuclei in a collapsed block."""
    if not noise and not info:
        return ""
    parts = ['<section class="noise"><h2>Noise &amp; recon</h2>']
    if noise:
        parts.append("".join(_summary_finding(f) for f in noise))
    else:
        parts.append('<p class="empty">No low-severity or recon findings.</p>')
    if info:
        parts.append(
            '<details class="info-findings"><summary>Info findings ({})</summary>'
            '{}</details>'.format(
                len(info), "".join(_summary_finding(f) for f in info)))
    parts.append('</section>')
    return "".join(parts)


def _summary_severity_pills(sev_counts) -> str:
    pills = []
    for s in ("critical", "high", "medium", "low", "info", "unknown"):
        n = sev_counts.get(s, 0)
        if n:
            pills.append(
                '<span class="pill sev-{}">{}: {}</span>'.format(s, s, n)
            )
    return "".join(pills)


def _summary_finding(f) -> str:
    sev = (f.get("severity") or "unknown").lower()
    title = f.get("name") or f.get("template") or ""
    url = f.get("url") or ""
    template = f.get("template") or ""
    host = f.get("host") or ""
    evidence = f.get("evidence") or ""

    parts = [
        '<article class="finding">',
        '<div class="finding-title {}">{}</div>'.format(
            _sev_class(sev), esc(title)
        ),
    ]
    meta = []
    if url:
        meta.append('<dt>url</dt><dd class="url">{}</dd>'.format(esc(url)))
    if template:
        meta.append('<dt>template</dt><dd>{}</dd>'.format(esc(template)))
    if host:
        meta.append('<dt>host</dt><dd>{}</dd>'.format(esc(host)))
    if meta:
        parts.append('<dl class="finding-meta">{}</dl>'.format("".join(meta)))
    if evidence:
        parts.append('<pre>{}</pre>'.format(esc(evidence)))
    parts.append('</article>')
    return "".join(parts)


def _summary_candidates_html(candidates) -> str:
    """Candidate cards in triage order (panel: first, then severity)."""
    if not candidates:
        return '<p class="empty">No candidates.</p>'
    return "".join(_summary_finding(f) for f in _order_candidates(candidates))


def _summary_origins_html(origins) -> str:
    if not origins:
        return ""
    cards = []
    for o in origins:
        ip = o.get("ip") or ""
        status = o.get("status") or ""
        sources = ", ".join(o.get("sources") or [])
        cards.append(
            '<div class="card"><dl>'
            '<dt>ip</dt><dd>{}</dd>'
            '<dt>status</dt><dd>{}</dd>'
            '<dt>sources</dt><dd>{}</dd>'
            '</dl></div>'.format(esc(ip), esc(status), esc(sources))
        )
    return '<section><h2>Origin candidates</h2>{}</section>'.format("".join(cards))


def _summary_content_html(content) -> str:
    if not content:
        return ""
    return '<section><h2>Discovered content</h2><pre>{}</pre></section>'.format(
        esc("\n".join(sorted(content)))
    )


_SUMMARY_FACE = (
    "⠀⠀⣀⡀⡀⡀⡀⣀\n"
    "⠀⡇⠀⠙⠒⠒⠉⠀⢸\n"
    "⠸⠁⠀⠀⠀⠀⠀⠀⠀⠏\n"
    "⠀⠙⠒⠒⠒⠒⠒⠒⠒⠁"
)

_SEV_COLORS = {
    "critical": "#ff5c57",
    "high": "#ff9f45",
    "medium": "#e3b341",
    "low": "#9aa4ad",
    "info": "#58a6ff",
    "unknown": "#9aa4ad",
}


def _sev_color(sev) -> str:
    return _SEV_COLORS.get((sev or "unknown").lower(), "#9aa4ad")


def _top_finding_card(f) -> str:
    """One top-finding card: severity pill + title + host + url + next action."""
    sev = (f.get("severity") or "unknown").lower()
    color = _sev_color(sev)
    title = f.get("name") or f.get("template") or "(untitled)"
    host = f.get("host") or ""
    url = f.get("url") or ""
    action = "verify & report" if sev in ("critical", "high") else "review"
    host_html = '<div class="det">{}</div>'.format(esc(host)) if host else ""
    url_html = '<div class="url"><b>{}</b></div>'.format(esc(url)) if url else ""
    return (
        '<article class="f"><div class="sv">'
        '<div class="n" style="color:{color}">{sev}</div>'
        '<div class="bar" style="background:{color}"></div></div>'
        '<div><div class="ttl">{title}</div>{host}{url}</div>'
        '<div class="act">→ {action}</div></article>'
    ).format(color=color, sev=esc(sev), title=esc(title),
             host=host_html, url=url_html, action=esc(action))


def _top_findings_html(candidates) -> str:
    if not candidates:
        return '<p class="empty">No candidates.</p>'
    return "".join(_top_finding_card(f) for f in _order_candidates(candidates))


def _metric_grid(subdomains, live_hosts, sev_counts, n_origins, cloudflare) -> str:
    tiles = [
        (subdomains, "subdomains", "#e6edf3"),
        (live_hosts, "live hosts", "#e6edf3"),
        (sev_counts.get("critical", 0), "critical", "#ff5c57"),
        (sev_counts.get("high", 0), "high", "#ff9f45"),
        (n_origins, "origin IPs", "#f85149"),
        ("ON" if cloudflare else "off", "cloudflare", "#58a6ff"),
    ]
    return "".join(
        '<div class="big" style="--b:{c}"><div class="v">{v}</div>'
        '<div class="k">{k}</div></div>'.format(c=color, v=esc(value), k=esc(label))
        for value, label, color in tiles
    )


def _heat_bar(sev_counts) -> str:
    segs = []
    for s, color in (("critical", "#ff5c57"), ("high", "#ff9f45"),
                     ("medium", "#e3b341"), ("low", "#9aa4ad"), ("info", "#58a6ff")):
        n = sev_counts.get(s, 0)
        if n:
            segs.append(
                '<span class="seg" style="flex:{n};background:{c}" '
                'title="{s}: {n}"></span>'.format(n=n, c=color, s=s))
    return '<div class="heat">{}</div>'.format("".join(segs))


def _origins_alert_html(origins) -> str:
    if not origins:
        return ""
    rows = []
    for o in origins:
        ip = o.get("ip") or "?"
        status = o.get("status") or ""
        sources = ", ".join(o.get("sources") or [])
        rows.append(
            '<div class="orow"><div><div class="ip">{ip}</div>'
            '<div class="via">{src}</div></div>'
            '<div class="st">{status}</div></div>'.format(
                ip=esc(ip), src=esc(sources), status=esc(status)))
    return (
        '<div class="alert"><h3><span class="dot"></span>'
        'Origin IPs exposed behind Cloudflare</h3>{}</div>'.format("".join(rows))
    )


def _surface_panels_html(cloudflare, waf, tech, api_count, nmap_count,
                         panels, tls_issues, nikto, dork_hits) -> str:
    edge = "Cloudflare yes" if cloudflare else "Cloudflare no"
    if waf:
        edge += " · WAF: " + ", ".join(waf)
    chips = ("".join('<span class="chip">{}</span>'.format(esc(t)) for t in tech)
             if tech else '<span class="chip">no tech detected</span>')
    return (
        '<div class="panel"><h3>Edge &amp; stack</h3>'
        '<div class="kv"><span>edge</span><b>{edge}</b></div>'
        '<div class="kv"><span>api endpoints</span><b>{api}</b></div>'
        '<div class="kv"><span>open ports</span><b>{ports}</b></div>'
        '<div class="chips">{chips}</div></div>'
        '<div class="panel"><h3>Scanner coverage</h3>'
        '<div class="kv"><span>tls</span><b>{tls}</b></div>'
        '<div class="kv"><span>nikto</span><b>{nikto}</b></div>'
        '<div class="kv"><span>dork hits</span><b>{dork}</b></div>'
        '<div class="kv"><span>panels</span><b>{panels}</b></div></div>'
    ).format(edge=esc(edge), api=esc(api_count), ports=esc(nmap_count),
             chips=chips, tls=esc(tls_issues), nikto=esc(nikto),
             dork=esc(dork_hits), panels=esc(panels))


def _detail_line(f) -> str:
    sev = (f.get("severity") or "unknown").lower()
    color = _sev_color(sev)
    title = f.get("name") or f.get("template") or "(untitled)"
    host = f.get("host") or ""
    url = f.get("url") or ""
    evidence = f.get("evidence") or ""
    ev = '<pre>{}</pre>'.format(esc(evidence)) if evidence else ""
    return (
        '<div class="drow"><div class="dhead">'
        '<span class="dsev" style="color:{c}">{s}</span> · {t}'
        '<span class="dhost">{h}</span></div>'
        '<div class="durl">{u}</div>{ev}</div>'
    ).format(c=color, s=esc(sev), t=esc(title), h=esc(host), u=esc(url), ev=ev)


def _details_section(title, items) -> str:
    if not items:
        return ""
    body = "".join(_detail_line(f) for f in items)
    return (
        '<details class="drop"><summary>{t} <b>({n})</b></summary>'
        '<div class="dropinner">{b}</div></details>'
    ).format(t=esc(title), n=len(items), b=body)


def _details_html(candidates, noise, info, content) -> str:
    parts = []
    if candidates:
        parts.append(_details_section("Full findings", candidates))
    if noise:
        parts.append(_details_section("Low & recon", noise))
    if info:
        parts.append(_details_section("Info findings", info))
    if content:
        body = '<pre>{}</pre>'.format(esc("\n".join(sorted(content))))
        parts.append(
            '<details class="drop"><summary>Discovered content <b>({n})</b></summary>'
            '<div class="dropinner">{b}</div></details>'.format(
                n=len(content), b=body))
    if not parts:
        return ""
    return '<div class="drops">{}</div>'.format("".join(parts))


SUMMARY_STYLESHEET = """<style>
:root {
  --bg:#0a0e14; --panel:#141a22; --panel2:#0f141b; --border:#262d38;
  --text:#e6edf3; --muted:#8b949e; --accent:#f85149; --accent-dim:#b4332e;
  --crit:#ff5c57; --high:#ff9f45; --med:#e3b341; --low:#9aa4ad; --info:#58a6ff;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
 font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
 -webkit-font-smoothing:antialiased}
body{background:radial-gradient(1200px 600px at 70% -10%,rgba(248,81,73,.10),transparent),var(--bg)}
a{color:inherit}
details summary{cursor:pointer;list-style:none}
details summary::-webkit-details-marker{display:none}
.wrap{max-width:1340px;margin:0 auto;padding:30px 40px 56px}
.top{display:flex;align-items:center;gap:16px;margin-bottom:26px}
.face{font-family:ui-monospace,monospace;white-space:pre;line-height:1.05;
 color:var(--accent);font-size:11px;text-shadow:0 0 14px rgba(248,81,73,.5)}
.top h1{margin:0;font-size:17px;letter-spacing:3px;text-transform:uppercase;font-weight:800}
.top h1 b{color:var(--accent)}
.top .meta{margin-left:auto;text-align:right;color:var(--muted);font-size:12px}
.top .meta b{color:var(--text)}
.hero{display:grid;grid-template-columns:auto 1fr;gap:28px;align-items:center;
 background:linear-gradient(135deg,rgba(248,81,73,.14),rgba(20,26,34,.6));
 border:1px solid var(--accent-dim);border-radius:16px;padding:26px 30px;margin-bottom:22px;
 box-shadow:0 0 60px rgba(248,81,73,.10) inset}
.threat{text-align:center;padding-right:28px;border-right:1px solid var(--accent-dim)}
.threat .ring{font-size:62px;font-weight:900;line-height:1;color:var(--accent);
 text-shadow:0 0 24px rgba(248,81,73,.6)}
.threat .lab{font-size:11px;letter-spacing:.18em;text-transform:uppercase;
 color:var(--muted);margin-top:8px}
.hero .story .lbl{color:var(--accent);font-weight:800;font-size:12px;letter-spacing:.14em;
 text-transform:uppercase;margin-bottom:8px}
.verdict{margin:0;font-size:17px;line-height:1.5;font-weight:600}
.grid{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:22px}
.big{background:var(--panel);border:1px solid var(--border);border-radius:13px;
 padding:16px 18px;position:relative;overflow:hidden}
.big::before{content:"";position:absolute;inset:0 0 auto 0;height:3px;background:var(--b)}
.big .v{font-size:38px;font-weight:900;line-height:1;color:var(--b)}
.big .k{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.06em;
 margin-top:8px}
.heat{display:flex;height:14px;border-radius:999px;overflow:hidden;margin-bottom:28px;
 box-shadow:0 0 24px rgba(248,81,73,.2)}
.heat .seg{display:block}
.cols{display:grid;grid-template-columns:1.6fr 1fr;gap:22px;align-items:start}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.12em;color:var(--accent);
 margin:0 0 16px;font-weight:800}
.f{display:grid;grid-template-columns:auto 1fr auto;gap:14px;align-items:center;
 background:var(--panel);border:1px solid var(--border);border-radius:12px;
 padding:14px 18px;margin-bottom:11px}
.f .sv{width:52px;text-align:center}
.f .sv .n{font-size:11px;font-weight:800;letter-spacing:.05em}
.f .sv .bar{height:4px;border-radius:2px;margin-top:6px}
.f .ttl{font-weight:700;font-size:15px}
.f .det{color:var(--muted);font-size:12.5px;margin-top:3px}
.f .url{color:var(--muted);font-size:11px;margin-top:4px;word-break:break-all}
.f .url b{color:var(--text)}
.f .act{color:var(--accent);font-size:11px;font-weight:700;white-space:nowrap;text-align:right}
.alert{background:linear-gradient(135deg,rgba(255,159,69,.12),var(--panel));
 border:1px solid #6b4a1f;border-radius:13px;padding:18px 20px;margin-bottom:14px;
 box-shadow:0 0 36px rgba(255,159,69,.08)}
.alert h3{margin:0 0 12px;font-size:12px;text-transform:uppercase;color:var(--high);
 letter-spacing:.08em;display:flex;align-items:center;gap:8px}
.alert h3 .dot{width:8px;height:8px;border-radius:50%;background:var(--high);
 box-shadow:0 0 10px var(--high)}
.orow{display:flex;justify-content:space-between;align-items:center;padding:9px 0;
 border-bottom:1px solid rgba(107,74,31,.5)}
.orow:last-child{border-bottom:none}
.orow .ip{font-weight:700;font-size:14px}
.orow .via{color:var(--muted);font-size:11px;margin-top:2px}
.orow .st{color:var(--high);font-size:12px;font-weight:700}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:13px;
 padding:16px 20px;margin-bottom:14px}
.panel h3{margin:0 0 12px;font-size:12px;text-transform:uppercase;color:var(--accent);
 letter-spacing:.07em}
.kv{display:flex;justify-content:space-between;padding:6px 0;font-size:13px;color:var(--muted)}
.kv b{color:var(--text)}
.chips{display:flex;flex-wrap:wrap;gap:7px;margin-top:4px}
.chip{background:var(--panel2);border:1px solid var(--border);border-radius:7px;
 padding:4px 10px;font-size:11.5px;color:var(--muted)}
.drops{margin-top:26px;display:grid;gap:10px}
.drop{background:var(--panel2);border:1px solid var(--border);border-radius:13px}
.drop summary{padding:16px 22px;color:var(--muted);font-weight:700;font-size:13px;
 letter-spacing:.04em;text-transform:uppercase;display:flex;justify-content:space-between}
.drop summary b{color:var(--text)}
.drop .dropinner{padding:0 22px 18px}
.drow{padding:9px 0;border-top:1px solid var(--border);font-size:13px}
.drow:first-child{border-top:none}
.dhead{color:var(--text)}
.dsev{font-weight:800;text-transform:uppercase;font-size:11px;letter-spacing:.04em}
.dhost{color:var(--muted);font-size:11px;margin-left:8px}
.durl{color:var(--muted);font-size:11.5px;word-break:break-all;margin-top:2px}
pre{background:#0c1118;border:1px solid var(--border);border-radius:8px;padding:12px;
 overflow-x:auto;margin:8px 0 0;font:11.5px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;
 white-space:pre-wrap;word-break:break-word;color:var(--muted)}
.empty{color:var(--muted);font-style:italic}
</style>"""


_SUMMARY_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bounty Runner — {target} command center</title>
{stylesheet}
</head>
<body>
<div class="wrap">
  <div class="top">
    <div class="face">{face}</div>
    <h1>Bounty <b>Runner</b></h1>
    <div class="meta">THREAT COMMAND CENTER<br><b>{target}</b> · {run_time}</div>
  </div>
  <div class="hero">
    <div class="threat"><div class="ring">{ring}</div><div class="lab">crit+high<br>candidates</div></div>
    <div class="story"><div class="lbl">▶ Risk story</div><p class="verdict">{verdict}</p></div>
  </div>
  <div class="grid">{metrics}</div>
  {heat}
  <div class="cols">
    <section><h2>■ Top findings</h2>{candidates}</section>
    <section><h2>■ Attack surface</h2>{alert}{panels}</section>
  </div>
  {drops}
</div>
</body>
</html>
"""


def write_run_summary(outdir, target, findings, content, origins, *,
                      run_time, subdomains, live_hosts, cloudflare,
                      meta=None, stages=None, metrics=None, out_of_scope=None,
                      provenance=None, evidence_index=None) -> Path:
    """Write a self-contained per-run command-center summary to ``outdir/summary.html``.

    The ``meta``/``stages``/``metrics``/``out_of_scope``/``provenance``/
    ``evidence_index`` keyword arguments carry extra run context for the richer
    layout (wired in C21); they default to ``None`` so existing callers and
    tests keep working unchanged.
    """
    unique = report.dedupe(findings)
    unique.sort(
        key=lambda f: report.SEVERITY_ORDER.get(
            (f.get("severity") or "unknown").lower(), 9)
    )
    cat_counts = categories.count_by_category(unique)
    tech = sorted({
        (f.get("name") or "").replace("Technology: ", "", 1)
        for f in unique
        if categories.classify(f.get("template")).key == "tech"
    })
    api_count = cat_counts.get("api", 0)
    nmap_count = cat_counts.get("nmap", 0)

    waf_names = sorted({
        _waf_name(f.get("name") or "")
        for f in unique
        if categories.classify(f.get("template")).key == "waf"
    } - {""})

    candidates = [f for f in unique if _is_candidate(f)]
    rest = [f for f in unique if not _is_candidate(f)]
    info = [f for f in rest if (f.get("severity") or "").lower() == "info"]
    noise = [f for f in rest if (f.get("severity") or "").lower() != "info"]

    sev_counts = Counter((f.get("severity") or "unknown").lower() for f in unique)
    crit_high = sev_counts.get("critical", 0) + sev_counts.get("high", 0)

    doc = _SUMMARY_TEMPLATE.format(
        stylesheet=SUMMARY_STYLESHEET,
        target=esc(target),
        run_time=esc(run_time),
        face=esc(_SUMMARY_FACE),
        ring=esc(crit_high),
        verdict=esc(_verdict_line(candidates, origins, cloudflare, subdomains)),
        metrics=_metric_grid(subdomains, live_hosts, sev_counts,
                             len(origins), cloudflare),
        heat=_heat_bar(sev_counts),
        candidates=_top_findings_html(candidates),
        alert=_origins_alert_html(origins),
        panels=_surface_panels_html(
            cloudflare, waf_names, tech, api_count, nmap_count,
            cat_counts.get("panel", 0), cat_counts.get("tls", 0),
            cat_counts.get("nikto", 0), cat_counts.get("dork", 0)),
        drops=_details_html(candidates, noise, info, content),
    )

    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    out_path = outdir / "summary.html"
    out_path.write_text(doc)
    return out_path
