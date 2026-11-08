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

from . import report, tracker

# Canonical severity ordering for display / filter dropdowns.
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


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
<title>BuntyRun — Dashboard</title>
{stylesheet}
</head>
<body>
<header><h1>BuntyRun <span>— Dashboard</span></h1></header>
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


def _summary_metric_cards(subdomains, live_hosts, cloudflare, total,
                          technologies, api_endpoints) -> str:
    cards = [
        ("subdomains", subdomains),
        ("live hosts", live_hosts),
        ("cloudflare", "yes" if cloudflare else "no"),
        ("technologies", ", ".join(technologies) if technologies else "none"),
        ("api endpoints", str(api_endpoints)),
        ("total findings", total),
    ]
    return "".join(
        '<div class="card"><div class="card-label">{}</div>'
        '<div class="card-value">{}</div></div>'.format(esc(label), esc(value))
        for label, value in cards
    )


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
        '<div class="finding-title sev-{}">{}</div>'.format(
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


def _summary_findings_html(findings) -> str:
    if not findings:
        return '<p class="empty">No vulnerabilities found.</p>'
    groups = {}
    for f in findings:
        sev = (f.get("severity") or "unknown").lower()
        groups.setdefault(sev, []).append(f)
    ordered = sorted(groups, key=lambda s: report.SEVERITY_ORDER.get(s, 9))
    parts = []
    for sev in ordered:
        parts.append(
            '<h3 class="sev sev-{}">{}</h3>'.format(_sev_class(sev), esc(sev))
        )
        parts.append("".join(_summary_finding(f) for f in groups[sev]))
    return "".join(parts)


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


_SUMMARY_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BuntyRun — Executive Summary</title>
{stylesheet}
</head>
<body>
<header>
  <h1>BuntyRun <span>— Executive Summary</span></h1>
  <p class="summary-meta">{target} · {run_time}</p>
</header>
<main>
  <section>
    <h2>Overview</h2>
    <div class="metrics">{metrics}</div>
    <div class="badges">{pills}</div>
  </section>
  <section>
    <h2>Findings</h2>
    {findings}
  </section>
  {origins}
  {content}
</main>
</body>
</html>
"""


def write_run_summary(outdir, target, findings, content, origins, *,
                      run_time, subdomains, live_hosts, cloudflare) -> Path:
    """Write a self-contained per-run executive summary to ``outdir/summary.html``.

    Dedupes ``findings`` with ``report.dedupe`` so the HTML total matches
    ``write_findings_report``'s return value.  Returns the written Path.
    """
    unique = report.dedupe(findings)
    unique.sort(
        key=lambda f: report.SEVERITY_ORDER.get(
            (f.get("severity") or "unknown").lower(), 9
        )
    )
    sev_counts = Counter((f.get("severity") or "unknown").lower() for f in unique)
    tech = sorted({
        (f.get("name") or "").replace("Technology: ", "", 1)
        for f in unique
        if (f.get("template") or "").startswith("tech-detect:")
    })
    api_count = sum(1 for f in unique if (f.get("template") or "") == "api-endpoint")

    doc = _SUMMARY_TEMPLATE.format(
        stylesheet=STYLESHEET,
        target=esc(target),
        run_time=esc(run_time),
        metrics=_summary_metric_cards(subdomains, live_hosts, cloudflare, len(unique),
                                      tech, api_count),
        pills=_summary_severity_pills(sev_counts),
        findings=_summary_findings_html(unique),
        origins=_summary_origins_html(origins),
        content=_summary_content_html(content),
    )

    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    out_path = outdir / "summary.html"
    out_path.write_text(doc)
    return out_path
