#!/usr/bin/env node
// Builds the static Monitor mock from the replay fixture and the engine's stage list.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const FRONTEND = join(dirname(fileURLToPath(import.meta.url)), '..');
const REPO = join(FRONTEND, '..', '..');
const FIXTURE = join(REPO, 'tui/internal/ui/testdata/full_run.jsonl');
const STYLESHEET = join(FRONTEND, 'mock/monitor.css');
const OUTPUT = join(FRONTEND, 'mock/monitor.html');

const TIERS = ['passive', 'active', 'intrusive'];
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_LABEL = { critical: 'CRIT', high: 'HIGH', medium: 'MED', low: 'LOW', info: 'INFO' };
const SEV_BARS = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const STATUSES = new Set(['ok', 'failed', 'skipped', 'running', 'queued']);
const ROW_COUNT = 40;
const LOG_LINES = 9;
const SELECTED_ROW = 1;

const SYNTHETIC = [
  ['critical', 'sqli-error-based', '/search?q=1', 'SQL error reflected in response'],
  ['high', 'exposed-env-file', '/.env', 'Environment file readable'],
  ['medium', 'open-redirect', '/out?to=', 'Redirect target not validated'],
  ['low', 'missing-hsts', '/', 'HSTS header not set'],
  ['info', 'tech-detect', '/', 'Reverse proxy detected'],
  ['medium', 'cors-misconfig', '/v2/users', 'CORS allows credentials'],
  ['high', 'admin-panel-exposed', '/admin/login', 'Admin login reachable'],
  ['info', 'robots-txt', '/robots.txt', 'robots.txt present'],
  ['low', 'cookie-no-secure', '/session', 'Session cookie lacks Secure'],
  ['medium', 'directory-listing', '/static/', 'Directory index enabled'],
  ['info', 'favicon-hash', '/favicon.ico', 'Favicon fingerprint recorded'],
  ['low', 'server-banner', '/', 'Server version disclosed'],
];
const SUBDOMAINS = ['api', 'app', 'auth', 'cdn', 'dev', 'mail', 'portal', 'staging', 'vpn'];

const ANSI =
  /\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)?|\u001b[PX^_][^\u001b]*(?:\u001b\\)?|[\u001b\u009b]\[?[0-?]*[ -/]*[@-~]?/g;
const CONTROLS = /[\u0000-\u0008\u000a-\u001f\u007f-\u009f]/g;
const BIDI = /[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;
const FORMAT = /[\u00AD\u180E\u200B-\u200D\u2028\u2029\u2060-\u2064\uFEFF\uFFF9-\uFFFB]|[\u{E0000}-\u{E007F}]/gu;
const HTML_ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

export const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (ch) => HTML_ESCAPES[ch]);

export const sanitizeText = (value) =>
  String(value)
    .toWellFormed()
    .replace(ANSI, '')
    .replace(CONTROLS, '')
    .replace(BIDI, '')
    .replace(FORMAT, '')
    .replaceAll('\t', ' ');

export const safeText = (value) => escapeHtml(sanitizeText(value));

export function loadEvents() {
  return readFileSync(FIXTURE, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

export function loadStages() {
  const out = execFileSync('python3', ['bounty_run.py', 'introspect', 'stages'], {
    cwd: REPO,
    encoding: 'utf8',
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' },
  });
  return JSON.parse(out).stages;
}

export function syntheticFindings(afterMs, count = ROW_COUNT - 4) {
  return Array.from({ length: count }, (_, i) => {
    const [severity, template, path, summary] = SYNTHETIC[i % SYNTHETIC.length];
    const host = `${SUBDOMAINS[i % SUBDOMAINS.length]}.example.com`;
    return { t: afterMs + (i + 1) * 500, severity, template, host, url: `https://${host}${path}`, summary };
  });
}

const pad2 = (n) => String(n).padStart(2, '0');
const clock = (ms) => new Date(ms).toISOString().slice(11, 19);
const hms = (ms) => {
  const s = Math.floor(ms / 1000);
  return `${pad2(Math.floor(s / 3600))}:${pad2(Math.floor(s / 60) % 60)}:${pad2(s % 60)}`;
};
const shortDuration = (ms) => {
  const s = Math.round(ms / 1000);
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}:${pad2(s % 60)}`;
};
const runId = (ms) => new Date(ms).toISOString().slice(0, 16).replace(/-/g, '').replace('T', '-').replace(':', '');
const icon = (id) => `<svg viewBox="0 0 16 16" aria-hidden="true"><use href="#${id}"/></svg>`;

// Fixture stages keep their real result. The rest get a deterministic state so
// every stage status is visible: one failure, opt-in stages skipped, the first
// stage after the fixture's last one running, and the remainder queued.
function stageStates(stages, events) {
  const ended = new Map(events.filter((e) => e.type === 'stage_end').map((e) => [e.stage, e]));
  const top = stages.filter((s) => !s.parent).sort((a, b) => a.num - b.num);
  const lastEnded = Math.max(0, ...top.filter((s) => ended.has(s.id)).map((s) => s.num));
  const running = top.find((s) => s.num > lastEnded && !s.opt_in);
  const failed = top.findLast(
    (s) => s.tier === 'passive' && !ended.has(s.id) && !s.opt_in && s.num < (running?.num ?? 0),
  );
  const state = (stage) => {
    const end = ended.get(stage.id);
    if (end) {
      return {
        status: STATUSES.has(end.status) ? end.status : 'queued',
        duration: end.duration_ms,
        count: Object.values(end.counts ?? {})[0],
      };
    }
    if (stage.opt_in) return { status: 'skipped' };
    if (stage.id === running?.id) return { status: 'running', duration: 41000 };
    if (stage.id === failed?.id) return { status: 'failed', duration: stage.num * 1000 };
    if (running && stage.num < running.num) {
      return { status: 'ok', duration: (((stage.num * 7) % 40) + 3) * 1000, count: (stage.num * 13) % 90 };
    }
    return { status: 'queued' };
  };
  const states = new Map();
  for (const stage of top) states.set(stage.id, state(stage));
  for (const stage of stages) {
    if (stage.parent) {
      const parent = states.get(stage.parent);
      states.set(stage.id, parent?.status === 'ok' ? { status: 'ok', duration: 4000, count: 2 } : { status: 'queued' });
    }
  }
  return { states, top, running };
}

const statusGlyph = (status) =>
  status === 'running'
    ? '<span class="status-running"><span class="live-dot is-live"></span></span>'
    : `<span class="status-${status}">${icon(`st-${status}`)}</span>`;

function renderStage(stage, state) {
  const child = stage.parent ? ' is-child' : '';
  const index = stage.parent ? '' : safeText(pad2(stage.num));
  const duration = state.duration === undefined ? '-' : shortDuration(state.duration);
  const count = state.count === undefined ? '' : safeText(state.count);
  return `<li class="stage ${state.status}${child}" data-stage="${safeText(stage.id)}"><span class="num idx">${index}</span><span class="tier">${icon(`tier-${stage.tier}`)}</span><span class="mono name clip">${safeText(stage.id)}</span>${statusGlyph(state.status)}<span class="num dur">${duration}</span><span class="num cnt">${count}</span></li>`;
}

function renderStageList(stages, states) {
  const unknown = stages.find((s) => !TIERS.includes(s.tier));
  if (unknown) throw new Error(`unknown tier for stage ${unknown.id}`);
  const children = (id) => stages.filter((s) => s.parent === id);
  return TIERS.map((tier) => {
    const rows = stages
      .filter((s) => !s.parent && s.tier === tier)
      .flatMap((s) => [s, ...children(s.id)])
      .map((s) => renderStage(s, states.get(s.id)))
      .join('');
    return `<div class="tier-head micro">${tier}</div><ol>${rows}</ol>`;
  }).join('');
}

function renderTrack(top, states) {
  return TIERS.map((tier) => {
    const segments = top
      .filter((s) => s.tier === tier)
      .map((s) => {
        const { status } = states.get(s.id);
        const live = status === 'running' ? ' is-live' : '';
        return `<span class="seg ${status}${live}" data-seg="${safeText(s.id)}"></span>`;
      })
      .join('');
    return `<span class="track-tier">${segments}</span>`;
  }).join('');
}

const renderChip = (severity) =>
  `<span class="chip sev-${severity}">${icon(`bars-${SEV_BARS[severity]}`)}${SEV_LABEL[severity]}</span>`;

function renderRow(row, index) {
  const selected = index === SELECTED_ROW ? ' selected' : '';
  const aria = index === SELECTED_ROW ? ' aria-selected="true"' : '';
  return `<div class="tr sev-${row.severity}${selected}" role="row" data-row="${index}"${aria}><span role="cell">${renderChip(row.severity)}</span><span class="mono clip td-template" role="cell">${safeText(row.template)}</span><span class="mono clip td-host" role="cell">${safeText(row.host)}</span><span class="mono clip td-url" role="cell">${safeText(row.url)}</span><span class="clip td-summary" role="cell">${safeText(row.summary)}</span><span class="num time" role="cell">${clock(row.t)}</span></div>`;
}

function renderLogLine(event) {
  const isLog = event.type === 'log';
  const level = isLog ? event.level : event.stream === 'stderr' ? 'err' : 'out';
  const css = level === 'err' || level === 'error' ? 'err' : level === 'out' ? 'out' : 'info';
  const tag = sanitizeText(isLog ? 'run' : event.stage).slice(0, 10).padEnd(10);
  const message = isLog ? event.msg : event.line;
  return `<div class="log-line"><span class="ts">${clock(event.t)}</span><span class="tag">${escapeHtml(tag)}</span><span class="lvl-${css}">${escapeHtml(sanitizeText(level).toUpperCase())}</span><span class="msg">${safeText(message)}</span></div>`;
}

const SPRITE = `<svg class="sprite" width="0" height="0" hidden aria-hidden="true"><defs>
<symbol id="nav-launch" viewBox="0 0 16 16"><path d="M4 2.5v11l9-5.5z"/></symbol>
<symbol id="nav-monitor" viewBox="0 0 16 16"><path d="M1.5 8.5h3l2-5 3 9 2-4h3"/></symbol>
<symbol id="nav-runs" viewBox="0 0 16 16"><path d="M2.5 3.5h11M2.5 8h11M2.5 12.5h11"/></symbol>
<symbol id="nav-findings" viewBox="0 0 16 16"><path d="M7 2.5a4.5 4.5 0 1 0 0 9 4.5 4.5 0 0 0 0-9zM10.5 10.5l3 3"/></symbol>
<symbol id="nav-doctor" viewBox="0 0 16 16"><path d="M2.5 2.5h11v11h-11zM8 5v6M5 8h6"/></symbol>
<symbol id="nav-settings" viewBox="0 0 16 16"><path d="M2.5 4.5h6M11.5 4.5h2M2.5 11.5h2M7.5 11.5h6M8.5 2.5h3v4h-3zM4.5 9.5h3v4h-3z"/></symbol>
<symbol id="win-min" viewBox="0 0 16 16"><path d="M3 8h10"/></symbol>
<symbol id="win-max" viewBox="0 0 16 16"><path d="M3.5 3.5h9v9h-9z"/></symbol>
<symbol id="win-close" viewBox="0 0 16 16"><path d="M3.5 3.5l9 9M12.5 3.5l-9 9"/></symbol>
<symbol id="tier-passive" viewBox="0 0 16 16"><path d="M3.5 3.5h9v9h-9z"/></symbol>
<symbol id="tier-active" viewBox="0 0 16 16"><path d="M3.5 3.5h9v9h-9z"/><path d="M3.5 3.5h4.5v9H3.5z" fill="currentColor"/></symbol>
<symbol id="tier-intrusive" viewBox="0 0 16 16"><path d="M3.5 3.5h9v9h-9zM3.5 8L8 3.5M3.5 12.5l9-9M8 12.5L12.5 8"/><path class="tick" d="M12.5 1v2"/></symbol>
<symbol id="st-ok" viewBox="0 0 16 16"><path d="M3 8.5l3.5 3.5L13 4.5"/></symbol>
<symbol id="st-failed" viewBox="0 0 16 16"><path d="M4 4l8 8M12 4l-8 8"/></symbol>
<symbol id="st-skipped" viewBox="0 0 16 16"><path d="M3.5 3.5h9v9h-9z" stroke-dasharray="2 2"/><path d="M5 11l6-6"/></symbol>
<symbol id="st-queued" viewBox="0 0 16 16"><path d="M5 5h6v6H5z"/></symbol>
<symbol id="sort-asc" viewBox="0 0 16 16"><path d="M8 4l5 8H3z"/></symbol>
<symbol id="sort-desc" viewBox="0 0 16 16"><path d="M8 12L3 4h10z"/></symbol>
<symbol id="stop" viewBox="0 0 16 16"><path d="M4 4h8v8H4z" fill="currentColor"/></symbol>
${[0, 1, 2, 3, 4]
  .map(
    (n) =>
      `<symbol id="bars-${n}" viewBox="0 0 11 8">${[0, 1, 2, 3]
        .map((b) => `<rect x="${b * 3}" y="0" width="2" height="8" opacity="${b < n ? 1 : 0.25}"/>`)
        .join('')}</symbol>`,
  )
  .join('')}
</defs></svg>`;

const NAV = [
  ['launch', 'Launch'],
  ['monitor', 'Monitor'],
  ['runs', 'Runs'],
  ['findings', 'Findings'],
  ['doctor', 'Doctor'],
  ['settings', 'Settings'],
];

export function renderMock({ stages, events }) {
  const css = readFileSync(STYLESHEET, 'utf8');
  const cssHash = createHash('sha256').update(css).digest('base64');
  const csp = `default-src 'none'; style-src 'self' 'sha256-${cssHash}'; font-src 'self'; base-uri 'none'; form-action 'none'`;

  const start = events.find((e) => e.type === 'run_start');
  const end = events.find((e) => e.type === 'run_end');
  const fixture = events.filter((e) => e.type === 'finding');
  const rows = [...fixture, ...syntheticFindings(fixture.at(-1)?.t ?? start.t, ROW_COUNT - fixture.length)].map(
    (row) => ({ ...row, severity: SEVERITIES.includes(row.severity) ? row.severity : 'info' }),
  );
  const totals = Object.fromEntries(SEVERITIES.map((s) => [s, rows.filter((r) => r.severity === s).length]));
  const selected = rows[SELECTED_ROW];

  const { states, top, running } = stageStates(stages, events);
  const logEvents = events.filter((e) => e.type === 'output' || e.type === 'log');
  const tools = [...new Set(events.filter((e) => e.type === 'output').map((e) => e.tool))];
  const elapsed = end.t - start.t;
  const rate = Math.round(events.length / (elapsed / 1000));
  const position = safeText(`${pad2(running?.num ?? top.length)}/${top.length}`);

  const filterTabs = [
    `<button class="tab active" type="button">All <span class="num">${rows.length}</span></button>`,
    ...SEVERITIES.map(
      (s) => `<button class="tab" type="button">${SEV_LABEL[s]} <span class="num">${totals[s]}</span></button>`,
    ),
  ].join('');
  const logTabs = ['all', ...tools]
    .map((tool, i) => `<button class="tab${i === 0 ? ' active' : ''}" type="button">${safeText(tool)}</button>`)
    .join('');
  const nav = NAV.map(
    ([id, label]) =>
      `<a class="${id === 'monitor' ? 'active' : ''}" role="link" aria-label="${label}"${id === 'monitor' ? ' aria-current="page"' : ''}>${icon(`nav-${id}`)}</a>`,
  ).join('');
  const counts = SEVERITIES.map(
    (s) => `<span class="sev-${s}"><span class="k">${s[0].toUpperCase()}</span>${totals[s]}</span>`,
  ).join('');

  return `<!doctype html>
<html lang="en" class="density-compact">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bounty Runner - Monitor</title>
<link rel="stylesheet" href="../src/styles/fonts.css">
<link rel="stylesheet" href="../src/styles/tokens.css">
<style>${css}</style>
</head>
<body>
${SPRITE}
<header class="titlebar"><span class="brand">BOUNTY RUN</span><span class="winctl"><button type="button" aria-label="Minimize">${icon('win-min')}</button><button type="button" aria-label="Maximize">${icon('win-max')}</button><button class="close" type="button" aria-label="Close">${icon('win-close')}</button></span></header>
<section class="context" aria-label="Run context"><span class="mono target">${safeText(start.target)}</span><span class="meta mono"><span>${runId(start.t)}</span><span class="sep">/</span><span class="label">Standard</span><span class="sep">/</span><span class="label">Ceiling intrusive</span></span><span class="track" aria-label="Stage progress">${renderTrack(top, states)}</span><span class="spacer"></span><span class="danger-wrap"><button class="btn btn-danger" type="button">${icon('stop')}Stop</button></span></section>
<div class="frame">
<nav class="rail" aria-label="Primary">${nav}</nav>
<main class="monitor">
<section class="pane stages" aria-label="Stages"><div class="pane-head"><h2 class="pane-title">Stages</h2><span class="spacer"></span><span class="num pane-count">${position}</span></div><div class="stage-groups">${renderStageList(stages, states)}</div></section>
<section class="pane findings" aria-label="Findings"><div class="pane-head"><h2 class="pane-title">Findings</h2><div class="tabs" role="tablist">${filterTabs}</div><span class="spacer"></span><div class="segmented" role="group" aria-label="Row density"><button type="button">Comfortable</button><button class="active" type="button" aria-pressed="true">Compact</button></div><span class="corner-mark"></span></div><div class="table" role="table" aria-label="Findings"><div class="tr thead" role="row"><span class="th label" role="columnheader">Sev</span><span class="th label" role="columnheader">Template</span><span class="th label" role="columnheader">Host</span><span class="th label" role="columnheader">URL</span><span class="th label" role="columnheader">Summary</span><span class="th label right" role="columnheader" aria-sort="ascending">Time ${icon('sort-asc')}</span></div><div class="tbody" role="rowgroup">${rows.map(renderRow).join('')}</div></div></section>
<aside class="pane inspector" aria-label="Inspector"><div class="pane-head"><h2 class="pane-title">Inspector</h2></div><div class="pane-head"><div class="tabs" role="tablist"><button class="tab" type="button">Request</button><button class="tab" type="button">Response</button><button class="tab active" type="button">Meta</button></div></div><div class="body"><div class="section-title">${safeText(selected.summary)}</div><dl class="kv"><dt class="micro">Severity</dt><dd>${renderChip(selected.severity)}</dd><dt class="micro">Template</dt><dd class="mono">${safeText(selected.template)}</dd><dt class="micro">Host</dt><dd class="mono">${safeText(selected.host)}</dd><dt class="micro">URL</dt><dd class="mono">${safeText(selected.url)}</dd><dt class="micro">Seen</dt><dd class="mono">${clock(selected.t)}</dd></dl><hr class="rule"><div class="note">No captured evidence in this replay.</div><div class="actions"><button class="btn btn-ghost" type="button">repro.sh</button></div></div></aside>
<section class="pane log" aria-label="Log"><div class="pane-head"><h2 class="pane-title">Log</h2><div class="tabs" role="tablist">${logTabs}</div><span class="new-lines">${icon('sort-desc')}${Math.max(0, logEvents.length - LOG_LINES)} NEW</span></div><div class="log-lines">${logEvents.slice(0, LOG_LINES).map(renderLogLine).join('')}</div></section>
</main>
</div>
<footer class="statusbar"><span class="live"><span class="live-dot is-live"></span>LIVE</span><span>STAGE ${position}</span><span>${hms(elapsed)}</span><span>${rate} ev/s</span><span class="counts">${counts}</span><span class="spacer"></span><span>engine</span><span class="ok">${icon('st-ok')}tools</span></footer>
</body>
</html>
`;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const html = renderMock({ stages: loadStages(), events: loadEvents() });
  if (process.argv.includes('--stdout')) process.stdout.write(html);
  else writeFileSync(OUTPUT, html);
}
