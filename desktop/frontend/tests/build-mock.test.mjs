import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { sanitizeText as appSanitizeText } from '../src/lib/monitor/text.js';
import { fileURLToPath } from 'node:url';

import {
  escapeHtml,
  loadEvents,
  loadStages,
  renderMock,
  safeText,
  sanitizeText,
  syntheticFindings,
} from '../scripts/build-mock.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const events = loadEvents();
const stages = loadStages();
const fixtureFindings = events.filter((event) => event.type === 'finding');

const HOSTILE = [
  '<script>alert(1)</script>',
  '"><img src=x onerror=alert(1)>',
  "' onmouseover='alert(1)",
  '</style><script>alert(1)</script>',
  '\u001b[31mred\u001b[0m',
  '\u001b]8;;https://evil.example\u0007link\u001b]8;;\u0007',
  'safe\u202Egnp.exe\u2066x\u2069',
].join(' ');

const hostileEvents = () =>
  events.map((event) =>
    event.type === 'finding'
      ? { ...event, template: HOSTILE, host: HOSTILE, url: HOSTILE, summary: HOSTILE }
      : event.type === 'output'
        ? { ...event, tool: HOSTILE, line: HOSTILE }
        : event.type === 'run_start'
          ? { ...event, target: HOSTILE }
          : event,
  );

test('escapeHtml neutralises every markup character', () => {
  assert.equal(escapeHtml(`<a href="x" id='y'>&`), '&lt;a href=&quot;x&quot; id=&#39;y&#39;&gt;&amp;');
});

test('sanitizeText (app and mock) strips zero-width and format characters', () => {
  const bad = ['\u00ad', '\u180e', '\u200b', '\u200c', '\u200d', '\u2028', '\u2029', '\u2060', '\u2064', '\ufeff', '\ufff9', '\ufffb', '\u{e0000}', '\u{e0041}', '\u{e007f}'];
  for (const c of bad) assert.equal(appSanitizeText(`a${c}b`), 'ab', `U+${c.codePointAt(0).toString(16)}`);
  for (const f of [sanitizeText, appSanitizeText]) assert.equal(f('a\u00adb\u{e0041}'), 'ab');
  assert.equal(appSanitizeText('pay\u200bpal\u202e'), 'paypal');
  assert.equal(appSanitizeText('caf\u00e9 \u{1f600}'), 'caf\u00e9 \u{1f600}');
});

test('sanitizeText strips ANSI, controls and bidi overrides', () => {
  assert.equal(sanitizeText('\u001b[31mred\u001b[0m'), 'red');
  assert.equal(sanitizeText('\u001b]8;;https://evil.example\u0007link\u001b]8;;\u0007'), 'link');
  assert.equal(sanitizeText('a\u0000b\u007fc\u0085d'), 'abcd');
  assert.equal(sanitizeText('a\u202Eb\u2066c\u2069d\u200Fe\u061Cf'), 'abcdef');
});

test('safeText keeps the visible text of a hostile string', () => {
  assert.equal(safeText('<b>\u202Ex'), '&lt;b&gt;x');
});

test('a hostile fixture renders inert', () => {
  const html = renderMock({ stages, events: hostileEvents() });
  assert.ok(!/<script/i.test(html), 'no script element');
  assert.ok(!/<img/i.test(html), 'no injected element');
  assert.ok(!/<[^>]*\son\w+\s*=/i.test(html), 'no event handler attribute');
  assert.ok(!/\u001b/.test(html), 'no ANSI escape');
  assert.ok(!/[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]/.test(html), 'no bidi control');
  assert.equal((html.match(/<\/style>/g) ?? []).length, 1, 'style block not closed early');
  assert.ok(html.includes('&lt;script&gt;'), 'hostile text is still visible as text');
});

test('hostile values in class-bound fields cannot break out of attributes', () => {
  const attack = '"><img src=x onerror=alert(1)>';
  const hostile = events.map((event) => {
    if (event.type === 'finding') return { ...event, severity: attack };
    if (event.type === 'stage_end') return { ...event, status: attack, counts: { hits: attack } };
    if (event.type === 'log') return { ...event, level: attack };
    return event;
  });
  const hostileStages = stages.map((stage, i) => (i === 0 ? { ...stage, num: attack } : stage));
  const html = renderMock({ stages: hostileStages, events: hostile });
  assert.ok(!/<img/i.test(html), 'no injected element');
  assert.ok(!/<[^>]*\son\w+\s*=/i.test(html), 'no event handler attribute');
});

test('a stage with an unknown tier fails the build instead of vanishing', () => {
  const bad = [...stages, { id: 'zz', num: 22, title: 'X', tier: 'unknown', caps: [], opt_in: false, parent: null }];
  assert.throws(() => renderMock({ stages: bad, events }), /unknown tier/);
});

test('the mock has no script, network reference or inline style', () => {
  const html = readFileSync(join(root, 'mock/monitor.html'), 'utf8');
  assert.ok(!/<script/i.test(html));
  assert.ok(!/\s(?:src|href|action|srcset|poster|data)\s*=\s*["']?(?:https?:)?\/\//i.test(html));
  assert.ok(!/url\(\s*["']?(?:https?:)?\/\//i.test(html));
  assert.ok(!/\sstyle\s*=/i.test(html));
  assert.ok(!/\son\w+\s*=/i.test(html));
});

test('the mock declares a restrictive CSP', () => {
  const html = readFileSync(join(root, 'mock/monitor.html'), 'utf8');
  const csp = html.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)?.[1] ?? '';
  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /base-uri 'none'/);
  assert.match(csp, /form-action 'none'/);
  assert.ok(!csp.includes('unsafe-inline'));
  assert.ok(!/script-src/.test(csp));
  assert.ok(!/https?:/.test(csp));
});

test('fixture findings come first and verbatim', () => {
  const html = renderMock({ stages, events });
  let last = -1;
  for (const finding of fixtureFindings) {
    const at = html.indexOf(`>${escapeHtml(finding.template)}<`);
    assert.ok(at > last, finding.template);
    last = at;
    assert.ok(html.includes(escapeHtml(finding.url)));
    assert.ok(html.includes(escapeHtml(finding.summary)));
  }
  assert.ok(html.indexOf('data-row="0"') < html.indexOf(escapeHtml(fixtureFindings[0].template)));
});

test('synthetic rows are deterministic, on example.com, and cover all severities', () => {
  const rows = syntheticFindings(fixtureFindings.at(-1).t);
  assert.deepEqual(rows, syntheticFindings(fixtureFindings.at(-1).t));
  for (const row of rows) {
    assert.ok(row.host.endsWith('.example.com'), row.host);
    assert.ok(new URL(row.url).hostname.endsWith('.example.com'), row.url);
  }
  const severities = new Set(rows.map((row) => row.severity));
  for (const severity of ['critical', 'high', 'medium', 'low', 'info']) {
    assert.ok(severities.has(severity), severity);
  }
});

test('stage rows come from the engine, with origin_deep nested under origin', () => {
  const html = renderMock({ stages, events });
  for (const stage of stages) {
    assert.ok(html.includes(`data-stage="${stage.id}"`), stage.id);
  }
  assert.match(html, /<li class="[^"]*\bis-child\b[^"]*" data-stage="origin_deep"/);
  assert.ok(html.indexOf('data-stage="origin"') < html.indexOf('data-stage="origin_deep"'));
});

test('a stage the engine adds appears without touching the build script', () => {
  const added = [...stages, { id: 'zz_new', num: 21, title: 'NEW', tier: 'active', caps: [], opt_in: false, parent: null }];
  assert.ok(renderMock({ stages: added, events }).includes('data-stage="zz_new"'));
});

test('the committed mock matches a fresh build', () => {
  const out = execFileSync(process.execPath, [join(root, 'scripts/build-mock.mjs'), '--stdout'], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  assert.equal(out, readFileSync(join(root, 'mock/monitor.html'), 'utf8'));
});

test('no tracked frontend source holds a literal bidi control', () => {
  const bidi = /\u061C|[\u200E\u200F\u202A-\u202E\u2066-\u2069]/;
  const tracked = execFileSync('git', ['ls-files', '-z', '.'], { cwd: root, encoding: 'utf8' })
    .split('\0')
    .filter((file) => file && !file.endsWith('.woff2'));
  assert.ok(tracked.length > 0);
  for (const file of tracked) {
    assert.ok(!bidi.test(readFileSync(join(root, file), 'utf8')), file);
  }
});
