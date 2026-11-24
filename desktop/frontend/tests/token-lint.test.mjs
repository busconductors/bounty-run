import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { lintSource, lintTree } from '../scripts/token-lint.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const TOKENS = 'src/styles/tokens.css';
const rules = (source, file = 'src/app.css') => lintSource(source, file).map((v) => v.rule);

test('rejects border-radius above 2px', () => {
  assert.ok(rules('.a { border-radius: 4px; }').includes('radius'));
});

test('rejects large radius in every unit and longhand', () => {
  for (const value of ['1rem', '50%', '0 0 3px 0', '999px']) {
    assert.ok(rules(`.a { border-radius: ${value}; }`).includes('radius'), value);
  }
  assert.ok(rules('.a { border-top-left-radius: 3px; }').includes('radius'));
});

test('rejects radius above 2px even inside tokens.css', () => {
  assert.ok(rules(':root { --radius-ctl: 4px; }', TOKENS).includes('radius'));
  assert.ok(rules('.a { border-radius: 4px; }', TOKENS).includes('radius'));
});

test('rejects a var() radius that resolves above 2px', () => {
  assert.ok(rules('.a { border-radius: var(--cut); }').includes('radius'));
});

test('accepts radius tokens and small radii', () => {
  for (const value of ['0', '1px', '2px', 'var(--radius)', 'var(--radius-ctl)']) {
    assert.deepEqual(rules(`.a { border-radius: ${value}; }`), [], value);
  }
});

test('rejects raw hex outside tokens.css', () => {
  assert.ok(rules('.a { color: #fff; }').includes('hex'));
  assert.ok(rules('.a { background: #0a0a0b80; }').includes('hex'));
});

test('rejects raw color functions outside tokens.css', () => {
  assert.ok(rules('.a { color: rgba(1, 2, 3, .5); }').includes('raw-color'));
  assert.ok(rules('.a { color: hsl(3 80% 50%); }').includes('raw-color'));
});

test('does not mistake an id selector for hex', () => {
  assert.deepEqual(rules('#abc { color: var(--tx); }'), []);
});

test('rejects off-scale px outside tokens.css', () => {
  for (const value of ['3px', '13px', '1.5px', '-1px', '10PX']) {
    assert.ok(rules(`.a { margin: ${value}; }`).includes('px'), value);
  }
});

test('allows only 0, 1px, 2px and var() for px values', () => {
  assert.deepEqual(rules('.a { margin: 0 1px 2px var(--s3); }'), []);
});

test('ignores values inside comments and strings', () => {
  assert.deepEqual(rules('/* #fff 13px */ .a { content: "#fff 13px"; }'), []);
});

test('accepts tokens.css as written', () => {
  const source = readFileSync(join(root, TOKENS), 'utf8');
  assert.deepEqual(lintSource(source, TOKENS), []);
});

test('a file merely named tokens.css gets no exemption', () => {
  assert.ok(rules('.a { color: #fff; }', 'src/lib/tokens.css').includes('hex'));
});

test('allows box-shadow only as var(--glow) on a live-state element', () => {
  assert.deepEqual(rules('.dot.is-live { box-shadow: var(--glow); }'), []);
  assert.ok(rules('.dot { box-shadow: var(--glow); }').includes('shadow'));
  assert.ok(rules('.dot.is-live { box-shadow: 0 0 1px var(--red-glow); }').includes('shadow'));
  assert.ok(rules('.dot.is-live:hover { box-shadow: var(--glow); }').includes('shadow'));
});

test('rejects text-shadow and drop-shadow filters', () => {
  assert.ok(rules('.a { text-shadow: 0 0 1px var(--tx); }').includes('shadow'));
  assert.ok(rules('.a { filter: drop-shadow(0 0 1px var(--tx)); }').includes('shadow'));
});

test('rejects backdrop-filter, prefixed or not', () => {
  assert.ok(rules('.a { backdrop-filter: blur(2px); }').includes('backdrop-filter'));
  assert.ok(rules('.a { -webkit-backdrop-filter: blur(2px); }').includes('backdrop-filter'));
});

test('rejects gradients except the hatch token', () => {
  assert.ok(rules('.a { background: linear-gradient(var(--bg-0), var(--bg-1)); }').includes('gradient'));
  assert.ok(rules(':root { --wash: radial-gradient(var(--bg-0), var(--bg-1)); }', TOKENS).includes('gradient'));
  assert.deepEqual(
    rules(':root { --hatch: repeating-linear-gradient(45deg, var(--tx-lo) 0 1px, transparent 1px 3px); }', TOKENS),
    [],
  );
  assert.deepEqual(rules('.a { background-image: var(--hatch); }'), []);
});

test('a hatch token outside tokens.css is still a gradient', () => {
  assert.ok(rules('.a { --hatch: linear-gradient(var(--bg-0), var(--bg-1)); }').includes('gradient'));
});

test('rejects {@html} in component files', () => {
  assert.ok(rules('<p>{@html row.summary}</p>', 'src/lib/Row.svelte').includes('raw-html'));
  assert.ok(rules('<p>{ @html row.summary }</p>', 'src/lib/Row.svelte').includes('raw-html'));
});

test('lints the CSS inside an HTML style block', () => {
  const html = '<!doctype html><style>.a { color: #fff; margin: 13px; }</style>';
  const found = rules(html, 'mock/monitor.html');
  assert.ok(found.includes('hex'));
  assert.ok(found.includes('px'));
});

test('lints inline style attributes and color attributes', () => {
  assert.ok(rules('<p style="margin: 13px">x</p>', 'mock/monitor.html').includes('px'));
  assert.ok(rules('<path fill="#ff0000"/>', 'mock/monitor.html').includes('hex'));
});

test('does not treat escaped page text as CSS', () => {
  assert.deepEqual(rules('<p>https://a.example/#fff 13px</p>', 'mock/monitor.html'), []);
});

test('reports the line of a violation', () => {
  const [violation] = lintSource('.a {\n  color: #fff;\n}', 'src/app.css');
  assert.equal(violation.line, 2);
});

test('the frontend tree lints clean, and includes the mock', () => {
  const { files, violations } = lintTree(root);
  assert.deepEqual(violations, []);
  assert.ok(files.some((file) => file.endsWith('mock/monitor.html')));
  assert.ok(files.some((file) => file.endsWith('src/styles/tokens.css')));
});
