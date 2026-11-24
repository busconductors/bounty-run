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

const SVELTE = 'src/lib/Row.svelte';
const HTML = 'mock/monitor.html';

test('a comment opener inside a string does not hide declarations', () => {
  const found = rules(
    'a{content:"/*";color:#fff;border-radius:99px;margin:13px;background:linear-gradient(red,blue)}b{content:"*/"}',
  );
  for (const rule of ['hex', 'radius', 'px', 'gradient']) assert.ok(found.includes(rule), rule);
});

test('a quote inside a comment does not hide declarations', () => {
  assert.ok(rules('/* it\'s */ .a { color: #fff; } /* \' */').includes('hex'));
});

test('an escaped quote outside a string does not open one', () => {
  assert.ok(rules('.a\\" { color: #fff; } .b\\" { margin: 13px; }').includes('hex'));
});

test('an arrow handler does not end the tag early', () => {
  const found = rules('<button onclick={() => go()} style="margin:13px;color:#fff">x</button>', SVELTE);
  assert.ok(found.includes('px'));
  assert.ok(found.includes('hex'));
});

test('a quoted attribute containing > does not end the tag early', () => {
  assert.ok(rules('<a title="a>b" style="margin:13px">x</a>', HTML).includes('px'));
});

test('lints style: directives with literal values', () => {
  assert.ok(rules('<p style:margin="13px">x</p>', SVELTE).includes('px'));
  assert.ok(rules('<p style:color="#fff">x</p>', SVELTE).includes('hex'));
  assert.ok(rules('<p style:margin|important="13px">x</p>', SVELTE).includes('px'));
  assert.deepEqual(rules('<p style:margin="var(--s3)">x</p>', SVELTE), []);
});

test('rejects dynamic style expressions', () => {
  for (const source of [
    '<p style={"margin:13px"}>x</p>',
    '<p style={css}>x</p>',
    '<p {style}>x</p>',
    '<p style="margin:{size}px">x</p>',
    '<p style=margin:{size}>x</p>',
    '<p style:margin={size}>x</p>',
    '<p style:margin>x</p>',
    '<p style:--gap={size}>x</p>',
    '<p style="--gap:{size}">x</p>',
  ]) {
    assert.ok(rules(source, SVELTE).includes('dynamic-style'), source);
  }
});

test('allows a dynamic form only when it is exactly a var() token', () => {
  assert.deepEqual(rules(`<p style:margin={'var(--s3)'}>x</p>`, SVELTE), []);
  assert.deepEqual(rules('<p style:--gap={"var(--s3)"}>x</p>', SVELTE), []);
  assert.deepEqual(rules(`<p style="--gap:{'var(--s3)'}">x</p>`, SVELTE), []);
  assert.ok(rules(`<p style="margin:{'var(--s3)'}">x</p>`, SVELTE).includes('dynamic-style'));
  assert.ok(rules(`<p style:margin={'var(--s3, 13px)'}>x</p>`, SVELTE).includes('dynamic-style'));
});

test('lints unquoted style and color attributes', () => {
  assert.ok(rules('<p style=margin:13px>x</p>', HTML).includes('px'));
  assert.ok(rules('<path fill=#ff0000>', HTML).includes('hex'));
  assert.ok(rules('<path fill=#ff0000/>', HTML).includes('hex'));
});

test('markup inside script bodies and comments is not linted as tags', () => {
  assert.deepEqual(rules('<script>const a = 1 < 2; const b = "<p style=margin:13px>";</script>', SVELTE), []);
  assert.deepEqual(rules('<!-- <p style="margin:13px"> -->', HTML), []);
});

test('text expressions containing < do not start a tag', () => {
  assert.deepEqual(rules('<p>{a <b style="margin:13px"}</p>', SVELTE), []);
});

test('rejects numeric forms that hide an off-scale px', () => {
  for (const value of ['1e1px', '1E1PX', '13p\\78', '13\\70 x', '+13px', '.13e2px']) {
    assert.ok(rules(`.a { margin: ${value}; }`).includes('px'), value);
  }
});

test('still accepts on-scale values in scientific form', () => {
  assert.deepEqual(rules('.a { margin: 1e0px 0px 2px; }'), []);
});

test('rejects arithmetic on raw lengths', () => {
  for (const value of ['calc(2px * 50)', 'calc(1px + 1px)', 'max(2px, 1px)', 'clamp(1px, 2px, 2px)']) {
    assert.ok(rules(`.a { margin: ${value}; }`).includes('px'), value);
  }
  assert.deepEqual(rules('.a { width: calc(100% - var(--s3)); }'), []);
});

test('rejects non-token length units', () => {
  for (const value of ['13rem', '13pt', '1em', '2vh', '3vw', '1cm', '1in', '1pc', '2ch', '1lh', '1dvh', '1cqw']) {
    assert.ok(rules(`.a { margin: ${value}; }`).includes('unit'), value);
  }
});

test('leaves non-length units alone', () => {
  assert.deepEqual(rules('.a { grid-template-columns: minmax(0, 1fr) 100%; rotate: 45deg; transition-duration: 1s; }'), []);
});

test('tokens.css may define lengths in any unit', () => {
  assert.deepEqual(rules(':root { --tr-x: .12em; --s9: 13px; }', TOKENS), []);
});

test('property names and functions cannot hide behind escapes', () => {
  assert.ok(rules('.a { border-r\\61 dius: 99px; }').includes('radius'));
  assert.ok(rules('.a { color: \\23 fff; }').includes('hex'));
});

test('rejects rounded clip-path shapes', () => {
  for (const value of ['circle(50%)', 'ellipse(50% 40%)', 'inset(0 round 50%)', 'path("M0 0A9 9 0 0 1 9 9")']) {
    assert.ok(rules(`.a { clip-path: ${value}; }`).includes('radius'), value);
  }
  assert.ok(rules('.a { -webkit-clip-path: circle(50%); }').includes('radius'));
  assert.ok(rules('.a { --shape: circle(50%); clip-path: var(--shape); }').includes('radius'));
});

test('the chamfer polygon keeps passing', () => {
  assert.deepEqual(rules('.a { clip-path: var(--chamfer); }'), []);
  const tokens = readFileSync(join(root, TOKENS), 'utf8');
  assert.match(tokens, /--chamfer: polygon\(/);
  assert.deepEqual(lintSource(tokens, TOKENS), []);
});

test('rejects SVG rx and ry above 2px', () => {
  assert.ok(rules('<rect rx="3" width="2"/>', HTML).includes('radius'));
  assert.ok(rules('<rect ry=9 width="2"/>', HTML).includes('radius'));
  assert.ok(rules('<rect rx="50%"/>', HTML).includes('radius'));
  assert.ok(rules('<rect rx={size}/>', SVELTE).includes('radius'));
  assert.ok(rules('.a { rx: 3px; }').includes('radius'));
  assert.deepEqual(rules('<rect rx="2" ry="1px"/>', HTML), []);
});

test('.is-live must be an exact positive class', () => {
  for (const selector of [
    '.dot:not(.is-live)',
    '.is-live-static',
    '.is-live_x',
    '.dot:not(.a, .is-live)',
    '.is-live .child',
    '.is-live, .dot',
  ]) {
    assert.ok(rules(`${selector} { box-shadow: var(--glow); }`).includes('shadow'), selector);
  }
  assert.deepEqual(rules('.a.is-live, .b.is-live { box-shadow: var(--glow); }'), []);
  assert.deepEqual(rules('.a .b.is-live { box-shadow: var(--glow); }'), []);
});

test('forbids redefining the glow outside tokens.css', () => {
  assert.ok(rules('.x.is-live { --glow: 0 0 2px var(--tx-hi); box-shadow: var(--glow); }').includes('shadow'));
  assert.ok(rules('.x { --red-glow: var(--tx-hi); }').includes('shadow'));
  assert.ok(rules('<p style="--glow: 0 0 1px var(--tx)">x</p>', HTML).includes('shadow'));
  assert.ok(rules('<p style:--glow="var(--tx)">x</p>', SVELTE).includes('shadow'));
});

test('rejects blur in filters', () => {
  assert.ok(rules('.a { filter: blur(2px); }').includes('blur'));
  assert.ok(rules('.a { -webkit-filter: blur(1px); }').includes('blur'));
  assert.ok(rules('.a { --soft: blur(1px); filter: var(--soft); }').includes('blur'));
  assert.ok(rules('.a { filter: bl\\75r(1px); }').includes('blur'));
});
