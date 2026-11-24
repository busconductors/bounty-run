import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { patchDragModule, wailsRuntimeFix } from '../scripts/wails-runtime-fix.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const dragPath = join(root, 'node_modules', '@wailsio', 'runtime', 'dist', 'drag.js');
const dragSource = readFileSync(dragPath, 'utf8');

// What WebKitGTK reports on ARM64 Linux: it names Android, which the stock
// runtime's UA fallback mistakes for a phone and so never arms window drag.
const ARM64_WEBKITGTK_UA =
  'Mozilla/5.0 (Linux; like Android 4.4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/60.5 Mobile Safari/605.1.15';
const DESKTOP_UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/60.5 Safari/605.1.15';

// Pulls isMobile out of drag.js and runs it against a fake window/navigator.
function isMobileFrom(source, { os, userAgent }) {
  const fn = /function isMobile\(\) \{[\s\S]*?\n\}/.exec(source)?.[0];
  assert.ok(fn, 'isMobile not found in drag.js');
  const window = { _wails: os ? { environment: { OS: os } } : {} };
  return new Function('window', 'navigator', `${fn}\nreturn isMobile();`)(window, { userAgent });
}

test('stock runtime treats ARM64 WebKitGTK as mobile (the bug this fix exists for)', () => {
  assert.equal(isMobileFrom(dragSource, { os: 'linux', userAgent: ARM64_WEBKITGTK_UA }), true);
});

test('patched runtime trusts the known desktop OS over the user agent', () => {
  const patched = patchDragModule(dragSource);
  assert.equal(isMobileFrom(patched, { os: 'linux', userAgent: ARM64_WEBKITGTK_UA }), false);
  assert.equal(isMobileFrom(patched, { os: 'linux', userAgent: DESKTOP_UA }), false);
  assert.equal(isMobileFrom(patched, { os: 'android', userAgent: DESKTOP_UA }), true);
  assert.equal(isMobileFrom(patched, { os: 'ios', userAgent: DESKTOP_UA }), true);
  // With no environment yet, the original UA heuristic still applies.
  assert.equal(isMobileFrom(patched, { userAgent: ARM64_WEBKITGTK_UA }), true);
  assert.equal(isMobileFrom(patched, { userAgent: DESKTOP_UA }), false);
});

test('patch fails loudly when the upstream runtime changes', () => {
  assert.throws(() => patchDragModule('function isMobile() { return false; }'), /wails-runtime-fix/);
});

test('plugin only rewrites the runtime drag module', () => {
  const plugin = wailsRuntimeFix();
  assert.equal(plugin.transform('const x = 1;', '/src/main.js'), null);
  const out = plugin.transform(dragSource, dragPath);
  assert.equal(isMobileFrom(out.code, { os: 'linux', userAgent: ARM64_WEBKITGTK_UA }), false);
});

test('vite build uses the plugin', () => {
  assert.match(readFileSync(join(root, 'vite.config.js'), 'utf8'), /wailsRuntimeFix\(\)/);
});
