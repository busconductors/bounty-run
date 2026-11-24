// Runtime isolation check (Chromium): the hostile report, served with the
// real CSP and embedded in a sandbox="allow-scripts" iframe, cannot reach the
// parent's Wails bindings. Skipped when no Playwright browser is installed.
// No HTTP listener: requests are fulfilled through page.route.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
// The CSP lives only in Go; read the constant from the source.
const csp = /const CSP = "([^"]+)"/.exec(readFileSync(here('../../internal/reports/handler.go'), 'utf8'))?.[1];
const hostile = readFileSync(here('../../internal/reports/testdata/hostile.html'), 'utf8');

let browser;
let skip = false;
try {
  const { chromium } = await import('playwright-core');
  browser = await chromium.launch();
} catch (e) {
  skip = `Playwright Chromium unavailable: ${String(e.message).split('\n')[0]}`;
}

test('CSP constant was read from the Go source', () => {
  assert.ok(csp && csp.includes("default-src 'none'") && csp.includes('sandbox allow-scripts'));
});

test('hostile report cannot reach parent bindings (Chromium)', { skip }, async () => {
  const page = await browser.newPage();
  const requested = [];
  await page.route('**/*', (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === '/parent.html') {
      return route.fulfill({
        contentType: 'text/html',
        body: `<!doctype html><script>
          window.__calls = [];
          const rec = (n) => (...a) => window.__calls.push(n);
          window.wails = { Call: rec('wails.Call') };
          window._wails = { invoke: rec('_wails.invoke') };
          window.webkit = { messageHandlers: { external: { postMessage: rec('webkit.postMessage') } } };
        </script><iframe id="r" sandbox="allow-scripts" src="/reports/ex.com/1/summary.html"></iframe>`,
      });
    }
    requested.push(url.pathname);
    if (url.pathname === '/reports/ex.com/1/summary.html') {
      return route.fulfill({ contentType: 'text/html; charset=utf-8', headers: { 'Content-Security-Policy': csp }, body: hostile });
    }
    return route.fulfill({ status: 404, body: '' });
  });
  const frameLoaded = page.waitForEvent('framenavigated', (f) => f.url().endsWith('/summary.html'));
  await page.goto('http://app.test/parent.html');
  await frameLoaded;
  const child = page.frames().find((f) => f.url().endsWith('/summary.html'));
  await page.waitForFunction(() => document.getElementById('r') !== null);
  await new Promise((r) => setTimeout(r, 500)); // let the inline script and fetches run
  const ran = await child.evaluate(() => document.title);
  assert.equal(ran, 'ran', 'the report script executed');
  assert.deepEqual(await page.evaluate(() => window.__calls), [], 'no parent binding was called');
  assert.equal(await page.evaluate(() => document.body.innerHTML.includes('pwned')), false);
  // location.origin reflects the URL; window.origin is the security origin.
  const probe = await child.evaluate(() => {
    let parentAccess = 'blocked';
    try { parentAccess = typeof parent.document.body; } catch (e) {}
    return { origin: window.origin, parentAccess };
  });
  assert.deepEqual(probe, { origin: 'null', parentAccess: 'blocked' }, 'opaque origin, parent.document throws');
  assert.deepEqual(requested.filter((p) => !p.startsWith('/reports/')), [], 'report made no other requests');
  await page.close();
});

test.after(async () => { await browser?.close(); });
