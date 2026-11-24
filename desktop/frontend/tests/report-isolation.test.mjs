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
// The parent page's CSP lives in index.html (a meta tag, frames only).
const indexHtml = readFileSync(here('../index.html'), 'utf8');
const parentCsp = /<meta http-equiv="Content-Security-Policy" content="([^"]+)"/.exec(indexHtml)?.[1];
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

test('index.html restricts frames only, not scripts', () => {
  assert.ok(parentCsp, 'index.html has a CSP meta tag');
  assert.match(parentCsp, /frame-src 'self'/);
  assert.match(parentCsp, /child-src 'self'/);
  assert.doesNotMatch(parentCsp, /default-src|script-src/);
});

test('hostile report cannot reach parent bindings (Chromium)', { skip }, async () => {
  const page = await browser.newPage();
  const requested = [];
  const offApp = [];
  await page.route('**/*', (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === '/parent.html') {
      return route.fulfill({
        contentType: 'text/html',
        body: `<!doctype html><meta http-equiv="Content-Security-Policy" content="${parentCsp}"><script>
          window.__calls = [];
          const rec = (n) => (...a) => window.__calls.push(n);
          window.wails = { Call: rec('wails.Call') };
          window._wails = { invoke: rec('_wails.invoke') };
          window.webkit = { messageHandlers: { external: { postMessage: rec('webkit.postMessage') } } };
        </script><iframe id="r" sandbox="allow-scripts" src="/reports/ex.com/1/summary.html"></iframe>`,
      });
    }
    if (url.host !== 'app.test') {
      offApp.push(url.href); // a request the CSP let through
      return route.abort();
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
  await new Promise((r) => setTimeout(r, 150)); // let the inline script and fetches run
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
  // Record the frame's own webkit bridge probe: absent in Chromium.
  const own = await child.evaluate(() => document.documentElement.getAttribute('data-own-webkit'));
  console.log(`# report frame own window.webkit...external present: ${own}`);
  assert.equal(own, 'false');
  await new Promise((r) => setTimeout(r, 800)); // the fixture navigates away at 400 ms
  assert.deepEqual(offApp, [], 'no request left the app origin (report navigation and image beacons blocked)');
  // Chromium shows an error page in a frame whose navigation the parent CSP
  // blocked; what matters is that nothing was requested and it never left.
  assert.ok(!child.url().includes('exfil.invalid'), `frame did not navigate to the attacker: ${child.url()}`);
  await page.close();
});

test.after(async () => { await browser?.close(); });
