import { afterEach, describe, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/svelte';
import LaunchForm from '../src/lib/launch/LaunchForm.svelte';
import StageGrid from '../src/lib/launch/StageGrid.svelte';
import { buildRequest, createForm, normalizeTarget, parseRate } from '../src/lib/launch/model.svelte.js';

// Shapes match the Go catalog's JSON (desktop/internal/catalog).
const STAGES = [
  { id: 'subs', num: 1, title: 'SUBDOMAIN ENUMERATION', tier: 'passive', caps: [], opt_in: false },
  { id: 'origin', num: 5, title: 'ORIGIN HUNTING', tier: 'active', caps: [], opt_in: false },
  { id: 'origin_deep', num: 5, title: 'ORIGIN HUNTING', tier: 'active', caps: [], opt_in: false, parent: 'origin' },
  { id: 'nmap', num: 6, title: 'PORT SCAN (NMAP)', tier: 'intrusive', caps: [], opt_in: true },
  { id: 'vuln', num: 11, title: 'VULNERABILITY SCAN (NUCLEI)', tier: 'active', caps: ['oast'], opt_in: false },
  { id: 'param', num: 14, title: 'PARAMETER / SQLi SCAN', tier: 'intrusive', caps: [], opt_in: false },
];
const MODIFIERS = [{ id: 'nmap-full', parent: 'nmap', title: 'ALL 65535 PORTS' }];
const PRESETS = [
  { id: 'quick', stages: ['subs', 'origin', 'origin_deep'] },
  { id: 'standard', stages: ['subs', 'origin', 'origin_deep', 'nmap', 'vuln'] },
  { id: 'deep', stages: ['subs', 'origin', 'origin_deep', 'nmap', 'vuln', 'param', 'nmap-full'] },
];
const DOCTOR = { tools: [], missing_by_stage: { nmap: ['nmap'] } };

function fakeApi(overrides = {}) {
  return {
    stages: vi.fn(async () => STAGES),
    modifiers: vi.fn(async () => MODIFIERS),
    presets: vi.fn(async () => PRESETS),
    doctor: vi.fn(async () => DOCTOR),
    version: vi.fn(async () => ({ engine_version: '1.2.0', events_schema: 1 })),
    preview: vi.fn(async (req) => ({
      target: req.options.Target.toLowerCase(),
      argv: ['/opt/bounty-run', req.options.Target.toLowerCase(), '-o', '/out/x/YYYYMMDD-HHMMSS'],
      env_names: ['BOUNTY_RUN_DATA'],
      warnings: [],
      scope: { default: true, allow: ['example.com', '*.example.com'], deny: [] },
      run_dir: '/out/x/YYYYMMDD-HHMMSS',
    })),
    start: vi.fn(async () => ({ id: 'abc', dir: '/out/example.com/1' })),
    ...overrides,
  };
}

const stageRow = (id) => document.querySelector(`[data-stage="${id}"]`);
const stageBox = (id) => within(stageRow(id)).getByRole('checkbox');
const launchButton = () => screen.getByRole('button', { name: /launch scan/i });

async function renderForm(api = fakeApi(), props = {}) {
  render(LaunchForm, { api, ...props });
  await waitFor(() => expect(stageRow('subs')).toBeTruthy());
  return api;
}

afterEach(() => {
  cleanup();
  localStorage.clear();
  sessionStorage.clear();
  vi.restoreAllMocks();
});

describe('launch screen', () => {
  test('stage grid renders from catalog', async () => {
    render(StageGrid, { stages: STAGES, modifiers: MODIFIERS, enabled: ['subs'], ceiling: 'intrusive', missing: {} });
    const rows = [...document.querySelectorAll('[data-stage]')].map((row) => row.dataset.stage);
    expect(rows).toEqual(['subs', 'origin', 'origin_deep', 'vuln', 'nmap', 'nmap-full', 'param']);
    expect(stageRow('vuln').textContent).toContain('VULNERABILITY SCAN (NUCLEI)');
    expect(stageBox('subs').checked).toBe(true);
    expect(stageBox('vuln').checked).toBe(false);

    // The form asks the engine (through the bridge) instead of a built-in list.
    const api = await renderForm();
    expect(api.stages).toHaveBeenCalled();
  });

  test('opt-in stages are marked', async () => {
    render(StageGrid, { stages: STAGES, modifiers: MODIFIERS, enabled: [], ceiling: 'intrusive', missing: { nmap: ['nmap'] } });
    expect(stageRow('nmap').dataset.optIn).toBe('true');
    expect(within(stageRow('nmap')).getByText('OPT-IN')).toBeTruthy();
    expect(within(stageRow('subs')).queryByText('OPT-IN')).toBeNull();
    // A missing tool is flagged on its stage.
    expect(within(stageRow('nmap')).getByText(/nmap missing/i)).toBeTruthy();
  });

  test('intensity disables stages above ceiling', async () => {
    const api = await renderForm();
    await fireEvent.input(screen.getByLabelText(/target/i), { target: { value: 'example.com' } });
    await fireEvent.click(screen.getByRole('radio', { name: /passive/i }));
    await waitFor(() => expect(stageBox('origin').disabled).toBe(true));
    expect(stageBox('subs').disabled).toBe(false);
    expect(stageBox('param').disabled).toBe(true);
    expect(stageRow('param').textContent).toMatch(/above ceiling/i);

    await fireEvent.click(screen.getByRole('radio', { name: /active/i }));
    await waitFor(() => expect(stageBox('origin').disabled).toBe(false));
    expect(stageBox('nmap').disabled).toBe(true);
    await waitFor(() => expect(api.preview).toHaveBeenLastCalledWith(
      expect.objectContaining({ options: expect.objectContaining({ Intensity: 'active' }) }),
    ));
  });

  test('invalid target blocks launch', async () => {
    const api = await renderForm();
    const target = screen.getByLabelText(/target/i);
    await fireEvent.input(target, { target: { value: 'not a domain' } });
    await waitFor(() => expect(screen.getByText(/not a valid domain/i)).toBeTruthy());
    expect(launchButton().disabled).toBe(true);
    await fireEvent.click(launchButton());
    expect(api.start).not.toHaveBeenCalled();

    await fireEvent.input(target, { target: { value: 'https://Example.com/x' } });
    await waitFor(() => expect(launchButton().disabled).toBe(false));
    expect(screen.getByText('example.com', { selector: '.normalized' })).toBeTruthy();
  });

  test('proxy field is never persisted', async () => {
    const setItem = vi.spyOn(Storage.prototype, 'setItem');
    const secret = 'http://user:hunter2@127.0.0.1:8080';
    const api = await renderForm();
    await fireEvent.input(screen.getByLabelText(/target/i), { target: { value: 'example.com' } });
    await fireEvent.click(screen.getByRole('button', { name: /advanced/i }));
    const proxy = screen.getByLabelText(/proxy/i);
    expect(proxy.getAttribute('autocomplete')).toBe('off');
    await fireEvent.input(proxy, { target: { value: secret } });
    await fireEvent.input(screen.getByLabelText(/headers/i), { target: { value: 'Authorization: Bearer tok' } });
    // The value reaches the backend in memory...
    await waitFor(() => expect(api.preview).toHaveBeenLastCalledWith(
      expect.objectContaining({ options: expect.objectContaining({ Proxy: secret, Headers: ['Authorization: Bearer tok'] }) }),
    ));
    // ...and is written nowhere the webview keeps.
    expect(setItem).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
    expect(document.cookie).toBe('');
    expect(window.location.href).not.toContain('hunter2');
    expect(JSON.stringify(history.state ?? null)).not.toContain('hunter2');
  });

  test('required warnings and effective scope are visible before launch', async () => {
    const api = fakeApi({
      preview: vi.fn(async () => ({
        target: 'example.com', argv: ['/opt/bounty-run', 'example.com'], env_names: ['BOUNTY_RUN_PROXY'],
        warnings: ['--scope-allow set: it replaces the default target-plus-subdomains scope.'],
        scope: { default: false, allow: ['api.example.com'], deny: ['admin.example.com'] }, run_dir: '/o/x',
      })),
    });
    await renderForm(api);
    await fireEvent.input(screen.getByLabelText(/target/i), { target: { value: 'example.com' } });
    await waitFor(() => expect(screen.getByText(/replaces the default target-plus-subdomains scope/)).toBeTruthy());
    const scope = screen.getByRole('region', { name: /effective scope/i });
    expect(within(scope).getByText('api.example.com')).toBeTruthy();
    expect(within(scope).getByText('admin.example.com')).toBeTruthy();
    expect(screen.getByText(/BOUNTY_RUN_PROXY/)).toBeTruthy();
  });

  test('launch error shows the engine.log tail as text', async () => {
    const err = Object.assign(new Error('engine exited'), {
      cause: { kind: 'launch', message: 'engine exited before starting', tail: '<b>usage</b>: bad flag' },
    });
    const onlaunched = vi.fn();
    const api = fakeApi({ start: vi.fn(async () => { throw err; }) });
    await renderForm(api, { onlaunched });
    await fireEvent.input(screen.getByLabelText(/target/i), { target: { value: 'example.com' } });
    await waitFor(() => expect(launchButton().disabled).toBe(false));
    await fireEvent.click(launchButton());
    await waitFor(() => expect(screen.getByText('<b>usage</b>: bad flag')).toBeTruthy());
    expect(document.querySelector('b')).toBeNull();
    expect(onlaunched).not.toHaveBeenCalled();
  });

  test('successful launch hands the run ref on', async () => {
    const onlaunched = vi.fn();
    const api = await renderForm(fakeApi(), { onlaunched });
    await fireEvent.input(screen.getByLabelText(/target/i), { target: { value: 'example.com' } });
    await waitFor(() => expect(launchButton().disabled).toBe(false));
    await fireEvent.click(launchButton());
    await waitFor(() => expect(onlaunched).toHaveBeenCalledWith({ id: 'abc', dir: '/out/example.com/1' }));
    expect(api.start.mock.calls[0][0]).toEqual(api.preview.mock.lastCall[0]);
  });
});

describe('launch model', () => {
  test('normalizeTarget mirrors engine.NormalizeTarget', () => {
    expect(normalizeTarget('  HTTPS://Sub.Example.COM:8443/path ')).toBe('sub.example.com');
    expect(normalizeTarget('a.com.')).toBe('a.com');
    for (const bad of ['', 'localhost', 'not a domain', '-a.com', 'a_b.com']) expect(normalizeTarget(bad)).toBeNull();
  });

  test('rate limit must be finite and in range', () => {
    expect(parseRate('')).toEqual({ value: 0, error: '' });
    expect(parseRate('2.5').value).toBe(2.5);
    for (const bad of ['Infinity', 'NaN', '0.01', '5000', '-1', '1e400', 'abc']) expect(parseRate(bad).error).not.toBe('');
  });

  test('request carries stage ids and only set options', () => {
    const form = createForm();
    form.target = 'Example.com';
    form.enabled = ['subs', 'nmap'];
    form.headers = 'A: 1\n\n  B: 2 ';
    const req = buildRequest(form);
    expect(req.stages).toEqual(['subs', 'nmap']);
    expect(req.options.Target).toBe('Example.com');
    expect(req.options.Headers).toEqual(['A: 1', 'B: 2']);
    expect(req.options.Intensity).toBe('intrusive');
  });
});
