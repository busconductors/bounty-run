import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/svelte';
import { tick } from 'svelte';
import LogConsole from '../src/lib/monitor/LogConsole.svelte';
import MonitorScreen from '../src/lib/monitor/MonitorScreen.svelte';
import StageList from '../src/lib/monitor/StageList.svelte';
import SeverityChip from '../src/lib/ui/SeverityChip.svelte';
import { MonitorSession, applyBatch, createRunState, stageRows } from '../src/lib/monitor/store.svelte.js';

// Vitest runs from desktop/frontend.
const REPO = new URL('../../', pathToFileURL(`${process.cwd()}/`));
const FULL_RUN = new URL('tui/internal/ui/testdata/full_run.jsonl', REPO);
const CAPPED = new URL('contract/testdata/capped_output.jsonl', REPO);
const DIR = '/out/acme.com/20251108-110600';
const ID = 'r1';

// Shapes match the Go catalog's JSON (desktop/internal/catalog).
const CATALOG = [
  { id: 'subs', num: 1, title: 'SUBDOMAIN ENUMERATION', tier: 'passive', caps: [], opt_in: false },
  { id: 'live', num: 3, title: 'LIVE HOSTS', tier: 'active', caps: [], opt_in: false },
  { id: 'origin', num: 5, title: 'ORIGIN HUNTING', tier: 'active', caps: [], opt_in: false },
  { id: 'origin_deep', num: 5, title: 'ORIGIN HUNTING', tier: 'active', caps: [], opt_in: false, parent: 'origin' },
  { id: 'vuln', num: 11, title: 'VULNERABILITY SCAN (NUCLEI)', tier: 'active', caps: ['oast'], opt_in: false },
];

const readEvents = (url) =>
  readFileSync(url, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));

// The wire batches run:<id>:batch would carry for these events: output events
// travel as sanitized output lines, everything else as events.
function toBatches(events, size = 8) {
  const out = [];
  for (let i = 0; i < events.length; i += size) {
    const chunk = events.slice(i, i + size);
    out.push({
      events: chunk.filter((ev) => ev.type !== 'output'),
      output: chunk
        .filter((ev) => ev.type === 'output')
        .map(({ t, stage, tool, stream, line }) => ({ t, stage, tool, stream, line })),
      elided: 0,
      reset: false,
    });
  }
  return out;
}

const batch = (events = [], extra = {}) => ({ events, output: [], elided: 0, reset: false, ...extra });
const runStart = (target = 'acme.com', stages = ['subs', 'live', 'vuln']) => ({
  v: 1, t: 1762600000500, type: 'run_start', target, flags: {}, stages,
});
const stageStart = (stage, t = 1762600001000) => ({ v: 1, t, type: 'stage_start', stage });
const stageEnd = (stage, status = 'ok', t = 1762600002000) => ({
  v: 1, t, type: 'stage_end', stage, status, duration_ms: 1000, counts: {},
});

function makeBus() {
  const subs = new Map();
  return {
    on: vi.fn((name, callback) => {
      if (!subs.has(name)) subs.set(name, new Set());
      subs.get(name).add(callback);
      return () => subs.get(name)?.delete(callback);
    }),
    emit(name, payload) {
      for (const callback of [...(subs.get(name) ?? [])]) callback(payload);
    },
    listeners: (name) => subs.get(name)?.size ?? 0,
  };
}

function fakeRuns(overrides = {}) {
  return {
    list: vi.fn(async () => []),
    runId: vi.fn(async () => ID),
    attach: vi.fn(async (dir) => ({ id: ID, dir })),
    detach: vi.fn(async () => {}),
    skip: vi.fn(async () => {}),
    cancel: vi.fn(async () => {}),
    hardKill: vi.fn(async () => {}),
    engineLogTail: vi.fn(async () => ''),
    ...overrides,
  };
}

const settle = async () => {
  for (let i = 0; i < 5; i += 1) await Promise.resolve();
  await tick();
};

async function renderMonitor({ api: overrides, ...props } = {}) {
  const bus = makeBus();
  const api = fakeRuns(overrides);
  const result = render(MonitorScreen, {
    run: { id: ID, dir: DIR },
    api,
    stages: async () => CATALOG,
    on: bus.on,
    ...props,
  });
  await settle();
  const send = async (payload) => {
    bus.emit(`run:${ID}:batch`, payload);
    await tick();
  };
  return { bus, api, send, ...result };
}

const hardKillButton = () => screen.queryByRole('button', { name: /hard kill/i });
const findingRows = () => document.querySelectorAll('[data-finding]');
const logLines = () => document.querySelectorAll('[data-log-line]');

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('monitor', () => {
  test('reducer snapshot over full_run.jsonl', () => {
    const state = createRunState();
    for (const b of toBatches(readEvents(FULL_RUN))) applyBatch(state, b);

    expect(state.target).toBe('acme.com');
    expect(state.order).toEqual(['subs', 'live', 'vuln']);
    expect([...state.stages.values()].map(({ id, status, durationMs, counts, done, total }) => ({
      id, status, durationMs, counts, done, total,
    }))).toEqual([
      { id: 'subs', status: 'ok', durationMs: 3500, counts: { subdomains: 212 }, done: 7, total: 7 },
      { id: 'live', status: 'ok', durationMs: 3500, counts: { live: 48 }, done: 6, total: 6 },
      { id: 'vuln', status: 'ok', durationMs: 3500, counts: { findings: 4 }, done: 7, total: 7 },
    ]);
    expect(state.findings.map((f) => [f.severity, f.template, f.host, f.url, f.summary, f.stage])).toEqual([
      ['medium', 'cors-misconfig', 'api.acme.com', 'https://api.acme.com/', 'CORS reflects arbitrary origin', 'vuln'],
      ['high', 'exposed-git', 'dev.acme.com', 'https://dev.acme.com/.git/config', 'Git repository exposed', 'vuln'],
      ['low', 'weak-cipher', 'www.acme.com', 'https://www.acme.com/', 'Weak TLS cipher offered', 'vuln'],
      ['info', 'tech-detect', 'acme.com', 'https://acme.com/', 'nginx detected', 'vuln'],
    ]);
    expect(state.sevCounts).toEqual({ critical: 0, high: 1, medium: 1, low: 1, info: 1, other: 0 });
    expect(state.log).toHaveLength(21);
    expect(state.log[0]).toMatchObject({ tag: 'subs', tool: 'subfinder', level: 'OUT', text: 'subfinder line 1' });
    expect(state.log.at(-1)).toMatchObject({ tag: 'engine', level: 'INFO', text: 'report written' });
    expect(state.log.map((l) => l.seq)).toEqual(state.log.map((_, i) => i + 1));
    expect(state.tools).toEqual(['subfinder', 'httpx', 'nuclei']);
    expect(state.ended).toBe(true);
    expect(state.endStatus).toBe('ok');
    expect(state.report).toBe('/tmp/acme/FINDINGS.md');
    expect(state.totals).toEqual({ critical: 0, high: 1, medium: 1, low: 1, info: 1 });
  });

  test('reset clears run state', async () => {
    const state = createRunState();
    for (const b of toBatches(readEvents(FULL_RUN))) applyBatch(state, b);
    applyBatch(state, batch([runStart('other.example', ['subs'])], { reset: true }));
    expect(state.target).toBe('other.example');
    expect(state.findings).toEqual([]);
    expect(state.log).toEqual([]);
    expect(state.order).toEqual(['subs']);
    expect(state.ended).toBe(false);

    // Live: a reset batch wipes what earlier batches built.
    const { send } = await renderMonitor();
    for (const b of toBatches(readEvents(FULL_RUN))) await send(b);
    expect(findingRows()).toHaveLength(4);
    expect(logLines().length).toBeGreaterThan(0);
    await send(batch([runStart('other.example', ['subs'])], { reset: true }));
    expect(findingRows()).toHaveLength(0);
    expect(logLines()).toHaveLength(0);
    expect(screen.getByText('other.example')).toBeTruthy();
  });

  test('hard kill hidden until ack timeout', async () => {
    vi.useFakeTimers();
    const { api, send } = await renderMonitor();
    await send(batch([runStart(), stageStart('subs')]));
    expect(hardKillButton()).toBeNull();

    await fireEvent.click(screen.getByRole('button', { name: /^stop$/i }));
    expect(screen.getByText(/cancel this run\?/i)).toBeTruthy();
    await fireEvent.keyDown(window, { key: 'y' });
    expect(api.cancel).toHaveBeenCalledWith(DIR);
    expect(hardKillButton()).toBeNull();

    await vi.advanceTimersByTimeAsync(9999);
    expect(hardKillButton()).toBeNull();
    await vi.advanceTimersByTimeAsync(1);
    expect(hardKillButton()).toBeTruthy();

    // A newer command supersedes the pending one and hides the offer until
    // its own timer runs out.
    await fireEvent.click(screen.getByRole('button', { name: /skip subs/i }));
    await fireEvent.keyDown(window, { key: 'y' });
    expect(api.skip).toHaveBeenCalledWith(DIR, 'subs');
    expect(hardKillButton()).toBeNull();
    await vi.advanceTimersByTimeAsync(9999);
    expect(hardKillButton()).toBeNull();
    await vi.advanceTimersByTimeAsync(1);

    await fireEvent.click(hardKillButton());
    expect(api.hardKill).toHaveBeenCalledWith(DIR);
  });

  test('skip prompt clears when stage ends', async () => {
    vi.useFakeTimers();
    const { api, send } = await renderMonitor();
    await send(batch([runStart(), stageStart('subs')]));

    await fireEvent.click(screen.getByRole('button', { name: /skip subs/i }));
    expect(screen.getByText(/skip stage subs\?/i)).toBeTruthy();
    await send(batch([stageEnd('subs')]));
    expect(screen.queryByText(/skip stage subs\?/i)).toBeNull();
    expect(api.skip).not.toHaveBeenCalled();
    // The prompt was dropped, so a late "y" sends nothing.
    await fireEvent.keyDown(window, { key: 'y' });
    expect(api.skip).not.toHaveBeenCalled();

    // A sent skip is acknowledged by that stage's stage_end: no hard kill.
    await send(batch([stageStart('live', 1762600003000)]));
    await fireEvent.click(screen.getByRole('button', { name: /skip live/i }));
    await fireEvent.keyDown(window, { key: 'y' });
    expect(api.skip).toHaveBeenCalledWith(DIR, 'live');
    await send(batch([stageEnd('live', 'skipped', 1762600004000)]));
    await vi.advanceTimersByTimeAsync(10000);
    expect(hardKillButton()).toBeNull();

    // "n" declines.
    await send(batch([stageStart('vuln', 1762600005000)]));
    await fireEvent.click(screen.getByRole('button', { name: /skip vuln/i }));
    await fireEvent.keyDown(window, { key: 'n' });
    expect(screen.queryByText(/skip stage vuln\?/i)).toBeNull();
    expect(api.skip).toHaveBeenCalledTimes(1);
  });

  test('capped output shows truncation notice', async () => {
    const { send } = await renderMonitor();
    await send(batch([runStart('example.com', ['vuln']), stageStart('vuln')]));
    for (const b of toBatches(readEvents(CAPPED))) await send(b);
    const log = screen.getByRole('region', { name: /log/i });
    expect(within(log).getByText(/output capped/i)).toBeTruthy();

    // Lines the backend coalescer elided are counted, not silently lost.
    await send(batch([], {
      elided: 1500,
      output: [{ t: 1762600003000, stage: 'vuln', tool: 'nuclei', stream: 'stdout', line: 'after the gap' }],
    }));
    expect(within(log).getAllByText(/1,500 lines dropped/i).length).toBeGreaterThan(0);
    expect(within(log).getByText('after the gap')).toBeTruthy();
  });

  test('unknown severity renders with raw label', async () => {
    render(SeverityChip, { severity: 'Sev-9000' });
    expect(screen.getByText('Sev-9000')).toBeTruthy();
    cleanup();
    render(SeverityChip, { severity: 'high' });
    expect(screen.getByText('HIGH')).toBeTruthy();
    cleanup();

    const { send } = await renderMonitor();
    await send(batch([runStart(), {
      v: 1, t: 1762600001000, type: 'finding', severity: 'Sev-9000', template: 't', host: 'h', url: 'u', summary: 's',
    }]));
    expect(within(findingRows()[0]).getByText('Sev-9000')).toBeTruthy();
  });

  test('origin_deep nests under origin', () => {
    const state = createRunState();
    applyBatch(state, batch([
      runStart('acme.com', ['subs', 'origin', 'vuln']),
      stageStart('origin'),
      stageEnd('origin'),
      // Planned stages are top-level only: origin_deep shows up when it starts.
      stageStart('origin_deep', 1762600003000),
    ]));
    render(StageList, { rows: stageRows(state, CATALOG), live: true });
    const rows = [...document.querySelectorAll('[data-stage]')];
    expect(rows.map((row) => row.dataset.stage)).toEqual(['subs', 'origin', 'origin_deep', 'vuln']);
    const deep = rows[2];
    expect(deep.dataset.parent).toBe('origin');
    expect(deep.getAttribute('aria-level')).toBe('2');
    expect(rows[1].getAttribute('aria-level')).toBe('1');
  });

  test('hostile strings render as text', async () => {
    const hostile = '<img src=x onerror="window.__pwned=1"><b>bold</b>';
    const { send, container } = await renderMonitor();
    await send(batch([
      runStart(hostile, ['subs']),
      stageStart('subs'),
      { v: 1, t: 1762600001500, type: 'finding', severity: hostile, template: hostile, host: hostile, url: hostile, summary: hostile },
      { v: 1, t: 1762600001600, type: 'log', level: 'warn', msg: hostile },
    ], { output: [{ t: 1762600001700, stage: 'subs', tool: 'x', stream: 'stdout', line: hostile }] }));
    await fireEvent.click(findingRows()[0]);

    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('b')).toBeNull();
    expect(window.__pwned).toBeUndefined();
    expect(container.textContent).toContain(hostile);
    const inspector = screen.getByRole('complementary', { name: /inspector/i });
    expect(inspector.textContent).toContain(hostile);
  });

  test('ANSI, control and bidi sequences are stripped before display', async () => {
    const ansi = '\u001b[31mred\u001b[0m\u001b]8;;http://x\u0007link\u001b]8;;\u0007\u202Eevil\u2066x\u0000\u0008';
    const { send, container } = await renderMonitor();
    await send(batch([
      runStart(ansi, ['subs']),
      stageStart('subs'),
      { v: 1, t: 1762600001500, type: 'finding', severity: 'high', template: ansi, host: ansi, url: ansi, summary: ansi },
      { v: 1, t: 1762600001600, type: 'log', level: 'info', msg: ansi },
    ], { output: [{ t: 1762600001700, stage: 'subs', tool: 'x', stream: 'stdout', line: ansi }] }));
    await fireEvent.click(findingRows()[0]);
    const text = container.textContent;
    expect(text).toContain('redlinkevilx');
    expect(text).not.toMatch(/[\u0000-\u0008\u001b\u009b\u202A-\u202E\u2066-\u2069]/);
  });

  test('a large replay keeps the DOM bounded', async () => {
    const { send } = await renderMonitor();
    const findings = [];
    const output = [];
    for (let i = 0; i < 20000; i += 1) {
      findings.push({ v: 1, t: 1762600001000 + i, type: 'finding', severity: 'low', template: `t${i}`, host: 'h', url: 'u', summary: 's' });
      output.push({ t: 1762600001000 + i, stage: 'subs', tool: 'x', stream: 'stdout', line: `line ${i}` });
    }
    await send(batch([runStart(), stageStart('subs'), ...findings], { output }));
    expect(screen.getByRole('tab', { name: /all\s*20,000/i })).toBeTruthy();
    expect(findingRows().length).toBeLessThanOrEqual(100);
    expect(logLines().length).toBeLessThanOrEqual(100);
  });

  test('autoscroll lock shows new-line count', async () => {
    const line = (seq) => ({ seq, t: 1762600000000 + seq, tag: 'subs', tool: 'subfinder', level: 'OUT', text: `line ${seq}` });
    const lines = [1, 2, 3, 4, 5].map(line);
    const { rerender } = render(LogConsole, { lines, rev: 1, tools: ['subfinder'] });
    const scroller = document.querySelector('[data-log-scroll]');
    Object.defineProperty(scroller, 'scrollHeight', { configurable: true, value: 1000 });
    Object.defineProperty(scroller, 'clientHeight', { configurable: true, value: 100 });
    scroller.scrollTop = 200; // the user scrolled up, away from the bottom
    await fireEvent.scroll(scroller);
    expect(screen.queryByRole('button', { name: /new/i })).toBeNull();

    lines.push(line(6), line(7), line(8));
    await rerender({ lines, rev: 2, tools: ['subfinder'] });
    const pill = screen.getByRole('button', { name: /3 new/i });
    expect(scroller.scrollTop).toBe(200); // locked: the view did not jump

    await fireEvent.click(pill);
    expect(screen.queryByRole('button', { name: /new/i })).toBeNull();
    expect(scroller.scrollTop).toBe(1000);
  });

  test('attaches on show and detaches on dead and on leaving', async () => {
    const { api, bus, send, unmount } = await renderMonitor();
    expect(api.attach).toHaveBeenCalledWith(DIR);
    expect(bus.listeners(`run:${ID}:batch`)).toBe(1);
    await send(batch([runStart()]));
    bus.emit(`run:${ID}:dead`, { status: 'crashed' });
    await settle();
    expect(api.detach).toHaveBeenCalledWith(DIR);
    expect(bus.listeners(`run:${ID}:batch`)).toBe(0);
    expect(screen.getAllByText(/crashed/i).length).toBeGreaterThan(0);
    expect(screen.queryByRole('button', { name: /^stop$/i })?.disabled ?? true).toBe(true);
    unmount();

    const again = await renderMonitor();
    const calls = again.api.detach.mock.calls.length;
    again.unmount();
    expect(again.api.detach.mock.calls.length).toBe(calls + 1);
    expect(again.bus.listeners(`run:${ID}:batch`)).toBe(0);
  });

  test('an attach that resolves after close is detached again', async () => {
    const bus = makeBus();
    let release;
    const api = fakeRuns({ attach: vi.fn(() => new Promise((resolve) => { release = resolve; })) });
    const session = new MonitorSession({ api, on: bus.on });
    const opened = session.open({ dir: DIR, id: ID });
    await settle();
    expect(api.attach).toHaveBeenCalledTimes(1);
    session.close();
    const detaches = api.detach.mock.calls.length;
    release({ id: ID, dir: DIR });
    await opened;
    await settle();
    expect(api.detach.mock.calls.length).toBeGreaterThan(detaches);
    expect(api.detach).toHaveBeenLastCalledWith(DIR);
  });

  test('without a run it lists runs to pick from', async () => {
    const onselect = vi.fn();
    const api = {
      list: async () => [
        { Info: { Dir: DIR, Target: 'acme.com', Started: '2025-11-08T11:06:00Z' }, Status: 'running', CurrentStage: 'vuln', Elapsed: 26e9, Sev: { high: 1 }, Ended: false },
      ],
    };
    render(MonitorScreen, { run: null, api: fakeRuns(api), stages: async () => CATALOG, on: makeBus().on, onselect });
    await settle();
    await fireEvent.click(screen.getByRole('button', { name: /acme\.com/i }));
    expect(onselect).toHaveBeenCalledWith({ dir: DIR });
  });
});
