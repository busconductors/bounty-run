import { afterEach, describe, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/svelte';
import RunsTable from '../src/lib/runs/RunsTable.svelte';
import FindingsScreen from '../src/lib/runs/FindingsScreen.svelte';

// Shapes match runstore.Run's JSON (core/runstore): no json tags, Elapsed in ns.
const run = (target, stamp, status, extra = {}) => ({
  Info: { Dir: `/out/${target}/${stamp}`, Target: target, Started: `2025-11-0${stamp}T10:00:00Z` },
  Status: status,
  CurrentStage: '',
  Elapsed: 65e9,
  Sev: {},
  Ended: status !== 'running',
  ...extra,
});

const ALL = [
  run('ok.com', '1', 'ok'),
  run('cancelled.com', '2', 'cancelled'),
  run('failed.com', '3', 'failed'),
  run('crashed.com', '4', 'crashed'),
  run('old.com', '5', 'incompatible'),
  run('live.com', '1', 'running', { CurrentStage: 'vuln', Ended: false }),
];

afterEach(cleanup);

const targets = () => [...document.querySelectorAll('[data-run]')].map((el) => el.querySelector('.target').textContent);

describe('RunsTable', () => {
  test('all six run statuses render', () => {
    render(RunsTable, { runs: ALL, onopen: () => {} });
    for (const status of ['running', 'ok', 'cancelled', 'failed', 'crashed', 'incompatible']) {
      const row = document.querySelector(`[data-status="${status}"]`);
      expect(row, status).toBeTruthy();
      expect(row.textContent.toLowerCase()).toContain(status);
    }
  });

  test('running sorts first', () => {
    render(RunsTable, { runs: ALL, onopen: () => {} });
    expect(targets()[0]).toBe('live.com');
  });

  test('filter and sort', async () => {
    render(RunsTable, { runs: ALL, onopen: () => {} });
    await fireEvent.click(screen.getByRole('tab', { name: /failed/i }));
    expect(targets()).toEqual(['failed.com']);
    await fireEvent.click(screen.getByRole('tab', { name: /^all/i }));
    await fireEvent.click(screen.getByRole('columnheader', { name: /target/i }));
    expect(targets()).toEqual(['cancelled.com', 'crashed.com', 'failed.com', 'live.com', 'ok.com', 'old.com']);
    await fireEvent.click(screen.getByRole('columnheader', { name: /target/i }));
    expect(targets()[0]).toBe('old.com');
  });

  test('opens a run and renders target text, not markup', async () => {
    const onopen = vi.fn();
    const evil = run('<img src=x onerror=alert(1)>', '1', 'ok');
    render(RunsTable, { runs: [evil], onopen });
    expect(document.querySelector('img')).toBeNull();
    await fireEvent.click(document.querySelector('[data-run]'));
    expect(onopen).toHaveBeenCalledWith(evil);
  });
});

const RESULT = {
  findings: [
    { severity: 'high', template: 't-a', name: 'Alpha', url: 'https://a.com/x', host: 'a.com', fingerprint: 'f'.repeat(12), evidencePath: '/out/a/1/evidence/ffffffffffff' },
    { severity: 'low', template: 't-b', name: 'Beta', url: 'https://a.com/y', host: 'a.com' },
  ],
  indexAvailable: true,
  pending: false,
  missing: false,
};

describe('FindingsScreen', () => {
  test('lists findings and filters by severity', async () => {
    const api = { get: vi.fn(async () => RESULT) };
    render(FindingsScreen, { dir: '/out/a/1', api });
    await waitFor(() => expect(document.querySelectorAll('[data-finding]').length).toBe(2));
    await fireEvent.click(screen.getByRole('tab', { name: /high/i }));
    expect(document.querySelectorAll('[data-finding]').length).toBe(1);
  });

  test('without an index says evidence link unavailable', async () => {
    const api = { get: vi.fn(async () => ({ ...RESULT, indexAvailable: false })) };
    render(FindingsScreen, { dir: '/out/a/1', api });
    await waitFor(() => expect(screen.getByText(/evidence link unavailable/i)).toBeTruthy());
  });

  test('pending result retries without showing an error', async () => {
    vi.useFakeTimers();
    try {
      const api = { get: vi.fn().mockResolvedValueOnce({ findings: [], pending: true }).mockResolvedValue(RESULT) };
      render(FindingsScreen, { dir: '/out/a/1', api });
      await vi.advanceTimersByTimeAsync(0);
      expect(document.querySelector('[role="alert"]')).toBeNull();
      await vi.advanceTimersByTimeAsync(5000);
      await waitFor(() => expect(document.querySelectorAll('[data-finding]').length).toBe(2));
      expect(api.get).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });

  test('gives up on a findings file that stays pending and offers Retry', async () => {
    vi.useFakeTimers();
    try {
      const api = { get: vi.fn().mockResolvedValue({ findings: [], pending: true }) };
      render(FindingsScreen, { dir: '/out/a/1', api, retryMs: 10, maxRetries: 2 });
      await vi.advanceTimersByTimeAsync(100);
      expect(api.get).toHaveBeenCalledTimes(3);
      expect(screen.queryByText(/still being written/i)).toBeNull();
      expect(screen.getByText('findings.json is incomplete or unreadable')).toBeTruthy();
      api.get.mockResolvedValue(RESULT);
      await fireEvent.click(screen.getByRole('button', { name: /retry/i }));
      await vi.advanceTimersByTimeAsync(0);
      await waitFor(() => expect(document.querySelectorAll('[data-finding]').length).toBe(2));
      expect(screen.queryByText(/incomplete or unreadable/i)).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  test('no dir asks to pick a run', () => {
    render(FindingsScreen, { dir: '', api: { get: vi.fn() } });
    expect(screen.getByText(/pick a run/i)).toBeTruthy();
  });
});
