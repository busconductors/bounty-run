import { afterEach, describe, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/svelte';
import DoctorScreen from '../src/lib/doctor/DoctorScreen.svelte';

// Shapes match the Go doctor package's JSON (desktop/internal/doctor).
const REPORT = {
  rows: [
    { name: 'subfinder', status: 'ok', version: '2.6.0', path: '/usr/bin/subfinder', optional: false, guidance: 'go install', affects: ['subs'] },
    { name: 'whatweb', status: 'missing', version: '', path: '', optional: false, guidance: 'sudo apt install whatweb', affects: ['tech', 'headers'] },
  ],
  missing: 1,
};

afterEach(cleanup);

describe('Doctor', () => {
  test('missing tool shows affected stages', async () => {
    const api = { report: vi.fn(async () => REPORT), recheck: vi.fn() };
    render(DoctorScreen, { api });
    const row = await waitFor(() => {
      const el = document.querySelector('[data-tool="whatweb"]');
      expect(el).toBeTruthy();
      return el;
    });
    expect(within(row).getByText(/missing/i)).toBeTruthy();
    expect(within(row).getByText('tech')).toBeTruthy();
    expect(within(row).getByText('headers')).toBeTruthy();
    expect(within(row).getByText('sudo apt install whatweb')).toBeTruthy();
    expect(screen.getByText(/1 tool missing/i)).toBeTruthy();
    const ok = document.querySelector('[data-tool="subfinder"]');
    expect(within(ok).getByText('2.6.0')).toBeTruthy();
  });

  test('recheck refreshes', async () => {
    const fixed = { rows: [{ ...REPORT.rows[1], status: 'ok', version: '0.5.5', path: '/usr/bin/whatweb' }], missing: 0 };
    const api = { report: vi.fn(async () => REPORT), recheck: vi.fn(async () => fixed) };
    render(DoctorScreen, { api });
    await waitFor(() => expect(document.querySelector('[data-tool="whatweb"]')).toBeTruthy());
    await fireEvent.click(screen.getByRole('button', { name: /re-check/i }));
    await waitFor(() => expect(screen.getByText('0.5.5')).toBeTruthy());
    expect(api.recheck).toHaveBeenCalledTimes(1);
    expect(document.querySelector('[data-tool="subfinder"]')).toBeNull();
    expect(screen.getByText(/all tools present/i)).toBeTruthy();
  });

  test('a failed check shows the error and can be retried', async () => {
    const api = {
      report: vi.fn(async () => { throw { cause: { message: 'engine not found' } }; }),
      recheck: vi.fn(async () => REPORT),
    };
    render(DoctorScreen, { api });
    await waitFor(() => expect(screen.getByText(/engine not found/)).toBeTruthy());
    await fireEvent.click(screen.getByRole('button', { name: /re-check/i }));
    await waitFor(() => expect(document.querySelector('[data-tool="whatweb"]')).toBeTruthy());
    expect(screen.queryByText(/engine not found/)).toBeNull();
  });
});
