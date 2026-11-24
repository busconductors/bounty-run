import { afterEach, describe, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import ReportFrame from '../src/lib/reports/ReportFrame.svelte';

afterEach(cleanup);

const DIR = '/out/ex.com/20250101-000000';
const api = (info) => ({ available: vi.fn(async () => info), openExternal: vi.fn(async () => {}) });

describe('ReportFrame', () => {
  test('iframe sandbox lacks allow-same-origin', async () => {
    render(ReportFrame, { dir: DIR, api: api({ html: true, markdown: [] }) });
    const frame = await waitFor(() => {
      const el = document.querySelector('iframe');
      expect(el).toBeTruthy();
      return el;
    });
    // Without allow-same-origin the report runs in an opaque origin, so its
    // script cannot reach window.parent.wails or the Go bindings.
    expect(frame.hasAttribute('sandbox')).toBe(true);
    const tokens = frame.getAttribute('sandbox').split(/\s+/).filter(Boolean);
    expect(tokens).toEqual(['allow-scripts']);
    expect(tokens).not.toContain('allow-same-origin');
    for (const bad of ['allow-top-navigation', 'allow-popups', 'allow-forms']) expect(tokens).not.toContain(bad);
    expect(frame.getAttribute('src')).toBe('/reports/ex.com/20250101-000000/summary.html');
    expect(frame.getAttribute('referrerpolicy')).toBe('no-referrer');
  });

  test('src encodes each path segment', async () => {
    render(ReportFrame, { dir: '/out/a b/2025 01', api: api({ html: true, markdown: [] }) });
    const frame = await waitFor(() => document.querySelector('iframe') ?? Promise.reject(new Error('none')));
    expect(frame.getAttribute('src')).toBe('/reports/a%20b/2025%2001/summary.html');
  });

  test('no summary.html says no report', async () => {
    render(ReportFrame, { dir: DIR, api: api({ html: false, markdown: [] }) });
    await waitFor(() => expect(screen.getByText(/no report for this run/i)).toBeTruthy());
    expect(document.querySelector('iframe')).toBeNull();
  });

  test('markdown reports open externally', async () => {
    const a = api({ html: false, markdown: ['FINDINGS.md'] });
    render(ReportFrame, { dir: DIR, api: a });
    await fireEvent.click(await screen.findByRole('button', { name: /FINDINGS\.md/ }));
    expect(a.openExternal).toHaveBeenCalledWith(DIR, 'FINDINGS.md');
  });
});
