import { afterEach, describe, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import ReportFrame from '../src/lib/reports/ReportFrame.svelte';

afterEach(cleanup);

const DIR = '/out/ex.com/20250101-000000';
const api = (info) => ({
  available: vi.fn(async () => info),
  openExternal: vi.fn(async () => {}),
  exportPDF: vi.fn(async () => '/out/report.pdf'),
});

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

  test('Export PDF (Light) exports then opens report.pdf', async () => {
    const a = api({ html: true, markdown: [] });
    render(ReportFrame, { dir: DIR, api: a });
    await fireEvent.click(await screen.findByRole('button', { name: /export pdf \(light\)/i }));
    await waitFor(() => expect(a.openExternal).toHaveBeenCalledWith(DIR, 'report.pdf'));
    expect(a.exportPDF).toHaveBeenCalledWith(DIR, 'light');
  });

  test('Dark exports the dark theme then opens report.pdf', async () => {
    const a = api({ html: true, markdown: [] });
    render(ReportFrame, { dir: DIR, api: a });
    await fireEvent.click(await screen.findByRole('button', { name: /export pdf \(dark\)/i }));
    await waitFor(() => expect(a.openExternal).toHaveBeenCalledWith(DIR, 'report.pdf'));
    expect(a.exportPDF).toHaveBeenCalledWith(DIR, 'dark');
  });

  test('exportPDF failure shows a sanitized error and does not open', async () => {
    const a = api({ html: true, markdown: [] });
    a.exportPDF = vi.fn(async () => {
      throw new Error('render failed\u001b[31m');
    });
    render(ReportFrame, { dir: DIR, api: a });
    await fireEvent.click(await screen.findByRole('button', { name: /export pdf \(light\)/i }));
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toMatch(/render failed/);
    expect(alert.textContent).not.toContain('\u001b');
    expect(a.openExternal).not.toHaveBeenCalled();
  });

  test('existing report.pdf can be reopened without re-rendering', async () => {
    const a = api({ html: true, markdown: [], pdf: true });
    render(ReportFrame, { dir: DIR, api: a });
    await fireEvent.click(await screen.findByRole('button', { name: /open report\.pdf/i }));
    expect(a.openExternal).toHaveBeenCalledWith(DIR, 'report.pdf');
    expect(a.exportPDF).not.toHaveBeenCalled();
  });

  test('no Open report.pdf button when none exists', async () => {
    render(ReportFrame, { dir: DIR, api: api({ html: true, markdown: [] }) });
    await screen.findByRole('button', { name: /export pdf \(light\)/i });
    expect(screen.queryByRole('button', { name: /open report\.pdf/i })).toBeNull();
  });

  test('pdf button appears even if opening the exported PDF fails', async () => {
    const a = api({ html: true, markdown: [] });
    a.openExternal = vi.fn(async () => {
      throw new Error('no handler');
    });
    render(ReportFrame, { dir: DIR, api: a });
    await fireEvent.click(await screen.findByRole('button', { name: /export pdf \(light\)/i }));
    expect(await screen.findByRole('button', { name: /open report\.pdf/i })).toBeTruthy();
    expect((await screen.findByRole('alert')).textContent).toMatch(/no handler/);
  });

  test('double-click while exporting exports once', async () => {
    let release;
    const a = api({ html: true, markdown: [] });
    a.exportPDF = vi.fn(() => new Promise((r) => (release = r)));
    render(ReportFrame, { dir: DIR, api: a });
    const btn = await screen.findByRole('button', { name: /export pdf \(light\)/i });
    await fireEvent.click(btn);
    await fireEvent.click(btn);
    expect(a.exportPDF).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('button', { name: /export pdf \(dark\)/i }).disabled).toBe(true);
    release('/p');
    await waitFor(() => expect(a.openExternal).toHaveBeenCalledTimes(1));
  });

  test('dir change mid-export does not stamp or open for the new run', async () => {
    const DIR2 = '/out/ex.com/20250202-000000';
    let release;
    const a = api({ html: true, markdown: [] });
    a.exportPDF = vi.fn(() => new Promise((r) => (release = r)));
    const { rerender } = render(ReportFrame, { dir: DIR, api: a });
    await fireEvent.click(await screen.findByRole('button', { name: /export pdf \(light\)/i }));
    await rerender({ dir: DIR2, api: a });
    await screen.findByRole('button', { name: /export pdf \(light\)/i });
    release('/p');
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.queryByRole('button', { name: /open report\.pdf/i })).toBeNull();
    expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.getByRole('button', { name: /export pdf \(light\)/i }).disabled).toBe(false);
  });
});
