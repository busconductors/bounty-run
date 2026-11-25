<script>
  // A run's summary.html in a sandboxed iframe. The report is untrusted: it is
  // scan data. sandbox="allow-scripts" (never allow-same-origin) gives it an
  // opaque origin, so its script cannot touch this window or the Wails
  // bindings, and the server adds a CSP that blocks network access. Markdown
  // reports open in the OS default app, never in this window.
  // api: { available(dir) -> { html, markdown[], pdf },
  //        openExternal(dir, name), exportPDF(dir, theme) -> path }
  import Button from '../ui/Button.svelte';
  import { sanitizeText } from '../monitor/text.js';

  let { dir = '', api } = $props();

  let info = $state.raw(null);
  let error = $state('');
  let exporting = $state(''); // theme being exported, or ''

  $effect(() => {
    const target = dir;
    info = null;
    error = '';
    exporting = '';
    if (!target) return;
    let live = true;
    api
      .available(target)
      .then((next) => live && (info = next))
      .catch((e) => live && (error = sanitizeText(e?.cause?.message ?? e?.message ?? e)));
    return () => {
      live = false;
    };
  });

  const src = $derived.by(() => {
    const [target, stamp] = dir.split(/[\\/]/).filter(Boolean).slice(-2);
    return target && stamp ? `/reports/${encodeURIComponent(target)}/${encodeURIComponent(stamp)}/summary.html` : '';
  });

  async function openExternal(name) {
    error = '';
    try {
      await api.openExternal(dir, name);
    } catch (e) {
      error = sanitizeText(e?.cause?.message ?? e?.message ?? e);
    }
  }

  // An export outlives a dir switch, so every write is guarded by `dir === target`:
  // a stale export must never touch the current run's state.
  async function exportPDF(theme) {
    if (exporting) return;
    const target = dir;
    exporting = theme;
    error = '';
    try {
      await api.exportPDF(target, theme);
      // Record the file before opening it: if opening fails the button stays for a retry.
      if (dir === target && info) info = { ...info, pdf: true };
      await api.openExternal(target, 'report.pdf');
    } catch (e) {
      if (dir === target) error = sanitizeText(e?.cause?.message ?? e?.message ?? e);
    } finally {
      if (dir === target) exporting = '';
    }
  }
</script>

<section class="report" data-view="report" aria-label="Report">
  {#if error}<p class="error" role="alert">Report: {error}</p>{/if}
  {#if info}
    {#if info.markdown?.length || info.html || info.pdf}
      <div class="open">
        {#each info.markdown ?? [] as name (name)}
          <Button onclick={() => openExternal(name)} title="Open in the default app">Open {name}</Button>
        {/each}
        {#if info.html}
          <Button variant="primary" disabled={exporting} onclick={() => exportPDF('light')} title="Export the report to a Light PDF and open it">
            {exporting === 'light' ? 'Exporting PDF…' : 'Export PDF (Light)'}
          </Button>
          <Button disabled={exporting} onclick={() => exportPDF('dark')} title="Export the report to a Dark PDF and open it">
            {exporting === 'dark' ? 'Exporting PDF…' : 'Export PDF (Dark)'}
          </Button>
        {/if}
        {#if info.pdf}
          <Button disabled={exporting} onclick={() => openExternal('report.pdf')} title="Open in the default app">Open report.pdf</Button>
        {/if}
      </div>
    {/if}
    {#if info.html && src}
      <iframe title="Run report" {src} sandbox="allow-scripts" referrerpolicy="no-referrer"></iframe>
    {:else}
      <p class="note">No report for this run</p>
    {/if}
  {/if}
</section>

<style>
  .report { flex: none; display: flex; flex-direction: column; height: 50%; min-height: 0; border-top: 1px solid var(--line-1); }
  .open { flex: none; display: flex; gap: var(--s2); padding: var(--s2) var(--s3); }
  iframe { flex: 1; min-height: 0; width: 100%; border: 0; background: var(--bg-0); }
  .note { margin: 0; padding: var(--s3); color: var(--tx-mid); }
  .error { margin: 0; padding: var(--s2) var(--s3); color: var(--st-failed); }
</style>
