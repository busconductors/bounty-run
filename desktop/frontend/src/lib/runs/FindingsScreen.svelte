<script>
  // One run's findings, read from the run directory (not replayed from
  // events), in the Monitor's findings table. api: { get(dir) } returning
  // { findings, indexAvailable, pending, missing }. A partly written
  // findings.json comes back pending and is asked for again; it is never an
  // error. Everything shown is engine text, rendered as text.
  import FindingsTable from '../monitor/FindingsTable.svelte';
  import { sevKey } from '../monitor/store.svelte.js';
  import { sanitizeText } from '../monitor/text.js';

  let { dir = '', api, report = undefined, retryMs = 1000, maxRetries = 30 } = $props();

  let result = $state.raw(null);
  let error = $state('');
  let loading = $state(false);
  let selected = $state(0);
  let density = $state('comfortable');

  $effect(() => {
    const target = dir;
    result = null;
    error = '';
    selected = 0;
    if (!target) return;
    let live = true;
    let timer = 0;
    let tries = 0;
    loading = true;
    const load = async () => {
      try {
        const next = await api.get(target);
        if (!live) return;
        result = next;
        error = '';
        if (next?.pending && tries++ < maxRetries) timer = setTimeout(load, retryMs);
        else loading = false;
      } catch (e) {
        if (!live) return;
        error = sanitizeText(e?.cause?.message ?? e?.message ?? e);
        loading = false;
      }
    };
    load();
    return () => {
      live = false;
      clearTimeout(timer);
    };
  });

  const rows = $derived(
    (result?.findings ?? []).map((f, i) => ({
      seq: i + 1,
      sev: sevKey(f.severity),
      severity: sanitizeText(f.severity),
      template: sanitizeText(f.template),
      host: sanitizeText(f.host),
      url: sanitizeText(f.url),
      summary: sanitizeText(f.name),
      t: 0,
      fingerprint: f.fingerprint ?? '',
      evidencePath: f.evidencePath ?? '',
    })),
  );
  const counts = $derived.by(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0, other: 0 };
    for (const f of rows) c[f.sev]++;
    return c;
  });
  const current = $derived(rows.find((f) => f.seq === selected) ?? null);
  const stamp = $derived(dir ? dir.split(/[\\/]/).filter(Boolean).slice(-2).join(' / ') : '');
</script>

<section class="screen" data-view="findings">
  {#if !dir}
    <p class="note">Pick a run in Runs to see its findings.</p>
  {:else}
    <header class="bar">
      <span class="stamp mono">{stamp}</span>
      {#if result?.pending}<span class="note" role="status">Findings are still being written…</span>{/if}
      {#if result?.missing}<span class="note" role="status">This run wrote no findings file.</span>{/if}
      {#if result && !result.pending && !result.missing && !result.indexAvailable}
        <span class="note" role="status">Evidence link unavailable: this run has no findings index.</span>
      {/if}
      {#if error}<span class="error" role="alert">Could not read findings: {error}</span>{/if}
    </header>
    <div class="body">
      <div class="table"><FindingsTable findings={rows} {counts} {selected} onselect={(seq) => (selected = seq)} bind:density /></div>
      {#if current}
        <dl class="detail" aria-label="Selected finding">
          <dt>Finding</dt><dd class="mono">{current.template}</dd>
          <dt>Evidence</dt>
          <dd class="mono">{current.evidencePath || (current.fingerprint ? 'no evidence recorded' : 'evidence link unavailable')}</dd>
        </dl>
      {/if}
      <!-- The report viewer renders here (Task 17). -->
      {#if report}{@render report()}{/if}
    </div>
  {/if}
</section>

<style>
  .screen { height: 100%; display: flex; flex-direction: column; min-height: 0; }
  .bar { flex: none; display: flex; align-items: center; gap: var(--s4); height: var(--panel-h); padding: 0 var(--s3); border-bottom: 1px solid var(--line-1); }
  .stamp { color: var(--tx-hi); }
  .mono { font: var(--w-body) var(--fs-mono)/var(--lh-mono) var(--font-mono); }
  .note { margin: 0; padding: var(--s3); color: var(--tx-mid); }
  .bar .note { padding: 0; }
  .error { color: var(--st-failed); }
  .body { flex: 1; min-height: 0; display: flex; flex-direction: column; }
  .table { flex: 1; min-height: 0; }
  .detail { flex: none; display: grid; grid-template-columns: var(--col-meta-key) minmax(0, 1fr); gap: var(--s1) var(--s2); margin: 0; padding: var(--s2) var(--s3); border-top: 1px solid var(--line-1); background: var(--bg-2); }
  dt { color: var(--tx-lo); }
  dd { margin: 0; color: var(--tx); overflow-wrap: anywhere; user-select: text; }
</style>
