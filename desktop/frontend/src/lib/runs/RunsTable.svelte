<script>
  // Run history: status filter tabs, sortable columns, one row per run. The
  // default order is running runs first, then newest first. Every cell is
  // engine text, rendered as text. runs: runstore.Run JSON (Info, Status,
  // CurrentStage, Elapsed in ns, Sev).
  import Tabs from '../ui/Tabs.svelte';
  import { SORT_GLYPH, STATUS_GLYPH, statusClass } from '../monitor/glyphs.js';
  import { SEVERITIES } from '../monitor/store.svelte.js';
  import { elapsed, grouped, sanitizeText } from '../monitor/text.js';

  let { runs, onopen } = $props();

  const STATUSES = ['running', 'ok', 'cancelled', 'failed', 'crashed', 'incompatible'];
  const LABELS = { running: 'Running', ok: 'OK', cancelled: 'Cancelled', failed: 'Failed', crashed: 'Crashed', incompatible: 'Incompatible' };
  const COLUMNS = [
    { id: 'status', label: 'Status' },
    { id: 'target', label: 'Target' },
    { id: 'started', label: 'Started' },
    { id: 'elapsed', label: 'Elapsed', right: true },
    { id: 'findings', label: 'Findings', right: true },
  ];
  const RUNNING_GLYPH = 'M5 3.5l7 4.5-7 4.5z';

  let filter = $state('all');
  let sortKey = $state('');
  let sortDir = $state('desc');

  const view = $derived(
    (runs ?? []).map((r, i) => {
      const sev = r?.Sev ?? {};
      return {
        raw: r,
        i,
        dir: String(r?.Info?.Dir ?? ''),
        target: sanitizeText(r?.Info?.Target) || '(unknown target)',
        started: Date.parse(r?.Info?.Started) || 0,
        status: String(r?.Status ?? ''),
        stage: sanitizeText(r?.CurrentStage),
        elapsed: Number.isFinite(r?.Elapsed) ? r.Elapsed : -1,
        sev,
        findings: Object.values(sev).reduce((n, v) => n + (Number(v) || 0), 0),
      };
    }),
  );

  const count = (status) => view.filter((r) => r.status === status).length;
  const tabs = $derived([
    { id: 'all', label: 'All', count: grouped(view.length) },
    ...STATUSES.map((id) => ({ id, label: LABELS[id], count: grouped(count(id)) })),
  ]);

  function compare(a, b) {
    switch (sortKey) {
      case 'status':
        return a.status.localeCompare(b.status);
      case 'target':
        return a.target.localeCompare(b.target);
      case 'started':
        return a.started - b.started;
      case 'elapsed':
        return a.elapsed - b.elapsed;
      default:
        return a.findings - b.findings;
    }
  }

  const rows = $derived.by(() => {
    const list = filter === 'all' ? view.slice() : view.filter((r) => r.status === filter);
    if (!sortKey) {
      return list.sort((a, b) => (b.status === 'running') - (a.status === 'running') || b.started - a.started || a.i - b.i);
    }
    list.sort((a, b) => compare(a, b) || a.i - b.i);
    return sortDir === 'desc' ? list.reverse() : list;
  });

  function sortBy(id) {
    if (sortKey === id) sortDir = sortDir === 'asc' ? 'desc' : 'asc';
    else {
      sortKey = id;
      sortDir = id === 'target' || id === 'status' ? 'asc' : 'desc';
    }
  }

  const pad = (n) => String(n).padStart(2, '0');
  function stamp(ms) {
    if (!ms) return '';
    const d = new Date(ms);
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  const sevText = (sev) =>
    SEVERITIES.filter((k) => sev[k] > 0)
      .map((k) => `${grouped(sev[k])} ${k.slice(0, 4)}`)
      .join(' · ');

  function onkeydown(event, r) {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    event.preventDefault();
    onopen(r.raw);
  }
</script>

<section class="pane runs" aria-label="Runs">
  <div class="pane-head">
    <h2 class="pane-title">Runs</h2>
    <Tabs {tabs} bind:value={filter} label="Filter by status" />
  </div>
  <div class="table" role="grid" aria-label="Runs" aria-rowcount={rows.length + 1}>
    <div class="tr thead" role="row">
      {#each COLUMNS as col (col.id)}
        <button
          type="button"
          class="th"
          class:right={col.right}
          role="columnheader"
          aria-sort={sortKey === col.id ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'}
          onclick={() => sortBy(col.id)}
        >
          {col.label}
          {#if sortKey === col.id}
            <svg viewBox="0 0 16 16" aria-hidden="true"><path d={SORT_GLYPH[sortDir]} /></svg>
          {/if}
        </button>
      {/each}
    </div>
    <div class="scroll" role="rowgroup">
      {#each rows as r (r.dir || r.i)}
        <div
          class="tr row st-{statusClass(r.status)}"
          role="row"
          tabindex="0"
          data-run={r.dir}
          data-status={r.status}
          onclick={() => onopen(r.raw)}
          onkeydown={(e) => onkeydown(e, r)}
        >
          <span class="td status" role="cell">
            <svg viewBox="0 0 16 16" aria-hidden="true"><path d={r.status === 'running' ? RUNNING_GLYPH : STATUS_GLYPH[statusClass(r.status)]} /></svg>
            {LABELS[r.status] ?? sanitizeText(r.status)}{#if r.status === 'running' && r.stage}<span class="stage"> · {r.stage}</span>{/if}
          </span>
          <span class="td target mono hi" role="cell">{r.target}</span>
          <span class="td mono lo" role="cell">{stamp(r.started)}</span>
          <span class="td mono lo right" role="cell">{r.elapsed >= 0 ? elapsed(r.elapsed / 1e6) : ''}</span>
          <span class="td mono right" role="cell" title={sevText(r.sev)}>{sevText(r.sev) || (r.findings ? grouped(r.findings) : '')}</span>
        </div>
      {/each}
      {#if rows.length === 0}
        <p class="empty">{view.length === 0 ? 'No runs yet. Start one from Launch.' : 'No runs with this status.'}</p>
      {/if}
    </div>
  </div>
</section>

<style>
  .runs { height: 100%; }
  .table { flex: 1; min-height: 0; display: flex; flex-direction: column; }
  .scroll { flex: 1; min-height: 0; overflow-y: auto; }
  .tr {
    position: relative;
    display: grid;
    grid-template-columns: var(--col-template) minmax(0, 1fr) var(--col-host) var(--col-time) var(--col-summary);
    align-items: center;
    height: var(--row-h);
    border-bottom: 1px solid var(--line-1);
  }
  .tr > * { min-width: 0; padding: 0 var(--s2); }
  .tr > :first-child { padding-left: var(--s3); }
  .tr > :last-child { padding-right: var(--s3); }
  .thead { flex: none; background: var(--bg-1); }
  .th {
    display: flex;
    align-items: center;
    gap: var(--s1);
    height: 100%;
    color: var(--tx-mid);
    font: var(--w-label) var(--fs-label)/var(--lh-label) var(--font-label);
    letter-spacing: var(--tr-label);
    text-transform: uppercase;
    text-align: left;
    cursor: pointer;
  }
  .th:hover { color: var(--tx-hi); }
  .right { justify-content: flex-end; text-align: right; }
  .th svg { width: var(--icon-sm); height: var(--icon-sm); fill: currentColor; stroke: none; }
  .row { cursor: pointer; transition: background-color var(--t-fast) var(--ease); }
  .row:hover { background: var(--bg-3); }
  .row:focus-visible { outline: none; background: var(--bg-4); }
  .row:focus-visible::after { content: ''; position: absolute; inset: 0 auto 0 0; width: var(--s0); background: var(--red-500); }
  .td { overflow: hidden; white-space: nowrap; text-overflow: ellipsis; color: var(--tx); user-select: text; }
  .status { display: flex; align-items: center; gap: var(--s1); color: var(--st); }
  .status svg { flex: none; width: var(--icon-sm); height: var(--icon-sm); fill: none; stroke: currentColor; stroke-width: 1.5; }
  .stage { color: var(--tx-mid); }
  .mono { font: var(--w-body) var(--fs-mono)/var(--lh-mono) var(--font-mono); font-variant-numeric: tabular-nums lining-nums; }
  .hi { color: var(--tx-hi); }
  .lo { color: var(--tx-lo); }
  .st-running { --st: var(--red-500); }
  .st-ok { --st: var(--st-ok); }
  .st-failed { --st: var(--st-failed); }
  .st-cancelled { --st: var(--tx-mid); }
  .st-warning { --st: var(--sev-medium); }
  .empty { margin: 0; padding: var(--s3); color: var(--tx-lo); }
</style>
