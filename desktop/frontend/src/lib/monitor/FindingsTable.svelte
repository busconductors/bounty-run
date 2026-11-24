<script>
  // Dense findings table: severity filter tabs, sortable columns, a 3px
  // severity bar, selection = bg-4 + 2px red inset. Only rows in view are in
  // the DOM. Every cell is engine text, rendered as text.
  import DensityToggle from '../ui/DensityToggle.svelte';
  import SeverityChip from '../ui/SeverityChip.svelte';
  import Tabs from '../ui/Tabs.svelte';
  import { px, rowHeight, visibleRange } from '../ui/virtual.js';
  import { SORT_GLYPH } from './glyphs.js';
  import { SEVERITIES } from './store.svelte.js';
  import { clock, grouped } from './text.js';

  let { findings, counts, rev = 0, selected = 0, onselect, density = $bindable('comfortable') } = $props();

  const TAB_LABELS = { critical: 'Crit', high: 'High', medium: 'Med', low: 'Low', info: 'Info', other: 'Other' };
  const RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4, other: 5 };
  const COLUMNS = [
    { id: 'sev', label: 'Sev' },
    { id: 'template', label: 'Template' },
    { id: 'host', label: 'Host' },
    { id: 'url', label: 'URL' },
    { id: 'summary', label: 'Summary' },
    { id: 'time', label: 'Time', right: true },
  ];

  let filter = $state('all');
  let sortKey = $state('time');
  let sortDir = $state('asc');
  let scroller = $state(null);
  let scrollTop = $state(0);
  let viewH = $state(0);
  let rowH = $state(0);

  const tabs = $derived.by(() => {
    void rev;
    const list = [{ id: 'all', label: 'All', count: grouped(findings.length) }];
    for (const key of [...SEVERITIES, 'other']) {
      if (key === 'other' && !counts.other) continue;
      list.push({ id: key, label: TAB_LABELS[key], count: grouped(counts[key]) });
    }
    return list;
  });

  function compare(a, b) {
    switch (sortKey) {
      case 'sev':
        return RANK[a.sev] - RANK[b.sev] || a.seq - b.seq;
      case 'time':
        return a.t - b.t || a.seq - b.seq;
      default:
        return a[sortKey].localeCompare(b[sortKey]) || a.seq - b.seq;
    }
  }

  const rows = $derived.by(() => {
    void rev;
    let list = filter === 'all' ? findings.slice() : findings.filter((f) => f.sev === filter);
    if (sortKey !== 'time') list.sort(compare);
    if (sortDir === 'desc') list.reverse();
    return list;
  });

  const range = $derived(visibleRange({ count: rows.length, rowH, scrollTop, viewH }));
  const slice = $derived(rows.slice(range.start, range.end));
  const now = $derived((void rev, Date.now()));

  function sortBy(id) {
    if (sortKey === id) sortDir = sortDir === 'asc' ? 'desc' : 'asc';
    else {
      sortKey = id;
      sortDir = 'asc';
    }
  }

  function measure() {
    if (!scroller) return;
    viewH = scroller.clientHeight;
    const h = rowHeight(scroller, '[data-finding]');
    if (h > 0) rowH = h;
  }

  $effect(() => {
    void rows;
    void density;
    measure();
  });

  $effect(() => {
    if (!scroller || typeof ResizeObserver === 'undefined') return;
    const observer = new ResizeObserver(measure);
    observer.observe(scroller);
    return () => observer.disconnect();
  });

  // Up/down move the selection through the visible order.
  function onkeydown(event) {
    const step = { ArrowDown: 1, ArrowUp: -1 }[event.key];
    if (!step || rows.length === 0) return;
    event.preventDefault();
    const at = rows.findIndex((f) => f.seq === selected);
    const next = rows[Math.min(rows.length - 1, Math.max(0, at === -1 ? 0 : at + step))];
    onselect(next.seq);
    if (rowH > 0) {
      const index = rows.indexOf(next);
      const top = index * rowH;
      if (top < scroller.scrollTop) scroller.scrollTop = top;
      else if (top + rowH > scroller.scrollTop + scroller.clientHeight) scroller.scrollTop = top + rowH - scroller.clientHeight;
    }
  }
</script>

<section class="pane findings" aria-label="Findings">
  <div class="pane-head">
    <h2 class="pane-title">Findings</h2>
    <Tabs {tabs} bind:value={filter} label="Filter by severity" />
    <span class="pane-spacer"></span>
    <DensityToggle bind:value={density} />
  </div>
  <div class="table" role="grid" aria-label="Findings" aria-rowcount={rows.length + 1} tabindex="0" {onkeydown}>
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
    <div class="scroll" bind:this={scroller} onscroll={() => (scrollTop = scroller.scrollTop)} role="rowgroup">
      <div class="space" use:px={['height', rowH > 0 ? rows.length * rowH : null]}>
        <div class="rows" use:px={['top', rowH > 0 ? range.start * rowH : null]}>
          {#each slice as f (f.seq)}
            <!-- Keys go to the grid (onkeydown above), so rows take no focus. -->
            <!-- svelte-ignore a11y_click_events_have_key_events, a11y_interactive_supports_focus -->
            <div
              class="tr row sev-{f.sev}"
              class:selected={f.seq === selected}
              class:flash={f.sev === 'critical' && now - f.t < 400}
              role="row"
              aria-selected={f.seq === selected}
              data-finding={f.seq}
              onclick={() => onselect(f.seq)}
            >
              <span class="td" role="cell"><SeverityChip severity={f.severity} /></span>
              <span class="td mono hi" role="cell">{f.template}</span>
              <span class="td mono" role="cell">{f.host}</span>
              <span class="td mono" role="cell">{f.url}</span>
              <span class="td" role="cell">{f.summary}</span>
              <span class="td mono time" role="cell">{clock(f.t)}</span>
            </div>
          {/each}
        </div>
      </div>
      {#if rows.length === 0}
        <p class="empty">{findings.length === 0 ? 'No findings yet.' : 'No findings at this severity.'}</p>
      {/if}
    </div>
  </div>
</section>

<style>
  .findings { height: 100%; border-right: 1px solid var(--line-1); }
  .table { flex: 1; min-height: 0; display: flex; flex-direction: column; }
  .scroll { flex: 1; min-height: 0; overflow-y: auto; overflow-x: hidden; }
  /* The grid is flush to the pane, so focus shows on its header rule. */
  .table:focus-visible { outline: none; }
  .table:focus-visible .thead { border-bottom-color: var(--red-400); }
  .space, .rows { position: relative; }
  .tr {
    position: relative;
    display: grid;
    grid-template-columns: var(--col-sev) var(--col-template) var(--col-host) minmax(0, 1fr) var(--col-summary) var(--col-time);
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
  .th.right { justify-content: flex-end; }
  .th svg { width: var(--icon-sm); height: var(--icon-sm); fill: currentColor; stroke: none; }
  .row { cursor: default; transition: background-color var(--t-fast) var(--ease); }
  .row:hover { background: var(--bg-3); }
  .row::before { content: ''; position: absolute; inset: 0 auto 0 0; width: var(--sev-bar-w); background: var(--sev); }
  .row.selected { background: var(--bg-4); }
  .row.selected::before { left: var(--s0); }
  .row.selected::after { content: ''; position: absolute; inset: 0 auto 0 0; width: var(--s0); background: var(--red-500); }
  .row.flash { animation: flash var(--t-flash) var(--ease); }
  @keyframes flash { from { background: var(--bg-4); } to { background: transparent; } }
  .td { overflow: hidden; white-space: nowrap; text-overflow: ellipsis; color: var(--tx); user-select: text; }
  .mono { font: var(--w-body) var(--fs-mono)/var(--lh-mono) var(--font-mono); }
  .hi { color: var(--tx-hi); }
  .time { text-align: right; color: var(--tx-lo); font-variant-numeric: tabular-nums lining-nums; }
  .selected .time { color: var(--tx-mid); }
  .sev-critical { --sev: var(--sev-critical); }
  .sev-high { --sev: var(--sev-high); }
  .sev-medium { --sev: var(--sev-medium); }
  .sev-low { --sev: var(--sev-low); }
  .sev-info, .sev-other { --sev: var(--sev-info); }
  .empty { margin: 0; padding: var(--s3); color: var(--tx-lo); }
</style>
