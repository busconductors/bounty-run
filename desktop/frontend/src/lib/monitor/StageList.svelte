<script>
  // The run's stages, grouped by tier (rows from stageRows). A child stage
  // (origin_deep) sits indented under its parent. live: the run is still going;
  // once it is over a stage left 'running' is shown as stopped.
  import { STATUS_GLYPH, TIER_GLYPH, statusClass } from './glyphs.js';
  import { duration } from './text.js';

  let { rows, live = false, now = 0 } = $props();

  const top = $derived(rows.filter((row) => row.level === 1));
  const finished = $derived(top.filter((row) => row.status !== 'queued' && row.status !== 'running').length);

  function shown(row) {
    if (row.status === 'running' && !live) return 'cancelled';
    return statusClass(row.status);
  }

  function statusTitle(row) {
    if (row.status === 'running' && !live) return 'stopped without stage_end';
    return row.reason ? `${row.status}: ${row.reason}` : row.status;
  }

  function took(row) {
    if (row.durationMs !== null) return duration(row.durationMs);
    if (row.status === 'running' && live && row.startT && now) return duration(Math.max(0, now - row.startT));
    return '-';
  }

  // The count column: progress while running, then the stage's first count.
  function count(row) {
    if (row.status === 'running' && row.total > 0) return `${row.done}/${row.total}`;
    const entries = row.counts ? Object.entries(row.counts) : [];
    return entries.length ? String(entries[0][1]) : '';
  }

  const countTitle = (row) => (row.counts ? Object.entries(row.counts).map(([k, v]) => `${k} ${v}`).join(', ') : '');
  const index = (row) => (row.level === 1 && Number.isFinite(row.num) ? String(row.num).padStart(2, '0') : '');
</script>

<section class="pane stages" aria-label="Stages">
  <div class="pane-head">
    <h2 class="pane-title">Stages</h2>
    <span class="pane-spacer"></span>
    <span class="pane-count">{finished}/{top.length}</span>
  </div>
  <div class="groups" role="list">
    {#if rows.length === 0}
      <p class="empty">Waiting for the run to start.</p>
    {/if}
    {#each rows as row, i (row.id)}
      {#if i === 0 || rows[i - 1].tier !== row.tier}
        <div class="tier-head">{row.tier}</div>
      {/if}
      <div
        class="stage {shown(row)}"
        class:is-child={row.level === 2}
        role="listitem"
        aria-level={row.level}
        data-stage={row.id}
        data-parent={row.parent || undefined}
        title={row.title || undefined}
      >
        <span class="num idx">{index(row)}</span>
        <svg class="tier tier-{row.tier}" viewBox="0 0 16 16" aria-hidden="true">
          {#each TIER_GLYPH[row.tier] ?? TIER_GLYPH.other as d, j (j)}
            <path {d} class:fill={j === 1} />
          {/each}
        </svg>
        <span class="name">{row.name}</span>
        <span class="status" title={statusTitle(row)}>
          {#if shown(row) === 'running'}
            <span class="live-dot is-live"></span>
          {:else}
            <svg class="st-{shown(row)}" viewBox="0 0 16 16" role="img" aria-label={statusTitle(row)}>
              <path d={STATUS_GLYPH[shown(row)]} />
            </svg>
          {/if}
        </span>
        <span class="num dur">{took(row)}</span>
        <span class="num cnt" title={countTitle(row) || undefined}>{count(row)}</span>
      </div>
    {/each}
  </div>
</section>

<style>
  .stages { height: 100%; border-right: 1px solid var(--line-1); }
  .num { font: var(--w-body) var(--fs-mono)/var(--lh-mono) var(--font-mono); font-variant-numeric: tabular-nums lining-nums; text-align: right; }
  .groups { flex: 1; min-height: 0; overflow-y: auto; }
  .empty { margin: 0; padding: var(--s3); color: var(--tx-mid); }
  .tier-head {
    display: flex;
    align-items: center;
    height: var(--row-h);
    padding: 0 var(--s3);
    border-bottom: 1px solid var(--line-1);
    background: var(--bg-1);
    color: var(--tx-lo);
    font: var(--w-label) var(--fs-micro)/var(--lh-micro) var(--font-label);
    letter-spacing: var(--tr-micro);
    text-transform: uppercase;
  }
  .stage {
    display: grid;
    grid-template-columns: var(--col-index) var(--icon) minmax(0, 1fr) var(--icon) var(--col-duration) var(--col-count);
    align-items: center;
    gap: var(--s1);
    height: var(--row-h);
    padding: 0 var(--s3);
    border-bottom: 1px solid var(--line-1);
  }
  svg { display: block; width: var(--icon); height: var(--icon); fill: none; stroke: currentColor; stroke-width: 1.5; stroke-linecap: square; stroke-linejoin: miter; }
  path.fill { fill: currentColor; }
  .idx { color: var(--tx-lo); text-align: left; }
  .tier { color: var(--tx-mid); }
  .tier-intrusive { color: var(--tier-intrusive); }
  .name { min-width: 0; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; color: var(--tx); font: var(--w-body) var(--fs-mono)/var(--lh-mono) var(--font-mono); }
  .is-child .name { padding-left: var(--s4); color: var(--tx-mid); }
  .stage.running { background: var(--red-tint); }
  .stage.running .name { color: var(--tx-hi); }
  .stage.skipped .name, .stage.queued .name { color: var(--tx-lo); }
  .dur, .cnt { color: var(--tx-mid); overflow: hidden; white-space: nowrap; }
  .stage.skipped .dur, .stage.queued .dur { color: var(--tx-off); }
  .status { display: grid; place-items: center; width: var(--icon); height: var(--icon); }
  .st-ok { color: var(--st-ok); }
  .st-failed { color: var(--st-failed); }
  .st-skipped { color: var(--tx-lo); stroke-dasharray: 2 2; }
  .st-cancelled { color: var(--tx-mid); }
  .st-queued { color: var(--tx-off); }
  .st-warning { color: var(--tx-mid); }
  .live-dot { width: var(--live-dot); height: var(--live-dot); background: var(--red-400); }
  .live-dot.is-live { box-shadow: var(--glow); }
</style>
