<script>
  // The context bar's stage mini-track: one 12×4 segment per top-level stage,
  // grouped by tier. The running segment sweeps and glows; skipped is hatched.
  import { statusClass } from './glyphs.js';

  let { rows, live = false } = $props();

  const tiers = $derived.by(() => {
    const groups = [];
    for (const row of rows) {
      if (row.level !== 1) continue;
      const last = groups.at(-1);
      if (last && last.tier === row.tier) last.rows.push(row);
      else groups.push({ tier: row.tier, rows: [row] });
    }
    return groups;
  });

  function shown(row) {
    if (row.status === 'running' && !live) return 'cancelled';
    return statusClass(row.status);
  }
</script>

<div class="track" role="img" aria-label="Stage progress">
  {#each tiers as group, i (i)}
    <div class="tier">
      {#each group.rows as row (row.id)}
        <span class="seg {shown(row)}" class:is-live={shown(row) === 'running'} title="{row.id}: {shown(row)}"></span>
      {/each}
    </div>
  {/each}
</div>

<style>
  .track { display: flex; align-items: center; gap: var(--track-tier-gap); flex: none; }
  .tier { display: flex; gap: var(--track-gap); }
  .seg { position: relative; width: var(--track-seg-w); height: var(--track-seg-h); overflow: hidden; background: var(--line-2); }
  .seg.ok { background: var(--st-ok); }
  .seg.failed { background: var(--st-failed); }
  .seg.cancelled, .seg.warning { background: var(--tx-mid); }
  .seg.skipped { background: var(--hatch); border: 1px dashed var(--tx-lo); }
  .seg.running { overflow: visible; background: var(--red-400); }
  .seg.running.is-live { box-shadow: var(--glow); }
  .seg.running::after {
    content: '';
    position: absolute;
    inset: 0;
    background: var(--red-300);
    transform-origin: left;
    animation: sweep var(--t-sweep) linear infinite;
  }
  @keyframes sweep { from { transform: scaleX(0); } to { transform: scaleX(1); } }
</style>
