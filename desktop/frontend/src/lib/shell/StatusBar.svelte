<script>
  // 22px telemetry row: LIVE state, stage x/N, elapsed, ev/s and C/H/M/L/I.
  import { runStatus as s } from './status.svelte.js';

  const SEV = [
    ['critical', 'C'],
    ['high', 'H'],
    ['medium', 'M'],
    ['low', 'L'],
    ['info', 'I'],
  ];
  const label = $derived(s.live ? 'LIVE' : (s.label || 'idle').toUpperCase());
</script>

<footer>
  <span class="state"><span class="dot" class:is-live={s.live} aria-hidden="true"></span>{label}</span>
  <span>STAGE {s.stage || '--/--'}</span>
  <span>{s.elapsed || '--:--:--'}</span>
  <span>{s.rate === null ? '--' : s.rate} ev/s</span>
  <span class="counts">
    {#each SEV as [key, letter] (key)}
      <span><b class={key}>{letter}</b>{s.counts ? s.counts[key] : '--'}</span>
    {/each}
  </span>
  <span class="health">engine · tools</span>
</footer>

<style>
  footer {
    display: flex;
    align-items: center;
    gap: var(--s4);
    height: 100%;
    padding: 0 var(--s3);
    overflow: hidden;
    background: var(--bg-0);
    border-top: 1px solid var(--line-1);
    color: var(--tx-mid);
    font: var(--w-body) var(--fs-mono)/var(--lh-micro) var(--font-mono);
    font-variant-numeric: tabular-nums lining-nums;
    white-space: nowrap;
  }
  .state {
    display: inline-flex;
    align-items: center;
    gap: var(--s1);
    color: var(--tx-mid);
    font: var(--w-label) var(--fs-label)/var(--lh-label) var(--font-label);
    letter-spacing: var(--tr-label);
  }
  .dot { width: var(--live-dot); height: var(--live-dot); border: 1px solid var(--tx-off); }
  .dot.is-live { border-color: var(--red-400); background: var(--red-400); box-shadow: var(--glow); }
  .counts { display: flex; gap: var(--s3); }
  b { margin-right: var(--s1); font-weight: var(--w-body); }
  .critical { color: var(--sev-critical); }
  .high { color: var(--sev-high); }
  .medium { color: var(--sev-medium); }
  .low { color: var(--sev-low); }
  .info { color: var(--sev-info); }
  .health { margin-left: auto; color: var(--tx-lo); }
</style>
