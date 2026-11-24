<script>
  // Square severity chip: 0-4 bar glyph, then the label. A severity outside
  // the five known ones keeps its raw label, in the neutral info style.
  import { sevKey } from '../monitor/store.svelte.js';

  let { severity } = $props();

  const LABELS = { critical: 'CRIT', high: 'HIGH', medium: 'MED', low: 'LOW', info: 'INFO' };
  const BARS = { critical: 4, high: 3, medium: 2, low: 1, info: 0, other: 0 };
  const key = $derived(sevKey(severity));
  const label = $derived(key === 'other' ? String(severity ?? '') : LABELS[key]);
  const bars = $derived(BARS[key]);
</script>

<span class="chip sev-{key}" title={String(severity ?? '')}>
  <svg viewBox="0 0 11 8" aria-hidden="true">
    {#each [0, 1, 2, 3] as i (i)}
      <rect x={i * 3} y="0" width="2" height="8" class:off={i >= bars} />
    {/each}
  </svg>
  <span class="label">{label}</span>
</span>

<style>
  .chip {
    --sev: var(--sev-info);
    display: inline-flex;
    align-items: center;
    gap: var(--s1);
    width: var(--chip-w);
    height: var(--chip-h);
    padding: 0 var(--s1);
    border: 1px solid var(--sev);
    border-radius: var(--radius-ctl);
    color: var(--sev);
    font: var(--w-label) var(--fs-micro)/var(--lh-micro) var(--font-label);
    letter-spacing: var(--tr-chip);
    vertical-align: middle;
  }
  .label { min-width: 0; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }
  svg { flex: none; width: var(--chip-bars-w); height: var(--chip-bars-h); fill: currentColor; }
  rect.off { opacity: .25; }
  .sev-critical { --sev: var(--sev-critical); background: var(--sev-critical); color: var(--bg-0); }
  .sev-high { --sev: var(--sev-high); background: var(--sev-high-tint); }
  .sev-medium { --sev: var(--sev-medium); background: var(--sev-medium-tint); }
  .sev-low { --sev: var(--sev-low); }
  .sev-info, .sev-other { border-color: var(--line-2); }
  .sev-other { color: var(--tx-mid); }
</style>
