<script>
  // Stage toggles grouped by tier, built from the engine's own stage list
  // (introspect stages via the catalog) — there is no stage list in the UI.
  import Checkbox from '../ui/Checkbox.svelte';
  import { TIERS, TIER_GLYPH, withinCeiling } from './model.svelte.js';

  let { stages, modifiers = [], enabled = $bindable([]), ceiling, missing = {}, onchange = undefined } = $props();

  // Each tier's rows: a stage, then its child stages and modifiers.
  const groups = $derived(
    TIERS.map((tier) => {
      const rows = [];
      for (const stage of stages) {
        if (stage.tier !== tier || stage.parent) continue;
        rows.push({ kind: 'stage', ...stage });
        for (const child of stages) if (child.parent === stage.id) rows.push({ kind: 'child', ...child });
        for (const mod of modifiers) if (mod.parent === stage.id) rows.push({ kind: 'modifier', ...mod, tier });
      }
      return { tier, rows };
    }).filter((group) => group.rows.length > 0),
  );

  const isOn = (id) => enabled.includes(id);
  const gated = (row) => !withinCeiling(row.tier, ceiling);
  // A child stage or modifier only means something while its parent runs.
  const orphaned = (row) => row.kind !== 'stage' && !isOn(row.parent);

  function set(id, on) {
    enabled = on ? [...enabled, id] : enabled.filter((x) => x !== id);
    onchange?.(enabled);
  }
</script>

<div class="grid">
  {#each groups as group (group.tier)}
    <section class="tier" aria-label="{group.tier} stages">
      <h3><span class="glyph" aria-hidden="true">{TIER_GLYPH[group.tier]}</span>{group.tier}</h3>
      {#each group.rows as row (row.id)}
        {@const off = gated(row) || orphaned(row)}
        <div
          class="row {row.kind}"
          class:off
          data-stage={row.id}
          data-opt-in={row.opt_in ? 'true' : 'false'}
        >
          <Checkbox
            label="{row.id} {row.title}"
            checked={isOn(row.id)}
            disabled={off}
            onchange={(on) => set(row.id, on)}
          />
          <span class="num">{row.kind === 'modifier' ? '+' : String(row.num).padStart(2, '0')}</span>
          <span class="id">{row.id}</span>
          <span class="title">{row.title}</span>
          <span class="marks">
            {#if row.opt_in}<span class="chip">OPT-IN</span>{/if}
            {#each row.caps ?? [] as cap (cap)}<span class="chip cap">{cap}</span>{/each}
            {#if missing[row.id]?.length}
              <span class="missing">⚠ {missing[row.id].join(', ')} missing</span>
            {/if}
            {#if gated(row)}<span class="note">above ceiling</span>{/if}
          </span>
        </div>
      {/each}
    </section>
  {/each}
</div>

<style>
  /* Two balanced columns when there is room; a row never splits. */
  .grid { columns: 2 var(--stage-col-min); column-gap: var(--s6); }
  .tier + .tier { margin-top: var(--s3); }
  .row { break-inside: avoid; }
  h3 {
    display: flex;
    align-items: center;
    gap: var(--s1);
    height: var(--ctl-h-sm);
    margin: 0;
    border-bottom: 1px solid var(--line-1);
    color: var(--tx-mid);
    font: var(--w-label) var(--fs-micro)/var(--lh-micro) var(--font-label);
    letter-spacing: var(--tr-micro);
    text-transform: uppercase;
    break-after: avoid;
  }
  .glyph { font: var(--w-body) var(--fs-mono)/var(--lh-micro) var(--font-mono); }
  .row {
    display: grid;
    grid-template-columns: var(--checkbox) var(--col-index) var(--stage-id-w) minmax(0, 1fr) auto;
    align-items: center;
    gap: var(--s2);
    height: var(--list-row-h);
    padding: 0 var(--s2);
    border-bottom: 1px solid var(--line-1);
  }
  .row:hover { background: var(--bg-3); }
  .num, .id { color: var(--tx-lo); font: var(--w-body) var(--fs-mono)/var(--lh-mono) var(--font-mono); }
  .num { text-align: right; }
  .id { color: var(--tx); }
  .child .id, .modifier .id { padding-left: var(--s3); }
  .title { overflow: hidden; color: var(--tx-mid); text-overflow: ellipsis; white-space: nowrap; }
  .marks { display: flex; align-items: center; gap: var(--s2); }
  .chip {
    display: inline-flex;
    align-items: center;
    height: var(--chip-h);
    padding: 0 var(--s1);
    border: 1px solid var(--line-2);
    border-radius: var(--radius-ctl);
    color: var(--tx-mid);
    font: var(--w-label) var(--fs-micro)/var(--lh-micro) var(--font-label);
    letter-spacing: var(--tr-chip);
    text-transform: uppercase;
  }
  .chip.cap { border-style: dashed; }
  .missing { color: var(--sev-medium); font: var(--w-body) var(--fs-mono)/var(--lh-mono) var(--font-mono); }
  .note { color: var(--tx-lo); font: var(--w-label) var(--fs-micro)/var(--lh-micro) var(--font-label); letter-spacing: var(--tr-micro); text-transform: uppercase; }
  .off .id, .off .title, .off .num { color: var(--tx-off); }
</style>
