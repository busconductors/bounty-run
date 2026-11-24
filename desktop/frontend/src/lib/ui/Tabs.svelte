<script>
  // Underline tabs (no pills). tabs: [{ id, label, count? }]. They stretch to
  // the height of the pane header they sit in; the active one gets the 2px red
  // underline on the header rule.
  let { tabs, value = $bindable(), label, onchange = undefined } = $props();

  function pick(id) {
    if (id === value) return;
    value = id;
    onchange?.(id);
  }

  function onkeydown(event) {
    const step = { ArrowRight: 1, ArrowLeft: -1 }[event.key];
    if (!step || tabs.length === 0) return;
    event.preventDefault();
    const at = tabs.findIndex((tab) => tab.id === value);
    const next = tabs[(at + step + tabs.length) % tabs.length];
    pick(next.id);
    const buttons = [...event.currentTarget.querySelectorAll('[role="tab"]')];
    buttons[tabs.indexOf(next)]?.focus();
  }
</script>

<div class="tabs" role="tablist" aria-label={label} tabindex="-1" {onkeydown}>
  {#each tabs as tab, i (i)}
    <button
      type="button"
      role="tab"
      class="tab"
      class:active={tab.id === value}
      aria-selected={tab.id === value}
      tabindex={tab.id === value ? 0 : -1}
      onclick={() => pick(tab.id)}
    >
      <span class="text">{tab.label}</span>
      {#if tab.count !== undefined}<span class="count">{tab.count}</span>{/if}
    </button>
  {/each}
</div>

<style>
  .tabs { display: flex; align-items: stretch; min-width: 0; overflow: hidden; }
  .tabs:focus { outline: none; }
  .tab {
    position: relative;
    flex: none;
    display: inline-flex;
    align-items: center;
    gap: var(--s1);
    padding: 0 var(--s2);
    color: var(--tx-mid);
    font: var(--w-label) var(--fs-label)/var(--lh-label) var(--font-label);
    letter-spacing: var(--tr-label);
    text-transform: uppercase;
    cursor: pointer;
    transition: color var(--t-fast) var(--ease);
  }
  .tab:hover, .tab.active { color: var(--tx-hi); }
  .tab.active::after {
    content: '';
    position: absolute;
    left: 0;
    right: 0;
    bottom: 0;
    z-index: 1;
    height: var(--s0);
    background: var(--red-500);
  }
  .text { max-width: var(--col-log-tag); overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }
  .count {
    color: var(--tx-lo);
    font: var(--w-body) var(--fs-micro)/var(--lh-micro) var(--font-mono);
    font-variant-numeric: tabular-nums lining-nums;
  }
</style>
