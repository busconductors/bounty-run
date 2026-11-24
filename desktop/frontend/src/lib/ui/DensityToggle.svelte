<script>
  // Instrument-tier row density: comfortable (26px rows) or compact (24px).
  let { value = $bindable('comfortable') } = $props();
  const OPTIONS = [
    { id: 'comfortable', label: 'Comfortable' },
    { id: 'compact', label: 'Compact' },
  ];
</script>

<div class="density" role="group" aria-label="Row density">
  {#each OPTIONS as option (option.id)}
    <button
      type="button"
      class:active={value === option.id}
      aria-pressed={value === option.id}
      onclick={() => (value = option.id)}
    >{option.label}</button>
  {/each}
</div>

<style>
  .density {
    align-self: center;
    display: flex;
    flex: none;
    height: var(--ctl-h-sm);
    border: 1px solid var(--line-2);
    border-radius: var(--radius-ctl);
  }
  button {
    padding: 0 var(--s2);
    color: var(--tx-lo);
    font: var(--w-label) var(--fs-micro)/var(--lh-micro) var(--font-label);
    letter-spacing: var(--tr-micro);
    text-transform: uppercase;
    cursor: pointer;
    transition: background-color var(--t-fast) var(--ease), color var(--t-fast) var(--ease);
  }
  button + button { border-left: 1px solid var(--line-2); }
  button:hover { color: var(--tx-hi); }
  button.active { background: var(--red-tint); color: var(--tx-hi); }
</style>
