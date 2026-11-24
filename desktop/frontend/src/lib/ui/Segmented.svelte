<script>
  // A square segmented control (radio group). options: [{ id, label, glyph? }].
  let { options, value = $bindable(), label, onchange = undefined } = $props();

  function pick(id) {
    if (id === value) return;
    value = id;
    onchange?.(id);
  }

  function onkeydown(event) {
    const step = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[event.key];
    if (!step) return;
    event.preventDefault();
    const at = options.findIndex((o) => o.id === value);
    const next = options[(at + step + options.length) % options.length];
    pick(next.id);
    event.currentTarget.querySelector(`[data-id="${next.id}"]`)?.focus();
  }
</script>

<div class="segmented" role="radiogroup" aria-label={label} tabindex="-1" {onkeydown}>
  {#each options as option (option.id)}
    <button
      type="button"
      role="radio"
      aria-checked={option.id === value}
      tabindex={option.id === value ? 0 : -1}
      data-id={option.id}
      class:active={option.id === value}
      onclick={() => pick(option.id)}
    >
      {#if option.glyph}<span class="glyph" aria-hidden="true">{option.glyph}</span>{/if}
      {option.label}
    </button>
  {/each}
</div>

<style>
  .segmented {
    display: inline-flex;
    height: var(--ctl-h);
    border: 1px solid var(--line-2);
    border-radius: var(--radius-ctl);
    background: var(--bg-0);
  }
  .segmented:focus { outline: none; }
  button {
    display: inline-flex;
    align-items: center;
    gap: var(--s1);
    padding: 0 var(--s3);
    color: var(--tx-mid);
    font: var(--w-label) var(--fs-label)/var(--lh-label) var(--font-label);
    letter-spacing: var(--tr-label);
    text-transform: uppercase;
    transition: background-color var(--t-fast) var(--ease), color var(--t-fast) var(--ease);
  }
  button + button { border-left: 1px solid var(--line-1); }
  button:hover { background: var(--bg-3); color: var(--tx-hi); }
  button.active { background: var(--red-tint); color: var(--tx-hi); }
  .glyph { font: var(--w-body) var(--fs-mono)/var(--lh-label) var(--font-mono); }
</style>
