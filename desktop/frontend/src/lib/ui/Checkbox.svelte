<script>
  // 12px square checkbox. A native input, so forms and assistive tech get the
  // real semantics; the box is styled in place.
  let { checked = $bindable(false), label, disabled = false, onchange = undefined } = $props();
</script>

<input
  type="checkbox"
  aria-label={label}
  bind:checked
  {disabled}
  onchange={() => onchange?.(checked)}
/>

<style>
  input {
    flex: none;
    width: var(--checkbox);
    height: var(--checkbox);
    margin: 0;
    padding: var(--s0);
    border: 1px solid var(--line-3);
    border-radius: var(--radius);
    background: var(--bg-0);
    background-clip: content-box;
    appearance: none;
    cursor: pointer;
    transition: background-color var(--t-fast) var(--ease), border-color var(--t-fast) var(--ease);
  }
  input:hover:not(:disabled) { border-color: var(--tx-lo); }
  input:checked { border-color: var(--tx-mid); background-color: var(--tx-hi); }
  input:disabled { border-color: var(--line-1); background-color: var(--bg-2); cursor: default; }
  input:checked:disabled { border-color: var(--line-3); background-color: var(--tx-off); }
</style>
