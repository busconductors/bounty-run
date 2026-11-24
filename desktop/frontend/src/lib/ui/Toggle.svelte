<script>
  // 28×14 rectangular switch with a square thumb; the track turns red when on.
  let { checked = $bindable(false), label, disabled = false, onchange = undefined } = $props();

  function toggle() {
    checked = !checked;
    onchange?.(checked);
  }
</script>

<button type="button" class="toggle" role="switch" aria-checked={checked} {disabled} onclick={toggle}>
  <span class="track" class:on={checked} aria-hidden="true"><span class="thumb"></span></span>
  <span class="label">{label}</span>
</button>

<style>
  .toggle {
    display: inline-flex;
    align-items: center;
    gap: var(--s2);
    min-height: var(--ctl-h-sm);
    color: var(--tx);
    cursor: pointer;
  }
  .toggle:disabled { color: var(--tx-off); cursor: default; }
  .track {
    display: flex;
    flex: none;
    align-items: center;
    width: var(--toggle-w);
    height: var(--toggle-h);
    padding: 0 1px;
    border: 1px solid var(--line-3);
    border-radius: var(--radius-ctl);
    background: var(--bg-0);
    transition: background-color var(--t-fast) var(--ease), border-color var(--t-fast) var(--ease);
  }
  .thumb { width: var(--toggle-thumb); height: var(--toggle-thumb); background: var(--tx-mid); }
  .track.on { justify-content: flex-end; border-color: var(--red-500); background: var(--red-500); }
  .track.on .thumb { background: var(--bg-0); }
  .toggle:hover:not(:disabled) .track { border-color: var(--tx-lo); }
  .toggle:hover:not(:disabled) .track.on { border-color: var(--red-400); background: var(--red-400); }
</style>
