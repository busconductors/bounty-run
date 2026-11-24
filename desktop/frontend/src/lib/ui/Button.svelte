<script>
  // variant: primary (the one red fill per view), ghost (default) or danger.
  // The chamfer is clipped on the face, so the focus ring sits on the
  // unclipped wrapper (UI spec: :has(:focus-visible)).
  let { variant = 'ghost', type = 'button', disabled = false, title = undefined, onclick = undefined, children } = $props();
</script>

<span class="button {variant}" class:disabled>
  <button class="face" {type} {disabled} {title} {onclick}>{@render children()}</button>
</span>

<style>
  .button { display: inline-flex; flex: none; }
  .button:has(.face:focus-visible) { outline: 1px solid var(--red-400); outline-offset: 2px; }
  .face {
    position: relative;
    isolation: isolate;
    display: inline-flex;
    align-items: center;
    gap: var(--s2);
    height: var(--ctl-h);
    padding: 0 var(--s4);
    clip-path: var(--chamfer);
    font: var(--w-value) var(--fs-label)/var(--lh-label) var(--font-label);
    letter-spacing: var(--tr-label);
    text-transform: uppercase;
    white-space: nowrap;
    cursor: pointer;
    transition: background-color var(--t-fast) var(--ease), color var(--t-fast) var(--ease);
  }
  .face:focus-visible { outline: none; }
  .face:disabled { cursor: default; }

  .primary .face { background: var(--red-500); color: var(--bg-0); font-weight: var(--w-label); }
  .primary .face:hover:not(:disabled) { background: var(--red-400); }
  .primary .face:active:not(:disabled) { background: var(--red-600); }
  .primary .face:disabled { background: var(--bg-4); color: var(--tx-off); }

  /* Ghost and danger: a 1px outline that follows the chamfer, drawn as the
     face's fill showing around an inset ::before of the surface colour. */
  .ghost .face, .danger .face { background: var(--line-2); color: var(--tx); }
  .ghost .face::before, .danger .face::before {
    content: '';
    position: absolute;
    inset: 1px;
    z-index: -1;
    background: var(--bg-1);
    clip-path: var(--chamfer);
    transition: background-color var(--t-fast) var(--ease);
  }
  .ghost .face:hover:not(:disabled) { background: var(--line-3); color: var(--tx-hi); }
  .ghost .face:hover:not(:disabled)::before { background: var(--bg-3); }
  .danger .face { background: var(--red-300); color: var(--red-300); }
  .danger .face:hover:not(:disabled)::before { background: var(--bg-3); }
  .ghost .face:disabled, .danger .face:disabled { background: var(--line-1); color: var(--tx-off); }
</style>
