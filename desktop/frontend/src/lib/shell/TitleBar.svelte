<script>
  import { close, minimise, toggleMaximise } from '../bridge/window.js';
</script>

<header>
  <span class="brand">BOUNTY RUN</span>
  <div class="controls">
    <button type="button" aria-label="Minimise" title="Minimise" onclick={minimise}>
      <svg viewBox="0 0 12 12" fill="none" stroke="currentColor" aria-hidden="true"><path d="M2 6h8" /></svg>
    </button>
    <button type="button" aria-label="Maximise" title="Maximise" onclick={toggleMaximise}>
      <svg viewBox="0 0 12 12" fill="none" stroke="currentColor" aria-hidden="true"><path d="M2.5 2.5h7v7h-7Z" /></svg>
    </button>
    <button type="button" class="close" aria-label="Close" title="Close" onclick={close}>
      <svg viewBox="0 0 12 12" fill="none" stroke="currentColor" aria-hidden="true"><path d="M2.5 2.5l7 7M9.5 2.5l-7 7" /></svg>
    </button>
  </div>
</header>

<style>
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    height: 100%;
    background: var(--bg-0);
    border-bottom: 1px solid var(--line-1);
    --wails-draggable: drag;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: var(--s2);
    padding-left: var(--s3);
    color: var(--tx-hi);
    font: var(--w-label) var(--fs-label)/var(--lh-label) var(--font-label);
    letter-spacing: var(--tr-micro);
  }
  .brand::before { content: ''; width: var(--brand-bar-w); height: var(--brand-bar-h); background: var(--red-500); }
  .controls { display: flex; --wails-draggable: no-drag; }
  button {
    display: grid;
    place-items: center;
    width: var(--winctl-w);
    height: var(--titlebar-h);
    color: var(--tx-mid);
    transition: background-color var(--t-fast) var(--ease), color var(--t-fast) var(--ease);
  }
  button:hover { background: var(--bg-3); color: var(--tx-hi); }
  .close:hover { background: var(--red-500); color: var(--bg-0); }
  svg { width: var(--icon-sm); height: var(--icon-sm); stroke-width: 1.5; stroke-linecap: square; stroke-linejoin: miter; }
</style>
