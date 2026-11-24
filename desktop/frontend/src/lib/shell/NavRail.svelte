<script>
  import { VIEWS } from './views.js';

  let { active = $bindable() } = $props();
</script>

<nav aria-label="Primary">
  {#each VIEWS as view (view.id)}
    <button
      type="button"
      class:active={active === view.id}
      aria-label={view.label}
      aria-current={active === view.id ? 'page' : undefined}
      title={view.label}
      data-nav={view.id}
      onclick={() => (active = view.id)}
    >
      <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" aria-hidden="true">
        <path d={view.icon} />
      </svg>
    </button>
  {/each}
</nav>

<style>
  nav { display: flex; flex-direction: column; min-height: 0; background: var(--bg-0); border-right: 1px solid var(--line-1); }
  button {
    position: relative;
    display: grid;
    flex: none;
    place-items: center;
    width: 100%;
    height: var(--rail-w);
    color: var(--tx-lo);
    transition: background-color var(--t-fast) var(--ease), color var(--t-fast) var(--ease);
  }
  button:hover { background: var(--bg-3); color: var(--tx-hi); }
  button:focus-visible { z-index: 1; }
  button.active { background: var(--red-tint); color: var(--red-400); }
  button.active::before { content: ''; position: absolute; inset: 0 auto 0 0; width: var(--s0); background: var(--red-500); }
  svg { width: var(--icon); height: var(--icon); stroke-width: 1.5; stroke-linecap: square; stroke-linejoin: miter; }
</style>
