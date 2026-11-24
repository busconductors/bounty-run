<script>
  import NavRail from './NavRail.svelte';
  import StatusBar from './StatusBar.svelte';
  import TitleBar from './TitleBar.svelte';

  let { active = $bindable(), children } = $props();
</script>

<div class="shell">
  <div class="title"><TitleBar /></div>
  <NavRail bind:active />
  <main>{@render children()}</main>
  <div class="status"><StatusBar /></div>
</div>

<style>
  .shell {
    display: grid;
    grid-template-columns: var(--rail-w) minmax(0, 1fr);
    grid-template-rows: var(--titlebar-h) minmax(0, 1fr) var(--status-h);
    height: 100%;
  }
  .title, .status { grid-column: 1 / -1; min-width: 0; }
  main { min-width: 0; min-height: 0; }
</style>
