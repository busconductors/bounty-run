<script>
  // The Runs view bound to the real backend: lists runs and refreshes when
  // the backend says the list changed.
  import { runsApi } from '../lib/bridge/api.js';
  import { onEvent } from '../lib/bridge/window.js';
  import RunsTable from '../lib/runs/RunsTable.svelte';
  import { sanitizeText } from '../lib/monitor/text.js';

  let { onopen } = $props();

  let runs = $state.raw([]);
  let error = $state('');

  $effect(() => {
    let live = true;
    const refresh = () =>
      Promise.resolve(runsApi.list())
        .then((list) => live && ((runs = Array.isArray(list) ? list : []), (error = '')))
        .catch((e) => live && (error = sanitizeText(e?.cause?.message ?? e?.message ?? e)));
    refresh();
    const off = onEvent('runs:changed', refresh);
    return () => {
      live = false;
      off?.();
    };
  });
</script>

<section class="view" data-view="runs">
  {#if error}<p class="error" role="alert">Could not list runs: {error}</p>{/if}
  <RunsTable {runs} {onopen} />
</section>

<style>
  .view { height: 100%; display: flex; flex-direction: column; overflow: hidden; background: var(--bg-1); }
  .view > :global(.runs) { flex: 1; }
  .error { margin: 0; padding: var(--s3); color: var(--st-failed); }
</style>
