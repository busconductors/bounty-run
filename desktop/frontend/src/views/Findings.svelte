<script>
  // The Findings view bound to the real backend, for the run picked in Runs.
  import { findingsApi, reportsApi } from '../lib/bridge/api.js';
  import FindingsScreen from '../lib/runs/FindingsScreen.svelte';
  import ReportFrame from '../lib/reports/ReportFrame.svelte';

  let { run = null } = $props();
</script>

<section class="view" data-view="findings-view">
  <FindingsScreen dir={run?.dir ?? ''} api={findingsApi}>
    {#snippet report()}<ReportFrame dir={run?.dir ?? ''} api={reportsApi} />{/snippet}
  </FindingsScreen>
</section>

<style>
  .view { height: 100%; overflow: hidden; background: var(--bg-1); }
</style>
