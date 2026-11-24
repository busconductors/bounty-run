<script>
  // The Monitor view bound to the real backend: the runs API, the event bus
  // and the engine stage catalog. It drives the status bar while shown.
  import { onDestroy } from 'svelte';
  import { launchApi, runsApi } from '../lib/bridge/api.js';
  import { onEvent } from '../lib/bridge/window.js';
  import MonitorScreen from '../lib/monitor/MonitorScreen.svelte';
  import { setRunStatus } from '../lib/shell/status.svelte.js';

  let { run = null, onselect } = $props();

  onDestroy(() => setRunStatus(null));
</script>

<section class="view" data-view="monitor">
  <MonitorScreen {run} api={runsApi} stages={launchApi.stages} on={onEvent} {onselect} onstatus={setRunStatus} />
</section>

<style>
  .view { height: 100%; overflow: hidden; background: var(--bg-1); }
</style>
