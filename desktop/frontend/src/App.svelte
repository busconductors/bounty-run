<script>
  import AppShell from './lib/shell/AppShell.svelte';
  import PlaceholderView from './lib/views/PlaceholderView.svelte';
  import { DEFAULT_VIEW, VIEWS } from './lib/shell/views.js';
  import Launch from './views/Launch.svelte';
  import Monitor from './views/Monitor.svelte';
  import Doctor from './views/Doctor.svelte';
  import Runs from './views/Runs.svelte';
  import Findings from './views/Findings.svelte';

  let active = $state(DEFAULT_VIEW);
  // The run Monitor follows: the last one launched, or one picked there.
  let run = $state(null);
  // The finished run Findings shows: the one picked in Runs.
  let findingsRun = $state(null);
  const view = $derived(VIEWS.find((candidate) => candidate.id === active));

  function launched(ref) {
    run = ref;
    active = 'monitor';
  }

  // A running run opens in Monitor; a finished one opens its findings.
  function opened(r) {
    const ref = { id: '', dir: r.Info.Dir };
    if (r.Status === 'running') {
      run = ref;
      active = 'monitor';
    } else {
      findingsRun = ref;
      active = 'findings';
    }
  }
</script>

<AppShell bind:active>
  {#key view.id}
    {#if view.id === 'launch'}
      <Launch onlaunched={launched} />
    {:else if view.id === 'monitor'}
      <Monitor {run} onselect={(ref) => (run = ref)} />
    {:else if view.id === 'runs'}
      <Runs onopen={opened} />
    {:else if view.id === 'findings'}
      <Findings run={findingsRun} />
    {:else if view.id === 'doctor'}
      <Doctor />
    {:else}
      <PlaceholderView title={view.label} />
    {/if}
  {/key}
</AppShell>
