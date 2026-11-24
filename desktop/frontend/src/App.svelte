<script>
  import AppShell from './lib/shell/AppShell.svelte';
  import PlaceholderView from './lib/views/PlaceholderView.svelte';
  import { DEFAULT_VIEW, VIEWS } from './lib/shell/views.js';
  import Launch from './views/Launch.svelte';
  import Monitor from './views/Monitor.svelte';
  import Doctor from './views/Doctor.svelte';

  let active = $state(DEFAULT_VIEW);
  // The run Monitor follows: the last one launched, or one picked there.
  let run = $state(null);
  const view = $derived(VIEWS.find((candidate) => candidate.id === active));

  function launched(ref) {
    run = ref;
    active = 'monitor';
  }
</script>

<AppShell bind:active>
  {#key view.id}
    {#if view.id === 'launch'}
      <Launch onlaunched={launched} />
    {:else if view.id === 'monitor'}
      <Monitor {run} onselect={(ref) => (run = ref)} />
    {:else if view.id === 'doctor'}
      <Doctor />
    {:else}
      <PlaceholderView title={view.label} />
    {/if}
  {/key}
</AppShell>
