<script>
  import AppShell from './lib/shell/AppShell.svelte';
  import PlaceholderView from './lib/views/PlaceholderView.svelte';
  import { DEFAULT_VIEW, VIEWS } from './lib/shell/views.js';

  let active = $state(DEFAULT_VIEW);
  const view = $derived(VIEWS.find((candidate) => candidate.id === active));
</script>

<AppShell bind:active>
  {#key view.id}
    <PlaceholderView title={view.label} />
  {/key}
</AppShell>
