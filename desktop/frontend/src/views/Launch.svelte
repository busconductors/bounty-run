<script>
  // The Launch view: the form bound to the real backend. Form values live in
  // a module-level object so they survive switching views for this session
  // (and nowhere else: never storage, never disk).
  import { launchApi } from '../lib/bridge/api.js';
  import LaunchForm from '../lib/launch/LaunchForm.svelte';
  import { sessionForm } from '../lib/launch/session.svelte.js';

  let { onlaunched } = $props();
</script>

<section class="view" data-view="launch">
  <LaunchForm api={launchApi} form={sessionForm} {onlaunched} />
</section>

<style>
  .view { height: 100%; overflow: auto; background: var(--bg-1); }
</style>
