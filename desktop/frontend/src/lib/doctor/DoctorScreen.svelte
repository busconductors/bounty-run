<script>
  // The toolchain report with a re-check. api: { report, recheck }.
  import Button from '../ui/Button.svelte';
  import DoctorTable from './DoctorTable.svelte';

  let { api } = $props();

  let report = $state(null);
  let error = $state('');
  let busy = $state(true);
  let seq = 0; // only the latest request may land

  const messageOf = (e) => e?.cause?.message ?? e?.message ?? String(e);

  async function run(fn) {
    const mine = ++seq;
    busy = true;
    try {
      const next = await fn();
      if (mine !== seq) return;
      report = next;
      error = '';
    } catch (e) {
      if (mine !== seq) return;
      error = messageOf(e);
    } finally {
      if (mine === seq) busy = false;
    }
  }

  run(() => api.report());
</script>

<div class="screen">
  <header class="bar">
    <span class="summary">
      {#if report && report.missing > 0}{report.missing} {report.missing === 1 ? 'tool' : 'tools'} missing
      {:else if report}All tools present
      {:else if busy}Checking tools…{/if}
    </span>
    <Button variant="primary" disabled={busy} onclick={() => run(() => api.recheck())}>Re-check</Button>
  </header>
  {#if error}<p class="error" role="alert">Tool check failed: {error}</p>{/if}
  {#if report}<DoctorTable rows={report.rows ?? []} />{/if}
</div>

<style>
  .screen { padding: var(--s4); }
  .bar { display: flex; align-items: center; justify-content: space-between; margin-bottom: var(--s4); color: var(--tx-mid); }
  .error { color: var(--st-failed); }
</style>
