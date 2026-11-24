<script>
  // One row per tool: status, version, path, what it affects and how to get it.
  let { rows } = $props();
  const LABEL = { ok: 'OK', missing: 'Missing', error: 'Error' };
</script>

<table class="table">
  <thead>
    <tr><th>Tool</th><th>Status</th><th>Version</th><th>Path</th><th>Affects</th><th>Guidance</th></tr>
  </thead>
  <tbody>
    {#each rows as row (row.name)}
      <tr data-tool={row.name} data-status={row.status}>
        <td class="name">{row.name}{#if row.optional}<span class="opt">optional</span>{/if}</td>
        <td><span class="status {row.status}">{LABEL[row.status] ?? row.status}</span></td>
        <td class="mono">{row.version}</td>
        <td class="mono path" title={row.path}>{row.path}</td>
        <td class="affects">{#each row.affects as id (id)}<span class="tag">{id}</span>{/each}</td>
        <td class="guide">{row.status === 'ok' ? '' : row.guidance}</td>
      </tr>
    {/each}
  </tbody>
</table>

<style>
  .table { width: 100%; border-collapse: collapse; font: var(--w-value) var(--fs-label)/var(--lh-label) var(--font-label); }
  th { text-align: left; padding: var(--s2) var(--s3); color: var(--tx-lo); text-transform: uppercase; letter-spacing: var(--tr-label); border-bottom: 1px solid var(--line-2); }
  td { padding: var(--s2) var(--s3); border-bottom: 1px solid var(--line-1); color: var(--tx); vertical-align: top; }
  .name { color: var(--tx-hi); }
  .opt { margin-left: var(--s2); color: var(--tx-lo); }
  .mono { font-family: var(--font-mono, monospace); }
  .path { overflow-wrap: anywhere; }
  .status.ok { color: var(--st-ok); }
  .status.missing { color: var(--sev-high); }
  .status.error { color: var(--st-failed); }
  .tag { display: inline-block; margin: 0 var(--s1) var(--s1) 0; padding: 0 var(--s2); border: 1px solid var(--line-2); color: var(--tx-mid); }
  .guide { color: var(--tx-mid); }
</style>
