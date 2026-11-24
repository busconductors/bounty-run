<script>
  // run: the { id, dir } of a just-launched run, shown until Monitor exists.
  let { title, run = null } = $props();
</script>

<section class="view" data-view={title.toLowerCase()}>
  <header><h1>{title}</h1></header>
  {#if run}
    <dl>
      <dt>Run</dt><dd>{run.id}</dd>
      <dt>Directory</dt><dd>{run.dir}</dd>
    </dl>
  {/if}
  <p>Not available yet.</p>
</section>

<style>
  .view { height: 100%; overflow: auto; background: var(--bg-1); }
  header { padding: var(--s4); border-bottom: 1px solid var(--line-1); }
  h1 { margin: 0; color: var(--tx-hi); font: var(--w-label) var(--fs-view)/var(--lh-view) var(--font-label); }
  p { margin: 0; padding: var(--s4); color: var(--tx-mid); }
  dl {
    display: grid;
    grid-template-columns: var(--col-meta-key) minmax(0, 1fr);
    gap: var(--s1) var(--s3);
    margin: 0;
    padding: var(--s4);
    border-bottom: 1px solid var(--line-1);
  }
  dt { color: var(--tx-mid); font: var(--w-label) var(--fs-label)/var(--lh-label) var(--font-label); letter-spacing: var(--tr-label); text-transform: uppercase; }
  dd { margin: 0; color: var(--tx); font: var(--w-body) var(--fs-mono)/var(--lh-mono) var(--font-mono); user-select: text; }
</style>
