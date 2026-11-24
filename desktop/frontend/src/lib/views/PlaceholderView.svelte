<script>
  let { title } = $props();
</script>

<section class="view" data-view={title.toLowerCase()}>
  <header><h1>{title}</h1></header>
  <p>Not available yet.</p>
</section>

<style>
  .view { height: 100%; overflow: auto; background: var(--bg-1); }
  header { padding: var(--s4); border-bottom: 1px solid var(--line-1); }
  h1 { margin: 0; color: var(--tx-hi); font: var(--w-label) var(--fs-view)/var(--lh-view) var(--font-label); }
  p { margin: 0; padding: var(--s4); color: var(--tx-mid); }
</style>
