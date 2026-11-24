<script>
  // The exact command the launch spawns (from catalog Preview, which uses the
  // same builder as StartRun). Read-only; secrets are never in it, only the
  // names of the environment variables that carry them.
  import { shellQuote } from './model.svelte.js';

  let { argv = [], envNames = [], runDir = '' } = $props();
</script>

<div class="preview">
  <pre class="argv">{argv.map(shellQuote).join(' ')}</pre>
  {#if envNames.length}
    <p class="env">
      <span class="key">env</span>
      {#each envNames as name, i (i)}<span class="name">{name}</span>{/each}
      <span class="hint">values hidden</span>
    </p>
  {/if}
  {#if runDir}
    <p class="env"><span class="key">run dir</span><span class="name">{runDir}</span><span class="hint">stamp set at launch</span></p>
  {/if}
</div>

<style>
  .preview { border: 1px solid var(--line-2); border-radius: var(--radius-ctl); background: var(--bg-0); }
  .argv {
    margin: 0;
    padding: var(--s3);
    color: var(--tx);
    font: var(--w-body) var(--fs-mono)/var(--lh-mono) var(--font-mono);
    white-space: pre-wrap;
    word-break: break-all;
    user-select: text;
  }
  .env {
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: var(--s2);
    margin: 0;
    padding: var(--s1) var(--s3);
    border-top: 1px solid var(--line-1);
    font: var(--w-body) var(--fs-mono)/var(--lh-mono) var(--font-mono);
  }
  .key { color: var(--tx-mid); font: var(--w-label) var(--fs-micro)/var(--lh-micro) var(--font-label); letter-spacing: var(--tr-micro); text-transform: uppercase; }
  .name { color: var(--tx); user-select: text; }
  .hint { color: var(--tx-lo); }
</style>
