<script>
  // 40px run context: target · run stamp · ceiling · stage mini-track, then the
  // run controls. Skip and STOP open a y/n prompt (keys y / n, like the TUI);
  // HARD KILL appears only once a sent command went unacknowledged.
  import Button from '../ui/Button.svelte';
  import { STOP_GLYPH } from './glyphs.js';
  import StageTrack from './StageTrack.svelte';

  let {
    target = '',
    stamp = '',
    ceiling = '',
    rows = [],
    live = false,
    phase = '',
    controllable = false,
    skippable = '',
    confirm = null,
    pending = null,
    hardKillOffered = false,
    error = '',
    onskip,
    onstop,
    onanswer,
    onhardkill,
  } = $props();

  const waiting = $derived(
    pending ? (pending.kind === 'skip' ? `skip ${pending.stage} sent, waiting for the engine` : 'cancel sent, waiting for the engine') : '',
  );
</script>

<header class="context" aria-label="Run">
  <span class="target mono data">{target || '—'}</span>
  {#if stamp}<span class="meta mono data">{stamp}</span>{/if}
  {#if ceiling}<span class="sep" aria-hidden="true">/</span><span class="label">Ceiling {ceiling}</span>{/if}
  <StageTrack {rows} {live} />
  {#if phase}<span class="label phase">{phase}</span>{/if}
  <span class="spacer"></span>

  {#if confirm}
    <span class="prompt" role="alert">
      <span class="question">{confirm.kind === 'skip' ? `Skip stage ${confirm.stage}?` : 'Cancel this run?'}</span>
      <kbd>y/n</kbd>
    </span>
    <Button onclick={() => onanswer(true)}>Yes</Button>
    <Button onclick={() => onanswer(false)}>No</Button>
  {:else}
    {#if error}<span class="error data" role="status">{error}</span>{/if}
    {#if hardKillOffered}
      <span class="warn" role="status">Engine not responding</span>
      <Button variant="danger" onclick={onhardkill} title="SIGKILL the engine and its tools (K)">Hard kill</Button>
    {:else if waiting}
      <span class="note" role="status">{waiting}</span>
    {/if}
    {#if controllable && skippable}
      <Button onclick={onskip} title="Skip the running stage (s)">Skip {skippable}</Button>
    {/if}
    <Button variant="danger" disabled={!controllable} onclick={onstop} title="Cancel the run (c)">
      <svg viewBox="0 0 16 16" aria-hidden="true"><path d={STOP_GLYPH} /></svg>Stop
    </Button>
  {/if}
</header>

<style>
  .context {
    display: flex;
    align-items: center;
    gap: var(--s4);
    height: var(--context-h);
    padding: 0 var(--s3);
    overflow: hidden;
    border-bottom: 1px solid var(--line-1);
    background: var(--bg-2);
    white-space: nowrap;
  }
  .mono { font: var(--w-body) var(--fs-mono)/var(--lh-mono) var(--font-mono); }
  .data { user-select: text; }
  .target { min-width: 0; max-width: var(--col-host); overflow: hidden; text-overflow: ellipsis; color: var(--tx-hi); }
  .meta { color: var(--tx-mid); font-variant-numeric: tabular-nums lining-nums; }
  .sep { color: var(--tx-off); }
  .label, .prompt, .warn, .note {
    font: var(--w-label) var(--fs-label)/var(--lh-label) var(--font-label);
    letter-spacing: var(--tr-label);
    text-transform: uppercase;
    color: var(--tx-mid);
  }
  .phase { color: var(--tx-hi); }
  .spacer { flex: 1; }
  .prompt { display: inline-flex; align-items: center; gap: var(--s2); color: var(--tx-hi); }
  kbd { padding: 0 var(--s1); border: 1px solid var(--line-3); border-radius: var(--radius-ctl); font: var(--w-body) var(--fs-mono)/var(--lh-mono) var(--font-mono); color: var(--tx); }
  .warn { color: var(--red-300); }
  .note { color: var(--tx-mid); text-transform: none; letter-spacing: 0; font-family: var(--font-body); font-weight: var(--w-body); }
  .error { min-width: 0; overflow: hidden; text-overflow: ellipsis; color: var(--red-300); }
  svg { width: var(--icon-sm); height: var(--icon-sm); fill: currentColor; stroke: none; }
</style>
