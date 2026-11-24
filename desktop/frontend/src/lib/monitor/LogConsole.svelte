<script>
  // The event/output console: dim timestamp, 10-char stage tag, level token,
  // message. Lines are sanitized by the store and rendered as text. Only the
  // rows in view are in the DOM. It follows the tail until the user scrolls
  // up; then it holds still and counts the lines that arrive meanwhile.
  import { tick } from 'svelte';
  import Tabs from '../ui/Tabs.svelte';
  import { firstAfter, px, rowHeight, visibleRange } from '../ui/virtual.js';
  import { NEW_LINES_GLYPH } from './glyphs.js';
  import { clock, grouped } from './text.js';

  let { lines, rev = 0, tools = [], capped = false, evicted = 0 } = $props();

  let tool = $state('all');
  let scroller = $state(null);
  let scrollTop = $state(0);
  let viewH = $state(0);
  let rowH = $state(0);
  let locked = $state(false);
  let seenSeq = $state(0);

  const tabs = $derived((void rev, [{ id: 'all', label: 'All' }, ...tools.map((t) => ({ id: t, label: t }))]));

  // A fresh object per batch: lines is mutated in place, so rev is what
  // signals a change.
  const view = $derived.by(() => {
    void rev;
    const list = tool === 'all' ? lines : lines.filter((line) => line.tool === tool || line.notice);
    return { list };
  });

  const range = $derived(visibleRange({ count: view.list.length, rowH, scrollTop, viewH }));
  const slice = $derived(view.list.slice(range.start, range.end));
  const fresh = $derived(locked ? view.list.length - firstAfter(view.list, seenSeq) : 0);

  const tag = (text) => (text.length > 10 ? text.slice(0, 10) : text);

  function measure() {
    if (!scroller) return;
    viewH = scroller.clientHeight;
    const h = rowHeight(scroller, '[data-log-line]');
    if (h > 0) rowH = h;
  }

  function toBottom() {
    if (!scroller) return;
    scroller.scrollTop = scroller.scrollHeight;
    scrollTop = scroller.scrollTop;
  }

  function onscroll() {
    scrollTop = scroller.scrollTop;
    const slack = Math.max(rowH, 4);
    const atBottom = scroller.scrollTop + scroller.clientHeight >= scroller.scrollHeight - slack;
    if (atBottom) {
      locked = false;
    } else if (!locked) {
      locked = true;
      seenSeq = view.list.at(-1)?.seq ?? 0;
    }
  }

  async function jump() {
    locked = false;
    await tick();
    toBottom();
  }

  // After each batch: measure, then follow the tail unless locked.
  $effect(() => {
    void view;
    measure();
    if (!locked) toBottom();
  });

  $effect(() => {
    if (!scroller || typeof ResizeObserver === 'undefined') return;
    const observer = new ResizeObserver(() => {
      measure();
      if (!locked) toBottom();
    });
    observer.observe(scroller);
    return () => observer.disconnect();
  });
</script>

<section class="pane log" aria-label="Log">
  <div class="pane-head">
    <h2 class="pane-title">Log</h2>
    <Tabs {tabs} bind:value={tool} label="Filter by tool" />
    {#if fresh > 0}
      <button type="button" class="new-lines" onclick={jump}>
        <svg viewBox="0 0 16 16" aria-hidden="true"><path d={NEW_LINES_GLYPH} /></svg>{grouped(fresh)} new
      </button>
    {/if}
    <span class="pane-spacer"></span>
    {#if capped}
      <span class="notice" title="The engine stopped recording some tool output in events; engine.log and the tool's output files have the rest.">Output capped</span>
    {/if}
    {#if evicted > 0}
      <span class="notice" title="The console keeps the newest lines only.">{grouped(evicted)} oldest trimmed</span>
    {/if}
  </div>
  <div class="scroll" bind:this={scroller} {onscroll} data-log-scroll>
    <div class="space" use:px={['height', rowH > 0 ? view.list.length * rowH : null]}>
      <div class="rows" use:px={['top', rowH > 0 ? range.start * rowH : null]}>
        {#each slice as line (line.seq)}
          <div class="line lv-{line.level.toLowerCase()}" class:notice-line={line.notice} data-log-line>
            <span class="ts">{clock(line.t)}</span>
            <span class="tag">{tag(line.tag)}</span>
            <span class="lv">{line.level}</span>
            <span class="msg">{line.text}</span>
          </div>
        {/each}
      </div>
    </div>
    {#if view.list.length === 0}
      <p class="empty">No output yet.</p>
    {/if}
  </div>
</section>

<style>
  .log { height: 100%; background: var(--bg-0); }
  .log .pane-head { background: var(--bg-0); }
  .scroll { flex: 1; min-height: 0; overflow: auto; }
  .space { position: relative; }
  .rows { position: relative; }
  .line {
    display: grid;
    grid-template-columns: var(--col-log-ts) var(--col-log-tag) var(--col-log-level) minmax(0, 1fr);
    height: var(--log-line-h);
    padding: 0 var(--s3);
    font: var(--w-body) var(--fs-mono)/var(--lh-mono) var(--font-mono);
    font-variant-numeric: tabular-nums lining-nums;
    white-space: pre;
    user-select: text;
  }
  .line > span { overflow: hidden; text-overflow: ellipsis; }
  .ts { color: var(--tx-lo); }
  .tag { color: var(--tx-mid); }
  .lv { color: var(--tx-lo); }
  .msg { color: var(--tx); }
  .lv-err .lv, .lv-err .msg { color: var(--st-failed); }
  .lv-warn .lv { color: var(--sev-medium); }
  .notice-line .msg, .notice-line .lv { color: var(--tx-hi); }
  .empty { margin: 0; padding: var(--s3); color: var(--tx-lo); }
  .notice {
    align-self: center;
    color: var(--sev-medium);
    font: var(--w-label) var(--fs-micro)/var(--lh-micro) var(--font-label);
    letter-spacing: var(--tr-micro);
    text-transform: uppercase;
  }
  .new-lines {
    align-self: center;
    display: inline-flex;
    align-items: center;
    gap: var(--s1);
    height: var(--chip-h);
    padding: 0 var(--s2);
    border: 1px solid var(--line-3);
    border-radius: var(--radius-ctl);
    color: var(--tx-hi);
    font: var(--w-label) var(--fs-micro)/var(--lh-micro) var(--font-label);
    letter-spacing: var(--tr-micro);
    text-transform: uppercase;
    cursor: pointer;
  }
  .new-lines:hover { background: var(--bg-3); }
  .new-lines svg { width: var(--icon-sm); height: var(--icon-sm); fill: currentColor; stroke: none; }
</style>
