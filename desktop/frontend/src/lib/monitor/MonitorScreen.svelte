<script>
  // The live Monitor: context bar over a three-pane split (stages | findings
  // + log | inspector). It attaches to `run` through `api` (runsApi) and the
  // `on` event subscriber, and detaches when the run dies or the view goes.
  // Without a run it lists the runs on disk to pick from.
  import { untrack } from 'svelte';
  import ContextBar from './ContextBar.svelte';
  import FindingsTable from './FindingsTable.svelte';
  import Inspector from './Inspector.svelte';
  import LogConsole from './LogConsole.svelte';
  import StageList from './StageList.svelte';
  import { MonitorSession, stageRows } from './store.svelte.js';
  import { elapsed, sanitizeText } from './text.js';

  let { run = null, api, stages = async () => [], on, onselect = () => {}, onstatus = () => {} } = $props();

  // The session lives as long as the view; api and on are fixed per mount.
  // svelte-ignore state_referenced_locally
  const session = new MonitorSession({ api, on });
  let catalog = $state.raw([]);
  let density = $state('comfortable');
  let selected = $state(0);
  let runs = $state.raw([]);
  let listError = $state('');

  $effect(() => {
    let live = true;
    Promise.resolve()
      .then(() => stages())
      .then((list) => live && (catalog = Array.isArray(list) ? list : []))
      .catch(() => {}); // stages then group under 'other'
    return () => (live = false);
  });

  $effect(() => {
    const ref = run;
    if (!ref?.dir) return;
    untrack(() => {
      selected = 0;
      session.open({ id: ref.id ?? '', dir: ref.dir });
    });
    return () => session.close();
  });

  // The run picker, refreshed whenever the backend says the list changed.
  $effect(() => {
    if (run?.dir) return;
    let live = true;
    const refresh = () =>
      Promise.resolve(api.list())
        .then((list) => live && ((runs = Array.isArray(list) ? list : []), (listError = '')))
        .catch((error) => live && (listError = sanitizeText(error?.message ?? error)));
    refresh();
    const off = on('runs:changed', refresh);
    return () => {
      live = false;
      off?.();
    };
  });

  const rows = $derived((void session.rev, stageRows(session.run, catalog)));
  const live = $derived((void session.rev, session.attached && !session.dead && !session.killed && !session.run.ended));
  // run is mutated in place; rev is what says it changed.
  const view = $derived.by(() => {
    void session.rev;
    return {
      target: session.run.target,
      controllable: session.controllable,
      skippable: session.skippable,
      capped: session.run.capped,
      evicted: session.run.logEvicted,
    };
  });
  const finding = $derived((void session.rev, session.run.findings.find((f) => f.seq === selected) ?? null));
  const stamp = $derived(run?.dir ? run.dir.split(/[\\/]/).filter(Boolean).at(-1) : '');
  const ceiling = $derived.by(() => {
    void session.rev;
    const value = session.run.flags?.intensity;
    return typeof value === 'string' ? sanitizeText(value) : '';
  });

  const phase = $derived.by(() => {
    void session.rev;
    if (session.killed) return 'killed';
    if (session.dead) return session.run.endStatus || session.dead.status;
    if (session.run.ended) return session.run.endStatus || 'ended';
    if (session.error && !session.attached) return 'error';
    if (session.attached) return session.run.startT ? 'live' : 'attaching';
    return '';
  });

  // Status bar telemetry.
  $effect(() => {
    void session.rev;
    const top = rows.filter((row) => row.level === 1);
    const started = top.filter((row) => row.status !== 'queued').length;
    const { startT, lastT } = session.run;
    const end = live ? session.now : lastT;
    onstatus({
      live,
      label: phase,
      stage: top.length ? `${String(started).padStart(2, '0')}/${String(top.length).padStart(2, '0')}` : '',
      elapsed: startT ? elapsed(Math.max(0, end - startT)) : '',
      rate: live ? session.rate : null,
      counts: { ...session.run.sevCounts },
    });
  });

  function onkeydown(event) {
    if (!run?.dir || event.defaultPrevented || event.ctrlKey || event.metaKey || event.altKey) return;
    if (event.target?.closest?.('input, textarea, select, [contenteditable="true"]')) return;
    if (['Shift', 'Control', 'Alt', 'Meta', 'CapsLock'].includes(event.key)) return;
    if (session.confirm) {
      event.preventDefault();
      session.answer(event.key === 'y' || event.key === 'Y');
      return;
    }
    switch (event.key) {
      case 's':
        session.requestSkip();
        break;
      case 'c':
        session.requestCancel();
        break;
      case 'K':
        session.hardKill();
        break;
      case 'Escape':
        selected = 0;
        break;
      default:
        return;
    }
    event.preventDefault();
  }

  const runLabel = (r) => sanitizeText(r?.Info?.Target) || '(unknown target)';
  const runStamp = (r) => sanitizeText(String(r?.Info?.Dir ?? '').split(/[\\/]/).filter(Boolean).at(-1) ?? '');
  const runElapsed = (r) => (Number.isFinite(r?.Elapsed) ? elapsed(r.Elapsed / 1e6) : '');
</script>

<svelte:window {onkeydown} />

{#if run?.dir}
  <div class="monitor" class:compact={density === 'compact'} data-view="monitor">
    <ContextBar
      target={view.target}
      {stamp}
      {ceiling}
      {rows}
      {live}
      {phase}
      controllable={view.controllable}
      skippable={view.skippable}
      confirm={session.confirm}
      pending={session.pending}
      hardKillOffered={session.hardKillOffered}
      error={session.error}
      onskip={() => session.requestSkip()}
      onstop={() => session.requestCancel()}
      onanswer={(yes) => session.answer(yes)}
      onhardkill={() => session.hardKill()}
    />
    <div class="panes">
      <div class="stages"><StageList {rows} {live} now={session.now} /></div>
      <div class="findings">
        <FindingsTable
          findings={session.run.findings}
          counts={session.run.sevCounts}
          rev={session.rev}
          {selected}
          onselect={(seq) => (selected = seq)}
          bind:density
        />
      </div>
      <div class="inspector">
        <Inspector {finding} run={session.run} rev={session.rev} dir={run.dir} {phase} />
      </div>
      <div class="log">
        <LogConsole
          lines={session.run.log}
          rev={session.rev}
          tools={session.run.tools}
          capped={view.capped}
          evicted={view.evicted}
        />
      </div>
    </div>
  </div>
{:else}
  <section class="picker" aria-label="Runs">
    <header><h1>Monitor</h1></header>
    <p class="hint">Pick a run to follow, or start one from Launch.</p>
    {#if listError}<p class="error">{listError}</p>{/if}
    {#if runs.length === 0 && !listError}
      <p class="hint">No runs yet.</p>
    {:else}
      <ul>
        {#each runs as r, i (r?.Info?.Dir ?? i)}
          <li>
            <button type="button" onclick={() => onselect({ dir: r.Info.Dir })}>
              <span class="status st-{sanitizeText(r.Status)}">{sanitizeText(r.Status)}</span>
              <span class="mono hi">{runLabel(r)}</span>
              <span class="mono">{runStamp(r)}</span>
              <span class="mono">{sanitizeText(r.CurrentStage)}</span>
              <span class="mono num">{runElapsed(r)}</span>
            </button>
          </li>
        {/each}
      </ul>
    {/if}
  </section>
{/if}

<style>
  .monitor { display: grid; grid-template-rows: var(--context-h) minmax(0, 1fr); height: 100%; min-width: 0; }
  .monitor.compact { --row-h: var(--row-compact); }
  .panes {
    display: grid;
    grid-template-columns: var(--stages-w) minmax(0, 1fr) var(--inspector-w);
    grid-template-rows: minmax(0, 1fr) var(--log-h);
    min-height: 0;
    min-width: 0;
  }
  .panes > div { min-height: 0; min-width: 0; }
  .stages { grid-row: 1 / 3; }
  .log { grid-column: 2 / 4; border-top: 1px solid var(--line-1); }

  .picker { height: 100%; overflow: auto; background: var(--bg-1); }
  .picker header { padding: var(--s4); border-bottom: 1px solid var(--line-1); }
  h1 { margin: 0; color: var(--tx-hi); font: var(--w-label) var(--fs-view)/var(--lh-view) var(--font-label); }
  .hint, .error { margin: 0; padding: var(--s3) var(--s4); color: var(--tx-mid); }
  .error { color: var(--red-300); user-select: text; }
  ul { margin: 0; padding: 0; list-style: none; border-top: 1px solid var(--line-1); }
  li button {
    display: grid;
    grid-template-columns: var(--col-sev) var(--col-host) var(--col-template) var(--col-template) minmax(0, 1fr);
    align-items: center;
    gap: var(--s2);
    width: 100%;
    height: var(--list-row-h);
    padding: 0 var(--s4);
    border-bottom: 1px solid var(--line-1);
    text-align: left;
    color: var(--tx);
    cursor: pointer;
  }
  li button:hover { background: var(--bg-3); }
  li button > span { overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }
  .mono { font: var(--w-body) var(--fs-mono)/var(--lh-mono) var(--font-mono); font-variant-numeric: tabular-nums lining-nums; }
  .hi { color: var(--tx-hi); }
  .num { text-align: right; color: var(--tx-mid); }
  .status { color: var(--tx-mid); font: var(--w-label) var(--fs-label)/var(--lh-label) var(--font-label); letter-spacing: var(--tr-label); text-transform: uppercase; }
  .st-running { color: var(--red-400); }
  .st-ok { color: var(--st-ok); }
  .st-failed { color: var(--st-failed); }
</style>
