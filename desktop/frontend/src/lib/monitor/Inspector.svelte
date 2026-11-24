<script>
  // 360px right pane. With a finding selected: its fields (Meta) and the
  // request/response tabs. Otherwise the run's own summary. All values are
  // engine text, rendered as text and selectable.
  import SeverityChip from '../ui/SeverityChip.svelte';
  import Tabs from '../ui/Tabs.svelte';
  import { clock, grouped } from './text.js';

  let { finding = null, run, rev = 0, dir = '', phase = '' } = $props();

  const TABS = [
    { id: 'request', label: 'Request' },
    { id: 'response', label: 'Response' },
    { id: 'meta', label: 'Meta' },
  ];
  let tab = $state('meta');

  const summary = $derived.by(() => {
    void rev;
    const c = run.sevCounts;
    return {
      status: run.endStatus || phase,
      findings: run.findings.length,
      counts: `C ${c.critical}  H ${c.high}  M ${c.medium}  L ${c.low}  I ${c.info}${c.other ? `  ? ${c.other}` : ''}`,
      report: run.report,
      error: run.endError,
    };
  });
</script>

<aside class="pane inspector" aria-label="Inspector">
  <div class="pane-head">
    <h2 class="pane-title">Inspector</h2>
  </div>
  {#if finding}
    <div class="tabs"><Tabs tabs={TABS} bind:value={tab} label="Finding detail" /></div>
    <div class="body">
      <p class="title data">{finding.summary || finding.template}</p>
      {#if tab === 'meta'}
        <dl class="kv">
          <dt>Severity</dt><dd><SeverityChip severity={finding.severity} /></dd>
          <dt>Template</dt><dd class="mono data">{finding.template}</dd>
          <dt>Host</dt><dd class="mono data">{finding.host}</dd>
          <dt>URL</dt><dd class="mono data">{finding.url}</dd>
          <dt>Stage</dt><dd class="mono data">{finding.stage || '—'}</dd>
          <dt>Seen</dt><dd class="mono data">{clock(finding.t)}</dd>
        </dl>
      {:else}
        <p class="note">The event stream carries no captured {tab}. Evidence files are in the run directory.</p>
        {#if dir}<p class="mono data path">{dir}</p>{/if}
      {/if}
    </div>
  {:else}
    <div class="body">
      <p class="note">Select a finding to inspect it.</p>
      <hr />
      <dl class="kv">
        <dt>Status</dt><dd class="mono data">{summary.status || '—'}</dd>
        <dt>Findings</dt><dd class="mono data">{grouped(summary.findings)}</dd>
        <dt>By sev</dt><dd class="mono data">{summary.counts}</dd>
        {#if summary.report}<dt>Report</dt><dd class="mono data">{summary.report}</dd>{/if}
        {#if summary.error}<dt>Error</dt><dd class="mono data err">{summary.error}</dd>{/if}
        {#if dir}<dt>Run dir</dt><dd class="mono data">{dir}</dd>{/if}
      </dl>
    </div>
  {/if}
</aside>

<style>
  .inspector { height: 100%; }
  .tabs { position: relative; flex: none; display: flex; height: var(--panel-h); padding: 0 var(--s1); border-bottom: 1px solid var(--line-1); }
  .body { flex: 1; min-height: 0; overflow-y: auto; display: flex; flex-direction: column; gap: var(--s4); padding: var(--s3); }
  .title { margin: 0; color: var(--tx-hi); font: var(--w-value) var(--fs-section)/var(--lh-section) var(--font-body); overflow-wrap: anywhere; }
  .kv { display: grid; grid-template-columns: var(--col-meta-key) minmax(0, 1fr); row-gap: var(--s1); margin: 0; }
  dt {
    align-self: center;
    color: var(--tx-lo);
    font: var(--w-label) var(--fs-micro)/var(--lh-micro) var(--font-label);
    letter-spacing: var(--tr-micro);
    text-transform: uppercase;
  }
  dd { margin: 0; min-width: 0; color: var(--tx); overflow-wrap: anywhere; }
  .mono { font: var(--w-body) var(--fs-mono)/var(--lh-mono) var(--font-mono); font-variant-numeric: tabular-nums lining-nums; }
  .data { user-select: text; }
  .err { color: var(--st-failed); }
  .note { margin: 0; color: var(--tx-mid); }
  .path { margin: 0; color: var(--tx); overflow-wrap: anywhere; }
  hr { margin: 0; border: 0; border-top: 1px solid var(--line-1); }
</style>
