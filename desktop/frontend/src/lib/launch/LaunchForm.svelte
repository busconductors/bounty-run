<script>
  // The Launch form: one left-aligned canvas of hairline-separated sections.
  // Everything the engine can do comes from the catalog (api); every launch is
  // previewed by the backend first and only a previewed request is started.
  import Button from '../ui/Button.svelte';
  import Segmented from '../ui/Segmented.svelte';
  import Toggle from '../ui/Toggle.svelte';
  import ArgvPreview from './ArgvPreview.svelte';
  import StageGrid from './StageGrid.svelte';
  import {
    PRESET_LABELS,
    TIERS,
    TIER_GLYPH,
    buildRequest,
    createForm,
    localErrors,
    normalizeTarget,
    presetSelection,
  } from './model.svelte.js';

  const PREVIEW_DELAY_MS = 120;

  let { api, form = $bindable(createForm()), onlaunched = undefined } = $props();

  let stages = $state([]);
  let modifiers = $state([]);
  let presets = $state([]);
  let missing = $state({});
  let engineVersion = $state('');
  let catalogError = $state('');
  let toolsError = $state('');
  let ready = $state(false);

  let preview = $state(null);
  let previewKey = $state('');
  let previewError = $state('');
  let launching = $state(false);
  let launchError = $state(null);
  let previewSeq = 0; // not reactive: only orders responses

  const known = $derived([...stages.map((s) => s.id), ...modifiers.map((m) => m.id)]);
  const presetOptions = $derived([
    ...presets.map((p) => ({ id: p.id, label: PRESET_LABELS[p.id] ?? p.id })),
    { id: 'custom', label: PRESET_LABELS.custom },
  ]);
  const intensityOptions = TIERS.map((tier) => ({ id: tier, label: tier, glyph: TIER_GLYPH[tier] }));

  const normalized = $derived(normalizeTarget(form.target));
  const errors = $derived(localErrors(form));
  const blocked = $derived(Object.keys(errors).length > 0);
  const requestKey = $derived(JSON.stringify(buildRequest(form)));
  const current = $derived(preview !== null && previewKey === requestKey && !previewError);
  const canLaunch = $derived(ready && !blocked && current && !launching);

  async function load() {
    try {
      const [s, m, p] = await Promise.all([api.stages(), api.modifiers(), api.presets()]);
      stages = s ?? [];
      modifiers = m ?? [];
      presets = p ?? [];
      if (form.enabled.length === 0 && form.preset !== 'custom') applyPreset(form.preset);
      ready = true;
    } catch (error) {
      catalogError = messageOf(error);
    }
    api.version().then((v) => (engineVersion = v?.engine_version ?? ''), () => {});
    api.doctor().then(
      (d) => (missing = d?.missing_by_stage ?? {}),
      (error) => (toolsError = messageOf(error)),
    );
  }
  load();

  function applyPreset(id) {
    const selection = presetSelection(presets, id, known);
    if (selection) form.enabled = selection;
  }

  function messageOf(error) {
    return error?.cause?.message ?? error?.message ?? String(error);
  }

  // Preview every settled change; a stale answer never replaces a newer one.
  $effect(() => {
    const key = requestKey;
    if (!ready || blocked) {
      preview = null;
      previewError = '';
      return;
    }
    const seq = ++previewSeq;
    const timer = setTimeout(async () => {
      try {
        const result = await api.preview(JSON.parse(key));
        if (seq !== previewSeq) return;
        preview = result;
        previewKey = key;
        previewError = '';
      } catch (error) {
        if (seq !== previewSeq) return;
        preview = null;
        previewError = messageOf(error);
      }
    }, PREVIEW_DELAY_MS);
    return () => clearTimeout(timer);
  });

  async function launch() {
    if (!canLaunch) return;
    launching = true;
    launchError = null;
    try {
      const ref = await api.start(JSON.parse(previewKey));
      onlaunched?.(ref);
    } catch (error) {
      const cause = error?.cause;
      launchError = { message: messageOf(error), tail: typeof cause?.tail === 'string' ? cause.tail : '' };
    } finally {
      launching = false;
    }
  }
</script>

<div class="launch">
  <header class="head">
    <h1>Launch</h1>
    {#if engineVersion}<span class="meta">engine {engineVersion}</span>{/if}
  </header>

  {#if catalogError}
    <p class="problem" role="alert">Engine unavailable: {catalogError}</p>
  {/if}

  <section class="field">
    <label class="label" for="launch-target">Target</label>
    <div class="control">
      <input
        id="launch-target"
        class="input mono"
        type="text"
        placeholder="example.com"
        autocomplete="off"
        spellcheck="false"
        bind:value={form.target}
      />
      {#if normalized}
        <p class="hint"><span aria-hidden="true">→</span> <span class="normalized">{normalized}</span></p>
      {:else if form.target.trim()}
        <p class="error">Not a valid domain.</p>
      {/if}
    </div>
  </section>

  <section class="field">
    <span class="label">Preset</span>
    <div class="control">
      <Segmented options={presetOptions} bind:value={form.preset} label="Preset" onchange={applyPreset} />
    </div>
  </section>

  <section class="field">
    <span class="label">Intensity ceiling</span>
    <div class="control">
      <Segmented options={intensityOptions} bind:value={form.intensity} label="Intensity ceiling" />
      <p class="hint">Stages above the ceiling do not run.</p>
    </div>
  </section>

  <section class="field">
    <span class="label">Stages</span>
    <div class="control wide">
      {#if ready}
        <StageGrid
          {stages}
          {modifiers}
          bind:enabled={form.enabled}
          ceiling={form.intensity}
          {missing}
          onchange={() => (form.preset = 'custom')}
        />
      {:else if !catalogError}
        <p class="hint">Reading stages from the engine…</p>
      {/if}
      {#if toolsError}<p class="hint">Tool check unavailable: {toolsError}</p>{/if}
      {#if errors.stages && ready}<p class="error">{errors.stages}</p>{/if}
    </div>
  </section>

  <section class="field">
    <span class="label">Advanced</span>
    <div class="control">
      <button type="button" class="disclose" aria-expanded={form.advanced} onclick={() => (form.advanced = !form.advanced)}>
        <span aria-hidden="true">{form.advanced ? '▾' : '▸'}</span> Advanced flags
      </button>
      {#if form.advanced}
        <div class="advanced">
          <label class="sub" for="launch-proxy">Proxy</label>
          <input
            id="launch-proxy"
            class="input mono"
            type="text"
            placeholder="http://127.0.0.1:8080"
            autocomplete="off"
            spellcheck="false"
            bind:value={form.proxy}
          />
          <p class="hint">Kept in memory for this session only; passed to the engine in its environment.</p>

          <label class="sub" for="launch-headers">Headers</label>
          <textarea id="launch-headers" class="input mono" rows="3" placeholder="Name: value" autocomplete="off" spellcheck="false" bind:value={form.headers}></textarea>

          <label class="sub" for="launch-scope-allow">Scope allow rules</label>
          <textarea id="launch-scope-allow" class="input mono" rows="2" placeholder="one per line: host, *.wildcard, CIDR, re:regex" spellcheck="false" bind:value={form.scopeAllow}></textarea>

          <label class="sub" for="launch-scope-deny">Scope deny rules</label>
          <textarea id="launch-scope-deny" class="input mono" rows="2" spellcheck="false" bind:value={form.scopeDeny}></textarea>

          <div class="pair">
            <div>
              <label class="sub" for="launch-rate">Rate limit (req/s)</label>
              <input id="launch-rate" class="input mono short" type="text" inputmode="decimal" placeholder="none" bind:value={form.rateLimit} />
            </div>
            <div>
              <label class="sub" for="launch-timeout">Timeout (s)</label>
              <input id="launch-timeout" class="input mono short" type="text" inputmode="numeric" placeholder="8" bind:value={form.timeout} />
            </div>
            <div>
              <label class="sub" for="launch-threads">Threads</label>
              <input id="launch-threads" class="input mono short" type="text" inputmode="numeric" placeholder="30" bind:value={form.threads} />
            </div>
          </div>
          {#each ['rateLimit', 'timeout', 'threads'] as key (key)}
            {#if errors[key]}<p class="error">{errors[key]}</p>{/if}
          {/each}

          <label class="sub" for="launch-ua">User agent</label>
          <input id="launch-ua" class="input mono" type="text" spellcheck="false" bind:value={form.userAgent} />

          <div class="toggles">
            <Toggle label="Verify TLS" bind:checked={form.verifyTLS} />
            <Toggle label="No OAST" bind:checked={form.noOAST} />
            <Toggle label="No subdomain cache" bind:checked={form.noSubsCache} />
            <Toggle label="IP intel offline" bind:checked={form.ipintelOffline} />
            <Toggle label="No evidence" bind:checked={form.noEvidence} />
            <Toggle label="Evidence unredacted" bind:checked={form.evidenceUnredacted} />
          </div>
        </div>
      {/if}
    </div>
  </section>

  <section class="field" aria-label="Effective scope">
    <span class="label">Effective scope</span>
    <div class="control">
      {#if preview}
        <p class="hint">{preview.scope.default ? 'Target and its subdomains (engine default)' : 'Custom rules (replace the default)'}</p>
        <ul class="scope">
          {#each preview.scope.allow as rule (rule)}<li><span class="tag">allow</span><span class="mono">{rule}</span></li>{/each}
          {#each preview.scope.deny as rule (rule)}<li><span class="tag">deny</span><span class="mono">{rule}</span></li>{/each}
          {#if preview.scope.file}<li><span class="tag">file</span><span class="mono">{preview.scope.file}</span></li>{/if}
        </ul>
      {:else}
        <p class="hint">Enter a valid target to see the scope.</p>
      {/if}
    </div>
  </section>

  {#if preview?.warnings?.length}
    <section class="field" aria-label="Warnings">
      <span class="label">Warnings</span>
      <ul class="control warnings">
        {#each preview.warnings as warning (warning)}<li><span class="glyph" aria-hidden="true">⚠</span>{warning}</li>{/each}
      </ul>
    </section>
  {/if}

  <section class="field" aria-label="Command">
    <span class="label">Command</span>
    <div class="control wide">
      {#if preview}
        <ArgvPreview argv={preview.argv} envNames={preview.env_names ?? []} runDir={preview.run_dir} />
      {:else if previewError}
        <p class="error">{previewError}</p>
      {:else}
        <p class="hint">The exact engine command appears here.</p>
      {/if}
    </div>
  </section>

  <section class="field actions">
    <span class="label"></span>
    <div class="control">
      <Button variant="primary" disabled={!canLaunch} onclick={launch}>
        {launching ? 'Launching…' : 'Launch scan'}
      </Button>
      {#if launchError}
        <div class="failure" role="alert">
          <p class="error">{launchError.message}</p>
          {#if launchError.tail}<pre class="tail">{launchError.tail}</pre>{/if}
        </div>
      {/if}
    </div>
  </section>
</div>

<style>
  .launch { min-height: 100%; background: var(--bg-1); }
  .head {
    display: flex;
    align-items: baseline;
    gap: var(--s3);
    padding: var(--s4);
    border-bottom: 1px solid var(--line-1);
  }
  h1 { margin: 0; color: var(--tx-hi); font: var(--w-label) var(--fs-view)/var(--lh-view) var(--font-label); }
  .meta { color: var(--tx-lo); font: var(--w-body) var(--fs-mono)/var(--lh-mono) var(--font-mono); }
  .field {
    display: grid;
    grid-template-columns: var(--form-label-w) minmax(0, 1fr);
    gap: var(--s4);
    padding: var(--s4);
    border-bottom: 1px solid var(--line-1);
  }
  .label, .sub {
    color: var(--tx-mid);
    font: var(--w-label) var(--fs-label)/var(--lh-label) var(--font-label);
    letter-spacing: var(--tr-label);
    text-transform: uppercase;
  }
  .label { padding-top: var(--s1); }
  .control { display: flex; flex-direction: column; align-items: flex-start; gap: var(--s2); min-width: 0; max-width: var(--field-w); }
  .control.wide { align-items: stretch; max-width: none; }
  .input {
    width: 100%;
    min-height: var(--ctl-h);
    padding: var(--s1) var(--s2);
    border: 1px solid var(--line-2);
    border-radius: var(--radius-ctl);
    background: var(--bg-0);
    color: var(--tx-hi);
    font: var(--w-body) var(--fs-body)/var(--lh-body) var(--font-body);
    user-select: text;
    resize: vertical;
    transition: border-color var(--t-fast) var(--ease);
  }
  .input:hover { border-color: var(--line-3); }
  .input:focus-visible { border-color: var(--red-400); outline: none; }
  .input::placeholder { color: var(--tx-off); }
  .mono, .input.mono { font: var(--w-body) var(--fs-mono)/var(--lh-mono) var(--font-mono); }
  .short { width: var(--field-w); max-width: 100%; }
  .hint, .error, .problem { margin: 0; }
  .hint { color: var(--tx-lo); }
  .normalized { color: var(--tx); font: var(--w-body) var(--fs-mono)/var(--lh-mono) var(--font-mono); }
  .error, .problem { color: var(--sev-critical); }
  .problem { padding: var(--s3) var(--s4); border-bottom: 1px solid var(--line-1); }
  .disclose {
    color: var(--tx);
    font: var(--w-value) var(--fs-label)/var(--lh-label) var(--font-label);
    letter-spacing: var(--tr-label);
    text-transform: uppercase;
    cursor: pointer;
  }
  .disclose:hover { color: var(--tx-hi); }
  .advanced { display: flex; flex-direction: column; gap: var(--s2); width: 100%; }
  .sub { margin-top: var(--s2); }
  .pair { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: var(--s3); }
  .toggles { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: var(--s2) var(--s4); margin-top: var(--s2); }
  .scope, .warnings { display: flex; flex-direction: column; gap: var(--s1); margin: 0; padding: 0; list-style: none; }
  .scope li { display: flex; align-items: baseline; gap: var(--s2); color: var(--tx); }
  .tag {
    width: var(--chip-w);
    color: var(--tx-lo);
    font: var(--w-label) var(--fs-micro)/var(--lh-micro) var(--font-label);
    letter-spacing: var(--tr-micro);
    text-transform: uppercase;
  }
  /* No ligatures: Barlow would draw the "--" of a flag name as a dash. */
  .warnings li { display: flex; gap: var(--s2); color: var(--tx); font-variant-ligatures: none; }
  .warnings .glyph { color: var(--sev-medium); }
  .failure { display: flex; flex-direction: column; gap: var(--s2); width: 100%; }
  .tail {
    max-height: var(--log-tail-h);
    margin: 0;
    padding: var(--s3);
    overflow: auto;
    border: 1px solid var(--line-2);
    border-radius: var(--radius-ctl);
    background: var(--bg-0);
    color: var(--tx);
    font: var(--w-body) var(--fs-mono)/var(--lh-mono) var(--font-mono);
    white-space: pre-wrap;
    user-select: text;
  }
</style>
