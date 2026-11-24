// Monitor state. The reducer (createRunState / applyBatch) folds the backend's
// run:<id>:batch payloads into a plain run state; MonitorSession owns the
// attach lifecycle and the skip/cancel/hard-kill controls around it.
//
// Batches carry events in the events v1 wire shape plus sanitized output
// lines (desktop/internal/runs/coalescer.go). The run state is deliberately not
// a deep $state proxy: the log can hold tens of thousands of lines, so the
// session bumps `rev` after each batch and views derive from (run, rev).
import { sanitizeText } from './text.js';

export const SEVERITIES = Object.freeze(['critical', 'high', 'medium', 'low', 'info']);
export const ACK_TIMEOUT_MS = 10_000;
// The log ring: oldest lines go first once either bound is passed.
export const LOG_MAX_LINES = 50_000;
export const LOG_MAX_CHARS = 16 * 1024 * 1024;
const RATE_WINDOW_MS = 5_000;
const MAX_TOOL_TABS = 12;
// The engine's warning when a stage's tool output stopped being recorded.
const CAPPED_WARNING = /output events capped/i;

// sevKey maps a raw severity onto a known one, or 'other'.
export function sevKey(raw) {
  const key = String(raw ?? '').trim().toLowerCase();
  return SEVERITIES.includes(key) ? key : 'other';
}

export function createRunState() {
  return {
    target: '',
    flags: {},
    startT: 0,
    lastT: 0,
    order: [], // stage ids: planned (run_start) first, then as first seen
    stages: new Map(), // id -> stage; a Map, so no id can reach a prototype
    current: '', // the most recently started stage
    findings: [],
    findingSeq: 0,
    sevCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0, other: 0 },
    log: [],
    logChars: 0,
    logSeq: 0,
    logEvicted: 0, // lines the ring dropped from its head
    elided: 0, // lines the backend dropped between batches
    capped: false, // the engine stopped recording some tool output
    tools: [],
    ended: false,
    endStatus: '',
    endError: '',
    report: '',
    summary: '',
    totals: null,
    received: 0, // events and output lines applied
  };
}

const str = (value) => (typeof value === 'string' ? value : value === undefined || value === null ? '' : String(value));
const int = (value) => (Number.isFinite(Number(value)) ? Number(value) : 0);
const plainObject = (value) => (value && typeof value === 'object' && !Array.isArray(value) ? value : null);

function stage(state, rawId) {
  const id = str(rawId);
  let s = state.stages.get(id);
  if (!s) {
    s = {
      id,
      name: sanitizeText(id),
      status: 'queued',
      reason: '',
      counts: null,
      done: 0,
      total: 0,
      startT: 0,
      endT: 0,
      durationMs: null,
    };
    state.stages.set(id, s);
    state.order.push(id);
  }
  return s;
}

function trimLog(state) {
  const overLines = state.log.length - LOG_MAX_LINES;
  if (overLines <= LOG_MAX_LINES / 10 && state.logChars <= LOG_MAX_CHARS) return;
  let drop = Math.max(0, overLines);
  let chars = state.logChars;
  for (let i = 0; i < drop; i += 1) chars -= state.log[i].text.length;
  while (chars > LOG_MAX_CHARS && drop < state.log.length - 1) {
    chars -= state.log[drop].text.length;
    drop += 1;
  }
  if (drop === 0) return;
  state.log.splice(0, drop);
  state.logChars = chars;
  state.logEvicted += drop;
}

function pushLog(state, line) {
  line.seq = ++state.logSeq;
  state.log.push(line);
  state.logChars += line.text.length;
  trimLog(state);
}

const LEVELS = { error: 'ERR', err: 'ERR', warn: 'WARN', warning: 'WARN', info: 'INFO', debug: 'DBG' };

function pushOutput(state, out) {
  const tool = sanitizeText(out.tool);
  if (tool && !state.tools.includes(tool) && state.tools.length < MAX_TOOL_TABS) state.tools.push(tool);
  pushLog(state, {
    t: int(out.t),
    tag: sanitizeText(out.stage),
    tool,
    level: out.stream === 'stderr' ? 'ERR' : 'OUT',
    text: sanitizeText(out.line),
  });
  state.received += 1;
}

export function applyEvent(state, ev) {
  if (!ev || typeof ev !== 'object') return;
  state.received += 1;
  const t = int(ev.t);
  if (t > state.lastT) state.lastT = t;
  switch (ev.type) {
    case 'run_start': {
      state.target = sanitizeText(ev.target);
      state.flags = plainObject(ev.flags) ?? {};
      state.startT = t;
      if (Array.isArray(ev.stages)) for (const id of ev.stages) stage(state, id);
      break;
    }
    case 'stage_start': {
      const s = stage(state, ev.stage);
      s.status = 'running';
      s.startT = t;
      state.current = s.id;
      break;
    }
    case 'progress': {
      const s = stage(state, ev.stage);
      s.done = int(ev.done);
      s.total = int(ev.total);
      break;
    }
    case 'stage_end': {
      const s = stage(state, ev.stage);
      s.status = str(ev.status) || 'ok';
      s.reason = sanitizeText(ev.reason);
      s.counts = plainObject(ev.counts);
      s.durationMs = ev.duration_ms === undefined ? null : int(ev.duration_ms);
      s.endT = t;
      break;
    }
    case 'log': {
      const level = str(ev.level).toLowerCase();
      const text = sanitizeText(ev.msg);
      if ((level === 'warn' || level === 'warning') && CAPPED_WARNING.test(text)) state.capped = true;
      pushLog(state, { t, tag: 'engine', tool: '', level: LEVELS[level] ?? sanitizeText(ev.level).toUpperCase(), text });
      break;
    }
    case 'output': {
      state.received -= 1; // pushOutput counts it
      pushOutput(state, ev);
      break;
    }
    case 'finding': {
      const severity = sanitizeText(ev.severity);
      const key = sevKey(severity);
      state.sevCounts[key] += 1;
      state.findings.push({
        seq: ++state.findingSeq,
        t,
        severity,
        sev: key,
        template: sanitizeText(ev.template),
        host: sanitizeText(ev.host),
        url: sanitizeText(ev.url),
        summary: sanitizeText(ev.summary),
        stage: state.current,
      });
      break;
    }
    case 'run_end': {
      state.ended = true;
      state.endStatus = sanitizeText(ev.status);
      state.endError = sanitizeText(ev.error);
      state.report = sanitizeText(ev.report);
      state.summary = sanitizeText(ev.summary);
      state.totals = plainObject(ev.totals);
      break;
    }
    default:
      break; // schema v1 has eight types; anything else is ignored
  }
}

// applyBatch folds one run:<id>:batch payload into state. A reset batch
// replaces everything earlier batches built. Events and output lines are
// merged by timestamp so the log reads in order.
export function applyBatch(state, batch) {
  if (!batch || typeof batch !== 'object') return state;
  if (batch.reset) Object.assign(state, createRunState());
  const events = Array.isArray(batch.events) ? batch.events : [];
  const output = Array.isArray(batch.output) ? batch.output : [];
  const elided = int(batch.elided);
  if (elided > 0) {
    state.elided += elided;
    const t = int(output[0]?.t) || state.lastT;
    pushLog(state, { t, tag: '', tool: '', level: 'NOTE', text: `${elided.toLocaleString('en-US')} lines dropped`, notice: true });
  }
  let o = 0;
  for (const ev of events) {
    const t = int(ev?.t);
    while (o < output.length && int(output[o]?.t) < t) pushOutput(state, output[o++] ?? {});
    applyEvent(state, ev);
  }
  while (o < output.length) pushOutput(state, output[o++] ?? {});
  return state;
}

// stageRows lists the run's stages for display, grouped by tier in catalog
// order. Tier, number and parent come from the engine catalog (Launch.Stages):
// a stage whose parent is also in the run nests under it (origin_deep under
// origin). A stage the catalog does not know is listed under 'other'.
export function stageRows(state, catalog = []) {
  const meta = new Map();
  const tiers = [];
  for (const entry of Array.isArray(catalog) ? catalog : []) {
    if (!entry || typeof entry.id !== 'string') continue;
    meta.set(entry.id, entry);
    if (entry.tier && !tiers.includes(entry.tier)) tiers.push(entry.tier);
  }
  const inRun = new Set(state.order);
  const parentOf = (id) => {
    const parent = meta.get(id)?.parent;
    return parent && parent !== id && inRun.has(parent) ? parent : '';
  };
  const children = new Map();
  for (const id of state.order) {
    const parent = parentOf(id);
    if (!parent) continue;
    if (!children.has(parent)) children.set(parent, []);
    children.get(parent).push(id);
  }
  const row = (id, level, parent) => {
    const s = state.stages.get(id);
    const m = meta.get(id);
    return { ...s, level, parent, num: m?.num ?? null, tier: m?.tier ?? 'other', title: m?.title ?? '' };
  };
  const groups = new Map([...tiers, 'other'].map((tier) => [tier, []]));
  for (const id of state.order) {
    if (parentOf(id)) continue;
    const tier = meta.get(id)?.tier;
    const group = groups.get(groups.has(tier) ? tier : 'other');
    group.push(row(id, 1, ''));
    for (const child of children.get(id) ?? []) group.push(row(child, 2, id));
  }
  return [...groups.values()].flat();
}

const errorText = (error) => sanitizeText(error?.cause?.message ?? error?.message ?? String(error));

// MonitorSession follows one run at a time. api is runsApi (lib/bridge/api.js)
// and on subscribes to a backend channel (lib/bridge/window.js onEvent).
export class MonitorSession {
  run = createRunState();
  rev = $state(0);
  ref = $state.raw(null);
  attached = $state(false);
  dead = $state.raw(null); // run:<id>:dead payload, once the engine is gone
  confirm = $state.raw(null); // { kind: 'skip', stage } | { kind: 'cancel' }
  pending = $state.raw(null); // the newest sent command awaiting its ack
  hardKillOffered = $state(false);
  killed = $state(false);
  error = $state('');
  now = $state(Date.now());
  rate = $state(0);

  #api;
  #on;
  #ackMs;
  #gen = 0;
  #unsubs = [];
  #ackTimer = null;
  #clock = null;
  #seq = 0;
  #samples = [];

  constructor({ api, on, ackTimeoutMs = ACK_TIMEOUT_MS }) {
    this.#api = api;
    this.#on = on;
    this.#ackMs = ackTimeoutMs;
  }

  get controllable() {
    return this.attached && !this.dead && !this.killed && !this.run.ended;
  }

  // open attaches to ref ({ dir, id? }). State is cleared first: the backend
  // replays the run's events from the start on every attach.
  async open(ref) {
    this.close();
    const gen = ++this.#gen;
    this.#clear();
    this.ref = ref;
    try {
      const id = ref.id || (await this.#api.runId(ref.dir));
      // Detach first and wait: once it returns no batch of an earlier attach
      // is still in flight, so every batch that follows belongs to this one.
      await this.#api.detach(ref.dir);
      if (gen !== this.#gen) return;
      this.#unsubs.push(
        this.#on(`run:${id}:batch`, (batch) => gen === this.#gen && this.#onBatch(batch)),
        this.#on(`run:${id}:dead`, (info) => gen === this.#gen && this.#onDead(info)),
      );
      this.attached = true;
      this.#startClock();
      await this.#api.attach(ref.dir);
      // close() or a newer open() ran while attach was in flight: its detach
      // came first, so this attach would otherwise leak a stream.
      // A newer session on the same dir already superseded this attach (the
      // backend detaches per dir), so detaching would kill it.
      if (gen !== this.#gen && !(this.attached && this.ref?.dir === ref.dir)) this.#api.detach(ref.dir)?.catch?.(() => {});
    } catch (error) {
      if (gen !== this.#gen) return;
      this.error = errorText(error);
      this.#teardown(true);
    }
  }

  // close unsubscribes and detaches. The engine keeps running.
  close() {
    this.#gen += 1;
    this.#teardown(this.attached);
    this.confirm = null;
    this.pending = null;
    this.hardKillOffered = false;
  }

  #teardown(detach) {
    for (const unsub of this.#unsubs.splice(0)) unsub?.();
    this.#stopClock();
    clearTimeout(this.#ackTimer);
    this.#ackTimer = null;
    if (detach && this.ref) this.#api.detach(this.ref.dir)?.catch?.(() => {});
    this.attached = false;
  }

  #clear() {
    this.run = createRunState();
    this.dead = null;
    this.killed = false;
    this.error = '';
    this.confirm = null;
    this.pending = null;
    this.hardKillOffered = false;
    this.#samples = [];
    this.rate = 0;
    this.rev += 1;
  }

  #onBatch(batch) {
    if (batch?.reset) {
      this.confirm = null;
      this.pending = null;
      this.hardKillOffered = false;
      clearTimeout(this.#ackTimer);
    }
    const before = this.run.received;
    applyBatch(this.run, batch);
    this.#sample(this.run.received - before);
    for (const ev of Array.isArray(batch?.events) ? batch.events : []) {
      if (ev?.type === 'stage_end') {
        const id = str(ev.stage);
        if (this.pending?.kind === 'skip' && this.pending.stage === id) this.#acked();
        if (this.confirm?.kind === 'skip' && this.confirm.stage === id) this.confirm = null;
      } else if (ev?.type === 'run_end') {
        this.#acked();
        this.confirm = null;
      }
    }
    if (this.run.ended) this.#stopClock();
    this.rev += 1;
  }

  #onDead(info) {
    const status = sanitizeText(info?.status) || 'crashed';
    this.dead = { status };
    this.confirm = null;
    this.#acked();
    this.#teardown(true);
    this.rev += 1;
    // The engine died without a clean end: show why, from engine.log.
    if (!this.run.ended && status !== 'ok' && status !== 'cancelled') this.#engineTail(this.#gen);
  }

  async #engineTail(gen) {
    try {
      const tail = await this.#api.engineLogTail?.(this.ref.dir, 20);
      if (gen !== this.#gen || typeof tail !== 'string' || !tail.trim()) return;
      const t = this.run.lastT;
      pushLog(this.run, { t, tag: 'engine.log', tool: '', level: 'NOTE', text: `engine exited (${this.dead?.status ?? 'crashed'}); engine.log tail:`, notice: true });
      for (const line of tail.split('\n')) pushLog(this.run, { t, tag: 'engine.log', tool: '', level: 'LOG', text: sanitizeText(line) });
      this.rev += 1;
    } catch {
      // the tail is a courtesy; the dead state is already shown
    }
  }

  #acked() {
    this.pending = null;
    this.hardKillOffered = false;
    clearTimeout(this.#ackTimer);
    this.#ackTimer = null;
  }

  #sample(n) {
    const now = Date.now();
    this.#samples.push([now, n]);
    while (this.#samples.length && this.#samples[0][0] < now - RATE_WINDOW_MS) this.#samples.shift();
    this.#updateRate(now);
  }

  #updateRate(now) {
    while (this.#samples.length && this.#samples[0][0] < now - RATE_WINDOW_MS) this.#samples.shift();
    const total = this.#samples.reduce((sum, [, n]) => sum + n, 0);
    this.rate = Math.round(total / (RATE_WINDOW_MS / 1000));
  }

  #startClock() {
    this.#stopClock();
    this.now = Date.now();
    this.#clock = setInterval(() => {
      this.now = Date.now();
      this.#updateRate(this.now);
    }, 1000);
  }

  #stopClock() {
    clearInterval(this.#clock);
    this.#clock = null;
  }

  // The running stage a skip would target: the most recently started one.
  get skippable() {
    const s = this.run.stages.get(this.run.current);
    return s && s.status === 'running' ? s.id : '';
  }

  requestSkip(stageId = this.skippable) {
    const s = this.run.stages.get(stageId);
    if (!this.controllable || !s || s.status !== 'running') return;
    this.confirm = { kind: 'skip', stage: s.id };
  }

  requestCancel() {
    if (this.controllable) this.confirm = { kind: 'cancel' };
  }

  // answer resolves the y/n prompt.
  answer(yes) {
    const asked = this.confirm;
    this.confirm = null;
    if (!yes || !asked || !this.controllable) return;
    this.#send(asked);
  }

  // A newer command replaces the pending one, so only its timer can raise
  // the hard-kill offer.
  #send(command) {
    const seq = ++this.#seq;
    const dir = this.ref.dir;
    this.pending = { ...command, seq };
    this.hardKillOffered = false;
    this.error = '';
    clearTimeout(this.#ackTimer);
    this.#ackTimer = setTimeout(() => {
      if (this.pending?.seq === seq && this.controllable) this.hardKillOffered = true;
    }, this.#ackMs);
    const sent = command.kind === 'skip' ? this.#api.skip(dir, command.stage) : this.#api.cancel(dir);
    Promise.resolve(sent).catch((error) => {
      if (this.pending?.seq !== seq) return;
      this.error = errorText(error);
      this.#acked();
    });
  }

  async hardKill() {
    if (!this.hardKillOffered || !this.controllable) return;
    this.hardKillOffered = false;
    const dir = this.ref.dir;
    try {
      await this.#api.hardKill(dir);
      this.killed = true;
      this.#acked();
      this.#stopClock();
    } catch (error) {
      this.error = errorText(error);
      this.hardKillOffered = this.controllable && this.pending !== null;
    }
  }
}
