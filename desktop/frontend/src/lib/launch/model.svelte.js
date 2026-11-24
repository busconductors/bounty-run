// Launch form state and the pure rules behind it. Values live in this
// in-memory object only: nothing here (proxy and headers included) is ever
// written to storage, cookies, the URL or logs.

// Tiers in ceiling order, as the engine reports them (introspect stages).
export const TIERS = Object.freeze(['passive', 'active', 'intrusive']);
// Tier marker shapes from the UI spec: passive / active / intrusive.
export const TIER_GLYPH = Object.freeze({ passive: '□', active: '◧', intrusive: '▨' });

// Mirrors engine.MinRateLimit / engine.MaxRateLimit (Go enforces them too).
export const RATE_MIN = 0.1;
export const RATE_MAX = 1000;

export const PRESET_LABELS = Object.freeze({ quick: 'Quick', standard: 'Standard', deep: 'Deep', custom: 'Custom' });
export const DEFAULT_PRESET = 'standard';

const DOMAIN = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;

// Port of engine.NormalizeTarget: the domain, or null when it is not one.
export function normalizeTarget(input) {
  let t = String(input ?? '').trim().toLowerCase();
  const scheme = t.indexOf('://');
  if (scheme >= 0) t = t.slice(scheme + 3);
  t = t.split('/')[0].split(':')[0].replace(/\.+$/, '');
  return DOMAIN.test(t) ? t : null;
}

export function withinCeiling(tier, ceiling) {
  return TIERS.indexOf(tier) <= TIERS.indexOf(ceiling);
}

// Trimmed, non-empty lines of a textarea.
export function lines(text) {
  return String(text ?? '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);
}

// '' means no limit (0); otherwise a finite number in [RATE_MIN, RATE_MAX].
export function parseRate(text) {
  const s = String(text ?? '').trim();
  if (s === '') return { value: 0, error: '' };
  const n = /^\d+(\.\d+)?$/.test(s) ? Number(s) : NaN;
  if (!Number.isFinite(n) || n < RATE_MIN || n > RATE_MAX) {
    return { value: 0, error: `Rate limit must be between ${RATE_MIN} and ${RATE_MAX} requests per second.` };
  }
  return { value: n, error: '' };
}

// '' means engine default (0); otherwise a positive whole number.
export function parseCount(text, label) {
  const s = String(text ?? '').trim();
  if (s === '') return { value: 0, error: '' };
  const n = /^\d{1,7}$/.test(s) ? Number(s) : 0;
  return n > 0 ? { value: n, error: '' } : { value: 0, error: `${label} must be a positive whole number.` };
}

export function createForm() {
  const form = $state({
    target: '',
    preset: DEFAULT_PRESET,
    intensity: 'intrusive',
    enabled: [],
    advanced: false,
    proxy: '',
    headers: '',
    scopeAllow: '',
    scopeDeny: '',
    rateLimit: '',
    userAgent: '',
    timeout: '',
    threads: '',
    verifyTLS: false,
    noOAST: false,
    noEvidence: false,
    evidenceUnredacted: false,
    noSubsCache: false,
    ipintelOffline: false,
  });
  return form;
}

// Input problems the form can see before asking the backend.
export function localErrors(form) {
  const errors = {};
  if (normalizeTarget(form.target) === null) errors.target = 'Not a valid domain.';
  const rate = parseRate(form.rateLimit).error;
  if (rate) errors.rateLimit = rate;
  const timeout = parseCount(form.timeout, 'Timeout').error;
  if (timeout) errors.timeout = timeout;
  const threads = parseCount(form.threads, 'Threads').error;
  if (threads) errors.threads = threads;
  if (form.enabled.length === 0) errors.stages = 'Select at least one stage.';
  return errors;
}

// The catalog.Request the backend previews and starts. Option keys are the
// engine.Options Go field names.
export function buildRequest(form) {
  return {
    options: {
      Target: form.target.trim(),
      Intensity: form.intensity,
      Proxy: form.proxy.trim(),
      Headers: lines(form.headers),
      ScopeAllow: lines(form.scopeAllow),
      ScopeDeny: lines(form.scopeDeny),
      RateLimit: parseRate(form.rateLimit).value,
      UserAgent: form.userAgent.trim(),
      Timeout: parseCount(form.timeout).value,
      Threads: parseCount(form.threads).value,
      VerifyTLS: form.verifyTLS,
      NoOAST: form.noOAST,
      NoEvidence: form.noEvidence,
      EvidenceUnredacted: form.evidenceUnredacted,
      NoSubsCache: form.noSubsCache,
      IPIntelOffline: form.ipintelOffline,
    },
    stages: [...form.enabled],
  };
}

// The ids a preset enables, limited to what this engine offers.
export function presetSelection(presets, id, known) {
  const preset = presets.find((p) => p.id === id);
  return preset ? preset.stages.filter((s) => known.includes(s)) : null;
}

// Display-only shell quoting for the argv preview.
export function shellQuote(arg) {
  return /^[A-Za-z0-9_./,:=@%+-]+$/.test(arg) ? arg : `'${arg.replaceAll("'", `'\\''`)}'`;
}
