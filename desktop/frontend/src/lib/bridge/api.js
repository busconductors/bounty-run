// Backend calls. Like window.js, this is the only place that reaches Go: bound
// service methods are called by fully qualified name (Wails v3 Call.ByName).
// internal/bridge/services/services_test.go checks every name below exists.
import { Call } from '@wailsio/runtime';

const PKG = 'bountyrun/desktop/internal/bridge/services';

const call = (method, ...args) => Call.ByName(`${PKG}.${method}`, ...args);

// The Launch screen's backend: engine stages, presets, tools, preview, start.
export const launchApi = Object.freeze({
  stages: () => call('Launch.Stages'),
  modifiers: () => call('Launch.Modifiers'),
  presets: () => call('Launch.Presets'),
  doctor: () => call('Launch.Doctor'),
  version: () => call('Launch.Version'),
  preview: (request) => call('Launch.Preview', request),
  start: (request) => call('Launch.Start', request),
});

export const runsApi = Object.freeze({
  list: () => call('Runs.ListRuns'),
  runId: (dir) => call('Runs.RunID', dir),
  attach: (dir) => call('Runs.Attach', dir),
  detach: (dir) => call('Runs.Detach', dir),
  skip: (dir, stage) => call('Runs.Skip', dir, stage),
  cancel: (dir) => call('Runs.Cancel', dir),
  hardKill: (dir) => call('Runs.HardKill', dir),
  engineLogTail: (dir, n) => call('Runs.EngineLogTail', dir, n),
});

// The Doctor screen's backend: tool rows with status, guidance and affected stages.
export const doctorApi = Object.freeze({
  report: () => call('Doctor.Report'),
  recheck: () => call('Doctor.Recheck'),
});

// The Findings view's backend: a run's findings, with evidence links when the run has an index.
export const findingsApi = Object.freeze({
  get: (dir) => call('Findings.GetFindings', dir),
});
