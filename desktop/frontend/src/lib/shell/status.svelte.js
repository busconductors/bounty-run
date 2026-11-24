// What the status bar shows. The Monitor writes it while it follows a run;
// every other view leaves it idle.
const IDLE = Object.freeze({ live: false, label: '', stage: '', elapsed: '', rate: null, counts: null });

export const runStatus = $state({ ...IDLE });

export function setRunStatus(next) {
  Object.assign(runStatus, IDLE, next ?? {});
}
