// Display helpers for engine-supplied strings. The backend sanitizes tool
// output, but structural event fields (targets, findings, log messages) reach
// the client raw; they are rendered as text, and stripped here of escape
// sequences, control characters and bidi overrides that could spoof the view.
const ANSI =
  /\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)?|\u001b[PX^_][^\u001b]*(?:\u001b\\)?|[\u001b\u009b]\[?[0-?]*[ -/]*[@-~]?/g;
const CONTROLS = /[\u0000-\u0008\u000a-\u001f\u007f-\u009f]/g;
const BIDI = /[؜‎‏‪-‮⁦-⁩]/g;

export function sanitizeText(value) {
  if (value === undefined || value === null) return '';
  let text = String(value);
  if (typeof text.toWellFormed === 'function') text = text.toWellFormed();
  return text.replace(ANSI, '').replace(CONTROLS, '').replace(BIDI, '').replaceAll('\t', ' ');
}

const pad = (n) => String(n).padStart(2, '0');

// HH:MM:SS in local time for an epoch-ms timestamp; '' when absent.
export function clock(ms) {
  if (!Number.isFinite(ms) || ms <= 0) return '';
  const d = new Date(ms);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

// A compact duration: 850ms, 4s, 2m05s, 1h04m.
export function duration(ms) {
  if (!Number.isFinite(ms) || ms < 0) return '';
  if (ms < 1000) return `${Math.round(ms)}ms`;
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m${pad(s % 60)}s`;
  return `${Math.floor(m / 60)}h${pad(m % 60)}m`;
}

// HH:MM:SS of elapsed time.
export function elapsed(ms) {
  if (!Number.isFinite(ms) || ms < 0) return '--:--:--';
  const s = Math.floor(ms / 1000);
  return `${pad(Math.floor(s / 3600))}:${pad(Math.floor(s / 60) % 60)}:${pad(s % 60)}`;
}

export const grouped = (n) => Number(n).toLocaleString('en-US');
