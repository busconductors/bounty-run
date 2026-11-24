// 16px square-geometry glyph paths (the mock's sprite), for stage tier and
// status. Every status is shown as colour plus glyph.
export const TIER_GLYPH = Object.freeze({
  passive: ['M3.5 3.5h9v9h-9z'],
  active: ['M3.5 3.5h9v9h-9z', 'M3.5 3.5h4.5v9H3.5z'],
  intrusive: ['M3.5 3.5h9v9h-9zM3.5 8L8 3.5M3.5 12.5l9-9M8 12.5L12.5 8'],
  other: ['M5.5 5.5h5v5h-5z'],
});

export const STATUS_GLYPH = Object.freeze({
  ok: 'M3 8.5l3.5 3.5L13 4.5',
  failed: 'M4 4l8 8M12 4l-8 8',
  skipped: 'M3.5 3.5h9v9h-9z M5 11l6-6',
  cancelled: 'M4.5 11.5l7-7',
  queued: 'M5 5h6v6H5z',
  warning: 'M8 2.5l6 11H2zM8 6.5v3.5M8 11.5v1',
});

export const STOP_GLYPH = 'M4 4h8v8H4z';
export const NEW_LINES_GLYPH = 'M8 12L3 4h10z';
export const SORT_GLYPH = { asc: 'M8 4l5 8H3z', desc: 'M8 12L3 4h10z' };

// statusClass maps an engine stage status onto a display class; anything the
// UI does not know (crashed, incompatible, a new engine status) is a warning.
export function statusClass(status) {
  switch (status) {
    case 'ok':
    case 'failed':
    case 'skipped':
    case 'cancelled':
    case 'queued':
    case 'running':
      return status;
    case 'error':
      return 'failed';
    default:
      return 'warning';
  }
}
