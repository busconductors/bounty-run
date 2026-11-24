// Fixed-row-height windowing for long lists (log lines, findings). Only the
// rows in view (plus overscan) are in the DOM.

// visibleRange returns the [start, end) slice to render. Before the row height
// or viewport is known (first paint, or a DOM without layout) it renders the
// first `fallback` rows.
export function visibleRange({ count, rowH, scrollTop, viewH, overscan = 8, fallback = 80 }) {
  if (!(rowH > 0) || !(viewH > 0)) return { start: 0, end: Math.min(count, fallback) };
  const start = Math.max(0, Math.floor(scrollTop / rowH) - overscan);
  const end = Math.min(count, Math.ceil((scrollTop + viewH) / rowH) + overscan);
  return { start: Math.min(start, end), end };
}

// Svelte action: sets one geometry property (height, top) in px, or clears it
// for null. Row geometry is computed at runtime, so it cannot be a token.
export function px(node, [prop, value]) {
  const apply = ([p, v]) => {
    if (v === null || v === undefined || !Number.isFinite(v)) node.style.removeProperty(p);
    else node.style.setProperty(p, `${v}px`);
  };
  apply([prop, value]);
  return { update: apply };
}

// The index of the first item whose seq is greater than seq, in a list sorted
// by ascending seq.
export function firstAfter(list, seq) {
  let lo = 0;
  let hi = list.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (list[mid].seq > seq) hi = mid;
    else lo = mid + 1;
  }
  return lo;
}

// rowHeight reads the rendered height of a row inside container (0 if none).
export function rowHeight(container, selector) {
  const row = container?.querySelector(selector);
  return row ? row.getBoundingClientRect().height : 0;
}
