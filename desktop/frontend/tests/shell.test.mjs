import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { DEFAULT_VIEW, VIEWS } from '../src/lib/shell/views.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');

const sources = (dir) =>
  readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return sources(path);
    return /\.(js|mjs|ts|svelte)$/.test(entry.name) ? [path] : [];
  });

test('rail lists the six spec views in order', () => {
  assert.deepEqual(
    VIEWS.map((view) => view.label),
    ['Launch', 'Monitor', 'Runs', 'Findings', 'Doctor', 'Settings'],
  );
  assert.equal(new Set(VIEWS.map((view) => view.id)).size, 6);
  assert.equal(DEFAULT_VIEW, 'launch');
});

test('only src/lib/bridge imports the Wails runtime', () => {
  const offenders = sources(root)
    .map((path) => relative(root, path).split(sep).join('/'))
    .filter((path) => !path.startsWith('lib/bridge/'))
    .filter((path) => readFileSync(join(root, path), 'utf8').includes('@wailsio/runtime'));
  assert.deepEqual(offenders, []);
});
