#!/usr/bin/env node
// Design-token lint: geometry, type and color must come from tokens.css.
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const TOKENS_FILE = 'src/styles/tokens.css';
const LINTED_DIRS = ['src', 'mock'];
const LINTED_EXT = /\.(css|html|svelte)$/;
const RADIUS_VARS = new Set(['--radius', '--radius-ctl']);
const ALLOWED_PX = new Set([0, 1, 2]);
const HEX = /#[0-9a-f]{3,8}\b/i;
const RAW_COLOR = /(?<![\w-])(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch|color)\(/i;
const PX = /(?<![\w-])(-?\d*\.?\d+)px\b/gi;
const COLOR_ATTR = /\s(?:fill|stroke|color|bgcolor|stop-color|flood-color)\s*=\s*("[^"]*"|'[^']*')/gi;
const STYLE_ATTR = /\sstyle\s*=\s*("[^"]*"|'[^']*')/gi;
const STYLE_BLOCK = /<style\b[^>]*>([\s\S]*?)(?:<\/style\s*>|$)/gi;

const blank = (text) => text.replace(/[^\n]/g, ' ');

// Blanks comments, strings and url() bodies, keeping offsets for line numbers.
function maskCss(css) {
  return css
    .replace(/\/\*[\s\S]*?(?:\*\/|$)/g, blank)
    .replace(/"(?:[^"\\]|\\[\s\S])*"|'(?:[^'\\]|\\[\s\S])*'/g, blank)
    .replace(/url\([^)]*\)/gi, blank);
}

function radiusOk(value) {
  const stripped = value.replace(/var\(\s*(--[\w-]+)\s*\)/g, (match, name) =>
    RADIUS_VARS.has(name) ? '0' : 'invalid',
  );
  return stripped
    .split(/[\s/]+/)
    .filter(Boolean)
    .every((part) => {
      if (part === '0') return true;
      const px = part.match(/^(\d*\.?\d+)px$/i);
      return px !== null && Number(px[1]) <= 2;
    });
}

const isLiveSelector = (selector) =>
  selector
    .split(',')
    .every((part) => /\.is-live\b/.test(part) && !/:(hover|focus|active)/.test(part));

function checkDeclaration(prop, value, selector, isTokens, report) {
  const name = prop.toLowerCase();
  const isRadius = /^(-webkit-|-moz-)?border(-[a-z]+)*-radius$/.test(name) || name.startsWith('--radius');
  if (isRadius && !radiusOk(value)) report('radius', `${prop}: ${value} exceeds 2px`);

  if (!isTokens) {
    for (const [raw, number] of value.matchAll(PX)) {
      if (!ALLOWED_PX.has(Number(number)) || number.startsWith('-')) {
        report('px', `${raw} is off-scale; use a token from tokens.css`);
      }
    }
    if (HEX.test(value)) report('hex', `raw hex in ${prop}: ${value}`);
    if (RAW_COLOR.test(value)) report('raw-color', `raw color in ${prop}: ${value}`);
  }

  if (/(^|-)box-shadow$/.test(name)) {
    if (value !== 'var(--glow)' || !isLiveSelector(selector)) {
      report('shadow', 'box-shadow is only allowed as var(--glow) on .is-live');
    }
  }
  if (name === 'text-shadow' || /drop-shadow\(/i.test(value)) {
    report('shadow', `${prop} is not allowed`);
  }
  if (name.endsWith('backdrop-filter')) report('backdrop-filter', `${prop} is not allowed`);
  if (/gradient\(/i.test(value)) {
    const isHatch = isTokens && name === '--hatch' && /^repeating-linear-gradient\(/i.test(value);
    if (!isHatch) report('gradient', `gradient in ${prop} is not allowed`);
  }
}

function lintCss(css, baseOffset, source, file, isTokens, out) {
  const masked = maskCss(css);
  const stack = [];
  let start = 0;
  const flush = (end) => {
    const chunk = masked.slice(start, end);
    const colon = chunk.indexOf(':');
    if (colon === -1) return;
    const prop = chunk.slice(0, colon).trim();
    const value = chunk.slice(colon + 1).trim();
    if (!prop || !value || prop.startsWith('@')) return;
    const at = baseOffset + start + (chunk.length - chunk.trimStart().length);
    const line = source.slice(0, at).split('\n').length;
    const selector = stack.at(-1) ?? '';
    checkDeclaration(prop, value, selector, isTokens, (rule, message) =>
      out.push({ file, line, rule, message }),
    );
  };
  for (let i = 0; i < masked.length; i += 1) {
    const ch = masked[i];
    if (ch === '{') {
      stack.push(masked.slice(start, i).trim());
      start = i + 1;
    } else if (ch === ';') {
      flush(i);
      start = i + 1;
    } else if (ch === '}') {
      flush(i);
      stack.pop();
      start = i + 1;
    }
  }
  flush(masked.length);
}

export function lintSource(source, file) {
  const path = file.split(sep).join('/');
  const isTokens = path === TOKENS_FILE;
  const out = [];
  const lineAt = (offset) => source.slice(0, offset).split('\n').length;

  for (const match of source.matchAll(/\{\s*@html\b/g)) {
    out.push({ file, line: lineAt(match.index), rule: 'raw-html', message: '{@html} is not allowed' });
  }

  if (path.endsWith('.css')) {
    lintCss(source, 0, source, file, isTokens, out);
    return out;
  }

  for (const match of source.matchAll(STYLE_BLOCK)) {
    const bodyAt = match.index + match[0].indexOf(match[1], match[0].indexOf('>') + 1);
    lintCss(match[1], bodyAt, source, file, false, out);
  }
  // Attributes are read from markup only, so page text is never treated as CSS.
  const markup = source.replace(STYLE_BLOCK, blank);
  for (const match of markup.matchAll(/<[a-z][^<>]*>/gi)) {
    for (const attr of match[0].matchAll(STYLE_ATTR)) {
      const at = match.index + attr.index + attr[0].indexOf(attr[1]) + 1;
      lintCss(attr[1].slice(1, -1), at, source, file, false, out);
    }
    for (const attr of match[0].matchAll(COLOR_ATTR)) {
      const value = attr[1].slice(1, -1);
      const line = lineAt(match.index + attr.index);
      if (HEX.test(value)) out.push({ file, line, rule: 'hex', message: `raw hex: ${value}` });
      if (RAW_COLOR.test(value)) out.push({ file, line, rule: 'raw-color', message: `raw color: ${value}` });
    }
  }
  return out;
}

function walk(dir, found) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch (error) {
    if (error.code === 'ENOENT') return;
    throw error;
  }
  for (const entry of entries) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== 'node_modules' && entry.name !== 'dist') walk(path, found);
    } else if (LINTED_EXT.test(entry.name)) {
      found.push(path);
    }
  }
}

export function lintTree(root) {
  const paths = [];
  for (const dir of LINTED_DIRS) walk(join(root, dir), paths);
  const files = paths.map((path) => relative(root, path).split(sep).join('/')).sort();
  const violations = files.flatMap((file) => lintSource(readFileSync(join(root, file), 'utf8'), file));
  return { files, violations };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..');
  const { files, violations } = lintTree(root);
  for (const v of violations) console.error(`${v.file}:${v.line} [${v.rule}] ${v.message}`);
  if (violations.length > 0) {
    console.error(`token lint: ${violations.length} violation(s) in ${files.length} files`);
    process.exit(1);
  }
  console.log(`token lint: ${files.length} files clean`);
}
