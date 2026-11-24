#!/usr/bin/env node
// Design-token lint: geometry, type and color must come from tokens.css.
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const TOKENS_FILE = 'src/styles/tokens.css';
const LINTED_DIRS = ['src', 'mock'];
const LINTED_EXT = /\.(css|html|svelte)$/;
const RADIUS_VARS = new Set(['--radius', '--radius-ctl']);
const GLOW_TOKENS = new Set(['--glow', '--red-glow']);
const COLOR_ATTRS = new Set(['fill', 'stroke', 'color', 'bgcolor', 'stop-color', 'flood-color']);
const ALLOWED_PX = new Set([0, 1, 2]);
const LENGTH_UNITS = new Set(
  ('em rem ex rex cap rcap ch rch ic ric lh rlh vw vh vi vb vmin vmax svw svh svi svb svmin svmax ' +
    'lvw lvh lvi lvb lvmin lvmax dvw dvh dvi dvb dvmin dvmax cqw cqh cqi cqb cqmin cqmax cm mm q in pc pt')
    .split(' '),
);
const HEX = /#[0-9a-f]{3,8}\b/i;
const RAW_COLOR = /(?<![\w-])(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch|color)\(/i;
const NUMBER = /(?<![\w#.-])([+-]?(?:\d+\.?\d*|\.\d+)(?:e[+-]?\d+)?)([a-z]+|%)?/gi;
const PLAIN_LENGTH = /^([+-]?(?:\d+\.?\d*|\.\d+)(?:e[+-]?\d+)?)(px)?$/i;
const MATH =
  /(?:^|[^\w-])(?:-(?:webkit|moz)-)?(?:calc|min|max|clamp|round|mod|rem|pow|sqrt|hypot|abs|sign|exp|log|sin|cos|tan|asin|acos|atan|atan2)\(/i;
const ROUNDED_SHAPE = /(?<![\w-])(?:circle|ellipse|path|shape)\(|(?<![\w-])round(?![\w-])/i;
const VAR_LITERAL = /^\{\s*(["'`])(var\(--[\w-]+\))\1\s*\}$/;
const CUSTOM_PROP_EXPR = /(^|;)(\s*)(--[\w-]+)(\s*:\s*)(\{[^{}]*\})(\s*)(?=;|$)/g;

const blank = (text) => text.replace(/[^\n]/g, ' ');

function cssStringEnd(css, start) {
  const quote = css[start];
  for (let i = start + 1; i < css.length; i += 1) {
    if (css[i] === '\\') i += 1;
    else if (css[i] === quote) return i + 1;
    // An unescaped newline ends a CSS string, and parsing resumes on that line.
    else if (css[i] === '\n') return i;
  }
  return css.length;
}

function cssUrlEnd(css, start) {
  let i = start + 4;
  while (/\s/.test(css[i] ?? '')) i += 1;
  if (css[i] === '"' || css[i] === "'") i = cssStringEnd(css, i);
  for (; i < css.length; i += 1) {
    if (css[i] === '\\') i += 1;
    else if (css[i] === ')') return i + 1;
  }
  return css.length;
}

// Blanks comments, strings and url() bodies in one left-to-right scan, so none
// can hide the start of another. Offsets are kept for line numbers.
function maskCss(css) {
  let out = '';
  let i = 0;
  while (i < css.length) {
    const ch = css[i];
    let end = -1;
    if (ch === '\\') {
      out += css.slice(i, i + 2);
      i += 2;
      continue;
    }
    if (css.startsWith('/*', i)) {
      const close = css.indexOf('*/', i + 2);
      end = close === -1 ? css.length : close + 2;
    } else if (ch === '"' || ch === "'") {
      end = cssStringEnd(css, i);
    } else if (/^url\($/i.test(css.slice(i, i + 4)) && !/[\w-]/.test(css[i - 1] ?? '')) {
      end = cssUrlEnd(css, i);
    }
    if (end === -1) {
      out += ch;
      i += 1;
    } else {
      out += blank(css.slice(i, end));
      i = end;
    }
  }
  return out;
}

function decodeEscapes(text) {
  return text.replace(/\\(?:([0-9a-f]{1,6})[ \t\r\n\f]?|([^\n]))/gi, (match, hex, literal) => {
    if (literal !== undefined) return literal;
    const code = Number.parseInt(hex, 16);
    return code > 0x10ffff ? '�' : String.fromCodePoint(code);
  });
}

function lengthWithinRadius(part, allowUnitless) {
  const match = part.match(PLAIN_LENGTH);
  if (!match) return false;
  const number = Number(match[1]);
  if (number === 0) return true;
  return (match[2] !== undefined || allowUnitless) && number > 0 && number <= 2;
}

function radiusOk(value) {
  const stripped = value.replace(/var\(\s*(--[\w-]+)\s*\)/g, (match, name) =>
    RADIUS_VARS.has(name) ? '0' : 'invalid',
  );
  return stripped
    .split(/[\s/]+/)
    .filter(Boolean)
    .every((part) => lengthWithinRadius(part, false));
}

function stripFunctionalPseudos(selector) {
  let out = '';
  let i = 0;
  while (i < selector.length) {
    const match = selector.slice(i).match(/^:[a-z-]+\(/i);
    if (!match) {
      out += selector[i];
      i += 1;
      continue;
    }
    let depth = 0;
    let j = i + match[0].length - 1;
    for (; j < selector.length; j += 1) {
      if (selector[j] === '(') depth += 1;
      else if (selector[j] === ')' && --depth === 0) break;
    }
    i = j + 1;
  }
  return out;
}

// True when every selector's subject carries .is-live as an exact, positive class.
function isLiveSelector(selector) {
  if (/:(hover|focus|active)/i.test(selector)) return false;
  return stripFunctionalPseudos(selector)
    .split(',')
    .every((part) => {
      const subject = part.trim().split(/[\s>+~]+/).at(-1) ?? '';
      return /\.is-live(?![\w\u0080-￿-])/.test(subject);
    });
}

function checkLengths(value, report) {
  const scan = value.replace(/--[\w-]+/g, ' ');
  let rawLength = false;
  for (const [raw, number, unit] of scan.matchAll(NUMBER)) {
    const magnitude = Number(number);
    const lower = unit?.toLowerCase();
    if (lower === 'px') {
      if (!ALLOWED_PX.has(magnitude)) report('px', `${raw} is off-scale; use a token from tokens.css`);
      if (magnitude !== 0) rawLength = true;
    } else if (LENGTH_UNITS.has(lower) && magnitude !== 0) {
      report('unit', `${raw} is not a token; define lengths in tokens.css`);
    }
  }
  if (rawLength && MATH.test(scan)) report('px', `arithmetic on a raw length: ${value}`);
}

function checkDeclaration(rawProp, rawValue, rawSelector, isTokens, report) {
  const prop = decodeEscapes(rawProp);
  const value = decodeEscapes(rawValue);
  const selector = decodeEscapes(rawSelector);
  const name = prop.toLowerCase();
  const isRadius =
    /^(-webkit-|-moz-)?border(-[a-z]+)*-radius$/.test(name) ||
    name.startsWith('--radius') ||
    name === 'rx' ||
    name === 'ry';
  if (isRadius && !radiusOk(value)) report('radius', `${prop}: ${value} exceeds 2px`);
  if ((/(^|-)clip-path$/.test(name) || name.startsWith('--')) && ROUNDED_SHAPE.test(value)) {
    report('radius', `${prop}: ${value} is a rounded shape`);
  }

  if (!isTokens) {
    checkLengths(value, report);
    if (HEX.test(value)) report('hex', `raw hex in ${prop}: ${value}`);
    if (RAW_COLOR.test(value)) report('raw-color', `raw color in ${prop}: ${value}`);
    if (GLOW_TOKENS.has(name)) report('shadow', `${prop} may only be defined in tokens.css`);
  }

  if (/(^|-)box-shadow$/.test(name)) {
    if (value !== 'var(--glow)' || !isLiveSelector(selector)) {
      report('shadow', 'box-shadow is only allowed as var(--glow) on .is-live');
    }
  }
  if (name === 'text-shadow' || /drop-shadow\(/i.test(value)) {
    report('shadow', `${prop} is not allowed`);
  }
  if (/(?<![\w-])blur\(/i.test(value)) report('blur', `${prop}: blur is not allowed`);
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
    if (ch === '\\') {
      i += 1;
    } else if (ch === '{') {
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

function skipJsString(src, start) {
  const quote = src[start];
  for (let i = start + 1; i < src.length; i += 1) {
    if (src[i] === '\\') i += 1;
    else if (src[i] === quote) return i + 1;
  }
  return src.length;
}

// Returns the offset just past the balanced {...} that opens at start.
function skipBraces(src, start) {
  let depth = 0;
  for (let i = start; i < src.length; i += 1) {
    const ch = src[i];
    if (ch === '"' || ch === "'" || ch === '`') {
      i = skipJsString(src, i) - 1;
    } else if (ch === '{') {
      depth += 1;
    } else if (ch === '}' && --depth === 0) {
      return i + 1;
    }
  }
  return src.length;
}

function readAttrValue(src, start, isSvelte) {
  const ch = src[start];
  if (ch === '"' || ch === "'") {
    let i = start + 1;
    while (i < src.length && src[i] !== ch) {
      i = isSvelte && src[i] === '{' ? skipBraces(src, i) : i + 1;
    }
    return { value: src.slice(start + 1, i), at: start + 1, end: Math.min(i + 1, src.length) };
  }
  if (isSvelte && ch === '{') {
    const end = skipBraces(src, start);
    return { value: src.slice(start, end), at: start, end };
  }
  let i = start;
  while (i < src.length && !/[\s>]/.test(src[i])) {
    i = isSvelte && src[i] === '{' ? skipBraces(src, i) : i + 1;
  }
  const selfClosed = src[i] === '>' && src[i - 1] === '/';
  return { value: src.slice(start, selfClosed ? i - 1 : i), at: start, end: i };
}

function parseTag(src, start, isSvelte) {
  let i = start + 1;
  while (i < src.length && !/[\s/>]/.test(src[i])) i += 1;
  const name = src.slice(start + 1, i).toLowerCase();
  const attrs = [];
  while (i < src.length) {
    while (i < src.length && /[\s/]/.test(src[i])) i += 1;
    if (i >= src.length) break;
    if (src[i] === '>') return { name, attrs, end: i + 1 };
    if (isSvelte && src[i] === '{') {
      const end = skipBraces(src, i);
      // {style} is shorthand for style={style}.
      if (src.slice(i + 1, end - 1).trim() === 'style') {
        attrs.push({ name: 'style', value: src.slice(i, end), at: i });
      }
      i = end;
      continue;
    }
    const nameStart = i;
    while (i < src.length && !/[\s=>/]/.test(src[i])) i += 1;
    if (i === nameStart) i += 1;
    const attrName = src.slice(nameStart, i).toLowerCase();
    let next = i;
    while (/\s/.test(src[next] ?? '')) next += 1;
    if (src[next] !== '=') {
      attrs.push({ name: attrName, value: null, at: nameStart });
      continue;
    }
    next += 1;
    while (/\s/.test(src[next] ?? '')) next += 1;
    const { value, at, end } = readAttrValue(src, next, isSvelte);
    attrs.push({ name: attrName, value, at });
    i = end;
  }
  return { name, attrs, end: src.length };
}

function lintStyleAttr(attr, ctx) {
  if (attr.value === null) return;
  const resolved = attr.value.replace(
    CUSTOM_PROP_EXPR,
    (match, lead, space, prop, colon, expr, tail) => {
      const literal = expr.match(VAR_LITERAL)?.[2];
      return literal ? `${lead}${space}${prop}${colon}${literal.padEnd(expr.length)}${tail}` : match;
    },
  );
  if (resolved.includes('{')) {
    ctx.report(attr.at, 'dynamic-style', 'dynamic style expressions are not allowed');
    return;
  }
  lintCss(resolved, attr.at, ctx.source, ctx.file, false, ctx.out);
}

function lintStyleDirective(attr, ctx) {
  const prop = attr.name.slice('style:'.length).split('|')[0];
  const literal = attr.value?.includes('{') ? attr.value.match(VAR_LITERAL)?.[2] : attr.value;
  if (!prop || literal === null || literal === undefined) {
    ctx.report(attr.at, 'dynamic-style', `style:${prop} needs a literal value or var(--token)`);
    return;
  }
  lintCss(`${prop}:${literal}`, attr.at, ctx.source, ctx.file, false, ctx.out);
}

function lintAttribute(attr, ctx) {
  if (attr.name === 'style') {
    lintStyleAttr(attr, ctx);
  } else if (attr.name.startsWith('style:')) {
    lintStyleDirective(attr, ctx);
  } else if (attr.value !== null && COLOR_ATTRS.has(attr.name)) {
    if (HEX.test(attr.value)) ctx.report(attr.at, 'hex', `raw hex: ${attr.value}`);
    if (RAW_COLOR.test(attr.value)) ctx.report(attr.at, 'raw-color', `raw color: ${attr.value}`);
  } else if (attr.value !== null && (attr.name === 'rx' || attr.name === 'ry')) {
    if (!lengthWithinRadius(attr.value.trim(), true)) {
      ctx.report(attr.at, 'radius', `${attr.name}="${attr.value}" exceeds 2px`);
    }
  }
}

function lintMarkup(ctx, isSvelte) {
  const { source } = ctx;
  let i = 0;
  while (i < source.length) {
    if (source.startsWith('<!--', i)) {
      const close = source.indexOf('-->', i + 4);
      i = close === -1 ? source.length : close + 3;
    } else if (isSvelte && source[i] === '{') {
      i = skipBraces(source, i);
    } else if (source[i] === '<' && /[a-z]/i.test(source[i + 1] ?? '')) {
      const tag = parseTag(source, i, isSvelte);
      for (const attr of tag.attrs) lintAttribute(attr, ctx);
      i = tag.end;
      if (tag.name === 'style' || tag.name === 'script') {
        const closer = new RegExp(`</${tag.name}\\s*>`, 'i');
        const rest = source.slice(i);
        const found = rest.search(closer);
        const body = found === -1 ? rest : rest.slice(0, found);
        if (tag.name === 'style') lintCss(body, i, source, ctx.file, false, ctx.out);
        i += found === -1 ? rest.length : found + rest.slice(found).match(closer)[0].length;
      }
    } else {
      i += 1;
    }
  }
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

  const report = (offset, rule, message) => out.push({ file, line: lineAt(offset), rule, message });
  lintMarkup({ source, file, out, report }, path.endsWith('.svelte'));
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
