// Converts HTML (an inert DOM from DOMParser, never a live page) to Markdown. Only structure and
// text come through: scripts, styles, frames, forms and every attribute other than link and
// image targets are dropped, and text is escaped so it can't become Markdown or HTML. The few
// HTML tags it writes (<details>, <sup>, <br> in table cells) are built here, never copied.
//
// It reads nodes through nodeType, localName, childNodes, nodeValue and getAttribute only, so
// tests can run it on a small parsed tree without a browser.

const BREAK = '\uE000';
// Budgets that keep the output close to the input's size whatever the HTML says: spans can't
// stretch a table past these, and structures nested deeper than this are flattened.
const MAX_TABLE_COLUMNS = 64;
const MAX_TABLE_CELLS = 50_000;
const MAX_DEPTH = 12;

const SKIP = new Set([
  'script', 'style', 'noscript', 'template', 'head', 'title', 'meta', 'link', 'base', 'svg', 'math', 'canvas', 'button',
  'input', 'select', 'option', 'textarea', 'object', 'embed', 'map', 'area', 'colgroup', 'col', 'param', 'source', 'track',
]);

const BLOCK = new Set([
  'address', 'article', 'aside', 'blockquote', 'body', 'caption', 'center', 'dd', 'details', 'dialog', 'div', 'dl', 'dt',
  'fieldset', 'figcaption', 'figure', 'footer', 'form', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'header', 'hgroup', 'hr',
  'html', 'iframe', 'legend', 'li', 'main', 'nav', 'ol', 'p', 'pre', 'section', 'summary', 'table', 'tbody', 'td', 'tfoot',
  'th', 'thead', 'tr', 'ul', 'video', 'audio',
]);

// ---------------------------------------------------------------------------
// Tree helpers, shared with the converters.

export const kids = (n) => Array.from((n && n.childNodes) || []);
export const isEl = (n) => n && n.nodeType === 1;
export const tag = (n) => (isEl(n) ? String(n.localName || n.nodeName || '').toLowerCase() : '');
export const attr = (n, name) => (isEl(n) && n.getAttribute(name)) || '';
export const classes = (n) => attr(n, 'class').split(/\s+/).filter(Boolean);
export const hasClass = (n, c) => classes(n).includes(c);
export const hasClassPrefix = (n, prefix) => classes(n).some((c) => c.startsWith(prefix));

/** The first element (depth first, including `root`) that `pred` accepts. */
export function find(root, pred) {
  if (!root) return null;
  if (isEl(root) && pred(root)) return root;
  for (const c of kids(root)) {
    const f = find(c, pred);
    if (f) return f;
  }
  return null;
}

/** Every element under `root` (including it) that `pred` accepts, in document order. */
export function findAll(root, pred, out = []) {
  if (!root) return out;
  if (isEl(root) && pred(root)) out.push(root);
  for (const c of kids(root)) findAll(c, pred, out);
  return out;
}

export const byId = (root, id) => find(root, (n) => attr(n, 'id') === id);

/** Text content with collapsed whitespace (or as written, with `raw`). */
export function textOf(n, raw = false) {
  let s = '';
  const walk = (x) => {
    if (x.nodeType === 3) s += x.nodeValue;
    else if (isEl(x) && !SKIP.has(tag(x))) {
      if (tag(x) === 'br') s += ' ';
      kids(x).forEach(walk);
    } else if (x.nodeType === 9 || x.nodeType === 11) kids(x).forEach(walk);
  };
  walk(n);
  return raw ? s : s.replace(/[\s\u00a0]+/g, ' ').trim();
}

// ---------------------------------------------------------------------------
// Escaping.

/** Escapes text so Markdown shows it literally. */
export function escapeText(s) {
  return String(s)
    .replace(/[\\`*[\]<~|]/g, (c) => '\\' + c)
    .replace(/(^|[^\p{L}\p{N}])_|_(?=$|[^\p{L}\p{N}])/gu, (m) => m.replace('_', '\\_'))
    .replace(/&(?=#?[a-z0-9]+;)/gi, '&amp;');
}

/** Escapes what would start a block at the beginning of a line. */
function escapeLineStart(line) {
  return line
    .replace(/^(\s*)(#{1,6})(?=\s|$)/, '$1\\$2')
    .replace(/^(\s*)>/, '$1\\>')
    .replace(/^(\s*)([-+*])(?=\s)/, '$1\\$2')
    .replace(/^(\s*)(\d+)([.)])(?=\s|$)/, '$1$2\\$3')
    .replace(/^(\s*)(=+|-{3,})\s*$/, (m, sp, run) => sp + '\\' + run);
}

/** A link or image destination: spaces, parentheses and angle brackets percent-encoded. */
export const dest = (url) => String(url).trim().replace(/[ ()<>]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());

const longestRun = (s, ch) => {
  let best = 0;
  let cur = 0;
  for (const c of s) {
    cur = c === ch ? cur + 1 : 0;
    if (cur > best) best = cur;
  }
  return best;
};

function codeSpan(text) {
  const t = text.replace(/\n/g, ' ');
  if (!t.trim()) return '';
  const ticks = '`'.repeat(longestRun(t, '`') + 1);
  const pad = t.startsWith('`') || t.endsWith('`') || (t.startsWith(' ') && t.endsWith(' ')) ? ' ' : '';
  return ticks + pad + t + pad + ticks;
}

/** Wraps inline Markdown in a marker, keeping surrounding spaces outside it. */
function wrap(marker, inner, close = marker) {
  const m = /^(\s*)([\s\S]*?)(\s*)$/.exec(inner);
  if (!m[2]) return inner;
  return m[1] + marker + m[2] + close + m[3];
}

/** Collapses an inline run into one paragraph's Markdown. */
function finishInline(s, breakAs = '\\\n') {
  const t = s.replace(/[ \t\n\r\f\u00a0]+/g, ' ')
    .replace(new RegExp(` ?${BREAK} ?`, 'g'), BREAK)
    .replace(new RegExp(`^[ ${BREAK}]+|[ ${BREAK}]+$`, 'g'), '');
  if (!t) return '';
  return t.split(BREAK).map((line) => (breakAs === '\\\n' ? escapeLineStart(line) : line)).join(breakAs);
}

const indentLines = (text, first, rest) => text.split('\n').map((l, i) => (i === 0 ? first + l : l ? rest + l : '')).join('\n');
const quote = (text) => text.split('\n').map((l) => (l ? '> ' + l : '>')).join('\n');
const isListBlock = (b) => /^([-*+]|\d+[.)]) /.test(b);

// ---------------------------------------------------------------------------
// Callouts. Confluence's info, tip, note and warning macros and its editor's panels, Guru's
// callouts and the generic `alert` classes become `> [!KIND]` callouts.

const KIND_BY_NAME = {
  info: 'NOTE', information: 'NOTE', note: 'NOTE', primary: 'NOTE',
  tip: 'TIP', success: 'TIP',
  important: 'IMPORTANT', custom: 'IMPORTANT',
  warning: 'WARNING', warn: 'WARNING', caution: 'CAUTION', error: 'CAUTION', danger: 'CAUTION',
};

/** The callout kind an element stands for, or null. */
export function calloutKind(el) {
  if (hasClass(el, 'confluence-information-macro')) {
    // Confluence's legacy macros: note is yellow and warning red, so they map one step up.
    const legacy = { information: 'NOTE', tip: 'TIP', note: 'WARNING', warning: 'CAUTION' };
    for (const c of classes(el)) {
      const m = /^confluence-information-macro-(\w+)$/.exec(c);
      if (m && legacy[m[1]]) return legacy[m[1]];
    }
    return 'NOTE';
  }
  const panelType = attr(el, 'data-panel-type') || attr(el, 'data-ghq-card-content-callout-type') || attr(el, 'data-callout-type');
  if (panelType) return KIND_BY_NAME[panelType.toLowerCase()] || 'NOTE';
  for (const c of classes(el)) {
    const m = /^(?:ghq-card-content__callout--|callout-|alert-)(\w+)$/.exec(c);
    if (m && KIND_BY_NAME[m[1].toLowerCase()]) return KIND_BY_NAME[m[1].toLowerCase()];
  }
  if (hasClass(el, 'ghq-card-content__callout') || hasClass(el, 'callout')) return 'NOTE';
  return null;
}

// ---------------------------------------------------------------------------

const defaultHooks = {
  link: (href) => (/^(https?:|mailto:|tel:)/i.test(href) ? { url: href } : null),
  image: (src) => (/^https:/i.test(src) ? { url: src } : null),
};

/**
 * Converts an element (or document) to Markdown.
 * hooks.link(href, el) → { url } to link, { text } to write instead, or null to keep just the text.
 * hooks.image(src, el) → { url, alt? }, { text }, or null to drop it.
 */
export function htmlToMarkdown(root, hooks = {}) {
  const c = new Converter({ ...defaultHooks, ...hooks });
  const md = c.blocks(root, {}).join('\n\n');
  return md.replace(/\n{3,}/g, '\n\n').trim();
}

class Converter {
  constructor(hooks) {
    this.hooks = hooks;
  }

  skip(el) {
    if (SKIP.has(tag(el)) || el.getAttribute('hidden') !== null || attr(el, 'aria-hidden') === 'true') return true;
    // Confluence: icons, anchors and the table of contents (posts have their own outline).
    return hasClass(el, 'confluence-information-macro-icon') || hasClass(el, 'confluence-anchor-link')
      || hasClass(el, 'toc-macro') || hasClass(el, 'client-side-toc-macro') || hasClass(el, 'aui-icon')
      || /display:\s*none/i.test(attr(el, 'style'));
  }

  isBlock(el) {
    return BLOCK.has(tag(el)) || calloutKind(el) !== null;
  }

  /** Block Markdown chunks for a container's children. */
  blocks(parent, st) {
    const out = [];
    let run = '';
    const flush = () => {
      const p = finishInline(run, st.cell ? '<br>' : '\\\n');
      if (p) out.push(p);
      run = '';
    };
    for (const child of kids(parent)) {
      if (child.nodeType === 3) {
        run += st.pre ? child.nodeValue : escapeText(child.nodeValue);
        continue;
      }
      if (child.nodeType === 9 || child.nodeType === 11) {
        flush();
        out.push(...this.blocks(child, st));
        continue;
      }
      if (!isEl(child) || this.skip(child)) continue;
      if (this.isBlock(child)) {
        flush();
        out.push(...this.block(child, st).filter(Boolean));
      } else {
        run += this.inline(child, st);
      }
    }
    flush();
    return out;
  }

  block(el, st) {
    const t = tag(el);
    const kind = calloutKind(el);
    if (kind) return this.callout(el, kind, st);
    if (hasClass(el, 'expand-container')) return this.expand(el, st);
    // Panels box their content; the code macro is a panel too, but its code block says enough.
    if (hasClass(el, 'panel') && !hasClass(el, 'code') && !st.cell) return this.panel(el, st);
    if (hasClass(el, 'codeHeader') || hasClass(el, 'panelHeader')) {
      const title = textOf(el);
      return title ? [`**${escapeText(title)}**`] : [];
    }
    switch (t) {
      case 'p': case 'legend': return this.blocks(el, st);
      case 'caption': case 'dt': {
        const p = finishInline(this.inlineChildren(el, st), st.cell ? '<br>' : '\\\n');
        return p ? [wrap('**', p)] : [];
      }
      case 'h1': case 'h2': case 'h3': case 'h4': case 'h5': case 'h6': {
        const text = finishInline(this.inlineChildren(el, st), ' ');
        if (!text) return [];
        return [st.cell ? wrap('**', text) : '#'.repeat(Number(t[1])) + ' ' + text];
      }
      case 'ul': case 'ol': return this.list(el, st);
      case 'li': return this.list({ childNodes: [el], nodeType: 1, localName: 'ul', getAttribute: () => null }, st);
      case 'pre': return this.pre(el, st);
      case 'blockquote': {
        const inner = this.blocks(el, down(st));
        if (!inner.length) return [];
        return st.cell || deep(st) ? inner : [quote(inner.join('\n\n'))];
      }
      case 'table': return this.table(el, st);
      case 'hr': return st.cell ? [] : ['---'];
      case 'details': return this.details(el, st);
      case 'figcaption': {
        const p = finishInline(this.inlineChildren(el, st), ' ');
        return p ? [wrap('*', p)] : [];
      }
      case 'iframe': case 'video': case 'audio': {
        // On a line of its own, a link to YouTube, Loom, Figma and the like becomes an embed.
        const src = attr(el, 'src') || attr(find(el, (n) => tag(n) === 'source'), 'src');
        const r = /^https?:/i.test(src) ? this.hooks.link(src, el) : null;
        const url = r && r.url ? r.url.trim() : '';
        return /^https?:\/\/[^\s<>]+$/i.test(url) ? [`<${url}>`] : [];
      }
      case 'tr': case 'td': case 'th': case 'tbody': case 'thead': case 'tfoot':
        return this.blocks(el, st);
      default:
        return this.blocks(el, st);
    }
  }

  inlineChildren(el, st) {
    let s = '';
    for (const c of kids(el)) {
      if (c.nodeType === 3) s += st.pre ? c.nodeValue : escapeText(c.nodeValue);
      else if (isEl(c) && !this.skip(c)) {
        // Blocks nested in inline context (a <div> in a <span>) still read as separate lines.
        s += this.isBlock(c) ? BREAK + this.block(c, { ...st, cell: true }).join(BREAK) + BREAK : this.inline(c, st);
      }
    }
    return s;
  }

  inline(el, st) {
    const t = tag(el);
    if (hasClass(el, 'status-macro') || hasClass(el, 'aui-lozenge')) return codeSpan(textOf(el));
    switch (t) {
      case 'br': return BREAK;
      case 'wbr': return '';
      case 'strong': case 'b':
        return st.strong ? this.inlineChildren(el, st) : wrap('**', this.inlineChildren(el, { ...st, strong: true }));
      case 'em': case 'i': case 'cite': case 'dfn': case 'var':
        return st.em ? this.inlineChildren(el, st) : wrap('*', this.inlineChildren(el, { ...st, em: true }));
      case 's': case 'del': case 'strike':
        return st.strike ? this.inlineChildren(el, st) : wrap('~~', this.inlineChildren(el, { ...st, strike: true }));
      case 'code': case 'tt': case 'kbd': case 'samp': return codeSpan(textOf(el));
      case 'sup': case 'sub': case 'u': case 'ins': case 'mark': {
        const inner = this.inlineChildren(el, st);
        const name = t === 'ins' ? 'u' : t;
        return inner.trim() ? wrap(`<${name}>`, inner, `</${name}>`) : inner;
      }
      case 'a': return this.link(el, st);
      case 'img': return this.image(el);
      default: return this.inlineChildren(el, st);
    }
  }

  link(el, st) {
    const href = attr(el, 'href');
    // Mentions of Confluence people link to profiles in the old site; keep the name.
    const mention = hasClass(el, 'confluence-userlink') || hasClass(el, 'user-mention');
    const inner = this.inlineChildren(el, { ...st, link: true });
    if (!href || st.link || mention) return inner;
    const r = this.hooks.link(href, el);
    if (!r) return inner;
    if (r.text !== undefined) return r.text;
    const m = /^(\s*)([\s\S]*?)(\s*)$/.exec(inner.replace(new RegExp(BREAK, 'g'), ' '));
    const label = m[2] || escapeText(r.label || href);
    return `${m[1]}[${label}](${dest(r.url)})${m[3]}`;
  }

  image(el) {
    // Emoticons: their emoji, or their text like (tick).
    if (hasClass(el, 'emoticon') || hasClassPrefix(el, 'emoticon-')) {
      return escapeText(attr(el, 'data-emoji-fallback') || attr(el, 'alt'));
    }
    const src = attr(el, 'data-image-src') || attr(el, 'src');
    if (!src) return '';
    const r = this.hooks.image(src, el);
    if (!r) return '';
    if (r.text !== undefined) return r.text;
    const alt = r.alt !== undefined ? r.alt : attr(el, 'alt') || attr(el, 'title') || '';
    return `![${escapeText(alt.replace(/\s+/g, ' ').trim())}](${dest(r.url)})`;
  }

  list(el, st) {
    // Lists nested past the limit read as text, so indentation can't multiply the size.
    if (deep(st)) {
      const text = escapeText(textOf(el));
      return text ? [text] : [];
    }
    const ordered = tag(el) === 'ol';
    let n = Number.parseInt(attr(el, 'start'), 10);
    if (!Number.isFinite(n) || n < 0) n = 1;
    const tasks = hasClass(el, 'inline-task-list');
    const items = [];
    for (const child of kids(el)) {
      if (isEl(child) && tag(child) === 'li') {
        items.push(this.item(child, ordered ? `${n++}. ` : '- ', tasks, st));
      } else if (isEl(child) && (tag(child) === 'ul' || tag(child) === 'ol') && items.length) {
        // A list directly inside a list (invalid, but common) belongs to the item before it.
        const nested = this.list(child, st).join('\n');
        const pad = items[items.length - 1].pad;
        items[items.length - 1].text += '\n' + indentLines(nested, pad, pad);
      } else if (isEl(child) && !this.skip(child)) {
        const text = this.blocks({ childNodes: [child], nodeType: 1 }, st).join('\n\n');
        if (text) items.push({ text: indentLines(text, '- ', '  '), pad: '  ' });
      }
    }
    if (!items.length) return [];
    if (st.cell) return [items.map((i) => i.text.replace(/\n\s*/g, ' ')).join('<br>')];
    const loose = items.some((i) => /\n\n/.test(i.text));
    return [items.map((i) => i.text).join(loose ? '\n\n' : '\n')];
  }

  item(li, marker, tasks, st) {
    let check = tasks ? hasClass(li, 'checked') : null;
    const box = find(li, (x) => tag(x) === 'input' && attr(x, 'type').toLowerCase() === 'checkbox');
    if (box && check === null) check = box.getAttribute('checked') !== null;
    const prefix = marker + (check === null ? '' : check ? '[x] ' : '[ ] ');
    const pad = ' '.repeat(marker.length);
    const blocks = this.blocks(li, down(st));
    let text = '';
    blocks.forEach((b, i) => {
      if (i > 0) text += isListBlock(b) && !isListBlock(blocks[i - 1]) ? '\n' : '\n\n';
      text += b;
    });
    return { text: indentLines(text, prefix, pad).replace(/\s+$/, ''), pad };
  }

  pre(el, st) {
    let text = '';
    // Guru writes one <code> per line, with nothing between them.
    const lines = kids(el).filter((x) => tag(x) === 'code');
    if (lines.length > 1 && kids(el).every((x) => tag(x) === 'code' || (x.nodeType === 3 && !x.nodeValue.trim()))) {
      text = lines.map((l) => textOf({ childNodes: [l], nodeType: 11 }, true)).join('\n');
    }
    const walk = (x) => {
      if (x.nodeType === 3) text += x.nodeValue;
      else if (isEl(x) && !SKIP.has(tag(x))) {
        if (tag(x) === 'br') text += '\n';
        else kids(x).forEach(walk);
        if (tag(x) === 'div' || tag(x) === 'p') text = text.replace(/\n?$/, '\n');
      }
    };
    if (!text) kids(el).forEach(walk);
    text = text.replace(/\u00a0/g, ' ').replace(/^\n/, '').replace(/\s+$/, '');
    if (!text) return [];
    if (st.cell) return [text.split('\n').map(codeSpan).filter(Boolean).join('<br>')];
    const fence = '`'.repeat(Math.max(3, longestRun(text, '`') + 1));
    return [`${fence}${codeLanguage(el)}\n${text}\n${fence}`];
  }

  callout(el, kind, st) {
    // Confluence puts the optional title in `.title` and the text in `...-macro-body`.
    const titleEl = find(el, (x) => x !== el && (hasClass(x, 'title') || hasClass(x, 'panelHeader') || hasClass(x, 'ghq-card-content__callout-title')));
    const bodyEl = find(el, (x) => hasClass(x, 'confluence-information-macro-body') || hasClass(x, 'panelContent')) || el;
    const title = titleEl ? textOf(titleEl) : '';
    const body = this.blocks(bodyEl === el && titleEl ? withoutNode(el, titleEl) : bodyEl, down(st));
    const parts = [title ? `**${escapeText(title)}**` : '', ...body].filter(Boolean);
    if (!parts.length) return [];
    if (st.cell) return [parts.join('<br>')];
    if (deep(st)) return parts;
    return [`> [!${kind}]\n` + quote(parts.join('\n\n'))];
  }

  panel(el, st) {
    const header = find(el, (x) => hasClass(x, 'panelHeader'));
    const content = find(el, (x) => hasClass(x, 'panelContent')) || (header ? withoutNode(el, header) : el);
    const parts = [header ? `**${escapeText(textOf(header))}**` : '', ...this.blocks(content, down(st))].filter(Boolean);
    if (deep(st)) return parts;
    return parts.length ? [quote(parts.join('\n\n'))] : [];
  }

  expand(el, st) {
    const control = find(el, (x) => hasClass(x, 'expand-control-text'));
    const content = find(el, (x) => hasClass(x, 'expand-content'));
    const summary = control ? textOf(control) : 'Details';
    const body = content ? this.blocks(content, down(st)) : [];
    return this.toggle(summary, body, st);
  }

  details(el, st) {
    const sum = kids(el).find((x) => tag(x) === 'summary');
    const summary = sum ? textOf(sum) : 'Details';
    return this.toggle(summary, this.blocks(sum ? withoutNode(el, sum) : el, down(st)), st);
  }

  toggle(summary, body, st) {
    if (st.cell) return [[escapeText(summary), ...body].join('<br>')];
    if (deep(st)) return [`**${escapeText(summary)}**`, ...body];
    const s = escapeHtml(summary || 'Details');
    return [`<details>\n<summary>${s}</summary>\n\n${body.join('\n\n')}\n\n</details>`];
  }

  table(el, st) {
    const rows = [];
    const collect = (node) => {
      for (const c of kids(node)) {
        const t = tag(c);
        if (t === 'tr') rows.push(c);
        else if (t === 'thead' || t === 'tbody' || t === 'tfoot') collect(c);
      }
    };
    collect(el);
    if (!rows.length) return [];
    if (deep(st)) {
      const text = escapeText(textOf(el));
      return text ? [text] : [];
    }
    const cellSt = { ...down(st), cell: true };
    const written = rows.map((tr) => kids(tr).filter((td) => tag(td) === 'td' || tag(td) === 'th').map((td) => ({
      text: this.blocks(td, cellSt).join('<br>').replace(/\n+/g, ' ').replace(/(?<!\\)\|/g, '\\|').trim(),
      colspan: Math.min(50, Math.max(1, Number.parseInt(attr(td, 'colspan'), 10) || 1)),
      rowspan: Math.min(500, Math.max(1, Number.parseInt(attr(td, 'rowspan'), 10) || 1)),
    })));
    if (written.every((r) => r.every((c) => !c.text))) return [];
    // Spans may add empty cells, but not many more than the table spells out.
    const allowed = Math.min(MAX_TABLE_CELLS, Math.max(2000, 4 * written.reduce((n, r) => n + r.length, 0)));
    // Lay the cells out with their spans, unless that would make a table too large to keep as one:
    // spans could otherwise turn a few kilobytes of HTML into megabytes of empty cells.
    const grid = [];
    const spans = [];
    let cells = 0;
    let fits = true;
    for (const r of written) {
      const row = [];
      let col = 0;
      const next = () => {
        while (spans[col] && spans[col].left > 0 && col < MAX_TABLE_COLUMNS) {
          row.push('');
          spans[col].left--;
          col++;
        }
      };
      for (const c of r) {
        next();
        for (let k = 0; k < c.colspan && fits; k++) {
          row.push(k === 0 ? c.text : '');
          spans[col] = { left: c.rowspan - 1 };
          col++;
          fits = col <= MAX_TABLE_COLUMNS;
        }
        if (!fits) break;
      }
      if (fits) next();
      cells += row.length;
      if (!fits || cells > allowed) {
        fits = false;
        break;
      }
      grid.push(row);
    }
    const width = fits ? Math.max(...grid.map((r) => r.length)) : 0;
    if (!fits || width * grid.length > allowed) {
      // Too big for a Markdown table: one line per row with just the cells it has.
      const lines = written.map((r) => r.map((c) => c.text).filter(Boolean).join(' · ')).filter(Boolean);
      return st.cell ? [lines.join('<br>')] : [lines.map((l) => `- ${l}`).join('\n')];
    }
    if (st.cell) return [grid.map((r) => r.filter(Boolean).join(' · ')).filter(Boolean).join('<br>')];
    const line = (r) => '| ' + Array.from({ length: width }, (_, i) => r[i] || '').join(' | ') + ' |';
    const out = [line(grid[0]), '|' + ' --- |'.repeat(width), ...grid.slice(1).map(line)];
    return [out.join('\n')];
  }
}

const deep = (st) => (st.depth || 0) >= MAX_DEPTH;
const down = (st) => ({ ...st, depth: (st.depth || 0) + 1 });

/** A shallow stand-in for `el` without one of its children. */
function withoutNode(el, drop) {
  return { nodeType: 1, localName: 'div', childNodes: kids(el).filter((c) => c !== drop), getAttribute: () => null };
}

const escapeHtml = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

/** A code block's language from Confluence's brush, or a `language-x` class. */
export function codeLanguage(el) {
  const guru = attr(el, 'data-ghq-code-block-prism');
  if (guru && /^[\w+#.-]{1,30}$/.test(guru)) return guru.toLowerCase();
  const params = attr(el, 'data-syntaxhighlighter-params') || attr(find(el, (x) => attr(x, 'data-syntaxhighlighter-params')), 'data-syntaxhighlighter-params');
  const brush = /brush:\s*([\w+#.-]+)/i.exec(params);
  let lang = brush ? brush[1] : '';
  if (!lang) {
    const code = find(el, (x) => tag(x) === 'code') || el;
    for (const node of [el, code]) {
      const c = classes(node).find((x) => /^(language|lang)-/.test(x));
      if (c) {
        lang = c.replace(/^(language|lang)-/, '');
        break;
      }
    }
  }
  lang = lang.toLowerCase();
  if (lang === 'none' || lang === 'text' || lang === 'plain') return '';
  return /^[\w+#.-]{1,30}$/.test(lang) ? lang : '';
}
