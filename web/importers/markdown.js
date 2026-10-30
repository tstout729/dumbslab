// Helpers for exports that are already Markdown (GitHub wikis, docs folders): front matter,
// titles, and rewriting link and image targets outside code. Raw HTML that would run (scripts,
// styles, event handlers, javascript: URLs) is removed; the server sanitizes the rest.

const MASK = '';

/** Splits YAML front matter off the top. Returns { data, body }; data holds simple `key: value` pairs. */
export function splitFrontMatter(md) {
  const m = /^﻿?---[ \t]*\r?\n([\s\S]*?)\r?\n(?:---|\.\.\.)[ \t]*(?:\r?\n|$)/.exec(md);
  if (!m) return { data: {}, body: md };
  const data = {};
  for (const line of m[1].split(/\r?\n/)) {
    const kv = /^([A-Za-z_][\w-]*):[ \t]*(.*)$/.exec(line);
    if (kv) data[kv[1].toLowerCase()] = unquote(kv[2].trim());
  }
  return { data, body: md.slice(m[0].length) };
}

export const unquote = (s) => {
  const t = String(s).trim();
  if (t.length >= 2 && ((t[0] === '"' && t.endsWith('"')) || (t[0] === "'" && t.endsWith("'")))) {
    return t[0] === '"' ? t.slice(1, -1).replace(/\\"/g, '"') : t.slice(1, -1).replace(/''/g, "'");
  }
  return t;
};

/** A leading `# Title` (or setext `Title\n===`): returns { title, body } without it, or null. */
export function leadingTitle(md) {
  const m = /^\s*#[ \t]+(.+?)[ \t]*#*[ \t]*(?:\r?\n|$)/.exec(md) || /^\s*([^\n#>*\-+|`].*?)[ \t]*\r?\n=+[ \t]*(?:\r?\n|$)/.exec(md);
  if (!m) return null;
  const title = m[1].replace(/\\([\\`*_{}[\]()#+\-.!|~<>])/g, '$1').replace(/[*_`]/g, '').trim();
  return title ? { title, body: md.slice(m[0].length).replace(/^\s*\n/, '') } : null;
}

/** Hides fenced code blocks and code spans behind placeholders, so rewrites never touch code. */
function maskCode(md) {
  const saved = [];
  const mask = (s) => `${MASK}${saved.push(s) - 1}${MASK}`;
  const lines = md.split('\n');
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const open = /^ {0,3}(`{3,}|~{3,})/.exec(lines[i]);
    if (!open || (open[1][0] === '`' && lines[i].slice(open[0].length).includes('`'))) {
      out.push(lines[i]);
      continue;
    }
    const fence = open[1];
    let j = i + 1;
    while (j < lines.length && !new RegExp(`^ {0,3}${fence[0] === '`' ? '`' : '~'}{${fence.length},}\\s*$`).test(lines[j])) j++;
    out.push(mask(lines.slice(i, Math.min(j + 1, lines.length)).join('\n')));
    i = j;
  }
  const text = out.join('\n').replace(/(?<!`)(`+)(?!`)(?:(?!\n[ \t]*\n)[\s\S])*?(?<!`)\1(?!`)/g, (m) => mask(m));
  return { text, restore: (s) => s.replace(new RegExp(`${MASK}(\\d+)${MASK}`, 'g'), (_, n) => saved[Number(n)]) };
}

/** Removes HTML that would run: script and style elements, event handlers, javascript: URLs. */
function stripActiveHtml(text) {
  return text
    .replace(/<(script|style|iframe|object|embed)\b[\s\S]*?<\/\1\s*>/gi, '')
    .replace(/<\/?(script|style|iframe|object|embed)\b[^>]*>/gi, '')
    .replace(/(<[a-z][^<>]*?)\s+on[a-z]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, (m, start) => start)
    .replace(/(<[a-z][^<>]*?\s(?:href|src)\s*=\s*["']?)\s*(?:javascript|vbscript|data):[^"'\s>]*/gi, '$1#');
}

const LABEL = String.raw`(?:\\.|[^\\\[\]\n]|\[(?:\\.|[^\\\[\]\n])*\])*`;
const DEST = String.raw`<[^<>\n]*>|(?:\\.|[^\s()\\]|\((?:\\.|[^\s()\\])*\))+`;
const INLINE = new RegExp(String.raw`(!?)\[(${LABEL})\]\([ \t]*(${DEST})([ \t]+(?:"[^"\n]*"|'[^'\n]*'|\([^()\n]*\)))?[ \t]*\)`, 'g');
const REFDEF = /^( {0,3}\[[^\]\n]+\]:[ \t]*)(<[^<>\n]*>|\S+)/gm;
const WIKI = /\[\[([^\]\n]+?)\]\]/g;
const HTML_TARGET = /(<(?:a|img|source|video|audio)\b[^<>]*?\s(?:href|src)\s*=\s*)("([^"]*)"|'([^']*)')/gi;

/**
 * Rewrites link and image targets outside code.
 * hooks.link(target, { image }) → a new target, { text } to replace the whole link, or null to keep it.
 * hooks.wikiLink(inner) → Markdown to put in place of `[[inner]]`, or null to keep it.
 */
export function rewriteMarkdown(md, { link = () => null, wikiLink = () => null } = {}) {
  const { text, restore } = maskCode(md.replace(/\r\n?/g, '\n'));
  const target = (raw) => (raw.startsWith('<') && raw.endsWith('>') ? raw.slice(1, -1) : raw.replace(/\\(.)/g, '$1'));
  const inline = (s) => s.replace(INLINE, (m, bang, label, raw, title = '') => {
    const inner = inline(label);
    const r = link(target(raw), { image: bang === '!', label: inner });
    if (r && typeof r === 'object') return r.text;
    return `${bang}[${inner}](${r ? r : raw}${title})`;
  });
  let out = stripActiveHtml(text);
  out = out.replace(WIKI, (m, inner) => {
    const r = wikiLink(inner.trim());
    return r === null || r === undefined ? m : r;
  });
  out = inline(out);
  out = out.replace(REFDEF, (m, start, raw) => {
    const r = link(target(raw), { image: false });
    return r && typeof r === 'string' ? start + r : m;
  });
  out = out.replace(HTML_TARGET, (m, start, quoted, dq, sq) => {
    const r = link(dq ?? sq, { image: /^<img/i.test(start), html: true });
    return r && typeof r === 'string' ? `${start}"${r.replace(/"/g, '%22')}"` : m;
  });
  return restore(out);
}
