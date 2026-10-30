// A GitHub wiki: a zip of the cloned wiki repository (`git clone https://github.com/OWNER/REPO.wiki.git`).
// Every Markdown page becomes a post titled the way GitHub shows it (`Getting-Started.md` is
// "Getting Started"). `_Sidebar.md` decides topics when it groups pages (headings, or list items
// with nested items); folders decide them otherwise. `_Sidebar`, `_Footer` and `_Header` aren't
// posts. `[[Wiki links]]`, links to page names and images in the repository are rewritten.

import { PlanBuilder, MAX_SOURCE_BYTES } from './plan.js';
import { rewriteMarkdown } from './markdown.js';
import { MARKDOWN_EXT } from './markdown-folder.js';
import { basename, dirname, extname, isImagePath, localTarget, resolvePath, stripExt, titleFromFileName } from './paths.js';
import { formatSize } from './zip.js';

const SPECIAL = new Set(['_sidebar', '_footer', '_header']);
// Other markups GitHub wikis render, which DumbSlab can't.
const OTHER_MARKUP = new Set(['textile', 'rdoc', 'org', 'creole', 'rst', 'rest', 'asciidoc', 'adoc', 'asc', 'pod', 'mediawiki', 'wiki']);

/** A page's name as links refer to it: case-insensitive, spaces and hyphens alike. */
const pageName = (s) => String(s).trim().replace(/\.(md|markdown|mdown|mkdn|mkd)$/i, '').replace(/[\s-]+/g, '-').toLowerCase();

/** OWNER/REPO from a wiki clone's .git/config, if present. */
export function wikiRepo(gitConfig) {
  const m = /url\s*=\s*(?:https?:\/\/github\.com\/|git@github\.com:|ssh:\/\/git@github\.com\/)([\w.-]+)\/([\w.-]+?)\.wiki(?:\.git)?\s*$/im.exec(gitConfig || '');
  return m ? { owner: m[1], repo: m[2] } : null;
}

export async function convertGithubWiki(source, opts = {}) {
  const { onProgress } = opts;
  const b = new PlanBuilder('github-wiki', source, opts);
  const repo = source.gitConfig ? wikiRepo(await source.gitConfig().catch(() => '')) : null;
  const repoName = repo ? repo.repo : (source.root || stripExt(source.name || '')).replace(/\.wiki$/i, '');
  b.rootTopic = repoName ? `${repoName} wiki` : 'Wiki';

  const pages = [];
  let sidebar = null;
  for (const p of source.paths) {
    const ext = extname(p);
    const name = stripExt(basename(p)).toLowerCase();
    if (SPECIAL.has(name)) {
      if (MARKDOWN_EXT.has(ext) && name === '_sidebar' && (!sidebar || !p.includes('/'))) sidebar = p;
      b.skip(p, name === '_sidebar' ? 'The wiki’s sidebar: used to arrange pages into topics, not imported as a post.' : `The wiki’s ${name.slice(1)}, shown on every page in GitHub: not imported as a post.`);
    } else if (MARKDOWN_EXT.has(ext)) {
      pages.push(p);
    } else if (OTHER_MARKUP.has(ext)) {
      b.skip(p, `A ${ext} page. Only Markdown pages are imported; convert it to Markdown first.`);
    }
  }
  const byName = new Map();
  for (const p of pages) {
    const n = pageName(stripExt(basename(p)));
    if (!byName.has(n) || !p.includes('/')) byName.set(n, p);
  }
  const findPage = (name) => {
    const n = pageName(String(name).split('#')[0]);
    return n ? byName.get(n) || null : null;
  };

  // A link from a page: wiki page names, files in the repository (GitHub serves pages from the
  // wiki root, so relative paths start there), and the wiki's own absolute URLs.
  const resolve = (fromDir, target, { image, label = '' } = {}) => {
    let t = String(target).trim();
    if (repo) {
      const base = new RegExp(`^https?://github\\.com/${escapeRe(repo.owner)}/${escapeRe(repo.repo)}/wiki/?`, 'i');
      const raw = new RegExp(`^https?://raw\\.githubusercontent\\.com/wiki/${escapeRe(repo.owner)}/${escapeRe(repo.repo)}/`, 'i');
      if (base.test(t)) t = t.replace(base, '') || 'Home';
      else if (raw.test(t)) t = t.replace(raw, '');
    }
    const lt = localTarget(t);
    if (!lt || !lt.path) return null;
    const hashAt = lt.query.indexOf('#');
    const fragment = hashAt >= 0 ? lt.query.slice(hashAt) : '';
    if (!image) {
      const page = findPage(lt.path.split('/').pop());
      if (page && !isImagePath(lt.path)) return b.pageToken(page) + fragment;
    }
    for (const candidate of [resolvePath('', lt.path), resolvePath(fromDir, lt.path)]) {
      if (candidate && source.has(candidate)) {
        if (MARKDOWN_EXT.has(extname(candidate))) return b.pageToken(candidate) + fragment;
        const file = b.fileToken(candidate);
        if (file) return file;
      }
    }
    return { text: image ? (label ? `*${label}*` : '') : label };
  };

  // [[Page]], [[Text|Page]] (GitHub's order) or [[Page|Text]], [[image.png]], [[image.png|alt=Text]].
  const wikiLink = (fromDir, inner) => {
    const parts = inner.split('|').map((s) => s.trim());
    const alt = parts.find((s) => /^alt=/i.test(s));
    const main = parts.filter((s) => !/^(alt|frame|align|float|width|height)=/i.test(s));
    if (main.length === 1 && isImagePath(main[0].split(/[?#]/)[0])) {
      const r = resolve(fromDir, main[0], { image: true });
      const text = alt ? alt.slice(4) : '';
      if (typeof r === 'string') return `![${escapeLabel(text)}](${r})`;
      if (/^https:\/\//i.test(main[0])) return `![${escapeLabel(text)}](${main[0]})`;
      return text ? `*${escapeLabel(text)}*` : '';
    }
    const [first, second] = main;
    const tryPage = (name) => findPage(name) && b.pageToken(findPage(name)) + (name.includes('#') ? name.slice(name.indexOf('#')) : '');
    if (second !== undefined) {
      const token = tryPage(second) || tryPage(first);
      const text = tryPage(second) ? first : second;
      if (token) return `[${escapeLabel(text)}](${token})`;
      if (/^https?:\/\//i.test(second)) return `[${escapeLabel(first)}](${second})`;
      return escapeLabel(first);
    }
    const token = tryPage(first);
    if (token) return `[${escapeLabel(first.split('#')[0])}](${token})`;
    if (/^https?:\/\//i.test(first)) return `<${first}>`;
    return escapeLabel(first);
  };

  // Topics: the sidebar's groups first, then folders.
  const pageByNumber = new Map(pages.map((p) => [b.pageNumber(p), p]));
  const pageFromToken = (token) => pageByNumber.get(Number(token.split(':')[2].split('#')[0])) || null;
  const placed = new Map();
  const order = [];
  if (sidebar) {
    for (const { page, topic } of sidebarPlaces(await source.text(sidebar, { maxBytes: MAX_SOURCE_BYTES }), (target) => {
      const r = resolve('', target, {});
      return typeof r === 'string' && r.startsWith('dsimport:page:') ? pageFromToken(r) : null;
    })) {
      if (!placed.has(page)) {
        placed.set(page, topic);
        order.push(page);
      }
    }
  }
  const home = pages.find((p) => pageName(stripExt(basename(p))) === 'home');
  const rest = pages.filter((p) => !placed.has(p)).sort((a, c) => (a === home ? -1 : c === home ? 1 : a.localeCompare(c)));
  const ordered = [...order.filter((p) => pages.includes(p)), ...rest];

  let done = 0;
  for (const path of ordered) {
    if (onProgress) onProgress(++done, ordered.length);
    if (b.full) {
      b.skip(path, b.fullReason);
      continue;
    }
    if (source.size(path) > MAX_SOURCE_BYTES) {
      b.skip(path, `The file is ${formatSize(source.size(path))}; pages can be at most ${formatSize(MAX_SOURCE_BYTES)}.`);
      continue;
    }
    const dir = dirname(path);
    const text = await source.text(path);
    const markdown = rewriteMarkdown(text, {
      link: (target, opts) => resolve(dir, target, opts),
      wikiLink: (inner) => wikiLink(dir, inner),
    }).trim();
    const topic = placed.has(path) ? placed.get(path) : (dir ? dir.split('/') : []);
    b.add({ key: path, title: titleFromFileName(path), topic, markdown, path });
  }
  if (!pages.length) b.notes.push('No Markdown pages were found. Zip the folder `git clone https://github.com/OWNER/REPO.wiki.git` creates.');
  return b.finish();
}

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const escapeLabel = (s) => String(s).replace(/[\\[\]*_`<]/g, (c) => '\\' + c);

/** Plain text of a sidebar label: link text without Markdown. */
function labelText(s) {
  return s
    .replace(/\[\[([^\]|]+)\|([^\]]+)\]\]/g, (m, a, c) => a)
    .replace(/\[\[([^\]]+)\]\]/g, '$1')
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/[*_`~]/g, '')
    .replace(/<[^>]+>/g, '')
    .trim();
}

/**
 * Where the sidebar puts each page it links to. A heading, or a list item with items under it,
 * becomes a topic; a linked item with items under it is that topic's own page.
 * `pageFor(target)` maps a link target to a page path.
 */
export function sidebarPlaces(md, pageFor) {
  const nodes = [];
  const headings = [];
  let items = [];
  const linkTargets = (s) => {
    const out = [];
    for (const m of s.matchAll(/\[\[([^\]]+)\]\]/g)) {
      const parts = m[1].split('|');
      out.push(parts.length > 1 ? parts[1].trim() : parts[0].trim(), parts[0].trim());
    }
    for (const m of s.matchAll(/\[[^\]]*\]\(([^)\s]+)[^)]*\)/g)) out.push(m[1]);
    return out;
  };
  for (const raw of md.replace(/\r\n?/g, '\n').split('\n')) {
    const line = raw.replace(/\t/g, '    ');
    const h = /^(#{1,6})\s+(.*?)\s*#*\s*$/.exec(line);
    if (h) {
      while (headings.length && headings[headings.length - 1].level >= h[1].length) headings.pop();
      const node = { label: labelText(h[2]), page: null, path: headings.map((x) => x.node.label), children: 0 };
      if (headings.length) headings[headings.length - 1].node.children++;
      headings.push({ level: h[1].length, node });
      nodes.push(node);
      items = [];
      continue;
    }
    const li = /^(\s*)(?:[-*+]|\d+[.)])\s+(.*)$/.exec(line);
    if (!li) continue;
    const indent = li[1].length;
    while (items.length && items[items.length - 1].indent >= indent) items.pop();
    let page = null;
    for (const t of linkTargets(li[2])) {
      page = pageFor(t);
      if (page) break;
    }
    const parent = items.length ? items[items.length - 1].node : headings.length ? headings[headings.length - 1].node : null;
    const node = { label: labelText(li[2]), page, path: [...headings.map((x) => x.node.label), ...items.map((x) => x.node.label)], children: 0 };
    if (parent) parent.children++;
    items.push({ indent, node });
    nodes.push(node);
  }
  return nodes
    .filter((n) => n.page)
    .map((n) => ({ page: n.page, topic: (n.children ? [...n.path, n.label] : n.path).filter(Boolean) }));
}
