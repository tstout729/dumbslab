// A Confluence space exported as HTML (Cloud: Space settings › Export space › HTML; Data Center:
// Space tools › Content tools › Export › HTML). The zip holds a folder named for the space key
// with index.html (the space's details and its page tree, "Available Pages"), one file per page
// (`Title_<pageId>.html` or `<pageId>.html`) and attachments under `attachments/<pageId>/`,
// named by attachment id. Real file names come from the pages themselves.
//
// The space becomes the top topic. The home page sits in it; every page with child pages
// becomes a topic holding itself and its children. Links between pages point at the imported
// posts, and images and files are uploaded.

import { PlanBuilder, MAX_SOURCE_BYTES } from './plan.js';
import { htmlToMarkdown, find, findAll, byId, kids, tag, attr, hasClass, textOf, escapeText } from './html-to-markdown.js';
import { basename, dirname, resolvePath, safeUrl } from './paths.js';
import { formatSize } from './zip.js';

const pageIdOf = (href) => {
  const s = String(href || '');
  const m = /(?:^|[/_])(\d+)\.html(?:[?#]|$)/.exec(s) || /\/pages\/(\d+)(?:[/?#]|$)/.exec(s) || /[?&]pageId=(\d+)/.exec(s);
  return m ? m[1] : null;
};

/** Where the export keeps its pages: the folder holding index.html. */
export function confluenceBase(paths) {
  if (paths.includes('index.html')) return '';
  const nested = paths.find((p) => p.split('/').length === 2 && p.endsWith('/index.html'));
  return nested ? dirname(nested) : null;
}

export async function convertConfluence(source, { parseHtml, onProgress, attachmentLists = true } = {}) {
  const b = new PlanBuilder('confluence', source);
  const base = confluenceBase(source.paths) ?? '';
  const inBase = (p) => (base ? p.startsWith(base + '/') && !p.slice(base.length + 1).includes('/') : !p.includes('/'));
  const indexPath = base ? `${base}/index.html` : 'index.html';
  const pages = source.paths.filter((p) => p.endsWith('.html') && inBase(p) && p !== indexPath);
  const byPageId = new Map();
  for (const p of pages) {
    const id = pageIdOf(basename(p));
    if (id && !byPageId.has(id)) byPageId.set(id, p);
  }
  const pageFor = (href) => {
    const id = pageIdOf(href);
    if (id && byPageId.has(id)) return byPageId.get(id);
    // A page whose file name has no id: match the name as written, then decoded.
    const raw = String(href || '').split(/[?#]/)[0];
    for (const name of [raw, safeDecode(raw)]) {
      const p = resolvePath(base, name);
      if (p && pages.includes(p)) return p;
    }
    return null;
  };

  // The space name and the page tree from index.html.
  let spaceName = '';
  const tree = [];
  if (source.has(indexPath)) {
    const doc = parseHtml(await source.text(indexPath, { maxBytes: MAX_SOURCE_BYTES }));
    const t = find(doc, (n) => tag(n) === 'title');
    const m = t ? /\(([^()]*(?:\([^()]*\)[^()]*)*)\)\s*$/.exec(textOf(t)) : null;
    if (m) spaceName = m[1].trim();
    if (!spaceName) {
      const row = findAll(doc, (n) => tag(n) === 'tr').find((r) => /^name$/i.test(textOf(find(r, (x) => tag(x) === 'th'))));
      if (row) spaceName = textOf(find(row, (x) => tag(x) === 'td'));
    }
    const section = findAll(doc, (n) => hasClass(n, 'pageSection')).find((s) => /available pages/i.test(textOf(find(s, (x) => hasClass(x, 'pageSectionTitle')) || { childNodes: [] })));
    const list = section ? find(section, (n) => tag(n) === 'ul') : null;
    const walk = (ul, out) => {
      for (const li of kids(ul)) {
        if (tag(li) !== 'li') continue;
        const a = kids(li).find((x) => tag(x) === 'a');
        const path = a ? pageFor(attr(a, 'href')) : null;
        const node = { path, title: a ? textOf(a) : '', home: kids(li).some((x) => tag(x) === 'img' && /home_page/.test(attr(x, 'src'))), children: [] };
        // Confluence wraps each child in its own <ul>.
        for (const sub of kids(li)) if (tag(sub) === 'ul') walk(sub, node.children);
        if (path) out.push(node);
        else out.push(...node.children);
      }
    };
    if (list) walk(list, tree);
  } else {
    b.notes.push('This zip has no index.html, so pages are arranged by their breadcrumbs instead of the space’s page tree.');
  }
  b.rootTopic = spaceName || source.root || 'Confluence';

  // Where each page goes. Pages under the home page are the space's top level.
  const place = new Map();
  const order = [];
  const visit = (node, topic) => {
    if (place.has(node.path)) return;
    const own = node.children.length ? [...topic, node.title] : topic;
    place.set(node.path, { topic: own, title: node.title });
    order.push(node.path);
    for (const c of node.children) visit(c, own);
  };
  const home = tree.find((n) => n.home) || (tree.length === 1 ? tree[0] : null);
  if (home) {
    place.set(home.path, { topic: [], title: home.title });
    order.push(home.path);
    for (const c of home.children) visit(c, []);
  }
  for (const n of tree) if (n !== home) visit(n, []);
  const unplaced = pages.filter((p) => !place.has(p));

  const titleOf = new Map();
  let done = 0;
  const all = [...order, ...unplaced];
  for (const path of all) {
    if (onProgress) onProgress(++done, all.length);
    if (source.size(path) > MAX_SOURCE_BYTES) {
      b.skip(path, `The page is ${formatSize(source.size(path))}; pages can be at most ${formatSize(MAX_SOURCE_BYTES)}.`);
      continue;
    }
    const doc = parseHtml(await source.text(path));
    const crumbs = findAll(byId(doc, 'breadcrumbs'), (n) => tag(n) === 'a');
    let title = place.has(path) ? place.get(path).title : '';
    if (!title) {
      const spacePrefix = crumbs.length ? textOf(crumbs[0]) + ' : ' : spaceName ? spaceName + ' : ' : '';
      const raw = textOf(byId(doc, 'title-text')) || textOf(find(doc, (n) => tag(n) === 'title'));
      title = spacePrefix && raw.startsWith(spacePrefix) ? raw.slice(spacePrefix.length) : raw;
    }
    titleOf.set(path, title);
    let topic = place.has(path) ? place.get(path).topic : [];
    if (!place.has(path)) {
      // Not in the tree: follow the breadcrumbs (space, home page, …, parent).
      const ancestors = crumbs.map((a) => pageFor(attr(a, 'href'))).filter((p) => p && p !== home?.path);
      topic = ancestors.map((p) => titleOf.get(p) || (place.get(p) || {}).title).filter(Boolean);
    }

    // Real names for attachments, which the zip stores by id.
    const names = new Map();
    const remember = (href, name) => {
      const p = attachmentPath(href);
      if (p && name && !names.has(p)) names.set(p, name.trim());
    };
    for (const el of findAll(doc, (n) => attr(n, 'data-linked-resource-default-alias'))) {
      remember(attr(el, 'data-image-src') || attr(el, 'href') || attr(el, 'src'), attr(el, 'data-linked-resource-default-alias'));
    }
    const listed = [];
    const attachmentsSection = findAll(doc, (n) => hasClass(n, 'pageSection')).find((s) => find(s, (x) => attr(x, 'id') === 'attachments'));
    if (attachmentsSection) {
      for (const a of findAll(attachmentsSection, (n) => tag(n) === 'a' && attr(n, 'href'))) {
        remember(attr(a, 'href'), textOf(a));
        const p = attachmentPath(attr(a, 'href'));
        if (p) listed.push(p);
      }
    }
    function attachmentPath(href) {
      const raw = String(href || '').split(/[?#]/)[0];
      if (!raw || /^[a-z][a-z0-9+.-]*:|^\/\//i.test(raw)) return null;
      for (const name of [raw, safeDecode(raw)]) {
        const p = resolvePath(dirname(path), name);
        if (p && source.has(p) && !p.endsWith('.html')) return p;
      }
      return null;
    }

    const used = new Set();
    let siteBase = '';
    const baseEl = find(doc, (n) => /^https:\/\//.test(attr(n, 'data-base-url')));
    if (baseEl) siteBase = attr(baseEl, 'data-base-url').replace(/\/wiki\/?$/, '');
    const hooks = {
      link: (href, el) => {
        if (hasClass(el, 'createlink')) return null;
        const file = attachmentPath(href);
        if (file) {
          const token = b.fileToken(file, names.get(file));
          if (token) used.add(file);
          return token ? { url: token, label: escapeText(names.get(file) || basename(file)) } : null;
        }
        const target = /(^|\/)index\.html(?:[?#]|$)/.test(href) ? home?.path : pageFor(href);
        if (target) return { url: b.pageToken(target) };
        if (safeUrl(href)) return { url: href };
        if (siteBase && /^\/wiki\//.test(href)) return { url: siteBase + href };
        return null;
      },
      image: (src, el) => {
        if (/(^|\/)images\/icons\//.test(src)) return null;
        const file = attachmentPath(src);
        if (file) {
          const token = b.fileToken(file, names.get(file));
          if (!token) return { text: `*${escapeText(names.get(file) || basename(file))}*` };
          used.add(file);
          return { url: token, alt: attr(el, 'alt') || names.get(file) || '' };
        }
        return /^https:\/\//i.test(src) ? { url: src } : null;
      },
    };
    const main = byId(doc, 'main-content') || find(doc, (n) => tag(n) === 'body') || doc;
    let markdown = htmlToMarkdown(main, hooks);
    if (attachmentLists) {
      const extra = [...new Set(listed)].filter((p) => !used.has(p) && !/\/thumbnails\//.test(p));
      const items = [];
      for (const p of extra) {
        const name = names.get(p) || basename(p);
        const token = b.fileToken(p, name);
        if (token) items.push(`- [${escapeText(name)}](${token})`);
      }
      if (items.length) markdown += `\n\n## Attachments\n\n${items.join('\n')}`;
    }
    b.add({ key: path, title: title || basename(path), topic, markdown: markdown.trim(), path });
  }
  if (!all.length) {
    b.notes.push('No Confluence pages were found. Export the space as HTML (not XML or PDF) and choose the zip it gives you.');
  }
  return b.finish();
}

function safeDecode(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}
