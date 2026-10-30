// A Guru collection export (Manage › Collection Settings › ⋯ › Export Collection; Guru emails a
// zip). The zip mirrors Guru's import format: collection.yaml, cards/<id>.yaml with each card's
// Title and Tags beside its content in cards/<id>.html or cards/<id>.md, folders/<id>.yaml
// (Title, Description, Items: cards, folders and titled sections), and resources/ for images and
// files. Exports made before Guru's folders have boards/ and board-groups/ instead.
//
// Folders (and boards, board groups and sections) become topics; cards become posts. The export
// carries no verification state or owners, so neither comes across.

import { PlanBuilder, MAX_SOURCE_BYTES } from './plan.js';
import { htmlToMarkdown, escapeText } from './html-to-markdown.js';
import { rewriteMarkdown } from './markdown.js';
import { parseYaml } from './yaml.js';
import { basename, dirname, localTarget, resolvePath, safeUrl, stripExt } from './paths.js';
import { formatSize } from './zip.js';

const asList = (v) => (Array.isArray(v) ? v : v ? [v] : []);
const str = (v) => (v === null || v === undefined ? '' : String(v));
const get = (obj, key) => {
  if (!obj || typeof obj !== 'object') return undefined;
  const k = Object.keys(obj).find((x) => x.toLowerCase() === key.toLowerCase());
  return k === undefined ? undefined : obj[k];
};

export async function convertGuru(source, { parseHtml, onProgress } = {}) {
  const b = new PlanBuilder('guru', source);
  const readYaml = async (p) => {
    try {
      return parseYaml(await source.text(p, { maxBytes: 1024 * 1024 })) || {};
    } catch {
      b.skip(p, 'This metadata file couldn’t be read.');
      return {};
    }
  };
  const collection = source.has('collection.yaml') ? await readYaml('collection.yaml') : {};
  b.rootTopic = str(get(collection, 'Title')) || cleanRoot(source.root) || stripExt(source.name || '') || 'Guru';

  // Cards: cards/<id>.yaml with cards/<id>.html or .md.
  const cards = new Map();
  for (const p of source.paths) {
    const m = /^cards\/(.+)\.(yaml|yml|html|htm|md|markdown)$/i.exec(p);
    if (!m) continue;
    const card = cards.get(m[1]) || { id: m[1] };
    if (/ya?ml/i.test(m[2])) card.meta = p;
    else card.content = p;
    cards.set(m[1], card);
  }

  // Where each card goes: folders (and boards) become topics, nested as they nest.
  const place = new Map();
  const order = [];
  const seenFolders = new Set();
  const folderPath = (kind, id) => {
    for (const dir of kind === 'board' ? ['boards'] : kind === 'boardgroup' ? ['board-groups', 'boardgroups'] : ['folders']) {
      for (const ext of ['yaml', 'yml']) if (source.has(`${dir}/${id}.${ext}`)) return `${dir}/${id}.${ext}`;
    }
    return null;
  };
  async function items(list, topic) {
    for (const item of asList(list)) {
      const type = str(get(item, 'Type')).toLowerCase().replace(/[-_ ]/g, '');
      const id = str(get(item, 'ID') ?? get(item, 'Id'));
      if (type === 'card' || (!type && cards.has(id))) {
        if (cards.has(id) && !place.has(id)) {
          place.set(id, topic);
          order.push(id);
        }
      } else if (type === 'section') {
        const title = str(get(item, 'Title'));
        await items(get(item, 'Items'), title ? [...topic, title] : topic);
      } else if (type === 'folder' || type === 'board' || type === 'boardgroup') {
        await folder(type === 'folder' ? 'folder' : type, id, topic);
      }
    }
  }
  async function folder(kind, id, topic) {
    const p = folderPath(kind, id);
    if (!p || seenFolders.has(p)) return;
    seenFolders.add(p);
    const meta = await readYaml(p);
    const title = str(get(meta, 'Title')) || id;
    await items(get(meta, 'Items'), [...topic, title]);
    // Board groups list their boards by id.
    for (const board of asList(get(meta, 'Boards'))) {
      const bid = typeof board === 'object' ? str(get(board, 'ID') ?? get(board, 'Id')) : str(board);
      if (bid) await folder('board', bid, [...topic, title]);
    }
  }
  await items(get(collection, 'Items'), []);
  // Folders and boards the collection file doesn't list (older or partial exports).
  for (const p of source.paths) {
    const m = /^(folders|boards|board-groups|boardgroups)\/(.+)\.ya?ml$/i.exec(p);
    if (m && !seenFolders.has(p)) {
      // A folder something else lists is visited from there, so only start from unlisted ones.
      const kind = m[1].startsWith('board-') || m[1] === 'boardgroups' ? 'boardgroup' : m[1] === 'boards' ? 'board' : 'folder';
      if (!(await listedElsewhere(p))) await folder(kind, m[2], []);
    }
  }
  async function listedElsewhere(p) {
    const id = stripExt(basename(p));
    for (const q of source.paths) {
      if (q === p || !/^(folders|board-groups|boardgroups)\/.+\.ya?ml$/i.test(q)) continue;
      if ((await source.text(q, { maxBytes: 1024 * 1024 })).includes(id)) return true;
    }
    return false;
  }
  for (const id of [...cards.keys()].sort()) {
    if (!place.has(id)) {
      place.set(id, []);
      order.push(id);
    }
  }

  // Links between cards use `cards/<id>`; images and files use `resources/<name>`.
  const resolve = (fromDir, target, { image, label = '' } = {}) => {
    const t = localTarget(target);
    if (!t || !t.path) {
      return safeUrl(target) || !image ? null : { text: label ? `*${label}*` : '' };
    }
    for (const candidate of [resolvePath('', t.path), resolvePath(fromDir, t.path)]) {
      if (!candidate) continue;
      const card = /^cards\/([^/]+?)(?:\.(?:html?|md|ya?ml))?$/i.exec(candidate);
      if (card && cards.has(card[1]) && cards.get(card[1]).content) return b.pageToken(cards.get(card[1]).content);
      if (source.has(candidate) && !/^(cards|folders|boards|board-groups)\//.test(candidate) && candidate !== 'collection.yaml') {
        const token = b.fileToken(candidate);
        if (token) return token;
      }
    }
    return { text: image ? (label ? `*${label}*` : '') : label };
  };

  let done = 0;
  for (const id of order) {
    if (onProgress) onProgress(++done, order.length);
    const card = cards.get(id);
    if (!card.content) {
      if (card.meta) b.skip(card.meta, 'A card without its content file (.html or .md).');
      continue;
    }
    if (source.size(card.content) > MAX_SOURCE_BYTES) {
      b.skip(card.content, `The card is ${formatSize(source.size(card.content))}; pages can be at most ${formatSize(MAX_SOURCE_BYTES)}.`);
      continue;
    }
    const meta = card.meta ? await readYaml(card.meta) : {};
    const text = await source.text(card.content);
    const dir = dirname(card.content);
    let markdown;
    if (/\.html?$/i.test(card.content)) {
      markdown = htmlToMarkdown(parseHtml(text), {
        link: (href) => {
          const r = resolve(dir, href, {});
          if (typeof r === 'string') return { url: r };
          return safeUrl(href) ? { url: href } : null;
        },
        image: (src, el) => {
          const r = resolve(dir, src, { image: true, label: escapeText(el.getAttribute('alt') || '') });
          if (typeof r === 'string') return { url: r };
          if (/^https:\/\//i.test(src)) return { url: src };
          return r && typeof r === 'object' ? { text: r.text } : null;
        },
      });
    } else {
      markdown = rewriteMarkdown(text, { link: (target, opts) => resolve(dir, target, opts) }).trim();
    }
    const title = str(get(meta, 'Title')) || firstLine(markdown) || id;
    b.add({ key: card.content, title, topic: place.get(id), markdown, path: card.content });
  }
  if (!cards.size) b.notes.push('No Guru cards were found. Choose the zip Guru emails you after Export Collection.');
  return b.finish();
}

const cleanRoot = (root) => String(root || '').replace(/^export-\d+-?$/i, '').trim();
const firstLine = (md) => (md.split('\n').find((l) => l.trim()) || '').replace(/^#+\s*/, '').replace(/[*_`\\]/g, '').trim().slice(0, 120);
