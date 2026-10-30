// A zip of Markdown files, such as a repository's docs folder: each .md file becomes a post and
// each folder a topic. Titles come from front matter, then a leading `# Heading`, then the file
// name. Relative links between files point at the imported posts; images and other files they
// link to are uploaded.

import { PlanBuilder, MAX_SOURCE_BYTES } from './plan.js';
import { splitFrontMatter, leadingTitle, rewriteMarkdown } from './markdown.js';
import { basename, dirname, extname, localTarget, resolvePath, stripExt, titleFromFileName } from './paths.js';
import { formatSize } from './zip.js';

export const MARKDOWN_EXT = new Set(['md', 'markdown', 'mdown', 'mkdn', 'mkd']);
const INDEX_NAMES = new Set(['readme', 'index', '_index']);

const isIndex = (p) => INDEX_NAMES.has(stripExt(basename(p)).toLowerCase());

export async function convertMarkdownFolder(source, opts = {}) {
  const { onProgress } = opts;
  const b = new PlanBuilder('markdown', source, opts);
  b.rootTopic = source.root || stripExt(source.name || '').replace(/[-_]+/g, ' ').trim();
  const pages = source.paths.filter((p) => MARKDOWN_EXT.has(extname(p)));
  for (const p of source.paths) {
    if (extname(p) === 'mdx') b.skip(p, 'MDX pages need their site’s build to render; convert them to Markdown first.');
  }
  const pageSet = new Set(pages);
  // Folder links (`guides/`) open the folder's README or index.
  const folderIndex = new Map();
  for (const p of pages) if (isIndex(p) && !folderIndex.has(dirname(p))) folderIndex.set(dirname(p), p);
  // README first in each folder, then the rest by path.
  pages.sort((a, c) => dirname(a).localeCompare(dirname(c)) || Number(isIndex(c)) - Number(isIndex(a)) || a.localeCompare(c));

  // A relative link to another page, a folder or a file in the zip. Links to things the zip
  // doesn't have keep only their text, since they would be broken here.
  const resolve = (fromDir, target, { image, label = '' } = {}) => {
    const t = localTarget(target);
    if (!t || !t.path) return null;
    const hashAt = t.query.indexOf('#');
    const fragment = hashAt >= 0 ? t.query.slice(hashAt) : '';
    const path = resolvePath(fromDir, t.path);
    if (path !== null) {
      if (pageSet.has(path)) return b.pageToken(path) + fragment;
      for (const ext of MARKDOWN_EXT) if (pageSet.has(`${path}.${ext}`)) return b.pageToken(`${path}.${ext}`) + fragment;
      const folder = folderIndex.get(path.replace(/\/$/, ''));
      if (folder) return b.pageToken(folder) + fragment;
      const file = source.has(path) ? b.fileToken(path) : null;
      if (file) return file;
    }
    return { text: image ? (label ? `*${label}*` : '') : label };
  };

  let done = 0;
  for (const path of pages) {
    if (onProgress) onProgress(++done, pages.length);
    if (b.full) {
      b.skip(path, b.fullReason);
      continue;
    }
    if (source.size(path) > MAX_SOURCE_BYTES) {
      b.skip(path, `The file is ${formatSize(source.size(path))}; pages can be at most ${formatSize(MAX_SOURCE_BYTES)}.`);
      continue;
    }
    const { data, body } = splitFrontMatter(await source.text(path));
    let title = data.title || '';
    let content = body;
    if (!title) {
      const lead = leadingTitle(body);
      if (lead) {
        title = lead.title;
        content = lead.body;
      }
    }
    const dir = dirname(path);
    if (!title) title = isIndex(path) ? (dir ? basename(dir) : b.rootTopic || 'Home') : titleFromFileName(path);
    const markdown = rewriteMarkdown(content, {
      link: (target, opts) => resolve(dir, target, opts),
    }).trim();
    b.add({ key: path, title, topic: dir ? dir.split('/') : [], markdown, path });
  }
  if (!pages.length) b.notes.push('No Markdown files (.md) were found in this zip.');
  return b.finish();
}
