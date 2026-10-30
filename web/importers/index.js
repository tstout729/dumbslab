// The formats the importer reads, how to tell them apart, and one entry point to convert any of them.

import { zipSource } from './source.js';
import { ZipError } from './zip.js';
import { convertConfluence, confluenceBase } from './confluence.js';
import { convertGuru } from './guru.js';
import { convertGithubWiki, wikiRepo } from './github-wiki.js';
import { convertMarkdownFolder } from './markdown-folder.js';

export const FORMATS = [
  {
    id: 'confluence',
    label: 'Confluence space',
    howTo: 'Confluence Cloud: open the space, then Space settings › Export space, and choose HTML. Data Center: Space tools › Content tools › Export, then HTML. Download the zip it makes.',
    limits: 'Only the HTML export works: Confluence’s XML export is for moving between Confluence sites and isn’t supported. HTML exports leave out blog posts and comments.',
  },
  {
    id: 'guru',
    label: 'Guru collection',
    howTo: 'In Guru, go to Manage › Collection Settings, open the ⋯ menu on the collection and choose Export Collection. Guru emails you the zip.',
    limits: 'Guru leaves archived cards out of exports, and exports carry no verification or owners.',
  },
  {
    id: 'github-wiki',
    label: 'GitHub wiki',
    howTo: 'Clone the wiki with git clone https://github.com/OWNER/REPO.wiki.git, then zip the folder it makes.',
    limits: 'Markdown pages only. Images added through GitHub’s editor live on GitHub, not in the clone, so they stay links.',
  },
  {
    id: 'markdown',
    label: 'Folder of Markdown files',
    howTo: 'Zip a folder of .md files, such as a repository’s docs folder. Each folder becomes a topic.',
  },
];

/** Opens a zip for importing. Throws with a message people can act on. */
export async function openSource(file) {
  try {
    new DecompressionStream('deflate-raw');
  } catch {
    throw new ZipError('This browser can’t unzip files. Use a current version of Chrome, Edge, Firefox or Safari (16.4 or later).');
  }
  return zipSource(file);
}

/** The format a source most likely is. */
export function detectFormat(source) {
  const paths = source.paths;
  const top = (p) => !p.includes('/');
  if (paths.includes('collection.yaml') || paths.some((p) => /^cards\/[^/]+\.ya?ml$/i.test(p))) return 'guru';
  const base = confluenceBase(paths);
  if (base !== null) {
    const pages = paths.filter((p) => /(^|[/_])\d+\.html$/.test(p));
    if (pages.length || paths.some((p) => p.startsWith(base ? `${base}/attachments/` : 'attachments/') || p.endsWith('styles/site.css'))) return 'confluence';
  }
  if (/\.wiki$/i.test(source.root) || paths.some((p) => top(p) && /^(home|_sidebar|_footer)\.(md|markdown|mdown|mkdn|mkd)$/i.test(p))) return 'github-wiki';
  return 'markdown';
}

/** Converts a source to an import plan. opts: { parseHtml, onProgress, attachmentLists }. */
export async function convert(format, source, opts = {}) {
  switch (format) {
    case 'confluence': return convertConfluence(source, opts);
    case 'guru': return convertGuru(source, opts);
    case 'github-wiki': return convertGithubWiki(source, opts);
    case 'markdown': return convertMarkdownFolder(source, opts);
    default: throw new Error(`Unknown format: ${format}`);
  }
}

export { wikiRepo };
