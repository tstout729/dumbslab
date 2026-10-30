// What a converter produces: an import plan. Documents carry Markdown whose links to other
// documents and to attachments are tokens (`dsimport:page:3`, `dsimport:file:7`); the import
// fills them in once the attachments are uploaded and the pages exist.

import { basename, cleanTitle, topicSegment, typeFor, isImagePath } from './paths.js';
import { formatSize } from './zip.js';

/** upload_file's limit. */
export const MAX_FILE_BYTES = 10 * 1024 * 1024;
/** import_documents takes Markdown up to 2 MB per document; leave room for filled-in links. */
export const MAX_DOC_BYTES = 1_900_000;
/** Larger source pages aren't parsed at all. */
export const MAX_SOURCE_BYTES = 20 * 1024 * 1024;

export const TOKEN = /dsimport:(page|file):(\d+)/g;
const utf8 = new TextEncoder();
export const byteLength = (s) => utf8.encode(s).length;

export class PlanBuilder {
  /** `format`: confluence, guru, github-wiki or markdown. `source`: see source.js. */
  constructor(format, source) {
    this.format = format;
    this.source = source;
    this.rootTopic = '';
    this.documents = [];
    this.attachments = [];
    this.skipped = [];
    this.notes = [];
    this.pageIndex = new Map();
    this.fileIndex = new Map();
    this.skippedPaths = new Set();
  }

  skip(path, reason) {
    if (this.skippedPaths.has(path)) return;
    this.skippedPaths.add(path);
    this.skipped.push({ path, reason });
  }

  /** Reserves a document number for `key`, whether or not it has been added yet. */
  pageNumber(key) {
    if (!this.pageIndex.has(key)) this.pageIndex.set(key, { n: this.pageIndex.size, doc: null });
    return this.pageIndex.get(key).n;
  }

  pageToken(key) {
    return `dsimport:page:${this.pageNumber(key)}`;
  }

  /**
   * A token for the file at `path` in the source, or null when it can't be imported (missing,
   * empty or over 10 MB; those are listed as skipped). `name` is the file name people see.
   */
  fileToken(path, name) {
    if (this.fileIndex.has(path)) return `dsimport:file:${this.fileIndex.get(path)}`;
    if (!this.source.has(path)) return null;
    const size = this.source.size(path);
    if (size === 0) {
      this.skip(path, 'The file is empty.');
      return null;
    }
    if (size > MAX_FILE_BYTES) {
      this.skip(path, `The file is ${formatSize(size)}; uploads can be at most 10 MB.`);
      return null;
    }
    const n = this.attachments.length;
    this.attachments.push({ n, path, name: cleanFileName(name || basename(path)), size, type: typeFor(name || path), image: isImagePath(name || path) });
    this.fileIndex.set(path, n);
    return `dsimport:file:${n}`;
  }

  /** Adds a document. `topic` is a list of topic names under the root topic. */
  add({ key, title, topic = [], markdown, path }) {
    const n = this.pageNumber(key);
    const doc = { n, key, title: cleanTitle(title), topic: topic.map(topicSegment).filter(Boolean), markdown, path: path || key };
    this.pageIndex.get(key).doc = doc;
    this.documents.push(doc);
    return doc;
  }

  /** Finishes the plan: drops documents that are too large, numbers duplicate titles. */
  finish() {
    const kept = [];
    const seen = new Map();
    for (const doc of this.documents) {
      const bytes = byteLength(doc.markdown);
      if (bytes > MAX_DOC_BYTES) {
        this.skip(doc.path, `After conversion the page is ${formatSize(bytes)}; posts can be at most 2 MB. Split it before importing.`);
        continue;
      }
      // Two pages with one title in one topic would look like one already imported.
      const where = doc.topic.join('/').toLowerCase();
      const k = `${where}\u0000${doc.title}`;
      const count = (seen.get(k) || 0) + 1;
      seen.set(k, count);
      if (count > 1) {
        let title = cleanTitle(`${doc.title} (${count})`);
        while (seen.has(`${where}\u0000${title}`)) title = cleanTitle(`${title} (${count})`);
        seen.set(`${where}\u0000${title}`, 1);
        doc.title = title;
      }
      kept.push(doc);
    }
    // Number documents by position; tokens keep pointing at the reserved numbers.
    const byNumber = new Map(kept.map((d) => [d.n, d]));
    const topics = new Set();
    for (const d of kept) {
      for (let i = 1; i <= d.topic.length; i++) topics.add(d.topic.slice(0, i).join('/').toLowerCase());
    }
    const used = new Set();
    for (const d of kept) {
      for (const m of d.markdown.matchAll(TOKEN)) if (m[1] === 'file') used.add(Number(m[2]));
    }
    const attachments = this.attachments.filter((a) => used.has(a.n));
    return {
      format: this.format,
      name: this.source.name,
      rootTopic: this.rootTopic,
      documents: kept,
      byNumber,
      attachments,
      skipped: this.skipped,
      notes: this.notes,
      stats: {
        documents: kept.length,
        topics: topics.size,
        attachments: attachments.length,
        attachmentBytes: attachments.reduce((s, a) => s + a.size, 0),
        markdownBytes: kept.reduce((s, d) => s + byteLength(d.markdown), 0),
      },
    };
  }
}

/** A file name for upload: no path, no control characters, at most 200 characters. */
export function cleanFileName(name) {
  const base = String(name || '').split(/[\\/]/).pop().replace(/[\u0000-\u001f\u007f]/g, '').trim();
  const s = base && !/^\.+$/.test(base) ? base : 'file';
  return s.length > 200 ? s.slice(0, 200) : s;
}

/** Fills in tokens. `page(n)` and `file(n)` return a URL, or null to drop the link and keep its text. */
export function fillTokens(md, { page, file }) {
  const resolve = (kind, n) => (kind === 'page' ? page(n) : file(n));
  // Links and images whose target is gone keep their text; the rest get their URL.
  const unwrapped = md.replace(/(!?)\[((?:\\.|[^\\[\]\n])*)\]\(dsimport:(page|file):(\d+)[^)\s]*\)/g, (m, bang, label, kind, n) => {
    const url = resolve(kind, Number(n));
    if (url !== null && url !== undefined) return m;
    return bang ? (label ? `*${label}*` : '') : label;
  });
  return unwrapped.replace(TOKEN, (m, kind, n) => {
    const url = resolve(kind, Number(n));
    return url === null || url === undefined ? '#' : url;
  });
}

/**
 * A link that works before the target page exists: a search for its title. It is unique per
 * page so the import can find it and point it at the page once that exists.
 */
export function pendingLink(doc) {
  const enc = (s) => encodeURIComponent(s).replace(/[()'!*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
  return `/search?q=${enc(doc.title)}&import=${hash(doc.key)}`;
}

function hash(s) {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, '0');
}

/** Rough cost of an import in database rows written and bytes stored (docs/cloudflare.md has the measurements). */
export function estimate(plan, { includeLinks = true } = {}) {
  const docs = plan.documents.length;
  const linking = includeLinks ? plan.documents.filter((d) => /dsimport:page:/.test(d.markdown)).length : 0;
  const chunks = plan.attachments.reduce((s, a) => s + Math.ceil(a.size / (1024 * 1024)), 0);
  const writes = docs * 19 + (plan.stats.topics + 1) * 6 + plan.attachments.length * 9 + chunks + linking * 10;
  // Content is stored in the post, its first version and the search index.
  const bytes = plan.stats.markdownBytes * 3 + plan.stats.attachmentBytes;
  return { writes, bytes };
}
