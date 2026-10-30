// Path, name and type helpers shared by the converters.

export const dirname = (p) => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '');
export const basename = (p) => p.slice(p.lastIndexOf('/') + 1);
export const extname = (p) => {
  const b = basename(p);
  const i = b.lastIndexOf('.');
  return i > 0 ? b.slice(i + 1).toLowerCase() : '';
};
export const stripExt = (name) => {
  const i = name.lastIndexOf('.');
  return i > 0 ? name.slice(0, i) : name;
};

/** Resolves `rel` against directory `dir` (both zip-relative). Null when it climbs out. */
export function resolvePath(dir, rel) {
  const parts = rel.startsWith('/') ? [] : (dir ? dir.split('/') : []);
  for (const part of rel.split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      if (!parts.length) return null;
      parts.pop();
    } else parts.push(part);
  }
  return parts.join('/');
}

/**
 * Splits a link target into its path and the rest. Returns null for anything that isn't a path
 * inside the export: URLs with a scheme, protocol-relative URLs and bare #anchors.
 */
export function localTarget(href) {
  const t = String(href || '').trim();
  if (!t || t.startsWith('#') || t.startsWith('//') || /^[a-z][a-z0-9+.-]*:/i.test(t)) return null;
  const cut = t.search(/[?#]/);
  const pathPart = cut < 0 ? t : t.slice(0, cut);
  let path = pathPart;
  try {
    path = decodeURIComponent(pathPart.replace(/\+/g, '%20'));
  } catch {
    /* keep it as written */
  }
  return { path, query: cut < 0 ? '' : t.slice(cut) };
}

/** Whether a URL is safe to keep as a link: web, mail and phone links only. */
export const safeUrl = (u) => /^(https?:|mailto:|tel:)/i.test(String(u || '').trim());

const IMAGE_EXT = new Set(['png', 'jpg', 'jpeg', 'gif', 'webp', 'avif']);
export const isImagePath = (p) => IMAGE_EXT.has(extname(p));

const TYPES = {
  png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp', avif: 'image/avif',
  pdf: 'application/pdf', txt: 'text/plain', csv: 'text/csv', json: 'application/json', zip: 'application/zip',
  doc: 'application/msword', docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xls: 'application/vnd.ms-excel', xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  ppt: 'application/vnd.ms-powerpoint', pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  mp4: 'video/mp4', mov: 'video/quicktime', mp3: 'audio/mpeg', wav: 'audio/wav',
};
/** A content type to claim for an upload. The server trusts only what it can detect from the bytes. */
export const typeFor = (p) => TYPES[extname(p)];

/** A topic path segment: no slashes (they separate segments), at most 120 characters. */
export function topicSegment(name) {
  const s = String(name || '').replace(/[\\/]+/g, '-').replace(/\s+/g, ' ').trim();
  return s.length > 120 ? s.slice(0, 119).trimEnd() + '…' : s;
}

/** A post title: one line, at most 300 characters. */
export function cleanTitle(title, fallback = 'Untitled') {
  const s = String(title || '').replace(/\s+/g, ' ').trim() || fallback;
  return s.length > 300 ? s.slice(0, 299).trimEnd() + '…' : s;
}

/** `Getting-Started` → `Getting Started` (GitHub wikis name files this way). */
export const titleFromFileName = (name) => stripExt(basename(name)).replace(/[-_]+/g, ' ').replace(/\s+/g, ' ').trim();
