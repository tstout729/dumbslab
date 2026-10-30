// A source is the set of files an export contains, addressed by clean relative paths:
//   { name, root, paths, has(path), size(path), text(path), bytes(path) }
// zipSource reads a zip lazily; memorySource wraps files already in memory (tests, agents).

import { openZip, readEntry, ZipError, MAX_ENTRY_BYTES } from './zip.js';

/** Files no export means to include: OS metadata and version-control internals. */
export function isJunk(path) {
  const parts = path.split('/');
  const base = parts[parts.length - 1];
  return parts.some((p) => p === '__MACOSX' || p === '.git' || p === '.svn' || p === '.hg')
    || base === '.DS_Store' || base === 'Thumbs.db' || base === 'desktop.ini' || base.startsWith('._');
}

/** A zip entry name as a clean relative path, or null for one that can't be (absolute, `..`). */
export function cleanPath(name) {
  const parts = [];
  for (const part of String(name).replace(/\\/g, '/').split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') return null;
    parts.push(part);
  }
  return parts.length ? parts.join('/') : null;
}

/** Splits off one folder that holds everything (most exports have one), returning its name. */
function stripRoot(paths) {
  const first = paths.length ? paths[0].split('/')[0] : '';
  if (!first || !paths.every((p) => p.startsWith(first + '/'))) return { root: '', strip: (p) => p };
  return { root: first, strip: (p) => p.slice(first.length + 1) };
}

const decoder = new TextDecoder('utf-8');
const decodeText = (bytes) => decoder.decode(bytes).replace(/^﻿/, '');

/** Opens a zip (a File or Blob) as a source. */
export async function zipSource(blob, name = blob.name || 'export.zip') {
  const { entries } = await openZip(blob);
  const kept = [];
  for (const e of entries) {
    if (e.dir) continue;
    const path = cleanPath(e.name);
    if (!path || isJunk(path)) continue;
    kept.push([path, e]);
  }
  if (!kept.length) throw new ZipError('This zip has no files in it.');
  const { root, strip } = stripRoot(kept.map(([p]) => p));
  const files = new Map(kept.map(([p, e]) => [strip(p), e]));
  // A cloned wiki zipped with its .git folder names its origin there; keep that one file.
  const gitConfig = entries.find((e) => {
    const p = cleanPath(e.name);
    return p && (p === '.git/config' || p.endsWith('/.git/config')) && (p.split('/').length <= 3);
  });
  return {
    name,
    root,
    paths: [...files.keys()].sort(),
    has: (p) => files.has(p),
    size: (p) => (files.has(p) ? files.get(p).size : 0),
    bytes: (p, opts) => readEntry(blob, files.get(p), opts),
    text: async (p, opts) => decodeText(await readEntry(blob, files.get(p), opts)),
    gitConfig: gitConfig ? async () => decodeText(await readEntry(blob, gitConfig, { maxBytes: 64 * 1024 })) : null,
  };
}

/** A source over `{ path: string | Uint8Array }`. */
export function memorySource(map, name = 'export', { gitConfig = null } = {}) {
  const enc = new TextEncoder();
  const raw = new Map();
  for (const [k, v] of Object.entries(map)) {
    const p = cleanPath(k);
    if (p && !isJunk(p)) raw.set(p, typeof v === 'string' ? enc.encode(v) : v);
  }
  const { root, strip } = stripRoot([...raw.keys()]);
  const files = new Map([...raw].map(([p, v]) => [strip(p), v]));
  const get = (p, { maxBytes = MAX_ENTRY_BYTES } = {}) => {
    const v = files.get(p);
    if (!v) throw new ZipError(`“${p}” isn’t in the export.`);
    if (v.length > maxBytes) throw new ZipError(`“${p}” is too large.`);
    return v;
  };
  return {
    name,
    root,
    paths: [...files.keys()].sort(),
    has: (p) => files.has(p),
    size: (p) => (files.has(p) ? files.get(p).length : 0),
    bytes: async (p, opts) => get(p, opts),
    text: async (p, opts) => decodeText(get(p, opts)),
    gitConfig: gitConfig ? async () => gitConfig : null,
  };
}
