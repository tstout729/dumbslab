// Test helpers: fixture folders as zips, built in memory with the platform's CompressionStream.

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { crc32 } from '../../web/importers/zip.js';

export const FIXTURES = fileURLToPath(new URL('./fixtures/', import.meta.url));

/** Every file under a fixture folder, as { 'relative/path': Uint8Array }. */
export function readFixture(name) {
  const root = join(FIXTURES, name);
  const out = {};
  const walk = (dir) => {
    for (const entry of readdirSync(dir)) {
      const p = join(dir, entry);
      if (statSync(p).isDirectory()) walk(p);
      else out[relative(root, p).split('\\').join('/')] = new Uint8Array(readFileSync(p));
    }
  };
  walk(root);
  return out;
}

async function deflate(bytes) {
  const stream = new Blob([bytes]).stream().pipeThrough(new CompressionStream('deflate-raw'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/**
 * A zip Blob of `files` ({ path: string | Uint8Array }). Text is deflated and binary stored,
 * so both methods get read. `utf8Flag: false` leaves the UTF-8 name flag off.
 */
export async function makeZip(files, { utf8Flag = true, comment = '' } = {}) {
  const enc = new TextEncoder();
  const locals = [];
  const central = [];
  let offset = 0;
  for (const [path, value] of Object.entries(files)) {
    const data = typeof value === 'string' ? enc.encode(value) : value;
    const name = enc.encode(path);
    const deflated = typeof value === 'string' && data.length > 0;
    const body = deflated ? await deflate(data) : data;
    const crc = crc32(data);
    const flags = utf8Flag ? 0x800 : 0;
    const local = new DataView(new ArrayBuffer(30));
    local.setUint32(0, 0x04034b50, true);
    local.setUint16(4, 20, true);
    local.setUint16(6, flags, true);
    local.setUint16(8, deflated ? 8 : 0, true);
    local.setUint32(14, crc, true);
    local.setUint32(18, body.length, true);
    local.setUint32(22, data.length, true);
    local.setUint16(26, name.length, true);
    locals.push(new Uint8Array(local.buffer), name, body);
    const cd = new DataView(new ArrayBuffer(46));
    cd.setUint32(0, 0x02014b50, true);
    cd.setUint16(4, 20, true);
    cd.setUint16(6, 20, true);
    cd.setUint16(8, flags, true);
    cd.setUint16(10, deflated ? 8 : 0, true);
    cd.setUint32(16, crc, true);
    cd.setUint32(20, body.length, true);
    cd.setUint32(24, data.length, true);
    cd.setUint16(28, name.length, true);
    cd.setUint32(42, offset, true);
    central.push(new Uint8Array(cd.buffer), name);
    offset += 30 + name.length + body.length;
  }
  const cdSize = central.reduce((s, b) => s + b.length, 0);
  const note = enc.encode(comment);
  const end = new DataView(new ArrayBuffer(22));
  end.setUint32(0, 0x06054b50, true);
  end.setUint16(8, Object.keys(files).length, true);
  end.setUint16(10, Object.keys(files).length, true);
  end.setUint32(12, cdSize, true);
  end.setUint32(16, offset, true);
  end.setUint16(20, note.length, true);
  return new Blob([...locals, ...central, new Uint8Array(end.buffer), note]);
}

/** A fixture folder as a zip, with every path under `prefix`. */
export async function fixtureZip(name, { prefix = '', extra = {} } = {}) {
  const files = {};
  for (const [p, v] of Object.entries(readFixture(name))) files[prefix + p] = isText(p) ? new TextDecoder().decode(v) : v;
  for (const [p, v] of Object.entries(extra)) files[p] = v;
  return makeZip(files);
}

const isText = (p) => /\.(html?|md|ya?ml|css|txt|textile|mdx)$/i.test(p);
