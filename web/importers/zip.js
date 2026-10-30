// Reads .zip files in the browser without loading them whole: the central directory first, then
// one entry at a time through Blob.slice. Deflated entries are inflated with the platform's
// DecompressionStream('deflate-raw'). Supports stored and deflated entries, UTF-8 and CP437
// names, data descriptors and Zip64. Encrypted entries and other methods are reported, not read.

/** The largest zip the importer opens. */
export const MAX_ZIP_BYTES = 1024 * 1024 * 1024;
/** More entries than this is almost certainly not a wiki export. */
export const MAX_ENTRIES = 200_000;

export class ZipError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ZipError';
  }
}

const EOCD = 0x06054b50;
const ZIP64_LOCATOR = 0x07064b50;
const ZIP64_EOCD = 0x06064b50;
const CENTRAL = 0x02014b50;
const LOCAL = 0x04034b50;
const U32 = 0xffffffff;

async function bytesAt(blob, start, end) {
  return new Uint8Array(await blob.slice(start, end).arrayBuffer());
}

const view = (b) => new DataView(b.buffer, b.byteOffset, b.byteLength);
const u64 = (dv, at) => dv.getUint32(at, true) + dv.getUint32(at + 4, true) * 2 ** 32;

// CP437's upper half, for names written by tools that predate the UTF-8 flag.
const CP437 = 'ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u00a0';
const utf8 = new TextDecoder('utf-8', { fatal: true });

function decodeName(raw, isUtf8) {
  if (isUtf8) return new TextDecoder('utf-8').decode(raw);
  try {
    // Most modern tools write UTF-8 without setting the flag.
    return utf8.decode(raw);
  } catch {
    let s = '';
    for (const b of raw) s += b < 0x80 ? String.fromCharCode(b) : CP437[b - 0x80];
    return s;
  }
}

/**
 * Lists a zip's entries. Each entry: { name, size, compressedSize, method, encrypted, dir,
 * offset, crc }. Throws ZipError for anything that isn't a readable zip.
 */
export async function openZip(blob) {
  if (blob.size > MAX_ZIP_BYTES) {
    throw new ZipError(`This file is ${formatSize(blob.size)}. The importer opens zips up to ${formatSize(MAX_ZIP_BYTES)}; export a smaller part (one space or collection at a time), or have an agent import it.`);
  }
  if (blob.size < 22) throw new ZipError('This file is too small to be a zip.');
  // The end record sits in the last 22 bytes plus a comment of up to 65,535 bytes.
  const tailStart = Math.max(0, blob.size - 22 - 65535);
  const tail = await bytesAt(blob, tailStart, blob.size);
  const tv = view(tail);
  let at = -1;
  for (let i = tail.length - 22; i >= 0; i--) {
    if (tv.getUint32(i, true) === EOCD) {
      at = i;
      break;
    }
  }
  if (at < 0) throw new ZipError('This isn’t a zip file (or it is damaged). Choose the .zip the export produced.');
  let count = tv.getUint16(at + 10, true);
  let cdSize = tv.getUint32(at + 12, true);
  let cdOffset = tv.getUint32(at + 16, true);
  if (count === 0xffff || cdSize === U32 || cdOffset === U32) {
    const loc = at - 20;
    if (loc < 0 || tv.getUint32(loc, true) !== ZIP64_LOCATOR) throw new ZipError('This zip’s directory is damaged.');
    const recAt = u64(tv, loc + 8);
    const rec = view(await bytesAt(blob, recAt, recAt + 56));
    if (rec.getUint32(0, true) !== ZIP64_EOCD) throw new ZipError('This zip’s directory is damaged.');
    count = u64(rec, 32);
    cdSize = u64(rec, 40);
    cdOffset = u64(rec, 48);
  }
  if (count > MAX_ENTRIES) throw new ZipError(`This zip has ${count.toLocaleString('en-US')} files; the importer reads at most ${MAX_ENTRIES.toLocaleString('en-US')}.`);
  if (cdOffset + cdSize > blob.size) throw new ZipError('This zip is incomplete. Download the export again.');
  const cd = await bytesAt(blob, cdOffset, cdOffset + cdSize);
  const dv = view(cd);
  const entries = [];
  let p = 0;
  for (let n = 0; n < count; n++) {
    if (p + 46 > cd.length || dv.getUint32(p, true) !== CENTRAL) throw new ZipError('This zip’s directory is damaged.');
    const flags = dv.getUint16(p + 8, true);
    const method = dv.getUint16(p + 10, true);
    const crc = dv.getUint32(p + 16, true);
    let compressedSize = dv.getUint32(p + 20, true);
    let size = dv.getUint32(p + 24, true);
    const nameLen = dv.getUint16(p + 28, true);
    const extraLen = dv.getUint16(p + 30, true);
    const commentLen = dv.getUint16(p + 32, true);
    let offset = dv.getUint32(p + 42, true);
    const name = decodeName(cd.subarray(p + 46, p + 46 + nameLen), (flags & 0x800) !== 0);
    // Zip64 sizes and offset live in extra field 0x0001, only for the values set to 0xFFFFFFFF.
    let e = p + 46 + nameLen;
    const extraEnd = e + extraLen;
    while (e + 4 <= extraEnd) {
      const id = dv.getUint16(e, true);
      const len = dv.getUint16(e + 2, true);
      if (id === 0x0001) {
        let q = e + 4;
        if (size === U32) { size = u64(dv, q); q += 8; }
        if (compressedSize === U32) { compressedSize = u64(dv, q); q += 8; }
        if (offset === U32) { offset = u64(dv, q); }
      }
      e += 4 + len;
    }
    entries.push({ name, size, compressedSize, method, crc, offset, encrypted: (flags & 1) !== 0, dir: name.endsWith('/') });
    p = extraEnd + commentLen;
  }
  return { entries };
}

/**
 * Reads one entry's bytes. Refuses entries larger than `maxBytes`, encrypted ones and
 * compression methods other than stored and deflate, and checks the CRC.
 */
export async function readEntry(blob, entry, { maxBytes = Infinity } = {}) {
  if (entry.encrypted) throw new ZipError(`“${entry.name}” is encrypted.`);
  if (entry.method !== 0 && entry.method !== 8) throw new ZipError(`“${entry.name}” uses a compression method browsers can’t read (${entry.method}).`);
  if (entry.size > maxBytes) throw new ZipError(`“${entry.name}” is ${formatSize(entry.size)}, more than the ${formatSize(maxBytes)} allowed.`);
  const head = view(await bytesAt(blob, entry.offset, entry.offset + 30));
  if (head.byteLength < 30 || head.getUint32(0, true) !== LOCAL) throw new ZipError(`“${entry.name}” is damaged.`);
  const start = entry.offset + 30 + head.getUint16(26, true) + head.getUint16(28, true);
  const raw = blob.slice(start, start + entry.compressedSize);
  let out;
  if (entry.method === 0) {
    out = new Uint8Array(await raw.arrayBuffer());
  } else {
    out = await inflate(raw, entry);
  }
  if (out.length !== entry.size) throw new ZipError(`“${entry.name}” is damaged (its size doesn’t match).`);
  if (crc32(out) !== entry.crc) throw new ZipError(`“${entry.name}” is damaged (its checksum doesn’t match).`);
  return out;
}

/** Inflates a deflated entry, stopping as soon as it produces more than its stated size. */
async function inflate(raw, entry) {
  const out = new Uint8Array(entry.size);
  let filled = 0;
  const reader = raw.stream().pipeThrough(new DecompressionStream('deflate-raw')).getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (filled + value.length > entry.size) throw new ZipError(`“${entry.name}” is damaged (it inflates past its stated size).`);
      out.set(value, filled);
      filled += value.length;
    }
  } catch (e) {
    if (e instanceof ZipError) throw e;
    throw new ZipError(`“${entry.name}” is damaged and can’t be decompressed.`);
  } finally {
    reader.cancel().catch(() => {});
  }
  return out.subarray(0, filled);
}

let table = null;

export function crc32(bytes) {
  if (!table) {
    table = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      table[n] = c >>> 0;
    }
  }
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) c = table[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

export function formatSize(n) {
  if (n < 1024) return `${n} bytes`;
  if (n < 1024 * 1024) return `${Math.round(n / 1024)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(n < 10 * 1024 * 1024 ? 1 : 0).replace(/\.0$/, '')} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(1).replace(/\.0$/, '')} GB`;
}
