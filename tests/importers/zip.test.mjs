import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeZip } from './helpers.mjs';
import { openZip, readEntry, ZipError, MAX_ZIP_BYTES, MAX_ENTRY_BYTES } from '../../web/importers/zip.js';
import { zipSource, cleanPath, isJunk } from '../../web/importers/source.js';

test('reads stored and deflated entries with UTF-8 names', async () => {
  const png = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 1, 2, 3]);
  const zip = await makeZip({ 'Space/Über café.html': '<p>héllo</p>'.repeat(50), 'Space/a.png': png }, { comment: 'made by a test' });
  const { entries } = await openZip(zip);
  assert.deepEqual(entries.map((e) => [e.name, e.method]), [['Space/Über café.html', 8], ['Space/a.png', 0]]);
  const html = new TextDecoder().decode(await readEntry(zip, entries[0]));
  assert.equal(html, '<p>héllo</p>'.repeat(50));
  assert.deepEqual(await readEntry(zip, entries[1]), png);
});

test('refuses what it can’t read, with a reason', async () => {
  await assert.rejects(openZip(new Blob(['not a zip at all, just some text in a file'])), /isn’t a zip/);
  await assert.rejects(openZip({ size: MAX_ZIP_BYTES + 1 }), (e) => e instanceof ZipError && /1 GB/.test(e.message));
  const zip = await makeZip({ 'a.txt': 'hello hello hello' });
  const { entries } = await openZip(zip);
  await assert.rejects(readEntry(zip, { ...entries[0], crc: entries[0].crc ^ 1 }), /checksum/);
  await assert.rejects(readEntry(zip, { ...entries[0], size: 3 }), /damaged|allowed/);
  await assert.rejects(readEntry(zip, entries[0], { maxBytes: 4 }), /more than/);
  await assert.rejects(readEntry(zip, { ...entries[0], method: 12 }), /compression method/);
  await assert.rejects(readEntry(zip, { ...entries[0], encrypted: true }), /encrypted/);
});

test('a source drops junk and the folder everything sits in', async () => {
  const zip = await makeZip({
    'ENG/index.html': '<html></html>',
    'ENG/attachments/1/2.png': new Uint8Array([1]),
    '__MACOSX/ENG/._index.html': 'x',
    'ENG/.DS_Store': 'x',
    '/': '',
  });
  const src = await zipSource(zip, 'eng.zip');
  assert.equal(src.root, 'ENG');
  assert.deepEqual(src.paths, ['attachments/1/2.png', 'index.html']);
  assert.equal(await src.text('index.html'), '<html></html>');
  assert.equal(src.size('attachments/1/2.png'), 1);
  assert.equal(cleanPath('a/../b'), null);
  assert.equal(cleanPath('\\a\\b.md'), 'a/b.md');
  assert.ok(isJunk('repo.wiki/.git/HEAD'));
});

test('a cloned wiki keeps its .git/config for the repository name', async () => {
  const zip = await makeZip({ 'w.wiki/Home.md': 'hi', 'w.wiki/.git/config': '[remote "origin"]\n\turl = https://github.com/o/w.wiki.git\n' });
  const src = await zipSource(zip);
  assert.deepEqual(src.paths, ['Home.md']);
  assert.match(await src.gitConfig(), /o\/w\.wiki\.git/);
});

test('crafted sizes are refused before anything large is read', async () => {
  const big = new Uint8Array(2 * 1024 * 1024).fill(7);
  // A stored entry that claims 1 byte but spans 2 MB of data.
  const liar = await makeZip({ 'a.bin': big }, { lie: { 'a.bin': { size: 1 } } });
  const [a] = (await openZip(liar)).entries;
  await assert.rejects(readEntry(liar, a), /sizes don’t agree/);
  // A deflated entry that claims far more compressed bytes than its size could need.
  const inflated = await makeZip({ 'b.txt': 'short text' }, { lie: { 'b.txt': { compressedSize: 5_000_000 } } });
  const [b] = (await openZip(inflated)).entries;
  await assert.rejects(readEntry(inflated, b), /sizes don’t agree/);
  // Sizes that agree but run past the end of the file.
  const cut = await makeZip({ 'c.bin': new Uint8Array(10) }, { lie: { 'c.bin': { size: 4000, compressedSize: 4000 } } });
  const [c] = (await openZip(cut)).entries;
  await assert.rejects(readEntry(cut, c), /past the end/);
  // An entry that says it is enormous is refused whatever the caller allows.
  const huge = await makeZip({ 'd.bin': new Uint8Array(4) }, { lie: { 'd.bin': { size: MAX_ENTRY_BYTES + 1, compressedSize: MAX_ENTRY_BYTES + 1 } } });
  const [d] = (await openZip(huge)).entries;
  await assert.rejects(readEntry(huge, d, { maxBytes: Infinity }), /more than the 64 MB allowed/);
  // The honest version reads.
  const honest = await makeZip({ 'a.bin': big });
  assert.equal((await readEntry(honest, (await openZip(honest)).entries[0])).length, big.length);
});
