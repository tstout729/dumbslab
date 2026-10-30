// The import runner against a fake API that behaves like import_documents, upload_file,
// list_files, get_post and update_post: all-or-nothing calls, skip_existing, base_version.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { fixtureZip } from './helpers.mjs';
import { parseHtml } from './mini-dom.mjs';
import { zipSource } from '../../web/importers/source.js';
import { convert } from '../../web/importers/index.js';
import { runImport } from '../../web/importers/run.js';
import { pendingFile } from '../../web/importers/plan.js';

const sha256 = async (b) => createHash('sha256').update(b).digest('hex');
const base64 = (b) => Buffer.from(b).toString('base64');
const fail = (status, code, message) => Object.assign(new Error(message), { status, code });

function fakeServer({ rejectContent, rejectFile, loseUploadAnswer, legacyMatch = false, importCalls = Infinity, flaky = 0 } = {}) {
  const posts = [];
  const files = [];
  let seq = 0;
  let imports = 0;
  let flakes = flaky;
  const key = (topic) => (topic || '').split('/').map((s) => s.trim().toLowerCase()).join('/');
  const api = {
    calls: [],
    imports: [],
    async get(path, query) {
      api.calls.push(['GET', path]);
      if (path === '/files') {
        const mine = query.post_id ? files.filter((f) => f.post_id === query.post_id) : files;
        const start = Number(query.cursor || 0);
        const items = mine.slice(start, start + 2);
        return { items, next_cursor: start + 2 < mine.length ? String(start + 2) : null };
      }
      const post = posts.find((p) => path === `/posts/${p.id}`);
      if (!post) throw fail(404, 'not_found', 'post not found');
      return { id: post.id, content: post.content, version: post.version, author: { id: post.author || 'me' } };
    },
    async post(path, body) {
      api.calls.push(['POST', path]);
      if (flakes > 0) {
        flakes--;
        throw fail(0, 'network', 'Could not reach the server.');
      }
      if (path === '/files') {
        if (rejectFile && body.name === rejectFile) throw fail(400, 'bad_request', 'the file is empty');
        if (body.post_id && !posts.some((p) => p.id === body.post_id)) throw fail(404, 'not_found', 'post not found');
        const bytes = Buffer.from(body.data_base64, 'base64');
        const id = `f${String(++seq).padStart(9, '0')}`;
        const f = { id, name: body.name, sha256: await sha256(bytes), path: `/files/${id}/${encodeURIComponent(body.name)}`, post_id: body.post_id || null };
        files.push(f);
        if (loseUploadAnswer === body.name) {
          loseUploadAnswer = null;
          throw fail(0, 'network', 'Could not reach the server.');
        }
        return f;
      }
      if (path === '/import') {
        if (++imports > importCalls) throw fail(429, 'write_limit', 'This workspace has made its 50,000 database writes for the last 24 hours.');
        const staged = [];
        const results = [];
        api.imports.push(body);
        for (const raw of body.documents) {
          // A destination given by id is where paths start.
          const d = body.topic_id ? { ...raw, topic: [`#${body.topic_id}`, raw.topic].filter(Boolean).join('/') } : raw;
          if (rejectContent && d.content.includes(rejectContent)) throw fail(400, 'bad_request', 'content is larger than 2 MB');
          // Like the server: the caller's own post first; someone else's is `taken` (an older
          // server, `legacyMatch`, matched anyone's as skipped).
          const same = [...posts, ...staged].filter((p) => p.title === d.title && key(p.topic) === key(d.topic));
          const match = body.skip_existing && (same.find((p) => (p.author || 'me') === 'me') || same[0]);
          if (match) {
            const taken = (match.author || 'me') !== 'me' && !legacyMatch;
            results.push({ id: match.id, title: match.title, url: `https://kb.test/p/${match.id}`, skipped: true, taken });
            continue;
          }
          const p = { id: `p${String(++seq).padStart(9, '0')}`, title: d.title, topic: d.topic, content: d.content, status: d.status, version: 1 };
          staged.push(p);
          results.push({ id: p.id, title: p.title, url: `https://kb.test/p/${p.id}`, skipped: false });
        }
        posts.push(...staged);
        return { created: [], skipped: [], results, topics_created: 0 };
      }
      throw fail(404, 'not_found', path);
    },
    async patch(path, body) {
      api.calls.push(['PATCH', path]);
      const post = posts.find((p) => path === `/posts/${p.id}`);
      if (!post) throw fail(404, 'not_found', 'post not found');
      if (body.base_version !== undefined && body.base_version !== post.version) throw fail(409, 'conflict', 'the post changed');
      post.content = body.content;
      post.version++;
      return post;
    },
  };
  return { api, posts, files, refill: () => { importCalls = Infinity; }, rejectNone: () => { rejectFile = null; } };
}

async function plan(name) {
  const source = await zipSource(await fixtureZip(name), `${name}.zip`);
  return { source, plan: await convert(name, source, { parseHtml }) };
}

const run = (p, server, extra = {}) => runImport(p.plan, { api: server.api, source: p.source, rootTopic: p.plan.rootTopic, userId: 'me', sha256, base64, sleep: async () => {}, ...extra });

test('imports everything, uploads files once and links pages to each other', async () => {
  const p = await plan('confluence');
  const server = fakeServer();
  const report = await run(p, server, { batchSize: 2 });
  assert.equal(report.stopped, null);
  assert.equal(report.created.length, 7);
  assert.equal(report.failed.length + report.notImported.length, 0);
  assert.equal(report.files.uploaded, 3);
  const all = server.posts.map((x) => x.content).join('\n');
  assert.ok(!/dsimport:|\/search\?q=/.test(all), all);
  const byTitle = (t) => server.posts.find((x) => x.title === t);
  assert.ok(byTitle('Engineering Handbook').content.includes(`[Onboarding](/p/${byTitle('Onboarding').id})`));
  assert.ok(byTitle('Deploy the API').content.includes(`[Runbooks](/p/${byTitle('Runbooks / On-call').id})`), 'a link back to an earlier page');
  assert.match(byTitle('Laptop setup').content, /!\[Dock diagram\]\(\/files\/f\d+\/dock\.png\)/);
  assert.deepEqual([...new Set(server.posts.map((x) => x.topic))], ['Engineering Handbook', 'Engineering Handbook/Onboarding', 'Engineering Handbook/Runbooks - On-call']);

  // Running it again creates nothing, uploads nothing and changes nothing.
  const before = JSON.stringify(server.posts);
  const again = await run(p, server, { batchSize: 2 });
  assert.equal(again.created.length, 0);
  assert.equal(again.existing.length, 7);
  assert.deepEqual([again.files.uploaded, again.files.reused], [0, 0]);
  assert.equal(server.files.length, 3);
  // Each file belongs to the page that shows it.
  const laptop = byTitle('Laptop setup');
  assert.deepEqual(server.files.filter((f) => f.post_id === laptop.id).map((f) => f.name).sort(), ['checklist.pdf', 'dock.png']);
  assert.equal(JSON.stringify(server.posts), before);
});

test('a page the server refuses fails alone', async () => {
  const p = await plan('confluence');
  const server = fakeServer({ rejectContent: 'older copy' });
  const report = await run(p, server);
  assert.equal(report.created.length, 6);
  assert.deepEqual(report.failed.map((f) => f.title), ['Deploy the API (2)']);
  assert.match(report.failed[0].reason, /2 MB/);
});

test('an import that runs out of writes stops, then finishes when run again', async () => {
  const p = await plan('confluence');
  const server = fakeServer({ importCalls: 2 });
  const first = await run(p, server, { batchSize: 2 });
  assert.match(first.stopped, /database writes/);
  assert.equal(first.created.length, 4);
  assert.deepEqual(first.notImported.map((x) => x.title), ['Deploy the API', 'Deploy the API (2)', 'FAQ']);
  // Links to pages that weren't there yet are searches for now.
  assert.ok(server.posts.some((x) => x.content.includes('/search?q=')));

  server.refill();
  const second = await run(p, server, { batchSize: 2 });
  assert.equal(second.stopped, null);
  assert.deepEqual([second.created.length, second.existing.length], [3, 4]);
  assert.equal(server.posts.length, 7);
  const all = server.posts.map((x) => x.content).join('\n');
  assert.ok(!/dsimport:|\/search\?q=/.test(all), all);
});

test('a file that fails to upload is added to the importer’s own page by the next run', async () => {
  const p = await plan('confluence');
  const server = fakeServer({ rejectFile: 'dock.png', flaky: 1 });
  const first = await run(p, server);
  assert.equal(first.created.length, 7);
  assert.deepEqual(first.files.failed.map((f) => [f.name, f.page]), [['dock.png', 'Laptop setup']]);
  const laptop = () => server.posts.find((x) => x.title === 'Laptop setup');
  assert.match(laptop().content, /!\[Dock diagram\]\(#import-file-[0-9a-f]{8}\)/);
  assert.match(laptop().content, /\[checklist\.pdf\]\(\/files\/f\d+\/checklist\.pdf\)/);

  // The page is already there, so it isn't imported again, but its missing image is added.
  server.rejectNone();
  const second = await run(p, server);
  assert.deepEqual([second.created.length, second.existing.length], [0, 7]);
  assert.deepEqual([second.files.uploaded, second.files.failed.length], [1, 0]);
  assert.match(laptop().content, /!\[Dock diagram\]\(\/files\/f\d+\/dock\.png\)/);
  assert.ok(!/#import-file-/.test(server.posts.map((x) => x.content).join('\n')));
  assert.deepEqual(server.files.filter((f) => f.post_id === laptop().id).map((f) => f.name).sort(), ['checklist.pdf', 'dock.png']);
});

test('a file someone already uploaded to another page is not borrowed', async () => {
  const p = await plan('confluence');
  const server = fakeServer();
  // The same image, by the same person, on an unrelated (say private) page.
  const dock = (await p.source.bytes('attachments/1003/2001.png'));
  server.files.push({ id: 'fprivate01', name: 'dock.png', sha256: await sha256(dock), path: '/files/fprivate01/dock.png', post_id: 'pprivate01' });
  await run(p, server);
  const laptop = server.posts.find((x) => x.title === 'Laptop setup');
  assert.ok(!laptop.content.includes('fprivate01'), laptop.content);
  const shown = /\/files\/(f\d+)\/dock\.png/.exec(laptop.content)[1];
  assert.equal(server.files.find((f) => f.id === shown).post_id, laptop.id);
});

test('an upload whose answer is lost is not stored twice', async () => {
  const p = await plan('confluence');
  const server = fakeServer({ loseUploadAnswer: 'dock.png' });
  const report = await run(p, server);
  assert.equal(report.files.uploaded, 3);
  assert.equal(server.files.filter((f) => f.name === 'dock.png').length, 1);
  const laptop = server.posts.find((x) => x.title === 'Laptop setup');
  assert.match(laptop.content, /!\[Dock diagram\]\(\/files\/f\d+\/dock\.png\)/);
});

test('drafts, a different top topic and every format run cleanly', async () => {
  for (const name of ['guru', 'github-wiki', 'markdown']) {
    const p = await plan(name);
    const server = fakeServer();
    const report = await run(p, server, { status: 'draft', rootTopic: 'Imported' });
    assert.equal(report.stopped, null, name);
    assert.equal(report.created.length, p.plan.documents.length, name);
    assert.ok(server.posts.every((x) => x.status === 'draft' && x.topic.startsWith('Imported')), name);
    assert.ok(!/dsimport:|\/search\?q=/.test(server.posts.map((x) => x.content).join('\n')), name);
  }
});

test('someone else’s same-titled post is never adopted, uploaded to or changed', async () => {
  for (const legacyMatch of [false, true]) {
    const p = await plan('confluence');
    const server = fakeServer({ legacyMatch });
    // Bob's post has the title one of the pages will use, and a planted upload placeholder.
    const dock = p.plan.attachments.find((a) => a.name === 'dock.png');
    const planted = `Send it here ![x](${pendingFile(dock)}) and [x](/search?q=Onboarding&import=00000000)`;
    server.posts.push({ id: 'pbob000001', title: 'Laptop setup', topic: 'Engineering Handbook/Onboarding', content: planted, status: 'published', version: 1, author: 'bob' });
    const report = await run(p, server);
    const bobs = server.posts.find((x) => x.id === 'pbob000001');
    assert.equal(bobs.content, planted, `legacyMatch ${legacyMatch}`);
    assert.equal(bobs.version, 1);
    assert.ok(!server.files.some((f) => f.post_id === 'pbob000001'), 'no files go to Bob’s post');
    assert.ok(!server.api.calls.some(([m, path]) => m === 'PATCH' && path.includes('pbob000001')));
    assert.equal(report.created.length, 6);
    if (legacyMatch) {
      // An older server matched it; the runner checks who wrote it and leaves it alone.
      assert.deepEqual(report.linkFailed.map((x) => x.title), ['Laptop setup']);
    } else {
      assert.deepEqual(report.taken.map((x) => x.title), ['Laptop setup']);
      assert.ok(!report.existing.some((x) => x.id === 'pbob000001'));
      // Links to that page don't point at Bob's post either.
      const onboarding = server.posts.find((x) => x.title === 'Onboarding');
      assert.ok(!onboarding.content.includes('/p/pbob000001'), onboarding.content);
    }
  }
});

test('an existing destination goes by id, with every path inside it', async () => {
  const p = await plan('confluence');
  const server = fakeServer();
  const report = await run(p, server, { topicId: 'tprivate01', rootTopic: 'ignored when there is an id' });
  assert.equal(report.created.length, 7);
  assert.ok(server.api.imports.every((b) => b.topic_id === 'tprivate01'));
  const topics = server.api.imports.flatMap((b) => b.documents.map((d) => d.topic));
  assert.deepEqual([...new Set(topics)], [undefined, 'Onboarding', 'Runbooks - On-call']);
  assert.ok(!topics.some((t) => t && t.includes('ignored')));
});
