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

const sha256 = async (b) => createHash('sha256').update(b).digest('hex');
const base64 = (b) => Buffer.from(b).toString('base64');
const fail = (status, code, message) => Object.assign(new Error(message), { status, code });

function fakeServer({ rejectContent, rejectFile, importCalls = Infinity, flaky = 0 } = {}) {
  const posts = [];
  const files = [];
  let seq = 0;
  let imports = 0;
  let flakes = flaky;
  const key = (topic) => (topic || '').split('/').map((s) => s.trim().toLowerCase()).join('/');
  const api = {
    calls: [],
    async get(path, query) {
      api.calls.push(['GET', path]);
      if (path === '/files') {
        const start = Number(query.cursor || 0);
        const items = files.slice(start, start + 2);
        return { items, next_cursor: start + 2 < files.length ? String(start + 2) : null };
      }
      const post = posts.find((p) => path === `/posts/${p.id}`);
      if (!post) throw fail(404, 'not_found', 'post not found');
      return { id: post.id, content: post.content, version: post.version };
    },
    async post(path, body) {
      api.calls.push(['POST', path]);
      if (flakes > 0) {
        flakes--;
        throw fail(0, 'network', 'Could not reach the server.');
      }
      if (path === '/files') {
        if (rejectFile && body.name === rejectFile) throw fail(400, 'bad_request', 'the file is empty');
        const bytes = Buffer.from(body.data_base64, 'base64');
        const id = `f${String(++seq).padStart(9, '0')}`;
        const f = { id, name: body.name, sha256: await sha256(bytes), path: `/files/${id}/${encodeURIComponent(body.name)}` };
        files.push(f);
        return f;
      }
      if (path === '/import') {
        if (++imports > importCalls) throw fail(429, 'write_limit', 'This workspace has made its 50,000 database writes for the last 24 hours.');
        const staged = [];
        const results = [];
        for (const d of body.documents) {
          if (rejectContent && d.content.includes(rejectContent)) throw fail(400, 'bad_request', 'content is larger than 2 MB');
          const match = body.skip_existing && [...posts, ...staged].find((p) => p.title === d.title && key(p.topic) === key(d.topic));
          if (match) {
            results.push({ id: match.id, title: match.title, url: `https://kb.test/p/${match.id}`, skipped: true });
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
  return { api, posts, files, refill: () => { importCalls = Infinity; } };
}

async function plan(name) {
  const source = await zipSource(await fixtureZip(name), `${name}.zip`);
  return { source, plan: await convert(name, source, { parseHtml }) };
}

const run = (p, server, extra = {}) => runImport(p.plan, { api: server.api, source: p.source, rootTopic: p.plan.rootTopic, sha256, base64, sleep: async () => {}, ...extra });

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
  assert.deepEqual([again.files.uploaded, again.files.reused], [0, 3]);
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

test('a file that fails to upload leaves its link text, and the page still imports', async () => {
  const p = await plan('confluence');
  const server = fakeServer({ rejectFile: 'checklist.pdf', flaky: 1 });
  const report = await run(p, server);
  assert.equal(report.created.length, 7);
  assert.deepEqual(report.files.failed.map((f) => f.name), ['checklist.pdf']);
  const laptop = server.posts.find((x) => x.title === 'Laptop setup').content;
  assert.ok(laptop.startsWith('Install the tools, then check the checklist.pdf.'), laptop);
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
