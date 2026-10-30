// Runs an import plan against the API: uploads the attachments a batch needs, imports the batch
// with import_documents, then points links that were waiting for later pages at them. Running a
// plan again is safe: pages already there are matched (skip_existing) and files already uploaded
// are reused by checksum.

import { fillTokens, pendingLink, byteLength, MAX_FILE_BYTES } from './plan.js';
import { topicSegment } from './paths.js';

/** Pages per import_documents call: small enough to retry and show progress, large enough to be quick. */
const BATCH_DOCS = 25;
/** The request body limit is 8 MB. */
const BATCH_BYTES = 4_000_000;

/** Errors that end the whole import: nothing after them would succeed either. */
export class StopImport extends Error {
  constructor(cause, message) {
    super(message || (cause && cause.message) || 'The import stopped.');
    this.name = 'StopImport';
    this.cause = cause;
  }
}

function stops(e) {
  const status = e && e.status;
  return status === 401 || status === 403 || status === 507 || status === 429
    || (status === 503 && e.code === 'free_capacity') || (e && e.name === 'AbortError');
}

/**
 * opts: { api: { get, post, patch }, source, rootTopic, status, sha256(bytes), base64(bytes),
 * onProgress(progress), signal, sleep(ms) }. Resolves to a report; never throws for a failed page.
 */
export async function runImport(plan, opts) {
  const { api, source, sha256, base64, signal } = opts;
  const sleep = opts.sleep || ((ms) => new Promise((r) => setTimeout(r, ms)));
  const status = opts.status === 'draft' ? 'draft' : 'published';
  const root = topicSegment(opts.rootTopic || '');
  const report = {
    created: [], existing: [], failed: [], notImported: [], stopped: null,
    files: { uploaded: 0, reused: 0, failed: [] },
    linked: 0, linkFailed: [],
  };
  const progress = { phase: 'import', docsDone: 0, docsTotal: plan.documents.length, filesDone: 0, filesTotal: plan.attachments.length, linksDone: 0, linksTotal: 0, failed: 0 };
  const tell = () => opts.onProgress && opts.onProgress({ ...progress });

  const checkAbort = () => {
    if (signal && signal.aborted) {
      const e = new Error('Cancelled');
      e.name = 'AbortError';
      throw e;
    }
  };

  /** One API call with retries for network trouble, server errors and the request limit. */
  async function call(fn) {
    for (let attempt = 0; ; attempt++) {
      checkAbort();
      try {
        return await fn();
      } catch (e) {
        if (e && e.name === 'AbortError') throw new StopImport(e, 'Cancelled.');
        const s = e && typeof e.status === 'number' ? e.status : 0;
        if (s === 429 && e.code === 'rate_limited' && attempt < 5) {
          await sleep(30_000);
          continue;
        }
        if ((s === 0 || (s >= 500 && s !== 507 && !(s === 503 && e.code === 'free_capacity'))) && attempt < 3) {
          await sleep([2000, 5000, 15000][attempt]);
          continue;
        }
        if (stops(e)) throw new StopImport(e);
        throw e;
      }
    }
  }

  const docs = new Map();
  const files = new Map();
  const waiting = new Set();
  let mine = null;

  async function myFiles() {
    if (mine) return mine;
    mine = new Map();
    let cursor;
    for (let pages = 0; pages < 100; pages++) {
      const r = await call(() => api.get('/files', { uploaded_by: 'me', limit: 200, cursor }));
      for (const f of r.items || []) mine.set(`${f.sha256}\u0000${f.name}`, f.path);
      cursor = r.next_cursor;
      if (!cursor) break;
    }
    return mine;
  }

  async function upload(att) {
    const bytes = await source.bytes(att.path, { maxBytes: MAX_FILE_BYTES });
    const sum = await sha256(bytes);
    const known = (await myFiles()).get(`${sum}\u0000${att.name}`);
    if (known) {
      report.files.reused++;
      return known;
    }
    const body = { name: att.name, data_base64: base64(bytes) };
    if (att.type) body.content_type = att.type;
    const r = await call(() => api.post('/files', body));
    mine.set(`${sum}\u0000${att.name}`, r.path);
    report.files.uploaded++;
    return r.path;
  }

  const topicOf = (d) => [root, ...d.topic].map(topicSegment).filter(Boolean).join('/') || undefined;

  function content(d) {
    return fillTokens(d.markdown, {
      page: (n) => {
        if (docs.has(n)) return `/p/${docs.get(n).id}`;
        const target = plan.byNumber.get(n);
        if (!target) return null;
        waiting.add(d.n);
        return pendingLink(target);
      },
      file: (n) => files.get(n) || null,
    });
  }

  function record(d, result, sent) {
    docs.set(d.n, { id: result.id, url: result.url, created: !result.skipped, sent });
    (result.skipped ? report.existing : report.created).push({ title: d.title, id: result.id, url: result.url, path: d.path });
  }

  const batches = [];
  let cur = [];
  let size = 0;
  for (const d of plan.documents) {
    // As JSON (newlines and quotes double), plus room for the links and file paths filled in.
    const bytes = byteLength(JSON.stringify(d.markdown)) + byteLength(d.title) + 300 + (d.markdown.match(/dsimport:/g) || []).length * 300;
    if (cur.length && (cur.length >= (opts.batchSize || BATCH_DOCS) || size + bytes > BATCH_BYTES)) {
      batches.push(cur);
      cur = [];
      size = 0;
    }
    cur.push(d);
    size += bytes;
  }
  if (cur.length) batches.push(cur);

  const attachmentsByNumber = new Map(plan.attachments.map((a) => [a.n, a]));
  let bi = 0;
  try {
    for (; bi < batches.length; bi++) {
      const batch = batches[bi];
      // Files this batch shows, uploaded first so its Markdown can point at them.
      for (const d of batch) {
        for (const m of d.markdown.matchAll(/dsimport:file:(\d+)/g)) {
          const n = Number(m[1]);
          if (files.has(n) || !attachmentsByNumber.has(n)) continue;
          const att = attachmentsByNumber.get(n);
          progress.phase = 'upload';
          progress.current = att.name;
          tell();
          try {
            files.set(n, await upload(att));
          } catch (e) {
            if (e instanceof StopImport) throw e;
            files.set(n, null);
            report.files.failed.push({ name: att.name, path: att.path, reason: e.message || String(e) });
          }
          progress.filesDone++;
          tell();
        }
      }
      progress.phase = 'import';
      progress.current = batch[0].title;
      tell();
      const payload = batch.map((d) => ({ d, doc: { title: d.title, content: content(d), topic: topicOf(d), status } }));
      try {
        const r = await call(() => api.post('/import', { skip_existing: true, documents: payload.map((p) => p.doc) }));
        payload.forEach((p, i) => record(p.d, r.results[i], p.doc.content));
      } catch (e) {
        if (e instanceof StopImport) throw e;
        // One bad page fails its whole batch; import them one by one to find it.
        for (const p of payload) {
          try {
            const r = await call(() => api.post('/import', { skip_existing: true, documents: [p.doc] }));
            record(p.d, r.results[0], p.doc.content);
          } catch (e2) {
            if (e2 instanceof StopImport) {
              report.notImported.push(...payload.slice(payload.indexOf(p)).map((x) => ({ title: x.d.title, path: x.d.path })));
              bi++;
              throw e2;
            }
            report.failed.push({ title: p.d.title, path: p.d.path, reason: e2.message || String(e2) });
            progress.failed++;
          }
        }
      }
      progress.docsDone += batch.length;
      tell();
    }

    // Links that waited for pages imported later, and pages a previous run left waiting.
    const toLink = plan.documents.filter((d) => docs.has(d.n) && (waiting.has(d.n) || (!docs.get(d.n).created && /dsimport:page:/.test(d.markdown))));
    progress.phase = 'link';
    progress.linksTotal = toLink.length;
    tell();
    for (const d of toLink) {
      const t = docs.get(d.n);
      const targets = [...new Set([...d.markdown.matchAll(/dsimport:page:(\d+)/g)].map((m) => Number(m[1])))]
        .filter((n) => docs.has(n) && plan.byNumber.has(n));
      const fix = (text) => targets.reduce((s, n) => s.split(pendingLink(plan.byNumber.get(n))).join(`/p/${docs.get(n).id}`), text);
      progress.current = d.title;
      try {
        let done = false;
        if (t.created && t.sent !== undefined) {
          const next = fix(t.sent);
          if (next === t.sent) done = true;
          else {
            try {
              await call(() => api.patch(`/posts/${encodeURIComponent(t.id)}`, { content: next, base_version: 1, note: 'Linked imported pages' }));
              report.linked++;
              done = true;
            } catch (e) {
              if (e instanceof StopImport || e.status !== 409) throw e;
            }
          }
        }
        if (!done) {
          const post = await call(() => api.get(`/posts/${encodeURIComponent(t.id)}`));
          const next = fix(post.content);
          if (next !== post.content) {
            await call(() => api.patch(`/posts/${encodeURIComponent(t.id)}`, { content: next, base_version: post.version, note: 'Linked imported pages' }));
            report.linked++;
          }
        }
      } catch (e) {
        if (e instanceof StopImport) throw e;
        report.linkFailed.push({ title: d.title, url: t.url, reason: e.message || String(e) });
      }
      progress.linksDone++;
      tell();
    }
  } catch (e) {
    if (!(e instanceof StopImport)) throw e;
    report.stopped = e.message;
    for (let k = bi; k < batches.length; k++) {
      for (const d of batches[k]) {
        if (!docs.has(d.n) && !report.notImported.some((x) => x.path === d.path)) report.notImported.push({ title: d.title, path: d.path });
      }
    }
  }
  progress.phase = 'done';
  progress.current = '';
  tell();
  return report;
}
