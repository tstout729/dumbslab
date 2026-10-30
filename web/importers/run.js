// Runs an import plan against the API in two steps.
//
// 1. Pages: batches go to import_documents with skip_existing. Links to pages that don't exist
//    yet and images and files that aren't uploaded yet are placeholders (see plan.js).
// 2. Finishing: each page with placeholders gets its files, uploaded to that page (so exactly its
//    readers can open them), and links to the pages that now exist, in one save.
//
// Running a plan again is safe. Pages already there are matched, not duplicated, and their
// remaining placeholders are finished, so a file that failed to upload the first time is
// uploaded then. A file already uploaded to a page is reused by checksum and name.
//
// Only the importer's own posts are ever finished. import_documents matches only the caller's
// posts; a page whose title someone else's post already has is reported, not imported, and
// before changing an existing post the runner checks that the importer wrote it.

import { fillTokens, pendingLink, pendingFile, byteLength, MAX_FILE_BYTES } from './plan.js';
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

/** No answer, or a server error: the request may or may not have taken effect. */
const ambiguous = (e) => {
  const s = e && typeof e.status === 'number' ? e.status : 0;
  return s === 0 || (s >= 500 && s !== 507 && !(s === 503 && e.code === 'free_capacity'));
};

/**
 * opts: { api: { get, post, patch }, source, topicId (an existing destination topic, see
 * destination.js) or rootTopic (the name of one to create), status, userId (the importer),
 * sha256(bytes), base64(bytes), onProgress(progress), signal, sleep(ms) }. Resolves to a report;
 * never throws for a failed page.
 */
export async function runImport(plan, opts) {
  const { api, source, sha256, base64, signal } = opts;
  const sleep = opts.sleep || ((ms) => new Promise((r) => setTimeout(r, ms)));
  const status = opts.status === 'draft' ? 'draft' : 'published';
  // An existing destination goes by id, so the server checks it, and nothing is renamed away from it.
  const topicId = opts.topicId || null;
  const root = topicId ? '' : topicSegment(opts.rootTopic || '');
  const importCall = (documents) => api.post('/import', topicId ? { skip_existing: true, topic_id: topicId, documents } : { skip_existing: true, documents });
  const report = {
    created: [], existing: [], taken: [], failed: [], notImported: [], stopped: null,
    files: { uploaded: 0, reused: 0, failed: [] },
    linked: 0, linkFailed: [],
  };
  const progress = { phase: 'import', docsDone: 0, docsTotal: plan.documents.length, finishDone: 0, finishTotal: 0, failed: 0 };
  const tell = () => opts.onProgress && opts.onProgress({ ...progress });

  const checkAbort = () => {
    if (signal && signal.aborted) throw new StopImport(null, 'Cancelled.');
  };

  /** One API call, retried after network trouble, server errors and the request limit. */
  async function call(fn) {
    for (let attempt = 0; ; attempt++) {
      checkAbort();
      try {
        return await fn();
      } catch (e) {
        if (e && e.name === 'AbortError') throw new StopImport(e, 'Cancelled.');
        if (e && e.status === 429 && e.code === 'rate_limited' && attempt < 5) {
          await sleep(30_000);
          continue;
        }
        if (ambiguous(e) && attempt < 3) {
          await sleep([2000, 5000, 15000][attempt]);
          continue;
        }
        if (stops(e)) throw new StopImport(e);
        throw e;
      }
    }
  }

  const docs = new Map();
  const attachments = new Map(plan.attachments.map((a) => [a.n, a]));
  const topicOf = (d) => [root, ...d.topic].map(topicSegment).filter(Boolean).join('/') || undefined;
  const pageRefs = (d) => [...new Set([...d.markdown.matchAll(/dsimport:page:(\d+)/g)].map((m) => Number(m[1])))];
  const fileRefs = (d) => [...new Set([...d.markdown.matchAll(/dsimport:file:(\d+)/g)].map((m) => Number(m[1])))].filter((n) => attachments.has(n));

  // ---------------------------------------------------------------------------
  // 1. Pages

  function content(d) {
    return fillTokens(d.markdown, {
      page: (n) => {
        if (docs.has(n)) return `/p/${docs.get(n).id}`;
        const target = plan.byNumber.get(n);
        return target ? pendingLink(target) : null;
      },
      file: (n) => (attachments.has(n) ? pendingFile(attachments.get(n)) : null),
    });
  }

  function record(d, result, sent) {
    const entry = { title: d.title, id: result.id, url: result.url, path: d.path };
    if (result.taken) {
      // Someone else's post has this title here. It isn't this import's page: never link to,
      // upload to or change it.
      report.taken.push(entry);
      return;
    }
    docs.set(d.n, { id: result.id, url: result.url, created: !result.skipped, sent });
    (result.skipped ? report.existing : report.created).push(entry);
  }

  const batches = [];
  let cur = [];
  let size = 0;
  for (const d of plan.documents) {
    // As JSON (newlines and quotes double), plus room for links and placeholders filled in.
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

  let bi = 0;
  try {
    for (; bi < batches.length; bi++) {
      const batch = batches[bi];
      progress.current = batch[0].title;
      tell();
      const payload = batch.map((d) => ({ d, doc: { title: d.title, content: content(d), topic: topicOf(d), status } }));
      try {
        const r = await call(() => importCall(payload.map((p) => p.doc)));
        payload.forEach((p, i) => record(p.d, r.results[i], p.doc.content));
      } catch (e) {
        if (e instanceof StopImport) throw e;
        // One bad page fails its whole batch; import them one by one to find it.
        for (const p of payload) {
          try {
            const r = await call(() => importCall([p.doc]));
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
  } catch (e) {
    if (!(e instanceof StopImport)) throw e;
    report.stopped = e.message;
    for (let k = bi; k < batches.length; k++) {
      for (const d of batches[k]) {
        if (!docs.has(d.n) && !report.notImported.some((x) => x.path === d.path)) report.notImported.push({ title: d.title, path: d.path });
      }
    }
  }

  // ---------------------------------------------------------------------------
  // 2. Finishing: files and links. This runs even after a stop, for the pages that are in, so a
  // stop leaves as little as possible for the next run; it stops itself at the next refusal.

  /** Files already uploaded to a post, by checksum and name. */
  const onPost = new Map();
  async function attachedTo(postId, { fresh = false } = {}) {
    if (onPost.has(postId) && !fresh) return onPost.get(postId);
    const found = new Map();
    let cursor;
    for (let page = 0; page < 50; page++) {
      const r = await call(() => api.get('/files', { post_id: postId, limit: 200, cursor }));
      for (const f of r.items || []) found.set(`${f.sha256}\u0000${f.name}`, f.path);
      cursor = r.next_cursor;
      if (!cursor) break;
    }
    onPost.set(postId, found);
    return found;
  }

  /** Uploads a file to a post, or finds it already there. Never stores the same file twice. */
  async function uploadTo(postId, att) {
    const bytes = await source.bytes(att.path, { maxBytes: MAX_FILE_BYTES });
    const key = `${await sha256(bytes)}\u0000${att.name}`;
    const known = (await attachedTo(postId)).get(key);
    if (known) {
      report.files.reused++;
      return known;
    }
    const body = { name: att.name, data_base64: base64(bytes), post_id: postId };
    if (att.type) body.content_type = att.type;
    for (let attempt = 0; ; attempt++) {
      checkAbort();
      try {
        const r = await api.post('/files', body);
        onPost.get(postId).set(key, r.path);
        report.files.uploaded++;
        return r.path;
      } catch (e) {
        if (e && e.name === 'AbortError') throw new StopImport(e, 'Cancelled.');
        if (e && e.status === 429 && e.code === 'rate_limited' && attempt < 5) {
          await sleep(30_000);
          continue;
        }
        if (!ambiguous(e) || attempt >= 3) {
          if (stops(e)) throw new StopImport(e);
          throw e;
        }
        // The upload may have landed even though the answer didn't: look before sending it again.
        await sleep([2000, 5000, 15000][attempt]);
        const landed = (await attachedTo(postId, { fresh: true })).get(key);
        if (landed) {
          report.files.uploaded++;
          return landed;
        }
      }
    }
  }

  const toFinish = plan.documents.filter((d) => {
    const t = docs.get(d.n);
    if (!t) return false;
    const hasRefs = pageRefs(d).length || fileRefs(d).length;
    return t.created ? /#import-file-|\/search\?q=[^)\s"]*&import=/.test(t.sent) : hasRefs;
  });
  progress.phase = 'finish';
  progress.finishTotal = toFinish.length;
  progress.current = '';
  tell();
  try {
    for (const d of toFinish) {
      checkAbort();
      const t = docs.get(d.n);
      progress.current = d.title;
      tell();
      try {
        let text;
        let version;
        if (t.created && t.sent !== undefined) {
          text = t.sent;
          version = 1;
        } else {
          const post = await call(() => api.get(`/posts/${encodeURIComponent(t.id)}`));
          // Only finish a post the importer wrote, whatever the server matched.
          if (!opts.userId || !post.author || post.author.id !== opts.userId) {
            report.linkFailed.push({ title: d.title, url: t.url, reason: 'Someone else wrote this post, so the import left it alone.' });
            progress.finishDone++;
            tell();
            continue;
          }
          text = post.content;
          version = post.version;
        }
        // What each placeholder becomes. Files are uploaded only for placeholders still there.
        const swaps = new Map();
        for (const n of pageRefs(d)) {
          const target = plan.byNumber.get(n);
          if (target && docs.has(n)) swaps.set(pendingLink(target), `/p/${docs.get(n).id}`);
        }
        for (const n of fileRefs(d)) {
          const att = attachments.get(n);
          const placeholder = pendingFile(att);
          if (!text.includes(placeholder)) continue;
          try {
            swaps.set(placeholder, await uploadTo(t.id, att));
          } catch (e) {
            if (e instanceof StopImport) throw e;
            report.files.failed.push({ name: att.name, path: att.path, page: d.title, reason: e.message || String(e) });
          }
        }
        const apply = (s) => [...swaps].reduce((acc, [from, to]) => acc.split(from).join(to), s);
        let next = apply(text);
        if (next !== text) {
          try {
            await call(() => api.patch(`/posts/${encodeURIComponent(t.id)}`, { content: next, base_version: version, note: 'Added imported files and links' }));
          } catch (e) {
            if (e instanceof StopImport || e.status !== 409) throw e;
            // Someone edited the page meanwhile: apply the same changes to their version.
            const post = await call(() => api.get(`/posts/${encodeURIComponent(t.id)}`));
            if (!opts.userId || !post.author || post.author.id !== opts.userId) throw new Error('Someone else wrote this post, so the import left it alone.');
            next = apply(post.content);
            if (next !== post.content) {
              await call(() => api.patch(`/posts/${encodeURIComponent(t.id)}`, { content: next, base_version: post.version, note: 'Added imported files and links' }));
            }
          }
          report.linked++;
        }
      } catch (e) {
        if (e instanceof StopImport) throw e;
        report.linkFailed.push({ title: d.title, url: t.url, reason: e.message || String(e) });
      }
      progress.finishDone++;
      tell();
    }
  } catch (e) {
    if (!(e instanceof StopImport)) throw e;
    report.stopped = report.stopped || e.message;
  }
  progress.phase = 'done';
  progress.current = '';
  tell();
  return report;
}
