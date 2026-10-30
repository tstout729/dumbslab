// Settings › Import: bring in a Confluence space, a Guru collection, a GitHub wiki or a folder of
// Markdown files. The zip is read and converted here in the browser (DOMParser gives an inert
// document; nothing from the export is ever put in the page as HTML), then sent in batches to
// import_documents, with images and files through upload_file.

import { api } from '/api.js';
import { h, icon, button, toast, field, input, select, checkbox, plural, spinner, BLOCK_RECORDING } from '/ui.js';
import { state, refreshTopics, myId } from '/state.js';
import { FORMATS, openSource, detectFormat, convert } from '/importers/index.js';
import { estimate } from '/importers/plan.js';
import { runImport } from '/importers/run.js';
import { formatSize, MAX_ZIP_BYTES, ZipError } from '/importers/zip.js';
import { resolveDestination } from '/importers/destination.js';

/** The import in this tab. It outlives the page, so leaving Settings doesn't lose it. */
let current = null;
/** Where the import section is on screen, if it is. */
let host = null;

const parseHtml = (text) => new DOMParser().parseFromString(text, 'text/html');

async function sha256(bytes) {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return Array.from(d, (b) => b.toString(16).padStart(2, '0')).join('');
}

function base64(bytes) {
  if (typeof bytes.toBase64 === 'function') return bytes.toBase64();
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

// The import keeps going on 401 instead of jumping to the sign-in page, so it can say what happened.
const importApi = {
  get: (path, query) => api.get(path, query, { redirectOn401: false }),
  post: (path, body) => api.post(path, body, { redirectOn401: false }),
  patch: (path, body) => api.patch(path, body, { redirectOn401: false }),
};

const warnLeaving = (e) => {
  e.preventDefault();
  e.returnValue = '';
};

export async function importSection() {
  // Never in session recordings: it shows the export's page titles and the zip's file name.
  const root = h('div', { class: ['stack import', BLOCK_RECORDING] });
  if (!current) current = { step: 'choose' };
  host = root;
  paint(root);
  return root;
}

function paint(root) {
  const c = current;
  const view = c.step === 'reading' ? readingView(c)
    : c.step === 'preview' ? previewView(c)
    : c.step === 'running' ? runningView(c)
    : c.step === 'done' ? doneView(c)
    : chooseView(c);
  root.replaceChildren(...[].concat(view));
}

function repaint() {
  if (host && current) paint(host);
}

function panel(title, description, ...body) {
  return h('section', { class: 'panel' },
    h('header', { class: 'panel-head' }, h('h2', { class: 'panel-title' }, title), description ? h('p', { class: 'panel-desc' }, description) : null),
    ...body);
}

// ---------------------------------------------------------------------------
// 1. Choose a file

function chooseView(c) {
  const file = h('input', { type: 'file', accept: '.zip,application/zip', class: ['sr-only import-file', BLOCK_RECORDING], id: 'import-file' });
  file.addEventListener('change', () => {
    if (file.files && file.files[0]) start(file.files[0]);
  });
  const pick = h('label', { class: 'btn btn-primary', for: 'import-file' }, icon('upload'), h('span', null, 'Choose a .zip'));
  return [
    panel('Import', 'Bring pages in from Confluence, Guru, a GitHub wiki or a folder of Markdown files. The zip is converted in this browser; you see what will be imported before anything is created, and running the same import again skips pages that are already here.',
      c.error ? h('p', { class: 'callout callout-warn', role: 'alert' }, icon('alert'), h('span', null, c.error)) : null,
      h('div', { class: 'row gap-sm wrap' }, file, pick, h('span', { class: 'muted small' }, `Up to ${formatSize(MAX_ZIP_BYTES)}.`))),
    panel('Get the export', null,
      h('ul', { class: 'import-sources' }, FORMATS.map((f) => h('li', { class: 'import-source' },
        h('strong', null, f.label),
        h('p', { class: 'small' }, f.howTo),
        f.limits ? h('p', { class: 'muted small' }, f.limits) : null))),
      h('p', { class: 'field-hint' }, 'Using an AI agent instead? It can read the export, convert pages to Markdown and call import_documents through MCP. Images go up with upload_file. ',
        h('a', { href: 'https://github.com/tstout729/dumbslab/blob/main/docs/import.md', target: '_blank', rel: 'noopener' }, 'How agents import'), '.')),
  ];
}

async function start(file, format, options = {}) {
  const c = { step: 'reading', file, options, read: { done: 0, total: 0 } };
  current = c;
  repaint();
  try {
    c.source = await openSource(file);
    c.format = format || detectFormat(c.source);
    c.plan = await convert(c.format, c.source, {
      ...options,
      parseHtml,
      onProgress: (done, total) => {
        c.read = { done, total };
        if (current === c) repaint();
      },
    });
    c.rootTopic = c.plan.rootTopic;
    await refreshTopics().catch(() => {});
    c.status = 'published';
    if (state.settings && state.settings.address) c.usage = await api.get('/plan').catch(() => null);
    c.step = 'preview';
  } catch (e) {
    if (!(e instanceof ZipError)) console.error(e);
    if (current === c) current = { step: 'choose', error: e && e.message ? e.message : String(e) };
  }
  repaint();
}

function readingView(c) {
  const { done, total } = c.read;
  return panel('Reading the export', c.file.name,
    h('div', { class: 'row gap-sm' }, spinner('Reading'), h('span', { class: 'small' }, total ? `Converting page ${done.toLocaleString('en-US')} of ${total.toLocaleString('en-US')}…` : 'Opening the zip…')),
    total ? progressBar(done, total, 'Converting pages') : null);
}

// ---------------------------------------------------------------------------
// 2. Preview

function previewView(c) {
  const { plan } = c;
  const s = plan.stats;
  const formatSel = select(FORMATS.map((f) => ({ value: f.id, label: f.label, selected: f.id === c.format })));
  formatSel.addEventListener('change', () => start(c.file, formatSel.value, c.options));
  // Confluence pages list every attachment; people may not want the ones the page doesn't show.
  const lists = c.format === 'confluence' ? checkbox('Also import files from each page’s Attachments list', { checked: c.options.attachmentLists !== false }) : null;
  if (lists) lists.querySelector('input').addEventListener('change', (e) => start(c.file, c.format, { ...c.options, attachmentLists: e.target.checked }));
  const topic = input({ value: c.rootTopic, maxlength: '120', placeholder: 'No top topic' });
  // The tree below names the top topic; keep it in step without re-rendering (a click on Import
  // right after typing must still land).
  // The destination is resolved once here and the run uses the same answer (by topic id when it
  // exists), so what this says about who will see the import is what happens.
  c.dest = resolveDestination(c.rootTopic, state.topics);
  const top = h('strong', null, c.dest.name || 'the top level');
  const privacy = h('span', null, privacyNote(c.dest));
  topic.addEventListener('input', () => {
    c.rootTopic = topic.value;
    c.dest = resolveDestination(topic.value, state.topics);
    top.textContent = c.dest.name || 'the top level';
    privacy.textContent = privacyNote(c.dest);
  });
  const status = select([
    { value: 'published', label: 'Published', selected: c.status === 'published' },
    { value: 'draft', label: 'Drafts, seen only by you and admins', selected: c.status === 'draft' },
  ]);
  status.addEventListener('change', () => { c.status = status.value; });

  const est = estimate(plan);
  const usage = c.usage;
  const checks = [];
  if (usage && usage.allowance && usage.usage) {
    const writesLeft = Math.max(0, usage.allowance.writes_per_day - usage.usage.writes_24h);
    const roomLeft = Math.max(0, usage.allowance.storage_bytes - usage.usage.storage_bytes);
    if (est.writes > writesLeft) {
      checks.push(`This workspace can make about ${writesLeft.toLocaleString('en-US')} more database writes today. The import stops when they run out; run it again once the allowance refills (hour by hour) and it continues where it stopped.`);
    }
    if (est.bytes > roomLeft) {
      checks.push(`This workspace has about ${formatSize(roomLeft)} of storage left, less than the import needs. Leave out large attachments, or make room first.`);
    }
  }
  const go = button(`Import ${plural(s.documents, 'page')}`, { variant: 'primary', icon: 'upload', disabled: !s.documents });
  go.addEventListener('click', () => run());
  const again = button('Choose another file', { variant: 'ghost' });
  again.addEventListener('click', () => { current = { step: 'choose' }; repaint(); });

  return [
    panel('Check the import', `${c.file.name}, ${formatSize(c.file.size)}`,
      h('div', { class: 'grid-2' },
        field('Format', formatSel, { hint: 'Detected from the files in the zip.' }),
        field('Status', status)),
      field('Put everything under the topic', topic, { hint: 'Created if it doesn’t exist. Leave empty to put the top-level topics at the top.' }),
      h('p', { class: 'callout', role: 'note' }, icon('lock'), privacy),
      lists,
      h('ul', { class: 'import-stats' },
        stat('Pages', s.documents.toLocaleString('en-US')),
        stat('Topics', s.topics.toLocaleString('en-US')),
        stat(s.attachments ? `Images and files, ${formatSize(s.attachmentBytes)}` : 'Images and files', s.attachments.toLocaleString('en-US')),
        stat('Skipped', plan.skipped.length.toLocaleString('en-US'))),
      h('p', { class: 'muted small' }, `Uses about ${est.writes.toLocaleString('en-US')} database writes and ${formatSize(est.bytes)} of storage.`),
      ...plan.notes.map((n) => h('p', { class: 'callout', role: 'note' }, icon('info'), h('span', null, n))),
      ...checks.map((n) => h('p', { class: 'callout callout-warn', role: 'alert' }, icon('alert'), h('span', null, n))),
      h('div', { class: 'plan-actions' }, go, again)),
    panel('What will be imported', null,
      h('p', { class: 'small' }, 'Topics under ', top, ', each with its pages:'),
      topicTree(plan),
      plan.skipped.length ? h('details', { class: 'import-details' },
        h('summary', null, `Skipped (${plan.skipped.length.toLocaleString('en-US')})`),
        h('ul', { class: 'import-list' }, plan.skipped.slice(0, 500).map((x) => h('li', null, h('code', null, x.path), h('span', { class: 'muted' }, ` ${x.reason}`))),
          plan.skipped.length > 500 ? h('li', { class: 'muted' }, `…and ${(plan.skipped.length - 500).toLocaleString('en-US')} more`) : null)) : null),
  ];
}

/** Who will see the import, given where it goes (see destination.js). */
function privacyNote(dest) {
  const renamed = dest.renamed ? ` Slashes separate topics, so the new topic is called “${dest.name}”.` : '';
  if (dest.exists && dest.private) {
    return `“${dest.name}” is private: the imported pages, and the topics the import creates inside it, are visible only to its members. Pages that would go into a topic inside it that more people can see aren’t imported; the report lists them.`;
  }
  if (dest.exists) {
    return `Pages go into the existing topic “${dest.name}”, which everyone in the workspace can see.${renamed}`;
  }
  return `Topics the import creates are visible to everyone in the workspace. To keep the import private, create a private topic first and put everything under it: topics created inside a private topic are private too, with the same members.${renamed}`;
}

const stat = (label, value) => h('li', null, h('span', { class: 'import-stat-value' }, value), h('span', { class: 'import-stat-label' }, label));

/** Topics as they will be created, each with its pages. */
function topicTree(plan) {
  const groups = new Map();
  for (const d of plan.documents) {
    const key = d.topic.join(' › ');
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(d.title);
  }
  const rows = [...groups].slice(0, 300).map(([key, titles]) => h('li', null,
    h('details', null,
      h('summary', null, icon('folder', { size: 14 }), ' ', key || 'Directly under it', h('span', { class: 'muted' }, ` ${plural(titles.length, 'page')}`)),
      h('ul', { class: 'import-list' }, titles.slice(0, 200).map((t) => h('li', null, t)),
        titles.length > 200 ? h('li', { class: 'muted' }, `…and ${titles.length - 200} more`) : null))));
  return h('ul', { class: 'import-tree' }, rows, groups.size > 300 ? h('li', { class: 'muted small' }, `…and ${groups.size - 300} more topics`) : null);
}

// ---------------------------------------------------------------------------
// 3. Run

async function run() {
  const c = current;
  c.step = 'running';
  c.controller = new AbortController();
  c.progress = { phase: 'import', docsDone: 0, docsTotal: c.plan.documents.length, finishDone: 0, finishTotal: 0, failed: 0 };
  window.addEventListener('beforeunload', warnLeaving);
  repaint();
  try {
    c.report = await runImport(c.plan, {
      api: importApi,
      source: c.source,
      topicId: c.dest && c.dest.id,
      rootTopic: c.dest ? c.dest.name : '',
      status: c.status,
      userId: myId(),
      sha256,
      base64,
      signal: c.controller.signal,
      onProgress: (p) => {
        c.progress = p;
        updateProgress(c);
      },
    });
  } catch (e) {
    console.error(e);
    c.report = { created: [], existing: [], taken: [], failed: [], notImported: [], stopped: e.message || String(e), files: { uploaded: 0, reused: 0, failed: [] }, linked: 0, linkFailed: [] };
  } finally {
    window.removeEventListener('beforeunload', warnLeaving);
  }
  c.step = 'done';
  try {
    const topics = await refreshTopics();
    // A topic the import created is the destination from now on, by id, for "Run it again".
    if (c.dest && !c.dest.id) c.dest = resolveDestination(c.dest.name, topics);
    c.topic = c.dest && c.dest.id ? { id: c.dest.id, name: c.dest.name } : null;
  } catch {
    c.topic = null;
  }
  repaint();
  toast(c.report.stopped ? 'The import stopped' : 'Import finished', { type: c.report.stopped ? 'error' : 'success' });
}

function progressBar(done, total, label) {
  const share = total ? Math.min(1, done / total) : 0;
  return h('div', { class: 'usage-bar', role: 'progressbar', 'aria-label': label, 'aria-valuemin': '0', 'aria-valuemax': String(total), 'aria-valuenow': String(done) },
    h('span', { class: 'usage-fill', style: `width: ${(share * 100).toFixed(1)}%` }));
}

function progressText(p) {
  if (p.phase === 'finish') return `Adding images, files and links: page ${p.finishDone.toLocaleString('en-US')} of ${p.finishTotal.toLocaleString('en-US')}${p.current ? ` (${p.current})` : ''}`;
  return `Importing pages: ${p.docsDone.toLocaleString('en-US')} of ${p.docsTotal.toLocaleString('en-US')}${p.current ? ` (${p.current}…)` : ''}`;
}

const progressDone = (p) => p.docsDone + p.finishDone;
const progressTotal = (p) => p.docsTotal + p.finishTotal;

function runningView(c) {
  const p = c.progress;
  const cancel = button('Cancel', { variant: 'ghost' });
  cancel.addEventListener('click', () => {
    cancel.disabled = true;
    c.controller.abort();
  });
  return panel('Importing', 'Keep this tab open until it finishes. You can use DumbSlab in the meantime.',
    h('p', { class: 'small', id: 'import-status', 'aria-live': 'polite' }, progressText(p)),
    progressBar(progressDone(p), progressTotal(p), 'Import progress'),
    h('p', { class: 'muted small', id: 'import-failed' }, p.failed ? `${plural(p.failed, 'page')} failed so far; you’ll see why at the end.` : ''),
    h('div', null, cancel));
}

function updateProgress(c) {
  const status = document.getElementById('import-status');
  if (!status) return repaint();
  const p = c.progress;
  status.textContent = progressText(p);
  const bar = status.nextElementSibling;
  const total = progressTotal(p);
  const done = progressDone(p);
  bar.setAttribute('aria-valuemax', String(total));
  bar.setAttribute('aria-valuenow', String(done));
  bar.firstChild.style.width = `${(total ? Math.min(100, (done / total) * 100) : 0).toFixed(1)}%`;
  const failed = document.getElementById('import-failed');
  if (failed) failed.textContent = p.failed ? `${plural(p.failed, 'page')} failed so far; you’ll see why at the end.` : '';
  return undefined;
}

// ---------------------------------------------------------------------------
// 4. Report

function doneView(c) {
  const r = c.report;
  const again = button('Run it again', { variant: 'subtle', icon: 'refresh' });
  again.title = 'Imports what failed or didn’t get imported. Pages already here are skipped, and uploaded files are reused.';
  again.addEventListener('click', () => run());
  const another = button('Import another file', { variant: 'ghost' });
  another.addEventListener('click', () => { current = { step: 'choose' }; repaint(); });
  const unfinished = r.failed.length + r.notImported.length + r.linkFailed.length + r.files.failed.length;
  const list = (title, items, render) => (items.length ? h('details', { class: 'import-details', open: items.length <= 10 },
    h('summary', null, `${title} (${items.length.toLocaleString('en-US')})`),
    h('ul', { class: 'import-list' }, items.slice(0, 500).map(render), items.length > 500 ? h('li', { class: 'muted' }, `…and ${(items.length - 500).toLocaleString('en-US')} more`) : null)) : null);
  return [
    panel(r.stopped ? 'The import stopped' : 'Import finished', null,
      r.stopped ? h('p', { class: 'callout callout-warn', role: 'alert' }, icon('alert'), h('span', null, `${r.stopped} Fix that, then run the import again: it picks up where it stopped.`)) : null,
      h('ul', { class: 'import-stats' },
        stat('Imported', r.created.length.toLocaleString('en-US')),
        stat('Already here', r.existing.length.toLocaleString('en-US')),
        stat('Failed', (r.failed.length + r.notImported.length).toLocaleString('en-US')),
        stat(r.files.reused ? `Files uploaded (${r.files.reused.toLocaleString('en-US')} were already)` : 'Files uploaded', r.files.uploaded.toLocaleString('en-US'))),
      c.topic ? h('p', null, h('a', { href: `/t/${encodeURIComponent(c.topic.id)}`, class: 'btn btn-primary' }, icon('folder'), h('span', null, `Open ${c.topic.name}`))) : null,
      list('Pages that failed', r.failed, (x) => h('li', null, h('strong', null, x.title), h('span', { class: 'muted' }, ` ${x.reason}`))),
      list('Not imported because the import stopped', r.notImported, (x) => h('li', null, x.title)),
      list('Not imported because someone else’s post in the topic has the same title (rename the page, or import into another topic)', r.taken, (x) => h('li', null, h('a', { href: x.url }, x.title))),
      list('Files that failed to upload (running the import again adds them)', r.files.failed, (x) => h('li', null, h('code', null, x.name), h('span', { class: 'muted' }, ` on ${x.page}: ${x.reason}`))),
      list('Pages whose images, files or links couldn’t be added', r.linkFailed, (x) => h('li', null, h('a', { href: x.url }, x.title), h('span', { class: 'muted' }, ` ${x.reason}`))),
      list('Imported pages', r.created, (x) => h('li', null, h('a', { href: x.url }, x.title))),
      h('div', { class: 'plan-actions' }, unfinished || r.stopped ? again : null, another)),
  ];
}
