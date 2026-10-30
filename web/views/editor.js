// The Markdown editor: title, topics, toolbar, live preview, drafts, publishing,
// conflict handling and a local recovery copy.

import { api, enc } from '/api.js';
import {
  h, icon, button, busy, toast, toastError, modal, confirmDialog, openPopover, closeLayers, debounce,
  checkbox, select, emptyState, relTime, modKey, topicIcon,
} from '/ui.js';
import { state, navigate, topicById, flatTopicTree, canEdit, myId } from '/state.js';
import { openTopicForm } from '/views/topic.js';

export async function renderNew(ctx) {
  if (!canEdit()) {
    ctx.setTitle('New post');
    ctx.main.replaceChildren(h('div', { class: 'page page-narrow' }, emptyState({ iconName: 'lock', title: 'You can read but not write here', body: 'Ask an admin to make you a member if you need to write posts.' })));
    return;
  }
  const topicId = ctx.query.get('topic');
  let templates = [];
  try {
    templates = (await api.get('/posts', { is_template: true, status: 'all', sort: 'title', limit: 100 })).items;
  } catch {
    templates = [];
  }
  if (!ctx.isCurrent()) return;
  mountEditor(ctx, {
    post: null,
    templates,
    startTemplate: ctx.query.get('template'),
    initial: {
      title: '',
      content: '',
      topic_ids: topicId && topicById(topicId) ? [topicId] : [],
      is_template: ctx.query.get('as') === 'template',
      status: 'draft',
    },
  });
}

export async function renderEdit(ctx) {
  const post = await api.get(`/posts/${enc(ctx.params.id)}`);
  if (!ctx.isCurrent()) return;
  if (!post.can_edit) {
    ctx.setTitle(`Edit ${post.title}`);
    ctx.main.replaceChildren(h('div', { class: 'page page-narrow' }, emptyState({
      iconName: 'lock',
      title: post.deleted_at ? 'This post is in the trash' : 'You can’t edit this post',
      body: post.deleted_at ? 'Restore it before editing.' : 'Viewers can read and comment but not edit.',
      action: h('a', { class: 'btn btn-primary', href: `/p/${post.id}/${post.slug}` }, 'Back to the post'),
    })));
    return;
  }
  mountEditor(ctx, {
    post,
    templates: [],
    initial: {
      title: post.title,
      content: post.content,
      topic_ids: post.topics.map((t) => t.id),
      is_template: post.is_template,
      status: post.status,
    },
  });
}

// ---------------------------------------------------------------------------
// Markdown editing helpers that keep the browser's undo history.

function replaceRange(ta, start, end, text, selStart, selEnd) {
  ta.focus();
  ta.setSelectionRange(start, end);
  let ok = false;
  try {
    ok = document.execCommand('insertText', false, text);
  } catch {
    ok = false;
  }
  if (!ok || ta.value.slice(start, start + text.length) !== text) {
    ta.setRangeText(text, start, end, 'end');
    ta.dispatchEvent(new Event('input', { bubbles: true }));
  }
  ta.setSelectionRange(selStart ?? start + text.length, selEnd ?? selStart ?? start + text.length);
}

function wrap(ta, before, after, placeholder) {
  const { selectionStart: s, selectionEnd: e, value } = ta;
  const sel = value.slice(s, e);
  if (value.slice(s - before.length, s) === before && value.slice(e, e + after.length) === after && (sel || before !== after)) {
    replaceRange(ta, s - before.length, e + after.length, sel, s - before.length, e - before.length);
    return;
  }
  const inner = sel || placeholder;
  replaceRange(ta, s, e, before + inner + after, s + before.length, s + before.length + inner.length);
}

const LINE_PATTERNS = {
  h2: /^#{1,6}\s+/,
  ul: /^\s*[-*+]\s+(?!\[[ xX]\])/,
  ol: /^\s*\d+[.)]\s+/,
  task: /^\s*[-*+]\s+\[[ xX]\]\s+/,
  quote: /^>\s?/,
};
const ANY_LIST = /^\s*([-*+]\s+(\[[ xX]\]\s+)?|\d+[.)]\s+)/;

function linePrefix(ta, kind) {
  const { selectionStart: s, selectionEnd: e, value } = ta;
  const lineStart = value.lastIndexOf('\n', s - 1) + 1;
  let lineEnd = value.indexOf('\n', e > s && value[e - 1] === '\n' ? e - 1 : e);
  if (lineEnd < 0) lineEnd = value.length;
  const lines = value.slice(lineStart, lineEnd).split('\n');
  const pattern = LINE_PATTERNS[kind];
  const has = lines.some((l) => l.trim()) && lines.every((l) => !l.trim() || pattern.test(l));
  const out = lines.map((l, i) => {
    if (has) return l.replace(pattern, '');
    if (!l.trim() && lines.length > 1) return l;
    const base = kind === 'quote' || kind === 'h2' ? l.replace(pattern, '') : l.replace(ANY_LIST, '');
    const prefix = { h2: '## ', ul: '- ', ol: `${i + 1}. `, task: '- [ ] ', quote: '> ' }[kind];
    return prefix + base;
  });
  const text = out.join('\n');
  if (lines.length === 1) replaceRange(ta, lineStart, lineEnd, text, lineStart + text.length);
  else replaceRange(ta, lineStart, lineEnd, text, lineStart, lineStart + text.length);
}

function insertBlock(ta, block, selectFrom, selectLen) {
  const { selectionStart: s, selectionEnd: e, value } = ta;
  const before = value.slice(0, s);
  const lead = !before.length || before.endsWith('\n\n') ? '' : before.endsWith('\n') ? '\n' : '\n\n';
  const after = value.slice(e);
  const trail = after.startsWith('\n') ? '' : '\n';
  const text = lead + block + trail;
  const start = s + lead.length + (selectFrom ?? block.length);
  replaceRange(ta, s, e, text, start, start + (selectLen ?? 0));
}

function link(ta) {
  const { selectionStart: s, selectionEnd: e, value } = ta;
  const sel = value.slice(s, e);
  if (/^https?:\/\/\S+$/.test(sel)) {
    replaceRange(ta, s, e, `[link text](${sel})`, s + 1, s + 10);
  } else {
    const label = sel || 'link text';
    const text = `[${label}](https://)`;
    const urlStart = s + label.length + 3;
    replaceRange(ta, s, e, text, sel ? urlStart : s + 1, sel ? urlStart + 8 : s + 1 + label.length);
  }
}

function code(ta) {
  const { selectionStart: s, selectionEnd: e, value } = ta;
  const sel = value.slice(s, e);
  if (sel.includes('\n') || (!sel && (s === 0 || value[s - 1] === '\n') && (value[e] === '\n' || e === value.length))) {
    const body = sel || '';
    insertBlock(ta, '```\n' + body + (body.endsWith('\n') || !body ? '' : '\n') + (body ? '' : '\n') + '```', 4, body.length);
  } else {
    wrap(ta, '`', '`', 'code');
  }
}

/** A provider link on a line of its own renders inline (see crates/core/src/embed.rs). */
function embed(ta) {
  const { selectionStart: s, selectionEnd: e, value } = ta;
  const sel = value.slice(s, e).trim();
  const url = /^https?:\/\/\S+$/.test(sel) ? sel : '';
  const placeholder = 'Paste a YouTube, Loom, Google Docs, Figma or Canva link';
  const after = value.slice(e);
  const block = (url || placeholder) + (!after || after.startsWith('\n\n') ? '' : '\n');
  insertBlock(ta, block, url ? block.length : 0, url ? 0 : placeholder.length);
}

function callout(ta) {
  const { selectionStart: s, selectionEnd: e, value } = ta;
  const sel = value.slice(s, e).trim();
  const body = sel || 'Callout text';
  const block = '> [!NOTE]\n' + body.split('\n').map((l) => '> ' + l).join('\n');
  insertBlock(ta, block, sel ? block.length : 12, sel ? 0 : body.length);
}

const ACTIONS = [
  { id: 'bold', icon: 'bold', label: 'Bold', keys: `${modKey}+B`, run: (ta) => wrap(ta, '**', '**', 'bold text') },
  { id: 'italic', icon: 'italic', label: 'Italic', keys: `${modKey}+I`, run: (ta) => wrap(ta, '_', '_', 'italic text') },
  { id: 'heading', icon: 'heading', label: 'Heading', run: (ta) => linePrefix(ta, 'h2') },
  'sep',
  { id: 'link', icon: 'link', label: 'Link', run: link },
  { id: 'quote', icon: 'quote', label: 'Quote', run: (ta) => linePrefix(ta, 'quote') },
  { id: 'code', icon: 'code', label: 'Code', run: code },
  { id: 'callout', icon: 'info', label: 'Callout', run: callout },
  'sep',
  { id: 'ul', icon: 'list', label: 'Bulleted list', run: (ta) => linePrefix(ta, 'ul') },
  { id: 'ol', icon: 'listOrdered', label: 'Numbered list', run: (ta) => linePrefix(ta, 'ol') },
  { id: 'task', icon: 'listChecks', label: 'Checklist', run: (ta) => linePrefix(ta, 'task') },
  'sep',
  { id: 'embed', icon: 'video', label: 'Embed a video, doc or design', run: embed },
  { id: 'table', icon: 'table', label: 'Table', run: (ta) => insertBlock(ta, '| Column | Column |\n| --- | --- |\n| Cell | Cell |', 2, 6) },
  { id: 'hr', icon: 'minus', label: 'Divider', run: (ta) => insertBlock(ta, '---') },
  'sep',
  // Runs the editor's file picker (see mountEditor).
  { id: 'upload', icon: 'paperclip', label: 'Upload an image or file' },
];

// ---------------------------------------------------------------------------
// Uploads: pasted, dropped or picked files become Markdown that shows them.

const MAX_UPLOAD = 10 * 1024 * 1024;

function readAsBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const url = String(reader.result);
      resolve(url.slice(url.indexOf(',') + 1));
    };
    reader.onerror = () => reject(reader.error || new Error('Couldn’t read the file.'));
    reader.readAsDataURL(file);
  });
}

/** Files to upload from a paste. Rich text (Word, Sheets, web pages) also carries a picture of itself; paste its text instead. */
function pastedFiles(data) {
  if (!data || !data.files || !data.files.length) return [];
  const types = [...data.types];
  if (types.includes('text/html') && types.includes('text/plain') && data.getData('text/plain').trim()) return [];
  return [...data.files];
}

function uploadError(name, err) {
  const reason = err.status === 413 ? 'it’s larger than 10 MB.' : err.message;
  return `Couldn’t upload “${name}”: ${reason}`;
}

/** Continues lists and quotes when pressing Enter; an empty item ends the list. */
function continueList(ev, ta) {
  if (ev.key !== 'Enter' || ev.shiftKey || ev.metaKey || ev.ctrlKey || ev.altKey || ev.isComposing) return;
  const { selectionStart: s, selectionEnd: e, value } = ta;
  if (s !== e) return;
  const lineStart = value.lastIndexOf('\n', s - 1) + 1;
  const line = value.slice(lineStart, s);
  const m = /^(\s*)([-*+] \[[ xX]\] |[-*+] |(\d+)([.)]) |> )/.exec(line);
  if (!m) return;
  const fences = (value.slice(0, lineStart).match(/^```/gm) || []).length;
  if (fences % 2 === 1) return;
  ev.preventDefault();
  if (!line.slice(m[0].length).trim()) {
    replaceRange(ta, lineStart, s, '', lineStart);
    return;
  }
  let marker = m[2];
  if (m[3]) marker = `${Number(m[3]) + 1}${m[4]} `;
  else if (/\[[xX]\]/.test(marker)) marker = marker.replace(/\[[xX]\]/, '[ ]');
  const text = '\n' + m[1] + marker;
  replaceRange(ta, s, s, text, s + text.length);
}

// ---------------------------------------------------------------------------

function topicPicker(selected, onChange) {
  const el = h('div', { class: 'topic-picker' });
  const addBtn = button('Add topic', { icon: 'plus', variant: 'ghost', size: 'sm', 'aria-haspopup': 'dialog', 'aria-expanded': 'false' });

  function draw() {
    el.replaceChildren(
      ...[...selected].map((id) => {
        const t = topicById(id);
        if (!t) return null;
        const rm = h('button', { type: 'button', class: 'chip-remove', 'aria-label': `Remove ${t.name}` }, icon('x', { size: 12 }));
        rm.addEventListener('click', () => {
          selected.delete(id);
          draw();
          onChange();
        });
        return h('span', { class: 'chip chip-removable' }, topicIcon(t, 'xs'), h('span', null, t.name), rm);
      }).filter(Boolean),
      addBtn);
  }

  addBtn.addEventListener('click', () => {
    const filter = h('input', { class: 'input input-sm', type: 'text', placeholder: 'Find a topic', 'aria-label': 'Find a topic', autocomplete: 'off' });
    const list = h('div', { class: 'picker-list', role: 'group', 'aria-label': 'Topics' });
    const drawList = () => {
      const q = filter.value.trim().toLowerCase();
      const rows = flatTopicTree().filter(({ topic }) => !q || topic.name.toLowerCase().includes(q));
      list.replaceChildren(...rows.map(({ topic, depth }) => {
        const on = selected.has(topic.id);
        const b = h('button', { type: 'button', class: 'picker-item', role: 'menuitemcheckbox', 'aria-checked': String(on), style: { '--depth': String(q ? 0 : depth) } },
          h('span', { class: 'picker-check' }, on ? icon('check', { size: 14 }) : null),
          topicIcon(topic, 'xs'),
          h('span', { class: 'picker-name' }, topic.name),
          topic.visibility === 'private' ? icon('lock', { size: 12, label: 'Private' }) : null);
        b.addEventListener('click', () => {
          if (selected.has(topic.id)) selected.delete(topic.id);
          else selected.add(topic.id);
          draw();
          onChange();
          drawList();
          layer.reposition();
        });
        return b;
      }));
      if (!rows.length) list.appendChild(h('p', { class: 'picker-empty' }, state.topics.length ? 'No topics match.' : 'No topics yet.'));
    };
    filter.addEventListener('input', drawList);
    filter.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        const first = list.querySelector('.picker-item');
        if (first) first.click();
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        const first = list.querySelector('.picker-item');
        if (first) first.focus();
      }
    });
    list.addEventListener('keydown', (e) => {
      const items = [...list.querySelectorAll('.picker-item')];
      const i = items.indexOf(document.activeElement);
      if (e.key === 'ArrowDown' && i < items.length - 1) { e.preventDefault(); items[i + 1].focus(); }
      if (e.key === 'ArrowUp') { e.preventDefault(); (i > 0 ? items[i - 1] : filter).focus(); }
    });
    const create = canEdit() ? button('Create a topic', {
      icon: 'plus',
      variant: 'ghost',
      size: 'sm',
      cls: 'picker-create',
      onClick: () => {
        layer.close();
        openTopicForm({ name: filter.value.trim(), onSaved: (t) => { selected.add(t.id); draw(); onChange(); } });
      },
    }) : null;
    drawList();
    const layer = openPopover(addBtn, h('div', { class: 'picker' }, filter, list, create), { label: 'Choose topics', cls: 'popover-picker' });
    filter.focus();
  });

  draw();
  return { el, redraw: draw };
}

function mountEditor(ctx, { post, initial, templates, startTemplate }) {
  let postId = post ? post.id : null;
  let slug = post ? post.slug : null;
  let baseVersion = post ? post.version : null;
  let status = initial.status;
  let templateId = null;
  let recoveryKey = `ds-recovery:${myId()}:${postId || 'new'}`;
  let saved = { title: initial.title, content: initial.content, topic_ids: [...initial.topic_ids].sort(), is_template: !!initial.is_template };
  let dirty = false;
  let saving = false;
  let uploads = 0;

  ctx.setTitle(post ? `Editing ${post.title}` : 'New post');

  // --- Controls -----------------------------------------------------------------
  const titleEl = h('input', { class: 'editor-title', type: 'text', placeholder: 'Untitled', 'aria-label': 'Title', maxlength: '300', value: initial.title, autocomplete: 'off' });
  const topicIds = new Set(initial.topic_ids);
  const picker = topicPicker(topicIds, () => changed());
  const ta = h('textarea', {
    class: 'editor-text',
    'aria-label': 'Post content in Markdown',
    placeholder: 'Write in Markdown. Link posts by pasting their URL, mention people with @handle.',
    spellcheck: 'true',
    value: initial.content,
  });
  const templateBox = checkbox('Template', { checked: !!initial.is_template, title: 'Templates are starting points for new posts' });
  const templateInput = templateBox.querySelector('input');
  templateInput.addEventListener('change', () => changed());

  const saveState = h('span', { class: 'save-state', 'aria-live': 'polite' });
  const statusBadge = h('span', { class: 'badge' });
  const wordCount = h('span', { class: 'muted small' });

  // --- Uploads ---------------------------------------------------------------------------
  const fileInput = h('input', { type: 'file', multiple: true, hidden: true, tabindex: '-1' });
  const placeholderTag = Date.now().toString(36);
  let placeholderSeq = 0;

  /** Swaps an upload's placeholder for its Markdown (or removes it), leaving the caret where it was. */
  function replacePlaceholder(placeholder, text) {
    const at = ta.value.indexOf(placeholder);
    if (at < 0) return; // deleted while uploading
    const end = at + placeholder.length;
    if (document.activeElement !== ta) {
      ta.setRangeText(text, at, end, 'preserve');
      ta.dispatchEvent(new Event('input', { bubbles: true }));
      return;
    }
    const move = (pos) => (pos >= end ? pos + text.length - placeholder.length : pos > at ? at + text.length : pos);
    const { selectionStart: s, selectionEnd: e } = ta;
    replaceRange(ta, at, end, text, move(s), move(e));
  }

  async function uploadFiles(files) {
    const ready = [];
    for (const f of files) {
      if (f.size > MAX_UPLOAD) toast(`“${f.name}” is larger than 10 MB, the most you can upload.`, { type: 'error' });
      else if (!f.size) toast(`“${f.name}” is empty or a folder, so it wasn’t uploaded.`, { type: 'error' });
      else ready.push(f);
    }
    if (!ready.length) return;
    const placeholders = ready.map((f) => `![Uploading ${f.name.replace(/[[\]\\\n]/g, '')}…](#uploading-${placeholderTag}-${++placeholderSeq})`);
    const { selectionStart: s, selectionEnd: e } = ta;
    const lead = s > 0 && !/\s/.test(ta.value[s - 1]) ? ' ' : '';
    const text = lead + placeholders.join('\n');
    replaceRange(ta, s, e, text, s + text.length);
    uploads += ready.length;
    updateChrome();
    // One at a time: the server runs requests in turn anyway.
    for (const [i, f] of ready.entries()) {
      try {
        const data = await readAsBase64(f);
        const r = await api.post('/files', {
          name: f.name || 'pasted file',
          content_type: f.type || undefined,
          data_base64: data,
          post_id: postId || undefined,
        });
        replacePlaceholder(placeholders[i], r.markdown);
      } catch (err) {
        replacePlaceholder(placeholders[i], '');
        toast(uploadError(f.name, err), { type: 'error' });
      } finally {
        uploads -= 1;
        updateChrome();
      }
    }
  }

  fileInput.addEventListener('change', () => {
    const files = [...fileInput.files];
    fileInput.value = '';
    ta.focus();
    uploadFiles(files);
  });

  const toolbar = h('div', { class: 'toolbar', role: 'toolbar', 'aria-label': 'Formatting', 'aria-controls': 'editor-text' });
  ta.id = 'editor-text';
  for (const a of ACTIONS) {
    if (a === 'sep') {
      toolbar.appendChild(h('span', { class: 'toolbar-sep', role: 'separator' }));
      continue;
    }
    const b = h('button', { type: 'button', class: 'tool', title: a.keys ? `${a.label} (${a.keys})` : a.label, 'aria-label': a.label, tabindex: '-1' }, icon(a.icon, { size: 16 }));
    b.addEventListener('mousedown', (e) => e.preventDefault());
    b.addEventListener('click', () => (a.run ? a.run(ta) : fileInput.click()));
    toolbar.appendChild(b);
  }
  const tools = [...toolbar.querySelectorAll('.tool')];
  if (tools[0]) tools[0].tabIndex = 0;
  toolbar.addEventListener('keydown', (e) => {
    const i = tools.indexOf(document.activeElement);
    if (i < 0) return;
    let next = -1;
    if (e.key === 'ArrowRight') next = (i + 1) % tools.length;
    if (e.key === 'ArrowLeft') next = (i - 1 + tools.length) % tools.length;
    if (e.key === 'Home') next = 0;
    if (e.key === 'End') next = tools.length - 1;
    if (next >= 0) {
      e.preventDefault();
      tools[i].tabIndex = -1;
      tools[next].tabIndex = 0;
      tools[next].focus();
    }
  });

  const previewTitle = h('h1', { class: 'post-title preview-title' });
  const previewBody = h('div', { class: 'prose post-body' });
  const previewPane = h('div', { class: 'pane pane-preview', id: 'pane-preview', role: 'tabpanel', 'aria-label': 'Preview' }, previewTitle, previewBody);
  const writePane = h('div', { class: 'pane pane-write', id: 'pane-write', role: 'tabpanel', 'aria-label': 'Write' }, toolbar, ta, fileInput);

  // Paste or drop files into the text to upload them.
  ta.addEventListener('paste', (e) => {
    const files = pastedFiles(e.clipboardData);
    if (!files.length) return;
    e.preventDefault();
    uploadFiles(files);
  });
  const draggingFiles = (e) => !!e.dataTransfer && [...e.dataTransfer.types].includes('Files');
  writePane.addEventListener('dragover', (e) => {
    if (!draggingFiles(e)) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = 'copy';
    writePane.classList.add('is-dropping');
  });
  writePane.addEventListener('dragleave', (e) => {
    if (!writePane.contains(e.relatedTarget)) writePane.classList.remove('is-dropping');
  });
  writePane.addEventListener('drop', (e) => {
    writePane.classList.remove('is-dropping');
    if (!draggingFiles(e)) return;
    e.preventDefault();
    ta.focus();
    uploadFiles([...e.dataTransfer.files]);
  });

  const tabWrite = h('button', { type: 'button', class: 'tab', role: 'tab', 'aria-selected': 'true', 'aria-controls': 'pane-write' }, 'Write');
  const tabPreview = h('button', { type: 'button', class: 'tab', role: 'tab', 'aria-selected': 'false', 'aria-controls': 'pane-preview' }, 'Preview');
  const tabs = h('div', { class: 'tabs editor-tabs', role: 'tablist', 'aria-label': 'Editor view' }, tabWrite, tabPreview);
  const panes = h('div', { class: 'editor-panes', dataset: { tab: 'write' } }, writePane, previewPane);
  const setTab = (t) => {
    panes.dataset.tab = t;
    tabWrite.setAttribute('aria-selected', String(t === 'write'));
    tabPreview.setAttribute('aria-selected', String(t === 'preview'));
    if (t === 'preview') renderPreview.flush();
    else ta.focus();
  };
  tabWrite.addEventListener('click', () => setTab('write'));
  tabPreview.addEventListener('click', () => setTab('preview'));

  let previewHidden = localStorage.getItem('ds-preview-hidden') === '1';
  const previewToggle = button('', { icon: 'layers', variant: 'ghost', size: 'sm', 'aria-label': 'Toggle preview', 'aria-pressed': String(!previewHidden), title: 'Show or hide the preview' });
  previewToggle.addEventListener('click', () => {
    previewHidden = !previewHidden;
    panes.classList.toggle('no-preview', previewHidden);
    previewToggle.setAttribute('aria-pressed', String(!previewHidden));
    try { localStorage.setItem('ds-preview-hidden', previewHidden ? '1' : '0'); } catch { /* ignore */ }
    if (!previewHidden) renderPreview.flush();
  });
  panes.classList.toggle('no-preview', previewHidden);

  // --- Preview --------------------------------------------------------------------------
  let previewSeq = 0;
  const renderPreview = debounce(async () => {
    const seq = ++previewSeq;
    previewTitle.textContent = titleEl.value.trim() || 'Untitled';
    const md = ta.value;
    if (!md.trim()) {
      previewBody.replaceChildren(h('p', { class: 'muted' }, 'Nothing to preview yet.'));
      wordCount.textContent = '0 words';
      return;
    }
    try {
      const r = await api.post('/render', { markdown: md });
      if (seq !== previewSeq) return;
      previewBody.innerHTML = r.html; // sanitized by the server
      wordCount.textContent = `${r.word_count} ${r.word_count === 1 ? 'word' : 'words'}`;
    } catch (e) {
      if (seq === previewSeq) previewBody.replaceChildren(h('p', { class: 'form-error' }, icon('alert', { size: 15 }), h('span', null, `Preview failed: ${e.message}`)));
    }
  }, 300);

  // --- Dirty tracking and recovery -----------------------------------------------------
  const snapshot = () => ({ title: titleEl.value, content: ta.value, topic_ids: [...topicIds].sort(), is_template: templateInput.checked });
  const same = (a, b) => a.title === b.title && a.content === b.content && a.is_template === b.is_template && a.topic_ids.join() === b.topic_ids.join();

  function persistRecovery() {
    try {
      localStorage.setItem(recoveryKey, JSON.stringify({ ...snapshot(), base_version: baseVersion, at: new Date().toISOString() }));
    } catch {
      /* storage full or unavailable */
    }
  }
  const writeRecovery = debounce(() => {
    if (dirty) persistRecovery();
    else {
      try { localStorage.removeItem(recoveryKey); } catch { /* ignore */ }
    }
  }, 400);

  function updateChrome() {
    const labels = { draft: 'Draft', published: 'Published', archived: 'Archived' };
    statusBadge.className = `badge badge-${status}`;
    statusBadge.textContent = postId ? labels[status] || status : 'New draft';
    saveState.textContent = saving ? 'Saving…' : uploads ? 'Uploading…' : dirty ? 'Unsaved changes' : postId ? 'All changes saved' : '';
    saveState.classList.toggle('is-dirty', dirty);
    document.body.dataset.dirty = dirty ? '1' : '';
    actionsBox.replaceChildren(...actionButtons());
  }

  function changed() {
    dirty = !same(snapshot(), saved);
    writeRecovery();
    updateChrome();
  }

  titleEl.addEventListener('input', () => {
    previewTitle.textContent = titleEl.value.trim() || 'Untitled';
    changed();
  });
  ta.addEventListener('input', () => {
    changed();
    if (!previewHidden || panes.dataset.tab === 'preview') renderPreview();
  });
  ta.addEventListener('keydown', (e) => {
    const mod = e.metaKey || e.ctrlKey;
    if (mod && !e.shiftKey && e.key.toLowerCase() === 'b') { e.preventDefault(); ACTIONS[0].run(ta); }
    else if (mod && !e.shiftKey && e.key.toLowerCase() === 'i') { e.preventDefault(); ACTIONS[1].run(ta); }
    else continueList(e, ta);
  });
  titleEl.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      ta.focus();
      ta.setSelectionRange(0, 0);
    }
  });

  // Keep the preview roughly in step with the textarea when both are visible.
  ta.addEventListener('scroll', () => {
    if (previewHidden || panes.dataset.tab === 'preview') return;
    const ratio = ta.scrollTop / Math.max(1, ta.scrollHeight - ta.clientHeight);
    previewPane.scrollTop = ratio * (previewPane.scrollHeight - previewPane.clientHeight);
  }, { passive: true });

  // --- Saving ------------------------------------------------------------------------------
  function conflictDialog(err, opts) {
    const current = err.details && err.details.current_version;
    modal({
      title: 'Someone else changed this post',
      content: h('p', { class: 'modal-text' },
        `While you were editing, the post was saved again${current ? ` (now version ${current})` : ''}. `,
        'Reload to see their changes. Your text stays in this browser as a recovery copy you can restore. Or overwrite their changes with yours.'),
      actions: [
        { label: 'Cancel', variant: 'ghost' },
        {
          label: 'Overwrite anyway',
          variant: 'danger',
          onClick: () => { setTimeout(() => save({ ...opts, force: true }), 0); },
        },
        {
          label: 'Reload',
          variant: 'primary',
          primary: true,
          onClick: () => {
            writeRecovery.cancel();
            persistRecovery();
            dirty = false;
            document.body.dataset.dirty = '';
            ctx.reload();
          },
        },
      ],
    });
  }

  async function save({ publish = false, view = false, force = false } = {}) {
    if (saving) return;
    const snap = snapshot();
    if (!snap.title.trim()) {
      toast('Add a title before saving.', { type: 'error' });
      titleEl.focus();
      return;
    }
    saving = true;
    updateChrome();
    try {
      let result;
      if (!postId) {
        result = await api.post('/posts', {
          title: snap.title.trim(),
          content: snap.content,
          topic_ids: snap.topic_ids,
          status: publish ? 'published' : 'draft',
          is_template: snap.is_template,
          template_id: templateId || undefined,
        });
      } else {
        const body = { title: snap.title.trim(), content: snap.content, topic_ids: snap.topic_ids, is_template: snap.is_template };
        if (!force) body.base_version = baseVersion;
        if (publish && status !== 'published') body.status = 'published';
        result = await api.patch(`/posts/${enc(postId)}`, body);
      }
      const wasNew = !postId;
      try {
        localStorage.removeItem(recoveryKey);
      } catch { /* ignore */ }
      postId = result.id;
      slug = result.slug;
      baseVersion = result.version;
      status = result.status;
      recoveryKey = `ds-recovery:${myId()}:${postId}`;
      saved = { ...snap, title: snap.title.trim() };
      const editedDuringSave = !same(snapshot(), snap);
      if (!editedDuringSave) titleEl.value = saved.title;
      dirty = !same(snapshot(), saved);
      saving = false;
      writeRecovery.cancel();
      if (dirty) persistRecovery();
      updateChrome();
      if (editedDuringSave) {
        if (wasNew) ctx.replaceUrl(`/p/${postId}/edit`);
        toast('Saved. You have newer changes that aren’t saved yet.');
        return;
      }
      if (publish || view) {
        ctx.clearLeaveGuard();
        toast(publish ? 'Published' : 'Saved');
        navigate(`/p/${postId}/${slug}`);
        return;
      }
      if (wasNew) ctx.replaceUrl(`/p/${postId}/edit`);
      toast(status === 'draft' ? 'Draft saved' : 'Saved');
    } catch (e) {
      saving = false;
      updateChrome();
      if (e.status === 409) conflictDialog(e, { publish, view });
      else toastError(e, 'Couldn’t save');
    }
  }

  const actionsBox = h('div', { class: 'editor-actions' });
  function actionButtons() {
    const out = [previewToggle];
    if (!postId || status === 'draft') {
      const draftBtn = button('Save draft', { variant: 'subtle', size: 'sm', title: `Save draft (${modKey}+S)` });
      draftBtn.addEventListener('click', () => save());
      const pubBtn = button('Publish', { variant: 'primary', size: 'sm' });
      pubBtn.addEventListener('click', () => save({ publish: true }));
      draftBtn.disabled = saving;
      pubBtn.disabled = saving;
      out.push(draftBtn, pubBtn);
    } else {
      const saveBtn = button('Save', { variant: 'primary', size: 'sm', title: `Save and view the post. ${modKey}+S saves and keeps editing.` });
      saveBtn.addEventListener('click', () => save({ view: true }));
      saveBtn.disabled = saving;
      out.push(saveBtn);
    }
    return out;
  }

  const cancelHref = postId ? `/p/${postId}/${slug}` : '/drafts';
  const back = h('a', { class: 'btn btn-ghost btn-sm', href: cancelHref }, icon('chevronLeft'), h('span', null, postId ? 'Back to post' : 'Cancel'));

  // --- Templates (new posts) -------------------------------------------------------------
  let templatePicker = null;
  if (!post && templates.length) {
    const sel = select([{ value: '', label: 'Blank post' }, ...templates.map((t) => ({ value: t.id, label: t.title }))], { 'aria-label': 'Start from a template', class: 'input select input-sm' });
    let last = '';
    sel.addEventListener('change', async () => {
      const id = sel.value;
      if (ta.value.trim() && ta.value !== saved.content) {
        const ok = await confirmDialog({ title: 'Replace what you wrote?', message: 'Starting from a template replaces the current text.', confirmLabel: 'Use template' });
        if (!ok) {
          sel.value = last;
          return;
        }
      }
      last = id;
      if (!id) {
        templateId = null;
        ta.value = '';
        changed();
        renderPreview.flush();
        return;
      }
      try {
        const t = await api.get(`/posts/${enc(id)}`);
        templateId = id;
        ta.value = t.content;
        if (!topicIds.size) {
          for (const tt of t.topics) topicIds.add(tt.id);
          picker.redraw();
        }
        changed();
        renderPreview.flush();
        ta.focus();
      } catch (e) {
        toastError(e);
      }
    });
    templatePicker = h('label', { class: 'template-pick' }, icon('template', { size: 15 }), h('span', null, 'Start from'), sel);
    if (startTemplate && templates.some((t) => t.id === startTemplate)) {
      sel.value = startTemplate;
      queueMicrotask(() => sel.dispatchEvent(new Event('change')));
    }
  }

  // --- Recovery banner --------------------------------------------------------------------
  let recoveryBanner = null;
  try {
    const raw = localStorage.getItem(recoveryKey);
    const rec = raw ? JSON.parse(raw) : null;
    if (rec && !same({ ...rec, topic_ids: [...(rec.topic_ids || [])].sort(), is_template: !!rec.is_template }, saved)) {
      const restore = button('Restore', { size: 'sm', variant: 'primary' });
      const discard = button('Discard', { size: 'sm', variant: 'ghost' });
      recoveryBanner = h('div', { class: 'banner', role: 'status' }, icon('history', { size: 16 }),
        h('span', null, `You have unsaved changes from ${relTime(rec.at)}${post && rec.base_version && rec.base_version !== post.version ? `, made on version ${rec.base_version} (the post is now version ${post.version})` : ''}.`),
        h('div', { class: 'banner-actions' }, restore, discard));
      restore.addEventListener('click', () => {
        titleEl.value = rec.title || '';
        ta.value = rec.content || '';
        topicIds.clear();
        for (const id of rec.topic_ids || []) if (topicById(id)) topicIds.add(id);
        templateInput.checked = !!rec.is_template;
        picker.redraw();
        recoveryBanner.remove();
        changed();
        renderPreview.flush();
        toast('Restored your unsaved changes');
      });
      discard.addEventListener('click', () => {
        try { localStorage.removeItem(recoveryKey); } catch { /* ignore */ }
        recoveryBanner.remove();
      });
    }
  } catch {
    /* corrupt recovery data */
  }

  // --- Assemble ---------------------------------------------------------------------------
  const bar = h('div', { class: 'editor-bar' },
    back,
    statusBadge,
    saveState,
    h('span', { class: 'spacer' }),
    actionsBox);
  const metaRow = h('div', { class: 'editor-meta' }, picker.el, h('span', { class: 'spacer' }), templatePicker, templateBox);
  const page = h('div', { class: 'page page-editor' },
    bar,
    recoveryBanner,
    h('div', { class: 'editor-head' }, titleEl, metaRow),
    tabs,
    panes,
    h('div', { class: 'editor-foot' }, wordCount, h('span', { class: 'muted small' }, `${modKey}+S saves. Markdown with tables, task lists, callouts and embeds.`)));
  ctx.main.replaceChildren(page);
  updateChrome();
  renderPreview.flush();
  if (!initial.title) titleEl.focus();
  else ta.focus();

  // --- Guards and shortcuts -------------------------------------------------------------
  const onKey = (e) => {
    if ((e.metaKey || e.ctrlKey) && !e.shiftKey && e.key.toLowerCase() === 's') {
      e.preventDefault();
      if (!document.querySelector('dialog[open]')) save();
    }
  };
  document.addEventListener('keydown', onKey);
  ctx.onCleanup(() => {
    document.removeEventListener('keydown', onKey);
    document.body.dataset.dirty = '';
    renderPreview.cancel();
    writeRecovery.cancel();
    if (dirty) persistRecovery();
    closeLayers();
  });
  ctx.setLeaveGuard(async () => {
    if (!dirty) return true;
    writeRecovery.cancel();
    persistRecovery();
    const ok = await confirmDialog({
      title: 'Leave without saving?',
      message: 'Your changes aren’t saved. A recovery copy stays in this browser, so you can restore it next time you open the editor.',
      confirmLabel: 'Leave',
      cancelLabel: 'Keep editing',
      danger: true,
    });
    if (ok) {
      writeRecovery.cancel();
      persistRecovery();
      document.body.dataset.dirty = '';
    }
    return ok;
  });
  void busy;
}
