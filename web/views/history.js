// Version history: list versions, view one, diff against the current or previous version, restore.

import { api, enc } from '/api.js';
import { h, icon, button, busy, timeEl, absTime, userLink, toast, toastError, confirmDialog, plural, spinner } from '/ui.js';

/** Renders a unified diff with line numbers and add/remove coloring. */
export function diffView(diffText) {
  const table = h('div', { class: 'diff', role: 'table', 'aria-label': 'Changes' });
  let oldLn = 0;
  let newLn = 0;
  const lines = diffText.replace(/\n$/, '').split('\n');
  for (const line of lines) {
    if (line.startsWith('---') || line.startsWith('+++')) continue;
    if (line.startsWith('@@')) {
      const m = /@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(line);
      if (m) {
        oldLn = Number(m[1]);
        newLn = Number(m[2]);
      }
      table.appendChild(h('div', { class: 'diff-line diff-hunk', role: 'row' }, h('span', { class: 'diff-ln' }), h('span', { class: 'diff-ln' }), h('span', { class: 'diff-sign' }), h('span', { class: 'diff-text' }, line)));
      continue;
    }
    if (line.startsWith('\\')) continue;
    const sign = line[0] || ' ';
    const text = line.slice(1);
    let cls = 'diff-ctx';
    let a = '';
    let b = '';
    if (sign === '+') {
      cls = 'diff-add';
      b = newLn++;
    } else if (sign === '-') {
      cls = 'diff-del';
      a = oldLn++;
    } else {
      a = oldLn++;
      b = newLn++;
    }
    table.appendChild(h('div', { class: ['diff-line', cls], role: 'row' },
      h('span', { class: 'diff-ln', 'aria-hidden': 'true' }, String(a)),
      h('span', { class: 'diff-ln', 'aria-hidden': 'true' }, String(b)),
      h('span', { class: 'diff-sign', 'aria-label': sign === '+' ? 'added' : sign === '-' ? 'removed' : undefined }, sign === ' ' ? '' : sign === '-' ? '−' : '+'),
      h('span', { class: 'diff-text' }, text || ' ')));
  }
  return table;
}

export async function render(ctx) {
  const id = ctx.params.id;
  const [post, first] = await Promise.all([
    api.get(`/posts/${enc(id)}`),
    api.get(`/posts/${enc(id)}/versions`, { limit: 50 }),
  ]);
  if (!ctx.isCurrent()) return;
  ctx.setTitle(`History of ${post.title}`);
  const postPath = `/p/${post.id}/${post.slug}`;

  let versions = first.items;
  let cursor = first.next_cursor;
  const current = first.current_version;
  let selected = current;
  let mode = 'previous'; // previous | current | content

  const list = h('ol', { class: 'version-list', 'aria-label': 'Versions' });
  const more = h('div', { class: 'load-more' });
  const detail = h('section', { class: 'version-detail', 'aria-live': 'polite' });

  function drawList() {
    list.replaceChildren(...versions.map((v) => {
      const b = h('button', { type: 'button', class: 'version-item', 'aria-current': v.version === selected ? 'true' : undefined },
        h('span', { class: 'version-num' }, `v${v.version}`),
        h('span', { class: 'version-info' },
          h('span', { class: 'version-line' },
            h('span', { class: 'version-who' }, v.editor ? v.editor.name : 'Unknown'),
            v.version === current ? h('span', { class: 'badge badge-current' }, 'Current') : null),
          h('span', { class: 'version-when', title: absTime(v.created_at) }, timeEl(v.created_at)),
          v.note ? h('span', { class: 'version-note' }, v.note) : null));
      b.addEventListener('click', () => {
        selected = v.version;
        if (selected === current && mode === 'current') mode = 'previous';
        drawList();
        drawDetail();
      });
      return h('li', null, b);
    }));
    more.replaceChildren();
    if (cursor) {
      const lm = button('Older versions', { variant: 'ghost', size: 'sm' });
      lm.addEventListener('click', () => busy(lm, async () => {
        const r = await api.get(`/posts/${enc(id)}/versions`, { limit: 50, cursor });
        versions = versions.concat(r.items);
        cursor = r.next_cursor;
        drawList();
      }).catch(toastError));
      more.appendChild(lm);
    }
  }

  let detailSeq = 0;
  async function drawDetail() {
    const seq = ++detailSeq;
    const v = versions.find((x) => x.version === selected);
    const modes = [
      ['previous', 'Changes in this version', selected > 1],
      ['current', 'Compare with current', selected !== current],
      ['content', 'Full text', true],
    ].filter((m) => m[2]);
    if (!modes.some((m) => m[0] === mode)) mode = modes[0][0];
    const seg = h('div', { class: 'segmented', role: 'tablist', 'aria-label': 'What to show' },
      modes.map(([key, label]) => {
        const b = h('button', { type: 'button', role: 'tab', class: 'seg', 'aria-selected': String(key === mode) }, label);
        b.addEventListener('click', () => { mode = key; drawDetail(); });
        return b;
      }));
    const restoreBtn = selected !== current && post.can_edit ? button(`Restore version ${selected}`, { icon: 'restore', size: 'sm', variant: 'subtle' }) : null;
    if (restoreBtn) {
      restoreBtn.addEventListener('click', async () => {
        const ok = await confirmDialog({
          title: `Restore version ${selected}?`,
          message: `The post will go back to how it was in version ${selected}. This saves a new version, so nothing in the history is lost.`,
          confirmLabel: 'Restore',
        });
        if (!ok) return;
        busy(restoreBtn, async () => {
          const r = await api.post(`/posts/${enc(id)}/versions/${selected}/restore`, {});
          toast(`Restored version ${selected} as version ${r.version}`);
          ctx.reload();
        }).catch(toastError);
      });
    }
    const body = h('div', { class: 'version-body' }, h('div', { class: 'inline-loading' }, spinner()));
    detail.replaceChildren(
      h('header', { class: 'version-head' },
        h('div', null,
          h('h2', { class: 'version-title' }, `Version ${selected}`, selected === current ? h('span', { class: 'badge badge-current' }, 'Current') : null),
          v ? h('p', { class: 'muted small version-sub' }, v.editor ? userLink(v.editor, { size: 'xs' }) : 'Unknown', h('span', null, 'saved this'), timeEl(v.created_at)) : null,
          v && v.note ? h('p', { class: 'small version-note' }, v.note) : null),
        restoreBtn),
      seg,
      body);

    try {
      if (mode === 'content') {
        const ver = await api.get(`/posts/${enc(id)}/versions/${selected}`);
        const rendered = ver.content.trim() ? await api.post('/render', { markdown: ver.content }) : { html: '' };
        if (seq !== detailSeq) return;
        body.replaceChildren(h('article', { class: 'version-content' },
          h('h1', { class: 'post-title' }, ver.title),
          rendered.html ? h('div', { class: 'prose post-body', trustedHtml: rendered.html }) : h('p', { class: 'muted' }, 'This version is empty.')));
      } else {
        const query = mode === 'current' ? { from: selected, to: current } : { from: selected - 1, to: selected };
        const d = await api.get(`/posts/${enc(id)}/diff`, query);
        if (seq !== detailSeq) return;
        const summary = h('p', { class: 'diff-summary' },
          h('span', { class: 'diff-stat-add' }, `+${d.added_lines}`),
          h('span', { class: 'diff-stat-del' }, `−${d.removed_lines}`),
          h('span', { class: 'muted' }, mode === 'current' ? `from version ${d.from} to the current version ${d.to}` : `from version ${d.from} to ${d.to}`),
          d.title_changed ? h('span', { class: 'badge' }, 'Title changed') : null);
        body.replaceChildren(summary, d.diff.trim()
          ? diffView(d.diff)
          : h('p', { class: 'muted' }, d.title_changed ? 'Only the title changed.' : 'No changes to the text.'));
      }
    } catch (e) {
      if (seq === detailSeq) body.replaceChildren(h('p', { class: 'form-error' }, icon('alert', { size: 15 }), h('span', null, e.message)));
    }
  }

  drawList();
  ctx.main.replaceChildren(h('div', { class: 'page page-wide' },
    h('header', { class: 'page-head' },
      h('div', { class: 'page-head-text' },
        h('a', { class: 'back-link', href: postPath }, icon('chevronLeft', { size: 14 }), 'Back to post'),
        h('h1', { class: 'page-title' }, 'History'),
        h('p', { class: 'page-desc' }, `“${post.title}” has ${plural(current, 'version')}. Every save keeps a version, and restoring one adds a new version.`))),
    h('div', { class: 'history-layout' },
      h('div', { class: 'version-col' }, list, more),
      detail)));
  drawDetail();
}
