// Search: the ⌘K command palette and the full /search page.

import { api } from '/api.js';
import { h, icon, kbd, modKey, debounce, timeEl, topicChip, urlPath, button, busy, toastError, emptyState, pageHeader, userLink, select, checkbox, setTheme, themePref } from '/ui.js';
import { state, navigate, canEdit } from '/state.js';
import { statusBadges, inlineLoading } from '/views/common.js';
import { connectedResults } from '/views/connected.js';

const KIND_ICON = { post: 'file', comment: 'comment', topic: 'hash' };
const KIND_LABEL = { post: 'Post', comment: 'Comment', topic: 'Topic' };

let palette = null;

export function togglePalette() {
  if (palette) palette.close();
  else openPalette();
}

export function openPalette(initial = '') {
  if (palette) {
    palette.input.focus();
    return;
  }
  const listId = 'palette-list';
  const inputEl = h('input', {
    class: 'palette-input',
    type: 'text',
    placeholder: 'Search posts, comments and topics',
    role: 'combobox',
    'aria-expanded': 'true',
    'aria-controls': listId,
    'aria-autocomplete': 'list',
    'aria-label': 'Search',
    autocomplete: 'off',
    spellcheck: 'false',
    value: initial,
  });
  const list = h('div', { class: 'palette-list', id: listId, role: 'listbox', 'aria-label': 'Results' });
  const hint = h('div', { class: 'palette-hint', hidden: true });
  const foot = h('div', { class: 'palette-foot' },
    h('span', null, kbd('↑', '↓'), ' to move'),
    h('span', null, kbd('Enter'), ' to open'),
    h('span', null, kbd('Esc'), ' to close'));
  const dialog = h('dialog', { class: 'palette', 'aria-label': 'Search' },
    h('div', { class: 'palette-box' },
      h('div', { class: 'palette-field' }, icon('search', { size: 18 }), inputEl, h('span', { class: 'palette-kbd' }, kbd('Esc'))),
      hint,
      list,
      foot));

  let items = [];
  let active = 0;
  let seq = 0;

  function setActive(i) {
    if (!items.length) {
      inputEl.removeAttribute('aria-activedescendant');
      return;
    }
    active = (i + items.length) % items.length;
    items.forEach((it, idx) => it.el.setAttribute('aria-selected', String(idx === active)));
    inputEl.setAttribute('aria-activedescendant', items[active].el.id);
    items[active].el.scrollIntoView({ block: 'nearest' });
  }

  function option(id, content, run) {
    const el = h('div', { class: 'palette-item', role: 'option', id: `po-${id}`, 'aria-selected': 'false' }, content);
    el.addEventListener('mousemove', () => {
      const i = items.findIndex((x) => x.el === el);
      if (i !== active) setActive(i);
    });
    el.addEventListener('click', run);
    return { el, run };
  }

  function groupLabel(text) {
    return h('div', { class: 'palette-group', role: 'presentation' }, text);
  }

  function hitContent(hit) {
    return [
      h('span', { class: 'palette-kind', title: KIND_LABEL[hit.kind] }, icon(KIND_ICON[hit.kind] || 'file', { size: 16 })),
      h('span', { class: 'palette-text' },
        h('span', { class: 'palette-title' },
          hit.kind === 'comment' ? h('span', { class: 'palette-sub' }, 'Comment on ') : null,
          h('span', null, hit.title),
          hit.status && hit.status !== 'published' ? h('span', { class: `badge badge-${hit.status}` }, hit.status === 'draft' ? 'Draft' : 'Archived') : null),
        hit.snippet ? h('span', { class: 'palette-snippet', trustedHtml: hit.snippet }) : null),
      hit.topics && hit.topics.length ? h('span', { class: 'palette-topics' }, hit.topics.slice(0, 2).map((t) => h('span', { class: 'chip chip-static' }, t.icon ? t.icon + ' ' : '', t.name))) : null,
    ];
  }

  function close() {
    if (!palette) return;
    palette = null;
    dialog.close();
    dialog.remove();
  }

  function go(path) {
    close();
    navigate(path);
  }

  function actions(q) {
    const all = [
      canEdit() && { id: 'new', label: 'New post', iconName: 'plus', run: () => go('/new') },
      { id: 'drafts', label: 'Go to drafts', iconName: 'draft', run: () => go('/drafts') },
      { id: 'topics', label: 'Browse topics', iconName: 'folder', run: () => go('/topics') },
      { id: 'notifications', label: 'Go to notifications', iconName: 'bell', run: () => go('/notifications') },
      { id: 'activity', label: 'Go to activity', iconName: 'activity', run: () => go('/activity') },
      { id: 'agents', label: 'Connect agents', iconName: 'plug', run: () => go('/settings/agents') },
      { id: 'settings', label: 'Open settings', iconName: 'settings', run: () => go('/settings') },
      { id: 'theme', label: document.documentElement.dataset.theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme', iconName: 'moon', run: () => { setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'); close(); } },
    ].filter(Boolean);
    if (!q) return all;
    const needle = q.toLowerCase();
    return all.filter((a) => a.label.toLowerCase().includes(needle));
  }

  function renderOptions(groups) {
    list.replaceChildren();
    items = [];
    for (const g of groups) {
      if (!g.items.length) continue;
      if (g.label) list.appendChild(groupLabel(g.label));
      for (const it of g.items) {
        items.push(it);
        list.appendChild(it.el);
      }
    }
    if (!items.length) list.appendChild(h('div', { class: 'palette-empty' }, 'No matches. Try fewer or different words.'));
    setActive(0);
  }

  async function showDefault() {
    hint.hidden = true;
    const mySeq = ++seq;
    let recent = [];
    try {
      recent = (await api.get('/me/recent', { limit: 6 })).items;
    } catch {
      recent = [];
    }
    if (mySeq !== seq || !palette) return;
    renderOptions([
      { label: 'Recently viewed', items: recent.map((p) => option(`r-${p.id}`, [h('span', { class: 'palette-kind' }, icon('file', { size: 16 })), h('span', { class: 'palette-text' }, h('span', { class: 'palette-title' }, p.title))], () => go(urlPath(p.url)))) },
      { label: 'Actions', items: actions('').map((a) => option(`a-${a.id}`, [h('span', { class: 'palette-kind' }, icon(a.iconName, { size: 16 })), h('span', { class: 'palette-text' }, h('span', { class: 'palette-title' }, a.label))], a.run)) },
    ]);
  }

  const runSearch = debounce(async (q) => {
    const mySeq = ++seq;
    let r;
    try {
      r = await api.get('/search', { q, limit: 8 });
    } catch (e) {
      if (mySeq === seq) {
        list.replaceChildren(h('div', { class: 'palette-empty' }, e.message));
      }
      return;
    }
    if (mySeq !== seq || !palette) return;
    hint.hidden = !r.broadened;
    hint.textContent = r.broadened ? 'No result has every word, so these match some of them.' : '';
    const hits = r.items.map((hit) => option(`h-${hit.kind}-${hit.id}`, hitContent(hit), () => go(urlPath(hit.url))));
    const all = option('all', [h('span', { class: 'palette-kind' }, icon('search', { size: 16 })), h('span', { class: 'palette-text' }, h('span', { class: 'palette-title' }, `See all results for “${q}”`))], () => go(`/search?q=${encodeURIComponent(q)}`));
    const acts = actions(q).map((a) => option(`a-${a.id}`, [h('span', { class: 'palette-kind' }, icon(a.iconName, { size: 16 })), h('span', { class: 'palette-text' }, h('span', { class: 'palette-title' }, a.label))], a.run));
    renderOptions([{ label: hits.length ? 'Results' : '', items: hits }, { label: '', items: [all] }, { label: acts.length ? 'Actions' : '', items: acts }]);
  }, 150);

  inputEl.addEventListener('input', () => {
    const q = inputEl.value.trim();
    if (!q) {
      runSearch.cancel();
      showDefault();
    } else runSearch(q);
  });
  inputEl.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive(active + 1); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive(active - 1); }
    else if (e.key === 'Enter') {
      e.preventDefault();
      if (e.isComposing) return;
      const q = inputEl.value.trim();
      if (items[active]) items[active].run();
      else if (q) go(`/search?q=${encodeURIComponent(q)}`);
    }
  });
  dialog.addEventListener('cancel', (e) => { e.preventDefault(); close(); });
  dialog.addEventListener('mousedown', (e) => { if (e.target === dialog) close(); });

  document.body.appendChild(dialog);
  dialog.showModal();
  palette = { close, input: inputEl };
  inputEl.focus();
  if (initial) runSearch.flush(initial);
  else showDefault();
  void themePref;
}

// ---------------------------------------------------------------------------
// Full search page.

export async function renderPage(ctx) {
  const q = ctx.query.get('q') || '';
  const type = ctx.query.get('type') || 'all';
  const archived = ctx.query.get('archived') === '1';
  ctx.setTitle(q ? `Search: ${q}` : 'Search');

  const qInput = h('input', { class: 'input input-lg', type: 'search', name: 'q', value: q, placeholder: 'Search the knowledge base', 'aria-label': 'Search', autocomplete: 'off' });
  const typeSel = select([
    { value: 'all', label: 'Everything', selected: type === 'all' },
    { value: 'post', label: 'Posts', selected: type === 'post' },
    { value: 'comment', label: 'Comments', selected: type === 'comment' },
    { value: 'topic', label: 'Topics', selected: type === 'topic' },
  ], { 'aria-label': 'Result type' });
  const archivedBox = checkbox('Include archived', { checked: archived });
  const form = h('form', { class: 'search-form', role: 'search' },
    h('div', { class: 'search-form-row' }, icon('search', { size: 18 }), qInput, button('Search', { variant: 'primary', type: 'submit' })),
    h('div', { class: 'search-filters' }, typeSel, archivedBox));
  const apply = () => {
    const params = new URLSearchParams();
    if (qInput.value.trim()) params.set('q', qInput.value.trim());
    if (typeSel.value !== 'all') params.set('type', typeSel.value);
    if (archivedBox.querySelector('input').checked) params.set('archived', '1');
    navigate(`/search?${params}`);
  };
  form.addEventListener('submit', (e) => { e.preventDefault(); apply(); });
  typeSel.addEventListener('change', apply);
  archivedBox.querySelector('input').addEventListener('change', apply);

  const results = h('div', { class: 'search-results' });
  const page = h('div', { class: 'page page-medium' }, pageHeader('Search'), form, results);

  if (!q) {
    results.appendChild(emptyState({ iconName: 'search', title: 'Search posts, comments and topics', body: 'Quoted phrases match exactly. The last word matches as a prefix, so partial words work too.' }));
    ctx.main.replaceChildren(page);
    qInput.focus();
    return;
  }

  const query = { q, types: type === 'all' ? undefined : type, include_archived: archived || undefined, limit: 20 };
  const first = await api.get('/search', query);
  if (!ctx.isCurrent()) return;

  const list = h('ol', { class: 'hit-list' });
  const more = h('div', { class: 'load-more' });
  let cursor = null;
  const add = (r) => {
    for (const hit of r.items) list.appendChild(hitRow(hit));
    cursor = r.next_cursor;
    more.replaceChildren();
    if (cursor) {
      const b = button('Load more', { variant: 'ghost' });
      b.addEventListener('click', () => busy(b, async () => add(await api.get('/search', { ...query, cursor }))).catch(toastError));
      more.appendChild(b);
    }
  };
  if (first.broadened) {
    results.appendChild(h('p', { class: 'callout' }, icon('info', { size: 15 }), h('span', null, 'Nothing matched every word, so these results match some of them.')));
  }
  if (!first.items.length) {
    results.appendChild(emptyState({ iconName: 'search', title: `No results for “${q}”`, body: 'Check the spelling, use fewer words, or include archived posts.' }));
  } else {
    add(first);
    results.append(list, more);
  }
  results.append(connectedResults(q));
  ctx.main.replaceChildren(page);
  void inlineLoading;
  void state;
}

function hitRow(hit) {
  return h('li', { class: 'hit' },
    h('div', { class: 'hit-kind', title: KIND_LABEL[hit.kind] }, icon(KIND_ICON[hit.kind] || 'file', { size: 16, label: KIND_LABEL[hit.kind] })),
    h('div', { class: 'hit-main' },
      h('div', { class: 'hit-head' },
        hit.kind === 'comment' ? h('span', { class: 'muted' }, 'Comment on ') : null,
        h('a', { class: 'hit-title', href: urlPath(hit.url) }, hit.title),
        ...(hit.status ? statusBadges({ status: hit.status }) : [])),
      hit.snippet ? h('p', { class: 'hit-snippet', trustedHtml: hit.snippet }) : null,
      h('div', { class: 'post-row-meta' },
        hit.topics && hit.topics.length ? h('span', { class: 'chips' }, hit.topics.slice(0, 3).map(topicChip)) : null,
        hit.author ? userLink(hit.author) : null,
        hit.updated_at ? h('span', { class: 'meta-item' }, timeEl(hit.updated_at, { prefix: 'Updated ' })) : null)));
}
