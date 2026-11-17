// Search: the ⌘K command palette and the full /search page.

import { api } from '/api.js';
import { h, icon, kbd, modKey, debounce, timeEl, topicChip, urlPath, button, busy, toastError, emptyState, pageHeader, userLink, select, checkbox, setTheme, themePref, BLOCK_RECORDING } from '/ui.js';
import { state, navigate, canEdit } from '/state.js';
import { statusBadges, inlineLoading } from '/views/common.js';
import { connectedResults, searchableConnections, searchConnected, webUrl, KIND_LABEL as APP_KIND_LABEL } from '/views/connected.js';

const KIND_ICON = { post: 'file', comment: 'comment', topic: 'hash' };
const KIND_LABEL = { post: 'Post', comment: 'Comment', topic: 'Topic' };
/** The palette shows this many results from each connected app. */
const APP_HITS = 3;
/** Shorter queries don't ask connected apps: they'd match too much to be worth the wait. */
const APP_MIN_CHARS = 2;

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

  /**
   * Shows the groups of options. `keep` re-renders in place: the option that was highlighted stays
   * highlighted, so results arriving late don't move the person's place.
   */
  function renderOptions(groups, { keep = false } = {}) {
    const was = keep && items[active] ? items[active].el.id : null;
    list.replaceChildren();
    items = [];
    for (const g of groups) {
      if (!g.items.length && !g.note) continue;
      if (g.label) list.appendChild(groupLabel(g.label));
      for (const it of g.items) {
        items.push(it);
        list.appendChild(it.el);
      }
      if (g.note) list.appendChild(g.note);
    }
    if (!items.length) list.appendChild(h('div', { class: 'palette-empty' }, 'No matches. Try fewer or different words.'));
    const again = was ? items.findIndex((it) => it.el.id === was) : -1;
    setActive(again >= 0 ? again : 0);
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

  // What the palette shows for the current query: the workspace's own results, then (when the
  // person connected apps that search) results from those apps, which take longer to arrive.
  let shown = null; // { q, hits }
  let apps = null; // { q, names } while searching, { q, r } once answered, { q, error } after a failure

  function appOption(it, i) {
    const url = webUrl(it.url);
    const kind = APP_KIND_LABEL[it.kind] || it.kind;
    // Someone's own data in another app (their Drive's file names): an empty box in recordings.
    return option(`c-${it.provider}-${i}`, [
      h('span', { class: 'palette-kind', title: kind }, icon('external', { size: 16 })),
      h('span', { class: ['palette-text', BLOCK_RECORDING] },
        h('span', { class: 'palette-title' }, h('span', null, it.title || '(untitled)')),
        h('span', { class: 'palette-snippet' }, [kind, it.context, it.author].filter(Boolean).join(' · '))),
    ], () => {
      if (!url) return;
      close();
      window.open(url, '_blank', 'noopener,noreferrer');
    });
  }

  function appGroups() {
    if (!apps || !shown || apps.q !== shown.q) return [];
    const muted = (text) => h('div', { class: 'palette-note', role: 'presentation' }, text);
    if (apps.names) return [{ label: '', items: [], note: muted(`Searching ${apps.names}…`) }];
    if (apps.error) return [{ label: '', items: [], note: muted(`Couldn’t search your connected apps: ${apps.error}`) }];
    return apps.r.apps.map((app) => {
      const hits = apps.r.items.filter((it) => it.provider === app.provider).slice(0, APP_HITS);
      // An app that failed says so quietly; one with nothing to show takes no room.
      const note = app.ok ? null : muted(app.error || `${app.name} couldn’t be searched.`);
      return { label: hits.length || note ? app.name : '', items: hits.map((it, i) => appOption(it, i)), note };
    });
  }

  function render({ keep = false } = {}) {
    if (!shown) return;
    const { q, hits } = shown;
    const all = option('all', [h('span', { class: 'palette-kind' }, icon('search', { size: 16 })), h('span', { class: 'palette-text' }, h('span', { class: 'palette-title' }, `See all results for “${q}”`))], () => go(`/search?q=${encodeURIComponent(q)}`));
    const acts = actions(q).map((a) => option(`a-${a.id}`, [h('span', { class: 'palette-kind' }, icon(a.iconName, { size: 16 })), h('span', { class: 'palette-text' }, h('span', { class: 'palette-title' }, a.label))], a.run));
    renderOptions([
      { label: hits.length ? 'Results' : '', items: hits.map((hit) => option(`h-${hit.kind}-${hit.id}`, hitContent(hit), () => go(urlPath(hit.url)))) },
      ...appGroups(),
      { label: '', items: [all] },
      { label: acts.length ? 'Actions' : '', items: acts },
    ], { keep });
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
    shown = { q, hits: r.items };
    render();
  }, 150);

  // Connected apps answer in seconds and each query asks every one, so wait for a pause in typing.
  const runApps = debounce(async (q) => {
    if (q.length < APP_MIN_CHARS) return;
    const mine = await searchableConnections();
    if (!mine.length || !palette || inputEl.value.trim() !== q) return;
    apps = { q, names: mine.map((a) => a.name).join(', ') };
    render({ keep: true });
    let next;
    try {
      next = { q, r: await searchConnected(q, APP_HITS) };
    } catch (e) {
      next = { q, error: e.message };
    }
    // Only the newest query's answer counts.
    if (!palette || inputEl.value.trim() !== q) return;
    apps = next;
    render({ keep: true });
  }, 350);

  inputEl.addEventListener('input', () => {
    const q = inputEl.value.trim();
    apps = null;
    if (!q) {
      runSearch.cancel();
      runApps.cancel();
      shown = null;
      showDefault();
    } else {
      runSearch(q);
      runApps(q);
    }
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
  searchableConnections().then((mine) => {
    if (mine.length && palette) inputEl.placeholder = 'Search posts, topics and your connected apps';
  });
  if (initial) {
    runSearch.flush(initial);
    runApps(initial.trim());
  } else showDefault();
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
  const noResults = () => emptyState({ iconName: 'search', title: `No results for “${q}”`, body: 'Check the spelling, use fewer words, or include archived posts.' });
  if (first.items.length) {
    add(first);
    results.append(list, more, connectedResults(q));
  } else if (!(await searchableConnections()).length) {
    if (!ctx.isCurrent()) return;
    results.append(noResults(), connectedResults(q));
  } else {
    // The person's connected apps may well have it: say so briefly while they answer, and show the
    // full "no results" only if they find nothing either.
    if (!ctx.isCurrent()) return;
    const none = h('p', { class: 'search-none muted' }, icon('search', { size: 15 }), h('span', null, `No posts match “${q}”.`));
    results.append(none, connectedResults(q, { onSettled: (found) => { if (!found) none.replaceWith(noResults()); } }));
  }
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
