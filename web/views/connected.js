// Connected apps in the web app: Settings › Connected apps, results from them on the search page,
// and previews of links to them in posts. Everyone connects their own accounts.

import { api, enc } from '/api.js';
import { h, icon, button, busy, toast, toastError, confirmDialog, field, input, emptyState, timeEl, openPopover } from '/ui.js';

let listing = null;

/** The apps and the person's connections, fetched once per page load. */
export function connections({ fresh = false } = {}) {
  if (!listing || fresh) listing = api.get('/connections').catch((e) => { listing = null; throw e; });
  return listing;
}

/** Only web links become links: app answers are someone else's data. */
const webUrl = (url) => (/^https?:\/\//i.test(url || '') ? url : null);

function external(url, label, cls) {
  const href = webUrl(url);
  return href ? h('a', { class: cls, href, target: '_blank', rel: 'noopener noreferrer' }, label) : h('span', { class: cls }, label);
}

const KIND_LABEL = {
  issue: 'Issue', pull_request: 'Pull request', repository: 'Repository', merge_request: 'Merge request', message: 'Message',
  page: 'Page', ticket: 'Ticket', article: 'Article', task: 'Task', project: 'Project', card: 'Card', file: 'File', folder: 'Folder',
  document: 'Doc', spreadsheet: 'Sheet', presentation: 'Slides', form: 'Form', story: 'Story', item: 'Item',
};

// ---------------------------------------------------------------------------
// Search page

/** A section that fills in with results from the person's connected apps. */
export function connectedResults(q) {
  const section = h('section', { class: 'connected-results', 'aria-label': 'Results from your connected apps' });
  (async () => {
    let list;
    try {
      list = await connections();
    } catch {
      return;
    }
    if (!list.enabled) return;
    const searchable = list.apps.filter((a) => a.search);
    const mine = searchable.filter((a) => a.connected);
    if (!mine.length) {
      if (searchable.length) {
        section.append(h('p', { class: 'connected-hint muted small' }, icon('plug', { size: 14 }),
          h('span', null, `Search ${searchable.slice(0, 3).map((a) => a.name).join(', ')} and more from here: `),
          h('a', { href: '/settings/connections' }, 'connect your apps')));
      }
      return;
    }
    const status = h('p', { class: 'muted small', role: 'status' }, `Searching ${mine.map((a) => a.name).join(', ')}…`);
    section.append(h('h2', { class: 'connected-title' }, 'From your connected apps'), status);
    let r;
    try {
      r = await api.get('/search/connected', { q, limit: 5 });
    } catch (e) {
      status.textContent = `Couldn't search your connected apps: ${e.message}`;
      return;
    }
    status.remove();
    for (const app of r.apps) {
      const hits = r.items.filter((i) => i.provider === app.provider);
      const group = h('div', { class: 'connected-group' }, h('h3', { class: 'connected-app' }, app.name));
      if (!app.ok) {
        group.append(h('p', { class: 'callout callout-warn' }, icon('alert', { size: 15 }), h('span', null, app.error || `${app.name} couldn't be searched.`)));
      } else if (!hits.length) {
        group.append(h('p', { class: 'muted small' }, `Nothing in ${app.name}.`));
      } else {
        group.append(h('ol', { class: 'hit-list' }, hits.map(hitRow)));
      }
      section.append(group);
    }
  })();
  return section;
}

function hitRow(hit) {
  return h('li', { class: 'hit' },
    h('div', { class: 'hit-kind', title: KIND_LABEL[hit.kind] || hit.kind }, icon('external', { size: 16, label: KIND_LABEL[hit.kind] || hit.kind })),
    h('div', { class: 'hit-main' },
      h('div', { class: 'hit-head' }, external(hit.url, hit.title || '(untitled)', 'hit-title')),
      hit.snippet ? h('p', { class: 'hit-snippet' }, hit.snippet) : null,
      h('div', { class: 'post-row-meta' },
        h('span', { class: 'meta-item' }, [KIND_LABEL[hit.kind] || hit.kind, hit.context].filter(Boolean).join(' · ')),
        hit.author ? h('span', { class: 'meta-item' }, hit.author) : null,
        hit.updated_at ? h('span', { class: 'meta-item' }, timeEl(hit.updated_at, { prefix: 'Updated ' })) : null)));
}

// ---------------------------------------------------------------------------
// Link previews

const previews = new Map();

function previewOf(url) {
  if (!previews.has(url)) previews.set(url, api.get('/connections/preview', { url }).catch(() => null));
  return previews.get(url);
}

function previewCard(p, appName) {
  const rows = [
    p.status ? ['Status', p.status] : null,
    p.assignee ? ['Assignee', p.assignee] : null,
    p.author ? ['Created by', p.author] : null,
    ...(p.details || []).map((d) => [d.label, d.value]),
  ].filter(Boolean);
  return h('div', { class: 'link-preview' },
    h('p', { class: 'link-preview-ref muted small' }, [appName, p.reference].filter(Boolean).join(' · ')),
    h('p', { class: 'link-preview-title' }, external(p.url, p.title || p.reference)),
    rows.length ? h('dl', { class: 'link-preview-facts' }, rows.map(([k, v]) => [h('dt', null, k), h('dd', null, v)])) : null,
    p.description ? h('p', { class: 'link-preview-desc' }, p.description) : null,
    p.updated_at ? h('p', { class: 'muted small' }, timeEl(p.updated_at, { prefix: 'Updated ' })) : null);
}

/** Shows a preview card when someone hovers or focuses a link to a connected app's item. */
export function attachPreviews(root) {
  let timer = null;
  let open = null;
  const nameOf = async (id) => ((await connections().catch(() => ({ apps: [] }))).apps.find((a) => a.id === id) || {}).name || id;
  const show = async (a) => {
    const r = await previewOf(a.href);
    if (!r || !r.app || document.activeElement !== a && !a.matches(':hover')) return;
    const name = await nameOf(r.app);
    let content;
    if (r.preview) content = previewCard(r.preview, name);
    else if (!r.connected) {
      content = h('div', { class: 'link-preview' }, h('p', { class: 'small' }, `Connect ${name} to see previews of its links. `), h('a', { href: '/settings/connections' }, 'Connect apps'));
    } else if (r.error) content = h('div', { class: 'link-preview' }, h('p', { class: 'small muted' }, r.error));
    else return;
    open = openPopover(a, content, { placement: 'bottom', align: 'start', label: `Preview of ${name} link` });
  };
  for (const a of root.querySelectorAll('a[href^="http"]')) {
    if (new URL(a.href).origin === location.origin) continue;
    const start = () => { clearTimeout(timer); timer = setTimeout(() => show(a), 350); };
    const stop = () => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        if (open && !open.el.matches(':hover')) { open.close(); open = null; }
      }, 250);
    };
    a.addEventListener('mouseenter', start);
    a.addEventListener('focus', start);
    a.addEventListener('mouseleave', stop);
    a.addEventListener('blur', stop);
  }
}

// ---------------------------------------------------------------------------
// Settings › Connected apps

export async function connectionsSection() {
  const list = await connections({ fresh: true });
  const query = new URLSearchParams(location.search);
  const notes = [];
  if (query.get('connected')) {
    const app = list.apps.find((a) => a.id === query.get('connected'));
    notes.push(h('p', { class: 'callout', role: 'status' }, icon('check', { size: 15 }), h('span', null, `${app ? app.name : 'The app'} is connected.`)));
  }
  if (query.get('connect_error')) {
    notes.push(h('p', { class: 'callout callout-warn', role: 'alert' }, icon('alert', { size: 15 }), h('span', null, query.get('connect_error'))));
  }
  if (!list.enabled) {
    return h('section', { class: 'panel' }, emptyState({ iconName: 'plug', title: 'Connected apps aren’t set up here',
      body: 'The server needs a connector key before anyone can connect GitHub, Google Drive and other apps. Whoever runs it can set CONNECTOR_KEY (or DUMBSLAB_CONNECTOR_KEY when self-hosting).' }));
  }
  const rerender = async () => {
    const fresh = await connectionsSection();
    section.replaceWith(fresh);
  };
  const cards = list.apps.map((app) => appCard(app, rerender));
  const section = h('div', { class: 'stack' }, ...notes,
    h('section', { class: 'panel' },
      h('header', { class: 'panel-head' }, h('h2', { class: 'panel-title' }, 'Connected apps'),
        h('p', { class: 'panel-desc' }, 'Connect your own accounts to search them from DumbSlab and see previews of their links in posts. Only you can use your connections, and you only see what your account can see there. Credentials are encrypted and never shown again.')),
      h('div', { class: 'app-list' }, cards)));
  return section;
}

function appCard(app, rerender) {
  const head = h('div', { class: 'app-head' },
    h('div', null, h('p', { class: 'app-name' }, app.name), h('p', { class: 'muted small' }, app.about)),
    app.connected ? h('span', { class: 'badge badge-published' }, 'Connected') : null);
  const body = h('div', { class: 'app-body' });
  if (app.connected) {
    const disconnect = button('Disconnect', { variant: 'subtle', size: 'sm' });
    disconnect.addEventListener('click', async () => {
      const ok = await confirmDialog({ title: `Disconnect ${app.name}?`, message: `DumbSlab forgets your ${app.name} credentials. To revoke its access completely, also remove it in ${app.name}’s settings.`, confirmLabel: 'Disconnect', danger: true });
      if (!ok) return;
      await busy(disconnect, async () => {
        await api.del(`/connections/${enc(app.id)}`);
        toast(`${app.name} disconnected`);
        await rerender();
      }).catch(toastError);
    });
    body.append(h('p', { class: 'small' }, `Connected as ${app.connected.account}.`), h('div', null, disconnect));
    return h('div', { class: 'app-card' }, head, body);
  }
  const actions = h('div', { class: 'plan-actions' });
  if (app.sign_in) {
    const connect = button(`Sign in with ${app.name}`, { variant: 'primary', size: 'sm', icon: 'external' });
    connect.addEventListener('click', () => busy(connect, async () => {
      const r = await api.post('/connections', { app: app.id });
      location.assign(r.authorize_url);
    }).catch(toastError));
    actions.append(connect);
  }
  if (app.token_fields.length) {
    const form = tokenForm(app, rerender);
    form.hidden = app.sign_in;
    if (app.sign_in) {
      const show = button('Use a token instead', { variant: 'ghost', size: 'sm' });
      show.addEventListener('click', () => { form.hidden = false; show.remove(); form.querySelector('input').focus(); });
      actions.append(show);
    }
    body.append(actions, form);
  } else if (app.sign_in) {
    body.append(actions);
  } else {
    body.append(h('p', { class: 'muted small' }, `Signing in with ${app.name} isn’t set up on this server yet.`));
  }
  return h('div', { class: 'app-card' }, head, body);
}

function tokenForm(app, rerender) {
  const inputs = app.token_fields.map((f) => [f, input({ type: f.secret ? 'password' : 'text', required: !f.optional, autocomplete: 'off', spellcheck: 'false', name: f.key })]);
  const submit = button(`Connect ${app.name}`, { variant: 'primary', size: 'sm', type: 'submit' });
  const form = h('form', { class: 'stack token-form', novalidate: true },
    ...inputs.map(([f, el]) => field(f.optional ? `${f.label} (optional)` : f.label, el, { hint: f.help })),
    app.token_help ? h('p', { class: 'field-hint' }, 'Make a token at ', external(app.token_help, new URL(app.token_help).host), '.') : null,
    h('div', null, submit));
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    if (!form.checkValidity()) {
      form.reportValidity();
      return;
    }
    const fields = Object.fromEntries(inputs.map(([f, el]) => [f.key, el.value.trim()]).filter(([, v]) => v));
    busy(submit, async () => {
      const r = await api.post('/connections', { app: app.id, fields });
      toast(`${app.name} connected as ${r.connection.account}`);
      await rerender();
    }).catch(toastError);
  });
  return form;
}

