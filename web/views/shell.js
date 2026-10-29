// The app frame: sidebar (navigation, topic tree, account), mobile drawer and shortcut help.

import { api } from '/api.js';
import { h, icon, avatar, kbd, modKey, openMenu, modal, frag, setTheme, themePref, topicIcon, toastError, button } from '/ui.js';
import { state, on, canEdit, canAdmin, topicTree, navigate } from '/state.js';
import { openPalette } from '/views/search.js';
import { openTopicForm } from '/views/topic.js';

let sidebar;
let backdrop;
let menuBtn;
const COLLAPSE_KEY = 'ds-topics-collapsed';

function collapsedSet() {
  try {
    return new Set(JSON.parse(localStorage.getItem(COLLAPSE_KEY) || '[]'));
  } catch {
    return new Set();
  }
}

function saveCollapsed(set) {
  try {
    localStorage.setItem(COLLAPSE_KEY, JSON.stringify([...set]));
  } catch {
    /* ignore */
  }
}

function navLink(href, label, iconName, extra) {
  return h('a', { class: 'nav-link', href, dataset: { nav: href } }, icon(iconName), h('span', { class: 'nav-label' }, label), extra || null);
}

function renderTopicTree(container) {
  const collapsed = collapsedSet();
  const build = (nodes, depth) => {
    const ul = h('ul', { class: 'tree', role: depth === 0 ? 'tree' : 'group', 'aria-label': depth === 0 ? 'Topics' : undefined });
    for (const n of nodes) {
      const t = n.topic;
      const hasKids = n.children.length > 0;
      const isOpen = !collapsed.has(t.id);
      const li = h('li', { class: 'tree-item', role: 'treeitem', 'aria-expanded': hasKids ? String(isOpen) : undefined });
      const toggle = hasKids
        ? h('button', { type: 'button', class: 'tree-toggle', 'aria-label': `${isOpen ? 'Collapse' : 'Expand'} ${t.name}` }, icon('chevronRight', { size: 14 }))
        : h('span', { class: 'tree-toggle tree-toggle-empty' });
      const row = h('div', { class: 'tree-row', style: { '--depth': String(depth) } },
        toggle,
        h('a', { class: 'tree-link', href: `/t/${t.id}/${t.slug}`, dataset: { nav: `/t/${t.id}` } },
          topicIcon(t, 'sm'),
          h('span', { class: 'tree-name' }, t.name),
          t.visibility === 'private' ? icon('lock', { size: 12, label: 'Private', cls: 'tree-lock' }) : null));
      li.appendChild(row);
      if (hasKids) {
        const kids = build(n.children, depth + 1);
        kids.hidden = !isOpen;
        li.appendChild(kids);
        toggle.addEventListener('click', () => {
          const open = kids.hidden;
          kids.hidden = !open;
          li.setAttribute('aria-expanded', String(open));
          toggle.setAttribute('aria-label', `${open ? 'Collapse' : 'Expand'} ${t.name}`);
          const set = collapsedSet();
          if (open) set.delete(t.id);
          else set.add(t.id);
          saveCollapsed(set);
        });
      }
      ul.appendChild(li);
    }
    return ul;
  };
  const tree = topicTree();
  container.replaceChildren(tree.length
    ? build(tree, 0)
    : h('p', { class: 'tree-empty' }, canEdit() ? 'No topics yet. Create one to organize posts.' : 'No topics yet.'));
  updateActiveNav(location.pathname);
}

function themeItems() {
  const pref = themePref();
  return [
    { heading: 'Theme' },
    { label: 'System', checked: pref === 'system', onClick: () => setTheme('system') },
    { label: 'Light', checked: pref === 'light', onClick: () => setTheme('light') },
    { label: 'Dark', checked: pref === 'dark', onClick: () => setTheme('dark') },
  ];
}

async function signOut() {
  try {
    await api.post('/auth/logout', {});
  } catch (e) {
    toastError(e);
  }
  location.href = '/login';
}

function userMenu(anchor) {
  const u = state.me.user;
  openMenu(anchor, [
    { label: 'Your profile', icon: 'user', onClick: () => navigate(`/u/${encodeURIComponent(u.handle)}`) },
    { label: 'Settings', icon: 'settings', onClick: () => navigate('/settings') },
    { label: 'Connect agents', icon: 'plug', onClick: () => navigate('/settings/agents') },
    { label: 'Keyboard shortcuts', icon: 'keyboard', hint: '?', onClick: showShortcuts },
    'separator',
    ...themeItems(),
    'separator',
    { label: 'Sign out', icon: 'logout', onClick: signOut },
  ], { placement: 'top' });
}

export function buildShell(root) {
  const ws = state.settings.workspace_name;
  const me = state.me.user;

  const wsName = h('span', { class: 'ws-name' }, ws);
  const unreadBadge = h('span', { class: 'nav-count', hidden: true });
  const topicsBox = h('div', { class: 'tree-wrap' });

  const searchBtn = h('button', { type: 'button', class: 'search-trigger', 'aria-label': 'Search', 'aria-keyshortcuts': 'Meta+K Control+K' },
    icon('search'), h('span', { class: 'search-trigger-label' }, 'Search'), kbd(modKey, 'K'));
  searchBtn.addEventListener('click', () => openPalette());

  const topicsHead = h('div', { class: 'side-head' },
    h('a', { class: 'side-head-link', href: '/topics', dataset: { nav: '/topics' } }, 'Topics'),
    canEdit() ? button('', { icon: 'plus', variant: 'ghost', size: 'xs', 'aria-label': 'Create topic', title: 'Create topic', onClick: () => openTopicForm({}) }) : null);

  const accountBtn = h('button', { type: 'button', class: 'account', 'aria-label': `Account menu for ${me.name}`, 'aria-haspopup': 'menu', 'aria-expanded': 'false' },
    avatar(me, 'sm'),
    h('span', { class: 'account-text' }, h('span', { class: 'account-name' }, me.name), h('span', { class: 'account-handle' }, '@' + me.handle)),
    icon('more', { cls: 'account-more' }));
  accountBtn.addEventListener('click', () => userMenu(accountBtn));

  sidebar = h('aside', { class: 'sidebar', id: 'sidebar', 'aria-label': 'Sidebar' },
    h('div', { class: 'side-top' },
      h('a', { class: 'ws', href: '/', 'aria-label': `${ws} home` }, h('img', { src: '/favicon.svg', alt: '', width: 22, height: 22, class: 'ws-mark' }), wsName),
      canEdit() ? h('a', { class: 'btn btn-primary btn-block new-post', href: '/new', 'aria-keyshortcuts': 'C' }, icon('plus'), h('span', null, 'New post')) : null,
      searchBtn),
    h('nav', { class: 'side-scroll', 'aria-label': 'Main' },
      h('div', { class: 'nav-group' },
        navLink('/', 'Home', 'home'),
        navLink('/drafts', 'Drafts', 'draft'),
        navLink('/notifications', 'Notifications', 'bell', unreadBadge),
        navLink('/activity', 'Activity', 'activity'),
        navLink('/insights', 'Insights', 'chart')),
      h('div', { class: 'nav-group' }, topicsHead, topicsBox),
      h('div', { class: 'nav-group nav-group-quiet' },
        navLink('/templates', 'Templates', 'template'),
        navLink('/archive', 'Archive', 'archive'),
        navLink('/trash', 'Trash', 'trash'))),
    h('div', { class: 'side-bottom' },
      navLink('/settings', 'Settings', 'settings'),
      accountBtn));

  backdrop = h('div', { class: 'backdrop', hidden: true });
  backdrop.addEventListener('click', closeDrawer);

  menuBtn = button('', { icon: 'menu', variant: 'ghost', 'aria-label': 'Open navigation', 'aria-controls': 'sidebar', 'aria-expanded': 'false', onClick: openDrawer });
  const topbarSearch = button('', { icon: 'search', variant: 'ghost', 'aria-label': 'Search', onClick: () => openPalette() });
  const topbar = h('header', { class: 'topbar' },
    menuBtn,
    h('a', { class: 'ws ws-top', href: '/' }, h('img', { src: '/favicon.svg', alt: '', width: 20, height: 20, class: 'ws-mark' }), h('span', { class: 'ws-name' }, ws)),
    topbarSearch,
    canEdit() ? h('a', { class: 'btn btn-ghost btn-icon', href: '/new', 'aria-label': 'New post' }, icon('plus')) : null);

  const main = h('main', { id: 'main', class: 'main', tabindex: '-1' });
  root.replaceChildren(h('div', { class: 'app' }, sidebar, backdrop, h('div', { class: 'main-col' }, topbar, main)));

  renderTopicTree(topicsBox);
  on('topics', () => renderTopicTree(topicsBox));
  on('unread', (n) => {
    unreadBadge.hidden = !n;
    unreadBadge.textContent = n > 99 ? '99+' : String(n);
    unreadBadge.setAttribute('aria-label', `${n} unread`);
  });
  on('settings', (s) => {
    for (const el of root.querySelectorAll('.ws-name')) el.textContent = s.workspace_name;
  });
  on('me', (me2) => {
    accountBtn.querySelector('.account-name').textContent = me2.user.name;
    accountBtn.querySelector('.account-handle').textContent = '@' + me2.user.handle;
    accountBtn.querySelector('.avatar').replaceWith(avatar(me2.user, 'sm'));
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && document.body.classList.contains('drawer-open')) closeDrawer();
  });
  void canAdmin;
  return main;
}

export function updateActiveNav(path) {
  if (!sidebar) return;
  for (const a of sidebar.querySelectorAll('[data-nav]')) {
    const nav = a.dataset.nav;
    const active = nav === '/' ? path === '/' : path === nav || path.startsWith(nav + '/');
    if (active) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  }
}

export function openDrawer() {
  document.body.classList.add('drawer-open');
  backdrop.hidden = false;
  menuBtn.setAttribute('aria-expanded', 'true');
  const first = sidebar.querySelector('a, button');
  if (first) first.focus();
}

export function closeDrawer() {
  if (!document.body.classList.contains('drawer-open')) return;
  document.body.classList.remove('drawer-open');
  backdrop.hidden = true;
  menuBtn.setAttribute('aria-expanded', 'false');
}

export function showShortcuts() {
  const row = (keys, label) => h('div', { class: 'shortcut' }, h('span', null, label), kbd(...keys));
  modal({
    title: 'Keyboard shortcuts',
    size: 'sm',
    content: frag(
      h('div', { class: 'shortcuts' },
        row([modKey, 'K'], 'Search and jump anywhere'),
        row(['/'], 'Search'),
        row(['C'], 'New post'),
        row(['E'], 'Edit the post you’re reading'),
        row([modKey, 'S'], 'Save while editing'),
        row([modKey, 'B'], 'Bold'),
        row([modKey, 'I'], 'Italic'),
        row([modKey, 'Enter'], 'Send a comment'),
        row(['?'], 'Show this list'))),
    actions: [{ label: 'Close', variant: 'primary' }],
  });
}
