// Bootstrap and client-side router.

import { api, ApiError } from '/api.js';
import { h, loadingView, emptyState, button, closeLayers, isTyping, toastError } from '/ui.js';
import { state, on, setNavigator, safeNext, refreshUnread, canEdit } from '/state.js';
import { buildShell, updateActiveNav, closeDrawer, showShortcuts } from '/views/shell.js';
import * as auth from '/views/auth.js';
import * as home from '/views/home.js';
import * as search from '/views/search.js';
import * as post from '/views/post.js';
import * as editor from '/views/editor.js';
import * as historyView from '/views/history.js';
import * as topic from '/views/topic.js';
import * as lists from '/views/lists.js';
import * as people from '/views/people.js';
import * as notifications from '/views/notifications.js';
import * as activity from '/views/activity.js';
import * as insights from '/views/insights.js';
import * as settings from '/views/settings.js';

const ROUTES = [
  ['/', home.render],
  ['/search', search.renderPage],
  ['/new', editor.renderNew],
  ['/p/:id/edit', editor.renderEdit],
  ['/p/:id/history', historyView.render],
  ['/p/:id/:slug/edit', editor.renderEdit],
  ['/p/:id/:slug/history', historyView.render],
  ['/p/:id', post.render],
  ['/p/:id/:slug', post.render],
  ['/t/:id', topic.render],
  ['/t/:id/:slug', topic.render],
  ['/topics', topic.renderAll],
  ['/drafts', lists.drafts],
  ['/templates', lists.templates],
  ['/archive', lists.archive],
  ['/trash', lists.trash],
  ['/u/:handle', people.renderProfile],
  ['/notifications', notifications.render],
  ['/activity', activity.render],
  ['/insights', insights.render],
  ['/settings', settings.render],
  ['/settings/:section', settings.render],
].map(([pattern, view]) => {
  const keys = [];
  const re = new RegExp('^' + pattern.replace(/:(\w+)/g, (_, k) => { keys.push(k); return '([^/]+)'; }) + '/?$');
  return { re, keys, view };
});

/** Paths the server handles itself; links to them do a full page load. */
const SERVER_PATH = /^\/(api\/|oauth\/|mcp($|\/)|llms\.txt$|healthz$|\.well-known\/)/;

let main = null;
let navToken = 0;
let leaveGuard = null;
let cleanups = [];
let pageKeys = new Map();
let currentKey = '';
let currentUrl = '';
// Requests cut off by a full page load shouldn't flash an error screen.
let unloading = false;
window.addEventListener('pagehide', () => { unloading = true; });
window.addEventListener('pageshow', () => { unloading = false; });

function matchRoute(path) {
  for (const r of ROUTES) {
    const m = r.re.exec(path);
    if (m) {
      const params = {};
      r.keys.forEach((k, i) => { params[k] = decodeURIComponent(m[i + 1]); });
      return { view: r.view, params };
    }
  }
  return null;
}

function scrollToHash() {
  const id = decodeURIComponent(location.hash.slice(1));
  if (!id) return;
  const el = document.getElementById(id);
  if (el) {
    el.scrollIntoView({ block: 'start' });
    if (id === 'main') el.focus({ preventScroll: true });
    if (el.classList.contains('comment')) {
      el.classList.remove('flash');
      void el.offsetWidth;
      el.classList.add('flash');
    }
  }
}

async function navigate(to, { replace = false } = {}) {
  const url = new URL(to, location.href);
  if (url.origin !== location.origin || SERVER_PATH.test(url.pathname)) {
    location.href = url.href;
    return;
  }
  const key = url.pathname + url.search;
  const full = key + url.hash;
  if (key === currentKey) {
    if (full !== location.pathname + location.search + location.hash) {
      history[replace ? 'replaceState' : 'pushState'](null, '', full);
      currentUrl = full;
    }
    scrollToHash();
    return;
  }
  if (leaveGuard && !(await leaveGuard())) return;
  leaveGuard = null;
  history[replace ? 'replaceState' : 'pushState'](null, '', full);
  await render();
}

window.addEventListener('popstate', async () => {
  const key = location.pathname + location.search;
  if (key === currentKey) {
    currentUrl = key + location.hash;
    scrollToHash();
    return;
  }
  if (leaveGuard && !(await leaveGuard())) {
    history.pushState(null, '', currentUrl);
    return;
  }
  leaveGuard = null;
  render();
});

function runCleanups() {
  const list = cleanups;
  cleanups = [];
  for (const fn of list) {
    try {
      fn();
    } catch (e) {
      console.error(e);
    }
  }
}

function setTitle(title) {
  const ws = (state.settings && state.settings.workspace_name) || (state.auth && state.auth.workspace_name) || 'DumbSlab';
  const unread = state.unread > 0 ? `(${state.unread}) ` : '';
  document.title = unread + (title ? `${title} - ${ws}` : ws);
  document.body.dataset.title = title || '';
}

function notFound() {
  setTitle('Not found');
  main.replaceChildren(h('div', { class: 'page page-narrow' },
    emptyState({
      iconName: 'search',
      title: 'This page doesn’t exist',
      body: 'The link may be wrong, or the post or topic was deleted or is private.',
      action: h('div', { class: 'row gap-sm center' },
        h('a', { class: 'btn btn-primary', href: '/' }, 'Go home'),
        h('a', { class: 'btn btn-ghost', href: '/search' }, 'Search')),
    })));
}

function errorView(err, retry) {
  setTitle('Error');
  main.replaceChildren(h('div', { class: 'page page-narrow' },
    emptyState({
      iconName: 'alert',
      title: err.status === 403 ? 'You don’t have access to this' : 'Something went wrong',
      body: err.message || String(err),
      action: button('Try again', { variant: 'primary', icon: 'refresh', onClick: retry }),
    })));
}

async function render({ keepScroll = false } = {}) {
  const token = ++navToken;
  runCleanups();
  leaveGuard = null;
  pageKeys = new Map();
  closeLayers();
  closeDrawer();
  const path = location.pathname;
  currentKey = path + location.search;
  currentUrl = currentKey + location.hash;
  updateActiveNav(path);
  const match = matchRoute(path);
  const ctx = {
    params: match ? match.params : {},
    query: new URLSearchParams(location.search),
    main,
    isCurrent: () => token === navToken,
    setTitle: (t) => { if (token === navToken) setTitle(t); },
    setLeaveGuard: (fn) => { if (token === navToken) leaveGuard = fn; },
    clearLeaveGuard: () => { if (token === navToken) leaveGuard = null; },
    onCleanup: (fn) => { if (token === navToken) cleanups.push(fn); else fn(); },
    onKey: (key, fn) => { if (token === navToken) pageKeys.set(key, fn); },
    reload: () => render({ keepScroll: true }),
    replaceUrl: (url) => {
      if (token !== navToken) return;
      history.replaceState(null, '', url);
      currentKey = location.pathname + location.search;
      currentUrl = currentKey + location.hash;
    },
    navigate,
  };
  const loadingTimer = keepScroll ? null : setTimeout(() => {
    if (token === navToken) main.replaceChildren(loadingView());
  }, 150);
  try {
    if (!match) notFound();
    else await match.view(ctx);
  } catch (e) {
    if (token !== navToken || unloading) return;
    if (e instanceof ApiError && e.status === 404) notFound();
    else if (e instanceof ApiError && e.status === 401) return;
    else {
      console.error(e);
      errorView(e, () => render());
    }
  } finally {
    clearTimeout(loadingTimer);
  }
  if (token !== navToken) return;
  if (!keepScroll) {
    if (location.hash) requestAnimationFrame(scrollToHash);
    else window.scrollTo(0, 0);
    const active = document.activeElement;
    if (!active || active === document.body || !document.contains(active)) main.focus({ preventScroll: true });
  }
}

function onLinkClick(e) {
  if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
  const a = e.target.closest && e.target.closest('a[href]');
  if (!a) return;
  if ((a.target && a.target !== '_self') || a.hasAttribute('download') || a.dataset.native !== undefined) return;
  const url = new URL(a.getAttribute('href'), location.href);
  if (url.origin !== location.origin || SERVER_PATH.test(url.pathname)) return;
  e.preventDefault();
  navigate(url.pathname + url.search + url.hash);
}

function onKeydown(e) {
  const mod = e.metaKey || e.ctrlKey;
  if (mod && !e.shiftKey && !e.altKey && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    search.togglePalette();
    return;
  }
  if (mod || e.altKey || isTyping(e.target) || document.querySelector('dialog[open]')) return;
  const handler = pageKeys.get(e.key);
  if (handler) {
    e.preventDefault();
    handler(e);
    return;
  }
  if (e.key === 'c' && canEdit()) {
    e.preventDefault();
    navigate('/new');
  } else if (e.key === '/') {
    e.preventDefault();
    search.openPalette();
  } else if (e.key === '?') {
    e.preventDefault();
    showShortcuts();
  }
}

function bootError(root, err) {
  root.replaceChildren(h('div', { class: 'auth-wrap' },
    h('div', { class: 'auth-card' },
      h('img', { src: '/favicon.svg', alt: '', width: 40, height: 40, class: 'auth-mark' }),
      h('h1', { class: 'auth-title' }, 'Can’t reach DumbSlab'),
      h('p', { class: 'auth-sub' }, err.message || String(err)),
      button('Try again', { variant: 'primary', icon: 'refresh', onClick: () => location.reload() }))));
}

async function boot() {
  const root = document.getElementById('root');
  let authState;
  try {
    authState = await api.get('/auth/state', null, { redirectOn401: false });
  } catch (e) {
    bootError(root, e);
    return;
  }
  state.auth = authState;
  const path = location.pathname;
  const query = new URLSearchParams(location.search);

  if (authState.needs_setup) {
    if (path !== '/setup') history.replaceState(null, '', '/setup' + location.search);
    auth.renderSetup(root, authState);
    return;
  }
  if (path === '/setup') {
    location.replace(authState.user ? '/' : '/login');
    return;
  }
  if (!authState.user) {
    if (path === '/login') auth.renderLogin(root, authState);
    else location.replace('/login?next=' + encodeURIComponent(path + location.search + location.hash));
    return;
  }
  if (path === '/login') {
    location.replace(safeNext(query.get('next')) || '/');
    return;
  }

  try {
    const [me, topics, settingsData] = await Promise.all([api.get('/me'), api.get('/topics'), api.get('/settings')]);
    state.me = me;
    state.topics = topics.items;
    state.settings = settingsData;
  } catch (e) {
    if (e.status !== 401) bootError(root, e);
    return;
  }

  main = buildShell(root);
  setNavigator(navigate);
  document.addEventListener('click', onLinkClick);
  document.addEventListener('keydown', onKeydown);
  window.addEventListener('beforeunload', (e) => {
    if (document.body.dataset.dirty === '1') {
      e.preventDefault();
      e.returnValue = '';
    }
  });
  await render();
  refreshUnread();
  // Every 5 minutes while the tab is visible: cheap for hosted workspaces, fresh enough for people.
  setInterval(() => {
    if (document.visibilityState === 'visible') refreshUnread();
  }, 300_000);
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') refreshUnread();
  });
}

window.addEventListener('unhandledrejection', (e) => {
  if (e.reason instanceof ApiError) {
    e.preventDefault();
    if (e.reason.status !== 401) toastError(e.reason);
  }
});

on('unread', () => setTitle(document.body.dataset.title));

boot();
