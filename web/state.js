// Session-wide state (who is signed in, topics, settings) and app-wide events.

import { api } from '/api.js';

export const state = {
  /** GET /auth/state: needs_setup, user, workspace_name, version, mcp_url, api_url. */
  auth: null,
  /** GET /me: user, scopes, can_edit, can_admin, workspace_name. */
  me: null,
  /** Flat list from list_topics. */
  topics: [],
  /** get_settings. */
  settings: null,
  unread: 0,
};

const bus = new EventTarget();

export function on(name, fn) {
  const handler = (e) => fn(e.detail);
  bus.addEventListener(name, handler);
  return () => bus.removeEventListener(name, handler);
}

export function emit(name, detail) {
  bus.dispatchEvent(new CustomEvent(name, { detail }));
}

let navImpl = (to) => {
  location.href = to;
};

export function setNavigator(fn) {
  navImpl = fn;
}

/** Client-side navigation (falls back to a full page load). */
export function navigate(to, opts) {
  return navImpl(to, opts);
}

export const canEdit = () => !!(state.me && state.me.can_edit);
export const canAdmin = () => !!(state.me && state.me.can_admin);
export const myId = () => (state.me ? state.me.user.id : null);

export async function refreshTopics() {
  const r = await api.get('/topics');
  state.topics = r.items;
  emit('topics', state.topics);
  return state.topics;
}

export async function refreshUnread() {
  try {
    const r = await api.get('/notifications', { unread_only: true, limit: 1 });
    setUnread(r.unread_count);
  } catch {
    /* polling is best-effort */
  }
}

export function setUnread(n) {
  state.unread = n;
  emit('unread', n);
}

export function topicById(id) {
  return state.topics.find((t) => t.id === id);
}

/** Builds the topic tree from the flat list: [{ topic, children: [...] }]. */
export function topicTree(topics = state.topics) {
  const nodes = new Map(topics.map((t) => [t.id, { topic: t, children: [] }]));
  const roots = [];
  for (const n of nodes.values()) {
    const parent = n.topic.parent_id && nodes.get(n.topic.parent_id);
    (parent ? parent.children : roots).push(n);
  }
  const sort = (list) => {
    list.sort((a, b) => a.topic.position - b.topic.position || a.topic.name.localeCompare(b.topic.name));
    for (const n of list) sort(n.children);
    return list;
  };
  return sort(roots);
}

/** Topics in tree order with depth, for pickers and selects. */
export function flatTopicTree(exclude) {
  const out = [];
  const walk = (list, depth) => {
    for (const n of list) {
      if (exclude && exclude(n.topic)) continue;
      out.push({ topic: n.topic, depth });
      walk(n.children, depth + 1);
    }
  };
  walk(topicTree(), 0);
  return out;
}

/** Ids of a topic and all its descendants. */
export function descendantIds(id) {
  const ids = new Set([id]);
  let grew = true;
  while (grew) {
    grew = false;
    for (const t of state.topics) {
      if (t.parent_id && ids.has(t.parent_id) && !ids.has(t.id)) {
        ids.add(t.id);
        grew = true;
      }
    }
  }
  return ids;
}

/** A same-origin path that is safe to send the browser to after signing in. */
export function safeNext(next) {
  if (!next || typeof next !== 'string') return null;
  if (!next.startsWith('/') || next.startsWith('//') || next.startsWith('/\\')) return null;
  try {
    const u = new URL(next, location.origin);
    if (u.origin !== location.origin) return null;
    return u.pathname + u.search + u.hash;
  } catch {
    return null;
  }
}
