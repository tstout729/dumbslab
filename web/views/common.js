// Pieces several views share: post rows, status and verification badges, paged lists.

import { api } from '/api.js';
import { h, icon, badge, timeEl, topicChip, userLink, urlPath, button, busy, toastError, emptyState, spinner, absTime, relTime, plural } from '/ui.js';

export function statusBadges(p) {
  const out = [];
  if (p.deleted_at) out.push(badge('In trash', 'trash', { iconName: 'trash' }));
  else if (p.status === 'draft') out.push(badge('Draft', 'draft'));
  else if (p.status === 'archived') out.push(badge('Archived', 'archived', { iconName: 'archive' }));
  if (p.is_template) out.push(badge('Template', 'template', { iconName: 'template' }));
  return out;
}

/** Verification as a compact badge. Unverified posts show nothing unless `showUnverified`. */
export function verificationBadge(v, { showUnverified = false } = {}) {
  if (!v) return null;
  if (v.status === 'verified') {
    const who = v.verified_by ? ` by ${v.verified_by.name}` : '';
    const until = v.expires_at ? `, until ${absTime(v.expires_at)}` : ', no expiry';
    return badge('Verified', 'verified', { iconName: 'verified', title: `Verified${who} ${relTime(v.verified_at)}${until}` });
  }
  if (v.status === 'expired') {
    return badge('Needs review', 'expired', { iconName: 'alert', title: `Verification expired ${relTime(v.expires_at)}` });
  }
  return showUnverified ? badge('Unverified', 'unverified', { iconName: 'circleDashed', title: 'Nobody has verified this post' }) : null;
}

export function postHref(p) {
  return urlPath(p.url) || `/p/${p.id}`;
}

/** One post in a list. */
export function postRow(p, { pinned = false, actions, excerpt = true, meta = true } = {}) {
  return h('li', { class: 'post-row' },
    h('div', { class: 'post-row-main' },
      h('div', { class: 'post-row-head' },
        pinned ? h('span', { class: 'pin-mark', title: 'Pinned' }, icon('pin', { size: 14, label: 'Pinned' })) : null,
        h('a', { class: 'post-row-title', href: postHref(p) }, p.title),
        ...statusBadges(p),
        verificationBadge(p.verification)),
      excerpt && p.excerpt ? h('p', { class: 'post-row-excerpt' }, p.excerpt) : null,
      meta ? h('div', { class: 'post-row-meta' },
        p.topics && p.topics.length ? h('span', { class: 'chips' }, p.topics.slice(0, 3).map(topicChip)) : null,
        userLink(p.author),
        h('span', { class: 'meta-item' }, timeEl(p.deleted_at || p.updated_at, { prefix: p.deleted_at ? 'Trashed ' : 'Updated ' })),
        p.comment_count ? h('span', { class: 'meta-item', title: plural(p.comment_count, 'comment') }, icon('comment', { size: 13 }), String(p.comment_count)) : null) : null),
    actions ? h('div', { class: 'post-row-actions' }, actions) : null);
}

/**
 * A list of posts backed by list_posts (or another paged endpoint) with "Load more".
 * Returns { el, reload, ready } where `ready` resolves after the first page.
 */
export function pagedPosts({ path = '/posts', query = {}, empty, rowOpts = () => ({}), limit = 25, onLoaded } = {}) {
  const list = h('ul', { class: 'post-list' });
  const body = h('div', { class: 'paged-body' }, list);
  const more = h('div', { class: 'load-more' });
  const el = h('div', { class: 'paged' }, body, more);
  let cursor = null;
  let total = 0;

  async function load(reset) {
    if (reset) {
      cursor = null;
      total = 0;
    }
    const r = await api.get(path, { ...query, limit, cursor: cursor || undefined });
    if (reset) list.replaceChildren();
    for (const p of r.items) list.appendChild(postRow(p, rowOpts(p)));
    total += r.items.length;
    cursor = r.next_cursor;
    more.replaceChildren();
    body.replaceChildren(!total && empty ? empty : list);
    if (cursor) {
      const b = button('Load more', { variant: 'ghost' });
      b.addEventListener('click', () => busy(b, () => load(false)).catch(toastError));
      more.appendChild(b);
    }
    if (onLoaded) onLoaded(r, total);
    return r;
  }
  const ready = load(true);
  return { el, reload: () => load(true), ready };
}

/** Section with a heading and content, used on dashboards. */
export function section(title, content, { action, cls } = {}) {
  return h('section', { class: ['section', cls] },
    h('div', { class: 'section-head' }, h('h2', { class: 'section-title' }, title), action || null),
    content);
}

export function inlineLoading() {
  return h('div', { class: 'inline-loading' }, spinner());
}

export { emptyState };
