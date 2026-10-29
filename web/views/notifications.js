// Notifications: mentions, comments, replies, updates to followed posts and new posts in followed topics.

import { api } from '/api.js';
import { h, icon, avatar, timeEl, button, busy, toast, toastError, emptyState, pageHeader, urlPath } from '/ui.js';
import { navigate, setUnread } from '/state.js';

const KIND = {
  mention: ['Mention', 'user'],
  comment: ['Comment', 'comment'],
  reply: ['Reply', 'reply'],
  post_updated: ['Update', 'pencil'],
  new_post: ['New post', 'file'],
};

export async function render(ctx) {
  const unreadOnly = ctx.query.get('filter') === 'unread';
  ctx.setTitle('Notifications');
  const first = await api.get('/notifications', { unread_only: unreadOnly || undefined, limit: 30 });
  if (!ctx.isCurrent()) return;
  setUnread(first.unread_count);

  let items = first.items;
  let cursor = first.next_cursor;
  const list = h('ul', { class: 'notif-list' });
  const more = h('div', { class: 'load-more' });

  async function markRead(ids) {
    const r = await api.post('/notifications/read', { ids });
    for (const n of items) if (ids.includes(n.id)) n.read = true;
    setUnread(Math.max(0, (await api.get('/notifications', { unread_only: true, limit: 1 })).unread_count));
    return r;
  }

  function target(n) {
    if (n.post) return urlPath(n.post.url) + (n.comment_id ? `#comment-${n.comment_id}` : '');
    if (n.topic_id) return `/t/${n.topic_id}`;
    return null;
  }

  function row(n) {
    const [label, iconName] = KIND[n.kind] || ['Notification', 'bell'];
    const href = target(n);
    const open = async (e) => {
      if (e && (e.metaKey || e.ctrlKey || e.shiftKey)) return;
      if (e) e.preventDefault();
      if (!n.read) await markRead([n.id]).catch(() => {});
      if (href) navigate(href);
    };
    const markBtn = !n.read ? button('', { icon: 'check', variant: 'ghost', size: 'xs', 'aria-label': 'Mark as read', title: 'Mark as read' }) : null;
    if (markBtn) {
      markBtn.addEventListener('click', () => busy(markBtn, async () => {
        await markRead([n.id]);
        draw();
      }).catch(toastError));
    }
    return h('li', { class: ['notif', !n.read && 'is-unread'] },
      h('span', { class: 'notif-dot', 'aria-hidden': 'true' }),
      n.actor ? avatar(n.actor, 'sm') : h('span', { class: 'avatar avatar-sm avatar-icon' }, icon(iconName, { size: 14 })),
      h('div', { class: 'notif-main' },
        href
          ? h('a', { class: 'notif-msg', href, on: { click: open } }, n.message)
          : h('span', { class: 'notif-msg' }, n.message),
        h('div', { class: 'notif-meta' },
          h('span', { class: 'notif-kind' }, icon(iconName, { size: 12 }), label),
          timeEl(n.created_at),
          !n.read ? h('span', { class: 'sr-only' }, 'Unread') : null)),
      markBtn);
  }

  function draw() {
    list.replaceChildren(...items.map(row));
    more.replaceChildren();
    if (cursor) {
      const b = button('Load more', { variant: 'ghost' });
      b.addEventListener('click', () => busy(b, async () => {
        const r = await api.get('/notifications', { unread_only: unreadOnly || undefined, limit: 30, cursor });
        items = items.concat(r.items);
        cursor = r.next_cursor;
        draw();
      }).catch(toastError));
      more.appendChild(b);
    }
  }

  const markAll = button('Mark all as read', { icon: 'check', variant: 'subtle', size: 'sm' });
  markAll.addEventListener('click', () => busy(markAll, async () => {
    const r = await api.post('/notifications/read', { all: true });
    for (const n of items) n.read = true;
    setUnread(0);
    toast(r.updated ? `Marked ${r.updated} as read` : 'Everything was already read');
    if (unreadOnly) items = [];
    draw();
  }).catch(toastError));

  const tabs = h('div', { class: 'segmented', role: 'tablist', 'aria-label': 'Filter' },
    h('a', { class: 'seg', role: 'tab', href: '/notifications', 'aria-selected': String(!unreadOnly) }, 'All'),
    h('a', { class: 'seg', role: 'tab', href: '/notifications?filter=unread', 'aria-selected': String(unreadOnly) }, `Unread${first.unread_count ? ` (${first.unread_count})` : ''}`));

  draw();
  ctx.main.replaceChildren(h('div', { class: 'page page-medium' },
    pageHeader('Notifications', { description: 'Mentions, comments, replies, and updates to posts and topics you follow.', actions: markAll }),
    tabs,
    items.length ? h('div', null, list, more) : emptyState({ iconName: 'bell', title: unreadOnly ? 'You’re all caught up' : 'No notifications yet', body: 'Follow posts and topics to hear about changes. Comments and mentions show up here too.' })));
}
