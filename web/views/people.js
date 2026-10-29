// A person's profile page.

import { api, enc } from '/api.js';
import { h, avatar, badge, timeEl, emptyState, icon } from '/ui.js';
import { myId } from '/state.js';
import { postRow, section } from '/views/common.js';

const ROLE_LABEL = { admin: 'Admin', member: 'Member', viewer: 'Viewer' };

export async function renderProfile(ctx) {
  const profile = await api.get(`/users/${enc(ctx.params.handle)}`);
  if (!ctx.isCurrent()) return;
  const u = profile.user;
  ctx.setTitle(u.name);
  const isMe = u.id === myId();
  const posts = profile.recent_posts.items;

  ctx.main.replaceChildren(h('div', { class: 'page page-medium' },
    h('header', { class: 'profile-head' },
      avatar(u, 'xl'),
      h('div', { class: 'profile-text' },
        h('h1', { class: 'page-title' }, u.name),
        h('p', { class: 'profile-handle' },
          h('span', null, '@' + u.handle),
          badge(ROLE_LABEL[u.role] || u.role, 'role'),
          u.is_bot ? badge('Bot', 'bot', { iconName: 'bot', title: 'Agent or integration account' }) : null,
          u.deactivated ? badge('Deactivated', 'trash') : null),
        u.bio ? h('p', { class: 'profile-bio' }, u.bio) : null,
        h('p', { class: 'muted small' },
          'Joined ', timeEl(u.created_at),
          u.last_seen_at ? h('span', null, '. Last seen ', timeEl(u.last_seen_at)) : null)),
      isMe ? h('a', { class: 'btn btn-subtle btn-sm', href: '/settings/profile' }, icon('pencil'), h('span', null, 'Edit profile')) : null),
    section(`Recent posts by ${u.name.split(' ')[0]}`, posts.length
      ? h('ul', { class: 'post-list' }, posts.map((p) => postRow(p)))
      : emptyState({ iconName: 'file', title: 'No published posts yet' }))));
}
