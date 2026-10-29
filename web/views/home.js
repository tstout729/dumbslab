// Home: welcome message, recently updated posts, your recent views, and posts in topics you follow.

import { api, enc } from '/api.js';
import { h, icon, timeEl, emptyState, urlPath, topicIcon } from '/ui.js';
import { state, canEdit } from '/state.js';
import { postRow, section } from '/views/common.js';

function greeting(name) {
  const hour = new Date().getHours();
  const part = hour < 5 ? 'Good evening' : hour < 12 ? 'Good morning' : hour < 18 ? 'Good afternoon' : 'Good evening';
  return `${part}, ${String(name).split(' ')[0]}`;
}

export async function render(ctx) {
  ctx.setTitle('');
  const [recent, viewed, follows, settings] = await Promise.all([
    api.get('/posts', { limit: 10 }),
    api.get('/me/recent', { limit: 8 }),
    api.get('/follows'),
    api.get('/settings'),
  ]);
  state.settings = settings;
  const followedTopics = follows.topics.slice(0, 6);
  const perTopic = await Promise.all(followedTopics.map((t) => api.get('/posts', { topic_id: t.id, limit: 6 }).catch(() => ({ items: [] }))));
  if (!ctx.isCurrent()) return;

  const seen = new Set();
  const followed = perTopic.flatMap((r) => r.items)
    .filter((p) => (seen.has(p.id) ? false : seen.add(p.id)))
    .sort((a, b) => b.updated_at.localeCompare(a.updated_at))
    .slice(0, 8);

  const welcome = settings.welcome_message
    ? h('div', { class: 'welcome' }, h('p', { class: 'welcome-text' }, settings.welcome_message))
    : null;

  const recentList = recent.items.length
    ? h('ul', { class: 'post-list' }, recent.items.map((p) => postRow(p)))
    : emptyState({
      iconName: 'file',
      title: 'Nothing published yet',
      body: 'Write the first post, or import your existing docs through the API.',
      action: canEdit() ? h('a', { class: 'btn btn-primary', href: '/new' }, 'New post') : null,
    });

  const viewedList = viewed.items.length
    ? h('ol', { class: 'compact-list' }, viewed.items.map((p) => h('li', null,
      h('a', { class: 'compact-link', href: urlPath(p.url) }, icon('file', { size: 14 }), h('span', { class: 'compact-title' }, p.title)))))
    : h('p', { class: 'muted small' }, 'Posts you open show up here.');

  const followedBody = followedTopics.length
    ? (followed.length
      ? h('ul', { class: 'post-list' }, followed.map((p) => postRow(p, { excerpt: false })))
      : h('p', { class: 'muted small' }, 'No posts in the topics you follow yet.'))
    : h('p', { class: 'muted small' }, 'Follow a topic to see its newest posts here and get notified when someone publishes one.');

  const followChips = followedTopics.length
    ? h('div', { class: 'chips' }, followedTopics.map((t) => h('a', { class: 'chip', href: urlPath(t.url) }, topicIcon(t, 'xs'), h('span', null, t.name))))
    : null;

  const quick = h('ul', { class: 'compact-list' },
    h('li', null, h('a', { class: 'compact-link', href: '/drafts' }, icon('draft', { size: 14 }), h('span', null, 'Your drafts'))),
    h('li', null, h('a', { class: 'compact-link', href: '/topics' }, icon('folder', { size: 14 }), h('span', null, 'All topics'))),
    h('li', null, h('a', { class: 'compact-link', href: '/insights' }, icon('chart', { size: 14 }), h('span', null, 'Posts that need attention'))),
    h('li', null, h('a', { class: 'compact-link', href: '/settings/agents' }, icon('plug', { size: 14 }), h('span', null, 'Connect AI agents'))));

  ctx.main.replaceChildren(h('div', { class: 'page page-home' },
    h('header', { class: 'home-head' },
      h('h1', { class: 'page-title home-title' }, greeting(state.me.user.name)),
      h('p', { class: 'page-desc' }, `Here’s what changed in ${settings.workspace_name}.`)),
    welcome,
    h('div', { class: 'home-grid' },
      h('div', { class: 'home-main' },
        section('Recently updated', recentList, { action: h('a', { class: 'section-link', href: '/search' }, 'Search everything') }),
        section('From topics you follow', h('div', null, followChips, followedBody))),
      h('aside', { class: 'home-side', 'aria-label': 'Shortcuts' },
        section('Recently viewed', viewedList),
        section('Jump to', quick)))));
  void timeEl;
  void enc;
}
