// Activity feed: who did what, and through which channel (web, API, MCP, CLI).

import { api } from '/api.js';
import { h, icon, avatar, badge, timeEl, button, busy, toastError, emptyState, pageHeader, select } from '/ui.js';
import { navigate } from '/state.js';

const FILTERS = [
  { value: '', label: 'All activity' },
  { value: 'post.', label: 'Posts' },
  { value: 'comment.', label: 'Comments' },
  { value: 'topic.', label: 'Topics' },
  { value: 'reaction.', label: 'Reactions' },
  { value: 'file.', label: 'Files' },
  { value: 'user.', label: 'People' },
  { value: 'token.', label: 'Tokens' },
  { value: 'webhook.', label: 'Webhooks' },
];

const EVENT_ICON = {
  post: 'file',
  comment: 'comment',
  topic: 'folder',
  reaction: 'smilePlus',
  file: 'paperclip',
  user: 'user',
  token: 'key',
  webhook: 'zap',
  settings: 'settings',
  import: 'download',
};

const VIA_LABEL = { web: 'Web', api: 'API', mcp: 'MCP', cli: 'CLI', slack: 'Slack' };
const VIA_TITLE = {
  web: 'Done in the web app',
  api: 'Done through the REST API',
  mcp: 'Done by an agent through MCP',
  cli: 'Done from the command line',
  slack: 'Done from Slack with /dumbslab',
};

export function viaBadge(via) {
  return badge(VIA_LABEL[via] || via, `via-${via}`, { title: VIA_TITLE[via] });
}

function targetHref(a) {
  if (a.post_id && !a.event.startsWith('post.purged')) {
    return `/p/${a.post_id}` + (a.target_type === 'comment' && !a.event.endsWith('deleted') ? `#comment-${a.target_id}` : '');
  }
  if (a.topic_id && a.event !== 'topic.deleted') return `/t/${a.topic_id}`;
  if (a.target_type === 'user') return null;
  return null;
}

export function activityRow(a) {
  const kind = a.event.split('.')[0];
  const href = targetHref(a);
  const actor = a.actor;
  const summary = href ? h('a', { href, class: 'activity-summary' }, a.summary) : h('span', { class: 'activity-summary' }, a.summary);
  return h('li', { class: ['activity', actor && actor.is_bot && 'is-bot'] },
    actor ? avatar(actor, 'sm') : h('span', { class: 'avatar avatar-sm avatar-icon' }, icon('settings', { size: 14 })),
    h('div', { class: 'activity-main' },
      h('p', { class: 'activity-text' },
        actor ? h('a', { class: 'activity-actor', href: `/u/${encodeURIComponent(actor.handle)}` }, actor.name) : h('span', { class: 'activity-actor' }, 'System'),
        ' ',
        summary),
      h('div', { class: 'activity-meta' },
        h('span', { class: 'activity-kind', title: a.event }, icon(EVENT_ICON[kind] || 'activity', { size: 12 }), a.event),
        actor && actor.is_bot ? badge('Bot', 'bot', { iconName: 'bot', title: 'An agent or integration account' }) : null,
        viaBadge(a.via),
        timeEl(a.created_at))));
}

export async function render(ctx) {
  ctx.setTitle('Activity');
  const event = ctx.query.get('event') || '';
  const mine = ctx.query.get('actor') === 'me';
  const query = { event: event || undefined, actor: mine ? 'me' : undefined, limit: 40 };
  const first = await api.get('/activity', query);
  if (!ctx.isCurrent()) return;

  let cursor = first.next_cursor;
  const list = h('ol', { class: 'activity-list' }, first.items.map(activityRow));
  const more = h('div', { class: 'load-more' });
  const drawMore = () => {
    more.replaceChildren();
    if (!cursor) return;
    const b = button('Load more', { variant: 'ghost' });
    b.addEventListener('click', () => busy(b, async () => {
      const r = await api.get('/activity', { ...query, cursor });
      for (const a of r.items) list.appendChild(activityRow(a));
      cursor = r.next_cursor;
      drawMore();
    }).catch(toastError));
    more.appendChild(b);
  };
  drawMore();

  const filter = select(FILTERS.map((f) => ({ ...f, selected: f.value === event })), { 'aria-label': 'Filter by kind', class: 'input select input-sm' });
  const whoSel = select([{ value: '', label: 'Everyone', selected: !mine }, { value: 'me', label: 'Only me', selected: mine }], { 'aria-label': 'Filter by person', class: 'input select input-sm' });
  const apply = () => {
    const p = new URLSearchParams();
    if (filter.value) p.set('event', filter.value);
    if (whoSel.value) p.set('actor', whoSel.value);
    navigate(`/activity${p.toString() ? `?${p}` : ''}`);
  };
  filter.addEventListener('change', apply);
  whoSel.addEventListener('change', apply);

  ctx.main.replaceChildren(h('div', { class: 'page page-medium' },
    pageHeader('Activity', {
      description: 'Everything that happens in the workspace. Badges show whether a change came from the web app, the API, an agent over MCP, or the CLI.',
      actions: h('div', { class: 'row gap-xs' }, filter, whoSel),
    }),
    first.items.length ? h('div', null, list, more) : emptyState({ iconName: 'activity', title: 'No activity matches', body: 'Try a different filter.' })));
}
