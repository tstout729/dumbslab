// Insights: counts, most-viewed posts, expired verifications, stale posts, top contributors.

import { api } from '/api.js';
import { h, userLink, pageHeader, select, plural } from '/ui.js';
import { navigate } from '/state.js';
import { postRow, section } from '/views/common.js';

export async function render(ctx) {
  ctx.setTitle('Insights');
  const days = Number(ctx.query.get('stale')) || 180;
  const r = await api.get('/insights', { stale_after_days: days });
  if (!ctx.isCurrent()) return;
  const c = r.counts;

  const stat = (label, value, href) => h(href ? 'a' : 'div', { class: 'stat', href },
    h('span', { class: 'stat-value' }, String(value)),
    h('span', { class: 'stat-label' }, label));

  const staleSel = select([30, 90, 180, 365].map((d) => ({ value: String(d), label: `${d} days`, selected: d === days })), { 'aria-label': 'Stale after', class: 'input select input-sm' });
  staleSel.addEventListener('change', () => navigate(`/insights?stale=${staleSel.value}`));

  const list = (items, empty) => (items.length
    ? h('ul', { class: 'post-list' }, items.map((p) => postRow(p, { excerpt: false })))
    : h('p', { class: 'muted small' }, empty));

  ctx.main.replaceChildren(h('div', { class: 'page page-medium' },
    pageHeader('Insights', { description: 'What’s in the knowledge base and which posts need attention.' }),
    h('div', { class: 'stats' },
      stat('Published', c.published, '/search'),
      stat('Drafts', c.drafts, '/drafts'),
      stat('Archived', c.archived, '/archive'),
      stat('Topics', c.topics, '/topics'),
      stat('People', c.people),
      stat('Comments', c.comments)),
    section('Verification expired', list(r.verification_expired, 'No expired verifications. Every verified post is current.'), {
      action: h('span', { class: 'muted small' }, 'Re-check these and verify them again.'),
    }),
    section('Not updated in a while', list(r.stale, `Every published post was updated in the last ${days} days.`), {
      action: h('label', { class: 'row gap-xs small muted' }, 'Older than', staleSel),
    }),
    h('div', { class: 'grid-2 grid-top' },
      section('Most viewed', list(r.most_viewed, 'No views recorded yet.')),
      section('Top contributors', r.top_contributors.length
        ? h('ol', { class: 'contributors' }, r.top_contributors.map((x) => h('li', { class: 'contributor' },
          userLink(x.user, { size: 'sm' }),
          h('span', { class: 'muted small' }, `${plural(x.edits, 'edit')}, ${plural(x.posts, 'post')}`))))
        : h('p', { class: 'muted small' }, 'No edits yet.')))));
}
