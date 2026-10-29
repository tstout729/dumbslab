// Topics: one topic's page, the list of all topics, and the create/edit form.

import { api, enc } from '/api.js';
import {
  h, icon, button, busy, badge, toast, toastError, modal, confirmDialog, field, input, textarea, select,
  avatar, userLink, menuButton, emptyState, topicIcon, pageHeader, openPopover, plural, frag,
} from '/ui.js';
import { state, navigate, refreshTopics, canEdit, flatTopicTree, descendantIds, topicTree } from '/state.js';
import { pagedPosts } from '/views/common.js';

const ICONS = ['📘', '📗', '📕', '📙', '🧭', '🛠️', '🚀', '💡', '🧪', '📣', '🔒', '🧑‍💻', '🎨', '📊', '🤝', '🏢'];
const COLORS = ['#4f46e5', '#0e7490', '#15803d', '#b45309', '#be123c', '#7c3aed', '#475569', '#0369a1'];

/**
 * Opens the create/edit topic dialog. With `topic` it edits; otherwise it creates
 * (optionally under `parentId`). `onSaved(topic)` runs after success.
 */
export function openTopicForm({ topic, parentId, name = '', onSaved } = {}) {
  const editing = !!topic;
  const nameIn = input({ required: true, maxlength: '120', value: topic ? topic.name : name, placeholder: 'For example, Engineering' });
  const descIn = textarea({ rows: 2, value: topic ? topic.description : '', placeholder: 'What belongs here?' });
  const iconIn = input({ value: topic ? topic.icon : '', maxlength: '16', class: 'input input-icon', 'aria-label': 'Icon emoji', placeholder: '📘' });
  const colorIn = h('input', { type: 'color', class: 'color-input', value: (topic && /^#[0-9a-f]{6}$/i.test(topic.color) && topic.color) || '#4f46e5', 'aria-label': 'Custom color' });
  let color = topic ? topic.color : '';

  const iconPicks = h('div', { class: 'swatches', role: 'group', 'aria-label': 'Suggested icons' },
    ICONS.map((e) => {
      const b = h('button', { type: 'button', class: 'emoji-btn', 'aria-label': `Use ${e}` }, e);
      b.addEventListener('click', () => { iconIn.value = e; });
      return b;
    }),
    h('button', { type: 'button', class: 'emoji-btn emoji-none', 'aria-label': 'No icon', title: 'No icon', onClick: () => { iconIn.value = ''; } }, icon('x', { size: 14 })));

  const colorRow = h('div', { class: 'swatches', role: 'radiogroup', 'aria-label': 'Color' });
  const drawColors = () => {
    colorRow.replaceChildren(
      ...COLORS.map((c) => {
        const b = h('button', { type: 'button', class: 'swatch', role: 'radio', 'aria-checked': String(color.toLowerCase() === c), 'aria-label': c, style: { '--c': c } });
        b.addEventListener('click', () => { color = c; colorIn.value = c; drawColors(); });
        return b;
      }),
      h('label', { class: 'swatch swatch-custom', title: 'Custom color' }, colorIn),
      h('button', { type: 'button', class: ['swatch', 'swatch-none'], role: 'radio', 'aria-checked': String(!color), 'aria-label': 'No color', onClick: () => { color = ''; drawColors(); } }, icon('x', { size: 12 })));
  };
  colorIn.addEventListener('input', () => { color = colorIn.value; drawColors(); });
  drawColors();

  const exclude = editing ? descendantIds(topic.id) : new Set();
  const parentSel = select([
    { value: '', label: 'None (top level)' },
    ...flatTopicTree((t) => exclude.has(t.id)).map(({ topic: t, depth }) => ({
      value: t.id,
      label: `${' '.repeat(depth)}${t.icon ? t.icon + ' ' : ''}${t.name}`,
      selected: editing ? topic.parent_id === t.id : parentId === t.id,
    })),
  ]);
  const visSel = select([
    { value: 'org', label: 'Everyone in the workspace', selected: !topic || topic.visibility === 'org' },
    { value: 'private', label: 'Only members (private)', selected: topic && topic.visibility === 'private' },
  ]);

  const content = frag(
    field('Name', nameIn),
    field('Description', descIn),
    h('div', { class: 'field' }, h('label', { class: 'field-label', for: (iconIn.id = `topic-icon-${Date.now()}`) }, 'Icon'), h('div', { class: 'row gap-sm wrap' }, iconIn, iconPicks)),
    h('div', { class: 'field' }, h('span', { class: 'field-label' }, 'Color'), colorRow, h('p', { class: 'field-hint' }, 'Shown as a dot when the topic has no icon.')),
    h('div', { class: 'grid-2' }, field('Parent topic', parentSel), field('Who can see it', visSel, { hint: 'Posts only in private topics are visible to members.' })));

  modal({
    title: editing ? 'Edit topic' : 'Create topic',
    content,
    actions: [
      { label: 'Cancel', variant: 'ghost' },
      {
        label: editing ? 'Save' : 'Create topic',
        variant: 'primary',
        onClick: async () => {
          const body = {
            name: nameIn.value.trim(),
            description: descIn.value.trim(),
            icon: iconIn.value.trim(),
            color,
            parent_id: parentSel.value,
            visibility: visSel.value,
          };
          if (!body.name) {
            nameIn.focus();
            toast('Give the topic a name.', { type: 'error' });
            return false;
          }
          let saved;
          if (editing) {
            saved = await api.patch(`/topics/${enc(topic.id)}`, body);
          } else {
            if (!body.parent_id) delete body.parent_id;
            saved = await api.post('/topics', body);
          }
          await refreshTopics();
          toast(editing ? 'Topic saved' : 'Topic created');
          if (onSaved) onSaved(saved);
          else if (!editing) navigate(`/t/${saved.id}/${saved.slug}`);
          return true;
        },
      },
    ],
  });
}

function memberPicker(anchor, topic, onAdded) {
  const q = input({ placeholder: 'Name, @handle or email', 'aria-label': 'Find a person', class: 'input input-sm' });
  const list = h('div', { class: 'picker-list' });
  let seq = 0;
  const search = async () => {
    const mySeq = ++seq;
    let r;
    try {
      r = await api.get('/users', { q: q.value.trim() || undefined, limit: 20 });
    } catch (e) {
      list.replaceChildren(h('p', { class: 'picker-empty' }, e.message));
      return;
    }
    if (mySeq !== seq) return;
    const memberIds = new Set(topic.members.map((m) => m.id));
    const people = r.items.filter((u) => !memberIds.has(u.id));
    list.replaceChildren(...people.map((u) => {
      const b = h('button', { type: 'button', class: 'picker-item' }, avatar(u, 'xs'), h('span', { class: 'picker-name' }, u.name), h('span', { class: 'muted small' }, '@' + u.handle));
      b.addEventListener('click', () => busy(b, async () => {
        const updated = await api.post(`/topics/${enc(topic.id)}/members`, { user: u.id });
        layer.close();
        toast(`Added ${u.name}`);
        onAdded(updated);
      }).catch(toastError));
      return b;
    }));
    if (!people.length) list.appendChild(h('p', { class: 'picker-empty' }, 'No one else matches.'));
  };
  let t;
  q.addEventListener('input', () => { clearTimeout(t); t = setTimeout(search, 150); });
  const layer = openPopover(anchor, h('div', { class: 'picker' }, q, list), { label: 'Add a member', cls: 'popover-picker' });
  q.focus();
  search();
}

export async function render(ctx) {
  const id = ctx.params.id;
  let topic = await api.get(`/topics/${enc(id)}`);
  if (!ctx.isCurrent()) return;
  const canonical = `/t/${topic.id}/${topic.slug}`;
  if (location.pathname !== canonical && ctx.replaceUrl) ctx.replaceUrl(canonical + location.search);
  ctx.setTitle(topic.name);

  const headBox = h('div');
  const membersBox = h('div');
  const childrenBox = h('div');

  function followBtn() {
    const b = button(topic.following ? 'Following' : 'Follow', { icon: topic.following ? 'check' : 'bell', variant: 'ghost', size: 'sm', 'aria-pressed': String(topic.following), title: topic.following ? 'You’re notified about new posts here. Click to unfollow.' : 'Get notified about new posts in this topic' });
    b.addEventListener('click', () => busy(b, async () => {
      if (topic.following) await api.del(`/follows/topic/${enc(topic.id)}`);
      else await api.post('/follows', { target_type: 'topic', target_id: topic.id });
      topic.following = !topic.following;
      toast(topic.following ? `Following ${topic.name}` : `Unfollowed ${topic.name}`);
      drawHead();
    }).catch(toastError));
    return b;
  }

  function manageItems() {
    return [
      { label: 'Edit topic', icon: 'pencil', onClick: () => openTopicForm({ topic, onSaved: () => ctx.reload() }) },
      { label: 'Add a subtopic', icon: 'plus', onClick: () => openTopicForm({ parentId: topic.id }) },
      'separator',
      {
        label: 'Delete topic',
        icon: 'trash',
        danger: true,
        onClick: async () => {
          const ok = await confirmDialog({
            title: `Delete “${topic.name}”?`,
            message: 'Posts are kept; they just lose this topic. Subtopics move up a level. Only the topic’s creator or an admin can do this.',
            confirmLabel: 'Delete topic',
            danger: true,
          });
          if (!ok) return;
          await api.del(`/topics/${enc(topic.id)}`);
          await refreshTopics();
          toast('Topic deleted');
          navigate(topic.parent_id ? `/t/${topic.parent_id}` : '/topics');
        },
      },
    ];
  }

  function drawHead() {
    const crumbs = topic.breadcrumbs.length
      ? h('nav', { class: 'crumbs', 'aria-label': 'Breadcrumbs' },
        h('a', { href: '/topics' }, 'Topics'),
        ...topic.breadcrumbs.flatMap((b) => [h('span', { class: 'crumb-sep', 'aria-hidden': 'true' }, '/'), h('a', { href: `/t/${b.id}` }, b.name)]))
      : h('nav', { class: 'crumbs', 'aria-label': 'Breadcrumbs' }, h('a', { href: '/topics' }, 'Topics'));
    headBox.replaceChildren(h('header', { class: 'topic-head', style: topic.color ? { '--c': topic.color } : undefined },
      crumbs,
      h('div', { class: 'topic-title-row' },
        h('div', { class: 'topic-title-wrap' },
          topicIcon(topic, 'lg'),
          h('h1', { class: 'page-title' }, topic.name),
          topic.visibility === 'private' ? badge('Private', 'private', { iconName: 'lock', title: 'Only members can see this topic' }) : null),
        h('div', { class: 'page-actions' },
          canEdit() ? h('a', { class: 'btn btn-primary btn-sm', href: `/new?topic=${encodeURIComponent(topic.id)}` }, icon('plus'), h('span', null, 'New post here')) : null,
          followBtn(),
          topic.can_manage ? menuButton(manageItems, { size: 'sm', ariaLabel: 'Topic actions' }) : null)),
      topic.description ? h('p', { class: 'page-desc' }, topic.description) : null,
      h('p', { class: 'muted small' }, plural(topic.post_count, 'published post'), topic.children.length ? `, ${plural(topic.children.length, 'subtopic')}` : '')));
  }

  function drawMembers() {
    if (topic.visibility !== 'private') {
      membersBox.replaceChildren();
      return;
    }
    const addBtn = topic.can_manage ? button('Add member', { icon: 'plus', variant: 'ghost', size: 'sm' }) : null;
    if (addBtn) addBtn.addEventListener('click', () => memberPicker(addBtn, topic, (updated) => { topic = updated; drawMembers(); }));
    membersBox.replaceChildren(h('section', { class: 'section members' },
      h('div', { class: 'section-head' }, h('h2', { class: 'section-title' }, `Members (${topic.members.length})`), addBtn),
      h('ul', { class: 'member-list' }, topic.members.map((m) => {
        const rm = topic.can_manage ? button('', { icon: 'x', variant: 'ghost', size: 'xs', 'aria-label': `Remove ${m.name}`, title: `Remove ${m.name}` }) : null;
        if (rm) {
          rm.addEventListener('click', async () => {
            const ok = await confirmDialog({ title: `Remove ${m.name}?`, message: `${m.name} won’t see this topic or posts that are only in it.`, confirmLabel: 'Remove', danger: true });
            if (!ok) return;
            busy(rm, async () => {
              await api.del(`/topics/${enc(topic.id)}/members/${enc(m.id)}`);
              topic.members = topic.members.filter((x) => x.id !== m.id);
              toast(`Removed ${m.name}`);
              drawMembers();
            }).catch(toastError);
          });
        }
        return h('li', { class: 'member' }, userLink(m, { size: 'sm' }), rm);
      }))));
  }

  function drawChildren() {
    if (!topic.children.length) {
      childrenBox.replaceChildren();
      return;
    }
    childrenBox.replaceChildren(h('section', { class: 'section' },
      h('div', { class: 'section-head' }, h('h2', { class: 'section-title' }, 'Subtopics')),
      h('ul', { class: 'subtopics' }, topic.children.map((c) => h('li', null,
        h('a', { class: 'subtopic', href: `/t/${c.id}/${c.slug}` },
          topicIcon(c, 'sm'),
          h('span', { class: 'subtopic-name' }, c.name),
          c.visibility === 'private' ? icon('lock', { size: 12, label: 'Private' }) : null,
          h('span', { class: 'muted small' }, String(c.post_count))))))));
  }

  const pinned = new Set(topic.pinned_post_ids);
  const posts = pagedPosts({
    query: { topic_id: topic.id },
    empty: emptyState({
      iconName: 'file',
      title: 'No posts in this topic yet',
      body: 'Write the first one, or add this topic to an existing post from its editor.',
      action: canEdit() ? h('a', { class: 'btn btn-primary', href: `/new?topic=${encodeURIComponent(topic.id)}` }, 'New post here') : null,
    }),
    rowOpts: (p) => ({
      pinned: pinned.has(p.id),
      actions: topic.can_manage && p.topics.some((t) => t.id === topic.id)
        ? menuButton(() => [{
          label: pinned.has(p.id) ? 'Unpin' : 'Pin to the top',
          icon: 'pin',
          onClick: async () => {
            const wasPinned = pinned.has(p.id);
            const updated = await api.post(`/topics/${enc(topic.id)}/pins`, { post_id: p.id, pinned: !wasPinned });
            pinned.clear();
            for (const pid of updated.pinned_post_ids) pinned.add(pid);
            toast(wasPinned ? 'Unpinned' : 'Pinned to the top');
            posts.reload().catch(toastError);
          },
        }], { size: 'xs', ariaLabel: `Actions for ${p.title}` })
        : null,
    }),
  });
  await posts.ready;
  if (!ctx.isCurrent()) return;

  drawHead();
  drawMembers();
  drawChildren();
  ctx.main.replaceChildren(h('div', { class: 'page page-medium' },
    headBox,
    membersBox,
    childrenBox,
    h('section', { class: 'section' }, h('div', { class: 'section-head' }, h('h2', { class: 'section-title' }, 'Posts')), posts.el)));
}

export async function renderAll(ctx) {
  ctx.setTitle('Topics');
  const topics = await refreshTopics();
  if (!ctx.isCurrent()) return;

  const build = (nodes, depth) => h('ul', { class: depth ? 'topic-tree-sub' : 'topic-tree' }, nodes.map((n) => {
    const t = n.topic;
    return h('li', null,
      h('a', { class: 'topic-card', href: `/t/${t.id}/${t.slug}` },
        topicIcon(t, 'md'),
        h('span', { class: 'topic-card-text' },
          h('span', { class: 'topic-card-name' }, t.name, t.visibility === 'private' ? icon('lock', { size: 12, label: 'Private' }) : null),
          t.description ? h('span', { class: 'topic-card-desc' }, t.description) : null),
        h('span', { class: 'topic-card-count', title: plural(t.post_count, 'published post') }, String(t.post_count))),
      n.children.length ? build(n.children, depth + 1) : null);
  }));

  const create = canEdit() ? button('Create topic', { icon: 'plus', variant: 'primary', size: 'sm', onClick: () => openTopicForm({}) }) : null;
  ctx.main.replaceChildren(h('div', { class: 'page page-medium' },
    pageHeader('Topics', { description: 'Topics organize posts. A post can be in several topics, and topics can nest.', actions: create }),
    topics.length
      ? build(topicTree(topics), 0)
      : emptyState({ iconName: 'folder', title: 'No topics yet', body: 'Create topics for teams, projects or areas of the business.', action: create ? button('Create topic', { icon: 'plus', variant: 'primary', onClick: () => openTopicForm({}) }) : null })));
  void state;
}
