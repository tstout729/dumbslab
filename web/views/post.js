// Reading a post: header and actions, rendered body, table of contents, reactions,
// backlinks and threaded comments (including inline comments on selected text).

import { api, enc } from '/api.js';
import {
  h, icon, avatar, badge, button, busy, timeEl, topicChip, userLink, urlPath, toast, toastError,
  openMenu, openPopover, closeLayers, confirmDialog, copyText, textarea, plural, menuButton, emptyState,
} from '/ui.js';
import { state, navigate, myId } from '/state.js';
import { statusBadges } from '/views/common.js';

export const QUICK_EMOJI = ['👍', '❤️', '🎉', '😄', '🚀', '👀', '🙏', '✅'];

const isAdminRole = () => state.me && state.me.user.role === 'admin';

/** Emoji reactions with a quick picker. `onChange` receives the new groups. */
export function reactionBar(targetType, targetId, groups, onChange, { compact = false } = {}) {
  const bar = h('div', { class: ['reactions', compact && 'reactions-compact'] });
  let current = groups || [];

  async function toggle(emoji) {
    const g = current.find((x) => x.emoji === emoji);
    const body = { target_type: targetType, target_id: targetId, emoji };
    try {
      const r = g && g.reacted ? await api.del('/reactions', body) : await api.post('/reactions', body);
      current = r.reactions;
      if (onChange) onChange(current);
      draw();
    } catch (e) {
      toastError(e);
    }
  }

  const addBtn = button('', { icon: 'smilePlus', variant: 'ghost', size: compact ? 'xs' : 'sm', 'aria-label': 'Add reaction', title: 'Add reaction', cls: 'reaction-add' });
  addBtn.addEventListener('click', () => {
    const grid = h('div', { class: 'emoji-grid', role: 'group', 'aria-label': 'Reactions' },
      QUICK_EMOJI.map((e) => {
        const reacted = current.some((g) => g.emoji === e && g.reacted);
        const b = h('button', { type: 'button', class: ['emoji-btn', reacted && 'is-on'], 'aria-label': `React with ${e}`, 'aria-pressed': String(reacted) }, e);
        b.addEventListener('click', () => { layer.close(); toggle(e); });
        return b;
      }));
    const layer = openPopover(addBtn, grid, { label: 'Pick a reaction', cls: 'popover-emoji' });
    const first = grid.querySelector('button');
    if (first) first.focus();
  });

  function draw() {
    bar.replaceChildren(
      ...current.map((g) => {
        const who = g.names.join(', ') + (g.count > g.names.length ? ` and ${g.count - g.names.length} more` : '');
        const b = h('button', {
          type: 'button',
          class: 'reaction',
          'aria-pressed': String(g.reacted),
          title: `${who} reacted with ${g.emoji}`,
          'aria-label': `${g.emoji} ${g.count}. ${g.reacted ? 'Remove your reaction' : 'Add your reaction'}`,
        }, h('span', { class: 'reaction-emoji' }, g.emoji), h('span', { class: 'reaction-count' }, String(g.count)));
        b.addEventListener('click', () => toggle(g.emoji));
        return b;
      }),
      addBtn);
  }
  draw();
  return bar;
}

/** A Markdown comment box. Cmd/Ctrl+Enter sends; Escape cancels. */
function composer({ placeholder = 'Add a comment', submitLabel = 'Comment', onSubmit, onCancel, initial = '', autofocus = false, label = 'Comment' }) {
  const ta = textarea({ rows: initial ? 4 : 2, placeholder, 'aria-label': label, value: initial });
  const grow = () => {
    ta.style.height = 'auto';
    ta.style.height = `${Math.min(ta.scrollHeight + 2, 420)}px`;
  };
  const submit = button(submitLabel, { variant: 'primary', size: 'sm' });
  submit.disabled = !initial.trim();
  const send = () => {
    const text = ta.value.trim();
    if (!text) return;
    ta.readOnly = true;
    busy(submit, async () => {
      await onSubmit(text);
      ta.value = '';
      grow();
      submit.disabled = true;
    })
      .catch(toastError)
      .finally(() => {
        ta.readOnly = false;
      });
  };
  ta.addEventListener('input', () => {
    submit.disabled = !ta.value.trim();
    grow();
  });
  ta.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      e.preventDefault();
      send();
    } else if (e.key === 'Escape' && onCancel) {
      e.preventDefault();
      e.stopPropagation();
      onCancel();
    }
  });
  submit.addEventListener('click', send);
  const el = h('div', { class: 'composer' },
    ta,
    h('div', { class: 'composer-foot' },
      h('span', { class: 'composer-hint' }, 'Markdown works. Mention people with @handle.'),
      h('div', { class: 'row gap-xs' },
        onCancel ? button('Cancel', { variant: 'ghost', size: 'sm', onClick: onCancel }) : null,
        submit)));
  if (autofocus) requestAnimationFrame(() => { ta.focus(); grow(); });
  return { el, ta };
}

export async function render(ctx) {
  const id = ctx.params.id;
  const [loaded, commentRes] = await Promise.all([
    api.get(`/posts/${enc(id)}`, { format: 'html' }),
    api.get(`/posts/${enc(id)}/comments`),
  ]);
  if (!ctx.isCurrent()) return;
  let post = loaded;
  let comments = commentRes.items;
  const html = post.html || '';

  const canonical = `/p/${post.id}/${post.slug}`;
  if (location.pathname !== canonical && ctx.replaceUrl) ctx.replaceUrl(canonical + location.search + location.hash);
  ctx.setTitle(post.title);

  const isAuthor = () => post.author.id === myId();
  const trashed = () => !!post.deleted_at;
  const canEditPost = () => post.can_edit && !trashed();

  // --- Layout skeleton ------------------------------------------------------
  const head = h('header', { class: 'post-head' });
  const body = h('div', { class: 'prose post-body', trustedHtml: html });
  const reactionsBox = h('div', { class: 'post-reactions' });
  const backlinksBox = h('div');
  const commentsList = h('div', { class: 'comment-list' });
  const resolvedBox = h('div', { class: 'resolved-box' });
  const commentsCount = h('span', { class: 'count' });
  const commentsSection = h('section', { class: 'comments', 'aria-labelledby': 'comments-title' },
    h('h2', { class: 'comments-title', id: 'comments-title' }, 'Comments ', commentsCount),
    commentsList,
    resolvedBox);
  const tocBox = h('aside', { class: 'toc', 'aria-label': 'On this page' });
  const article = h('article', { class: 'post' }, head);

  if (!post.content.trim()) {
    body.replaceChildren(h('p', { class: 'muted' }, 'This post is empty.', canEditPost() ? ' ' : '', canEditPost() ? h('a', { href: `${canonical}/edit` }, 'Start writing') : null));
  }

  // Heading anchor links and external links in the rendered body.
  for (const hd of body.querySelectorAll('h1[id], h2[id], h3[id], h4[id]')) {
    hd.appendChild(h('a', { class: 'heading-anchor', href: `#${hd.id}`, 'aria-label': `Link to “${hd.textContent}”` }, '#'));
  }
  for (const a of body.querySelectorAll('a[href]')) {
    try {
      const u = new URL(a.getAttribute('href'), location.href);
      if (u.origin !== location.origin) {
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
      }
    } catch {
      /* leave odd links alone */
    }
  }

  // --- Header -------------------------------------------------------------------
  function verifyMenuItems() {
    const v = post.verification;
    const days = state.settings ? state.settings.default_verification_days : 90;
    const verify = (d) => async () => {
      post = { ...(await api.post(`/posts/${enc(post.id)}/verify`, d === undefined ? {} : { expires_in_days: d })), html };
      toast(d === 0 ? 'Verified with no expiry' : `Verified for ${d ?? days} days`);
      renderHead();
    };
    const items = [];
    if (v.status === 'verified') {
      items.push({ heading: `Verified${v.verified_by ? ` by ${v.verified_by.name}` : ''}${v.expires_at ? `, until ${new Date(v.expires_at).toLocaleDateString()}` : ''}` });
    } else if (v.status === 'expired') {
      items.push({ heading: 'Verification expired. Check the post and verify it again.' });
    } else {
      items.push({ heading: 'Mark this post as accurate and current' });
    }
    if (canEditPost()) {
      const again = v.status === 'unverified' ? 'Verify' : 'Verify again';
      items.push({ label: days > 0 ? `${again} for ${days} days` : `${again} with no expiry`, icon: 'verified', onClick: verify(undefined) });
      if (days !== 30) items.push({ label: `${again} for 30 days`, onClick: verify(30) });
      if (days !== 365) items.push({ label: `${again} for 1 year`, onClick: verify(365) });
      if (days !== 0) items.push({ label: `${again} with no expiry`, onClick: verify(0) });
      if (v.status !== 'unverified') {
        items.push('separator', {
          label: 'Remove verification',
          icon: 'x',
          danger: true,
          onClick: async () => {
            post = { ...(await api.del(`/posts/${enc(post.id)}/verify`)), html };
            toast('Verification removed');
            renderHead();
          },
        });
      }
    }
    return items;
  }

  function verificationButton() {
    const v = post.verification;
    const map = {
      verified: ['Verified', 'verified', 'verified'],
      expired: ['Needs review', 'expired', 'alert'],
      unverified: [canEditPost() ? 'Verify' : 'Unverified', 'unverified', 'circleDashed'],
    };
    const [label, variant, iconName] = map[v.status] || map.unverified;
    const b = h('button', { type: 'button', class: ['verify-btn', `verify-${variant}`], 'aria-haspopup': 'menu', 'aria-expanded': 'false', title: v.verified_at ? `Verified ${new Date(v.verified_at).toLocaleString()}` : 'Verification' },
      icon(iconName, { size: 15 }), h('span', null, label));
    b.addEventListener('click', () => openMenu(b, verifyMenuItems(), { align: 'end' }));
    return b;
  }

  async function setStatus(status, message) {
    post = { ...(await api.patch(`/posts/${enc(post.id)}`, { id: post.id, status })), html };
    toast(message);
    renderHead();
  }

  async function moveToTrash() {
    const ok = await confirmDialog({ title: 'Move to trash?', message: `“${post.title}” will be hidden from everyone. You can restore it from the trash.`, confirmLabel: 'Move to trash', danger: true });
    if (!ok) return;
    await api.del(`/posts/${enc(post.id)}`);
    toast('Moved to trash', {
      action: { label: 'Undo', onClick: async () => { await api.post(`/posts/${enc(post.id)}/restore`); toast('Restored'); ctx.reload(); } },
    });
    ctx.reload();
  }

  async function restoreFromTrash() {
    post = { ...(await api.post(`/posts/${enc(post.id)}/restore`)), html };
    toast('Restored from the trash');
    ctx.reload();
  }

  async function deleteForever() {
    const ok = await confirmDialog({ title: 'Delete permanently?', message: `“${post.title}”, its history and comments will be erased. This can’t be undone.`, confirmLabel: 'Delete permanently', danger: true });
    if (!ok) return;
    await api.del(`/posts/${enc(post.id)}`, { permanent: true });
    toast('Deleted permanently');
    navigate('/trash');
  }

  function moreItems() {
    const items = [];
    if (canEditPost()) {
      if (post.status === 'draft') items.push({ label: 'Publish', icon: 'check', onClick: () => setStatus('published', 'Published') });
      if (post.status === 'published' && (isAuthor() || isAdminRole())) items.push({ label: 'Move back to drafts', icon: 'draft', onClick: () => setStatus('draft', 'Moved to drafts') });
      items.push({
        label: 'Duplicate',
        icon: 'copy',
        onClick: async () => {
          const copy = await api.post(`/posts/${enc(post.id)}/duplicate`, {});
          toast('Duplicated as a draft');
          navigate(`/p/${copy.id}/edit`);
        },
      });
      items.push(post.status === 'archived'
        ? { label: 'Unarchive', icon: 'restore', onClick: () => setStatus('published', 'Unarchived') }
        : { label: 'Archive', icon: 'archive', onClick: () => setStatus('archived', 'Archived') });
      items.push({
        label: post.is_template ? 'Remove from templates' : 'Make this a template',
        icon: 'template',
        onClick: async () => {
          post = { ...(await api.patch(`/posts/${enc(post.id)}`, { id: post.id, is_template: !post.is_template })), html };
          toast(post.is_template ? 'Saved as a template' : 'Removed from templates');
          renderHead();
        },
      });
      if (post.topics.length) {
        items.push('separator');
        for (const t of post.topics) {
          const pinned = post.pinned_in.includes(t.id);
          items.push({
            label: pinned ? `Unpin from ${t.name}` : `Pin in ${t.name}`,
            icon: 'pin',
            onClick: async () => {
              await api.post(`/topics/${enc(t.id)}/pins`, { post_id: post.id, pinned: !pinned });
              post.pinned_in = pinned ? post.pinned_in.filter((x) => x !== t.id) : [...post.pinned_in, t.id];
              toast(pinned ? `Unpinned from ${t.name}` : `Pinned in ${t.name}`);
            },
          });
        }
      }
      items.push('separator');
    }
    items.push({ label: 'History', icon: 'history', onClick: () => navigate(`${canonical}/history`) });
    items.push({ label: 'Copy link', icon: 'link', onClick: () => copyText(`${location.origin}${canonical}`, 'Link copied') });
    if (!trashed() && (isAuthor() || isAdminRole()) && state.me.can_edit) {
      items.push('separator', { label: 'Move to trash', icon: 'trash', danger: true, onClick: moveToTrash });
    }
    if (trashed()) {
      items.push('separator', { label: 'Restore', icon: 'restore', onClick: restoreFromTrash });
      if (isAdminRole()) items.push({ label: 'Delete permanently', icon: 'trash', danger: true, onClick: deleteForever });
    }
    return items;
  }

  function banner() {
    if (trashed()) {
      return h('div', { class: 'banner banner-danger', role: 'status' }, icon('trash', { size: 16 }),
        h('span', null, 'This post is in the trash. Only people who can restore it see it.'),
        h('div', { class: 'banner-actions' },
          state.me.can_edit ? button('Restore', { size: 'sm', icon: 'restore', onClick: (e) => busy(e.currentTarget, restoreFromTrash).catch(toastError) }) : null,
          isAdminRole() ? button('Delete permanently', { size: 'sm', variant: 'danger', onClick: () => deleteForever().catch(toastError) }) : null));
    }
    if (post.status === 'draft') {
      return h('div', { class: 'banner', role: 'status' }, icon('draft', { size: 16 }),
        h('span', null, 'Draft. Only you and admins can see it until it’s published.'),
        canEditPost() ? h('div', { class: 'banner-actions' }, button('Publish', { size: 'sm', variant: 'primary', onClick: (e) => busy(e.currentTarget, () => setStatus('published', 'Published')).catch(toastError) })) : null);
    }
    if (post.status === 'archived') {
      return h('div', { class: 'banner banner-muted', role: 'status' }, icon('archive', { size: 16 }),
        h('span', null, 'Archived. It’s kept for reference and left out of lists and search.'),
        canEditPost() ? h('div', { class: 'banner-actions' }, button('Unarchive', { size: 'sm', onClick: (e) => busy(e.currentTarget, () => setStatus('published', 'Unarchived')).catch(toastError) })) : null);
    }
    return null;
  }

  function followButton() {
    const b = button(post.following ? 'Following' : 'Follow', {
      icon: post.following ? 'check' : 'bell',
      variant: 'ghost',
      size: 'sm',
      'aria-pressed': String(post.following),
      title: post.following ? 'You’ll be notified about comments and updates. Click to unfollow.' : 'Get notified about comments and updates',
    });
    b.addEventListener('click', () => busy(b, async () => {
      if (post.following) await api.del(`/follows/post/${enc(post.id)}`);
      else await api.post('/follows', { target_type: 'post', target_id: post.id });
      post.following = !post.following;
      toast(post.following ? 'Following this post' : 'Unfollowed');
      renderHead();
    }).catch(toastError));
    return b;
  }

  function renderHead() {
    const editor = post.last_editor && post.last_editor.id !== post.author.id ? post.last_editor : null;
    const actions = h('div', { class: 'post-actions' },
      canEditPost() ? h('a', { class: 'btn btn-subtle btn-sm', href: `${canonical}/edit`, 'aria-keyshortcuts': 'E', title: 'Edit (E)' }, icon('pencil'), h('span', null, 'Edit')) : null,
      !trashed() ? followButton() : null,
      menuButton(moreItems, { size: 'sm', ariaLabel: 'More post actions' }));
    head.replaceChildren(
      ...[banner()].filter(Boolean),
      h('div', { class: 'post-crumbs' },
        post.topics.length ? h('span', { class: 'chips' }, post.topics.map(topicChip)) : h('span', { class: 'muted small' }, 'No topic'),
        ...statusBadges(post).filter((b) => !b.classList.contains('badge-trash'))),
      h('div', { class: 'post-title-row' },
        h('h1', { class: 'post-title' }, post.title),
        actions),
      h('div', { class: 'post-meta' },
        userLink(post.author, { size: 'sm' }),
        h('span', { class: 'meta-item' },
          timeEl(post.updated_at, { prefix: 'Updated ' }),
          editor ? h('span', null, ' by ', h('a', { href: `/u/${encodeURIComponent(editor.handle)}` }, editor.name)) : null),
        h('a', { class: 'meta-item meta-link', href: `${canonical}/history`, title: 'Version history' }, icon('history', { size: 14 }), `Version ${post.version}`),
        h('span', { class: 'meta-item', title: 'Views' }, icon('eye', { size: 14 }), plural(post.view_count, 'view')),
        verificationButton()));
    renderReactions();
  }

  function renderReactions() {
    reactionsBox.replaceChildren(...(trashed() ? [] : [reactionBar('post', post.id, post.reactions, (g) => { post.reactions = g; })]));
  }

  // --- Backlinks ------------------------------------------------------------------
  if (post.backlinks.length) {
    backlinksBox.appendChild(h('section', { class: 'backlinks', 'aria-labelledby': 'backlinks-title' },
      h('h2', { class: 'backlinks-title', id: 'backlinks-title' }, 'Linked from'),
      h('ul', { class: 'backlink-list' }, post.backlinks.map((b) => h('li', null, icon('link', { size: 14 }), h('a', { href: urlPath(b.url) }, b.title))))));
  }

  // --- Table of contents -----------------------------------------------------------
  const outline = post.outline.filter((o) => o.level <= 3);
  let tocLinks = [];
  if (outline.length >= 2) {
    const min = Math.min(...outline.map((o) => o.level));
    const mkList = () => h('ol', { class: 'toc-list' }, outline.map((o) => h('li', { class: 'toc-item', style: { '--lvl': String(o.level - min) } },
      h('a', { href: `#${o.anchor}`, dataset: { anchor: o.anchor } }, o.text))));
    const list = mkList();
    tocLinks = [...list.querySelectorAll('a')];
    tocBox.append(h('p', { class: 'toc-title' }, 'On this page'), list);
    article.classList.add('has-toc');
  }

  // --- Comments --------------------------------------------------------------------
  let showResolved = false;
  let replyingTo = null;
  let editingId = null;

  function scrollToComment(cid) {
    const el = document.getElementById(`comment-${cid}`);
    if (!el) return;
    el.scrollIntoView({ block: 'center', behavior: 'smooth' });
    el.classList.remove('flash');
    void el.offsetWidth;
    el.classList.add('flash');
  }

  function commentEl(c, depth, byParent) {
    const mine = c.author.id === myId();
    const replies = h('div', { class: 'comment-replies' });
    for (const k of byParent.get(c.id) || []) replies.appendChild(commentEl(k, depth + 1, byParent));

    let bodyEl = h('div', { class: 'prose prose-comment comment-body', trustedHtml: c.html });
    if (editingId === c.id) {
      bodyEl = composer({
        initial: c.body,
        submitLabel: 'Save',
        label: 'Edit comment',
        autofocus: true,
        onCancel: () => { editingId = null; renderComments(); },
        onSubmit: async (text) => {
          const updated = await api.patch(`/comments/${enc(c.id)}`, { id: c.id, body: text });
          comments = comments.map((x) => (x.id === c.id ? updated : x));
          editingId = null;
          renderComments();
          toast('Comment updated');
        },
      }).el;
    }

    const menuItems = () => [
      { label: 'Copy link', icon: 'link', onClick: () => copyText(`${location.origin}${canonical}#comment-${c.id}`, 'Link copied') },
      mine ? { label: 'Edit', icon: 'pencil', onClick: () => { editingId = c.id; renderComments(); } } : null,
      mine || isAdminRole() ? 'separator' : null,
      mine || isAdminRole() ? {
        label: 'Delete',
        icon: 'trash',
        danger: true,
        onClick: async () => {
          const ok = await confirmDialog({ title: 'Delete comment?', message: 'The comment will be removed for everyone. Replies stay.', confirmLabel: 'Delete', danger: true });
          if (!ok) return;
          await api.del(`/comments/${enc(c.id)}`);
          comments = comments.filter((x) => x.id !== c.id);
          renderComments();
          toast('Comment deleted');
        },
      } : null,
    ].filter(Boolean);

    const resolveBtn = depth === 0 && !trashed() ? button(c.resolved ? 'Reopen' : 'Resolve', {
      variant: 'ghost',
      size: 'xs',
      icon: c.resolved ? 'restore' : 'check',
      onClick: (e) => busy(e.currentTarget, async () => {
        const updated = await api.patch(`/comments/${enc(c.id)}`, { id: c.id, resolved: !c.resolved });
        comments = comments.map((x) => (x.id === c.id ? updated : x));
        renderComments();
        toast(updated.resolved ? 'Thread resolved' : 'Thread reopened');
      }).catch(toastError),
    }) : null;

    const replyBtn = !trashed() ? button('Reply', {
      variant: 'ghost',
      size: 'xs',
      icon: 'reply',
      onClick: () => { replyingTo = c.id; renderComments(); },
    }) : null;

    let replyBox = null;
    if (replyingTo === c.id) {
      replyBox = composer({
        placeholder: `Reply to ${c.author.name}`,
        submitLabel: 'Reply',
        label: 'Reply',
        autofocus: true,
        onCancel: () => { replyingTo = null; renderComments(); },
        onSubmit: async (text) => {
          const created = await api.post(`/posts/${enc(post.id)}/comments`, { body: text, parent_id: c.id });
          comments.push(created);
          replyingTo = null;
          renderComments();
          scrollToComment(created.id);
        },
      }).el;
      replyBox.classList.add('composer-reply');
    }

    return h('article', { class: ['comment', c.resolved && 'is-resolved', depth > 0 && 'is-reply'], id: `comment-${c.id}`, 'aria-label': `Comment by ${c.author.name}` },
      h('div', { class: 'comment-avatar' }, avatar(c.author, depth > 0 ? 'xs' : 'sm')),
      h('div', { class: 'comment-main' },
        h('header', { class: 'comment-head' },
          userLink(c.author, { withAvatar: false }),
          h('a', { class: 'comment-time', href: `#comment-${c.id}` }, timeEl(c.created_at)),
          c.edited ? h('span', { class: 'muted small', title: `Edited ${new Date(c.updated_at).toLocaleString()}` }, 'edited') : null,
          c.resolved ? badge('Resolved', 'resolved', { iconName: 'check', title: c.resolved_by ? `Resolved by ${c.resolved_by.name}` : undefined }) : null,
          h('span', { class: 'spacer' }),
          menuButton(menuItems, { size: 'xs', ariaLabel: 'Comment actions' })),
        c.quote ? h('blockquote', { class: 'comment-quote', title: 'The passage this comment is about' }, c.quote) : null,
        bodyEl,
        editingId === c.id ? null : h('div', { class: 'comment-actions' },
          reactionBar('comment', c.id, c.reactions, (g) => { c.reactions = g; }, { compact: true }),
          replyBtn,
          resolveBtn),
        replyBox,
        replies.childNodes.length ? replies : null));
  }

  function renderComments() {
    const ids = new Set(comments.map((c) => c.id));
    const byParent = new Map();
    for (const c of comments) {
      const key = c.parent_id && ids.has(c.parent_id) ? c.parent_id : null;
      if (!byParent.has(key)) byParent.set(key, []);
      byParent.get(key).push(c);
    }
    const tops = byParent.get(null) || [];
    const open = tops.filter((c) => !c.resolved);
    const resolved = tops.filter((c) => c.resolved);
    commentsCount.textContent = comments.length ? String(comments.length) : '';
    commentsList.replaceChildren(...open.map((c) => commentEl(c, 0, byParent)));
    if (!open.length && !resolved.length) {
      commentsList.appendChild(h('p', { class: 'muted comments-empty' }, trashed() ? 'No comments.' : 'No comments yet. Select text in the post to comment on a passage.'));
    }
    resolvedBox.replaceChildren();
    if (resolved.length) {
      const toggle = button(showResolved ? `Hide resolved (${resolved.length})` : `Show resolved (${resolved.length})`, {
        variant: 'ghost',
        size: 'sm',
        icon: showResolved ? 'chevronDown' : 'chevronRight',
        'aria-expanded': String(showResolved),
        onClick: () => { showResolved = !showResolved; renderComments(); },
      });
      resolvedBox.appendChild(toggle);
      if (showResolved) resolvedBox.appendChild(h('div', { class: 'comment-list resolved-list' }, resolved.map((c) => commentEl(c, 0, byParent))));
    }
    if (mainComposer) resolvedBox.appendChild(mainComposer);
    markQuotes();
  }

  const mainComposer = trashed() ? null : h('div', { class: 'composer-main' }, avatar(state.me.user, 'sm'), composer({
    onSubmit: async (text) => {
      const created = await api.post(`/posts/${enc(post.id)}/comments`, { body: text });
      comments.push(created);
      renderComments();
      scrollToComment(created.id);
    },
  }).el);

  // Highlight passages that open inline comments refer to.
  function markQuotes() {
    for (const m of body.querySelectorAll('mark.quote-mark')) m.replaceWith(...m.childNodes);
    body.normalize();
    const open = comments.filter((c) => c.quote && !c.resolved);
    for (const c of open) {
      const candidates = [c.quote.trim(), c.quote.trim().split('\n')[0].trim()].filter((q) => q.length >= 3);
      let done = false;
      for (const q of candidates) {
        if (done) break;
        const walker = document.createTreeWalker(body, NodeFilter.SHOW_TEXT);
        let node;
        while ((node = walker.nextNode())) {
          if (node.parentElement && node.parentElement.closest('.heading-anchor, mark.quote-mark')) continue;
          const i = node.data.indexOf(q);
          if (i < 0) continue;
          const range = document.createRange();
          range.setStart(node, i);
          range.setEnd(node, i + q.length);
          const mark = h('mark', { class: 'quote-mark', title: `${c.author.name} commented on this`, tabindex: '0', role: 'button', 'aria-label': `Show comment by ${c.author.name}` });
          try {
            range.surroundContents(mark);
          } catch {
            continue;
          }
          const goTo = () => scrollToComment(c.id);
          mark.addEventListener('click', goTo);
          mark.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); goTo(); } });
          done = true;
          break;
        }
      }
    }
  }

  // --- Inline comments on a selection --------------------------------------------------
  const floatBtn = h('button', { type: 'button', class: 'float-comment', hidden: true }, icon('comment', { size: 15 }), h('span', null, 'Comment'));
  let pending = null;
  document.body.appendChild(floatBtn);
  ctx.onCleanup(() => floatBtn.remove());

  function hideFloat() {
    floatBtn.hidden = true;
  }
  function checkSelection() {
    if (trashed()) return hideFloat();
    const sel = window.getSelection();
    if (!sel || sel.isCollapsed || !sel.rangeCount) return hideFloat();
    const range = sel.getRangeAt(0);
    if (!body.contains(range.commonAncestorContainer)) return hideFloat();
    const text = sel.toString().replace(/\s+\n/g, '\n').trim();
    if (!text || text.length > 2000) return hideFloat();
    const rect = range.getBoundingClientRect();
    pending = { text, rect };
    floatBtn.hidden = false;
    const left = rect.left + rect.width / 2 - floatBtn.offsetWidth / 2 + window.scrollX;
    const top = rect.top + window.scrollY - floatBtn.offsetHeight - 8;
    floatBtn.style.left = `${Math.max(8, left)}px`;
    floatBtn.style.top = `${Math.max(8 + window.scrollY, top)}px`;
  }
  body.addEventListener('mouseup', () => setTimeout(checkSelection, 0));
  body.addEventListener('keyup', (e) => { if (e.shiftKey || e.key.startsWith('Arrow')) checkSelection(); });
  const onSelChange = () => {
    const sel = window.getSelection();
    if (!sel || sel.isCollapsed) hideFloat();
  };
  document.addEventListener('selectionchange', onSelChange);
  ctx.onCleanup(() => document.removeEventListener('selectionchange', onSelChange));
  floatBtn.addEventListener('mousedown', (e) => e.preventDefault());
  floatBtn.addEventListener('click', () => {
    if (!pending) return;
    const { text, rect } = pending;
    hideFloat();
    const box = composer({
      placeholder: 'Comment on this passage',
      label: 'Comment on the selected passage',
      autofocus: true,
      onCancel: () => layer.close(),
      onSubmit: async (bodyText) => {
        const created = await api.post(`/posts/${enc(post.id)}/comments`, { body: bodyText, quote: text });
        comments.push(created);
        layer.close();
        window.getSelection().removeAllRanges();
        renderComments();
        toast('Comment added', { action: { label: 'View', onClick: () => scrollToComment(created.id) } });
      },
    });
    const quote = text.length > 280 ? text.slice(0, 280) + '…' : text;
    const layer = openPopover(null, h('div', { class: 'inline-composer' }, h('blockquote', { class: 'comment-quote' }, quote), box.el), { rect, placement: 'bottom', align: 'center', label: 'Comment on the selected passage', cls: 'popover-composer' });
  });

  // --- Assemble -----------------------------------------------------------------------
  renderHead();
  renderComments();
  if (outline.length >= 3) {
    article.appendChild(h('details', { class: 'toc-inline' }, h('summary', null, 'On this page'),
      h('ol', { class: 'toc-list' }, outline.map((o) => h('li', { class: 'toc-item', style: { '--lvl': String(o.level - Math.min(...outline.map((x) => x.level))) } }, h('a', { href: `#${o.anchor}` }, o.text))))));
  }
  article.append(body, reactionsBox, backlinksBox, commentsSection);
  const layout = h('div', { class: ['post-layout', tocLinks.length && 'with-toc'] }, article, tocLinks.length ? tocBox : null);
  ctx.main.replaceChildren(h('div', { class: 'page page-post' }, layout));

  // Active section tracking for the TOC.
  if (tocLinks.length) {
    const targets = tocLinks.map((a) => ({ a, el: body.querySelector(`#${CSS.escape(a.dataset.anchor)}`) })).filter((x) => x.el);
    let raf = 0;
    const update = () => {
      raf = 0;
      let current = targets[0];
      for (const t of targets) if (t.el.getBoundingClientRect().top < 140) current = t;
      for (const t of targets) {
        if (t === current) t.a.setAttribute('aria-current', 'location');
        else t.a.removeAttribute('aria-current');
      }
    };
    const onScroll = () => { if (!raf) raf = requestAnimationFrame(update); };
    window.addEventListener('scroll', onScroll, { passive: true });
    ctx.onCleanup(() => window.removeEventListener('scroll', onScroll));
    update();
  }

  ctx.onKey('e', () => { if (canEditPost()) navigate(`${canonical}/edit`); });
  ctx.onCleanup(closeLayers);
  void emptyState;
}
