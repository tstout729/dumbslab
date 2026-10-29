// Drafts, templates, archive and trash: filtered post lists.

import { api, enc } from '/api.js';
import { h, icon, button, busy, toast, toastError, confirmDialog, pageHeader, emptyState } from '/ui.js';
import { state, canEdit } from '/state.js';
import { pagedPosts } from '/views/common.js';

async function listPage(ctx, { title, description, query, empty, actions, rowOpts }) {
  ctx.setTitle(title);
  const list = pagedPosts({ query, empty, rowOpts: rowOpts ? (p) => rowOpts(p, list) : undefined });
  await list.ready;
  if (!ctx.isCurrent()) return;
  ctx.main.replaceChildren(h('div', { class: 'page page-medium' }, pageHeader(title, { description, actions }), list.el));
}

export function drafts(ctx) {
  return listPage(ctx, {
    title: 'Drafts',
    description: 'Posts you haven’t published yet. Only you and admins can see them.',
    query: { status: 'draft', author: 'me' },
    actions: canEdit() ? h('a', { class: 'btn btn-primary btn-sm', href: '/new' }, icon('plus'), h('span', null, 'New post')) : null,
    empty: emptyState({ iconName: 'draft', title: 'No drafts', body: 'Drafts you start appear here until you publish them.' }),
  });
}

export function templates(ctx) {
  return listPage(ctx, {
    title: 'Templates',
    description: 'Starting points for new posts. Pick one in the editor under “Start from”, or turn any post into a template from its menu.',
    query: { is_template: true, status: 'all' },
    actions: canEdit() ? h('a', { class: 'btn btn-primary btn-sm', href: '/new?as=template' }, icon('plus'), h('span', null, 'New template')) : null,
    empty: emptyState({ iconName: 'template', title: 'No templates yet', body: 'Make a post a template to reuse its structure, like a meeting-notes or runbook layout.' }),
    rowOpts: (p) => ({
      actions: canEdit() ? h('a', { class: 'btn btn-ghost btn-xs', href: `/new?template=${encodeURIComponent(p.id)}`, title: 'New post from this template', dataset: { template: p.id } }, icon('plus'), h('span', null, 'Use')) : null,
    }),
  });
}

export function archive(ctx) {
  return listPage(ctx, {
    title: 'Archive',
    description: 'Posts kept for reference. They’re left out of lists and search unless you include archived posts.',
    query: { status: 'archived' },
    empty: emptyState({ iconName: 'archive', title: 'Nothing archived', body: 'Archive posts that are out of date but worth keeping.' }),
    rowOpts: (p, list) => ({
      actions: canEdit() ? button('Unarchive', {
        size: 'xs',
        variant: 'ghost',
        icon: 'restore',
        onClick: (e) => busy(e.currentTarget, async () => {
          await api.patch(`/posts/${enc(p.id)}`, { status: 'published' });
          toast(`Unarchived “${p.title}”`);
          await list.reload();
        }).catch(toastError),
      }) : null,
    }),
  });
}

export function trash(ctx) {
  const isAdmin = state.me.user.role === 'admin';
  return listPage(ctx, {
    title: 'Trash',
    description: isAdmin
      ? 'Deleted posts. Restore them, or delete them permanently to erase their history.'
      : 'Posts you deleted. Restore them any time; an admin can delete them permanently.',
    query: { status: 'trash' },
    empty: emptyState({ iconName: 'trash', title: 'The trash is empty' }),
    rowOpts: (p, list) => ({
      actions: h('div', { class: 'row gap-xs' },
        canEdit() ? button('Restore', {
          size: 'xs',
          variant: 'ghost',
          icon: 'restore',
          onClick: (e) => busy(e.currentTarget, async () => {
            await api.post(`/posts/${enc(p.id)}/restore`, {});
            toast(`Restored “${p.title}”`);
            await list.reload();
          }).catch(toastError),
        }) : null,
        isAdmin ? button('Delete permanently', {
          size: 'xs',
          variant: 'ghost',
          cls: 'text-danger',
          icon: 'trash',
          onClick: async () => {
            const ok = await confirmDialog({ title: 'Delete permanently?', message: `“${p.title}”, its history and comments will be erased. This can’t be undone.`, confirmLabel: 'Delete permanently', danger: true });
            if (!ok) return;
            try {
              await api.del(`/posts/${enc(p.id)}`, { permanent: true });
              toast('Deleted permanently');
              await list.reload();
            } catch (e) {
              toastError(e);
            }
          },
        }) : null),
    }),
  });
}
