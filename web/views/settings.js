// Settings: profile, connecting agents, API tokens, and (for admins) people, single sign-on,
// webhooks, workspace and, on hosted DumbSlab, the plan.

import { api, enc } from '/api.js';
import {
  h, icon, button, busy, badge, toast, toastError, modal, confirmDialog, secretDialog, field, input, textarea,
  select, checkbox, avatar, timeEl, copyField, copyText, emptyState, setTheme, themePref, frag, menuButton, absTime, plural,
} from '/ui.js';
import { state, emit, navigate, canAdmin, myId } from '/state.js';
import { connectionsSection } from '/views/connected.js';
import { ssoMessage } from '/views/auth.js';

const SECTIONS = [
  { id: 'profile', label: 'Profile', icon: 'user' },
  { id: 'agents', label: 'Connect agents', icon: 'plug' },
  { id: 'tokens', label: 'API tokens', icon: 'key' },
  { id: 'connections', label: 'Connected apps', icon: 'link' },
  { id: 'people', label: 'People', icon: 'users', admin: true },
  { id: 'sso', label: 'Single sign-on', icon: 'lock', admin: true },
  { id: 'webhooks', label: 'Webhooks', icon: 'zap', admin: true },
  { id: 'workspace', label: 'Workspace', icon: 'settings', admin: true },
  { id: 'plan', label: 'Plan', icon: 'layers', admin: true, hosted: true },
];

export async function render(ctx) {
  const id = ctx.params.section || 'profile';
  // Only hosted workspaces have an address, and a plan.
  const hosted = Boolean(state.settings && state.settings.address);
  const sections = SECTIONS.filter((s) => (!s.admin || canAdmin()) && (!s.hosted || hosted));
  const current = sections.find((s) => s.id === id);
  if (!current) {
    navigate('/settings', { replace: true });
    return;
  }
  ctx.setTitle(`${current.label} settings`);
  const content = await RENDER[id](ctx);
  if (!ctx.isCurrent()) return;
  const nav = h('nav', { class: 'settings-nav', 'aria-label': 'Settings' },
    sections.map((s, i) => [
      i > 0 && s.admin && !sections[i - 1].admin ? h('p', { class: 'settings-nav-head' }, 'Admin') : null,
      h('a', { class: ['settings-link', s.id === 'agents' && 'settings-link-accent'], href: `/settings/${s.id}`, 'aria-current': s.id === id ? 'page' : undefined }, icon(s.icon), h('span', null, s.label)),
    ]));
  ctx.main.replaceChildren(h('div', { class: 'page page-settings' },
    h('h1', { class: 'page-title settings-title' }, 'Settings'),
    h('div', { class: 'settings-layout' }, nav, h('div', { class: 'settings-content' }, content))));
}

function panel(title, description, ...body) {
  return h('section', { class: 'panel' },
    h('header', { class: 'panel-head' }, h('h2', { class: 'panel-title' }, title), description ? h('p', { class: 'panel-desc' }, description) : null),
    ...body);
}

function form(onSubmit, ...children) {
  const f = h('form', { class: 'stack', novalidate: true }, ...children);
  f.addEventListener('submit', (e) => {
    e.preventDefault();
    if (!f.checkValidity()) {
      f.reportValidity();
      return;
    }
    const btn = f.querySelector('button[type=submit]');
    busy(btn, () => onSubmit(f)).catch((err) => toastError(err));
  });
  return f;
}

// ---------------------------------------------------------------------------
// Profile

async function profileSection() {
  const u = state.me.user;
  const name = input({ required: true, value: u.name, autocomplete: 'name', maxlength: '120' });
  const handle = input({ required: true, value: u.handle, autocomplete: 'off', spellcheck: 'false' });
  const bio = textarea({ rows: 3, value: u.bio || '', maxlength: '1000' });
  const avatarUrl = input({ type: 'url', value: u.avatar_url || '', placeholder: 'https://…' });
  const profileForm = form(async () => {
    const updated = await api.patch('/users/me', { name: name.value.trim(), handle: handle.value.trim(), bio: bio.value, avatar_url: avatarUrl.value.trim() });
    state.me.user = updated;
    handle.value = updated.handle;
    emit('me', state.me);
    toast('Profile saved');
  },
  h('div', { class: 'grid-2' }, field('Name', name), field('Handle', handle, { hint: 'People mention you with @handle.' })),
  field('Bio', bio),
  field('Avatar image URL', avatarUrl, { hint: 'An https image. Leave empty to use your initials.' }),
  h('div', null, button('Save profile', { variant: 'primary', type: 'submit' })));

  const pref = themePref();
  const themeGroup = h('div', { class: 'segmented', role: 'radiogroup', 'aria-label': 'Theme' },
    [['system', 'System', 'monitor'], ['light', 'Light', 'sun'], ['dark', 'Dark', 'moon']].map(([value, label, iconName]) => {
      const b = h('button', { type: 'button', class: 'seg', role: 'radio', 'aria-checked': String(pref === value) }, icon(iconName, { size: 14 }), label);
      b.addEventListener('click', () => {
        setTheme(value);
        for (const x of themeGroup.children) x.setAttribute('aria-checked', String(x === b));
      });
      return b;
    }));

  const current = input({ type: 'password', required: true, autocomplete: 'current-password' });
  const next = input({ type: 'password', required: true, minlength: 8, autocomplete: 'new-password' });
  const confirm = input({ type: 'password', required: true, minlength: 8, autocomplete: 'new-password' });
  const pwForm = form(async (f) => {
    if (next.value !== confirm.value) {
      toast('The new passwords don’t match.', { type: 'error' });
      confirm.focus();
      return;
    }
    await api.post('/me/password', { current_password: current.value, new_password: next.value });
    f.reset();
    toast('Password changed. Other browser sessions were signed out.');
  },
  field('Current password', current),
  h('div', { class: 'grid-2' }, field('New password', next, { hint: 'At least 8 characters.' }), field('Confirm new password', confirm)),
  h('div', null, button('Change password', { variant: 'subtle', type: 'submit' })));

  return frag(
    panel('Profile', null, h('div', { class: 'profile-preview' }, avatar(u, 'lg'), h('div', null, h('strong', null, u.name), h('p', { class: 'muted small' }, `${u.email}, ${u.role}`))), profileForm),
    await ssoProfilePanel(),
    panel('Appearance', 'Follow your system setting, or pick a theme for this browser.', themeGroup),
    panel('Password', 'Changing your password signs out your other browser sessions.', pwForm));
}

/** Your account at the workspace's identity provider, when it signs in with one. */
async function ssoProfilePanel() {
  const sso = state.auth.sso;
  if (!sso) return null;
  const query = new URLSearchParams(location.search);
  const r = await api.get('/sso/identities');
  const mine = r.items.filter((i) => i.current);
  const notes = [];
  if (query.get('sso_linked')) notes.push(h('p', { class: 'callout', role: 'status' }, icon('check', { size: 15 }), h('span', null, `Your ${sso.name} account is linked. You can sign in with it now.`)));
  if (query.get('sso_error')) notes.push(h('p', { class: 'callout callout-warn', role: 'alert' }, icon('alert', { size: 15 }), h('span', null, ssoMessage(query.get('sso_error'), sso.name))));
  const body = h('div', { class: 'stack' }, ...notes);
  const unlinkButton = (identity, row) => {
    const b = button('Unlink', { size: 'xs', variant: 'ghost', cls: 'text-danger' });
    b.addEventListener('click', async () => {
      const ok = await confirmDialog({ title: `Unlink your ${sso.name} account?`, message: `You can link it again here, or ${sso.name} may match it to you by your verified email the next time you sign in.`, confirmLabel: 'Unlink', danger: true });
      if (!ok) return;
      busy(b, async () => {
        await api.del(`/sso/identities/${enc(identity.id)}`);
        toast(`${sso.name} account unlinked`);
        row.remove();
      }).catch(toastError);
    });
    return b;
  };
  if (mine.length) {
    body.append(h('ul', { class: 'token-list' }, mine.map((i) => {
      const row = h('li', { class: 'token' },
        h('div', { class: 'token-icon' }, icon('lock', { size: 16 })),
        h('div', { class: 'token-main' },
          h('div', { class: 'token-head' }, h('strong', null, i.email || `Your ${sso.name} account`)),
          h('div', { class: 'token-meta' }, h('span', null, 'Linked ', timeEl(i.linked_at)), i.last_used_at ? h('span', null, 'Last used ', timeEl(i.last_used_at)) : null)));
      row.append(unlinkButton(i, row));
      return row;
    })));
  } else {
    const link = button(`Link your ${sso.name} account`, { icon: 'external', variant: 'subtle', size: 'sm' });
    link.addEventListener('click', () => busy(link, async () => {
      const started = await api.post('/me/sso');
      location.assign(started.authorize_url);
    }).catch(toastError));
    body.append(h('div', null, link));
  }
  return panel('Single sign-on', `This workspace signs in with ${sso.name}. Link your ${sso.name} account to sign in with it, even if ${sso.name} doesn’t share a verified email address with DumbSlab.`, body);
}

// ---------------------------------------------------------------------------
// Connect agents

async function agentsSection() {
  const mcp = state.auth.mcp_url;
  const apiUrl = state.auth.api_url;
  const origin = location.origin;
  let token = '<your-token>';

  const snippets = [];
  const snippet = (title, build, note) => {
    const pre = h('pre', { class: 'code-block' }, h('code', null, build()));
    snippets.push(() => { pre.firstChild.textContent = build(); });
    const copy = button('Copy', { icon: 'copy', size: 'xs', variant: 'subtle', 'aria-label': `Copy: ${title}` });
    copy.addEventListener('click', () => copyText(build(), 'Copied'));
    return h('div', { class: 'snippet' },
      h('div', { class: 'snippet-head' }, h('span', { class: 'snippet-title' }, title), copy),
      pre,
      note ? h('p', { class: 'field-hint' }, note) : null);
  };
  const refresh = () => snippets.forEach((f) => f());

  const tokenStatus = h('p', { class: 'field-hint' }, 'Commands below show <your-token>. Create a token to fill it in.');
  const makeToken = button('Create a token for these commands', { icon: 'key', variant: 'subtle', size: 'sm' });
  makeToken.addEventListener('click', () => busy(makeToken, async () => {
    const r = await api.post('/tokens', { name: 'Agent (from Connect agents)', scopes: ['read', 'write'] });
    token = r.token;
    refresh();
    tokenStatus.replaceChildren(icon('alert', { size: 14 }), h('span', null, `Token “${r.info.name}” created and filled in below. Copy what you need now; the secret won’t be shown again.`));
    tokenStatus.className = 'callout callout-warn';
    toast('Token created');
  }).catch(toastError));

  const jsonConfig = () => JSON.stringify({ mcpServers: { dumbslab: { url: mcp, headers: { Authorization: `Bearer ${token}` } } } }, null, 2);

  return frag(
    h('section', { class: 'panel panel-hero' },
      h('div', { class: 'hero-mark' }, icon('plug', { size: 22 })),
      h('h2', { class: 'panel-title' }, 'Connect your AI agents'),
      h('p', { class: 'panel-desc' }, 'Agents can do anything you can here: search, read, write and edit posts, comment, and organize topics. Their changes show up in history and activity with an MCP or API badge.'),
      h('div', { class: 'field' },
        h('span', { class: 'field-label' }, 'MCP server URL'),
        copyField(mcp, { label: 'MCP URL' }),
        h('p', { class: 'field-hint' }, 'Clients that support OAuth (Claude, ChatGPT, Cursor) only need this URL. You approve access in the browser.'))),
    panel('Claude Code', 'Add the server with one command. The first time Claude Code connects, it opens a browser window to approve access.',
      snippet('With OAuth (recommended)', () => `claude mcp add --transport http dumbslab ${mcp}`),
      snippet('With an API token', () => `claude mcp add --transport http dumbslab ${mcp} --header "Authorization: Bearer ${token}"`),
      h('div', { class: 'row gap-sm wrap' }, makeToken),
      tokenStatus),
    panel('Cursor, VS Code and other clients', 'Most clients accept a JSON config with the URL and a header.',
      snippet('mcp.json', jsonConfig)),
    panel('Smaller tool lists', 'Agents with limited context can load fewer tools. Add a toolset to the URL.',
      snippet('Core tools only', () => `${mcp}?toolset=core`, 'Search, read, write and comment.'),
      snippet('Read-only', () => `${mcp}?toolset=read`, 'Search and read. Apps that sign in through this URL get read-only access; with a token, use a read-only one.')),
    panel('REST API', 'Every operation is also a REST endpoint. Send a token as a Bearer header.',
      snippet('Search with curl', () => `curl -H "Authorization: Bearer ${token}" "${apiUrl}/search?q=onboarding"`),
      h('ul', { class: 'link-list' },
        h('li', null, h('a', { href: `${origin}/api/v1/openapi.json`, target: '_blank', rel: 'noopener' }, icon('external', { size: 14 }), 'OpenAPI document'), h('span', { class: 'muted small' }, ' /api/v1/openapi.json')),
        h('li', null, h('a', { href: `${origin}/llms.txt`, target: '_blank', rel: 'noopener' }, icon('external', { size: 14 }), 'Guide for agents'), h('span', { class: 'muted small' }, ' /llms.txt')),
        h('li', null, h('span', null, 'Call any operation with '), h('code', null, `POST ${apiUrl}/operations/<name>`)))),
    panel('Give each agent its own identity', 'Add a bot account for each agent and mint it a token, so its edits appear under its own name with a bot badge.',
      canAdmin()
        ? h('a', { class: 'btn btn-subtle btn-sm', href: '/settings/people' }, icon('bot'), h('span', null, 'Add a bot account'))
        : h('p', { class: 'muted small' }, 'Ask a workspace admin to add a bot account.')));
}

// ---------------------------------------------------------------------------
// API tokens

function tokenRow(t, onRevoke) {
  const revoke = !t.revoked ? button('Revoke', { size: 'xs', variant: 'ghost', cls: 'text-danger' }) : null;
  if (revoke) {
    revoke.addEventListener('click', async () => {
      const ok = await confirmDialog({ title: `Revoke “${t.name}”?`, message: 'Anything using this token stops working right away.', confirmLabel: 'Revoke', danger: true });
      if (!ok) return;
      busy(revoke, async () => {
        await api.del(`/tokens/${enc(t.id)}`);
        toast('Token revoked');
        onRevoke();
      }).catch(toastError);
    });
  }
  return h('li', { class: 'token' },
    h('div', { class: 'token-icon' }, icon(t.kind === 'oauth' ? 'plug' : 'key', { size: 16 })),
    h('div', { class: 'token-main' },
      h('div', { class: 'token-head' },
        h('strong', null, t.name),
        t.kind === 'oauth' ? badge('Connected app', 'oauth', { title: t.client_id ? `OAuth client ${t.client_id}` : 'Issued to an MCP client through OAuth' }) : null,
        t.scopes.map((s) => badge(s, 'scope'))),
      h('div', { class: 'token-meta' },
        h('code', null, `${t.prefix}…`),
        t.user && t.user.id !== myId() ? h('span', null, `for ${t.user.name}`) : null,
        h('span', null, 'Created ', timeEl(t.created_at)),
        h('span', null, t.last_used_at ? h('span', null, 'Last used ', timeEl(t.last_used_at)) : 'Never used'),
        t.expires_at ? h('span', { title: absTime(t.expires_at) }, 'Expires ', timeEl(t.expires_at)) : h('span', null, 'No expiry'))),
    revoke);
}

/** Opens the create-token dialog. `user` mints for another account (admins). */
export function createTokenDialog({ user, defaultName = '', onCreated } = {}) {
  const name = input({ required: true, maxlength: '100', value: defaultName, placeholder: 'For example, Claude Code on my laptop' });
  const read = checkbox('Read', { checked: true, value: 'read' });
  const write = checkbox('Write', { checked: true, value: 'write' });
  const admin = (user ? user.role === 'admin' : state.me.user.role === 'admin') ? checkbox('Admin', { value: 'admin' }) : null;
  const expiry = select([
    { value: '', label: 'Never' },
    { value: '30', label: 'In 30 days' },
    { value: '90', label: 'In 90 days' },
    { value: '365', label: 'In a year' },
  ]);
  modal({
    title: user ? `New token for ${user.name}` : 'New API token',
    content: frag(
      field('Name', name, { hint: 'What it’s for, so you recognize it later.' }),
      h('fieldset', { class: 'field fieldset' }, h('legend', { class: 'field-label' }, 'Scopes'), h('div', { class: 'row gap-md wrap' }, read, write, admin),
        h('p', { class: 'field-hint' }, 'Read lets it search and read. Write lets it create and change things. Admin manages people and settings.')),
      field('Expires', expiry)),
    actions: [
      { label: 'Cancel', variant: 'ghost' },
      {
        label: 'Create token',
        variant: 'primary',
        onClick: async () => {
          const scopes = [read, write, admin].filter(Boolean).map((c) => c.querySelector('input')).filter((i) => i.checked).map((i) => i.value);
          if (!name.value.trim()) {
            name.focus();
            toast('Name the token.', { type: 'error' });
            return false;
          }
          if (!scopes.length) {
            toast('Pick at least one scope.', { type: 'error' });
            return false;
          }
          const r = await api.post('/tokens', {
            name: name.value.trim(),
            scopes,
            expires_in_days: expiry.value ? Number(expiry.value) : undefined,
            user: user ? user.id : undefined,
          });
          setTimeout(() => {
            secretDialog({
              title: 'Token created',
              intro: `Use this token as “Authorization: Bearer …” for ${user ? user.name : 'your scripts and agents'}.`,
              secret: r.token,
              extra: h('div', { class: 'snippet' },
                h('div', { class: 'snippet-head' }, h('span', { class: 'snippet-title' }, 'Claude Code')),
                h('pre', { class: 'code-block' }, h('code', null, `claude mcp add --transport http dumbslab ${state.auth.mcp_url} --header "Authorization: Bearer ${r.token}"`))),
            }).then(() => { if (onCreated) onCreated(r); });
          }, 0);
          return true;
        },
      },
    ],
  });
}

async function tokensSection(ctx) {
  const r = await api.get('/tokens');
  const personal = r.items.filter((t) => t.kind !== 'oauth');
  const oauth = r.items.filter((t) => t.kind === 'oauth');
  const reload = () => ctx.reload();
  const create = button('New token', { icon: 'plus', variant: 'primary', size: 'sm', onClick: () => createTokenDialog({ onCreated: reload }) });
  return frag(
    panel('API tokens', 'Personal tokens let scripts and agents act as you. Treat them like passwords.',
      h('div', null, create),
      personal.length ? h('ul', { class: 'token-list' }, personal.map((t) => tokenRow(t, reload))) : h('p', { class: 'muted small' }, 'No tokens yet.')),
    panel('Connected apps', 'Apps you approved through OAuth, such as MCP clients. Revoke access any time.',
      oauth.length ? h('ul', { class: 'token-list' }, oauth.map((t) => tokenRow(t, reload))) : h('p', { class: 'muted small' }, 'No connected apps.')));
}

// ---------------------------------------------------------------------------
// People (admins)

function addPersonDialog(onDone) {
  const name = input({ required: true, maxlength: '120' });
  const email = input({ type: 'email', required: true });
  const handle = input({ placeholder: 'Optional', spellcheck: 'false' });
  const role = select([{ value: 'member', label: 'Member: reads and writes' }, { value: 'viewer', label: 'Viewer: reads and comments' }, { value: 'admin', label: 'Admin: manages everything' }]);
  const bot = checkbox('This is a bot (an agent or integration)');
  const password = input({ type: 'password', placeholder: 'Leave empty to generate one', autocomplete: 'new-password', minlength: 8 });
  const pwField = field('Password', password, { hint: 'People get a temporary password if you leave this empty. Bots don’t need one; they use tokens.' });
  modal({
    title: 'Add a person or bot',
    content: frag(
      h('div', { class: 'grid-2' }, field('Name', name), field('Email', email, { hint: 'Bots need a unique address too, like claude@example.com.' })),
      h('div', { class: 'grid-2' }, field('Handle', handle), field('Role', role)),
      bot,
      pwField),
    actions: [
      { label: 'Cancel', variant: 'ghost' },
      {
        label: 'Add',
        variant: 'primary',
        onClick: async () => {
          if (!name.value.trim() || !email.value.trim()) {
            toast('Name and email are required.', { type: 'error' });
            return false;
          }
          const isBot = bot.querySelector('input').checked;
          const r = await api.post('/users', {
            name: name.value.trim(),
            email: email.value.trim(),
            handle: handle.value.trim() || undefined,
            role: role.value,
            is_bot: isBot,
            password: password.value || undefined,
          });
          setTimeout(async () => {
            if (r.temporary_password) {
              await secretDialog({ title: `${r.user.name} was added`, intro: `Share this temporary password with ${r.user.name} so they can sign in at ${location.origin}/login with ${r.user.email}. They can change it under Settings.`, secret: r.temporary_password });
            } else {
              toast(`${r.user.name} was added`);
            }
            if (isBot) {
              const mint = await confirmDialog({ title: `Create a token for ${r.user.name}?`, message: 'Bots act through API tokens. Create one now and paste it into the agent’s MCP or API config.', confirmLabel: 'Create token', cancelLabel: 'Later' });
              if (mint) createTokenDialog({ user: r.user, defaultName: `${r.user.name} token`, onCreated: onDone });
              else onDone();
            } else onDone();
          }, 0);
          return true;
        },
      },
    ],
  });
}

async function peopleSection(ctx) {
  const r = await api.get('/users', { include_deactivated: true, limit: 200 });
  const reload = () => ctx.reload();
  const add = button('Add person or bot', { icon: 'plus', variant: 'primary', size: 'sm', onClick: () => addPersonDialog(reload) });

  const row = (u) => {
    const isMe = u.id === myId();
    const roleSel = select(['admin', 'member', 'viewer'].map((x) => ({ value: x, label: x[0].toUpperCase() + x.slice(1), selected: u.role === x })), { 'aria-label': `Role for ${u.name}`, class: 'input select input-sm', disabled: u.deactivated });
    roleSel.addEventListener('change', async () => {
      try {
        const updated = await api.patch(`/users/${enc(u.id)}`, { role: roleSel.value });
        u.role = updated.role;
        toast(`${u.name} is now ${updated.role === 'admin' ? 'an admin' : `a ${updated.role}`}`);
      } catch (e) {
        roleSel.value = u.role;
        toastError(e);
      }
    });
    const items = () => [
      { label: 'View profile', icon: 'user', onClick: () => navigate(`/u/${encodeURIComponent(u.handle)}`) },
      !u.deactivated ? { label: 'Create a token', icon: 'key', onClick: () => createTokenDialog({ user: u, defaultName: `${u.name} token` }) } : null,
      {
        label: 'Set a new password',
        icon: 'lock',
        onClick: () => {
          const pw = input({ type: 'password', required: true, minlength: 8, autocomplete: 'new-password' });
          modal({
            title: `New password for ${u.name}`,
            size: 'sm',
            content: field('Password', pw, { hint: 'At least 8 characters. Their current sessions are signed out.' }),
            actions: [{ label: 'Cancel', variant: 'ghost' }, {
              label: 'Set password',
              variant: 'primary',
              onClick: async () => {
                if (pw.value.length < 8) {
                  toast('Use at least 8 characters.', { type: 'error' });
                  return false;
                }
                await api.patch(`/users/${enc(u.id)}`, { new_password: pw.value });
                toast('Password set');
                return true;
              },
            }],
          });
        },
      },
      !isMe ? 'separator' : null,
      !isMe ? {
        label: u.deactivated ? 'Reactivate' : 'Deactivate',
        icon: u.deactivated ? 'restore' : 'x',
        danger: !u.deactivated,
        onClick: async () => {
          if (!u.deactivated) {
            const ok = await confirmDialog({ title: `Deactivate ${u.name}?`, message: 'They’re signed out, can’t sign in, and their tokens stop working. Their posts stay.', confirmLabel: 'Deactivate', danger: true });
            if (!ok) return;
          }
          await api.patch(`/users/${enc(u.id)}`, { deactivated: !u.deactivated });
          toast(u.deactivated ? `${u.name} reactivated` : `${u.name} deactivated`);
          reload();
        },
      } : null,
    ].filter(Boolean);
    return h('li', { class: ['person', u.deactivated && 'is-deactivated'] },
      avatar(u, 'sm'),
      h('div', { class: 'person-main' },
        h('div', { class: 'person-head' },
          h('a', { href: `/u/${encodeURIComponent(u.handle)}`, class: 'person-name' }, u.name),
          isMe ? badge('You', 'scope') : null,
          u.is_bot ? badge('Bot', 'bot', { iconName: 'bot' }) : null,
          u.deactivated ? badge('Deactivated', 'trash') : null),
        h('div', { class: 'person-meta' }, h('span', null, '@' + u.handle), h('span', null, u.email), u.last_seen_at ? h('span', null, 'Seen ', timeEl(u.last_seen_at)) : null)),
      roleSel,
      menuButton(items, { size: 'xs', ariaLabel: `Actions for ${u.name}` }));
  };

  const humans = r.items.filter((u) => !u.is_bot);
  const bots = r.items.filter((u) => u.is_bot);
  return frag(
    panel('People', 'Admins manage everything. Members read and write. Viewers read and comment.',
      h('div', null, add),
      h('ul', { class: 'people-list' }, humans.map(row))),
    panel('Bots', 'Agent and integration accounts. Each acts through its own tokens, and its changes carry a bot badge.',
      bots.length ? h('ul', { class: 'people-list' }, bots.map(row)) : h('p', { class: 'muted small' }, 'No bots yet. Add one with “Add person or bot” and tick “This is a bot”.')));
}

// ---------------------------------------------------------------------------
// Single sign-on (admins)

const SSO_DOCS = 'https://github.com/tstout729/dumbslab/blob/main/docs/sso.md';

const SSO_PROVIDERS = {
  google: {
    label: 'Google Workspace',
    help: 'In Google Cloud console › APIs & Services › Credentials, create an OAuth client ID (Web application) with the redirect URI below. Only accounts in your allowed domains can sign in.',
  },
  microsoft: {
    label: 'Microsoft Entra ID',
    help: 'In Microsoft Entra admin center › App registrations, register a single-tenant app with the redirect URI below (Web), and add a client secret. Add the optional ID token claims email and xms_edov so first sign-ins can find people by email.',
  },
  okta: {
    label: 'Okta',
    issuer: 'https://acme.okta.com',
    help: 'In Okta, create an OIDC Web Application with the redirect URI below as its sign-in redirect URI, and assign it to your people. The issuer is your Okta URL, or your authorization server’s.',
  },
  onelogin: {
    label: 'OneLogin',
    issuer: 'https://acme.onelogin.com/oidc/2',
    help: 'In OneLogin, add the OpenId Connect (OIDC) app with the redirect URI below and Basic token endpoint authentication, and give your people access. The issuer is in the app’s SSO tab.',
  },
  slack: {
    label: 'Slack',
    help: 'At api.slack.com/apps, create an app, add the redirect URI below under OAuth & Permissions, and the openid, email and profile scopes. Sign in with Slack works for any Slack workspace unless you name yours.',
  },
  oidc: {
    label: 'Another OpenID Connect provider',
    issuer: 'https://login.example.com',
    help: 'Register a confidential web app that uses the authorization code flow, with the redirect URI below. The issuer must be exactly what the provider’s /.well-known/openid-configuration says.',
  },
};

function ssoCheckNote(check) {
  if (!check) return null;
  return check.ok
    ? h('p', { class: 'callout', role: 'status' }, icon('check', { size: 15 }), h('span', null, 'The provider’s settings check out. Try signing in from a private window before requiring single sign-on.'))
    : h('p', { class: 'callout callout-warn', role: 'alert' }, icon('alert', { size: 15 }), h('span', null, `The provider’s settings don’t check out: ${check.error}`));
}

function ssoStatus(s) {
  if (s.client_secret_unreadable) {
    return h('p', { class: 'callout callout-warn', role: 'alert' }, icon('alert', { size: 15 }),
      h('span', null, 'Single sign-on is off: the saved client secret can’t be read, because the server’s connector key changed. Enter the client secret again and save. Until then everyone can sign in with a password.'));
  }
  if (s.active) return h('p', { class: 'callout', role: 'status' }, icon('check', { size: 15 }), h('span', null, `People can sign in with ${s.name}.${s.require_sso ? ' Only admins can sign in with a password.' : ''}`));
  if (s.enabled) return h('p', { class: 'callout callout-warn' }, icon('alert', { size: 15 }), h('span', null, 'Single sign-on is on but not finished: fill in everything below.'));
  return h('p', { class: 'muted small' }, 'Single sign-on is off. Everyone signs in with a password.');
}

async function ssoSection(ctx) {
  const s = await api.get('/sso');
  if (!s.available) {
    return h('section', { class: 'panel' }, emptyState({ iconName: 'lock', title: 'Single sign-on isn’t available on this server',
      body: 'It needs a connector key to encrypt the client secret. Whoever runs the server can set CONNECTOR_KEY (or DUMBSLAB_CONNECTOR_KEY when self-hosting).' }));
  }
  const status = h('div', { class: 'stack' }, ssoStatus(s));
  const provider = select([
    { value: '', label: 'Choose a provider', selected: !s.provider, disabled: true },
    ...Object.entries(SSO_PROVIDERS).map(([value, p]) => ({ value, label: p.label, selected: s.provider === value })),
  ]);
  const help = h('span');
  const issuer = input({ type: 'url', value: s.issuer || '', spellcheck: 'false', autocapitalize: 'off' });
  const tenant = input({ value: s.tenant || '', spellcheck: 'false', placeholder: '72f988bf-86f1-41af-91ab-2d7cd011db47' });
  const team = input({ value: s.team || '', spellcheck: 'false', placeholder: 'Optional, like T0123ABCD' });
  const label = input({ value: s.label || '', maxlength: '40', placeholder: 'SSO' });
  const clientId = input({ value: s.client_id || '', spellcheck: 'false', autocapitalize: 'off' });
  const secretHint = (x) => (x.client_secret_unreadable ? 'Enter it again: the saved one can’t be read.' : x.client_secret_set ? 'Saved. Leave empty to keep it.' : '');
  const clientSecret = input({ type: 'password', autocomplete: 'new-password', placeholder: secretHint(s) });
  const domains = input({ value: (s.allowed_domains || []).join(', '), spellcheck: 'false', autocapitalize: 'off', placeholder: 'acme.com' });
  const enabled = checkbox('Show “Sign in with …” on the sign-in page', { checked: s.enabled });
  const autoProvision = checkbox('Add new people automatically: verified addresses at the allowed domains join as members', { checked: s.auto_provision });
  const requireSso = checkbox('Require single sign-on: only admins can sign in with a password', { checked: s.require_sso });
  const issuerField = field('Issuer URL', issuer, { hint: 'Exactly as the provider names it, https and all.' });
  const tenantField = field('Directory (tenant) ID', tenant, { hint: 'Microsoft Entra admin center › Overview. Only this directory’s accounts can sign in.' });
  const teamField = field('Slack workspace ID', team, { hint: 'Only people in this Slack workspace can sign in. Leave empty to allow any.' });
  const labelField = field('Button name', label, { hint: 'Shown as “Sign in with …”.' });
  const domainsHint = h('span');
  const domainsField = field('Allowed email domains', domains, { hint: domainsHint });
  const show = () => {
    const p = provider.value;
    const info = SSO_PROVIDERS[p];
    help.replaceChildren(info ? info.help : 'Pick the provider your organization signs in with.', ' ', h('a', { href: SSO_DOCS, target: '_blank', rel: 'noopener' }, 'Setup steps'), '.');
    issuerField.hidden = !['okta', 'onelogin', 'oidc'].includes(p);
    if (info && info.issuer) issuer.placeholder = info.issuer;
    tenantField.hidden = p !== 'microsoft';
    teamField.hidden = p !== 'slack';
    labelField.hidden = p !== 'oidc';
    domainsHint.textContent = p === 'google'
      ? 'Your Google Workspace domains, separated by commas. Only accounts in them can sign in.'
      : 'Separated by commas. A first sign-in finds someone here by email only when the provider says it’s verified and it’s at one of these.';
  };
  provider.addEventListener('change', show);
  show();
  const checks = h('div', { class: 'stack' });
  const f = form(async () => {
    const p = provider.value;
    if (!p) {
      toast('Choose a provider.', { type: 'error' });
      provider.focus();
      return;
    }
    const body = {
      provider: p,
      client_id: clientId.value.trim(),
      allowed_domains: domains.value.split(/[\s,]+/).map((d) => d.trim()).filter(Boolean),
      enabled: enabled.querySelector('input').checked,
      auto_provision: autoProvision.querySelector('input').checked,
      require_sso: requireSso.querySelector('input').checked,
    };
    if (['okta', 'onelogin', 'oidc'].includes(p)) body.issuer = issuer.value.trim();
    if (p === 'microsoft' && tenant.value.trim()) body.tenant = tenant.value.trim();
    if (p === 'slack') body.team = team.value.trim();
    if (p === 'oidc') body.label = label.value.trim();
    if (clientSecret.value.trim()) body.client_secret = clientSecret.value.trim();
    const saved = await api.patch('/sso', body);
    clientSecret.value = '';
    clientSecret.placeholder = secretHint(saved);
    status.replaceChildren(ssoStatus(saved));
    checks.replaceChildren(...[ssoCheckNote(saved.check)].filter(Boolean));
    // The sign-in page's button follows the new settings.
    state.auth.sso = saved.active ? { name: saved.name, url: `${location.origin}/sso/start`, required: saved.require_sso } : null;
    toast('Single sign-on saved');
  },
  field('Provider', provider, { hint: help }),
  issuerField, tenantField, teamField, labelField,
  h('div', { class: 'field' }, h('span', { class: 'field-label' }, 'Redirect URI'), copyField(s.redirect_uri, { label: 'Redirect URI' }),
    h('p', { class: 'field-hint' }, 'Register this in the provider’s app. It changes if the workspace’s address does.')),
  h('div', { class: 'grid-2' }, field('Client ID', clientId), field('Client secret', clientSecret, { hint: 'Stored encrypted and never shown again.' })),
  domainsField,
  h('fieldset', { class: 'field fieldset' }, h('legend', { class: 'field-label' }, 'Sign-in'), h('div', { class: 'stack' }, enabled, autoProvision, requireSso),
    h('p', { class: 'field-hint' }, 'API tokens and MCP connections keep working either way. Admins keep their password in case the provider is down.')),
  checks,
  h('div', null, button('Save single sign-on', { variant: 'primary', type: 'submit' })));

  const linked = await api.get('/sso/identities', { user: 'all' });
  const reload = () => ctx.reload();
  const row = (i) => {
    const unlink = button('Unlink', { size: 'xs', variant: 'ghost', cls: 'text-danger' });
    unlink.addEventListener('click', async () => {
      const ok = await confirmDialog({ title: `Unlink ${i.user.name}’s account?`, message: 'It can’t sign in here until it’s linked again, or matched by a verified email on its next sign-in.', confirmLabel: 'Unlink', danger: true });
      if (!ok) return;
      busy(unlink, async () => {
        await api.del(`/sso/identities/${enc(i.id)}`);
        toast('Account unlinked');
        reload();
      }).catch(toastError);
    });
    return h('li', { class: 'person' },
      avatar(i.user, 'sm'),
      h('div', { class: 'person-main' },
        h('div', { class: 'person-head' }, h('span', { class: 'person-name' }, i.user.name), i.current ? null : badge('Old provider', 'trash')),
        h('div', { class: 'person-meta' }, h('span', null, i.email || i.issuer), h('span', null, 'Linked ', timeEl(i.linked_at)), i.last_used_at ? h('span', null, 'Used ', timeEl(i.last_used_at)) : null)),
      unlink);
  };
  return frag(
    panel('Single sign-on', 'People sign in with your organization’s identity provider. You register an app with the provider and paste its details here.', status, f),
    panel('Linked accounts', 'Accounts at the provider that sign in as people here.',
      linked.items.length ? h('ul', { class: 'people-list' }, linked.items.map(row)) : h('p', { class: 'muted small' }, 'Nobody has signed in with single sign-on yet.')));
}

// ---------------------------------------------------------------------------
// Webhooks (admins)

function addWebhookDialog(onDone) {
  const url = input({ type: 'url', required: true, placeholder: 'https://example.com/hooks/dumbslab' });
  const events = input({ value: '*', spellcheck: 'false' });
  const desc = input({ placeholder: 'Optional' });
  modal({
    title: 'Add a webhook',
    content: frag(
      field('URL', url, { hint: 'Each matching event is POSTed here as JSON.' }),
      field('Events', events, { hint: 'Use * for everything, post.* for all post events, or a list like post.created, comment.created.' }),
      field('Description', desc)),
    actions: [
      { label: 'Cancel', variant: 'ghost' },
      {
        label: 'Add webhook',
        variant: 'primary',
        onClick: async () => {
          if (!url.value.trim()) {
            url.focus();
            toast('Enter the URL to deliver to.', { type: 'error' });
            return false;
          }
          const list = events.value.split(',').map((s) => s.trim()).filter(Boolean);
          const r = await api.post('/webhooks', { url: url.value.trim(), events: list.length ? list : undefined, description: desc.value.trim() || undefined });
          setTimeout(() => {
            secretDialog({
              title: 'Webhook added',
              intro: 'Use this signing secret to check that deliveries come from DumbSlab.',
              secret: r.secret,
              extra: h('p', { class: 'field-hint' }, 'Each delivery has x-dumbslab-timestamp and x-dumbslab-signature: sha256=HMAC_SHA256(secret, timestamp + "." + body).'),
            }).then(onDone);
          }, 0);
          return true;
        },
      },
    ],
  });
}

async function webhooksSection(ctx) {
  const r = await api.get('/webhooks');
  const reload = () => ctx.reload();
  const add = button('Add webhook', { icon: 'plus', variant: 'primary', size: 'sm', onClick: () => addWebhookDialog(reload) });
  const row = (w) => {
    const toggle = h('input', { type: 'checkbox', role: 'switch', class: 'switch', checked: w.active, 'aria-label': `Active: ${w.url}` });
    toggle.addEventListener('change', async () => {
      try {
        const updated = await api.patch(`/webhooks/${enc(w.id)}`, { active: toggle.checked });
        w.active = updated.active;
        toast(updated.active ? 'Webhook turned on' : 'Webhook paused');
      } catch (e) {
        toggle.checked = w.active;
        toastError(e);
      }
    });
    const del = button('', { icon: 'trash', variant: 'ghost', size: 'xs', 'aria-label': `Delete webhook ${w.url}`, title: 'Delete' });
    del.addEventListener('click', async () => {
      const ok = await confirmDialog({ title: 'Delete this webhook?', message: `Events will stop going to ${w.url}.`, confirmLabel: 'Delete', danger: true });
      if (!ok) return;
      busy(del, async () => {
        await api.del(`/webhooks/${enc(w.id)}`);
        toast('Webhook deleted');
        reload();
      }).catch(toastError);
    });
    const ok = w.last_status && w.last_status >= 200 && w.last_status < 300;
    const last = w.last_delivery_at
      ? h('span', { class: ok ? 'status-ok' : 'status-bad' }, icon(ok ? 'checkCircle' : 'alert', { size: 13 }), `Last delivery ${w.last_status ?? 'failed'}`, ' ', timeEl(w.last_delivery_at))
      : h('span', { class: 'muted' }, 'No deliveries yet');
    return h('li', { class: 'webhook' },
      h('label', { class: 'switch-wrap', title: w.active ? 'Active' : 'Paused' }, toggle, h('span', { class: 'switch-ui', 'aria-hidden': 'true' })),
      h('div', { class: 'webhook-main' },
        h('code', { class: 'webhook-url' }, w.url),
        w.description ? h('p', { class: 'small' }, w.description) : null,
        h('div', { class: 'token-meta' }, h('span', null, 'Events: ', h('code', null, w.events)), last),
        w.last_error ? h('p', { class: 'form-error small' }, w.last_error) : null),
      del);
  };
  return panel('Webhooks', 'Send workspace events to other systems as they happen. Deliveries are signed with a secret.',
    h('div', null, add),
    r.items.length ? h('ul', { class: 'webhook-list' }, r.items.map(row)) : emptyState({ iconName: 'zap', title: 'No webhooks', body: 'Add one to tell another system when posts or comments change.' }));
}

// ---------------------------------------------------------------------------
// Workspace (admins)

async function workspaceSection() {
  const s = await api.get('/settings');
  const name = input({ required: true, maxlength: '80', value: s.workspace_name });
  const welcome = textarea({ rows: 4, value: s.welcome_message, placeholder: 'For example: Start with the Getting Started topic. Ask in #docs if you can’t find something.' });
  const days = input({ type: 'number', min: '0', max: '3650', value: String(s.default_verification_days) });
  const f = form(async () => {
    const updated = await api.patch('/settings', { workspace_name: name.value.trim(), welcome_message: welcome.value, default_verification_days: Number(days.value) });
    state.settings = updated;
    emit('settings', updated);
    toast('Workspace saved');
  },
  field('Workspace name', name),
  field('Welcome message', welcome, { hint: 'Shown on everyone’s home page.' }),
  field('Default verification period (days)', days, { hint: 'How long a verification lasts before a post needs review. 0 means it never expires.' }),
  h('div', null, button('Save workspace', { variant: 'primary', type: 'submit' })));

  const exportBtn = button('Download export', { icon: 'download', variant: 'subtle', size: 'sm' });
  exportBtn.addEventListener('click', () => busy(exportBtn, async () => {
    const data = await api.get('/export');
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const a = h('a', { href: URL.createObjectURL(blob), download: `dumbslab-export-${new Date().toISOString().slice(0, 10)}.json` });
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
    toast(`Exported ${plural(data.posts.length, 'post')}`);
  }).catch(toastError));

  return frag(
    panel('Workspace', null, f),
    s.address ? addressPanel(s.address) : null,
    panel('Export','Download every topic, post (as Markdown), comment and person as JSON, for backups or moving elsewhere.', h('div', null, exportBtn)));
}

/** Hosted workspaces: move to another subdomain. */
function addressPanel(current) {
  const root = location.host.slice(current.length + 1);
  const address = input({
    id: 'settings-address', required: true, value: current, minlength: '3', maxlength: '32',
    pattern: '[a-z0-9]+(-[a-z0-9]+)*', spellcheck: 'false', autocapitalize: 'off', 'aria-describedby': 'settings-address-hint',
  });
  address.addEventListener('input', () => { address.value = address.value.toLowerCase().replace(/[^a-z0-9-]/g, ''); });
  const f = form(async () => {
    const next = address.value.trim();
    if (next === current) {
      toast('The workspace is already at that address.');
      return;
    }
    const ok = await confirmDialog({
      title: 'Change the address?',
      message: `Move this workspace to ${next}.${root}? Everyone signs in again there, and AI tools need the new MCP URL. ${current}.${root} will send people to the new address.`,
      confirmLabel: 'Change address',
    });
    if (!ok) return;
    const r = await api.post('/settings/address', { address: next });
    toast(`Moved to ${r.address}.${root}. Taking you there…`);
    setTimeout(() => location.assign(`${r.url}/login?next=${encodeURIComponent('/settings/workspace')}`), 1200);
  },
  h('div', { class: 'field' },
    h('label', { class: 'field-label', for: address.id }, 'Address'),
    h('div', { class: 'input-suffix' }, address, h('span', { class: 'input-suffix-text' }, `.${root}`)),
    h('p', { class: 'field-hint', id: 'settings-address-hint' }, '3 to 32 lowercase letters, numbers or single hyphens.')),
  h('div', null, button('Change address', { variant: 'subtle', type: 'submit' })));
  return panel('Address', 'Your workspace’s web address. Posts, people and API tokens all move with it. Everyone signs in again at the new address, and the old one keeps sending people there.', f);
}

// ---------------------------------------------------------------------------
// Plan (hosted workspaces)

function formatBytes(n) {
  if (n < 1024 * 1024) return `${Math.max(1, Math.round(n / 1024))} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(n < 10 * 1024 * 1024 ? 1 : 0)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(1).replace(/\.0$/, '')} GB`;
}

const count = (n) => n.toLocaleString('en-US');

function usageRow(label, used, limit, text, hint) {
  const share = limit > 0 ? used / limit : 0;
  const level = share >= 1 ? 'full' : share >= 0.8 ? 'high' : 'ok';
  return h('div', { class: 'usage' },
    h('div', { class: 'usage-head' }, h('span', { class: 'usage-label' }, label), h('span', { class: 'usage-value' }, text)),
    h('div', { class: ['usage-bar', `usage-${level}`], role: 'meter', 'aria-label': label, 'aria-valuemin': '0', 'aria-valuemax': String(limit), 'aria-valuenow': String(Math.min(used, limit)), 'aria-valuetext': text },
      h('span', { class: 'usage-fill', style: `width: ${Math.min(100, share * 100).toFixed(1)}%` })),
    hint ? h('p', { class: 'field-hint' }, hint) : null);
}

function allowanceList(a) {
  return h('ul', { class: 'plan-list' },
    h('li', null, `${formatBytes(a.storage_bytes)} of storage, uploads included`),
    h('li', null, `${count(a.writes_per_day)} database writes a day`),
    h('li', null, 'Everything else: MCP, the API, webhooks, people and bots'));
}

const dayFmt = new Intl.DateTimeFormat(undefined, { month: 'long', day: 'numeric', year: 'numeric' });
const day = (unix) => (unix ? dayFmt.format(new Date(unix * 1000)) : '');

async function planSection() {
  const p = await api.get('/plan');
  const query = new URLSearchParams(location.search);
  const justPaid = query.get('checkout') === 'done';
  const look = Number(query.get('look') || 0);
  if (justPaid && p.plan !== 'pro' && look < 10) {
    // Stripe tells DumbSlab a moment after the payment; look again shortly (a new URL re-renders).
    setTimeout(() => {
      if (location.pathname === '/settings/plan') navigate(`/settings/plan?checkout=done&look=${look + 1}`, { replace: true });
    }, 3000);
  }
  const sub = p.subscription;
  const pro = p.plan === 'pro';
  const a = p.allowance;
  const u = p.usage;

  const usage = panel('Usage',
    `This workspace is on the ${pro ? 'Pro' : 'Free'} plan. Every feature is on every plan; plans differ only in how much a workspace stores and how much it writes in a day, the two things that cost money to run.`,
    h('div', { class: 'stack' },
      usageRow('Storage', u.storage_bytes, a.storage_bytes, `${formatBytes(u.storage_bytes)} of ${formatBytes(a.storage_bytes)}`,
        'Past this, new posts, edits and uploads that need more room are refused. Deleting old files or posts frees space.'),
      usageRow('Writes in the last 24 hours', u.writes_24h, a.writes_per_day, `${count(u.writes_24h)} of ${count(a.writes_per_day)}`,
        'Every database row a change writes counts: an edit writes about 10, a new post about 20. Past the allowance, changes pause until it refills, hour by hour. Reading always works.')));

  const parts = [];
  if (justPaid) {
    parts.push(h('p', { class: 'callout', role: 'status' }, icon('check'),
      h('span', null, pro ? 'Thanks! This workspace is on Pro.' : 'Thanks! Pro turns on as soon as Stripe confirms the payment, usually within a minute.')));
  }
  if (sub && sub.status === 'past_due') {
    parts.push(h('p', { class: 'callout callout-warn', role: 'alert' }, icon('alert'),
      h('span', null, 'The last payment didn’t go through. Stripe will try again; update the card under Manage billing to keep Pro.')));
  }
  parts.push(usage);

  const manage = button('Manage billing', { icon: 'external', variant: 'subtle' });
  manage.addEventListener('click', () => busy(manage, async () => {
    const r = await api.post('/plan/billing');
    location.assign(r.url);
  }).catch(toastError));

  if (pro && p.granted) {
    parts.push(panel('Pro, on the house', 'DumbSlab gave this workspace Pro. There’s nothing to pay.', allowanceList(a)));
  } else if (pro) {
    const when = sub && sub.period_end ? (sub.cancel_at_period_end ? `Pro ends on ${day(sub.period_end)}; it won’t renew.` : `Renews on ${day(sub.period_end)}.`) : '';
    parts.push(panel(`Pro, ${p.pro.price}`, when, allowanceList(a), h('div', null, manage)));
  } else {
    const upgrade = button('Upgrade to Pro', { icon: 'zap', variant: 'primary' });
    upgrade.addEventListener('click', () => busy(upgrade, async () => {
      const r = await api.post('/plan/upgrade');
      location.assign(r.url);
    }).catch(toastError));
    const actions = p.pro.available
      ? h('div', { class: 'plan-actions' }, upgrade, sub ? manage : null)
      : h('p', { class: 'muted small' }, 'Pro isn’t on sale yet. Until then, delete old files to make room, or export the workspace and self-host DumbSlab, which has no limits.');
    parts.push(panel(`Pro, ${p.pro.price}`, 'For workspaces that need more room. Payments go through Stripe; cancel any time and Pro lasts until the end of the paid month.', allowanceList(p.pro.allowance), actions));
  }
  return frag(...parts);
}

const RENDER = {
  profile: profileSection,
  agents: agentsSection,
  tokens: tokensSection,
  connections: connectionsSection,
  people: peopleSection,
  sso: ssoSection,
  webhooks: webhooksSection,
  workspace: workspaceSection,
  plan: planSection,
};
