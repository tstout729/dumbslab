// Settings › People sync (BambooHR) and Settings › Docs sync (GitHub, GitLab), for admins.

import { api, enc, request } from '/api.js';
import {
  h, icon, button, busy, toast, toastError, confirmDialog, secretDialog, field, input, select, emptyState, timeEl, copyField, frag, plural,
} from '/ui.js';

function panel(title, description, ...body) {
  return h('section', { class: 'panel' },
    h('header', { class: 'panel-head' }, h('h2', { class: 'panel-title' }, title), description ? h('p', { class: 'panel-desc' }, description) : null),
    ...body);
}

function off(what) {
  return h('section', { class: 'panel' }, emptyState({ iconName: 'plug', title: `${what} isn’t available here`,
    body: 'The server needs a connector key to encrypt the credentials a sync uses. Whoever runs it can set CONNECTOR_KEY (or DUMBSLAB_CONNECTOR_KEY when self-hosting).' }));
}

/** Where a sync stands: running, how the last one went, and when. */
function stateLine(s) {
  if (s.running) return h('span', { class: 'muted' }, icon('refresh', { size: 13 }), ' Syncing now…');
  if (!s.last_status) return h('span', { class: 'muted' }, 'Not synced yet');
  const good = s.last_status === 'ok';
  const label = { ok: 'Synced', partial: 'Partly synced', failed: 'Last sync failed' }[s.last_status] || s.last_status;
  return h('span', { class: good ? 'status-ok' : 'status-bad' }, icon(good ? 'checkCircle' : 'alert', { size: 13 }), label, ' ',
    timeEl(s.last_finished_at || s.last_started_at));
}

function stateNotes(s) {
  return frag(
    s.last_error ? h('p', { class: 'form-error small' }, s.last_error) : null,
    s.pending && !s.running ? h('p', { class: 'small muted' }, 'A change was reported while the last sync ran. Sync again to be sure it’s in.') : null);
}

// ---------------------------------------------------------------------------
// People sync

function peopleResult(r) {
  if (!r) return null;
  const facts = [
    `${plural(r.employees, 'employee')} read`,
    `${r.matched} matched`,
    `${r.updated} updated`,
    r.skipped ? `${r.skipped} skipped` : null,
    r.without_record ? `${plural(r.without_record, 'person', 'people')} here without a BambooHR record` : null,
  ].filter(Boolean);
  return frag(
    h('p', { class: 'small' }, facts.join(' · ')),
    r.truncated ? h('p', { class: 'small form-error' }, 'BambooHR has more active employees than one sync reads (7,500).') : null,
    r.not_found_count
      ? h('details', { class: 'small' },
        h('summary', null, `${plural(r.not_found_count, 'employee')} not in this workspace`),
        h('ul', { class: 'plan-list' }, r.not_found.map((p) => h('li', null, `${p.name} `, h('span', { class: 'muted' }, p.email)))),
        r.not_found_count > r.not_found.length ? h('p', { class: 'muted' }, `and ${r.not_found_count - r.not_found.length} more`) : null)
      : null);
}

export async function peopleSyncSection(ctx) {
  const s = await api.get('/people-sync');
  if (!s.enabled) return off('People sync');
  const reload = () => ctx.reload();
  const subdomain = input({ required: true, value: s.subdomain || '', placeholder: 'acme', spellcheck: 'false', autocapitalize: 'off' });
  const apiKey = input({ type: 'password', required: !s.configured, placeholder: s.configured ? 'Saved. Leave empty to keep it.' : '', spellcheck: 'false' });
  const hookKey = input({ type: 'password', placeholder: s.webhook ? 'Saved. Leave empty to keep it.' : 'Optional', spellcheck: 'false' });
  const save = button(s.configured ? 'Save' : 'Save and sync', { variant: 'primary', type: 'submit' });
  const f = h('form', { class: 'stack token-form', novalidate: true },
    field('BambooHR company domain', subdomain, { hint: 'The acme in acme.bamboohr.com.' }),
    field('API key', apiKey, { hint: 'In BambooHR: your name › API Keys › Add new key. Its user must be able to see employees’ work emails and job details. It’s encrypted and never shown again.' }),
    field('Webhook private key (optional)', hookKey, { hint: frag('To sync when someone changes in BambooHR, add a webhook in BambooHR (Settings › Webhooks) that posts to the address below, and paste its private key here.') }),
    copyField(s.webhook_url, { label: 'Webhook address' }),
    h('div', null, save));
  f.addEventListener('submit', (e) => {
    e.preventDefault();
    if (!f.checkValidity()) {
      f.reportValidity();
      return;
    }
    busy(save, async () => {
      const body = { subdomain: subdomain.value.trim() };
      if (apiKey.value.trim()) body.api_key = apiKey.value.trim();
      if (hookKey.value.trim()) body.webhook_key = hookKey.value.trim();
      await request('PUT', '/people-sync', { body });
      toast('People sync saved');
      if (!s.configured) await runPeople();
      reload();
    }).catch(toastError);
  });

  const runPeople = async () => {
    const r = await api.post('/people-sync/run');
    toast(`Synced from BambooHR: ${plural(r.updated, 'profile')} updated`);
  };
  const run = button('Sync now', { icon: 'refresh', variant: 'subtle', size: 'sm' });
  run.addEventListener('click', () => busy(run, async () => { await runPeople(); reload(); }).catch((e) => { toastError(e); reload(); }));
  const remove = button('Remove', { variant: 'ghost', size: 'sm' });
  remove.addEventListener('click', async () => {
    const ok = await confirmDialog({ title: 'Remove the people sync?', message: 'DumbSlab forgets the BambooHR key. Details already synced stay on people’s profiles.', confirmLabel: 'Remove', danger: true });
    if (!ok) return;
    busy(remove, async () => { await api.del('/people-sync'); toast('People sync removed'); reload(); }).catch(toastError);
  });

  const status = s.configured
    ? panel('Status', null,
      h('div', { class: 'token-meta' }, stateLine(s), s.webhook ? h('span', null, icon('zap', { size: 13 }), ' Webhook on') : null),
      stateNotes(s),
      peopleResult(s.last_result),
      h('div', { class: 'plan-actions' }, run, remove))
    : null;
  return frag(
    panel('People sync', 'Fill in people’s title, department, location, work phone, pronouns and manager from BambooHR. People are matched by email to their BambooHR work email; a sync never adds, deactivates or removes anyone, and changes only those details.', f),
    status);
}

// ---------------------------------------------------------------------------
// Docs sync

function docsResult(r) {
  if (!r) return null;
  const facts = [
    `${plural(r.files, 'file')}`,
    r.created ? `${r.created} new` : null,
    r.updated ? `${r.updated} updated` : null,
    r.renamed ? `${r.renamed} moved` : null,
    r.archived ? `${r.archived} archived` : null,
    r.restored ? `${r.restored} restored` : null,
    r.images_uploaded ? `${plural(r.images_uploaded, 'image')} uploaded` : null,
    r.remaining ? `${r.remaining} still to sync` : null,
  ].filter(Boolean);
  return frag(
    h('p', { class: 'small' }, facts.join(' · ')),
    r.skipped && r.skipped.length
      ? h('details', { class: 'small' }, h('summary', null, `${plural(r.skipped.length, 'file')} skipped`),
        h('ul', { class: 'plan-list' }, r.skipped.map((x) => h('li', null, h('code', null, x.path), ` ${x.reason}`))))
      : null);
}

/** Syncs until everything is in (a run takes at most 20 changed files), showing progress. */
async function syncAll(source, onProgress) {
  let total = { created: 0, updated: 0 };
  for (let round = 0; round < 40; round++) {
    const r = await api.post(`/docs-sources/${enc(source.id)}/sync`);
    total = { created: total.created + r.created, updated: total.updated + r.updated };
    if (r.done || !r.remaining) return { ...r, ...total };
    onProgress(`Synced ${total.created + total.updated} so far, ${r.remaining} to go…`);
  }
  return null;
}

function webhookHelp(source) {
  const steps = source.provider === 'github'
    ? ['In the repository on GitHub: Settings › Webhooks › Add webhook.', 'Payload URL: the address below. Content type: application/json.', 'Secret: this secret. Events: just the push event.']
    : ['In the project on GitLab: Settings › Webhooks › Add new webhook.', 'URL: the address below.', 'Secret token: this secret. Trigger: Push events.'];
  return frag(h('ol', { class: 'plan-list' }, steps.map((s) => h('li', null, s))), copyField(source.webhook_url, { label: 'Webhook address' }));
}

function showSecret(source, secret) {
  return secretDialog({ title: 'Sync on every push', intro: 'Add a webhook so each push to the branch syncs. Use this secret:', secret, extra: webhookHelp(source) });
}

/** How a source connects, for its card. */
function connectionMeta(source) {
  if (source.connection === 'github_app') return h('span', null, icon('plug', { size: 13 }), ' Through DumbSlab’s GitHub App');
  if (source.connection === 'gitlab_oauth') return h('span', null, icon('plug', { size: 13 }), ' Through DumbSlab’s GitLab app');
  return source.has_token ? h('span', null, icon('key', { size: 13 }), ' Token saved') : h('span', null, 'No token (public repository)');
}

/**
 * A GitLab app folder that can't sync (GitLab stopped accepting its approval, or whoever approved it
 * lost access to the project): reconnect it with a new approval, perhaps another maintainer's.
 * Reconnecting also puts its webhook right.
 */
function reconnect(source, gitlab, reload) {
  const stuck = source.disconnected || source.last_status === 'failed';
  if (source.connection !== 'gitlab_oauth' || !stuck || !gitlab || !gitlab.available) return null;
  if (!gitlab.connected) return connectLink(gitlab.connect_url, 'Connect GitLab', 'subtle');
  const b = button(`Reconnect with ${gitlab.account}`, { variant: 'primary', size: 'sm' });
  b.addEventListener('click', () => busy(b, async () => {
    await api.patch(`/docs-sources/${enc(source.id)}`, { gitlab_connection: true });
    toast('Reconnected');
    reload();
  }).catch(toastError));
  return b;
}

function sourceCard(source, reload, gitlab) {
  const where = `${source.repository}${source.folder ? `/${source.folder}` : ''}`;
  const app = source.connection !== 'token';
  const run = button('Sync now', { icon: 'refresh', variant: 'subtle', size: 'sm', disabled: Boolean(source.disconnected) });
  const progress = h('span', { class: 'small muted', role: 'status' });
  run.addEventListener('click', () => busy(run, async () => {
    const r = await syncAll(source, (text) => { progress.textContent = text; });
    toast(r ? `Synced ${where}: ${r.created} new, ${r.updated} updated` : 'Synced part of the folder; sync again to continue');
    reload();
  }).catch((e) => { toastError(e); reload(); }));
  const token = button(source.has_token ? 'Change token' : 'Add token', { variant: 'ghost', size: 'sm' });
  const tokenInput = input({ type: 'password', placeholder: 'Leave empty to remove the token', spellcheck: 'false' });
  const tokenSave = button('Save token', { variant: 'primary', size: 'sm', type: 'submit' });
  const tokenForm = h('form', { class: 'stack token-form', novalidate: true, hidden: true }, field('Token', tokenInput, { hint: tokenHint(source.provider) }), h('div', null, tokenSave));
  token.addEventListener('click', () => { tokenForm.hidden = false; tokenInput.focus(); });
  tokenForm.addEventListener('submit', (e) => {
    e.preventDefault();
    busy(tokenSave, async () => {
      await api.patch(`/docs-sources/${enc(source.id)}`, { token: tokenInput.value.trim() });
      toast(tokenInput.value.trim() ? 'Token saved' : 'Token removed');
      reload();
    }).catch(toastError);
  });
  const rotate = button('New webhook secret', { variant: 'ghost', size: 'sm' });
  rotate.addEventListener('click', async () => {
    const ok = await confirmDialog({ title: 'Make a new webhook secret?', message: `The current secret stops working. Update the webhook in ${source.provider === 'github' ? 'GitHub' : 'GitLab'} with the new one.`, confirmLabel: 'Make a new secret' });
    if (!ok) return;
    busy(rotate, async () => {
      const r = await api.patch(`/docs-sources/${enc(source.id)}`, { new_webhook_secret: true });
      await showSecret(r.source, r.webhook_secret);
    }).catch(toastError);
  });
  const remove = button('Remove', { variant: 'ghost', size: 'sm' });
  remove.addEventListener('click', async () => {
    const ok = await confirmDialog({ title: `Stop syncing ${where}?`, message: app ? 'The synced posts and topics stay, and become ordinary posts anyone with access can edit.' : 'DumbSlab forgets the token. The synced posts and topics stay, and become ordinary posts anyone with access can edit.', confirmLabel: 'Stop syncing', danger: true });
    if (!ok) return;
    busy(remove, async () => { await api.del(`/docs-sources/${enc(source.id)}`); toast('Docs sync removed'); reload(); }).catch(toastError);
  });
  const link = (url, label) => h('a', { href: url, target: '_blank', rel: 'noopener noreferrer' }, label);
  return h('div', { class: 'app-card' },
    h('div', { class: 'app-head' },
      h('div', null,
        h('p', { class: 'app-name' }, link(source.folder_url, where)),
        h('p', { class: 'muted small' }, `${source.provider === 'github' ? 'GitHub' : `GitLab (${source.host})`}, branch ${source.branch} → `,
          source.topic ? h('a', { href: new URL(source.topic.url).pathname }, source.topic.name) : 'a deleted topic')),
      h('span', { class: 'badge' }, plural(source.synced_files, 'post'))),
    h('div', { class: 'app-body' },
      h('div', { class: 'token-meta' }, stateLine(source), connectionMeta(source)),
      source.disconnected ? h('p', { class: 'form-error small' }, source.disconnected) : null,
      stateNotes(source),
      docsResult(source.last_result),
      app ? null : h('details', { class: 'small' }, h('summary', null, 'Sync on every push'), webhookHelp(source),
        h('p', { class: 'muted' }, 'The secret was shown when the source was added. Make a new one if you don’t have it.')),
      h('div', { class: 'plan-actions' }, reconnect(source, gitlab, reload), run, app ? null : token, app ? null : rotate, remove, progress),
      app ? null : tokenForm));
}

function tokenHint(provider) {
  return provider === 'github'
    ? 'A fine-grained personal access token with read-only access to the repository’s Contents (github.com › Settings › Developer settings). Leave out for public repositories.'
    : 'A personal, group or project access token with the read_api scope. Leave out for public projects.';
}

function topicSelect(topics) {
  return select([{ value: '', label: 'Choose a topic…' }, ...topics.map((t) => ({ value: t.id, label: t.label }))], { required: true });
}

/** Syncs a new source, then reloads. A token source shows its webhook secret afterwards. */
async function firstSync(created, progress, reload) {
  progress.textContent = 'Syncing…';
  try {
    const done = await syncAll(created.source, (text) => { progress.textContent = text; });
    toast(done ? `Synced ${plural(done.created, 'post')}` : 'Synced part of the folder; sync again to continue');
  } catch (err) {
    toastError(err);
  }
  if (created.webhook_secret) await showSecret(created.source, created.webhook_secret);
  reload();
}

function tokenSourceForm(topics, reload) {
  const provider = select([{ value: 'github', label: 'GitHub' }, { value: 'gitlab', label: 'GitLab' }]);
  const repository = input({ required: true, placeholder: 'acme/handbook', spellcheck: 'false', autocapitalize: 'off' });
  const host = input({ placeholder: 'https://gitlab.example.com', spellcheck: 'false', type: 'url' });
  const hostField = field('GitLab address (self-managed only)', host, { hint: 'Leave empty for gitlab.com.' });
  const branch = input({ value: 'main', required: true, spellcheck: 'false' });
  const folder = input({ placeholder: 'docs', spellcheck: 'false' });
  const topic = topicSelect(topics);
  const token = input({ type: 'password', spellcheck: 'false' });
  const tokenField = field('Token (private repositories)', token, { hint: tokenHint('github') });
  const sync = () => {
    const gh = provider.value === 'github';
    hostField.hidden = gh;
    repository.placeholder = gh ? 'acme/handbook' : 'group/project';
    tokenField.querySelector('.field-hint').textContent = tokenHint(provider.value);
  };
  provider.addEventListener('change', sync);
  sync();
  const submit = button('Add and sync', { variant: 'primary', type: 'submit' });
  const progress = h('span', { class: 'small muted', role: 'status' });
  const f = h('form', { class: 'stack token-form', novalidate: true },
    field('From', provider),
    field('Repository', repository, { hint: 'owner/name, a GitLab project’s path, or the repository’s web address.' }),
    hostField,
    field('Branch', branch),
    field('Folder', folder, { hint: 'The folder whose Markdown files to sync, with its sub-folders. Leave empty for the whole repository.' }),
    field('Topic', topic, { hint: 'Posts go here; sub-folders become sub-topics with the same visibility.' }),
    tokenField,
    h('div', { class: 'plan-actions' }, submit, progress));
  f.addEventListener('submit', (e) => {
    e.preventDefault();
    if (!f.checkValidity()) {
      f.reportValidity();
      return;
    }
    busy(submit, async () => {
      const body = { provider: provider.value, repository: repository.value.trim(), branch: branch.value.trim(), folder: folder.value.trim(), topic_id: topic.value };
      if (token.value.trim()) body.token = token.value.trim();
      if (provider.value === 'gitlab' && host.value.trim()) body.host = host.value.trim();
      await firstSync(await api.post('/docs-sources', body), progress, reload);
    }).catch(toastError);
  });
  return f;
}

/** Picking a repository DumbSlab's GitHub App reads: no token, no webhook. */
function githubSourceForm(github, topics, reload) {
  const picks = new Map();
  const repository = h('select', { class: 'input select', required: true }, h('option', { value: '' }, 'Choose a repository…'));
  for (const i of github.installations.filter((x) => !x.suspended && x.repositories.length)) {
    const group = h('optgroup', { label: i.account });
    for (const r of i.repositories) {
      const value = `${i.installation_id}/${r.id}`;
      picks.set(value, { installation: i, repo: r });
      group.appendChild(h('option', { value }, `${r.full_name}${r.private ? ' (private)' : ''}`));
    }
    repository.appendChild(group);
  }
  const branch = input({ value: 'main', required: true, spellcheck: 'false' });
  repository.addEventListener('change', () => {
    const picked = picks.get(repository.value);
    if (picked) branch.value = picked.repo.default_branch;
  });
  const folder = input({ placeholder: 'docs', spellcheck: 'false' });
  const topic = topicSelect(topics);
  const submit = button('Add and sync', { variant: 'primary', type: 'submit' });
  const progress = h('span', { class: 'small muted', role: 'status' });
  const more = github.installations.some((i) => i.more_repositories)
    ? h('p', { class: 'small muted' }, 'Your GitHub account can read more repositories than are listed here; the first 500 are.')
    : null;
  const f = h('form', { class: 'stack token-form', novalidate: true },
    field('Repository', repository, { hint: 'Repositories DumbSlab’s GitHub App can read that your GitHub account can read too. To add one, choose Connect GitHub and give the app access to it.' }),
    more,
    field('Branch', branch),
    field('Folder', folder, { hint: 'The folder whose Markdown files to sync, with its sub-folders. Leave empty for the whole repository.' }),
    field('Topic', topic, { hint: 'Posts go here; sub-folders become sub-topics with the same visibility.' }),
    h('div', { class: 'plan-actions' }, submit, progress));
  f.addEventListener('submit', (e) => {
    e.preventDefault();
    if (!f.checkValidity()) {
      f.reportValidity();
      return;
    }
    const picked = picks.get(repository.value);
    busy(submit, async () => {
      const body = { provider: 'github', installation_id: picked.installation.installation_id, repository: picked.repo.full_name, branch: branch.value.trim(), folder: folder.value.trim(), topic_id: topic.value };
      await firstSync(await api.post('/docs-sources', body), progress, reload);
    }).catch(toastError);
  });
  return f;
}

/** Picking a gitlab.com project through DumbSlab's GitLab app, which adds the webhook itself. */
function gitlabSourceForm(gitlab, topics, reload) {
  const byId = new Map(gitlab.projects.map((p) => [String(p.id), p]));
  const project = select([{ value: '', label: 'Choose a project…' }, ...gitlab.projects.map((p) => ({ value: String(p.id), label: `${p.path}${p.visibility === 'public' ? '' : ` (${p.visibility})`}` }))], { required: true });
  const branch = input({ value: 'main', required: true, spellcheck: 'false' });
  project.addEventListener('change', () => {
    const picked = byId.get(project.value);
    if (picked && picked.default_branch) branch.value = picked.default_branch;
  });
  const folder = input({ placeholder: 'docs', spellcheck: 'false' });
  const topic = topicSelect(topics);
  const submit = button('Add and sync', { variant: 'primary', type: 'submit' });
  const progress = h('span', { class: 'small muted', role: 'status' });
  const f = h('form', { class: 'stack token-form', novalidate: true },
    field('Project', project, { hint: `Projects on gitlab.com where ${gitlab.account} has the Maintainer role, which adding a webhook needs.${gitlab.more ? ' The 300 most recently active are listed.' : ''}` }),
    field('Branch', branch),
    field('Folder', folder, { hint: 'The folder whose Markdown files to sync, with its sub-folders. Leave empty for the whole project.' }),
    field('Topic', topic, { hint: 'Posts go here; sub-folders become sub-topics with the same visibility.' }),
    h('div', { class: 'plan-actions' }, submit, progress));
  f.addEventListener('submit', (e) => {
    e.preventDefault();
    if (!f.checkValidity()) {
      f.reportValidity();
      return;
    }
    const picked = byId.get(project.value);
    busy(submit, async () => {
      const body = { provider: 'gitlab', gitlab_connection: true, repository: picked.path, branch: branch.value.trim(), folder: folder.value.trim(), topic_id: topic.value };
      await firstSync(await api.post('/docs-sources', body), progress, reload);
    }).catch(toastError);
  });
  return f;
}

/** Connect GitHub: a page on the server, so the browser goes there rather than this app routing it. */
function connectLink(url, label, variant) {
  return h('a', { class: ['btn', `btn-${variant}`, 'btn-sm'], href: new URL(url).pathname }, icon('plug'), h('span', null, label));
}

function githubBlock(github, topics, reload) {
  const usable = github.installations.some((i) => !i.suspended && i.repositories.length);
  const intro = usable
    ? 'Pick a repository. Choose Connect GitHub to install DumbSlab’s app on another account, or to give it more repositories.'
    : 'Choose Connect GitHub, install DumbSlab’s app on the repositories you want, and come back here to pick one. No token or webhook needed: pushes sync by themselves.';
  return h('div', { class: 'stack' },
    h('p', { class: 'app-name' }, 'GitHub'),
    h('p', { class: 'small muted' }, intro),
    usable ? githubSourceForm(github, topics, reload) : null,
    h('div', { class: 'plan-actions' }, connectLink(github.connect_url, 'Connect GitHub', usable ? 'subtle' : 'primary')));
}

function gitlabBlock(gitlab, topics, reload) {
  const intro = gitlab.connected
    ? `Pick a project ${gitlab.account} maintains on gitlab.com. DumbSlab adds its push webhook. Each folder takes its own approval, so choose Connect GitLab again for the next one.`
    : 'For gitlab.com: choose Connect GitLab and approve DumbSlab’s app, then pick a project. DumbSlab adds the webhook itself. A self-managed GitLab uses a token.';
  return h('div', { class: 'stack' },
    h('p', { class: 'app-name' }, 'GitLab'),
    h('p', { class: 'small muted' }, intro),
    gitlab.error ? h('p', { class: 'form-error small' }, gitlab.error) : null,
    gitlab.connected ? gitlabSourceForm(gitlab, topics, reload) : null,
    h('div', { class: 'plan-actions' }, connectLink(gitlab.connect_url, gitlab.connected ? 'Connect GitLab again' : 'Connect GitLab', gitlab.connected ? 'subtle' : 'primary')));
}

/** Adding a folder: through DumbSlab's GitHub or GitLab app when the server has them, or with a token. */
function addSource(github, gitlab, topics, reload) {
  const tokenForm = tokenSourceForm(topics, reload);
  const blocks = [github && github.available ? githubBlock(github, topics, reload) : null, gitlab && gitlab.available ? gitlabBlock(gitlab, topics, reload) : null].filter(Boolean);
  if (!blocks.length) return tokenForm;
  tokenForm.hidden = true;
  const useToken = button('Use a token instead', { variant: 'ghost', size: 'sm' });
  useToken.addEventListener('click', () => { tokenForm.hidden = false; useToken.remove(); });
  return h('div', { class: 'stack' }, ...blocks, h('div', { class: 'plan-actions' }, useToken), tokenForm);
}

/** Topics as an indented list, for choosing one. */
function topicOptions(list) {
  const byParent = new Map();
  for (const t of list) {
    const k = t.parent_id || '';
    if (!byParent.has(k)) byParent.set(k, []);
    byParent.get(k).push(t);
  }
  const out = [];
  const walk = (parent, depth) => {
    for (const t of byParent.get(parent) || []) {
      out.push({ id: t.id, label: `${'  '.repeat(depth)}${t.name}${t.visibility === 'private' ? ' (private)' : ''}` });
      walk(t.id, depth + 1);
    }
  };
  walk('', 0);
  return out;
}

// What the codes in `?connect_error=` mean, after Connect GitHub or GitLab. The link carries only
// a code, never a message: anyone can make a link to this page.
const connectErrors = {
  expired_link: (app) => `That link is no longer valid. Choose Connect ${app} again.`,
  too_slow: (app) => `Connecting took too long. Choose Connect ${app} again.`,
  wrong_person: (app) => `Finish connecting in the same browser, signed in as the admin who started it. Choose Connect ${app} again.`,
  not_admin: (app) => `Only admins can connect ${app} for docs sync.`,
  unavailable: (app) => `DumbSlab’s ${app} app isn’t set up on this server. Use a token instead.`,
  approval_requested: () => 'An owner of the GitHub organization has to approve DumbSlab’s app first; GitHub has asked them. Once they have, choose Connect GitHub again.',
  declined: (app) => `${app} didn’t allow access. Choose Connect ${app} again, and authorize DumbSlab when ${app} asks.`,
  no_code: (app) => `${app} didn’t finish connecting. Choose Connect ${app} again.`,
  not_yours: () => 'Your GitHub account can’t access that installation of DumbSlab’s app. Install it on an account or organization you manage, then try again.',
  failed: (app) => `Connecting ${app} didn’t work. Try again.`,
};

const appNames = { github: 'GitHub', gitlab: 'GitLab' };

function connectNotes() {
  const query = new URLSearchParams(location.search);
  const connected = query.get('connected');
  if (Object.hasOwn(appNames, connected)) {
    const what = connected === 'github' ? 'a repository' : 'a project';
    return h('p', { class: 'callout', role: 'status' }, icon('check', { size: 15 }), h('span', null, `${appNames[connected]} is connected. Pick ${what} below.`));
  }
  const code = query.get('connect_error');
  if (!code) return null;
  const app = Object.hasOwn(appNames, query.get('app')) ? appNames[query.get('app')] : 'the app';
  const say = Object.hasOwn(connectErrors, code) ? connectErrors[code](app) : 'Connecting didn’t work. Try again.';
  return h('p', { class: 'callout callout-warn', role: 'alert' }, icon('alert', { size: 15 }), h('span', null, say));
}

/** The GitLab projects the admin can pick, or why not. Listing asks GitLab, so it can fail. */
async function gitlabProjects() {
  try {
    return await api.get('/docs-sources/gitlab');
  } catch (err) {
    return { available: true, connected: false, connect_url: `${location.origin}/sync/gitlab/start`, projects: [], error: err.message || String(err) };
  }
}

export async function docsSyncSection(ctx) {
  const [list, topics] = await Promise.all([api.get('/docs-sources'), api.get('/topics')]);
  if (!list.enabled) return off('Docs sync');
  const [github, gitlab] = await Promise.all([
    list.github_app ? api.get('/docs-sources/github') : null,
    list.gitlab_app ? gitlabProjects() : null,
  ]);
  const reload = () => ctx.reload();
  const add = addSource(github, gitlab, topicOptions(topics.items), reload);
  const justConnected = Object.hasOwn(appNames, new URLSearchParams(location.search).get('connected'));
  add.hidden = list.items.length > 0 && !justConnected;
  const show = button('Add a folder', { icon: 'plus', variant: 'primary', size: 'sm', onClick: () => { add.hidden = false; show.remove(); } });
  return frag(
    connectNotes(),
    panel('Docs sync', 'Keep a GitHub or GitLab folder’s Markdown files as posts in a topic. Each file is a post, sub-folders become sub-topics, and relative links and images keep working. It’s one way: synced posts are edited in the repository, and each push brings the change here.',
      list.items.length ? h('div', { class: 'app-list' }, list.items.map((s) => sourceCard(s, reload, gitlab))) : null,
      list.items.length && add.hidden ? h('div', null, show) : null,
      add));
}
