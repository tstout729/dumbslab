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

/** Adding BambooHR's webhook by hand, for when DumbSlab can't add it itself. */
function manualWebhook(s, reload) {
  const manual = s.webhook && !s.automatic_webhook;
  const key = input({ type: 'password', required: true, placeholder: manual ? 'Saved. Paste a new one to replace it.' : '', spellcheck: 'false' });
  const save = button('Save private key', { variant: 'subtle', size: 'sm', type: 'submit' });
  const form = h('form', { class: 'stack token-form', novalidate: true },
    h('ol', { class: 'plan-list' },
      h('li', null, 'In BambooHR, open Settings › Webhooks and add a webhook.'),
      h('li', null, 'URL: the address below. Format: JSON.'),
      h('li', null, 'Fields to watch: Work Email, Job Title, Department, Location, Work Phone, Reporting To and Status.'),
      h('li', null, 'Save it, then paste its private key here.')),
    copyField(s.webhook_url, { label: 'Webhook address' }),
    field('Webhook private key', key),
    h('div', null, save));
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    if (!key.value.trim()) {
      key.reportValidity();
      return;
    }
    busy(save, async () => {
      await request('PUT', '/people-sync', { body: { subdomain: s.subdomain, webhook_key: key.value.trim() } });
      toast('Private key saved. Changes in BambooHR now start a sync.');
      reload();
    }).catch(toastError);
  });
  let automatic = null;
  if (manual) {
    automatic = button('Let DumbSlab add the webhook instead', { variant: 'ghost', size: 'sm' });
    automatic.addEventListener('click', () => busy(automatic, async () => {
      const r = await request('PUT', '/people-sync', { body: { subdomain: s.subdomain, webhook_key: '' } });
      if (r.automatic_webhook) toast('DumbSlab added the webhook in BambooHR. You can delete the one you added.');
      else toast('DumbSlab couldn’t add the webhook. See People sync for why.', { type: 'error' });
      reload();
    }).catch(toastError));
  }
  return h('details', { class: 'small', open: !s.webhook && !!s.webhook_error },
    h('summary', null, manual ? 'Webhook added by hand' : 'Add the webhook yourself'),
    h('p', { class: 'muted' }, 'Only needed when DumbSlab can’t add it for you.'),
    form,
    automatic);
}

// What the codes in `?people_sync_error=` mean. The link carries only a code, never a message:
// anyone can make a link to this page.
const signInErrors = {
  expired_link: 'That sign-in link is no longer valid. Start again.',
  wrong_person: 'Finish signing in from the same browser and DumbSlab account that started it.',
  not_admin: 'Only admins can set up the people sync.',
  too_slow: 'Signing in took too long. Start again.',
  unavailable: 'Sign in with BambooHR isn’t available on this server.',
  declined: 'BambooHR didn’t allow access. Try again, and allow access when BambooHR asks.',
  no_code: 'BambooHR didn’t finish signing in. Try again.',
  busy: 'Another change to the people sync was being saved. Try again in a minute.',
  refused: 'BambooHR didn’t accept the sign-in. Try again.',
  no_access: 'The BambooHR user who signed in can’t see employee information. Sign in as a user who can.',
  failed: 'Signing in with BambooHR didn’t work. Try again.',
};

/** How signing in went, from the link BambooHR sent the admin back with. Read once. */
function signInOutcome() {
  const query = new URLSearchParams(location.search);
  const connected = query.get('people_sync') === 'connected';
  const error = query.get('people_sync_error');
  if (connected || error) history.replaceState(null, '', location.pathname);
  if (connected) {
    // `old_webhook`: the webhook DumbSlab had added before is still to be deleted.
    const more = query.get('people_sync_notice') === 'old_webhook'
      ? ' DumbSlab couldn’t delete the webhook it had added in BambooHR before yet; it tries again after the next syncs.'
      : '';
    return { connected, note: h('p', { class: 'callout', role: 'status' }, icon('check', { size: 15 }), h('span', null, `Signed in with BambooHR.${more}`)) };
  }
  if (error) {
    const message = Object.hasOwn(signInErrors, error) ? signInErrors[error] : signInErrors.failed;
    return { connected, note: h('p', { class: 'callout callout-warn', role: 'alert' }, icon('alert', { size: 15 }), h('span', null, message)) };
  }
  return { connected, note: null };
}

export async function peopleSyncSection(ctx) {
  const s = await api.get('/people-sync');
  if (!s.enabled) return off('People sync');
  if (!s.sign_in_available && !s.api_key_allowed) {
    return h('section', { class: 'panel' }, emptyState({ iconName: 'plug', title: 'People sync isn’t available yet on this host',
      body: 'BambooHR’s terms let hosted services connect only through Sign in with BambooHR, and this host hasn’t registered its BambooHR app yet.' }));
  }
  const reload = () => ctx.reload();
  const outcome = signInOutcome();
  const runPeople = async () => {
    const r = await api.post('/people-sync/run');
    toast(`Synced from BambooHR: ${plural(r.updated, 'profile')} updated`);
  };
  // The first sync after signing in, as Save and sync does for API keys.
  if (outcome.connected && s.configured && !s.last_started_at) {
    runPeople().then(reload, (e) => { toastError(e); reload(); });
  }

  const subdomain = input({ required: true, value: s.subdomain || '', placeholder: 'acme', spellcheck: 'false', autocapitalize: 'off' });
  const domainField = field('BambooHR company domain', subdomain, { hint: 'The acme in acme.bamboohr.com. Pasting the address you sign in at works too.' });
  const checkDomain = () => {
    if (subdomain.value.trim()) return true;
    subdomain.reportValidity();
    return false;
  };

  let signIn = null;
  if (s.sign_in_available) {
    signIn = button(s.auth === 'oauth' ? 'Sign in with BambooHR again' : 'Sign in with BambooHR', { variant: 'primary' });
    signIn.addEventListener('click', () => {
      if (!checkDomain()) return;
      busy(signIn, async () => {
        const r = await api.post('/people-sync/sign-in', { subdomain: subdomain.value.trim() });
        location.assign(r.authorize_url);
      }).catch(toastError);
    });
  }

  let keyForm = null;
  if (s.api_key_allowed) {
    const apiKey = input({ type: 'password', required: !(s.configured && s.auth === 'api_key'), placeholder: s.configured && s.auth === 'api_key' ? 'Saved. Leave empty to keep it.' : '', spellcheck: 'false' });
    const save = button(s.configured ? 'Save' : 'Save and sync', { variant: s.sign_in_available ? 'subtle' : 'primary', type: 'submit' });
    keyForm = h('form', { class: 'stack token-form', novalidate: true },
      field('API key', apiKey, { hint: 'In BambooHR: your name › API Keys › Add new key. Its user must be able to see employees’ work emails and job details. DumbSlab checks the key with BambooHR, then adds a webhook there so changes sync on their own. It’s encrypted and never shown again.' }),
      h('div', null, save));
    keyForm.addEventListener('submit', (e) => {
      e.preventDefault();
      if (!checkDomain()) return;
      if (!keyForm.checkValidity()) {
        keyForm.reportValidity();
        return;
      }
      busy(save, async () => {
        const body = { subdomain: subdomain.value.trim() };
        if (apiKey.value.trim()) body.api_key = apiKey.value.trim();
        const r = await request('PUT', '/people-sync', { body });
        if (r.webhook) toast('People sync saved. Changes in BambooHR now start a sync.');
        else toast('People sync saved, but changes in BambooHR don’t start a sync yet. See below.', { type: 'info' });
        if (r.notice) toast(r.notice, { type: 'info' });
        if (!s.configured) await runPeople();
        reload();
      }).catch(toastError);
    });
  }

  const setup = h('div', { class: 'stack token-form' },
    domainField,
    signIn ? h('div', null, signIn) : null,
    signIn ? h('p', { class: 'small muted' }, 'You approve DumbSlab in BambooHR, then come back here. DumbSlab adds a webhook in BambooHR so changes sync on their own.') : null,
    keyForm && signIn ? h('details', { class: 'small', open: s.auth === 'api_key' }, h('summary', null, 'Use an API key instead'), keyForm) : keyForm);

  const run = button('Sync now', { icon: 'refresh', variant: 'subtle', size: 'sm' });
  run.addEventListener('click', () => busy(run, async () => { await runPeople(); reload(); }).catch((e) => { toastError(e); reload(); }));
  const remove = button('Remove', { variant: 'ghost', size: 'sm' });
  remove.addEventListener('click', async () => {
    const ok = await confirmDialog({ title: 'Remove the people sync?', message: 'DumbSlab deletes the webhook it added in BambooHR and forgets its BambooHR credentials. Details already synced stay on people’s profiles.', confirmLabel: 'Remove', danger: true });
    if (!ok) return;
    busy(remove, async () => {
      const r = await api.del('/people-sync');
      toast('People sync removed');
      if (r.notice) toast(r.notice, { type: 'info' });
      reload();
    }).catch(toastError);
  });
  // Saving again with the saved credentials: moves the webhook, or adds it once BambooHR allows.
  let again = null;
  if (s.configured && s.webhook_error) {
    again = button('Save again', { variant: 'subtle', size: 'sm' });
    again.addEventListener('click', () => busy(again, async () => {
      const r = await request('PUT', '/people-sync', { body: { subdomain: s.subdomain } });
      toast(r.webhook ? 'Saved. Changes in BambooHR now start a sync.' : 'Saved, but changes in BambooHR still don’t start a sync. See why below.', { type: r.webhook ? 'success' : 'info' });
      reload();
    }).catch(toastError));
  }

  const signedIn = s.auth === 'oauth' ? 'Signed in with BambooHR' : 'API key';
  const automatic = s.webhook
    ? h('span', null, icon('zap', { size: 13 }), s.automatic_webhook ? ' Syncs when BambooHR changes' : ' Syncs when BambooHR changes (webhook added by hand)')
    : null;
  const status = s.configured
    ? panel('Status', null,
      h('div', { class: 'token-meta' }, stateLine(s), h('span', null, `${signedIn} · ${s.subdomain}.bamboohr.com`), automatic),
      s.webhook_error ? h('p', { class: 'callout callout-warn' }, icon('alert', { size: 15 }), h('span', null, s.webhook_error)) : null,
      stateNotes(s),
      s.webhook_cleanup ? h('p', { class: 'small muted' }, 'DumbSlab is still deleting its old webhooks in BambooHR. It tries again after syncs and saves, and when you open this page. Meanwhile it turns their calls away; they carry no employee details.') : null,
      peopleResult(s.last_result),
      manualWebhook(s, reload),
      h('div', { class: 'plan-actions' }, run, again, remove))
    : null;
  return frag(
    outcome.note,
    panel('People sync', 'Fill in people’s title, department, location, work phone, pronouns and manager from BambooHR. People are matched by email to their BambooHR work email; a sync never adds, deactivates or removes anyone, and changes only those details.', setup),
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
    // A disconnected GitHub App folder: nothing synced; DumbSlab is asking GitHub again.
    if (r.checking) return r;
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
  return source.has_token ? h('span', null, icon('key', { size: 13 }), ' Token saved') : h('span', null, 'No token (public repository)');
}

function sourceCard(source, reload) {
  const where = `${source.repository}${source.folder ? `/${source.folder}` : ''}`;
  const app = source.connection !== 'token';
  // A disconnected GitHub App folder's Sync now asks GitHub again; others wait to be reconnected.
  const run = button('Sync now', { icon: 'refresh', variant: 'subtle', size: 'sm', disabled: Boolean(source.disconnected) && source.connection !== 'github_app' });
  const progress = h('span', { class: 'small muted', role: 'status' });
  run.addEventListener('click', () => busy(run, async () => {
    const r = await syncAll(source, (text) => { progress.textContent = text; });
    toast(r && r.checking ? r.checking : r ? `Synced ${where}: ${r.created} new, ${r.updated} updated` : 'Synced part of the folder; sync again to continue');
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
      h('div', { class: 'plan-actions' }, run, app ? null : token, app ? null : rotate, remove, progress),
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
  const full = github.installations.filter((i) => i.forwarding === 'full').map((i) => i.account);
  const unreachable = full.length
    ? h('p', { class: 'small form-error' }, `Pushes from ${full.join(', ')} don’t sync by themselves here: that installation of DumbSlab’s app already serves as many workspaces as it can. Sync now still works.`)
    : null;
  const f = h('form', { class: 'stack token-form', novalidate: true },
    field('Repository', repository, { hint: 'Repositories DumbSlab’s GitHub App can read that your GitHub account can read too. To add one, choose Connect GitHub and give the app access to it.' }),
    more,
    unreachable,
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
      // The repository's id decides which one is added; its name is for reading.
      const body = { provider: 'github', installation_id: picked.installation.installation_id, repository_id: picked.repo.id, repository: picked.repo.full_name, branch: branch.value.trim(), folder: folder.value.trim(), topic_id: topic.value };
      await firstSync(await api.post('/docs-sources', body), progress, reload);
    }).catch(toastError);
  });
  return f;
}

/** Connect GitHub: a page on the server, so the browser goes there rather than this app routing it. */
function connectLink(url, label, variant) {
  return h('a', { class: ['btn', `btn-${variant}`, 'btn-sm'], href: new URL(url).pathname }, icon('plug'), h('span', null, label));
}

/** Adding a folder: through DumbSlab's GitHub App when the server has it, or with a token. */
function addSource(github, topics, reload) {
  const tokenForm = tokenSourceForm(topics, reload);
  if (!github || !github.available) return tokenForm;
  const usable = github.installations.some((i) => !i.suspended && i.repositories.length);
  tokenForm.hidden = true;
  const useToken = button('Use a token instead', { variant: 'ghost', size: 'sm' });
  useToken.addEventListener('click', () => { tokenForm.hidden = false; useToken.remove(); });
  const intro = usable
    ? h('p', { class: 'small muted' }, 'Pick a repository from GitHub. Choose Connect GitHub to install DumbSlab’s app on another account, or to give it more repositories.')
    : h('p', { class: 'small muted' }, 'Choose Connect GitHub, install DumbSlab’s app on the repositories you want, and come back here to pick one. No token or webhook needed: pushes sync by themselves. For GitLab, or a GitHub repository without the app, use a token.');
  return h('div', { class: 'stack' },
    intro,
    usable ? githubSourceForm(github, topics, reload) : null,
    h('div', { class: 'plan-actions' }, connectLink(github.connect_url, 'Connect GitHub', usable ? 'subtle' : 'primary'), useToken),
    tokenForm);
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

// What the codes in `?connect_error=` mean, after Connect GitHub. The link carries only a code,
// never a message: anyone can make a link to this page.
const connectErrors = {
  expired_link: () => 'That link is no longer valid. Choose Connect GitHub again.',
  too_slow: () => 'Connecting took too long. Choose Connect GitHub again.',
  wrong_person: () => 'Finish connecting in the same browser, signed in as the admin who started it. Choose Connect GitHub again.',
  not_admin: () => 'Only admins can connect GitHub for docs sync.',
  unavailable: () => 'DumbSlab’s GitHub App isn’t set up on this server. Use a token instead.',
  approval_requested: () => 'An owner of the GitHub organization has to approve DumbSlab’s app first; GitHub has asked them. Once they have, choose Connect GitHub again.',
  declined: () => 'GitHub didn’t allow access. Choose Connect GitHub again, and authorize DumbSlab when GitHub asks.',
  no_code: () => 'GitHub didn’t finish connecting. Choose Connect GitHub again.',
  not_yours: () => 'Your GitHub account can’t access that installation of DumbSlab’s app. Install it on an account or organization you manage, then try again.',
  choose_installation: () => 'GitHub didn’t say which installation of DumbSlab’s app you set up, and you can reach too many to connect them all. On GitHub, open the app under Installed GitHub Apps in your account’s or organization’s settings, choose Configure and save; that brings you back here with it.',
  installation_full: () => 'GitHub is connected, but that installation of DumbSlab’s app already serves as many DumbSlab workspaces as it can, so pushes won’t sync by themselves here. Sync now still works.',
  failed: () => 'Connecting GitHub didn’t work. Try again.',
};

function connectNotes() {
  const query = new URLSearchParams(location.search);
  if (query.get('connected') === 'github') {
    return h('p', { class: 'callout', role: 'status' }, icon('check', { size: 15 }), h('span', null, 'GitHub is connected. Pick a repository below.'));
  }
  const code = query.get('connect_error');
  if (!code) return null;
  const say = Object.hasOwn(connectErrors, code) ? connectErrors[code]() : 'Connecting didn’t work. Try again.';
  return h('p', { class: 'callout callout-warn', role: 'alert' }, icon('alert', { size: 15 }), h('span', null, say));
}

export async function docsSyncSection(ctx) {
  const [list, topics] = await Promise.all([api.get('/docs-sources'), api.get('/topics')]);
  if (!list.enabled) return off('Docs sync');
  const github = list.github_app ? await api.get('/docs-sources/github') : null;
  const reload = () => ctx.reload();
  const add = addSource(github, topicOptions(topics.items), reload);
  const justConnected = new URLSearchParams(location.search).get('connected') === 'github';
  add.hidden = list.items.length > 0 && !justConnected;
  const show = button('Add a folder', { icon: 'plus', variant: 'primary', size: 'sm', onClick: () => { add.hidden = false; show.remove(); } });
  return frag(
    connectNotes(),
    panel('Docs sync', 'Keep a GitHub or GitLab folder’s Markdown files as posts in a topic. Each file is a post, sub-folders become sub-topics, and relative links and images keep working. It’s one way: synced posts are edited in the repository, and each push brings the change here.',
      list.items.length ? h('div', { class: 'app-list' }, list.items.map((s) => sourceCard(s, reload))) : null,
      list.items.length && add.hidden ? h('div', null, show) : null,
      add));
}
