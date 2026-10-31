// Settings › Slack (admins): connect Slack with Add to Slack (DumbSlab's own Slack app, when the
// server has one) or the workspace's own Slack app, turn link previews on or off, and pick the
// Slack channels that hear about new and updated posts. See docs/slack.md.

import { api, enc } from '/api.js';
import { h, icon, button, busy, badge, toast, toastError, confirmDialog, field, input, select, checkbox, copyText, emptyState, frag } from '/ui.js';

function panel(title, description, ...body) {
  return h('section', { class: 'panel' },
    h('header', { class: 'panel-head' }, h('h2', { class: 'panel-title' }, title), description ? h('p', { class: 'panel-desc' }, description) : null),
    ...body);
}

const checked = (box) => box.querySelector('input').checked;

// What the codes in `?slack_error=` mean. The link back from Slack carries only a code, never
// Slack's words: anyone can make a link to this page.
const installErrors = {
  not_admin: 'Only admins can connect Slack.',
  unavailable: 'Add to Slack isn’t set up on this server. Use your own Slack app instead.',
  expired: 'That link to Slack was used already, or is no longer valid. Click Add to Slack again.',
  too_slow: 'Connecting took too long. Click Add to Slack again.',
  other_session: 'Finish connecting in the browser you started in, signed in as the same admin. Click Add to Slack again.',
  declined: 'Slack didn’t allow DumbSlab. Click Add to Slack again, and choose Allow.',
  slack_error: 'Slack didn’t finish connecting. Try again.',
  enterprise_install: 'DumbSlab connects one Slack workspace at a time, not a whole Enterprise organization. An org admin can remove the org-wide install in Slack (Organization settings › Integrations › Installed apps). Then add DumbSlab to one workspace.',
  slack_team_taken: 'That Slack workspace is already connected to another DumbSlab workspace. Disconnect it there first, then try again.',
  failed: 'Connecting Slack didn’t work. Try again.',
};

function installError(code) {
  return Object.hasOwn(installErrors, code) ? installErrors[code] : installErrors.failed;
}

/** Add to Slack: DumbSlab's own Slack app. One click, then approve in Slack. */
function addPanel(s) {
  // A full page load (`data-native`): the server sends the browser on to Slack.
  const add = h('a', { class: 'btn btn-primary', href: s.install_url, 'data-native': true }, icon('hash'), h('span', null, 'Add to Slack'));
  return panel('Add to Slack', 'Approve DumbSlab in Slack and you’re done. There’s no app to create and nothing to paste.',
    h('div', null, add),
    h('p', { class: 'field-hint' }, `DumbSlab asks Slack for ${s.scopes.join(', ')}: the /dumbslab command, posting in channels, link previews, and matching people by the email address Slack has confirmed.`));
}

// Slack's help on removing an app (workspace admins), and on org-wide apps (Enterprise org admins).
const REMOVE_APP_HELP = 'https://slack.com/help/articles/360003125231-Remove-apps-and-custom-integrations-from-your-workspace';

/** Connected with Add to Slack. */
function sharedPanel(s) {
  const status = s.connected
    ? h('p', { class: 'callout', role: 'status' }, icon('checkCircle'),
      h('span', null, `Connected to ${s.slack_workspace || 'Slack'} with DumbSlab’s Slack app.`))
    : h('p', { class: 'callout callout-warn', role: 'status' }, icon('alert'),
      h('span', null, `DumbSlab’s Slack app isn’t working for ${s.slack_workspace || 'this Slack workspace'} right now, so DumbSlab posts nothing in Slack. Click Add to Slack to connect it again.`));
  return panel('Connected', null,
    status,
    s.install_url
      ? h('p', { class: 'field-hint' }, 'To use another Slack workspace, click Add to Slack again and pick it there. ', h('a', { href: s.install_url, 'data-native': true }, 'Add to Slack'))
      : null);
}

/** Own app connected, and the server offers Add to Slack too. */
function switchPanel(s) {
  const add = h('a', { class: 'btn btn-subtle btn-sm', href: s.install_url, 'data-native': true }, icon('hash'), h('span', null, 'Add to Slack'));
  return panel('Switch to DumbSlab’s Slack app', 'This workspace uses its own Slack app. Click Add to Slack to use DumbSlab’s instead, then delete your own app at api.slack.com/apps, so Slack doesn’t send links and commands to both.',
    h('div', null, add));
}

function previewsToggle(s) {
  const toggle = h('input', { type: 'checkbox', role: 'switch', class: 'switch', checked: s.unfurls, 'aria-label': 'Preview links to posts' });
  toggle.addEventListener('change', async () => {
    try {
      await api.patch('/slack', { unfurls: toggle.checked });
      toast(toggle.checked ? 'Link previews on' : 'Link previews off');
    } catch (e) {
      toggle.checked = !toggle.checked;
      toastError(e);
    }
  });
  return frag(
    h('div', { class: 'row gap-sm' },
      h('label', { class: 'switch-wrap' }, toggle, h('span', { class: 'switch-ui', 'aria-hidden': 'true' })),
      h('span', null, 'Preview links to posts pasted in Slack')),
    h('p', { class: 'field-hint' }, 'Slack shows a preview to everyone in the conversation, including guests and people from other companies in shared channels. So DumbSlab previews only posts everyone in this workspace can see, and only when the person who shared the link can see them.'));
}

function previewsPanel(s) {
  return panel('Link previews', null, previewsToggle(s));
}

/** Step 1: create the Slack app from this workspace's manifest. */
function createPanel(s) {
  const manifest = JSON.stringify(s.manifest, null, 2);
  const copy = button('Copy the manifest', { icon: 'copy', variant: 'primary', size: 'sm', onClick: () => copyText(manifest, 'Manifest copied') });
  const open = h('a', { class: 'btn btn-subtle btn-sm', href: s.create_app_url, target: '_blank', rel: 'noopener noreferrer' }, icon('external'), h('span', null, 'Create a Slack app'));
  return panel('1. Create the Slack app', 'Each workspace uses its own Slack app, so nobody else holds a key to your Slack.',
    h('ol', { class: 'plan-list' },
      h('li', null, 'Copy the manifest, then open Create a Slack app and choose From a manifest.'),
      h('li', null, 'Pick your Slack workspace, paste the manifest (JSON), and create the app.'),
      h('li', null, 'Install it to your workspace (Install App), and allow what it asks for.')),
    h('div', { class: 'row gap-sm wrap' }, copy, open),
    h('details', null,
      h('summary', { class: 'small' }, 'Show the manifest'),
      h('pre', { class: 'code-block' }, h('code', null, manifest))),
    h('p', { class: 'field-hint' }, `It asks for ${s.scopes.join(', ')}: the /dumbslab command, posting in channels, link previews, and matching people by the email address Slack has confirmed.`));
}

/** Step 2: save the bot token and signing secret. */
function credentialsPanel(s, reload) {
  const token = input({ type: 'password', autocomplete: 'off', spellcheck: 'false', placeholder: s.bot_token_saved ? 'Saved. Paste a new one to replace it.' : 'xoxb-…' });
  const secret = input({ type: 'password', autocomplete: 'off', spellcheck: 'false', placeholder: s.signing_secret_saved ? 'Saved. Paste a new one to replace it.' : '' });
  const save = button('Save', { variant: 'primary', type: 'submit' });
  const f = h('form', { class: 'stack', novalidate: true },
    field('Bot User OAuth Token', token, { hint: 'In your Slack app: OAuth & Permissions, after installing it. DumbSlab checks it with Slack before saving.' }),
    field('Signing Secret', secret, { hint: 'In your Slack app: Basic Information › App Credentials. It proves requests come from Slack.' }),
    h('div', null, save));
  f.addEventListener('submit', (e) => {
    e.preventDefault();
    const body = {};
    if (token.value.trim()) body.bot_token = token.value.trim();
    if (secret.value.trim()) body.signing_secret = secret.value.trim();
    if (!Object.keys(body).length) {
      toast('Paste the bot token, the signing secret, or both.', { type: 'error' });
      return;
    }
    busy(save, async () => {
      await api.patch('/slack', body);
      toast('Slack saved');
      reload();
    }).catch(toastError);
  });
  const status = s.connected
    ? h('p', { class: 'callout', role: 'status' }, icon('checkCircle'), h('span', null, `Connected to ${s.slack_workspace || 'Slack'}. Secrets are encrypted and never shown again.`))
    : null;
  return panel('2. Connect it to DumbSlab', null, status, f);
}

/** Step 3: Slack checks the events URL; link previews on or off. */
function eventsPanel(s) {
  return panel('3. Let Slack check the events URL', 'Once the signing secret is saved, open your Slack app’s App Manifest page (or Event Subscriptions) and click Verify next to the Request URL. Slack sends link previews there.',
    h('ul', { class: 'link-list' },
      h('li', null, h('span', null, 'Slash command '), h('code', null, s.commands_url)),
      h('li', null, h('span', null, 'Events '), h('code', null, s.events_url))),
    previewsToggle(s));
}

function topicOptions(topics, selected) {
  return [{ value: '', label: 'Every post everyone can see', selected: !selected }]
    .concat(topics.map((t) => ({ value: t.id, label: `${t.visibility === 'private' ? '🔒 ' : ''}${t.name}`, selected: t.id === selected })));
}

function addChannelForm(topics, reload) {
  const channel = input({ required: true, spellcheck: 'false', autocapitalize: 'characters', placeholder: 'C0123ABCD', pattern: '[CG][A-Z0-9]{8,23}' });
  const topic = select(topicOptions(topics, null));
  const fresh = checkbox('New posts', { checked: true });
  const updated = checkbox('Updated posts');
  const add = button('Add channel', { icon: 'plus', variant: 'primary', size: 'sm', type: 'submit' });
  const f = h('form', { class: 'stack', novalidate: true },
    h('div', { class: 'grid-2' },
      field('Slack channel ID', channel, { hint: 'Open the channel in Slack, click its name at the top, and copy the Channel ID at the bottom of the About tab. Invite the app to private channels.' }),
      field('Posts from', topic, { hint: 'A topic includes its org-wide subtopics. A private topic’s posts go only to channels you pick it for.' })),
    h('div', { class: 'row gap-md wrap' }, fresh, updated),
    h('div', null, add));
  f.addEventListener('submit', (e) => {
    e.preventDefault();
    if (!channel.value.trim()) {
      channel.focus();
      toast('Enter the Slack channel.', { type: 'error' });
      return;
    }
    busy(add, async () => {
      await api.post('/slack/channels', { channel: channel.value.trim(), topic_id: topic.value || undefined, new_posts: checked(fresh), updated_posts: checked(updated) });
      toast('Channel added');
      reload();
    }).catch(toastError);
  });
  return f;
}

function channelRow(c, topics, reload, connected) {
  const update = async (patch, revert) => {
    try {
      await api.patch(`/slack/channels/${enc(c.id)}`, patch);
      toast('Saved');
    } catch (e) {
      revert();
      toastError(e);
    }
  };
  const fresh = checkbox('New', { checked: c.new_posts });
  const updated = checkbox('Updated', { checked: c.updated_posts });
  fresh.querySelector('input').addEventListener('change', (e) => update({ new_posts: e.target.checked }, () => { e.target.checked = !e.target.checked; }));
  updated.querySelector('input').addEventListener('change', (e) => update({ updated_posts: e.target.checked }, () => { e.target.checked = !e.target.checked; }));
  const topic = select(topicOptions(topics, c.topic ? c.topic.id : null), { class: 'input select input-sm', 'aria-label': `Posts for ${c.channel}` });
  topic.addEventListener('change', () => update({ topic_id: topic.value }, () => { topic.value = c.topic ? c.topic.id : ''; }));
  const test = button('Send a test message', { size: 'xs', variant: 'subtle', disabled: !connected, title: connected ? undefined : 'Connect Slack first' });
  test.addEventListener('click', () => busy(test, async () => {
    await api.post(`/slack/channels/${enc(c.id)}/test`);
    toast(`Sent a test message to ${c.channel}`);
  }).catch(toastError));
  const del = button('', { icon: 'trash', variant: 'ghost', size: 'xs', 'aria-label': `Stop sending posts to ${c.channel}`, title: 'Remove' });
  del.addEventListener('click', async () => {
    const ok = await confirmDialog({ title: `Stop sending posts to ${c.channel}?`, message: 'The channel keeps what it already got.', confirmLabel: 'Remove', danger: true });
    if (!ok) return;
    busy(del, async () => {
      await api.del(`/slack/channels/${enc(c.id)}`);
      toast('Channel removed');
      reload();
    }).catch(toastError);
  });
  return h('li', { class: 'webhook' },
    h('div', { class: 'webhook-main' },
      h('code', { class: 'webhook-url' }, c.channel),
      h('div', { class: 'row gap-sm wrap' }, topic, fresh, updated, test)),
    del);
}

/** Channels that get a message when posts are published or updated. */
function channelsPanel(s, topics, reload) {
  return panel('Channels', 'Post a message in Slack when posts are published or updated. The app posts in public channels by itself; invite it to private ones (/invite @dumbslab).',
    s.channels.length
      ? h('ul', { class: 'webhook-list' }, s.channels.map((c) => channelRow(c, topics, reload, s.connected)))
      : emptyState({ iconName: 'hash', title: 'No channels yet', body: 'Add one to tell a Slack channel about new posts.' }),
    addChannelForm(topics, reload));
}

function disconnectPanel(reload, shared) {
  const off = button('Disconnect Slack', { variant: 'subtle', size: 'sm', cls: 'text-danger' });
  const message = shared
    ? 'DumbSlab stops using this Slack workspace and forgets its token and the channel list. /dumbslab and link previews stop answering, and the Slack workspace can be added to another DumbSlab workspace. The app stays in Slack until a Slack admin removes it there.'
    : 'DumbSlab forgets the bot token, the signing secret and the channel list. /dumbslab and link previews stop working. Delete the app at api.slack.com/apps to remove it from Slack too.';
  off.addEventListener('click', async () => {
    const ok = await confirmDialog({ title: 'Disconnect Slack?', message, confirmLabel: 'Disconnect', danger: true });
    if (!ok) return;
    busy(off, async () => {
      await api.del('/slack');
      toast('Slack disconnected');
      reload();
    }).catch(toastError);
  });
  return panel('Disconnect', null, h('div', null, off),
    shared
      ? h('p', { class: 'field-hint' }, 'Disconnecting doesn’t remove DumbSlab’s app from Slack. A Slack admin can remove it there: ',
        h('a', { href: REMOVE_APP_HELP, target: '_blank', rel: 'noopener noreferrer' }, 'how to remove an app'), '.')
      : null);
}

export async function slackSection(ctx) {
  const [s, topicList] = await Promise.all([api.get('/slack'), api.get('/topics')]);
  const topics = topicList.items;
  const reload = () => ctx.reload();
  const intro = h('section', { class: 'panel panel-hero' },
    h('div', { class: 'hero-mark' }, icon('hash', { size: 22 })),
    h('h2', { class: 'panel-title' }, 'Slack ', s.connected ? badge('Connected', 'scope') : null),
    h('p', { class: 'panel-desc' }, 'Search DumbSlab with /dumbslab search, start a draft with /dumbslab new, preview links to posts, and tell channels about new posts. Everyone acts as themselves: Slack people are matched to DumbSlab people by the email address Slack has confirmed, and see only what they can see here.'));
  // How Add to Slack went, when Slack sent the admin back here.
  const query = new URLSearchParams(location.search);
  const notes = [];
  if (query.get('slack') === 'connected' && s.connected) {
    notes.push(h('p', { class: 'callout', role: 'status' }, icon('check', { size: 15 }), h('span', null, `Slack is connected${s.slack_workspace ? ` to ${s.slack_workspace}` : ''}.`)));
  }
  if (query.get('slack_error')) {
    notes.push(h('p', { class: 'callout callout-warn', role: 'alert' }, icon('alert', { size: 15 }), h('span', null, installError(query.get('slack_error')))));
  }
  if (!s.available) {
    return frag(intro, ...notes, h('p', { class: 'callout callout-warn', role: 'alert' }, icon('alert'),
      h('span', null, 'Slack needs this server’s connector key to keep the Slack app’s secrets. Set DUMBSLAB_CONNECTOR_KEY (self-hosted) or the CONNECTOR_KEY secret (Cloudflare), then come back.')));
  }
  const saved = s.bot_token_saved || s.signing_secret_saved || s.channels.length;
  const channels = channelsPanel(s, topics, reload);
  if (s.mode === 'shared') {
    return frag(intro, ...notes, sharedPanel(s), previewsPanel(s), channels, disconnectPanel(reload, true));
  }
  const ownApp = [createPanel(s), credentialsPanel(s, reload), eventsPanel(s)];
  const disconnect = saved ? disconnectPanel(reload, false) : null;
  if (s.install_url && s.mode !== 'own') {
    // Add to Slack first; your own app is the fallback, folded away.
    const own = h('details', { class: 'stack' },
      h('summary', null, 'Use your own Slack app instead'),
      h('p', { class: 'field-hint' }, 'For a Slack workspace that only allows apps it made itself. You create the app from a manifest and paste its bot token and signing secret.'),
      ...ownApp);
    return frag(intro, ...notes, addPanel(s), own, channels, disconnect);
  }
  return frag(intro, ...notes, s.install_url ? switchPanel(s) : null, ...ownApp, channels, disconnect);
}
