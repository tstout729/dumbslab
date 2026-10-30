// Settings › Slack (admins): connect the workspace's own Slack app, turn link previews on or off,
// and pick the Slack channels that hear about new and updated posts. See docs/slack.md.

import { api, enc } from '/api.js';
import { h, icon, button, busy, badge, toast, toastError, confirmDialog, field, input, select, checkbox, copyText, emptyState, frag } from '/ui.js';

function panel(title, description, ...body) {
  return h('section', { class: 'panel' },
    h('header', { class: 'panel-head' }, h('h2', { class: 'panel-title' }, title), description ? h('p', { class: 'panel-desc' }, description) : null),
    ...body);
}

const checked = (box) => box.querySelector('input').checked;

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
function eventsPanel(s, reload) {
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
  return panel('3. Let Slack check the events URL', 'Once the signing secret is saved, open your Slack app’s App Manifest page (or Event Subscriptions) and click Verify next to the Request URL. Slack sends link previews there.',
    h('ul', { class: 'link-list' },
      h('li', null, h('span', null, 'Slash command '), h('code', null, s.commands_url)),
      h('li', null, h('span', null, 'Events '), h('code', null, s.events_url))),
    h('div', { class: 'row gap-sm' },
      h('label', { class: 'switch-wrap' }, toggle, h('span', { class: 'switch-ui', 'aria-hidden': 'true' })),
      h('span', null, 'Preview links to posts pasted in Slack')),
    h('p', { class: 'field-hint' }, 'Slack shows a preview to everyone in the conversation, including guests and people from other companies in shared channels. So DumbSlab previews only posts everyone in this workspace can see, and only when the person who shared the link can see them.'));
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

function disconnectPanel(reload) {
  const off = button('Disconnect Slack', { variant: 'subtle', size: 'sm', cls: 'text-danger' });
  off.addEventListener('click', async () => {
    const ok = await confirmDialog({ title: 'Disconnect Slack?', message: 'DumbSlab forgets the bot token, the signing secret and the channel list. /dumbslab and link previews stop working. Delete the app at api.slack.com/apps to remove it from Slack too.', confirmLabel: 'Disconnect', danger: true });
    if (!ok) return;
    busy(off, async () => {
      await api.del('/slack');
      toast('Slack disconnected');
      reload();
    }).catch(toastError);
  });
  return panel('Disconnect', null, h('div', null, off));
}

export async function slackSection(ctx) {
  const [s, topicList] = await Promise.all([api.get('/slack'), api.get('/topics')]);
  const topics = topicList.items;
  const reload = () => ctx.reload();
  const intro = h('section', { class: 'panel panel-hero' },
    h('div', { class: 'hero-mark' }, icon('hash', { size: 22 })),
    h('h2', { class: 'panel-title' }, 'Slack ', s.connected ? badge('Connected', 'scope') : null),
    h('p', { class: 'panel-desc' }, 'Search DumbSlab with /dumbslab search, start a draft with /dumbslab new, preview links to posts, and tell channels about new posts. Everyone acts as themselves: Slack people are matched to DumbSlab people by the email address Slack has confirmed, and see only what they can see here.'));
  if (!s.available) {
    return frag(intro, h('p', { class: 'callout callout-warn', role: 'alert' }, icon('alert'),
      h('span', null, 'Slack needs this server’s connector key to keep the Slack app’s secrets. Set DUMBSLAB_CONNECTOR_KEY (self-hosted) or the CONNECTOR_KEY secret (Cloudflare), then come back.')));
  }
  const saved = s.bot_token_saved || s.signing_secret_saved || s.channels.length;
  return frag(intro, createPanel(s), credentialsPanel(s, reload), eventsPanel(s, reload), channelsPanel(s, topics, reload), saved ? disconnectPanel(reload) : null);
}
