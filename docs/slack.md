# Slack

Connect a DumbSlab workspace to your Slack workspace, and from Slack people can:

- **search DumbSlab:** `/dumbslab search onboarding` answers with the posts that person can see, in a reply only they see;
- **start a draft:** `/dumbslab new Onboarding checklist` creates a draft that belongs to them and links to it;
- **preview links:** a link to a post pasted in Slack shows its title, an excerpt, its author and its topics.

DumbSlab can also post in Slack channels when posts are published or updated: every post everyone can see, or the posts in a topic you pick.

`/dumbslab help`, or anything else after `/dumbslab`, explains the commands.

## Who is asking

Everyone acts as themselves. DumbSlab asks Slack who typed the command or shared the link, and matches them to the active DumbSlab person with the same email address. That works only when Slack says it has **confirmed** the address, and only for people in the Slack workspace the app is installed in. Bot accounts are never matched.

So a search returns only what that person can see in DumbSlab, and a draft belongs to them. Anyone DumbSlab can't match (a different email, an unconfirmed one, a guest from another company in a shared channel) gets a reply that says how to connect, and nothing from the workspace. Everything people do from Slack shows in the activity log with a **Slack** badge, and counts against a hosted workspace's daily writes like any other change.

## What Slack shows to whom

- **Search results and draft replies** are ephemeral: only the person who typed the command sees them.
- **Link previews go to everyone in the conversation.** That can include Slack guests, and people from other companies in channels shared with them. So DumbSlab previews only posts that **everyone in the workspace can see** (published, and in no topic or in at least one org-wide topic), and only when the person who shared the link can see the post too. A post in a private topic, a draft, or a link shared by someone DumbSlab can't match gets no preview at all, not even a title. Turn previews off in Settings › Slack if even that is too much.
- **Channel messages** show the post's title, an excerpt, who published or updated it, and its org-wide topics. A channel set to "every post everyone can see" never gets posts from private topics. A post in a private topic reaches a channel only if an admin picked that topic for it. Picking a topic includes its org-wide subtopics, not its private ones.

Everything DumbSlab sends is escaped for Slack (`&`, `<` and `>`), so a post's title can't mention `@channel`, link somewhere else, or format a message as something it isn't.

## Set it up

You need to be a DumbSlab admin and able to create apps in your Slack workspace. Each DumbSlab workspace uses its own Slack app: DumbSlab doesn't run a shared one, because Slack lets an app reach other companies only through its Marketplace.

1. **Create the app.** In DumbSlab, open Settings › Slack and copy the manifest. It has this workspace's URLs filled in. Open [api.slack.com/apps](https://api.slack.com/apps?new_app=1), choose **Create New App › From a manifest**, pick your Slack workspace, paste the manifest (JSON) and create the app.
2. **Install it.** In the app, open **Install App** and install it to your workspace.
3. **Connect it to DumbSlab.** Copy the **Bot User OAuth Token** (`xoxb-…`, from **OAuth & Permissions**) and the **Signing Secret** (from **Basic Information › App Credentials**) into Settings › Slack, and save. DumbSlab checks the token with Slack first.
4. **Let Slack check the events URL.** Back in the Slack app, open **App Manifest** (or **Event Subscriptions**) and click **Verify** next to the Request URL. Slack can only check it once the signing secret is saved.
5. **Pick channels** (optional). Under Channels, add a Slack channel by its ID, like `C0123ABCD` (open the channel, click its name at the top, and copy the Channel ID at the bottom of the About tab; names aren't accepted, because they change), pick which posts it gets, and send a test message. The app posts in public channels by itself; type `/invite @dumbslab` in a private channel first.

Agents and scripts can do the same with `get_slack`, `update_slack`, `add_slack_channel`, `update_slack_channel`, `delete_slack_channel`, `test_slack_channel` and `disconnect_slack` (admins only).

### Scopes

The manifest asks for these bot scopes, each for one feature:

| Scope | For |
| --- | --- |
| `commands` | the `/dumbslab` command |
| `chat:write` | channel messages and test messages |
| `chat:write.public` | posting in public channels without being invited |
| `links:read`, `links:write` | link previews (`link_shared` events and `chat.unfurl`) |
| `users:read`, `users:read.email` | finding who someone is by their confirmed email (`users.info`) |

It subscribes to one event, `link_shared`, for the workspace's own domain.

### Requirements

- **A connector key.** The bot token and signing secret are encrypted with the same key as [connected apps](connected-apps.md): `DUMBSLAB_CONNECTOR_KEY` for a self-hosted server, the `CONNECTOR_KEY` secret on Cloudflare. Without it, Slack can't be connected. Changing it means saving the token and secret again.
- **A public HTTPS address** Slack can reach, with a real domain name (Slack previews no links to IP addresses or `localhost`). Start a self-hosted server with `--base-url https://your-host`. Hosted workspaces already have one: each workspace's app points at its own address, such as `acme.dumbslab.com`.
- **Changing the workspace's address** changes the URLs too. Copy the new manifest into the Slack app's App Manifest page, and reinstall it if Slack asks.
- Two DumbSlab workspaces connected to one Slack workspace each need their own command name: change `/dumbslab` in one app's manifest.

## How it works

- Slack calls `POST /slack/commands` (the command) and `POST /slack/events` (link previews, and its URL check). These sit outside DumbSlab's sign-in: a request is accepted only with a valid `X-Slack-Signature` (HMAC-SHA256 of `v0:{timestamp}:{body}` with the signing secret, compared in constant time) made within five minutes. Each signature works once, so a copied request is refused, and an event Slack sends again after a slow answer is handled once. Requests are limited to 64 KB.
- Slack wants an answer within three seconds. So once a command's or event's signature checks out, DumbSlab acknowledges it right away and does the work afterwards: it asks Slack's `users.info` who the person is, searches its own index or starts the draft, and posts the answer to the command's `response_url`. That address must be https on Slack's own `hooks.slack.com` (or GovSlack's `hooks.slack-gov.com`); a command with any other is refused. If the work fails and is undone (the workspace is out of storage, say), the person still gets a short note there instead of silence. Link previews go to `chat.unfurl` the same way. This work counts against a hosted workspace's daily writes and storage like any other.
- Channel messages are sent like webhooks, after the change is saved, to Slack's `chat.postMessage` with the bot token. A channel hears about a post once, however many of its settings match it, and one request sends a channel at most three messages, so a bulk import doesn't flood it. Slack reports some problems (an app not invited to a private channel) in its answer rather than as an error, so use **Send a test message** to check a channel.
- The bot token and signing secret are never returned by any operation, and never written to logs.

## Troubleshooting

| Slack says | What to do |
| --- | --- |
| `/dumbslab failed with the error "dispatch_failed"` | The command's URL is wrong or unreachable. Copy the manifest again from Settings › Slack. |
| "Your Slack account isn't linked to anyone" | Use the same email in Slack and DumbSlab, and confirm it in Slack. An admin can add people in Settings › People. |
| "can't read email addresses" | The app is missing `users:read.email`. Paste the manifest from Settings › Slack into the app's App Manifest page and reinstall it. |
| No preview for a link | Only posts everyone can see get previews, and only for people DumbSlab can match. Check that previews are on, and that the events URL is verified. |
| Test message: "isn't in the channel" | Type `/invite @dumbslab` in the channel. |
