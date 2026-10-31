# Slack

Connect a DumbSlab workspace to your Slack workspace, and from Slack people can:

- **search DumbSlab:** `/dumbslab search onboarding` answers with the posts that person can see, in a reply only they see;
- **start a draft:** `/dumbslab new Onboarding checklist` creates a draft that belongs to them and links to it;
- **preview links:** a link to a post pasted in Slack shows its title, an excerpt, its author and its topics.

DumbSlab can also post in Slack channels when posts are published or updated: every post everyone can see, or the posts in a topic you pick.

`/dumbslab help`, or anything else after `/dumbslab`, explains the commands.

## Add to Slack

On dumbslab.com (and any server whose operator set up DumbSlab's Slack app):

1. Open **Settings › Slack** as an admin and click **Add to Slack**.
2. Slack asks you to pick your Slack workspace and allow DumbSlab. Click **Allow**.

That's all. Slack sends you back to Settings › Slack, which names the Slack workspace you connected. `/dumbslab`, link previews and channel messages work right away. There's no app to create and nothing to paste.

Then, if you like, add channels under **Channels** (see [Channels](#channels)).

Agents can find the link in `get_slack`: `install_url` is set when Add to Slack works here, and `mode` says how Slack is connected (`shared` for Add to Slack, `own` for your own app). An admin must open the link in a browser where they're signed in to DumbSlab.

What to know:

- **One Slack workspace, one DumbSlab workspace.** A Slack workspace can be connected to one DumbSlab workspace at a time. If another DumbSlab workspace has it, Add to Slack says so; disconnect it there first.
- **Switching Slack workspaces.** Click Add to Slack again and pick the other one. The channel list is cleared, since channel IDs belong to one Slack workspace, and the old Slack workspace is free for another DumbSlab workspace.
- **Disconnect** stops DumbSlab from using the Slack workspace: it forgets its token and the channel list, and the Slack workspace is free for another DumbSlab workspace right away. It doesn't remove the app from Slack. A Slack admin does that in Slack ([how to remove an app](https://slack.com/help/articles/360003125231-Remove-apps-and-custom-integrations-from-your-workspace)).
- **Removing the app in Slack** (or revoking its token) disconnects it in DumbSlab too, once Slack says the token no longer works.
- **Enterprise Grid.** Add DumbSlab to one workspace in your organization at a time. Installing it across a whole organization isn't supported. If one happens, an org admin removes it in Slack ([manage apps in an Enterprise organization](https://slack.com/help/articles/360000281563-Manage-apps-in-an-Enterprise-organization)).
- **Links to a workspace's posts.** DumbSlab's Slack app previews links on the whole domain (Slack counts every subdomain of an app's link domain). Each DumbSlab workspace previews only links to its own address, never another workspace's.
- **Channels shared between companies (Slack Connect).** If both companies connected DumbSlab, Slack sends a link pasted there to only one of them. Links to the other company's posts get no preview.
- **Moving from your own Slack app.** After Add to Slack, delete your own app at [api.slack.com/apps](https://api.slack.com/apps). Otherwise both apps answer `/dumbslab`, and Slack sends link previews only to the app installed first.

If Add to Slack isn't offered, the server has no shared Slack app. Use your own Slack app instead (below), or ask whoever runs the server to set one up ([docs/hosting/slack-app.md](hosting/slack-app.md)).

## Who is asking

Everyone acts as themselves. DumbSlab asks Slack who typed the command or shared the link, and matches them to the active DumbSlab person with the same email address. That works only when Slack says it has **confirmed** the address, and only for people in the Slack workspace that's connected. Bot accounts are never matched.

So a search returns only what that person can see in DumbSlab, and a draft belongs to them. Anyone DumbSlab can't match (a different email, an unconfirmed one, a guest from another company in a shared channel) gets a reply that says how to connect, and nothing from the workspace. Everything people do from Slack shows in the activity log with a **Slack** badge, and counts against a hosted workspace's daily writes like any other change.

## What Slack shows to whom

- **Search results and draft replies** are ephemeral: only the person who typed the command sees them.
- **Link previews go to everyone in the conversation.** That can include Slack guests, and people from other companies in channels shared with them. So DumbSlab previews only posts that **everyone in the workspace can see** (published, and in no topic or in at least one org-wide topic), and only when the person who shared the link can see the post too. A post in a private topic, a draft, or a link shared by someone DumbSlab can't match gets no preview at all, not even a title. Turn previews off in Settings › Slack if even that is too much.
- **Channel messages** show the post's title, an excerpt, who published or updated it, and its org-wide topics. A channel set to "every post everyone can see" never gets posts from private topics. A post in a private topic reaches a channel only if an admin picked that topic for it. Picking a topic includes its org-wide subtopics, not its private ones.

Everything DumbSlab sends is escaped for Slack (`&`, `<` and `>`), so a post's title can't mention `@channel`, link somewhere else, or format a message as something it isn't.

## Channels

Under **Channels** in Settings › Slack, add a Slack channel by its ID, like `C0123ABCD`. To find it, open the channel, click its name at the top, and copy the Channel ID at the bottom of the About tab. Names aren't accepted, because they change. Pick which posts it gets, and send a test message. The app posts in public channels by itself; type `/invite @dumbslab` in a private channel first.

Agents and scripts can do the same with `get_slack`, `update_slack`, `add_slack_channel`, `update_slack_channel`, `delete_slack_channel`, `test_slack_channel` and `disconnect_slack` (admins only).

## Use your own Slack app

Use this when the server has no shared Slack app (a self-hosted server, say), or your Slack workspace allows only apps it made itself. You need to be a DumbSlab admin and able to create apps in your Slack workspace. In Settings › Slack it's under **Use your own Slack app instead**.

1. **Create the app.** In DumbSlab, open Settings › Slack and copy the manifest. It has this workspace's URLs filled in. Open [api.slack.com/apps](https://api.slack.com/apps?new_app=1), choose **Create New App › From a manifest**, pick your Slack workspace, paste the manifest (JSON) and create the app.
2. **Install it.** In the app, open **Install App** and install it to your workspace.
3. **Connect it to DumbSlab.** Copy the **Bot User OAuth Token** (`xoxb-…`, from **OAuth & Permissions**) and the **Signing Secret** (from **Basic Information › App Credentials**) into Settings › Slack, and save. DumbSlab checks the token with Slack first.
4. **Let Slack check the events URL.** Back in the Slack app, open **App Manifest** (or **Event Subscriptions**) and click **Verify** next to the Request URL. Slack can only check it once the signing secret is saved.
5. **Pick channels** (optional), as above.

While DumbSlab's Slack app is connected, `update_slack` won't take your own app's token or secret: disconnect first.

What's different with your own app:

- **Changing the workspace's address** changes the URLs too. Copy the new manifest into the Slack app's App Manifest page, and reinstall it if Slack asks.
- Two DumbSlab workspaces connected to one Slack workspace each need their own command name: change `/dumbslab` in one app's manifest.
- Disconnecting doesn't touch the app in Slack. Delete it at api.slack.com/apps to remove it from Slack too.

## Scopes

Both apps ask for these bot scopes, each for one feature:

| Scope | For |
| --- | --- |
| `commands` | the `/dumbslab` command |
| `chat:write` | channel messages and test messages |
| `chat:write.public` | posting in public channels without being invited |
| `links:read`, `links:write` | link previews (`link_shared` events and `chat.unfurl`) |
| `users:read`, `users:read.email` | finding who someone is by their confirmed email (`users.info`) |

Your own app subscribes to one event, `link_shared`, for the workspace's own domain. DumbSlab's Slack app also subscribes to `app_uninstalled` and `tokens_revoked`, so it hears when it's removed. Its user scopes (`search:read`, `openid`, `email`, `profile`) are for searching Slack from DumbSlab ([connected apps](connected-apps.md)) and signing in with Slack ([single sign-on](sso.md)); Add to Slack doesn't ask for them.

## Requirements

- **A connector key.** The bot token (and your own app's signing secret) are encrypted with the same key as [connected apps](connected-apps.md): `DUMBSLAB_CONNECTOR_KEY` for a self-hosted server, the `CONNECTOR_KEY` secret on Cloudflare. Without it, Slack can't be connected. Changing it means connecting Slack again.
- **A public HTTPS address** Slack can reach, with a real domain name (Slack previews no links to IP addresses or `localhost`). Start a self-hosted server with `--base-url https://your-host`.

## How it works

- Slack calls `POST /slack/commands` (the command) and `POST /slack/events` (link previews, and its URL check). These sit outside DumbSlab's sign-in: a request is accepted only with a valid `X-Slack-Signature` (HMAC-SHA256 of `v0:{timestamp}:{body}` with the signing secret, compared in constant time) made within five minutes. Each signature works once, so a copied request is refused, and an event Slack sends again after a slow answer is handled once. Requests are limited to 64 KB.
- **DumbSlab's Slack app on dumbslab.com** sends every Slack workspace's requests to `https://dumbslab.com/slack/…`. The root domain checks the signature, finds the Slack workspace the request is for (a command's `team_id`; an event's installation, `authorizations[0]`), and sends the request unchanged to the DumbSlab workspace that connected it. That workspace checks the signature again, remembers it, and handles it only if the Slack workspace is the one it holds. A Slack workspace nobody connected gets a reply saying how to connect it.
- **Add to Slack** sends the admin to Slack with a one-time `state` (stored only as a hash, tied to the admin and their browser session, good for 15 minutes). Slack sends them back to `/slack/install/callback` (on dumbslab.com, through the root domain, which forwards by the workspace address at the start of the `state`). DumbSlab exchanges the code at Slack's `oauth.v2.access` for the bot token. Problems come back to Settings › Slack as a code, never as Slack's own words.
- **On dumbslab.com, the server's directory holds the installation.** It records which DumbSlab workspace holds each Slack workspace, and keeps the bot token (encrypted with the server's connector key). It's the only record of both. A DumbSlab workspace keeps no token: it saves only the Slack workspace's name and ID, and its settings.
  - Add to Slack has the directory record the installation, then saves that reference. The directory refuses while another DumbSlab workspace holds the Slack workspace. Adding the same Slack workspace again just records it again.
  - Switching to another Slack workspace records the new one, saves it, then lets go of the old one. If that last step doesn't happen, the next visit to Settings › Slack lets go of it, and so does Slack's next request for it.
  - Disconnecting lets go in the directory first. If that fails, nothing changes and Settings › Slack shows the error.
  - Every time DumbSlab acts on Slack (asking who typed a command, previewing a link, posting in a channel, a test message), it asks the directory for the token first. Only the DumbSlab workspace that holds the Slack workspace gets it. If the directory says no, DumbSlab stops, and forgets the stale connection. So a workspace restored from a backup, or one whose Slack workspace now belongs to another DumbSlab workspace, can't act on it.
  - Settings › Slack asks the directory whether the workspace holds its Slack workspace.
- **DumbSlab never revokes its app's token.** Slack gives every install of DumbSlab's app in a Slack workspace the same bot token, so a revoke by one DumbSlab workspace could reach the next one's.
- **Uninstalls are checked with Slack.** Slack doesn't keep events in order, and their times are whole seconds. So on `app_uninstalled`, or `tokens_revoked` naming DumbSlab's bot, DumbSlab asks Slack (`auth.test`) whether the token still works. On dumbslab.com the root domain does this itself, with the directory's token. Only a dead token is forgotten, and only while the directory still holds that very token: an install made since, with a new token, stays. If Slack's answer is unclear, DumbSlab answers the event with an error, so Slack sends it again. A token Slack calls dead while DumbSlab acts is forgotten the same way.
- **Self-hosted servers** have no directory. Add to Slack keeps the bot token in the workspace, like your own app's.
- Slack wants an answer within three seconds. So once a command's or event's signature checks out, DumbSlab acknowledges it right away and does the work afterwards: it asks Slack's `users.info` who the person is, searches its own index or starts the draft, and posts the answer to the command's `response_url`. That address must be https on Slack's own `hooks.slack.com` (or GovSlack's `hooks.slack-gov.com`); a command with any other is refused. If the work fails and is undone (the workspace is out of storage, say), the person still gets a short note there instead of silence. Link previews go to `chat.unfurl` the same way. This work counts against a hosted workspace's daily writes and storage like any other.
- Channel messages are sent like webhooks, after the change is saved, to Slack's `chat.postMessage` with the bot token. On dumbslab.com with DumbSlab's own app, they wait for the directory's token. A channel hears about a post once, however many of its settings match it, and one request sends a channel at most three messages, so a bulk import doesn't flood it. Slack reports some problems (an app not invited to a private channel) in its answer rather than as an error, so use **Send a test message** to check a channel.
- The bot token and signing secrets are never returned by any operation, and never written to logs.

## Troubleshooting

| Slack or DumbSlab says | What to do |
| --- | --- |
| "That Slack workspace is already connected to another DumbSlab workspace" | Disconnect it in the other DumbSlab workspace first. |
| "DumbSlab's Slack app isn't working for … right now" | Click Add to Slack again. |
| "This Slack workspace is no longer connected to DumbSlab here" | The Slack workspace was disconnected, or connected to another DumbSlab workspace. An admin can click Add to Slack again. |
| "not a whole Enterprise organization" | Add DumbSlab to one workspace of your organization, not the whole organization. |
| "This Slack workspace isn't connected to DumbSlab yet" | An admin clicks Add to Slack in Settings › Slack. |
| `/dumbslab failed with the error "dispatch_failed"` | Your own app: the command's URL is wrong or unreachable. Copy the manifest again from Settings › Slack. |
| "Your Slack account isn't linked to anyone" | Use the same email in Slack and DumbSlab, and confirm it in Slack. An admin can add people in Settings › People. |
| "can't read email addresses" | Your own app is missing `users:read.email`. Paste the manifest from Settings › Slack into the app's App Manifest page and reinstall it. |
| No preview for a link | Only posts everyone can see get previews, and only for people DumbSlab can match. Check that previews are on, and (your own app) that the events URL is verified. |
| Test message: "isn't in the channel" | Type `/invite @dumbslab` in the channel. |
