# DumbSlab's Slack app (for operators)

One Slack app serves every workspace on your server. With it, an admin clicks **Add to Slack** in Settings › Slack, approves in Slack, and is done (see [docs/slack.md](../slack.md)). The same app also lets people search Slack from DumbSlab ([connected apps](../connected-apps.md)) and sign in with Slack ([single sign-on](../sso.md); operator notes in [sign-in apps](sign-in-apps.md#slack)).

Without it, admins can still connect their own Slack app by hand.

These steps use `dumbslab.com`. Put your own domain in its place.

## 1. Check the connector key

Bot tokens are encrypted with the connector key. On Cloudflare that's the `CONNECTOR_KEY` secret; self-hosted, `DUMBSLAB_CONNECTOR_KEY`. Set it first if it isn't set (see [connected apps](../connected-apps.md)).

## 2. Create the app

Open `https://dumbslab.com/slack/create-app` while signed in to Slack. It sends you to Slack's **Create an app** page with the manifest filled in. Pick the Slack workspace that should own the app (yours, not a customer's), check the summary and click **Create**.

To read the manifest first, open `https://dumbslab.com/slack/app-manifest.json`. You can also paste it into **Create New App › From a manifest** at [api.slack.com/apps](https://api.slack.com/apps).

The manifest sets up:

- the bot user `dumbslab` and the `/dumbslab` command, sent to `https://dumbslab.com/slack/commands`;
- events (`link_shared`, `app_uninstalled`, `tokens_revoked`), sent to `https://dumbslab.com/slack/events`;
- link previews for `dumbslab.com`, which covers every workspace's subdomain;
- three redirect URLs: `/connect/callback`, `/sso/callback` and `/slack/install/callback`, all on `https://dumbslab.com`;
- the bot scopes Add to Slack needs, and the user scopes for searching Slack and signing in with Slack;
- no org-wide installs and no token rotation.

## 3. Give the server the app's credentials

In the app, open **Basic Information › App Credentials**. Copy the **Client ID**, **Client Secret** and **Signing Secret**.

On Cloudflare, the client ID is public, so it goes in `crates/worker/wrangler.toml` under `[vars]`:

```toml
SLACK_CLIENT_ID = "1234567890.1234567890"
```

The two secrets go in as Worker secrets:

```sh
cd crates/worker
npx wrangler secret put SLACK_CLIENT_SECRET
npx wrangler secret put SLACK_SIGNING_SECRET
npx wrangler deploy
```

Self-hosted, set these in the server's environment and restart it:

| Variable | Value |
| --- | --- |
| `DUMBSLAB_SLACK_CLIENT_ID` | Client ID |
| `DUMBSLAB_SLACK_CLIENT_SECRET` | Client Secret |
| `DUMBSLAB_SLACK_SIGNING_SECRET` | Signing Secret |

A self-hosted server's manifest is at `https://your-host/slack/app-manifest.json` (and `/slack/create-app`). Its URLs are the server's own, so Slack sends people back to `https://your-host/slack/install/callback`.

## 4. Let Slack check the events URL

Back in the Slack app, open **App Manifest** (or **Event Subscriptions**) and click **Verify** next to the Request URL. This works only once the signing secret is deployed.

## 5. Turn on public distribution

The manifest can't do this part. Until you do, only the Slack workspace that owns the app can install it.

1. In the app, open **Manage Distribution**.
2. Under **Share Your App with Other Workspaces**, finish each item on the checklist.
3. Click **Activate Public Distribution**.

A self-hosted server used by one company can skip this if the app lives in that company's own Slack workspace.

## 6. Try it

In any workspace, open Settings › Slack as an admin. You should see **Add to Slack**. `get_slack` now returns an `install_url`.

## What to know

- **The `Directory` object holds each installation.** Its `slack_installs` table records which DumbSlab workspace holds each Slack workspace, with the bot token, encrypted with `CONNECTOR_KEY`. It's the only record of both. Workspaces keep no token: each time one acts on Slack, it asks the `Directory`, which gives the token only to the workspace that holds the Slack workspace. Slack sends all requests to the root domain, and the Worker forwards each one there. Deleting a workspace with the operator API frees its Slack workspaces.
- **Each change names where it started.** The `slack_homes` table keeps a counter for each workspace. Every install and release names the value its workflow read when it started, and moves the counter on; one naming an old value is refused (`slack_changed`). Forgetting a dead token moves it on too, and so does deleting a workspace with the operator API, so nothing the deleted workspace still had under way reaches a new workspace at the same address. So a delayed step never undoes a newer one. A workspace lets go of a Slack workspace it doesn't name only once it's been there 15 minutes.
- **Forwarded requests are marked.** The Worker adds `x-dumbslab-slack-via-root` to the requests it forwards, and removes it from any other request. A workspace checks marked requests with `SLACK_SIGNING_SECRET`, even if it now uses its own Slack app, so it can still let go of a Slack workspace left over from before.
- **The one allowed window.** An action that already fetched the token may finish within seconds of a disconnect or transfer. Its next action asks the `Directory` again.
- **DumbSlab never revokes this app's tokens.** Slack gives every install of the app in a Slack workspace the same bot token, so a revoke by one DumbSlab workspace could reach the next one's. Disconnecting frees the Slack workspace in the `Directory`; removing the app from Slack is the Slack admin's job.
- **Uninstalls are checked at the root.** When Slack sends `app_uninstalled`, or `tokens_revoked` for the bot, the Worker asks Slack (`auth.test`) whether the token in the `Directory` still works. If it doesn't, the `Directory` forgets the installation, only while it still holds that same token. No workspace is involved: one finds out the next time it asks for the token, or opens Settings › Slack. If Slack's answer is unclear, the Worker answers 500, so Slack sends the event again.
- **Backups.** A workspace's backup holds no Slack token. A restored workspace acts on Slack only if the `Directory` says it still holds that Slack workspace; otherwise it forgets the connection. Restoring the `Directory` to an earlier point brings back who held what then, and workspaces follow it.
- **Changing the root domain.** Open `/slack/app-manifest.json` on the new domain and paste it into the app's **App Manifest** page. Slack may ask workspaces to reinstall the app after its link domain changes.
- **Rotating the signing secret.** Regenerate it in Slack, then run `npx wrangler secret put SLACK_SIGNING_SECRET` and deploy. Requests fail in between.
- **Rate limits.** Slack's May 2025 limit cut for apps outside the Marketplace covers `conversations.history` and `conversations.replies` only. DumbSlab calls neither.
- **Enterprise Grid.** Org-wide installs are off in the manifest. If one happens anyway, DumbSlab refuses it without revoking: an org-wide token also reaches the org's workspaces that installed the app themselves. An org admin removes it in Slack.

## Slack Marketplace

An unlisted app with public distribution installs in any Slack workspace that allows it, but Slack's rules limit how long you should rely on that:

- Slack's [API terms](https://slack.com/terms-of-service/api) forbid "Commercial Distribution" without an agreement with Slack. That includes "a free App that connects to a paid product or service", so DumbSlab with a Pro plan counts. For most apps, the agreement is the Marketplace Agreement you accept when you submit to the Marketplace; a partner agreement with Slack or Salesforce also works.
- Some Slack workspaces only allow apps listed in the Marketplace.

So submit DumbSlab's app to the [Slack Marketplace](https://docs.slack.dev/slack-marketplace/slack-marketplace-app-guidelines-and-requirements) once you can. Have these ready:

- **Use.** Slack turns down apps installed in fewer than 10 active workspaces with fewer than 10 weekly active users.
- **A public landing page** that explains the app, links the privacy policy, and shows an Add to Slack button or says where to find one (Settings › Slack). After installing, people land on Settings › Slack, which confirms it worked.
- **A public privacy policy** that says what's collected, how it's used, how long it's kept, and how to ask for access or deletion, with an email address or form.
- **A public support page** with a way to reach you. Slack expects answers within 2 business days.
- **A reason for each scope.** The table in [docs/slack.md](../slack.md#scopes) has one per bot scope. The user scopes are for searching Slack and signing in with Slack.
- **Security.** Slack checks that the OAuth `state` is used (it is), that requests are verified with the signing secret (they are), that tokens are stored securely (encrypted with the connector key), and TLS 1.2 or later (Cloudflare).
- **Direct install** is optional. Slack requires a direct install URL to redirect straight to `slack.com/oauth/v2/authorize`. DumbSlab's `/slack/install` asks people to sign in to their DumbSlab workspace first, so leave direct install off.
