# DumbSlab's GitHub App (for operators)

With a GitHub App, docs sync needs no token and no webhook. An admin chooses **Connect GitHub** in Settings › Docs sync, installs the App on the repositories they want, and picks one. Pushes then sync by themselves. This page is for whoever runs the server. People who use docs sync read [docs sync](../docs-sync.md).

You register one App for the whole server. Hosted DumbSlab registers it once for every workspace.

This App is separate from the GitHub OAuth app that connected apps use (`GITHUB_CLIENT_ID`, see [connected apps](../connected-apps.md)). Keep both.

## What you need first

- The connector key (`CONNECTOR_KEY` on Cloudflare, `DUMBSLAB_CONNECTOR_KEY` self-hosted). Docs sync is off without it.
- A server GitHub can reach over https. Self-hosted servers must be on the public internet for pushes to arrive.

Below, `<ROOT>` is your public address: `https://dumbslab.com` for hosted DumbSlab, or your self-hosted server's URL, like `https://wiki.example.com`.

## 1. Register the App

Register it under the account or organization that should own it. For hosted DumbSlab, that's DumbSlab's own organization.

Open **Settings › Developer settings › GitHub Apps › New GitHub App** (for an organization: the organization's **Settings › Developer settings › GitHub Apps**). Fill it in like this:

| Setting | Value |
| --- | --- |
| GitHub App name | `DumbSlab` (or any free name; it sets the slug) |
| Homepage URL | `<ROOT>` |
| Callback URL | `<ROOT>/sync/github/callback` |
| Expire user authorization tokens | On (the default) |
| Request user authorization (OAuth) during installation | **On** |
| Enable Device Flow | Off |
| Setup URL | Leave empty (GitHub hides it when the option above is on) |
| Redirect on update | On |
| Webhook: Active | On |
| Webhook URL | `<ROOT>/hooks/github` |
| Webhook secret | A long random string, e.g. from `openssl rand -hex 32`. Keep it for step 3. |
| Repository permissions | **Contents: Read-only**. Metadata: Read-only is added by itself. Nothing else. |
| Organization and account permissions | None |
| Subscribe to events | **Push** |
| Where can this GitHub App be installed? | **Any account** (hosted). A self-hosted server for one organization can choose "Only on this account". |

Then choose **Create GitHub App**.

Why each one matters:

- **Request user authorization during installation** sends the admin back to the callback with a code. DumbSlab uses it to check that their own GitHub account can access the installation. GitHub's `installation_id` in that link can be forged, so DumbSlab never trusts it alone.
- **Contents: Read-only** is all a sync needs. Each sync gets a token that can read only that one repository, for an hour.
- **Push** syncs each push. GitHub also sends every App its installation events, so DumbSlab hears when the App is uninstalled or suspended, or when a repository is taken out. It then marks those folders as disconnected; their posts stay.

## 2. Collect the App's values

On the App's page (**General**):

1. Note the **App ID** (a number) and the **Client ID** (starts with `Iv`).
2. The **slug** is the last part of the App's public link, `https://github.com/apps/<slug>`.
3. Under **Client secrets**, choose **Generate a new client secret**. Copy it now; GitHub shows it once.
4. Under **Private keys**, choose **Generate a private key**. Your browser downloads a `.pem` file. Keep it safe. Anyone with it can act as the App.

## 3. Give them to the server

### Cloudflare

Put the three public values in `crates/worker/wrangler.toml`, under `[vars]`:

```toml
GITHUB_APP_ID = "1234567"
GITHUB_APP_SLUG = "dumbslab"
GITHUB_APP_CLIENT_ID = "Iv23li…"
```

Put the three secrets in with Wrangler, from `crates/worker`:

```sh
npx wrangler secret put GITHUB_APP_CLIENT_SECRET
npx wrangler secret put GITHUB_APP_WEBHOOK_SECRET
npx wrangler secret put GITHUB_APP_PRIVATE_KEY < ~/Downloads/dumbslab.2026-11-01.private-key.pem
```

The first two prompt for the value. The last one reads the whole `.pem` file, line breaks included. A key pasted on one line with `\n` for its line breaks works too.

Each `secret put` takes effect at once. Then deploy, so the `[vars]` change goes live: `npx wrangler deploy`.

### Self-hosted

Set the same six values with `DUMBSLAB_` in front:

```sh
export DUMBSLAB_GITHUB_APP_ID=1234567
export DUMBSLAB_GITHUB_APP_SLUG=dumbslab
export DUMBSLAB_GITHUB_APP_CLIENT_ID=Iv23li…
export DUMBSLAB_GITHUB_APP_CLIENT_SECRET=…
export DUMBSLAB_GITHUB_APP_WEBHOOK_SECRET=…
export DUMBSLAB_GITHUB_APP_PRIVATE_KEY="$(cat dumbslab.2026-11-01.private-key.pem)"
```

Then restart the server.

All six must be set; with any missing, Connect GitHub isn't offered and docs sync uses tokens only.

## 4. Check it

1. In a workspace, sign in as an admin and open **Settings › Docs sync**. **Connect GitHub** should be there.
2. Choose it, install the App on a test repository, and come back. The repository should be in the list.
3. Add a folder, then push a change to it. The post should change within a few seconds.
4. On the App's page, **Advanced › Recent Deliveries** shows each delivery and DumbSlab's answer. Hosted DumbSlab answers with how many workspaces it reached. If any of them didn't take it, the answer is a 502 and the Worker's log names those workspaces (by first address). Choose **Redeliver** once they're back: workspaces that already handled it handle it again the same way.

## How deliveries reach workspaces

GitHub sends every installation's events to one address, `<ROOT>/hooks/github`.

- **Hosted:** the root domain checks the signature (`X-Hub-Signature-256`, with the webhook secret). It then sends the delivery on, unchanged, to each workspace that connected that installation. The directory keeps that list (`installation_workspaces`): a workspace is added when an admin there connects the installation, and removed when it's uninstalled. Connecting waits for the directory to add it. One installation can serve up to 100 workspaces; past that, connecting says so (`installation_full`) and pushes don't reach the extra workspace, though Sync now works. If the directory couldn't be reached, each sync asks again until it's added. Each workspace checks the signature again, and acts only on installations its own admins connected.
- **Self-hosted:** the server is the only workspace, and gets deliveries directly.

A delivery about the installation itself (uninstalled, suspended, unsuspended, new permissions, repositories added or taken out) only starts a check of what GitHub says now:
- It reads the installation (`GET /app/installations/{id}` with the App's JWT; 404 means it's gone, `suspended_at` that it's suspended).
- While the installation is active, it reads each repository a folder here syncs by its id (`GET /repositories/{id}` with a metadata-only installation token). On a 404 it asks once more by the folder's repository name (`GET /repos/{owner}/{repo}`), and only an answer about the same id counts. That's at most 40 requests, however many repositories the installation has. A renamed repository renames its folders, and their next sync renders every file again.
- One check runs at a time per installation in each workspace. A change while it runs is noted, and checked right after.
- A check that fails waits a while (a minute, doubling up to an hour). The change it owed is checked by the next change GitHub reports, or after the wait by a push, Sync now, or opening Settings › Docs sync. Only a reported change skips the wait. Sync now and a refused sync token ask for a check only when none is owed.
- Only a check marks folders as disconnected. A late, out-of-order or redelivered delivery can't undo a newer change, and a sync that GitHub refuses a token for (422) asks for a check instead of deciding itself.

A workspace only syncs repositories its own admin's GitHub account can read in the installation. That's checked when they connect, so one workspace never gets repositories that only another workspace's admin chose. The list is kept per admin (`github_repositories` by installation, admin and repository), so within a workspace too, an admin adds folders only from repositories their own GitHub account could read. Folders already added sync for everyone, and any admin can run, change or remove them.

## Registering from a manifest instead

GitHub can also create the App from a manifest, with these settings filled in. Save this as `register.html`, open it in a browser signed in to GitHub, and submit it. To register under an organization, change the form's address to `https://github.com/organizations/<org>/settings/apps/new`.

```html
<form action="https://github.com/settings/apps/new" method="post">
  <input type="hidden" name="manifest" value='{
    "name": "DumbSlab",
    "url": "https://dumbslab.com",
    "description": "Keeps a repository folder’s Markdown files as posts in DumbSlab.",
    "hook_attributes": { "url": "https://dumbslab.com/hooks/github", "active": true },
    "redirect_url": "https://dumbslab.com/",
    "callback_urls": ["https://dumbslab.com/sync/github/callback"],
    "request_oauth_on_install": true,
    "setup_on_update": true,
    "public": true,
    "default_permissions": { "contents": "read", "metadata": "read" },
    "default_events": ["push"]
  }'>
  <button>Register DumbSlab's GitHub App</button>
</form>
```

After you confirm on GitHub, it sends you to `redirect_url` with `?code=…` in the address. Within an hour, exchange that code for the App's values:

```sh
curl -X POST -H "Accept: application/vnd.github+json" https://api.github.com/app-manifests/<code>/conversions
```

The answer has `id` (the App ID), `slug`, `client_id`, `client_secret`, `webhook_secret` and `pem` (the private key). GitHub makes the webhook secret itself. Put them in as in step 3. In `pem`, the line breaks are written as `\n`; DumbSlab accepts it that way.

## Facts this relies on

- App JWTs are RS256, with `iat` 60 seconds back and `exp` at most 10 minutes ahead, issued by the client ID: [generating a JWT](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app).
- Installation tokens last an hour and can be limited to some repositories and permissions: [create an installation access token](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app).
- With user authorization during installation, GitHub sends people to the callback URL instead of the setup URL: [registering a GitHub App](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/registering-a-github-app), [the setup URL](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/about-the-setup-url).
- `GET /user/installations` and `GET /user/installations/{id}/repositories` list what the person's own account can access: [installations](https://docs.github.com/en/rest/apps/installations).
- Every App gets `installation` and `installation_repositories` events: [webhook events](https://docs.github.com/en/webhooks/webhook-events-and-payloads).
- The manifest flow: [registering a GitHub App from a manifest](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest).
