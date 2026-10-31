# DumbSlab's GitLab app (for operators)

With it, docs sync from gitlab.com needs no token and no webhook to copy. An admin chooses **Connect GitLab** in Settings › Docs sync, approves DumbSlab's app, and picks a project. DumbSlab adds the project's push webhook itself, and removes it when the folder is removed. Self-managed GitLab keeps using tokens.

It's the same GitLab OAuth app that [connected apps](../connected-apps.md) use (`GITLAB_CLIENT_ID` and `GITLAB_CLIENT_SECRET`). Docs sync asks it for more, so the app needs two additions.

Below, `<ROOT>` is your public address: `https://dumbslab.com` for hosted DumbSlab, or your self-hosted server's URL.

## 1. Set up the app on gitlab.com

If you have no GitLab app yet, make one: on gitlab.com, your avatar › **Edit profile** › **Applications** › **Add new application** (or a group's **Settings › Applications**, so it isn't tied to one person).

| Setting | Value |
| --- | --- |
| Name | `DumbSlab` |
| Redirect URI | Two lines: `<ROOT>/connect/callback` (connected apps) and `<ROOT>/sync/gitlab/callback` (docs sync) |
| Confidential | On |
| Scopes | `api` and `read_api` |

An existing app needs only the second redirect URI and the `api` scope added.

Why `api`: adding a project webhook writes to GitLab, and `read_api` only reads. GitLab has no narrower scope for it. The person approving needs the Maintainer role in the project, which GitLab requires to add webhooks. Connected apps keep asking for `read_api` only.

## 2. Give it to the server

| Host | Client id | Client secret |
| --- | --- | --- |
| Cloudflare | `GITLAB_CLIENT_ID` in `wrangler.toml` `[vars]` | `npx wrangler secret put GITLAB_CLIENT_SECRET` |
| Self-hosted | `DUMBSLAB_GITLAB_CLIENT_ID` | `DUMBSLAB_GITLAB_CLIENT_SECRET` |

The connector key must be set too. With both, Settings › Docs sync offers **Connect GitLab**.

## How it works

- **Each folder has its own approval.** Picking a project moves the approval's tokens onto that folder. GitLab's tokens last two hours, and each refresh replaces both tokens, so tokens shared between folders would break each other. For the next folder, the admin connects again.
- **Refreshing** happens at the start of a sync, under the sync's lease, so only one refresh runs at a time. An approval still waiting for a project is held by one request at a time (`docs_connections.claimed_until`), so it's refreshed once and never ends up in two folders.
- **If a folder can't sync** (someone revoked the app, or the approving admin lost access to the project), it says so. Its posts stay. An admin who maintains the project chooses Connect GitLab, then **Reconnect** on the folder. Reconnecting edits the webhook (`PUT /projects/:id/hooks/:hook_id`) to the workspace's address now and the folder's secret, or adds it again if it's gone. After a connector key change, the folder's secret can't be read, so it gets a new one, on GitLab too.
- **The webhook** points at the workspace's `/hooks/docs/<source id>` and carries the folder's own secret in `X-Gitlab-Token`. If the workspace moves to a new address, Reconnect points it at the new one.
- **Removing** a folder, or deleting its topic, removes its webhook. It waits for a running sync, so the removal uses the folder's current tokens. If saving a new folder fails after GitLab added its webhook, even when the host rolls the save back, the webhook comes off again.

## Facts this relies on

- Scopes: `api` grants read and write access to the API, `read_api` read access only: [OAuth provider](https://docs.gitlab.com/integration/oauth_provider/).
- Tokens expire after two hours, and refreshing replaces both tokens: [OAuth 2.0 API](https://docs.gitlab.com/api/oauth2/).
- Adding a project webhook needs the Maintainer role: [project webhooks API](https://docs.gitlab.com/api/project_webhooks/).
- `min_access_level=40` lists projects where you're a Maintainer: [projects API](https://docs.gitlab.com/api/projects/#list-all-projects).
