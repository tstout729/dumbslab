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
- **Refreshing** happens at the start of a sync, under the sync's lease, so only one refresh runs at a time.
- **If GitLab stops accepting a folder's tokens** (someone revoked the app, or the approving admin lost access), the folder says so and stops syncing. Its posts stay. An admin chooses Connect GitLab, then **Reconnect** on the folder. The webhook stays as it was.
- **The webhook** points at the workspace's `/hooks/docs/<source id>` and carries the folder's own secret in `X-Gitlab-Token`. If the workspace moves to a new address, remove the folder and add it again, so the webhook follows.

## Facts this relies on

- Scopes: `api` grants read and write access to the API, `read_api` read access only: [OAuth provider](https://docs.gitlab.com/integration/oauth_provider/).
- Tokens expire after two hours, and refreshing replaces both tokens: [OAuth 2.0 API](https://docs.gitlab.com/api/oauth2/).
- Adding a project webhook needs the Maintainer role: [project webhooks API](https://docs.gitlab.com/api/project_webhooks/).
- `min_access_level=40` lists projects where you're a Maintainer: [projects API](https://docs.gitlab.com/api/projects/#list-all-projects).
