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
- **Refreshing** happens at the start of a sync. GitLab takes each refresh token once, so:
  - A refresh under way is noted on the folder, and another sync doesn't spend the same token for three minutes. It says to try again in a moment.
  - New tokens are kept if the folder still has the refresh token that was spent, even when the sync that asked lost its lease meanwhile. Only the token fields change, so webhook settings saved since stay.
  - If another refresh got there first, its newer tokens are used.
  - The step that reads a refresh's answer stores only the new tokens, so a full workspace keeps it (`Job::wrote_only_credentials`), as it does for the people sync. The same goes for an approval's refresh and a cleanup's.
  - A refusal only disconnects the folder if it still has the spent token and no other refresh of it may still land. If that other refresh lands after all, the folder is back. An approval still waiting for a project is held by one request at a time (`docs_connections.claimed_until`), so it's refreshed once and never ends up in two folders.
- **If a folder can't sync** (someone revoked the app, or the approving admin lost access to the project), it says so. Its posts stay. An admin who maintains the project chooses Connect GitLab, then **Reconnect** on the folder. Reconnecting edits the webhook (`PUT /projects/:id/hooks/:hook_id`) to the workspace's address now and the folder's secret, or adds it again if it's gone. After a connector key change, the folder's secret can't be read, so it gets a new one, on GitLab too.
- **The webhook** points at the workspace's `/hooks/docs/<source id>` and carries the folder's own secret in `X-Gitlab-Token`. The folder remembers the address it gave it. Every Sync now edits it (`PUT`) along with the folder's listing, and adds it again (`POST`) along with the next requests if GitLab says it's gone; it takes no extra step. Sync now points it at the workspace's address only when the server knows its own address (hosted, or `--base-url` / `DUMBSLAB_BASE_URL` / `BASE_URL` set); otherwise it keeps the address it was given, since a request's `Host` can be anything. Reconnect moves it, and Settings shows where it points. Pushes never change it. A sync that lost its lease to another never saves a webhook over that one's: it fails, and tries to take the webhook it added off again. Whether or not that works (its tokens may have been replaced), Sync now also lists the project's webhooks (`GET /projects/:id/hooks`, up to 200) and deletes every other one that posts to exactly this folder's `/hooks/docs/<id>` at an address the folder's webhook has had (the workspace's address now, when the server knows it, and up to 10 earlier ones). It must have the same scheme, host and path, with no query. Someone's own webhook that only ends the same way, on another host, under another path or with a query, is left alone.
- **Picking the project.** The picker sends the project's id. Adding the folder reads that project by id, among those the admin maintains (`GET /projects?membership=true&min_access_level=40&id_after=<id-1>&id_before=<id+1>`, which counts roles inherited from groups), and its webhook and folder use that id. The path is only for reading. An API caller that sends a path alone gets it looked up once, and the id kept.
- **Duplicates.** Two GitLab app folders are the same project only by id, so a project that takes another folder's old path is another project. A folder compares its path with others only after its sync has read the project's current path, so a stale path never stops it. Against a token folder, which has no id, paths are compared.
- **Reading the project.** A folder reads its project by id (`/projects/:id/repository/...`), never by path. Each sync also reads `GET /projects/:id` with its listing. If the project was renamed or moved, the folder follows the new path for its links and Settings, and its next sync renders every file again so links use it. Another project that takes the old path is never read. (A token folder, on gitlab.com or a self-managed GitLab, reads by path, so it follows whatever project has that path.)
- **Removing** a folder, or deleting its topic, removes every webhook pointing at it, found by listing the project's. It waits for a running sync, and for three minutes after a sync started renewing the folder's tokens (the renewal's answer may still bring new ones), so it says to try again in a moment. Removal then keeps the folder's tokens and its webhook's addresses in a cleanup record (`docs_hook_cleanup`, sealed with the connector key), and a pass starts right away:
  - The pass renews the tokens if they're about to expire, saving the new ones first. Then it lists the project's webhooks, deletes the folder's, and drops the record.
  - A pass that fails (GitLab down, 429, 5xx) waits a minute, doubling up to a day. Passes run again when Settings › Docs sync loads and with Sync now.
  - DumbSlab gives up only when GitLab definitely won't let it: it refuses to renew the same tokens twice (the first refusal may be a renewal still on its way), answers 401 or 403, or no longer shows the project. It also gives up after 30 days. Either way the activity log says so for admins (`docs_source.webhook_abandoned`), with the project and the webhook ids to delete by hand, and the tokens are dropped.
- **Adding a folder records its webhook first.** In the step that commits just before it asks GitLab for the webhook, DumbSlab keeps a cleanup record. The record holds the project, the webhook's exact address (with the new folder's id), and a sealed copy of the approval's tokens. Saving the folder drops the record in the same transaction.
  - If GitLab added the webhook but its answer was lost, or the folder wasn't saved, the record stays.
  - After 10 minutes (an add may still be under way), the usual cleanup passes find the webhook by that address and delete it. They have the same waits, retries and 30-day limit.
  - Saving the folder takes the record in the same transaction, but only if no cleanup pass ever claimed it. A pass may already have deleted the webhook of an add that took too long. Then nothing is saved, and the admin is told to try again.
  - The copied tokens may still be the approval's, so a pass never renews them. Once they expire, it holds the admin's approval like any request, renews that the approval's way if needed, and uses it.
  - When the approval moves onto a folder (another try at adding one, or a reconnect), records that borrowed it borrow that folder instead, in the same transaction. A pass then holds the folder as a sync does and uses its tokens. If those need renewing, it renews them the folder's way: the refresh is noted on the folder, and new tokens are kept only if the folder still has the refresh token that was spent. If that folder is removed, its removal record takes the borrowing records over, in the same transaction. Their exact webhook addresses (and their projects, if different) join it, and they go. One record, with the folder's tokens, then deletes them all. It keeps the latest grace period of the records it took over (`hold_until`). A webhook one of those adds asked for may still appear until then, so the record isn't done before a pass after that deadline finds nothing left.
- **Failed saves.** If saving a new folder, a reconnect, or a sync fails after GitLab added a webhook, the webhook comes off again: even when the host rolls the save back, or its transaction never starts or commits. Each job notes a webhook GitLab added before the step that saves it, so the notice a host sends for a failed step deletes it.

## Facts this relies on

- Scopes: `api` grants read and write access to the API, `read_api` read access only: [OAuth provider](https://docs.gitlab.com/integration/oauth_provider/).
- Tokens expire after two hours, and refreshing replaces both tokens: [OAuth 2.0 API](https://docs.gitlab.com/api/oauth2/).
- Adding a project webhook needs the Maintainer role: [project webhooks API](https://docs.gitlab.com/api/project_webhooks/).
- `min_access_level=40` lists projects where you're a Maintainer: [projects API](https://docs.gitlab.com/api/projects/#list-all-projects).
