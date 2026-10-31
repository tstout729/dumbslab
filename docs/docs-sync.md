# Docs sync (GitHub and GitLab)

Docs sync keeps the Markdown files in a repository folder as posts in a topic. Write docs next to the code in GitHub or GitLab, and people find them in DumbSlab, with search, comments and verification. It's one way: the repository is the source of truth.

There's nothing to copy: on GitHub, choose **Connect GitHub**, install DumbSlab's app on the repositories you want, and pick one. On gitlab.com, choose **Connect GitLab**, approve DumbSlab's app, and pick a project. Pushes sync by themselves. See [set it up](#set-it-up).

- **Each file is a published post.** Files ending in `.md` or `.markdown`, in the folder and its sub-folders. Hidden folders (like `.github`) and `node_modules` are skipped.
- **Titles.** A post's title comes from the file's front matter (`title:`), or from a `# heading` at the very top (which then leaves the body, since the post shows its title), or from the file name: `getting-started.md` becomes "Getting started". A `README.md` or `index.md` is named after its folder.
- **Folders become sub-topics** of the topic you choose, with the same visibility. In a private topic, they're private and start with the topic's members. The sync remembers those memberships. When someone leaves the chosen topic, the next sync removes the membership it gave them. Memberships people add stay, but if they make the sub-topic wider, the check below applies. A sub-topic is named after its folder, cut to 120 characters, and numbered ("Guides (2)") when a sibling topic already has that name. Each post sits in the chosen topic and in its folder's sub-topic.
- **A synced post is never visible to more people than the chosen topic.** It always stays in the chosen topic: removing it from there is refused. Every sync checks each sub-topic, before reading files and again in the step that writes them. A sub-topic fails the check if someone made it public, or gave it a member the chosen topic doesn't have (admins don't count, since they see every topic). When one fails:
  - the source's posts are taken out of it, after making sure each is still in the chosen topic, so none is left in no topic. Each post moved this way records `post.moved` with the topics added and removed, like any change of topics;
  - its files are skipped, and the result gives the reason;
  - its visibility is never changed.
  Make it private with the topic's members, or delete it so the next sync makes a new one; the next sync then puts the posts back.
- **Links.** Relative links between synced files point at their posts, `#anchors` included; a link to a folder points at its README. Other relative links (source code, files outside the folder) point at the file on GitHub or GitLab.
- **Images.** PNG, JPEG, GIF, WebP and AVIF images inside the folder, up to 3 MB, are uploaded once and reused until they change. Other images (SVG, larger ones, ones outside the folder) link to the repository, so they only show if the reader can see the repository.
- **Other uploads stay private.** A synced post only gets the images the sync uploaded itself. If the text names another upload here (`/files/…`), that file isn't attached to the post, so the link opens only for people who could already open it. Anyone who can push to the repository writes these posts, so this keeps them from exposing private files.
- **Changes.** Each sync that changes a post saves a new version, like an edit, so history and diffs work. Synced changes don't notify anyone.
- **Renames.** A file moved or renamed without changes keeps its post, with its comments, links and history. A move to another folder moves the post to that folder's sub-topic and records `post.moved` (with the topics added and removed), like any change of topics, even when its text is unchanged.
- **Removed files.** When a file is gone from the repository, its post is **archived, never deleted**. It stays linked to the repository: if the file comes back at the same path, the post is published again once the file has been synced, even if that takes several runs.
- **Read-only here.** A synced post's title and content can only change in the repository. Saving, `edit_post` and restoring an old version are refused with a `synced_post` error that links to the file. The post shows "Synced from …; edit it there". Topics, status, pins, verification, comments and reactions still work. To edit a synced post here, duplicate it, or remove the source (its posts then become ordinary posts).

Only admins can set up, run or change a source (Settings › Docs sync, or the `list_docs_sources`, `list_github_repositories`, `list_gitlab_projects`, `create_docs_source`, `update_docs_source`, `sync_docs_source` and `delete_docs_source` operations). It's available on every plan. It needs the server's connector key (`CONNECTOR_KEY` on Cloudflare, `DUMBSLAB_CONNECTOR_KEY` self-hosted; see [connected apps](connected-apps.md)): tokens and webhook secrets are encrypted with it, and no operation returns a token. Synced posts are written as the admin who added the source, while they're still an active admin; otherwise as the workspace's first active admin. If that admin stops being one, at the next sync their synced posts and images pass to the admin it now writes as, and they keep no membership the sync gave them unless they're still in the chosen topic, so they keep no access through the source.

## Set it up

### GitHub: Connect GitHub

This works when the server has DumbSlab's GitHub App. Hosted DumbSlab does; a self-hosted server needs its own (see [the operator steps](hosting/github-app.md)). Without it, use [a token](#with-a-token).

1. In DumbSlab, open **Settings › Docs sync** and choose **Connect GitHub**.
2. GitHub asks where to install DumbSlab's app: your account or an organization, and all repositories or just some. Choose, then **Install & Authorize**. In an organization you don't own, GitHub asks an owner to approve it; once they have, choose Connect GitHub again.
3. Back in DumbSlab, pick the repository. Then the branch (it starts as the repository's default branch), the folder (leave it empty for the whole repository) and the topic.
4. Choose **Add and sync**. The first sync runs right away, and repeats until every file is in.

That's all. Every push to the branch syncs.

- **Which repositories you can pick.** Those the app can read that your own GitHub account can read too, as of when you connected. To add one, choose Connect GitHub again and give the app access to it. Another admin's repositories, or another workspace's, never show up for you, even when the app is installed on the same organization.
- **What the app can do.** Read files, nothing more (GitHub's "Contents: Read-only"). Each sync gets a token that reads only that one repository and lasts an hour. DumbSlab keeps no token.
- **Renamed repositories** keep syncing: DumbSlab follows the repository, not its name.
- **When a folder can't sync.** If the app is uninstalled or suspended on GitHub, or the repository is taken out of it, the folder says so in Settings and stops syncing. Its posts stay. It picks up again by itself when the app is unsuspended or the repository is put back. After an uninstall, Connect GitHub again: folders on repositories you can pick there pick up where they were.

Agents can do the same: `list_github_repositories` lists the repositories (and the `connect_url` an admin opens in a browser for step 2). Then `create_docs_source` with the repository's `installation_id` and `full_name`.

### gitlab.com: Connect GitLab

This works when the server has DumbSlab's GitLab app (see [the operator steps](hosting/gitlab-app.md)). Self-managed GitLab uses [a token](#with-a-token).

1. In DumbSlab, open **Settings › Docs sync** and choose **Connect GitLab**.
2. GitLab asks you to authorize DumbSlab. Choose **Authorize**.
3. Back in DumbSlab, pick the project: the list has the projects where you're a Maintainer, which adding a webhook needs. Then the branch, the folder and the topic.
4. Choose **Add and sync**. DumbSlab adds the project's push webhook, and the first sync runs.

- **What DumbSlab can do.** GitLab only offers full API access (`api`) for adding webhooks, so that's what you approve. DumbSlab uses it to list your projects, add and remove its own webhook, and read files. The tokens are encrypted, belong to that one folder, and are refreshed as GitLab requires.
- **Another folder** needs another approval: choose Connect GitLab again.
- **One request at a time.** An approval is used by one request at a time (listing projects, adding or reconnecting a folder): GitLab replaces its tokens whenever they're refreshed. Another request meanwhile is refused with "try again in a moment".
- **When a folder can't sync** because GitLab stopped accepting its approval (you revoked it), or whoever approved it lost access to the project, the folder says so. Its posts stay. Any admin who maintains the project chooses Connect GitLab, then **Reconnect** on the folder. Reconnecting also puts the webhook right: it points it at the workspace's address now, gives it the folder's secret, and adds it again if someone deleted it.
- **Removing the folder**, or its topic, removes the webhook DumbSlab added. While a sync of it runs, removing it waits: it's refused until the sync is done, so the removal uses the folder's current tokens.

Agents can do the same: `list_gitlab_projects` lists the projects (and the `connect_url` an admin opens in a browser first). Then `create_docs_source` with `gitlab_connection: true`.

### With a token

For self-managed GitLab, and for GitHub or gitlab.com without DumbSlab's apps. In Settings › Docs sync, **Use a token instead** shows this form.

1. Make a read-only token, unless the repository is public:
   - **GitHub:** a [fine-grained personal access token](https://github.com/settings/personal-access-tokens/new) with access to just that repository and the **Contents: Read-only** permission (Metadata: Read-only is added automatically). A classic token with `repo` works too, but gives far more access.
   - **GitLab** (gitlab.com or self-managed): a personal, group or project access token with the **read_api** scope. `read_repository` alone doesn't cover the tree and blob API that sync uses.
2. In DumbSlab, open **Settings › Docs sync** › **Add a folder**. Choose GitHub or GitLab. Enter the repository: `owner/name`, a GitLab project path (`group/subgroup/project`), or the repository's address. For self-managed GitLab, also enter its address. Then enter the branch (default `main`), the folder (leave it empty for the whole repository), the topic, and the token.
3. Choose **Add and sync**. The first sync runs right away, and repeats until every file is in.
4. DumbSlab then shows the **webhook secret once**. Add a push webhook with it:
   - **GitHub:** the repository's Settings › Webhooks › Add webhook. Payload URL: the webhook address shown (`https://<your workspace>/hooks/docs/<source id>`). Content type: `application/json`. Secret: the webhook secret. Events: just the push event.
   - **GitLab:** the project's Settings › Webhooks › Add new webhook. URL: the webhook address. Secret token: the webhook secret. Trigger: push events.

After that, every push to the branch syncs. **Sync now** syncs any time. **New webhook secret** replaces a secret you didn't keep: update the webhook with the new one.

## Webhooks

- **DumbSlab's GitHub App:** GitHub sends every push to the app's own address. DumbSlab checks its signature, and syncs the folders on that repository and branch in workspaces whose admins connected the installation. Pushes to other branches, tags, and repositories no folder syncs are ignored. The sync starts right after the answer, so GitHub never waits for it.
- **GitHub with a token:** DumbSlab checks `X-Hub-Signature-256` (`sha256=` + hex HMAC-SHA256 of the raw body, keyed with the secret) in constant time. A ping gets `pong`. A push to another branch, or another event, is ignored.
- **GitLab:** DumbSlab compares `X-Gitlab-Token` with the secret in constant time. Only `Push Hook` events to the branch start a sync. Through DumbSlab's GitLab app, DumbSlab added the webhook with the folder's own secret, so there's nothing to check by hand.
- **What a delivery is trusted for.** A delivery only means that something changed. Apart from the repository and branch, used to pick the folders it's about, nothing in it is used: the sync reads the repository itself.
- **Errors.** A delivery with a wrong or missing signature gets a 401. If a sync is already running, the delivery is noted, and Settings says to sync again.
- **Timing.** With a token, a delivery's response waits for its sync, which is usually a second or two. GitHub and GitLab give up after 10 seconds, but the sync's progress is kept either way.
- **Moving the workspace.** Webhooks you added with a token, and those DumbSlab added to GitLab projects, are on the workspace's own address. If the workspace moves to a new address, update yours, and choose Connect GitLab, then Reconnect, on folders that came through Connect GitLab. The GitHub App's address doesn't change.

## Limits

| Limit | Value | Why |
| --- | --- | --- |
| Markdown files per source | 500 | Keeps one listing and its bookkeeping small; split a larger folder into several sources |
| Changed files per sync | 20 | A sync is one job of at most 5 steps; `remaining` says what's left, and the next sync carries on |
| Images uploaded per sync | 10 | Same; a file whose images don't fit waits for the next sync |
| Post size after links are rewritten | 2 MB | A file whose rewritten links make it longer is skipped until it changes; the rest of the run goes on |
| Markdown file size | 1 MB | Larger files are skipped and listed. GitLab's listing has no sizes, so there a file turns out too large when it's read; it's then skipped until it changes, so it doesn't hold up other files |
| Image size | 3 MB | Images arrive as base64 in JSON, which must fit in a 4 MB answer; larger ones link to the repository |
| GitLab folder listing | 1,000 files and folders | GitLab lists 100 per page; a sync asks for 10 pages at once |
| Sources per workspace | 20 | |

A large first sync takes several runs. The Settings page keeps running them until everything is in, and agents call `sync_docs_source` again while `remaining` is above 0. A push syncs at most 20 changed files. A bigger push leaves the source `partial` until the next push or **Sync now**.

If a listing has no Markdown files at all (a renamed folder or a deleted branch, say), the sync fails and archives nothing.

## How it works

- **Requests.** The core builds every request and the host only sends it: over https, without following redirects, within 8 seconds, reading at most 4 MB.
  - GitHub: `GET /repos/{owner}/{repo}/git/trees/{branch}:{folder}?recursive=1` lists the folder, and `GET /repos/{owner}/{repo}/git/blobs/{sha}` reads each changed file and image. Through DumbSlab's GitHub App, a sync first signs the app's token request (a JWT) and asks for a token: `POST /app/installations/{id}/access_tokens`, for this repository and Contents: Read-only only. The app's private key stays with the server; it's never in a workspace's database.
  - GitLab: `GET /projects/{path}/repository/tree` and `.../repository/blobs/{sha}`. Through DumbSlab's GitLab app, a sync first refreshes the folder's token when it's about to expire (`POST https://gitlab.com/oauth/token`). Adding a folder reads the project (`GET /projects/{path}`) and adds its webhook (`POST /projects/{id}/hooks`); removing it deletes the webhook.
  - The self-hosted server refuses private network addresses, as it does for connected apps.
- **What changed.** Files are compared by their git blob id, so unchanged files aren't read again. A file is also read again when a file it links to appears, or when an image it shows changes.
- **Where things are kept.** The `docs_items` table remembers each file's post, each image's upload and each folder's topic. `github_installations` and `github_repositories` keep the app installations admins here connected, and the repositories their GitHub accounts could read there. A new file's post id is chosen when it's first listed, so links to it work while a large first sync is still running.
- **One sync at a time** per source.
- **Plans.** Every post, version and upload counts against the plan's daily writes and storage, like any change.
- **Removing.** Deleting the chosen topic removes its sources too. Its posts stay, as ordinary posts. Removing a source, or its topic, waits for a running sync of it: it's refused until the sync is done.
- **Workspace webhooks and Slack channels** hear of synced changes (`post.created`, `post.updated`, `post.archived`, `post.published` and the rest) like any change, once the sync's run finishes. Each event is recorded after the post is in its topics, so channels decide who may see it by where it ended up. If a later step of a run fails, the changes earlier steps saved are still announced.
