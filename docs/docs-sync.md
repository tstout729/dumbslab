# Docs sync (GitHub and GitLab)

Docs sync keeps the Markdown files in a repository folder as posts in a topic. Write docs next to the code in GitHub or GitLab, and people find them in DumbSlab, with search, comments and verification. It's one way: the repository is the source of truth.

- **Each file is a published post.** Files ending in `.md` or `.markdown`, in the folder and its sub-folders. Hidden folders (like `.github`) and `node_modules` are skipped.
- **Titles.** A post's title comes from the file's front matter (`title:`), or from a `# heading` at the very top (which then leaves the body, since the post shows its title), or from the file name: `getting-started.md` becomes "Getting started". A `README.md` or `index.md` is named after its folder.
- **Folders become sub-topics** of the topic you choose, with the same visibility. Each post sits in the chosen topic and in its folder's sub-topic, so a synced post is never visible to more people than the chosen topic. In a private topic, the sub-topics are private too. Their only member is the admin who set up the sync, and you can add more.
- **Links.** Relative links between synced files point at their posts, `#anchors` included; a link to a folder points at its README. Other relative links (source code, files outside the folder) point at the file on GitHub or GitLab.
- **Images.** PNG, JPEG, GIF, WebP and AVIF images inside the folder, up to 3 MB, are uploaded once and reused until they change. Other images (SVG, larger ones, ones outside the folder) link to the repository, so they only show if the reader can see the repository.
- **Changes.** Each sync that changes a post saves a new version, like an edit, so history and diffs work. Synced changes don't notify anyone.
- **Renames.** A file moved or renamed without changes keeps its post, with its comments, links and history.
- **Removed files.** When a file is gone from the repository, its post is **archived, never deleted**. It stays linked to the repository: if the file comes back at the same path, the post is published again.
- **Read-only here.** A synced post's title and content can only change in the repository. Saving, `edit_post` and restoring an old version are refused with a `synced_post` error that links to the file. The post shows "Synced from …; edit it there". Topics, status, pins, verification, comments and reactions still work. To edit a synced post here, duplicate it, or remove the source (its posts then become ordinary posts).

Only admins can set up, run or change a source (Settings › Docs sync, or the `list_docs_sources`, `create_docs_source`, `update_docs_source`, `sync_docs_source` and `delete_docs_source` operations). It's available on every plan. It needs the server's connector key (`CONNECTOR_KEY` on Cloudflare, `DUMBSLAB_CONNECTOR_KEY` self-hosted; see [connected apps](connected-apps.md)): tokens and webhook secrets are encrypted with it, and no operation returns a token. Synced posts are written as the admin who added the source.

## Set it up

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

- **GitHub:** DumbSlab checks `X-Hub-Signature-256` (`sha256=` + hex HMAC-SHA256 of the raw body, keyed with the secret) in constant time. A ping gets `pong`. A push to another branch, or another event, is ignored.
- **GitLab:** DumbSlab compares `X-Gitlab-Token` with the secret in constant time. Only `Push Hook` events to the branch start a sync.
- **What a delivery is trusted for.** A delivery only means that something changed. Apart from the branch name used to ignore other branches, nothing in it is used: the sync reads the repository itself.
- **Errors.** A delivery with a wrong or missing signature gets a 401. If a sync is already running, the delivery is noted, and Settings says to sync again.
- **Timing.** A delivery's response waits for its sync, which is usually a second or two. GitHub and GitLab give up after 10 seconds, but the sync's progress is kept either way.
- **Moving the workspace.** Webhook addresses are on the workspace's own address. If the workspace moves to a new address, update the webhooks.

## Limits

| Limit | Value | Why |
| --- | --- | --- |
| Markdown files per source | 500 | Keeps one listing and its bookkeeping small; split a larger folder into several sources |
| Changed files per sync | 20 | A sync is one job of at most 4 steps; `remaining` says what's left, and the next sync carries on |
| Images uploaded per sync | 10 | Same; a file whose images don't fit waits for the next sync |
| Markdown file size | 1 MB | Larger files are skipped and listed |
| Image size | 3 MB | Images arrive as base64 in JSON, which must fit in a 4 MB answer; larger ones link to the repository |
| GitLab folder listing | 1,000 files and folders | GitLab lists 100 per page; a sync asks for 10 pages at once |
| Sources per workspace | 20 | |

A large first sync takes several runs. The Settings page keeps running them until everything is in, and agents call `sync_docs_source` again while `remaining` is above 0. A push syncs at most 20 changed files. A bigger push leaves the source `partial` until the next push or **Sync now**.

If a listing has no Markdown files at all (a renamed folder or a deleted branch, say), the sync fails and archives nothing.

## How it works

- **Requests.** The core builds every request and the host only sends it: over https, without following redirects, within 8 seconds, reading at most 4 MB.
  - GitHub: `GET /repos/{owner}/{repo}/git/trees/{branch}:{folder}?recursive=1` lists the folder, and `GET /repos/{owner}/{repo}/git/blobs/{sha}` reads each changed file and image.
  - GitLab: `GET /projects/{path}/repository/tree` and `.../repository/blobs/{sha}`.
  - The self-hosted server refuses private network addresses, as it does for connected apps.
- **What changed.** Files are compared by their git blob id, so unchanged files aren't read again. A file is also read again when a file it links to appears, or when an image it shows changes.
- **Where things are kept.** The `docs_items` table remembers each file's post, each image's upload and each folder's topic. A new file's post id is chosen when it's first listed, so links to it work while a large first sync is still running.
- **One sync at a time** per source.
- **Plans.** Every post, version and upload counts against the plan's daily writes and storage, like any change.
- **Removing.** Deleting the chosen topic removes its sources too. Its posts stay, as ordinary posts.
- **Not sent:** a synced change records activity, but the job that makes it can't send the workspace's own outgoing webhooks yet.
