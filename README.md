# DumbSlab

An open-source team knowledge base, written in Rust and built so AI agents can do everything people can.

**Try it free at [dumbslab.com](https://dumbslab.com).** Pick an address, and your workspace lives at `name.dumbslab.com`. Every feature is free there; a Pro plan adds storage and daily writes for teams that need more room. Or self-host it from this repository, with no limits at all.

- **One binary, one SQLite file.** Or deploy to Cloudflare, where each workspace is its own SQLite-backed Durable Object. It runs either as a hosted service anyone can sign up for, or as one private workspace.
- **Every feature is an operation.** Each one is exposed four ways from a single definition: the REST API, a call-any-operation endpoint, MCP tools, and the CLI. The web app uses the same public API, so nothing is UI-only.
- **Agents are first-class.** There's a built-in MCP server with OAuth, precise edits that never clobber a teammate's change, bot accounts with their own identity, an activity feed every agent change shows up in, and signed webhooks.

## Features

| Area | What you get |
| --- | --- |
| Posts | Markdown posts with live preview, drafts, publish/archive, templates, duplicate, trash and restore |
| Rich content | Embeds (paste a link on its own line: YouTube, Vimeo, Loom, Wistia, Google Docs/Sheets/Slides/Forms/Drive, Word/Excel/PowerPoint embed links from OneDrive or SharePoint, Figma, Canva, Miro, Lucid, Draw.io, Gliffy, Airtable, Smartsheet, monday.com, Mode, Typeform, Jotform, CodePen, JSFiddle, iorad, Ludus, SlideShare, Dropbox images and videos; X posts show as a link card), callouts (`> [!NOTE]`, `[!TIP]`, `[!IMPORTANT]`, `[!WARNING]`, `[!CAUTION]`), tables, checklists, toggles (`<details>`), linked URLs |
| Images and files | Paste, drop or upload screenshots and files into a post (10 MB each). Images show inline; other files download |
| History | Every save is a version; diff any two versions and restore any of them |
| Topics | Nested topics, private topics with members, pinned posts, follow topics |
| Verification | Mark posts verified for N days; expired and stale docs surface in Insights |
| Collaboration | Threaded and inline (quoted) comments, resolve/reopen, emoji reactions, `@mentions`, backlinks |
| Search | Full-text search (SQLite FTS5) across posts, comments and topics; stemming, phrases, prefix matching, highlighted snippets, permission-aware |
| People | Admin, member and viewer roles, bot accounts, deactivation |
| People sync | Titles, departments, locations, work phones, pronouns and managers from BambooHR, matched by work email, on demand or by BambooHR webhook. Admins set it up in Settings › People sync. See [docs/people-sync.md](docs/people-sync.md) |
| Docs sync | A GitHub or GitLab folder's Markdown files kept as read-only posts in a topic, one way: sub-folders become sub-topics, relative links and images keep working, and each push syncs. Admins set it up in Settings › Docs sync. See [docs/docs-sync.md](docs/docs-sync.md) |
| Notifications | Mentions, replies, comments and updates on followed posts, new posts in followed topics |
| Admin | Workspace settings, API tokens with scopes, signed webhooks, JSON export, bulk Markdown import |
| Connected apps | Everyone connects their own GitHub, Google Drive, Slack, Jira, Confluence, Zendesk, Asana, Box, Dropbox, Guru and more, to search them from DumbSlab and preview links to them in posts. See [docs/connected-apps.md](docs/connected-apps.md) |

## Quick start

```sh
cargo run --release -p dumbslab -- serve
```

On first run the server logs a one-time setup link (`/setup?token=…`). Open it to create the admin account. A "Getting Started" topic is created for you.

Options (flags or environment variables):

| Flag | Env | Default |
| --- | --- | --- |
| `--db` | `DUMBSLAB_DB` | `dumbslab.db` |
| `--bind` | `DUMBSLAB_BIND` | `127.0.0.1:8080` |
| `--base-url` | `DUMBSLAB_BASE_URL` | the request's origin |
| `--setup-token` | `DUMBSLAB_SETUP_TOKEN` | generated and logged |
| | `DUMBSLAB_CONNECTOR_KEY` | unset: [connected apps](docs/connected-apps.md), people sync and docs sync are off |
| `--open-setup` | | off (local development only: setup without a token) |

### Docker

```sh
docker build -t dumbslab .
docker run -p 127.0.0.1:8080:8080 -v dumbslab:/data dumbslab
```

This publishes the server on your machine only. Passwords and session cookies must not cross a network in the clear, so to share it, put it behind a reverse proxy that serves HTTPS (Caddy, nginx, a Cloudflare Tunnel) and start it with `--base-url https://your-host`. The public URL decides whether cookies are marked `Secure`, and connected apps' tokens only work at that address.

### Cloudflare

See [docs/cloudflare.md](docs/cloudflare.md). It covers both the hosted multi-tenant mode that runs dumbslab.com and a single private workspace.

## For agents

**MCP.** The server is at `https://your-host/mcp` (Streamable HTTP). Clients that support OAuth (Claude, ChatGPT, Cursor and others) only need the URL: you approve access in the browser, and the connection appears under Settings → API tokens, where you can revoke it.

```sh
claude mcp add --transport http dumbslab https://your-host/mcp
# or with a personal access token
claude mcp add --transport http dumbslab https://your-host/mcp --header "Authorization: Bearer ds_pat_..."
```

- `?toolset=core` exposes about 15 everyday tools plus `call_operation`, which reaches everything else. `?toolset=read` lists only read-only tools, and apps that sign in through it get read-only access. With a token, use a read-only one: a token's scopes, not the URL, decide what it can do.
- Tools carry `readOnlyHint`, `destructiveHint` and `idempotentHint` annotations, typed input and output schemas, and `structuredContent` results.
- Resources: `dumbslab://guide`, `dumbslab://posts/{id}` (Markdown with front matter) and `dumbslab://topics/{id}`. Prompts: `write_post`, `find_stale_docs`, `summarize_topic`.
- Local agents can use stdio: `dumbslab mcp --as you@example.com`.

**REST.** `https://your-host/api/v1` with `Authorization: Bearer <token>`.

- OpenAPI 3.1: `/api/v1/openapi.json`. Agent guide: `/llms.txt`.
- Any operation by name: `POST /api/v1/operations/{name}` with the input as JSON.
- Precise edits: `POST /api/v1/posts/{id}/edit` with find/replace, append/prepend, and section edits addressed by heading text. Pass `base_version` to get a 409 instead of overwriting someone else's change.
- Images and files: `POST /api/v1/files` (`upload_file`) with `name`, the bytes as `data_base64` (up to 10 MB) and an optional `post_id`. It returns `markdown` to put in a post: `![name](/files/<id>/<name>)` shows an image, `[name](/files/<id>/<name>)` links a download. Fetch the bytes from `/files/<id>/<name>` with your token.
- Polling: `GET /api/v1/activity?after_id=N`. Push: admins add webhooks signed with `x-dumbslab-signature: sha256=HMAC(secret, timestamp + "." + body)`.

**CLI.**

```sh
dumbslab ops                                          # list every operation
dumbslab call search '{"q":"onboarding"}' --as you@example.com
dumbslab openapi > openapi.json
```

An agent can also start a hosted workspace for a person: [dumbslab.com/llms.txt](https://dumbslab.com/llms.txt) explains how.

Give each agent its own bot account (Settings → People → Add bot) and token. Its edits then show up under its own name in history and activity, with a badge showing whether they came in via `api`, `mcp` or `cli`.

## Permissions

- **Roles.** Admins manage everything. Members write and organize. Viewers read, comment and react.
- **Drafts** are visible only to their author and admins. So is the **trash**: a trashed post disappears for everyone else until it's restored.
- **Private topics.** A post whose topics are all private is visible only to members of those topics. It is hidden from lists, search, activity and notifications for everyone else. Removing its last private topic is refused, because a post without topics is visible to everyone; to share it, add an org-wide topic.
- **Files** are stored in the workspace database and open only for signed-in people. A file that belongs to a post (uploaded for it, or referenced when its uploader saves the post) opens only for people who can see that post. PNG, JPEG, GIF, WebP and AVIF images, recognized by their bytes, show inline; everything else, including SVG and HTML, downloads.
- **Tokens** carry `read`, `write` and/or `admin` scopes. A token never exceeds its owner's role, and an MCP connection from a read-only token lists only read-only tools. Tokens can't change passwords, and a connected app can't create tokens or revoke other credentials unless it was granted `admin`.

## Architecture

```
crates/core    storage-agnostic core: schema, permissions, operations, REST routing, MCP, OAuth, search
crates/server  `dumbslab` binary: axum + SQLite (one transaction per request), embedded web app, CLI, stdio MCP
crates/worker  Cloudflare Worker: a Durable Object per workspace running the same core (wasm), plus the sign-up Directory
web/           the web app: plain HTML/CSS/JS modules, no build step
```

The core talks to SQLite through a small synchronous `Db` trait. The native server implements it with `rusqlite`; the Worker implements it with the Durable Object SQL API inside `transactionSync`. Both hosts run every request as a single transaction and roll back when an operation fails.

## Development

```sh
cargo test -p dumbslab-core -p dumbslab        # unit + end-to-end tests
cargo run -p dumbslab -- serve --open-setup    # debug builds read web/ from disk, so edits need only a reload
cd crates/worker && npx wrangler dev --env dev   # the hosted Cloudflare build, locally (workspaces at name.localhost:8787)
```

See [AGENTS.md](AGENTS.md) for conventions, which apply to people too.

## Support

[Report a bug](https://github.com/tstout729/dumbslab/issues/new?template=bug_report.yml) with steps to reproduce it and what you expected to happen. Public issues are visible to everyone; leave out passwords, tokens, workspace content and other private details.

For account, billing or other private support, email [simplycoo+dumbslab@mail.grokbot.com](mailto:simplycoo+dumbslab@mail.grokbot.com).

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
