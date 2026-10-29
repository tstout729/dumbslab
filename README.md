# DumbSlab

An open-source team knowledge base in the spirit of [Slab](https://slab.com), written in Rust and built so AI agents can do everything people can.

- **One binary, one SQLite file.** Or deploy to Cloudflare, where the whole workspace lives in a SQLite-backed Durable Object.
- **Every feature is an operation.** Each one is exposed four ways from a single definition: the REST API, a call-any-operation endpoint, MCP tools, and the CLI. The web app uses the same public API, so nothing is UI-only.
- **Agents are first-class.** There's a built-in MCP server with OAuth, precise edits that never clobber a teammate's change, bot accounts with their own identity, an activity feed every agent change shows up in, and signed webhooks.

## Features

| Area | What you get |
| --- | --- |
| Posts | Markdown posts with live preview, drafts, publish/archive, templates, duplicate, trash and restore |
| History | Every save is a version; diff any two versions and restore any of them |
| Topics | Nested topics, private topics with members, pinned posts, follow topics |
| Verification | Mark posts verified for N days; expired and stale docs surface in Insights |
| Collaboration | Threaded and inline (quoted) comments, resolve/reopen, emoji reactions, `@mentions`, backlinks |
| Search | Full-text search (SQLite FTS5) across posts, comments and topics; stemming, phrases, prefix matching, highlighted snippets, permission-aware |
| People | Admin, member and viewer roles, bot accounts, deactivation |
| Notifications | Mentions, replies, comments and updates on followed posts, new posts in followed topics |
| Admin | Workspace settings, API tokens with scopes, signed webhooks, JSON export, bulk Markdown import |

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
| `--open-setup` | | off (local development only: setup without a token) |

### Docker

```sh
docker build -t dumbslab .
docker run -p 8080:8080 -v dumbslab:/data dumbslab
```

### Cloudflare

See [docs/cloudflare.md](docs/cloudflare.md). In short: `cd crates/worker && npx wrangler secret put SETUP_TOKEN && npx wrangler deploy`.

## For agents

**MCP.** The server is at `https://your-host/mcp` (Streamable HTTP). Clients that support OAuth (Claude, ChatGPT, Cursor and others) only need the URL: you approve access in the browser, and the connection appears under Settings → API tokens, where you can revoke it.

```sh
claude mcp add --transport http dumbslab https://your-host/mcp
# or with a personal access token
claude mcp add --transport http dumbslab https://your-host/mcp --header "Authorization: Bearer ds_pat_..."
```

- `?toolset=core` exposes about 15 everyday tools plus `call_operation`, which reaches everything else. `?toolset=read` is read-only.
- Tools carry `readOnlyHint`, `destructiveHint` and `idempotentHint` annotations, typed input and output schemas, and `structuredContent` results.
- Resources: `dumbslab://guide`, `dumbslab://posts/{id}` (Markdown with front matter) and `dumbslab://topics/{id}`. Prompts: `write_post`, `find_stale_docs`, `summarize_topic`.
- Local agents can use stdio: `dumbslab mcp --as you@example.com`.

**REST.** `https://your-host/api/v1` with `Authorization: Bearer <token>`.

- OpenAPI 3.1: `/api/v1/openapi.json`. Agent guide: `/llms.txt`.
- Any operation by name: `POST /api/v1/operations/{name}` with the input as JSON.
- Precise edits: `POST /api/v1/posts/{id}/edit` with find/replace, append/prepend, and section edits addressed by heading text. Pass `base_version` to get a 409 instead of overwriting someone else's change.
- Polling: `GET /api/v1/activity?after_id=N`. Push: admins add webhooks signed with `x-dumbslab-signature: sha256=HMAC(secret, timestamp + "." + body)`.

**CLI.**

```sh
dumbslab ops                                          # list every operation
dumbslab call search '{"q":"onboarding"}' --as you@example.com
dumbslab openapi > openapi.json
```

Give each agent its own bot account (Settings → People → Add bot) and token. Its edits then show up under its own name in history and activity, with a badge showing whether they came in via `api`, `mcp` or `cli`.

## Permissions

- **Roles.** Admins manage everything. Members write and organize. Viewers read, comment and react.
- **Drafts** are visible only to their author and admins.
- **Private topics.** A post whose topics are all private is visible only to members of those topics. It is hidden from lists, search, activity and notifications for everyone else.
- **Tokens** carry `read`, `write` and/or `admin` scopes. A token never exceeds its owner's role, and an MCP connection from a read-only token lists only read-only tools.

## Architecture

```
crates/core    storage-agnostic core: schema, permissions, operations, REST routing, MCP, OAuth, search
crates/server  `dumbslab` binary: axum + SQLite (one transaction per request), embedded web app, CLI, stdio MCP
crates/worker  Cloudflare Worker + SQLite-backed Durable Object running the same core (compiled to wasm)
web/           the web app: plain HTML/CSS/JS modules, no build step
```

The core talks to SQLite through a small synchronous `Db` trait. The native server implements it with `rusqlite`; the Worker implements it with the Durable Object SQL API inside `transactionSync`. Both hosts run every request as a single transaction and roll back when an operation fails.

## Development

```sh
cargo test -p dumbslab-core -p dumbslab        # unit + end-to-end tests
cargo run -p dumbslab -- serve --open-setup    # debug builds read web/ from disk, so edits need only a reload
cd crates/worker && npx wrangler dev --var OPEN_SETUP:true   # the Cloudflare build, locally
```

See [AGENTS.md](AGENTS.md) for conventions, which apply to people too.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

DumbSlab is an independent project. It is not affiliated with or endorsed by Slab, Inc.
