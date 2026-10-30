# Working on DumbSlab

## Layout

- `crates/core`: everything that isn't transport or storage. Start at `src/lib.rs` (host contract), `src/registry.rs` (operations), `src/ops/*` (features), `src/model.rs` (visibility rules), `src/http.rs` (routing), `src/mcp.rs`, `src/oauth.rs`.
- `crates/server`: the `dumbslab` binary. `store.rs` implements the `Db` trait with rusqlite; `main.rs` is the axum host and CLI; `tests/api.rs` holds the end-to-end tests.
- `crates/worker`: the Cloudflare host (wasm). It must stay a thin adapter. `lib.rs` routes by host (hosted mode: sign-up site on the root domain, one `Workspace` object per subdomain), `workspace.rs` runs the core, and `directory.rs` tracks addresses. Shared tenancy rules (address validation, signed sign-up links, directory SQL) live in `crates/core/src/tenancy.rs` so they're tested natively.
- `web/`: the web app. Plain ES modules, no build step, no third-party code except the telemetry SDKs in `web/vendor` (loaded only when the host configures them; see `web/vendor/README.md`), CSP `script-src 'self'`.

## Rules

- **Every capability is an operation.** Add it with `op(...)` in `crates/core/src/ops/*`, with typed input and output structs (`Deserialize + JsonSchema` with `deny_unknown_fields`, and `Serialize + JsonSchema`). REST, MCP, OpenAPI, `/llms.txt` and the CLI pick it up automatically. Never add a UI-only or API-only path.
- **Write a description for the operation and doc comments on its fields.** Agents read them as tool documentation.
- **Visibility.** Every query that returns posts or topics uses `post_visible_sql` / `topic_visible_sql` (or `load_post` / `load_topic`). Notifications check `can_view_post` for the recipient.
- **Writes** emit an activity event with `events::emit`. Admin-only events use `.admin_only()`.
- **SQL** must run on both SQLite and Cloudflare Durable Objects. Use `?` placeholders only (no named parameters), no `BEGIN`/`SAVEPOINT`, and chunk `IN` lists with `model::query_in`. Schema changes go in a new file under `crates/core/src/migrations/`. Never edit a shipped migration.
- **Errors** are `ApiError`s. A failed operation rolls back the whole request, so validate before writing where you can.
- **Server HTML** (post bodies, comments, search snippets) is sanitized by the core. The web app inserts everything else as text.

## Checks

```sh
cargo fmt --all
cargo clippy -p dumbslab-core -p dumbslab --all-targets -- -D warnings
cargo clippy -p dumbslab-worker --target wasm32-unknown-unknown -- -D warnings
cargo test -p dumbslab-core -p dumbslab
```

Add an end-to-end test in `crates/server/tests/api.rs` for any new behavior, especially permissions.
