# Deploying to Cloudflare

DumbSlab runs on Cloudflare Workers with no servers to manage:

- **Static assets** serve the web app from `web/`.
- **A Worker**, compiled from Rust to WebAssembly, routes `/api/*`, `/mcp`, `/oauth/*`, `/.well-known/*` and `/llms.txt` to one Durable Object.
- **The Durable Object** holds the entire workspace in its private SQLite database. It runs the same core as the native server, wrapping every request in `transactionSync`.

Durable Object storage is durable and replicated, and you can restore it to any point in the last 30 days.

## Requirements

- A Cloudflare account on the **Workers Paid** plan. Password hashing (Argon2) needs more than the free plan's 10 ms of CPU per request.
- Rust with the `wasm32-unknown-unknown` target: `rustup target add wasm32-unknown-unknown`.
- `worker-build`: `cargo install worker-build`.
- Wrangler 4.

## Deploy

```sh
cd crates/worker
npx wrangler secret put SETUP_TOKEN    # any long random string; needed once to create the first admin
npx wrangler deploy
```

Then open `https://<your-worker>/setup?token=<SETUP_TOKEN>` and create the admin account. Setup works only while the workspace has no users. Once it's set up, you can delete the secret.

## Custom domain

The checked-in `wrangler.toml` deploys the project's own instance at dumbslab.com. Point the routes and `BASE_URL` at your domain instead (requests to `www.` redirect to the bare domain):

```toml
routes = [{ pattern = "wiki.example.com", custom_domain = true }]

[vars]
BASE_URL = "https://wiki.example.com"
```

## Configuration

| Name | Kind | Purpose |
| --- | --- | --- |
| `SETUP_TOKEN` | secret | Required to create the first admin |
| `BASE_URL` | var | Public URL for links and OAuth metadata (defaults to the request origin) |
| `WORKSPACE_NAME` | var | Name of the Durable Object holding the workspace (default `main`) |
| `OPEN_SETUP` | var | `true` allows setup without a token. Only for `wrangler dev`. |

## Local development

```sh
cd crates/worker
npx wrangler dev --var BASE_URL:http://localhost:8787 --var OPEN_SETUP:true
```

The `BASE_URL` override makes links and OAuth metadata point at your local server instead of the production domain.

## Backups

- Export everything as JSON with the `export_workspace` operation (admins): `GET /api/v1/export`.
- Durable Objects support point-in-time recovery for 30 days. See Cloudflare's [PITR API](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/#pitr-point-in-time-recovery-api).
