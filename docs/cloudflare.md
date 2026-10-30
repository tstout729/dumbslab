# Deploying to Cloudflare

DumbSlab runs on Cloudflare Workers with no servers to manage:

- **Static assets** serve the web app from `web/`.
- **A Worker**, compiled from Rust to WebAssembly, routes every request.
- **SQLite-backed Durable Objects** hold the data. Each workspace is one object with its own private database. It runs the same core as the native server, wrapping every request in `transactionSync`. Cloudflare keeps this storage durable and lets you restore it to any point in the last 30 days.

There are two modes:

| Mode | `MULTI_TENANT` | What you get |
| --- | --- | --- |
| Hosted, like dumbslab.com | `"true"` | The root domain is a sign-up site. Anyone can create a workspace at `name.your-domain`. |
| One private workspace | `"false"` | Your whole domain is a single workspace, created with a setup token. |

## Requirements

- A Cloudflare account on the **Workers Paid** plan. Password hashing (Argon2) needs more than the free plan's 10 ms of CPU per request.
- Rust with the `wasm32-unknown-unknown` target: `rustup target add wasm32-unknown-unknown`.
- `worker-build`: `cargo install worker-build`.
- Wrangler 4.

## Hosted mode (multi-tenant)

The checked-in `crates/worker/wrangler.toml` deploys dumbslab.com in this mode. For your own domain:

1. Set `ROOT_DOMAIN` and the three `routes` to your domain.
2. Add a proxied wildcard DNS record so workspace subdomains reach the Worker: type `AAAA`, name `*`, content `100::`, proxied. Cloudflare's free Universal SSL covers one level of subdomains.
3. Add the secrets and deploy:

```sh
cd crates/worker
npx wrangler secret put SIGNUP_SECRET    # any long random string; signs one-hour sign-up links
npx wrangler secret put OPERATOR_TOKEN   # any long random string; unlocks the operator API
npx wrangler deploy
```

How sign-up works:

1. On the root domain, someone picks a workspace name and an address.
2. The `Directory` object reserves the address for an hour. It enforces the limits below.
3. The browser goes to `https://address.your-domain/setup` with a signed link, and the person creates the admin account.

An address nobody has signed up for answers "no workspace here" and creates no storage.

### Changing a workspace's address

Admins can move a workspace to another address under **Settings › Workspace**, or with the `change_address` operation (`POST /api/v1/settings/address`).

- **Data:** posts, people and API tokens all move with the workspace. Its data stays in the object named after its first address; the object for the new address only points there.
- **Signing in:** everyone signs in again at the new address, and AI tools need the new MCP URL.
- **Old addresses:** they stay reserved for the workspace. Browsers opening one are sent to the new address. API and MCP calls get a `410 workspace_moved` error that names it.
- **Limit:** a workspace can use 5 addresses in total, counting its first. Moving back to an earlier address is always allowed.

### Limits that keep it free

| Variable | Default | Meaning |
| --- | --- | --- |
| `SIGNUPS_PER_IP_PER_DAY` | `3` | New workspaces per visitor IP per day |
| `SIGNUPS_PER_DAY` | `200` | New workspaces per day overall |
| `MAX_WORKSPACES` | `1000` | Total workspaces; sign-up pauses at the cap |
| `WORKSPACE_STORAGE_MB` | `50` | A workspace past this size stops accepting new content. Reading, deleting and signing in keep working. |

What workspaces cost: a new workspace with its starter posts is about 0.3 MB. A busy one, with 100 documents each edited a few times, is about 6 MB. Workers Paid includes 5 GB of Durable Object storage and 1M Durable Object requests a month. So roughly a thousand active small-team workspaces, or many thousands of idle ones, fit in the included usage. Past that, storage is $0.20 per GB-month and requests are $0.15 per million.

### Operator API

Remove abuse with `Authorization: Bearer $OPERATOR_TOKEN` on the root domain:

```sh
curl -H "Authorization: Bearer $OPERATOR_TOKEN" https://your-domain/api/operator/workspaces
curl -X POST -H "Authorization: Bearer $OPERATOR_TOKEN" https://your-domain/api/operator/workspaces/acme/disable   # or enable
curl -X POST -H "Authorization: Bearer $OPERATOR_TOKEN" https://your-domain/api/operator/workspaces/acme/delete    # erases it; its addresses become free
```

Any of a workspace's addresses works in these URLs. The list shows each workspace's current `address` and its `previous_addresses`.

## Single-workspace mode

Set `MULTI_TENANT = "false"`. Point `routes` at your domain, set `BASE_URL` to its URL, and remove the wildcard route. Then:

```sh
npx wrangler secret put SETUP_TOKEN   # any long random string; needed once to create the first admin
npx wrangler deploy
```

Open `https://your-domain/setup?token=<SETUP_TOKEN>` and create the admin account. Setup works only while the workspace has no users. Once it's set up, you can delete the secret.

| Name | Kind | Purpose |
| --- | --- | --- |
| `SETUP_TOKEN` | secret | Required to create the first admin |
| `BASE_URL` | var | Public URL for links and OAuth metadata (defaults to the request origin) |
| `WORKSPACE_NAME` | var | Name of the Durable Object holding the workspace (default `main`) |
| `OPEN_SETUP` | var | `true` allows setup without a token. Only for local development. |

## Local development

```sh
cd crates/worker
npx wrangler dev --env dev
```

The `dev` environment runs hosted mode on `localhost` with throwaway secrets: open http://localhost:8787 and create a workspace. It appears at `http://name.localhost:8787`, and browsers resolve `*.localhost` to your machine.

## Backups

- Admins can export a workspace as JSON with the `export_workspace` operation: `GET /api/v1/export`.
- Durable Objects support point-in-time recovery for 30 days. See Cloudflare's [PITR API](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/#pitr-point-in-time-recovery-api).
