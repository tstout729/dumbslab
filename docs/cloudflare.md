# Deploying to Cloudflare

DumbSlab runs on Cloudflare Workers with no servers to manage:

- **Static assets** serve the web app from `web/`.
- **A Worker**, compiled from Rust to WebAssembly, routes every request.
- **HTTPS only.** The Worker redirects plain HTTP to HTTPS and sends `Strict-Transport-Security` (covering workspace subdomains in hosted mode), except on `localhost` for `wrangler dev`.
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

1. Set `ROOT_DOMAIN` and the three `routes` to your domain. Also replace `https://dumbslab.com` in `web/welcome.html`: the sign-up page's canonical link, social tags and structured data name it.
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

An address nobody has signed up for answers "no workspace here" and creates no storage. While someone types, the form asks `GET /api/signup/check?address=…` whether the address is free.

For search engines and agents, the root domain serves `/robots.txt`, `/sitemap.xml` and `/llms.txt`, built from `ROOT_DOMAIN`. The `llms.txt` explains how an agent can start a sign-up for a person. Every workspace subdomain answers `/robots.txt` with `Disallow: /`, so its sign-in pages stay out of search results.

### Changing a workspace's address

Admins can move a workspace to another address under **Settings › Workspace**, or with the `change_address` operation (`POST /api/v1/settings/address`).

- **Data:** posts, people and API tokens all move with the workspace. Its data stays in the object named after its first address; the object for the new address only points there.
- **Signing in:** everyone signs in again at the new address, and AI tools need the new MCP URL.
- **Old addresses:** they stay reserved for the workspace. Browsers opening one are sent to the new address. API and MCP calls get a `410 workspace_moved` error that names it.
- **Limit:** a workspace can use 5 addresses in total, counting its first. Moving back to an earlier address is always allowed.

### Plans and the limits that keep it free

Every feature is on every plan: MCP, the API, webhooks, uploads, people and bots. Plans differ only in what costs money to run, which is storage and database writes. Past either limit, changes are refused; reading, signing in, exporting and upgrading keep working.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SIGNUPS_PER_IP_PER_DAY` | `3` | New workspaces per visitor IP per day |
| `SIGNUPS_PER_DAY` | `200` | New workspaces per day overall |
| `MAX_WORKSPACES` | `1000` | Total workspaces; sign-up pauses at the cap |
| `FREE_STORAGE_MB` | `50` | A free workspace's storage, uploads included |
| `FREE_WRITES_PER_DAY` | `50000` | Database rows a free workspace may write in any 24 hours |
| `PRO_STORAGE_MB` | `5120` | A Pro workspace's storage (a Durable Object holds at most 10 GB) |
| `PRO_WRITES_PER_DAY` | `200000` | Database rows a Pro workspace may write in any 24 hours |
| `FREE_TOTAL_WRITES_PER_DAY` | `1000000` | Rows all free workspaces together may write in 24 hours |
| `FREE_TOTAL_STORAGE_MB` | `4096` | What all free workspaces together may store |
| `PRO_PRICE_LABEL` | `$8 a month` | How Pro's price reads in the app and on the sign-up page |

How the limits work:

- **Writes** are counted as Cloudflare bills them: every row a request's statements write, index and search-index rows included, even when the request is rolled back. Signing in doesn't count, since anyone can fail to sign in and the sign-in limits already bound those writes. Each workspace keeps hourly totals and refuses changes, including new app registrations, once the last 24 hours reach its allowance. Anonymous app registration (OAuth's `/oauth/register`) is also capped at 120 an hour per workspace. Measured costs: a new 2 KB post writes about 18 rows, an edit about 10, a comment about 10, an upload about 9, and an imported document about 19. Agents reading posts write nothing.
- **Storage** is the workspace database's size. A change that would take it past the plan's allowance is refused with `507 storage_full`.
- **The free plan's totals.** Each busy workspace reports its plan, recent writes and size to the `Directory` every five minutes at most. Once free workspaces together reach `FREE_TOTAL_WRITES_PER_DAY`, free workspaces stop accepting changes (`503 free_capacity`) until the total falls. Once they reach `FREE_TOTAL_STORAGE_MB`, they stop growing. In both cases sign-ups pause. Pro workspaces are never paused.
- **Request floods.** The `REQUEST_LIMITER` binding lets each client network (an IPv4 address or IPv6 /64) make 1,200 API, MCP and file requests a minute, enough for a whole office behind one address. The Worker refuses the rest with `429` before they reach a workspace. Static files aren't counted.

What this costs. Workers Paid ($5 a month) includes 50 million rows written and 5 GB stored a month; past that, rows are $1.00 per million and storage $0.20 per GB-month. The free plan's totals keep free use inside the included amounts: 1 million rows a day is about 30 million a month, and 4 GB stays under 5 GB. A Pro workspace at its limits for a whole month writes about 6 million rows and stores 5 GB, roughly $7 if nothing else were included, which is less than its $8 price after Stripe's fee. Requests cost little (Workers $0.30 and Durable Objects $0.15 per million past what's included); the request limit stops any one network from running them up, and Cloudflare's DDoS protection handles floods from many.

### Selling Pro with Stripe

Pro goes on sale once three things are set. Until then, `upgrade_plan` answers `503 unavailable`, and the app and sign-up page say Pro is coming soon.

1. In the Stripe account that should be paid, create the product, the monthly price, the customer portal settings and the webhook endpoint. Use the account's secret key, or a restricted key that can write Products, Prices, Customer portal and Webhook Endpoints:

   ```sh
   STRIPE_API_KEY=sk_live_... scripts/stripe-setup.sh https://your-domain 800   # price in cents
   ```

2. For the Worker, create a [restricted key](https://docs.stripe.com/keys#limit-access) that can only write Checkout Sessions and Customer portal, and read Subscriptions and Charges.
3. Put the printed `STRIPE_PRICE_ID` and `STRIPE_PORTAL_CONFIG` in `wrangler.toml`, add the secrets and deploy:

   ```sh
   cd crates/worker
   npx wrangler secret put STRIPE_SECRET_KEY       # the Worker's restricted key
   npx wrangler secret put STRIPE_WEBHOOK_SECRET   # whsec_… printed by the script
   npx wrangler deploy
   ```

How it works:

- An admin chooses **Upgrade to Pro** under Settings › Plan (or an agent calls `upgrade_plan`). The workspace asks Stripe for a Checkout page and sends the person there. Agents get the link to hand to a person.
- Stripe calls `POST /api/stripe/webhook` on the root domain. The Worker checks the signature, then reads the subscription from Stripe and records it on the workspace. Events that arrive late, twice or out of order change nothing. The checkout links the Stripe customer to the workspace's first address, so moving the workspace doesn't break billing.
- Each subscription carries its workspace's billing id (made at its first checkout), and a workspace accepts only its own. A subscription made by hand in the Stripe Dashboard won't turn Pro on; use the operator API's `grant-pro` instead.
- Pro stays on while a renewal is `past_due` and Stripe retries. Cancelling in the customer portal (**Manage billing**) keeps Pro until the paid period ends. After that the workspace is free again: nothing is deleted, but past the free limits it can only shrink.
- Refunds, disputes and fraud warnings are noted on the workspace in the operator list (`billing_risk`) for you to look at.
- Stripe Tax isn't on. If you need to collect sales tax or VAT, register with Stripe Tax first, then turn on `automatic_tax` in the Checkout call (`crates/core/src/plan.rs`).

To try it locally, create a Stripe sandbox, run `scripts/stripe-setup.sh local` against it, and put its `STRIPE_SECRET_KEY`, `STRIPE_PRICE_ID` and the secret `stripe listen --forward-to http://localhost:8787/api/stripe/webhook` prints in `crates/worker/.dev.vars`.

### Operator API

Manage workspaces with `Authorization: Bearer $OPERATOR_TOKEN` on the root domain:

```sh
curl -H "Authorization: Bearer $OPERATOR_TOKEN" https://your-domain/api/operator/workspaces
curl -X POST -H "Authorization: Bearer $OPERATOR_TOKEN" https://your-domain/api/operator/workspaces/acme/disable    # or enable
curl -X POST -H "Authorization: Bearer $OPERATOR_TOKEN" https://your-domain/api/operator/workspaces/acme/delete     # erases it; its addresses become free
curl -X POST -H "Authorization: Bearer $OPERATOR_TOKEN" https://your-domain/api/operator/workspaces/acme/grant-pro  # Pro without paying; or revoke-pro
```

Any of a workspace's addresses works in these URLs. The list shows each workspace's current `address`, its `previous_addresses`, its plan, writes in the last 24 hours, size and Stripe status, and the free plan's totals against their budget (`free_plan`). Deleting a workspace that someone still pays for is refused; cancel its subscription in the Stripe Dashboard first. Deleting one detaches its Stripe customers, so if someone claims the address later, the old customer's events never reach the new workspace.

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
