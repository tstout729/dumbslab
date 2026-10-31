# The host's BambooHR app (Sign in with BambooHR)

People sync on hosted DumbSlab connects to BambooHR only through Sign in with BambooHR. BambooHR's [developer terms](https://www.bamboohr.com/legal/developer-terms-of-service) (§3.2 and §3.3) allow API keys only in systems a company runs itself. Services hosted by someone else must use BambooHR's OAuth. Until the host registers a BambooHR app, Settings › People sync says it isn't available yet on this host.

A self-hosted server can register its own app the same way, so its admins can sign in instead of pasting an API key.

This guide is for whoever runs the server. See [people sync](../people-sync.md) for admins.

## 1. Register the app

1. Sign up at the [BambooHR Developer Portal](https://developers.bamboohr.com). Anyone can register since April 2025; you no longer need to contact BambooHR first ([API changelog, 2025-04-15](https://documentation.bamboohr.com/docs/past-changes-to-the-api)). The account owner accepts the developer terms.
2. Choose **Add Application**. Give it a name people will recognize, such as "DumbSlab".
3. Add the redirect URI. It must match exactly, with no extra slash:
   - Hosted: `https://<ROOT_DOMAIN>/sync/bamboohr/callback`, for example `https://dumbslab.com/sync/bamboohr/callback`. The root domain sends each admin on to their own workspace.
   - Self-hosted: `https://<your server>/sync/bamboohr/callback`, the server's `DUMBSLAB_BASE_URL` followed by that path.
4. Choose these scopes:

   | Scope | Why |
   | --- | --- |
   | `openid` | Sign in with BambooHR |
   | `offline_access` | A refresh token, so DumbSlab can renew the hour-long access token |
   | `employee` | Employees' non-sensitive details |
   | `employee:contact` | Work email and work phone |
   | `employee:job` | Job title, department, location and manager |
   | `employee:name` | Names, for employees not found in the workspace |
   | `webhooks` | Look up the webhook DumbSlab added |
   | `webhooks.write` | Add and delete that webhook |

5. Save the app, and copy its **client ID** and **client secret**. Treat the secret like a password.

DumbSlab asks for exactly these scopes when an admin signs in. If the app lacks one, BambooHR refuses the sign-in.

## 2. Give DumbSlab the app

| Where | Client ID | Client secret |
| --- | --- | --- |
| Cloudflare | `BAMBOOHR_CLIENT_ID` in `wrangler.toml` `[vars]` | `npx wrangler secret put BAMBOOHR_CLIENT_SECRET` |
| Self-hosted | `DUMBSLAB_BAMBOOHR_CLIENT_ID` | `DUMBSLAB_BAMBOOHR_CLIENT_SECRET` |

The server also needs its connector key (`CONNECTOR_KEY`, or `DUMBSLAB_CONNECTOR_KEY` self-hosted), which encrypts the tokens. See [connected apps](../connected-apps.md). Deploy, then open Settings › People sync in a workspace: it offers **Sign in with BambooHR**.

On Cloudflare, `ROOT_DOMAIN` must be set (it is for hosted mode). The Worker answers `/sync/bamboohr/callback` on the root domain and forwards it to the workspace named at the start of the sign-in's state.

## 3. Test it

- The developer terms (§1.5) allow at most two BambooHR test accounts at a time, with made-up data only, used by hand (no scripts). A free BambooHR trial is the usual way to get one; a sandbox comes only with the Marketplace partner program.
- Sign in from a test workspace, then check that Settings shows "Signed in with BambooHR" and "Syncs when BambooHR changes", and that Sync now works.

## What BambooHR may require before production use

- **Review (§7.1).** BambooHR "may require" a new integration to be submitted for review and approval before granting production access, or before listing it in any BambooHR marketplace. It may approve or reject in its own discretion. Self-registration doesn't exempt an app from this. If BambooHR asks, submit DumbSlab for review.
- **Security (§6.2).** BambooHR may require a security review to keep production access.
- **Customer consent (§1.2).** Each customer must authorize the integration. Sign in with BambooHR is that authorization.
- **Marketplace listing (optional).** Listing DumbSlab in the BambooHR Marketplace needs the partner program: at least 100 customers, Crossbeam, a security questionnaire, a signed partner agreement and a W-9 ([requirements](https://www.bamboohr.com/partner-programs/apps-marketplace-application)). People sync works without a listing.

## How it works

- DumbSlab sends the admin to `https://<company>.bamboohr.com/authorize.php?request=authorize&response_type=code&client_id=…&redirect_uri=…&state=…&scope=…`. BambooHR's sign-in pages are on each company's own domain, so the admin gives the company domain first.
- The state is random, kept only as a hash, and works once, for 15 minutes, for the admin who started (and their browser session). On hosted DumbSlab it starts with the workspace's address, so the root domain knows where to forward. BambooHR documents no PKCE, so DumbSlab sends none.
- The workspace exchanges the code at `https://<company>.bamboohr.com/token.php?request=token`, with the client ID and secret, and stores the access and refresh tokens encrypted. It renews the access token shortly before it expires (an hour), one request at a time.
- Errors go back to Settings as short codes only, never as text in the link.

BambooHR's OAuth docs: [Getting started](https://documentation.bamboohr.com/docs/getting-started). Scopes per endpoint are in the [API reference](https://documentation.bamboohr.com/reference).
