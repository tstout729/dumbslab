# Single sign-on

People can sign in with your organization's identity provider instead of a password: Google Workspace, Microsoft Entra ID, Okta, OneLogin, Slack, or any other OpenID Connect provider. Each workspace sets it up for itself, in Settings › Single sign-on. It's on every plan.

## Before you start

The server needs a **connector key**, the same one [connected apps](connected-apps.md) use. It encrypts the client secret. Without it, Settings › Single sign-on says it isn't available.

| Host | Setting |
| --- | --- |
| Cloudflare | `npx wrangler secret put CONNECTOR_KEY` |
| Self-hosted | `DUMBSLAB_CONNECTOR_KEY` in the environment |

If the key changes or is lost, the saved client secret can't be read. Single sign-on then turns itself off (so "Require single sign-on" no longer blocks passwords) until an admin enters the secret again; Settings › Single sign-on says so.

You register an app with your provider. Its **redirect URI** is your workspace's own address followed by `/sso/callback`:

- hosted DumbSlab: `https://<your workspace>.dumbslab.com/sso/callback`, for example `https://acme.dumbslab.com/sso/callback`
- self-hosted: `<your public URL>/sso/callback`

Settings › Single sign-on shows it with a copy button. If the workspace's address changes, change it in the provider's app too.

## Set it up

1. Register an app with your provider (see [the providers](#the-providers)) and copy its client ID and client secret.
2. In Settings › Single sign-on, choose the provider and fill in its details, the client ID and secret, and your organization's email domains.
3. Tick "Show “Sign in with …” on the sign-in page" and save. DumbSlab reads the provider's discovery document and says whether it checks out.
4. Try signing in from a private window. Then turn on auto-provisioning or require single sign-on, if you want them.

## Who can sign in

- **Linked accounts.** DumbSlab links each account at the provider to one person here, by the provider's issuer and its permanent ID for the account (`sub`). A linked account signs in as that person, whatever email it has later.
- **First sign-in.** An account that isn't linked yet joins the person here with the same email only when the provider says the address is verified and its domain is one of the allowed domains. The rules for each provider are in the table below.
- **Linking your own account.** When the provider doesn't vouch for someone's email, or their email there differs from the one here, they sign in with their password and choose Settings › Profile › "Link your … account". Linking must finish in the same browser session that started it, while it's still signed in: a link started in a session that is then signed out (or revoked) can't be finished anywhere.
- **Auto-provisioning** is off by default. When it's on, someone whose verified email is at an allowed domain, and who has no account here, joins as a member.
- **Deactivated people and bot accounts** can't sign in with single sign-on.
- An email that's already linked to a different account at the same provider isn't taken over: an admin unlinks the old one first, under Settings › Single sign-on › Linked accounts.

| Provider | Only these accounts can sign in | A first sign-in trusts the email when |
| --- | --- | --- |
| Google Workspace | accounts whose hosted domain (`hd`) is an allowed domain | `email_verified` is true |
| Microsoft Entra ID | accounts in your directory (`tid`) | `xms_edov` is true. `email` alone, and `upn`, are never trusted |
| Okta, OneLogin, other OIDC | accounts at your issuer | `email_verified` is true |
| Slack | members of your Slack workspace, when you name it | `email_verified` is true |

In every case the email's domain must be one of the allowed domains. When the ID token doesn't give the email or say whether it's verified, DumbSlab asks the provider's userinfo endpoint (never Microsoft's), and uses its answer only when it's about the same account (`sub`) and, if the ID token has an address, the same address. If your provider doesn't send `email_verified` at all, first sign-ins can't find people by email, so people link their accounts from Settings › Profile, or you turn on auto-provisioning only where the provider does vouch for addresses.

## Requiring single sign-on

With "Require single sign-on" on, only admins can sign in with a password, so an admin can still get in if the provider is down or set up wrong. Everyone else uses the provider. API tokens and MCP connections keep working.

It applies only while single sign-on is on and fully set up. Turning single sign-on off lets everyone use their password again.

## The providers

### Google Workspace

1. In the [Google Cloud console](https://console.cloud.google.com/), set up the OAuth consent screen for a project. Choose **Internal**, so only your organization's accounts can use it.
2. Under **APIs & Services › Credentials**, choose **Create credentials › OAuth client ID**, with application type **Web application**. Add the redirect URI under **Authorized redirect URIs**.
3. Copy the client ID and client secret.
4. In DumbSlab, choose **Google Workspace** and list your Google Workspace domains as allowed domains. Only accounts in those domains can sign in; personal Google accounts can't.

### Microsoft Entra ID

1. In the [Microsoft Entra admin center](https://entra.microsoft.com/), go to **App registrations › New registration**. Choose **Accounts in this organizational directory only (Single tenant)**, and add the redirect URI with the platform **Web**.
2. Under **Certificates & secrets**, add a client secret and copy its **Value** (not its ID). Microsoft secrets expire, so note when to make a new one.
3. Under **Token configuration › Add optional claim › ID**, add `email` and `xms_edov`. If `xms_edov` isn't in the list, add it to the app's **Manifest** under `optionalClaims.idToken`. Without `xms_edov`, people link their Microsoft account from Settings › Profile before they can sign in with it.
4. In DumbSlab, choose **Microsoft Entra ID**. Enter the **Directory (tenant) ID** from the app's Overview (a GUID; `common` and `organizations` aren't allowed), the **Application (client) ID**, and the secret.

DumbSlab uses the issuer `https://login.microsoftonline.com/<tenant ID>/v2.0` and accepts only ID tokens whose `tid` is your directory.

### Okta

1. In the Okta Admin Console, go to **Applications › Create App Integration**, and choose **OIDC - OpenID Connect** and **Web Application**.
2. Keep the grant type **Authorization Code**, and add the redirect URI as a **Sign-in redirect URI**. Under **Assignments**, choose who may sign in.
3. Copy the client ID and client secret.
4. In DumbSlab, choose **Okta**. The issuer is your Okta URL, such as `https://acme.okta.com`, or your custom authorization server's issuer, such as `https://acme.okta.com/oauth2/default`.

### OneLogin

1. In OneLogin, go to **Applications › Add App**, add **OpenId Connect (OIDC)**, and save it.
2. On the **Configuration** tab, add the redirect URI.
3. On the **SSO** tab, set **Token Endpoint Authentication Method** to **Basic**. Copy the client ID, the client secret and the **Issuer URL**, such as `https://acme.onelogin.com/oidc/2`.
4. On the **Access** or **Users** tab, give people access.
5. In DumbSlab, choose **OneLogin** and paste the issuer URL.

### Slack

1. At [api.slack.com/apps](https://api.slack.com/apps), create an app.
2. Under **OAuth & Permissions**, add the redirect URI, and add the user token scopes `openid`, `email` and `profile`.
3. Under **Basic Information › App Credentials**, copy the client ID and client secret.
4. In DumbSlab, choose **Slack** and enter your Slack workspace's team ID, which starts with `T`. It's in the address when you open Slack in a browser (`app.slack.com/client/T…`). It's required: only members of that Slack workspace can sign in, like Microsoft's tenant and Google's domains.

### Other OpenID Connect providers

Auth0, Keycloak, JumpCloud, Ping, Authentik and others work the same way.

1. Register a confidential web app that uses the authorization code flow, with the redirect URI, and allow the scopes `openid`, `email` and `profile`.
2. In DumbSlab, choose **Another OpenID Connect provider**. The issuer must be exactly the `issuer` in `<issuer>/.well-known/openid-configuration`, including a trailing slash if it has one (Auth0's does).
3. Name the button, for example `Acme SSO` for "Sign in with Acme SSO".

## How it works

- Signing in uses OpenID Connect's authorization code flow with PKCE (S256), a `state` and a `nonce`. The `state` is stored hashed and works once, for 15 minutes, in the browser that started it (a short-lived cookie names that browser).
- Each sign-in reads `<issuer>/.well-known/openid-configuration`. Its `issuer` must equal the configured issuer exactly, and its endpoints must be https.
- The code is exchanged at the token endpoint with the client secret: with HTTP Basic, or in the form for providers that only take that (Slack).
- The ID token arrives straight from the token endpoint over TLS, so, as OpenID Connect Core 1.0 section 3.1.3.7 allows, its signature isn't checked. Its issuer, audience, authorized party, expiry, issue time and nonce are. When it lacks the email or `email_verified`, and the account isn't linked yet, DumbSlab asks the userinfo endpoint (except Microsoft's). Its answer must be about the same `sub`, and its `email_verified` counts only for the ID token's own address.
- The core builds every request and reads every answer; the host only sends them, over https, without following redirects, within 8 seconds and reading at most 4 MB. The self-hosted server refuses private network addresses unless it runs with `--allow-private-webhooks`.
- A sign-in starts an ordinary browser session, with the same cookie rules and 30-day length as a password sign-in.
- Problems send people back to the sign-in page (or Settings › Profile, when linking) with only an error code, such as `?sso_error=unverified_email`. The page shows its own message for each code, so a link can't make the sign-in page say anything else, and nothing the provider sends (error text, tokens) ever reaches it. The admin's settings check gives the details of a provider that doesn't check out.
- Changes to the settings, every newly linked account (linked by the person, matched by a verified email on a first sign-in, or created by auto-provisioning) and people who join appear in the admins' activity log (`sso.updated`, `sso.linked`, `sso.unlinked`, `user.created`). Events that happen during a sign-in aren't sent to webhooks.

## For agents and scripts

The operations are `get_sso`, `update_sso`, `list_sso_identities`, `link_sso` and `unlink_sso`. For example, as an admin:

```sh
curl -X PATCH https://acme.dumbslab.com/api/v1/sso \
  -H "Authorization: Bearer $DUMBSLAB_TOKEN" -H "content-type: application/json" \
  -d '{"provider": "okta", "issuer": "https://acme.okta.com", "client_id": "…", "client_secret": "…",
       "allowed_domains": ["acme.com"], "enabled": true}'
```

The answer includes `check`, which says whether the provider's discovery document checked out. No operation returns the client secret.
