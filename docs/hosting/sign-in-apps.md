# Sign-in apps for single sign-on

This page is for whoever runs DumbSlab. It explains how to register DumbSlab's own Google, Microsoft and Slack sign-in apps.

With these apps in place, a workspace admin sets up single sign-on by choosing **Set up with Google**, **Set up with Microsoft** or **Set up with Slack** in Settings › Single sign-on, and signing in once. Nobody else registers anything. See [Single sign-on](../sso.md) for what admins see.

Each app is optional. A provider without an app has no button, and admins can still use their own app there.

## The redirect URI

Every app uses one redirect URI:

- hosted DumbSlab: `https://dumbslab.com/sso/callback`
- self-hosted: `<your public URL>/sso/callback`, for example `https://wiki.example.com/sso/callback`

On hosted DumbSlab, the root domain receives every workspace's sign-ins. It sends each browser on to its workspace (the `state` starts with the workspace's address), and the workspace checks everything.

## Google

Register the app in the [Google Cloud console](https://console.cloud.google.com/), in a project for DumbSlab.

1. Open **Google Auth Platform › Branding**. Fill in the app name (DumbSlab), the support email, the home page (`https://dumbslab.com`), and the privacy policy and terms links. Add `dumbslab.com` under **Authorized domains**. A logo is optional.
2. Open **Audience**. Choose the user type **External**, so any Google Workspace organization can sign in. Then choose **Publish app**, so the status is **In production**. While it's in **Testing**, only listed test users can sign in.
3. Open **Data Access**. Add only the scopes `openid`, `.../auth/userinfo.email` and `.../auth/userinfo.profile`. Google calls these non-sensitive.
4. Open **Clients › Create client**. Choose the application type **Web application** and name it, for example "DumbSlab single sign-on". Under **Authorized redirect URIs**, add the redirect URI. You don't need JavaScript origins.
5. Copy the client ID and the client secret.

**Verification.** An app that asks only for non-sensitive scopes doesn't need Google's app verification. To show DumbSlab's name and logo on Google's consent screen, Google requires brand verification for External, published apps. Submit it from **Google Auth Platform**. See Google's [verification requirements](https://support.google.com/cloud/answer/13463073) and [brand verification](https://developers.google.com/identity/protocols/oauth2/production-readiness/brand-verification).

**Workspace admins.** Some Google Workspace organizations allow only apps their admin trusts. Their admin can add DumbSlab to the trusted apps in the Google Admin console.

## Microsoft

Register the app in the [Microsoft Entra admin center](https://entra.microsoft.com/), in the directory that DumbSlab's business owns. Use a work account, not a personal Microsoft account.

1. Open **App registrations › New registration**. Name it DumbSlab.
2. Under **Supported account types**, choose **Accounts in any organizational directory (Any Microsoft Entra ID tenant - Multitenant)**. Don't include personal Microsoft accounts.
3. Under **Redirect URI**, choose the platform **Web** and enter the redirect URI. Register the app.
4. Open **Certificates & secrets › Client secrets › New client secret**. Choose an expiry. Copy the secret's **Value** at once (not its ID); Microsoft shows it only once.
5. Open **Token configuration › Add optional claim**, choose the token type **ID**, and add `email` and `xms_edov`. If Microsoft asks, allow the Microsoft Graph `email` permission. If `xms_edov` isn't in the list, open **Manifest** and add it under `optionalClaims.idToken`: `{"name": "xms_edov", "essential": false}`.
6. Under **Branding & properties**, set the publisher domain to `dumbslab.com`, and the home page and privacy links.
7. Copy the **Application (client) ID** from the app's **Overview**.

**Who's who.** DumbSlab links Microsoft accounts by `oid`, which is the same for every app in a directory, so workspaces can switch between this app and their own without losing links. Microsoft sends `oid` for the `profile` scope, which DumbSlab asks for.

**Why `xms_edov`.** Microsoft's `email` claim isn't proof that the person owns the address. `xms_edov` says the domain's owner verified it. Without it, setting up still works, but admins must type in their email domains, and people link their Microsoft accounts before signing in.

**Secret expiry.** Microsoft client secrets expire. Put a reminder before the date. Make a new secret, update `SSO_MICROSOFT_CLIENT_SECRET`, and then delete the old one. If the secret expires, Microsoft sign-ins fail until you replace it. Admins keep their passwords, so they can still get in.

**Approval.** Some organizations let only their administrators approve new apps. Their people then see a request for an administrator, and DumbSlab shows its own message. Publisher verification (a blue "verified" badge) makes approval easier, because organizations can allow apps from verified publishers. It needs a Microsoft AI Cloud Partner Program account. See [publisher verification](https://learn.microsoft.com/en-us/entra/identity-platform/publisher-verification-overview).

## Slack

Slack uses the one DumbSlab Slack app, which also powers Add to Slack and connected-app search. Create it from its manifest ([DumbSlab's Slack app](slack-app.md)), which already has the redirect URI and scopes below. For single sign-on it needs:

1. Under **OAuth & Permissions › Redirect URLs**, the redirect URI (`https://dumbslab.com/sso/callback`).
2. The user token scopes `openid`, `email` and `profile`. Slack asks for these in their own sign-in, separate from the bot's install.
3. Distribution turned on (**Manage Distribution**), so people outside DumbSlab's own Slack workspace can sign in with it.

Its client ID and secret are the same `SLACK_CLIENT_ID` and `SLACK_CLIENT_SECRET` as the rest of the Slack app. Slack confirms people's addresses, not that a domain is their organization's, so setting up only suggests the admin's email domain; they allow it with one click.

## Where the values go

### Cloudflare (dumbslab.com)

Client IDs aren't secret. Put them in `crates/worker/wrangler.toml` under `[vars]`:

```toml
SSO_GOOGLE_CLIENT_ID = "1234567890-abc.apps.googleusercontent.com"
SSO_MICROSOFT_CLIENT_ID = "00000000-0000-0000-0000-000000000000"
SLACK_CLIENT_ID = "1234567890.1234567890"
```

Keep them in `wrangler.toml`: a deploy replaces the Worker's vars with the file's.

Client secrets are secrets. Store each one with Wrangler, from `crates/worker`:

```sh
npx wrangler secret put SSO_GOOGLE_CLIENT_SECRET
npx wrangler secret put SSO_MICROSOFT_CLIENT_SECRET
npx wrangler secret put SLACK_CLIENT_SECRET
```

Then deploy. A provider needs both its ID and its secret; with only one, it has no button.

### Self-hosted

Set the same names with `DUMBSLAB_` in front, in the server's environment:

```sh
DUMBSLAB_SSO_GOOGLE_CLIENT_ID=…
DUMBSLAB_SSO_GOOGLE_CLIENT_SECRET=…
DUMBSLAB_SSO_MICROSOFT_CLIENT_ID=…
DUMBSLAB_SSO_MICROSOFT_CLIENT_SECRET=…
DUMBSLAB_SLACK_CLIENT_ID=…
DUMBSLAB_SLACK_CLIENT_SECRET=…
```

Set `DUMBSLAB_BASE_URL` too, so the redirect URI is your public URL.

## Removing an app

If you remove an app (or its ID or secret), single sign-on turns itself off in every workspace that used it. "Require single sign-on" stops applying, so everyone can sign in with a password, and Settings › Single sign-on tells admins why. Put the app back, and single sign-on works again as it was.
