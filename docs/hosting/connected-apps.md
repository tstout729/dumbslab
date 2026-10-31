# Registering connected apps for dumbslab.com

This guide is for whoever runs hosted DumbSlab. It shows how to register DumbSlab's own app with each provider, so people can click **Sign in with …** in Settings › Connected apps and approve. Nobody has to make a token.

The apps are listed from quickest to slowest to register. [connected-apps.md](../connected-apps.md) explains how connected apps work.

## Before you start

- Connected apps need the connector key. Set it once: `npx wrangler secret put CONNECTOR_KEY` (any long random string). Changing it later disconnects everyone.
- Register each app under a DumbSlab account or organization, not a personal one, where the provider allows it. Then you can hand it over later.
- Use a privacy policy and terms page on dumbslab.com. Several providers ask for them.

## The same for every app

**Redirect URI.** Every app uses exactly one:

```
https://dumbslab.com/connect/callback
```

The root domain sends each person back to their own workspace, so one address serves every workspace. Providers compare it exactly: no trailing slash, no `www`.

**Where the values go.** Each app gives you a client ID and a client secret. `<APP>` is the name in the table below.

| Value | Where | How |
| --- | --- | --- |
| Client ID | `crates/worker/wrangler.toml`, under `[vars]` | `<APP>_CLIENT_ID = "…"` |
| Client secret | a Worker secret | `cd crates/worker && npx wrangler secret put <APP>_CLIENT_SECRET` |

Deploy after changing `wrangler.toml`. A secret takes effect without a deploy. An app shows **Sign in with …** only when both values are set.

Self-hosted servers use the same names with `DUMBSLAB_` in front, in the environment. A self-hosted server's redirect URI is `<its public URL>/connect/callback`.

**Scopes.** Some providers ask for scopes when you register the app; others take them only at sign-in. Each section says which. DumbSlab asks for exactly the scopes listed, and they come from each app's code (`OAuthSpec` in `crates/core/src/connect/providers/`). If you change one there, change it here and in the provider's console.

## Summary

| # | App | `<APP>` | Time | Before the public can sign in |
| --- | --- | --- | --- | --- |
| 1 | GitHub | `GITHUB` | minutes | nothing |
| 2 | GitLab (gitlab.com) | `GITLAB` | minutes | nothing |
| 3 | Linear | `LINEAR` | minutes | make the app public |
| 4 | Todoist | `TODOIST` | minutes | nothing |
| 5 | Asana | `ASANA` | minutes | allow any workspace |
| 6 | ClickUp | `CLICKUP` | minutes | nothing |
| 7 | Wrike | `WRIKE` | minutes | nothing documented |
| 8 | Box | `BOX` | minutes | some companies' Box admins must allow it |
| 9 | Jira and Confluence | `ATLASSIAN` | under an hour | turn on sharing |
| 10 | Trello | `TRELLO` | under an hour | nothing documented |
| 11 | monday.com | `MONDAY` | under an hour | share the app; an admin of each account installs it |
| 12 | Dropbox | `DROPBOX` | minutes, then a review | production approval after 50 users |
| 13 | Slack | `SLACK` | days to weeks | public distribution, then the Slack Marketplace |
| 14 | Zendesk | `ZENDESK` | days to weeks | Zendesk approves a global OAuth client |
| 15 | Google Drive | `GOOGLE_DRIVE` | weeks | Google's restricted-scope verification and a yearly security assessment |

Freshdesk, Guru and Shortcut have no sign-in in DumbSlab. People connect them with a token. See [the end of this guide](#apps-without-sign-in).

## 1. GitHub

- **Register at:** [github.com/settings/applications/new](https://github.com/settings/applications/new), or for an organization, its Settings › Developer settings › OAuth Apps.
- **App type:** **OAuth App**, not a GitHub App.
- **Fill in:** Homepage URL `https://dumbslab.com`. Authorization callback URL: the redirect URI.
- **Scopes:** chosen at sign-in, not in the console: `repo` and `read:org`.
- **Values:** `GITHUB_CLIENT_ID` is the Client ID. Choose **Generate a new client secret** for `GITHUB_CLIENT_SECRET`.
- **Review:** none.
- **Worth knowing:** an organization with OAuth app access restrictions (on by default for new organizations) must approve DumbSlab before it can read the organization's private repositories. People can ask their owners while signing in. GitHub has no read-only scope for private repositories; DumbSlab only reads. [Creating an OAuth app](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app), [access restrictions](https://docs.github.com/en/organizations/managing-oauth-access-to-your-organizations-data/about-oauth-app-access-restrictions).

## 2. GitLab (gitlab.com)

- **Register at:** a DumbSlab group's **Settings › Applications** on gitlab.com, or your own [User settings › Applications](https://gitlab.com/-/user_settings/applications).
- **App type:** an application with **Confidential** checked.
- **Fill in:** Redirect URI: the redirect URI.
- **Scopes:** check `read_api` in the console. Sign-in asks for `read_api`.
- **Values:** `GITLAB_CLIENT_ID` is the Application ID; `GITLAB_CLIENT_SECRET` is the Secret.
- **Review:** none.
- **Worth knowing:** this is gitlab.com only. People on a self-managed GitLab connect with a personal access token. The one-click docs sync in another pull request uses this same GitLab app; if it needs more scopes or another redirect URI, add them to this app rather than making a second one. [GitLab as an OAuth provider](https://docs.gitlab.com/integration/oauth_provider/).

## 3. Linear

- **Register at:** [linear.app/settings/api/applications/new](https://linear.app/settings/api/applications/new).
- **Fill in:** Callback URL: the redirect URI.
- **Scopes:** chosen at sign-in: `read`.
- **Values:** `LINEAR_CLIENT_ID` and `LINEAR_CLIENT_SECRET`.
- **Before the public can use it:** turn on **Public**, so other workspaces can install the app. A private app works only in your own workspace. Paid workspaces can make their admins approve new apps. [OAuth](https://linear.app/developers/oauth-2-0-authentication), [app distribution](https://linear.app/developers/oauth-app-manifests).

## 4. Todoist

- **Register at:** [Todoist › Settings › Integrations › Developer › App Management](https://app.todoist.com/app/settings/integrations/app-management).
- **Fill in:** OAuth redirect URL: the redirect URI.
- **Scopes:** chosen at sign-in: `data:read`.
- **Values:** `TODOIST_CLIENT_ID` and `TODOIST_CLIENT_SECRET`.
- **Review:** none. Listing in Todoist's integrations directory is optional. [Todoist OAuth](https://developer.todoist.com/guides/#oauth).

## 5. Asana

- **Register at:** [app.asana.com/0/my-apps](https://app.asana.com/0/my-apps) › Create new app.
- **Fill in:** under OAuth, add the redirect URI.
- **Scopes:** choose exactly these in the console, not "Full permissions": `users:read`, `workspaces:read`, `workspaces.typeahead:read`, `tasks:read`, `projects:read`. Sign-in asks for the same.
- **Values:** `ASANA_CLIENT_ID` and `ASANA_CLIENT_SECRET`.
- **Before the public can use it:** under **Manage distribution**, choose **Any workspace**. A new app isn't available to any workspace until you do. No review unless you list it in Asana's app directory. Enterprise admins can block apps. [OAuth](https://developers.asana.com/docs/oauth), [distribution](https://developers.asana.com/docs/manage-distribution).

## 6. ClickUp

- **Register at:** ClickUp › your avatar › **Settings › Apps › Create new app**. Only Workspace owners and admins can.
- **Fill in:** the redirect URI.
- **Scopes:** ClickUp has none. People choose which Workspaces to allow, and the token can do whatever they can there. DumbSlab only reads.
- **Values:** `CLICKUP_CLIENT_ID` and `CLICKUP_CLIENT_SECRET`.
- **Review:** none mentioned. [ClickUp authentication](https://developer.clickup.com/docs/authentication).

## 7. Wrike

- **Register at:** Wrike › Apps & Integrations › API ([app console](https://www.wrike.com/appconsole.htm?#/api)). Create an app.
- **Fill in:** Redirect URI: the redirect URI.
- **Scopes:** chosen at sign-in: `wsReadOnly`. Without it, Wrike gives read and write.
- **Values:** `WRIKE_CLIENT_ID` and `WRIKE_CLIENT_SECRET`.
- **Review:** none documented. Wrike's docs don't say outright that an app works for other Wrike accounts; try it with a second account before announcing it. [Wrike OAuth](https://developers.wrike.com/oauth-20-authorization/).

## 8. Box

- **Register at:** [app.box.com/developers/console](https://app.box.com/developers/console) › New App. Choose user authentication (**OAuth 2.0**).
- **Fill in:** under Configuration, the OAuth 2.0 redirect URI.
- **Scopes:** under Application scopes, check only **Read all files and folders stored in Box**. Sign-in asks for `root_readonly`.
- **Values:** `BOX_CLIENT_ID` and `BOX_CLIENT_SECRET`.
- **Before the public can use it:** nothing to publish. But a company whose Box admin turned on "Disable unpublished apps by default" must enable DumbSlab in its Admin Console (it can add it by client ID). Until then its people get an error. [OAuth 2.0 setup](https://developer.box.com/guides/authentication/oauth2/oauth2-setup/), [app approval](https://developer.box.com/guides/authorization/platform-app-approval).

## 9. Jira and Confluence (one Atlassian app)

One Atlassian app covers both. Set `ATLASSIAN_CLIENT_ID` and `ATLASSIAN_CLIENT_SECRET`. `JIRA_…` or `CONFLUENCE_…` values, when both of a pair are set, override it for that product.

- **Register at:** [developer.atlassian.com/console/myapps](https://developer.atlassian.com/console/myapps/) › Create › **OAuth 2.0 integration**.
- **Fill in:** Authorization › OAuth 2.0 (3LO) › Callback URL: the redirect URI.
- **Scopes:** under Permissions, add two APIs and these classic scopes:
  - **Jira API:** `read:jira-work`
  - **Confluence API:** `search:confluence`
  
  `offline_access` isn't configured; sign-in asks for it to get refresh tokens. The User identity API isn't needed: DumbSlab never reads the person's profile. Each sign-in asks for both products' scopes (`read:jira-work search:confluence offline_access`). Atlassian keeps one grant per person and app, and each new consent replaces its scopes, so connecting Confluence must not take away Jira's.
- **Values:** from Settings: `ATLASSIAN_CLIENT_ID` and `ATLASSIAN_CLIENT_SECRET`.
- **Before the public can use it:** a new app is private: only you can use it. Under **Distribution**, choose Edit and turn on **Enable sharing**. Atlassian asks for a vendor name, a privacy policy and whether the app stores personal data. Until Atlassian reviews the app, people see a warning that it hasn't been reviewed, but they can still approve. Sharing doesn't list the app in the Atlassian Marketplace. [OAuth 2.0 (3LO) apps](https://developer.atlassian.com/cloud/jira/platform/oauth-2-3lo-apps/), [managing apps](https://developer.atlassian.com/cloud/oauth/getting-started/managing-oauth-apps/).
- **Personal data:** answer that the app does **not** store personal data. A connection keeps only its site: the label is the site's address ("acme.atlassian.net"), and the settings hold the site and its cloud id. DumbSlab never saves anyone's Atlassian account ID, email or name. Search results and previews read names when they're shown and keep none. Atlassian's duty to check its [personal data reporting API](https://developer.atlassian.com/cloud/jira/platform/user-privacy-developer-guide/) every 7 days applies to apps that store personal data, so it doesn't apply. One caveat: a connection made with an API token keeps the email the person typed, sealed with the token, because Atlassian needs both to sign in. That's the person's own sign-in, not data DumbSlab's app reads from Atlassian, and Atlassian's guide doesn't mention credentials like it.

## 10. Trello

Trello can't share the Atlassian app. Its OAuth 2.0 clients (new on September 15, 2026) are made in Trello's own app admin, and Atlassian's docs don't offer Trello scopes in the developer console.

- **Register at:** [trello.com/apps/admin](https://trello.com/apps/admin). Make a new app that doesn't use Power-Up capabilities. The first visit asks you to accept Trello's Joint Development Agreement.
- **Fill in:** the app's **OAuth 2.0** tab: choose a **Confidential** client and add the redirect URI as a callback URL.
- **Scopes:** check `read:member:trello` and `read:board:trello` there. Sign-in also asks for `offline_access`, which isn't in the list but brings refresh tokens.
- **Values:** `TRELLO_CLIENT_ID` and `TRELLO_CLIENT_SECRET`.
- **Review:** none documented. Clients that aren't Power-Ups aren't limited to one Trello Workspace.
- **Personal data:** Trello asks every app to register whether it stores personal data. Register DumbSlab's as **not** storing any. Connecting only checks the key and token or the sign-in; the label is just "Trello" and nothing about the member is saved. Previews read card members' names when they're shown and keep none. Apps that store personal data must poll Trello's compliance API at least every 14 days; apps that don't only register. [Personal data storage](https://developer.atlassian.com/cloud/trello/guides/compliance/personal-data-storage-gdpr/), [client configuration](https://developer.atlassian.com/cloud/trello/guides/rest-api/oauth-2-client-configuration/), [confidential clients](https://developer.atlassian.com/cloud/trello/guides/rest-api/oauth-2-confidential-client-usage/).

## 11. monday.com

- **Register at:** monday.com's Developer Center (your avatar › Developers). Create an app.
- **Fill in:** in the **OAuth** tab, add the redirect URI. Turn on the **new OAuth flow** (expiring tokens with refresh tokens); DumbSlab uses it.
- **Scopes:** check these in the OAuth tab: `me:read`, `account:read`, `boards:read`, `users:read`. Sign-in asks for the same, and monday refuses any that aren't configured.
- **Values:** from Basic Information: `MONDAY_CLIENT_ID` and `MONDAY_CLIENT_SECRET`.
- **Before the public can use it:** promote the app version to live, then use the **Share** tab to share it with anyone who has the link. A monday.com account must install the app before its people can sign in. Sign-in passes `force_install_if_needed=true`, so an admin who signs in first sees monday's install screen and goes straight on. Anyone else needs an admin to install it first. No Marketplace listing is needed, but an app monday hasn't reviewed shows a "not vetted" notice. [OAuth](https://developer.monday.com/apps/docs/oauth), [sharing](https://developer.monday.com/apps/docs/install-and-share-your-apps), [new OAuth flow](https://developer.monday.com/apps/docs/migrating-to-the-new-oauth-flow).

## 12. Dropbox

- **Register at:** [dropbox.com/developers/apps](https://www.dropbox.com/developers/apps) › Create app.
- **App type:** **Scoped access**, then **Full Dropbox**. "App folder" can't see people's files.
- **Fill in:** Settings › Redirect URIs: the redirect URI.
- **Scopes:** on the Permissions tab, check `account_info.read` and `files.metadata.read`. Sign-in asks for the same, with offline access for refresh tokens.
- **Values:** `DROPBOX_CLIENT_ID` is the App key; `DROPBOX_CLIENT_SECRET` is the App secret.
- **Before the public can use it:** on Settings, choose **Enable additional users**. Until then only your own account works. A development app takes up to 500 people. Once 50 have connected, you have two weeks to get production approval (**Apply for production**), or the app stops letting more people connect. Dropbox checks its branding guidelines, how the app uses the API, and an icon. You can ask for an early review. [Developer guide](https://docs.dropboxapi.com/dropbox-api/docs/developer-resources/developer-guide), [OAuth](https://docs.dropboxapi.com/dropbox-api/docs/oauth).

## 13. Slack

The connected Slack app is the **same single DumbSlab Slack app** that the Add to Slack pull request sets up; see `docs/hosting/slack-app.md` in that pull request. Don't make a second Slack app. For connected apps, that app also needs:

- **Redirect URL:** under OAuth & Permissions › Redirect URLs, add the redirect URI.
- **Scope:** under **User Token Scopes** (not bot scopes), add `search:read`. Only user tokens can search, and they see only what that person can see.
- **Values:** `SLACK_CLIENT_ID` and `SLACK_CLIENT_SECRET`, from Basic Information › App Credentials. If that pull request names them differently, both names must hold this same app's ID and secret.
- **Single sign-on:** the same app and values also sign people in to workspaces ("Set up with Slack"). For that it needs the redirect URL `https://<root domain>/sso/callback` and the user token scopes `openid`, `email` and `profile`, which Slack asks for in their own sign-in, apart from `search:read`. See [sign-in apps](sign-in-apps.md).
- **Before the public can use it:** under **Manage Distribution**, choose **Activate Public Distribution**. Then any workspace can install it, unless its admins restrict apps. Slack's terms say the Slack Marketplace is the place to distribute a commercial app. You can submit once 10 workspaces actively use it. Slack's preliminary review takes up to 10 business days and its functional review up to 10 weeks. [Distribution](https://docs.slack.dev/distribution/), [Marketplace review guide](https://docs.slack.dev/slack-marketplace/slack-marketplace-review-guide/), [rate limits for apps outside the Marketplace](https://docs.slack.dev/changelog/2025/05/29/rate-limit-changes-for-non-marketplace-apps/).

## 14. Zendesk (global OAuth client)

Zendesk stopped making new API tokens on October 27, 2026, and all of them stop working on April 30, 2027. A new Zendesk customer can connect only by signing in. Zendesk's terms don't let a service for many companies use each customer's own OAuth client or tokens. It needs a **global OAuth client**, which only Zendesk can create.

With one, Settings asks for the person's Zendesk subdomain (`acme` for acme.zendesk.com) and sends them to sign in at `https://acme.zendesk.com/oauth/authorizations/new`. DumbSlab uses PKCE and the client secret.

Steps:

1. **Get a sponsored developer account.** Start a Zendesk Support trial whose subdomain begins with `d3v-`, like `d3v-dumbslab`. Then fill in Zendesk's sponsored account request form. Zendesk sponsors accounts for developers building Zendesk Marketplace apps. [Trial or sponsored account](https://developer.zendesk.com/documentation/api-basics/getting-started/getting-a-trial-or-sponsored-account-for-development/).
2. **Make a local OAuth client** in that account: Admin Center › Apps and integrations › APIs › **OAuth Clients** › Add OAuth client.
   - **Unique identifier:** `zdg-dumbslab`. It must start with `zdg-`, name the product, and be the final value.
   - **Client kind:** Confidential.
   - **Redirect URLs:** the redirect URI.
   - Fill in **every** field, even optional ones: name, description, company, logo.
   - Copy the secret now. You lose the client's admin page once Zendesk converts it.
3. **Test it.** Set the values below, then connect Zendesk with the subdomain `d3v-dumbslab`. A local client works only in its own account.
4. **Ask for the conversion.** Sign in to the Zendesk Marketplace portal (apps.zendesk.com) › **Global OAuth** › **Request new OAuth**. Ask for the scope `read` only. Zendesk emails a ticket number, then converts the client if it approves. Zendesk doesn't say how long that takes. [Set up a global OAuth client](https://developer.zendesk.com/documentation/marketplace/building-a-marketplace-app/set-up-a-global-oauth-client/).

- **Scopes:** `read`, set as the client's allowed scopes when Zendesk converts it. It covers every GET; no narrower scope covers searching tickets and Help Center together. Zendesk refuses a sign-in that asks for a scope outside the allowed ones.
- **Values:** `ZENDESK_CLIENT_ID` is the unique identifier (`zdg-dumbslab`); `ZENDESK_CLIENT_SECRET` is the secret.
- **Tokens:** DumbSlab asks for access tokens that last 8 hours and refresh tokens that last 90 days, Zendesk's longest. Each refresh brings a new refresh token. A connection nobody uses for 90 days must be connected again.
- **Worth knowing:** Zendesk admins see DumbSlab under Admin Center › Apps and integrations › APIs › External OAuth clients, and can delete its tokens. People must use their `zendesk.com` subdomain, not a custom domain. Existing API tokens keep working until April 30, 2027. [OAuth requests](https://support.zendesk.com/hc/en-us/articles/4408845965210), [token expiry](https://developer.zendesk.com/api-reference/ticketing/oauth/grant_type_tokens/), [PKCE](https://developer.zendesk.com/documentation/api-basics/authentication/oauth-pkce/), [migrating from API tokens](https://developer.zendesk.com/documentation/api-basics/authentication/oauth-migration/).

## 15. Google Drive

- **Register at:** a Google Cloud project for DumbSlab. Enable the **Google Drive API**. Then [Google Auth Platform › Clients](https://console.cloud.google.com/auth/clients) › Create client.
- **App type:** **Web application**.
- **Fill in:** Authorized redirect URIs: the redirect URI.
- **Scopes:** under Data access, add `https://www.googleapis.com/auth/drive.readonly`, `openid` and `email`. Sign-in asks for the same, with offline access and a consent prompt so a refresh token comes back.
- **Values:** `GOOGLE_DRIVE_CLIENT_ID` and `GOOGLE_DRIVE_CLIENT_SECRET`.
- **Before the public can use it:** this is the slowest. `drive.readonly` is a **restricted** scope.
  - While the app's audience is "Testing", only up to 100 test users you list can connect, and their access ends after 7 days.
  - Published but unverified, the app takes at most 100 new people and shows an "unverified app" screen.
  - To remove the limits: brand verification (usually 2–3 business days), then restricted-scope verification with a demo video (several weeks). Because DumbSlab keeps tokens for restricted data on its servers, Google also requires a paid third-party security assessment (CASA), repeated every 12 months.
  
  [Restricted-scope verification](https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification), [Drive scopes](https://developers.google.com/workspace/drive/api/guides/api-specific-auth), [unverified apps](https://support.google.com/cloud/answer/7454865).

## Apps without sign-in

These connect with a token only. None offers a sign-in that a service for many companies can register for itself today.

- **Freshdesk:** its API takes only each agent's API key. Freshworks' OAuth for outside apps covers Freshservice, not Freshdesk, and Freshworks staff said in 2025 that Freshdesk support isn't planned. [API authentication](https://developers.freshdesk.com/api/#authentication), [Freshworks OAuth for external apps](https://developers.freshworks.com/docs/app-sdk/v3.0/service_ticket/oauth-implementation-in-apps/oauth-in-external-apps/), [community answer](https://community.freshworks.dev/t/how-to-use-oauth-authentication-mechanism-for-freshdesk-api/1691).
- **Guru:** OAuth clients exist, but you email Guru support to turn them on for one workspace, and the docs describe them as for your own organization. Using one for other organizations isn't documented. Ask Guru before building it. [OAuth2 clients](https://developer.getguru.com/docs/oauth2-clients).
- **Shortcut:** the REST API documents only API tokens. Shortcut does run an OAuth server, with self-service client registration, PKCE and a `read` scope, for its hosted MCP server. Whether those tokens work with the REST API isn't documented. Testing that means registering a client with Shortcut. [REST API](https://developer.shortcut.com/api/rest/v3), [OAuth server metadata](https://api.app.shortcut.com/.well-known/oauth-authorization-server), [MCP server](https://www.shortcut.com/help/integrations/mcp-server/).
