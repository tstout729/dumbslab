# Connected apps

Each person can connect their own accounts in other apps (GitHub, Google Drive, Jira, Slack and more), then:

- **search them** next to the workspace: the search page shows a "From your connected apps" section, and agents call `search_connected`;
- **preview links** to them: hovering a link to a GitHub issue, Jira issue, Zendesk ticket and so on in a post shows its title, status, assignee and description (`preview_link` for agents).

Everyone uses their own account, so results and previews hold only what that person can see in the app. Nobody can use anyone else's connection. Connections live in Settings › Connected apps (`list_connections`, `connect_app`, `disconnect_app`).

## How it works

- Credentials are encrypted in the workspace database with the server's connector key (AES-256-GCM, bound to the person and the app). No operation returns them.
- The core builds every request to an app and reads every answer. The host only sends the requests: over https, without following redirects, within 8 seconds, reading at most 4 MB. The self-hosted server also refuses private network addresses, like it does for webhooks.
- Links in results and previews must be `http(s)` links, and everything an app returns is shown as plain text.
- Tokens that expire (Google, Box, Dropbox, Atlassian and others) are refreshed with their refresh token in the five minutes before they expire, by one request at a time: some apps accept each refresh token only once. Zendesk also revokes the old access token when it refreshes. So while one request refreshes a Zendesk token, the others ask the person to try again in a moment instead of sending the old token, and a request refused because another one just refreshed tries once more with the new token.

## Turning it on

Connected apps need a **connector key**: any long random string. Changing or losing it disconnects everyone.

| Host | Setting |
| --- | --- |
| Cloudflare | `npx wrangler secret put CONNECTOR_KEY` |
| Self-hosted | `DUMBSLAB_CONNECTOR_KEY` in the environment |

With only the key, people can connect every app that has personal tokens by pasting one. Settings › Connected apps links to where each app makes them.

### Letting people sign in with an app

To let people sign in instead of pasting a token (and for apps that only sign in: Google Drive, Slack, Box and Dropbox), register an OAuth app with that app and give the server its client id and secret:

| Host | Client id | Client secret |
| --- | --- | --- |
| Cloudflare | `<APP>_CLIENT_ID` in `wrangler.toml` `[vars]` | `npx wrangler secret put <APP>_CLIENT_SECRET` |
| Self-hosted | `DUMBSLAB_<APP>_CLIENT_ID` | `DUMBSLAB_<APP>_CLIENT_SECRET` |

`<APP>` is the app's id in capitals with `-` as `_`, e.g. `GITHUB`, `GOOGLE_DRIVE`.

One Atlassian app can serve Jira and Confluence: set `ATLASSIAN_CLIENT_ID` and `ATLASSIAN_CLIENT_SECRET` (`DUMBSLAB_ATLASSIAN_…` self-hosted) instead of each app's own. An app's own pair wins when both of its values are set.

[hosting/connected-apps.md](hosting/connected-apps.md) walks through registering each app for hosted DumbSlab: where, which scopes, and what review each provider needs before the public can sign in.

The redirect (callback) URL to register is:

- hosted DumbSlab: `https://<root domain>/connect/callback`, e.g. `https://dumbslab.com/connect/callback`. The root domain forwards each person to their own workspace, so one URL serves every workspace.
- self-hosted or a single workspace: `<your public URL>/connect/callback`.

The person who started signing in must be the one who comes back, signed in to the workspace, within 15 minutes; each sign-in link works once.

Some apps live on each company's own address. For those (Zendesk), Settings asks for it first, like `acme` for acme.zendesk.com, and signing in happens there (`connect_app` takes it as `site`). The server checks it strictly, keeps it with the sign-in rather than in the link, and seals it with the token, so the token only ever goes back to that address.

## The apps

| App | `<APP>` | Search | Link previews | Connect with a token | Sign in |
| --- | --- | --- | --- | --- | --- |
| GitHub | `GITHUB` | issues, pull requests, repositories | issues, pull requests | personal access token (fine-grained read-only works) | OAuth app |
| Google Drive | `GOOGLE_DRIVE` | files in My Drive and shared drives | | | OAuth client (see below) |
| Slack | `SLACK` | messages | | | Slack app with a user token (`search:read`) |
| Jira | `JIRA` or `ATLASSIAN` | issues | issues | site, email and API token | Atlassian OAuth 2.0 (3LO) app |
| Confluence | `CONFLUENCE` or `ATLASSIAN` | pages and blog posts | | site, email and API token | Atlassian OAuth 2.0 (3LO) app |
| Zendesk | `ZENDESK` | tickets, Help Center articles | tickets | subdomain, email and API token | global OAuth client; asks for the subdomain first |
| Asana | `ASANA` | tasks, projects | tasks | personal access token | OAuth app |
| Box | `BOX` | files and folders | | | OAuth app |
| Dropbox | `DROPBOX` | files and folders | | | app with PKCE |
| Guru | `GURU` | cards | cards | email and user token | |
| GitLab | `GITLAB` | | issues, merge requests | personal access token (and the server's URL for self-managed GitLab) | gitlab.com OAuth app |
| Linear | `LINEAR` | | issues | personal API key | OAuth app |
| Freshdesk | `FRESHDESK` | | tickets | domain and API key | |
| Shortcut | `SHORTCUT` | | stories | API token | |
| Todoist | `TODOIST` | | tasks | API token | OAuth app |
| Trello | `TRELLO` | | cards | API key and token | Trello OAuth 2.0 client, made in Trello's app admin |
| ClickUp | `CLICKUP` | | tasks | personal token | OAuth app |
| monday.com | `MONDAY` | | items | API token | OAuth app with the new OAuth flow turned on |
| Wrike | `WRIKE` | | tasks | permanent access token | OAuth app |

Things worth knowing before you register apps:

- **Google Drive** needs the `drive.readonly` scope, which Google calls restricted: a public app must pass Google's verification before more than 100 people can connect. Until then, add testers to the OAuth consent screen.
- **Slack**'s terms allow distributing an app commercially only through the Slack Marketplace, so hosted DumbSlab's shared Slack app needs a listing. A self-hosted server's own Slack app counts as internal. Message search uses `search.messages`, which works for any app. Use the same Slack app for **Add to Slack** ([docs/hosting/slack-app.md](hosting/slack-app.md)): its manifest has every redirect URL and scope both need.
- **Zendesk** is retiring API tokens: no new ones since October 27, 2026, and existing ones stop working on April 30, 2027. A service for many companies, like hosted DumbSlab, needs a *global* OAuth client, which Zendesk approves. With one, people type their subdomain and sign in on their own Zendesk (scope `read`, PKCE). Access tokens last 8 hours and refresh tokens 90 days, renewed on each refresh, so a connection unused for 90 days must be connected again. A self-hosted server connecting its own company's Zendesk may use a normal OAuth client from that account, or existing tokens.
- **Atlassian**: one app in Atlassian's developer console serves Jira and Confluence (`ATLASSIAN_CLIENT_ID`). Add the Jira and Confluence APIs. Connections keep only the site, never anyone's account ID, email or name, so DumbSlab has no personal data to report to Atlassian (or to Trello). When the two share an app, each sign-in asks for both products' scopes: Atlassian keeps one grant per person and app, and a new consent replaces the old one's scopes. Trello can't share it: its OAuth 2.0 clients are made at trello.com/apps/admin.
- **Asana**'s OAuth app should ask only for `users:read`, `workspaces:read`, `workspaces.typeahead:read`, `tasks:read` and `projects:read`.
