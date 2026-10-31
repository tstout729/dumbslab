# Connected apps

Each person can connect their own accounts in other apps (GitHub, Google Drive, Jira, Slack and more), then:

- **search them** next to the workspace: the search page shows a "From your connected apps" section, and agents call `search_connected`;
- **preview links** to them: hovering a link to a GitHub issue, Jira issue, Zendesk ticket and so on in a post shows its title, status, assignee and description (`preview_link` for agents).

Everyone uses their own account, so results and previews hold only what that person can see in the app. Nobody can use anyone else's connection. Connections live in Settings › Connected apps (`list_connections`, `connect_app`, `disconnect_app`).

## How it works

- Credentials are encrypted in the workspace database with the server's connector key (AES-256-GCM, bound to the person and the app). No operation returns them.
- The core builds every request to an app and reads every answer. The host only sends the requests: over https, without following redirects, within 8 seconds, reading at most 4 MB. The self-hosted server also refuses private network addresses, like it does for webhooks.
- Links in results and previews must be `http(s)` links, and everything an app returns is shown as plain text.
- Tokens that expire (Google, Box, Dropbox, Atlassian and others) are refreshed with their refresh token in the five minutes before they expire, by one request at a time: some apps accept each refresh token only once.

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

The redirect (callback) URL to register is:

- hosted DumbSlab: `https://<root domain>/connect/callback`, e.g. `https://dumbslab.com/connect/callback`. The root domain forwards each person to their own workspace, so one URL serves every workspace.
- self-hosted or a single workspace: `<your public URL>/connect/callback`.

The person who started signing in must be the one who comes back, signed in to the workspace, within 15 minutes; each sign-in link works once.

## The apps

| App | `<APP>` | Search | Link previews | Connect with a token | Sign in |
| --- | --- | --- | --- | --- | --- |
| GitHub | `GITHUB` | issues, pull requests, repositories | issues, pull requests | personal access token (fine-grained read-only works) | OAuth app |
| Google Drive | `GOOGLE_DRIVE` | files in My Drive and shared drives | | | OAuth client (see below) |
| Slack | `SLACK` | messages | | | Slack app with a user token (`search:read`) |
| Jira | `JIRA` | issues | issues | site, email and API token | Atlassian OAuth 2.0 (3LO) app |
| Confluence | `CONFLUENCE` | pages and blog posts | | site, email and API token | Atlassian OAuth 2.0 (3LO) app |
| Zendesk | `ZENDESK` | tickets, Help Center articles | tickets | subdomain, email and API token | |
| Asana | `ASANA` | tasks, projects | tasks | personal access token | OAuth app |
| Box | `BOX` | files and folders | | | OAuth app |
| Dropbox | `DROPBOX` | files and folders | | | app with PKCE |
| Guru | `GURU` | cards | cards | email and user token | |
| GitLab | `GITLAB` | | issues, merge requests | personal access token (and the server's URL for self-managed GitLab) | gitlab.com OAuth app |
| Linear | `LINEAR` | | issues | personal API key | OAuth app |
| Freshdesk | `FRESHDESK` | | tickets | domain and API key | |
| Shortcut | `SHORTCUT` | | stories | API token | |
| Todoist | `TODOIST` | | tasks | API token | OAuth app |
| Trello | `TRELLO` | | cards | API key and token | Atlassian OAuth 2.0 app for Trello |
| ClickUp | `CLICKUP` | | tasks | personal token | OAuth app |
| monday.com | `MONDAY` | | items | API token | OAuth app with the new OAuth flow turned on |
| Wrike | `WRIKE` | | tasks | permanent access token | OAuth app |

Things worth knowing before you register apps:

- **Google Drive** needs the `drive.readonly` scope, which Google calls restricted: a public app must pass Google's verification before more than 100 people can connect. Until then, add testers to the OAuth consent screen.
- **Slack**'s terms allow distributing an app commercially only through the Slack Marketplace, so hosted DumbSlab's shared Slack app needs a listing. A self-hosted server's own Slack app counts as internal. Message search uses `search.messages`, which works for any app.
- **Zendesk** is retiring API tokens: no new ones since October 27, 2026, and existing ones stop working on April 30, 2027. Zendesk's own OAuth clients belong to one Zendesk account, so a shared app needs a global OAuth client that Zendesk approves; until then, Zendesk works only with existing tokens.
- **Atlassian** (Jira, Confluence, Trello) uses one developer console. Add the "User identity API" so DumbSlab can show whose account it is.
- **GitLab**: docs sync's Connect GitLab uses the same app, with the `api` scope and a second redirect URI, `<root>/sync/gitlab/callback` (see [hosting/gitlab-app.md](hosting/gitlab-app.md)). Connected apps keep asking for `read_api` only.
- **Asana**'s OAuth app should ask only for `users:read`, `workspaces:read`, `workspaces.typeahead:read`, `tasks:read` and `projects:read`.
