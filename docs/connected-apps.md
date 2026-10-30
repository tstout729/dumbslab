# Connected apps

Each person can connect their own accounts in other apps (GitHub, Google Drive, Jira, Slack and more), then:

- **search them** next to the workspace: the search page shows a "From your connected apps" section, and agents call `search_connected`;
- **preview links** to them: hovering a link to a GitHub issue, Jira issue, Zendesk ticket and so on in a post shows its title, status, assignee and description (`preview_link` for agents).

Everyone uses their own account, so results and previews hold only what that person can see in the app. Nobody can use anyone else's connection. Connections live in Settings › Connected apps (`list_connections`, `connect_app`, `disconnect_app`).

## How it works

- Credentials are encrypted in the workspace database with the server's connector key (AES-256-GCM, bound to the person and the app). No operation returns them.
- The core builds every request to an app and reads every answer. The host only sends the requests: over https, without following redirects, within 8 seconds, reading at most 4 MB. The self-hosted server also refuses private network addresses, like it does for webhooks.
- Links in results and previews must be `http(s)` links, and everything an app returns is shown as plain text.
- Tokens that expire (Google, Box, Dropbox, Atlassian and others) are refreshed with their refresh token before use.

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
