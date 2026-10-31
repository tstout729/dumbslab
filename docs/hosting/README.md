# Setting up DumbSlab's own apps (for operators)

Hosted DumbSlab registers one app with each provider, so people connect with a click and an approval instead of making their own apps or pasting tokens. Until an app is registered and its values are set, the feature it powers stays hidden, and workspaces can still use their own app or a token where that's offered.

This page is the checklist. Each step links to the guide with the exact settings.

## Before you start

- The server needs its connector key (`CONNECTOR_KEY` on Cloudflare). It encrypts every token and secret these apps produce. See [Cloudflare](../cloudflare.md).
- Every redirect URI below is on the root domain, such as `https://dumbslab.com/connect/callback`. The root domain sends each person back to their own workspace, so one URI serves every workspace.
- Client IDs and other public values go in `crates/worker/wrangler.toml` under `[vars]`. Secrets go in with `npx wrangler secret put <NAME>`. Deploy after changing `[vars]`.

## The checklist

Do the quick ones first. Start the reviews in the last section early, because they take days or weeks.

| # | App | What it turns on | Guide | Values |
| --- | --- | --- | --- | --- |
| 1 | DumbSlab's Slack app | Add to Slack, Sign in with Slack, Slack search | [slack-app.md](slack-app.md) | `SLACK_CLIENT_ID`; secrets `SLACK_CLIENT_SECRET`, `SLACK_SIGNING_SECRET` |
| 2 | DumbSlab's GitHub App | Docs sync from GitHub without tokens or webhooks | [github-app.md](github-app.md) | `GITHUB_APP_ID`, `GITHUB_APP_SLUG`, `GITHUB_APP_CLIENT_ID`; secrets `GITHUB_APP_CLIENT_SECRET`, `GITHUB_APP_PRIVATE_KEY`, `GITHUB_APP_WEBHOOK_SECRET` |
| 3 | GitLab OAuth app | Docs sync from gitlab.com, GitLab previews | [gitlab-app.md](gitlab-app.md) | `GITLAB_CLIENT_ID`; secret `GITLAB_CLIENT_SECRET` |
| 4 | Google sign-in client | Set up single sign-on with Google | [sign-in-apps.md](sign-in-apps.md#google) | `SSO_GOOGLE_CLIENT_ID`; secret `SSO_GOOGLE_CLIENT_SECRET` |
| 5 | Microsoft Entra app (multi-tenant) | Set up single sign-on with Microsoft | [sign-in-apps.md](sign-in-apps.md#microsoft) | `SSO_MICROSOFT_CLIENT_ID`; secret `SSO_MICROSOFT_CLIENT_SECRET` |
| 6 | BambooHR app | People sync with Sign in with BambooHR | [bamboohr-app.md](bamboohr-app.md) | `BAMBOOHR_CLIENT_ID`; secret `BAMBOOHR_CLIENT_SECRET` |
| 7 | Connected apps (GitHub, Atlassian, Linear, Asana and 11 more) | Searching and previewing each app from DumbSlab | [connected-apps.md](connected-apps.md) | `<APP>_CLIENT_ID`; secret `<APP>_CLIENT_SECRET` |

Notes:

- **One Slack app does everything Slack.** Create it from `https://dumbslab.com/slack/create-app`, which fills in the whole manifest. Then turn on public distribution in the app's settings.
- **GitLab's app serves two features.** Connected apps use it with `read_api`. Docs sync also needs the `api` scope and its own redirect URI. Register it once with both.
- **Atlassian:** one app (`ATLASSIAN_CLIENT_ID`) covers Jira and Confluence. Trello registers separately.
- **Okta, OneLogin and other OpenID Connect providers** stay per workspace, because every organization runs its own. Nothing to register here.
- **Freshdesk, Guru and Shortcut** have no sign-in that a hosted service can use, so people connect them with a token.

## Reviews to start early

Each of these lets DumbSlab work for everyone, not just test accounts. Submit them as soon as the app exists.

| Provider | What it needs | Until then |
| --- | --- | --- |
| Google Drive (connected app) | Restricted-scope verification and a yearly security assessment | Only test users you list (up to 100) can connect Drive |
| Zendesk | Zendesk approves a global OAuth client | Zendesk can't use sign-in; existing API tokens stop working on April 30, 2027 |
| Dropbox | Production approval | Up to 50 people can connect |
| Slack | Slack Marketplace listing: at least 10 active workspaces, a landing page, privacy policy and support page | Everything works. Slack's terms ask commercially distributed apps to be listed. |
| BambooHR | BambooHR may review the app before production use | Ask BambooHR once the app is registered |
| Microsoft | Publisher verification (optional) | Some organizations need an administrator to approve the app |
| Google sign-in | Brand verification (optional) | Google's consent screen doesn't show DumbSlab's name and logo |

## Moving to another Cloudflare account

Secrets don't move with the code. After moving the Worker to a new account, set `CONNECTOR_KEY` to the same value as before, or every saved token becomes unreadable. Then put each secret above again. The apps themselves don't change, because their redirect URIs are on the domain, not the account.
