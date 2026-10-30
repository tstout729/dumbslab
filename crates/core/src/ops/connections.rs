//! Connected apps: connect your own accounts elsewhere (GitHub, Google Drive…) and search them
//! from the workspace. The machinery lives in [`crate::connect`].

use std::collections::BTreeMap;

use chrono::Utc;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{DONE, Done, NoInput};
use crate::connect::{
    self, ConnectJob, ConnectedAccount, ConnectedResults, Credential, Deferred, Field, Job, LinkPreview, PreviewJob, SearchJob, providers,
};
use crate::db::DbExt;
use crate::error::{ApiError, ApiResult};
use crate::registry::{Access, Ctx, Op, op};
use crate::{Effect, params};

pub fn ops() -> Vec<Op> {
    vec![
        op("connections", "list_connections", "GET", "/connections", Access::Read, list_connections)
            .title("Connected apps")
            .desc("The apps you can connect (GitHub, Google Drive…) and which you have. For each: whether this server lets you sign in to it (`sign_in`), and the fields for connecting with a personal token instead (`token_fields`). Everyone connects their own accounts; nobody else can use them.")
            .build(),
        op("connections", "connect_app", "POST", "/connections", Access::Write, connect_app)
            .title("Connect an app")
            .desc("Connect one of your accounts in another app, so search_connected can search it. Without `fields`, returns an `authorize_url` for a person to open and sign in to the app; they come back to Settings. With `fields` (at least `token`; list_connections names each app's fields), connects with a personal token right away. Credentials are encrypted and never shown again.")
            .build(),
        op("connections", "disconnect_app", "DELETE", "/connections/{app}", Access::Write, disconnect_app)
            .title("Disconnect an app")
            .desc("Remove your connection to an app and forget its credentials here. To revoke DumbSlab's access completely, also remove it in the app's own settings.")
            .destructive()
            .build(),
        op("connections", "search_connected", "GET", "/search/connected", Access::Read, search_connected)
            .title("Search connected apps")
            .desc("Search the apps you connected (GitHub issues and pull requests, Google Drive files…) with your own accounts, so results hold only what you can see there. Answers with each app's results and how each app's search went. `search` covers the workspace's own posts.")
            .build(),
        op("connections", "preview_link", "GET", "/connections/preview", Access::Read, preview_link)
            .title("Preview a link")
            .desc("Preview a link to an item in a connected app (a GitHub issue or pull request, a Jira issue, a Zendesk ticket…): its title, status, assignee and description, read with your own account. `app` names the app even when you haven't connected it, so you can suggest connecting it.")
            .build(),
    ]
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct AppInfo {
    /// `github`, `google-drive`…
    pub id: String,
    pub name: String,
    /// What connecting it gives you.
    pub about: String,
    /// search_connected searches it.
    pub search: bool,
    /// preview_link previews links to it.
    pub preview: bool,
    /// You can connect by signing in to the app: this server registered an OAuth app with it.
    pub sign_in: bool,
    /// What to fill in to connect with a personal token instead. Empty when the app has none.
    pub token_fields: Vec<Field>,
    /// Where to make that token.
    pub token_help: Option<String>,
    /// Your connection, if you made one.
    pub connected: Option<ConnectedAccount>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ConnectionList {
    /// Connecting apps is set up on this server.
    pub enabled: bool,
    pub apps: Vec<AppInfo>,
}

fn list_connections(ctx: &mut Ctx, _: NoInput) -> ApiResult<ConnectionList> {
    let enabled = connect::enabled(ctx.cfg);
    let mine = if enabled { connect::connections(ctx.db, ctx.cfg, &ctx.actor.user_id)? } else { vec![] };
    let apps = providers::ALL
        .iter()
        .map(|c| {
            let info = c.info();
            AppInfo {
                id: info.id.into(),
                name: info.name.into(),
                about: info.about.into(),
                search: info.search,
                preview: info.preview,
                sign_in: info.oauth.is_some() && connect::oauth_app(ctx.cfg, info.id).is_some(),
                token_fields: info.token_fields.to_vec(),
                token_help: Some(info.token_help.to_string()).filter(|h| !h.is_empty()),
                connected: mine.iter().find(|m| m.provider == info.id).map(|m| ConnectedAccount {
                    provider: info.id.into(),
                    name: info.name.into(),
                    account: m.account.label.clone(),
                    connected_at: m.connected_at.clone(),
                }),
            }
        })
        .collect();
    Ok(ConnectionList { enabled, apps })
}

fn app(id: &str) -> ApiResult<&'static dyn connect::Connector> {
    providers::get(id.trim()).ok_or_else(|| ApiError::bad_request(format!("unknown app `{id}`; list_connections names them")))
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectInput {
    /// `github`, `google-drive`… (see list_connections).
    pub app: String,
    /// To connect with a personal token: the app's `token_fields`, at least `token`. Leave out to sign in to the app instead.
    pub fields: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ConnectStart {
    /// Open this in a browser to sign in to the app. Afterwards the person lands on Settings › Connected apps.
    pub authorize_url: Option<String>,
    /// The new connection, when you connected with a token.
    pub connection: Option<ConnectedAccount>,
}

fn connect_app(ctx: &mut Ctx, input: ConnectInput) -> ApiResult<Deferred<ConnectStart>> {
    let connector = app(&input.app)?;
    let info = connector.info();
    if !connect::enabled(ctx.cfg) {
        return Err(ApiError::new(503, "connections_off", "Connected apps aren't set up on this server: it has no connector key."));
    }
    let Some(fields) = input.fields else {
        let url = connect::start_sign_in(ctx.db, ctx.cfg, &ctx.base_url, &ctx.actor.user_id, connector, Utc::now())?;
        return Ok(Deferred::Ready(ConnectStart { authorize_url: Some(url), connection: None }));
    };
    if info.token_fields.is_empty() {
        return Err(ApiError::bad_request(format!("{} has no personal tokens; leave out `fields` to sign in instead", info.name)));
    }
    let mut cred = Credential::default();
    for (key, value) in fields {
        let Some(field) = info.token_fields.iter().find(|f| f.key == key) else {
            return Err(ApiError::bad_request(format!("{} doesn't take `{key}`", info.name)));
        };
        let value = value.trim().to_string();
        if value.chars().count() > 4096 {
            return Err(ApiError::bad_request(format!("`{}` is too long", field.label)));
        }
        if key == "token" {
            cred.token = value;
        } else if !value.is_empty() {
            cred.fields.insert(key, value);
        }
    }
    for f in info.token_fields.iter().filter(|f| !f.optional) {
        let filled = if f.key == "token" { !cred.token.is_empty() } else { cred.fields.contains_key(f.key) };
        if !filled {
            return Err(ApiError::bad_request(format!("{} needs `{}` ({})", info.name, f.key, f.label)));
        }
    }
    // The host checks the token with the app, then saves it.
    ctx.effects.push(Effect::Connect(Job::Connect(ConnectJob::with_token(&ctx.actor.user_id, info.id, cred))));
    Ok(Deferred::Pending)
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AppInput {
    /// `github`, `google-drive`…
    pub app: String,
}

fn disconnect_app(ctx: &mut Ctx, input: AppInput) -> ApiResult<Done> {
    let connector = app(&input.app)?;
    if !connect::remove(ctx.db, &ctx.actor.user_id, connector.info().id)? {
        return Err(ApiError::not_found(format!("your {} connection", connector.info().name)));
    }
    Ok(DONE)
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchConnectedInput {
    pub q: String,
    /// Only these apps, e.g. `["github"]`. Default: every app you connected.
    pub apps: Option<Vec<String>>,
    /// Results per app, 1 to 20. Default 5.
    pub limit: Option<u32>,
}

fn search_connected(ctx: &mut Ctx, input: SearchConnectedInput) -> ApiResult<Deferred<ConnectedResults>> {
    let q = input.q.trim();
    if q.is_empty() {
        return Ok(Deferred::Ready(ConnectedResults::default()));
    }
    if q.chars().count() > 200 {
        return Err(ApiError::bad_request("search for at most 200 characters"));
    }
    let limit = input.limit.unwrap_or(5).clamp(1, 20) as usize;
    let only: Vec<String> = match input.apps {
        Some(list) => list.iter().map(|a| app(a).map(|c| c.info().id.to_string())).collect::<ApiResult<_>>()?,
        None => vec![],
    };
    if !connect::enabled(ctx.cfg)
        || ctx.db.scalar_i64("SELECT COUNT(*) FROM connections WHERE user_id = ?", &params![ctx.actor.user_id.clone()])? == 0
    {
        return Ok(Deferred::Ready(ConnectedResults::default()));
    }
    ctx.effects.push(Effect::Connect(Job::Search(SearchJob::new(&ctx.actor.user_id, q, limit, only))));
    Ok(Deferred::Pending)
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PreviewInput {
    /// The link, e.g. `https://github.com/acme/api/issues/7`.
    pub url: String,
}

fn preview_link(ctx: &mut Ctx, input: PreviewInput) -> ApiResult<Deferred<LinkPreview>> {
    let url = input.url.trim();
    if !(url.starts_with("https://") || url.starts_with("http://")) || url.len() > 2000 {
        return Err(ApiError::bad_request("`url` must be an http(s) link"));
    }
    if connect::enabled(ctx.cfg) {
        for conn in connect::connections(ctx.db, ctx.cfg, &ctx.actor.user_id)? {
            let p = providers::get(conn.provider).expect("connections() returns known apps");
            if !p.info().preview {
                continue;
            }
            if let Some(job) = PreviewJob::new(&ctx.actor.user_id, conn, url) {
                ctx.effects.push(Effect::Connect(Job::Preview(job)));
                return Ok(Deferred::Pending);
            }
        }
    }
    // Not connected: say which app it is anyway, where the link alone tells.
    let app = providers::ALL.iter().find(|p| p.info().preview && p.recognizes(url)).map(|p| p.info().id.to_string());
    Ok(Deferred::Ready(LinkPreview { app, connected: false, preview: None, error: None }))
}
