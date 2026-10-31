//! Docs sync from gitlab.com without a token or a webhook to copy. An admin chooses **Connect
//! GitLab** and approves DumbSlab's GitLab app; they pick a project, and DumbSlab adds the
//! project's push webhook itself. Self-managed GitLab keeps the token path.
//!
//! - **The app** is the one connected apps already use (`GITLAB_CLIENT_ID` and
//!   `GITLAB_CLIENT_SECRET`), with its own authorization for docs sync: it asks for the `api` scope,
//!   the one GitLab requires to add a project webhook (`read_api` can't), and comes back to
//!   `/sync/gitlab/callback` with PKCE.
//! - **Connecting** ([`start`], [`callback`]) uses the same hashed, single-use state bound to the
//!   admin's browser session as Connect GitHub ([`super::github_app::begin`]). The approval waits in
//!   `docs_connections` for the admin to pick a project, which they must be able to maintain
//!   (GitLab's Maintainer role: `min_access_level=40`).
//! - **Adding a folder** moves the approval's tokens onto the new source, so each source refreshes
//!   its own: GitLab's access tokens last two hours and each refresh replaces the refresh token. A
//!   source refreshes during a sync, under the sync's lease, so two refreshes never race. DumbSlab
//!   adds the push webhook (`POST /projects/:id/hooks`, with the source's secret as its token) to
//!   the workspace's usual `/hooks/docs/<source id>`, and removes it when the source is removed.
//!
//! Docs: https://docs.gitlab.com/api/oauth2/ (PKCE; tokens last 7200 seconds; refreshing replaces
//! both tokens), https://docs.gitlab.com/integration/oauth_provider/ (scopes: `api` reads and
//! writes, `read_api` only reads), https://docs.gitlab.com/api/projects/#list-all-projects
//! (`membership`, `min_access_level=40`, `simple`, 100 a page), https://docs.gitlab.com/api/project_webhooks/
//! (Maintainer role; `url`, `push_events`, `token`, `enable_ssl_verification`; deliveries carry the
//! token in `X-Gitlab-Token`).

use std::collections::BTreeSet;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::github_app::{Problem, begin, query_map, returned, settings_url};
use crate::connect::{self, Credential, Finish, HttpCall, HttpReply, Job, OAuthApp, Step, TokenSet, http_error};
use crate::db::{Db, DbExt};
use crate::error::{ApiError, ApiResult};
use crate::util::{parse_ts, ts};
use crate::{Effect, HostConfig, Outcome, Request, Response, params};

pub const START_PATH: &str = "/sync/gitlab/start";
pub const CALLBACK_PATH: &str = "/sync/gitlab/callback";
pub const HOST: &str = "gitlab.com";
const API: &str = "https://gitlab.com/api/v4";
const TOKEN_URL: &str = "https://gitlab.com/oauth/token";
/// Adding a project webhook needs it; `read_api` only reads.
pub const SCOPE: &str = "api";
/// Pages of 100 projects a listing reads.
pub const PROJECT_PAGES: usize = 3;
/// Tokens this close to expiring are refreshed first.
const REFRESH_MARGIN_SECS: i64 = 300;
/// The name DumbSlab gives the webhooks it adds.
const HOOK_NAME: &str = "DumbSlab docs sync";
/// A source's `disconnected` code: GitLab stopped accepting its tokens.
pub(crate) const SIGNED_OUT: &str = "gitlab_signed_out";

/// The connected-app GitLab OAuth app, when the host registered one.
pub fn app(cfg: &HostConfig) -> Option<&OAuthApp> {
    connect::oauth_app(cfg, "gitlab")
}

/// Connect GitLab is offered: the host has the GitLab app and a connector key.
pub fn available(cfg: &HostConfig) -> bool {
    app(cfg).is_some() && connect::enabled(cfg)
}

/// Where GitLab sends the admin back: the root domain's, on hosted DumbSlab (it forwards to the
/// workspace, like connected apps' sign-ins), or this server's.
fn redirect_uri(cfg: &HostConfig, base_url: &str) -> String {
    match cfg.connectors.callback_url.as_deref().and_then(|u| u.strip_suffix("/connect/callback")) {
        Some(root) => format!("{root}{CALLBACK_PATH}"),
        None => format!("{base_url}{CALLBACK_PATH}"),
    }
}

fn gitlab() -> &'static dyn connect::Connector {
    connect::providers::get("gitlab").expect("GitLab is a connected app")
}

fn api_get(url: String, token: &str) -> HttpCall {
    HttpCall::get(url).header("accept", "application/json").header("user-agent", "DumbSlab").bearer(token)
}

fn enc(s: &str) -> String {
    urlencoding::encode(s).into_owned()
}

/// When tokens from GitLab expire.
pub(crate) fn expiry(now: DateTime<Utc>, tokens: &TokenSet) -> Option<DateTime<Utc>> {
    tokens.expires_in.filter(|s| *s > 0).map(|s| now + Duration::seconds(s))
}

pub(crate) fn needs_refresh(cred: &Credential, expires_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    cred.refresh_token.is_some() && expires_at.is_some_and(|e| e - Duration::seconds(REFRESH_MARGIN_SECS) <= now)
}

/// A request to GitLab's token endpoint, with the app's client id and secret. Built here rather
/// than by the connected-app connector: docs sync only ever talks to gitlab.com.
fn token_call(app: &OAuthApp, form: &[(&str, &str)]) -> HttpCall {
    let mut all = form.to_vec();
    all.push(("client_id", &app.client_id));
    all.push(("client_secret", &app.client_secret));
    HttpCall::post_form(TOKEN_URL, &all).header("accept", "application/json")
}

/// Reads GitLab's token answer.
fn read_tokens(reply: &HttpReply) -> Result<TokenSet, String> {
    connect::standard_token("GitLab", reply)
}

pub(crate) fn refresh_call(app: &OAuthApp, cred: &Credential) -> HttpCall {
    let refresh = cred.refresh_token.clone().unwrap_or_default();
    token_call(app, &[("grant_type", "refresh_token"), ("refresh_token", &refresh)])
}

/// Puts refreshed tokens in `cred`, keeping its other fields (the webhook secret).
pub(crate) fn apply_tokens(cred: &mut Credential, tokens: TokenSet) {
    cred.token = tokens.access_token;
    if let Some(r) = tokens.refresh_token {
        cred.refresh_token = Some(r);
    }
}

/// Reads a refresh's answer. An error says what to do, for the admin.
pub(crate) fn read_refresh(reply: &HttpReply) -> Result<TokenSet, String> {
    read_tokens(reply).map_err(|_| match reply.status {
        0 | 429 => http_error("GitLab", reply),
        s if s >= 500 => http_error("GitLab", reply),
        _ => "GitLab no longer accepts DumbSlab's access for this folder (it was revoked, or the person who approved it lost access). Connect GitLab again and choose Reconnect.".into(),
    })
}

// ---------------------------------------------------------------------------
// Approvals waiting for a project

/// How long one request may hold an approval (`docs_connections.claimed_until`): a job takes at
/// most [`connect::MAX_STEPS`] steps of at most [`connect::FETCH_TIMEOUT_SECS`] each.
const CLAIM_SECS: i64 = 90;

/// An admin's approval of DumbSlab's GitLab app, held by one request (see [`claim`]).
#[derive(Clone)]
pub(crate) struct Pending {
    pub account: String,
    pub cred: Credential,
    pub expires_at: Option<DateTime<Utc>>,
}

// Holds tokens; never print them.
impl std::fmt::Debug for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pending").field("account", &self.account).finish_non_exhaustive()
    }
}

fn pending_owner(user_id: &str) -> String {
    format!("docs-connection:{user_id}")
}

/// Claims the admin's approval for one request (listing projects, adding or reconnecting a
/// folder), so only that request refreshes or takes it: GitLab replaces both tokens at each
/// refresh, so two requests using one approval would break each other, or end up with one
/// approval in two sources. `Ok(None)` when they have none; a conflict while another request
/// holds it.
pub(crate) fn claim(db: &dyn Db, user_id: &str, now: DateTime<Utc>) -> ApiResult<Option<String>> {
    if db.one("SELECT 1 AS ok FROM docs_connections WHERE provider = 'gitlab' AND user_id = ?", &params![user_id])?.is_none() {
        return Ok(None);
    }
    let claim = format!("{} {}", ts(now + Duration::seconds(CLAIM_SECS)), crate::util::new_id());
    let claimed = db.execute(
        "UPDATE docs_connections SET claimed_until = ? WHERE provider = 'gitlab' AND user_id = ? AND (claimed_until IS NULL OR claimed_until <= ?)",
        &params![claim.clone(), user_id, ts(now)],
    )? > 0;
    if !claimed {
        return Err(ApiError::conflict("Your GitLab approval is in use by another request. Try again in a moment."));
    }
    Ok(Some(claim))
}

/// The approval `claim` holds, unless it was replaced (connected again) or taken meanwhile, or
/// can't be read (the connector key changed).
fn held(db: &dyn Db, cfg: &HostConfig, user_id: &str, claim: &str) -> ApiResult<Option<Pending>> {
    let Some(r) = db.one(
        "SELECT account, secret, expires_at FROM docs_connections WHERE provider = 'gitlab' AND user_id = ? AND claimed_until = ?",
        &params![user_id, claim],
    )?
    else {
        return Ok(None);
    };
    Ok(super::open(cfg, &pending_owner(user_id), "gitlab", &r.str("secret")).ok().map(|cred| Pending {
        account: r.str("account"),
        cred,
        expires_at: r.opt_str("expires_at").and_then(|e| parse_ts(&e)),
    }))
}

/// Saves the held approval's refreshed tokens. `false` when `claim` doesn't hold it any more.
fn save_held(db: &dyn Db, cfg: &HostConfig, user_id: &str, claim: &str, p: &Pending) -> ApiResult<bool> {
    let secret = super::seal(cfg, &pending_owner(user_id), "gitlab", &p.cred)?;
    Ok(db.execute(
        "UPDATE docs_connections SET secret = ?, expires_at = ? WHERE provider = 'gitlab' AND user_id = ? AND claimed_until = ?",
        &params![secret, p.expires_at.map(ts), user_id, claim],
    )? > 0)
}

/// Lets go of the approval, for the next request.
fn release(db: &dyn Db, user_id: &str, claim: &str) -> ApiResult<()> {
    db.execute(
        "UPDATE docs_connections SET claimed_until = NULL WHERE provider = 'gitlab' AND user_id = ? AND claimed_until = ?",
        &params![user_id, claim],
    )?;
    Ok(())
}

/// Takes the held approval (its tokens move to a source, or GitLab refused them). `false` when
/// `claim` doesn't hold it any more.
fn take(db: &dyn Db, user_id: &str, claim: &str) -> ApiResult<bool> {
    Ok(db.execute(
        "DELETE FROM docs_connections WHERE provider = 'gitlab' AND user_id = ? AND claimed_until = ?",
        &params![user_id, claim],
    )? > 0)
}

/// Keeps a new approval, in place of any earlier one: whoever held that one finds it gone.
fn save_new(db: &dyn Db, cfg: &HostConfig, user_id: &str, p: &Pending, now: DateTime<Utc>) -> ApiResult<()> {
    let secret = super::seal(cfg, &pending_owner(user_id), "gitlab", &p.cred)?;
    db.execute(
        "INSERT INTO docs_connections (id, provider, user_id, account, secret, expires_at, created_at) VALUES (?, 'gitlab', ?, ?, ?, ?, ?)
         ON CONFLICT(provider, user_id) DO UPDATE SET account = excluded.account, secret = excluded.secret, expires_at = excluded.expires_at,
           claimed_until = NULL, created_at = excluded.created_at",
        &params![crate::util::new_id(), user_id, p.account.clone(), secret, p.expires_at.map(ts), ts(now)],
    )?;
    Ok(())
}

/// Holds a source like a sync does (`running_until`), so no sync refreshes its tokens while it's
/// reconnected. Its sync history stays as it was.
pub(crate) fn hold_source(db: &dyn Db, source_id: &str, now: DateTime<Utc>) -> ApiResult<Option<String>> {
    let lease = format!("{} {}", ts(now + Duration::seconds(super::LEASE_SECS)), crate::util::new_id());
    let held = db.execute(
        "UPDATE docs_sources SET running_until = ? WHERE id = ? AND (running_until IS NULL OR running_until <= ?)",
        &params![lease.clone(), source_id, ts(now)],
    )? > 0;
    Ok(held.then_some(lease))
}

fn let_go_source(db: &dyn Db, source_id: &str, lease: &str) -> ApiResult<()> {
    db.execute("UPDATE docs_sources SET running_until = NULL WHERE id = ? AND running_until = ?", &params![source_id, lease])?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Projects and webhooks

/// A project the admin can maintain on gitlab.com.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Project {
    pub id: i64,
    /// `group/subgroup/project`.
    pub path: String,
    /// GitLab leaves it out for people who can't read the code, and for empty projects.
    pub default_branch: Option<String>,
    /// `private`, `internal` or `public`.
    pub visibility: String,
}

fn read_project(v: &Value) -> Option<Project> {
    let (_, path) = super::repo::gitlab_project(v["path_with_namespace"].as_str()?, "").ok()?;
    Some(Project {
        id: v["id"].as_i64().filter(|i| *i > 0)?,
        path,
        default_branch: v["default_branch"].as_str().filter(|b| super::repo::valid_branch(b)).map(str::to_string),
        visibility: v["visibility"].as_str().unwrap_or_default().chars().take(20).collect(),
    })
}

/// The requests that list the projects the admin can maintain, most recently active first.
pub(crate) fn project_calls(token: &str) -> Vec<HttpCall> {
    (1..=PROJECT_PAGES)
        .map(|page| {
            api_get(
                format!(
                    "{API}/projects?membership=true&min_access_level=40&simple=true&order_by=last_activity_at&per_page=100&page={page}"
                ),
                token,
            )
        })
        .collect()
}

/// The projects in the answers to [`project_calls`], and whether there are more.
pub(crate) fn read_projects(replies: &[HttpReply]) -> Result<(Vec<Project>, bool), String> {
    let mut out: Vec<Project> = vec![];
    let mut last_full = false;
    for r in replies {
        let v = r.json();
        let (true, Some(page)) = (r.ok(), v.as_array()) else { return Err(http_error("GitLab", r)) };
        last_full = page.len() >= 100;
        out.extend(page.iter().filter_map(read_project));
    }
    let mut seen = BTreeSet::new();
    out.retain(|p| seen.insert(p.id));
    Ok((out, last_full))
}

pub(crate) fn project_call(token: &str, path: &str) -> HttpCall {
    api_get(format!("{API}/projects/{}", enc(path)), token)
}

/// The request for one project by id, among those the admin can maintain (the same filter as
/// [`project_calls`], which counts roles inherited from groups): empty when they can't.
pub(crate) fn maintained_project_call(token: &str, id: i64) -> HttpCall {
    api_get(format!("{API}/projects?membership=true&min_access_level=40&simple=true&id_after={}&id_before={}", id - 1, id + 1), token)
}

/// The request that adds a project's push webhook, to `url` with `secret` as its token.
pub(crate) fn add_hook_call(token: &str, project_id: i64, url: &str, secret: &str) -> HttpCall {
    let body = json!({ "name": HOOK_NAME, "url": url, "push_events": true, "token": secret, "enable_ssl_verification": true });
    HttpCall::post_json(format!("{API}/projects/{project_id}/hooks"), &body)
        .header("accept", "application/json")
        .header("user-agent", "DumbSlab")
        .bearer(token)
}

pub(crate) fn read_hook(reply: &HttpReply) -> Result<i64, String> {
    match (reply.status, reply.json()["id"].as_i64()) {
        (200 | 201, Some(id)) => Ok(id),
        (403, _) => Err("GitLab refused to add the webhook: you need the Maintainer role in that project.".into()),
        (404, _) => Err("GitLab can't find that project for your account.".into()),
        _ => Err(http_error("GitLab", reply)),
    }
}

/// The request that points an existing webhook at `url`, with `secret` as its token.
pub(crate) fn edit_hook_call(token: &str, project_id: i64, hook_id: i64, url: &str, secret: &str) -> HttpCall {
    let body = json!({ "name": HOOK_NAME, "url": url, "push_events": true, "token": secret, "enable_ssl_verification": true });
    HttpCall { method: "PUT", url: format!("{API}/projects/{project_id}/hooks/{hook_id}"), headers: vec![], body: Some(body.to_string()) }
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .header("user-agent", "DumbSlab")
        .bearer(token)
}

/// Pages of 100 of a project's webhooks read when looking for a source's.
pub(crate) const HOOK_PAGES: usize = 2;

/// The requests that list a project's webhooks.
pub(crate) fn list_hooks_calls(token: &str, project_id: i64) -> Vec<HttpCall> {
    (1..=HOOK_PAGES).map(|page| api_get(format!("{API}/projects/{project_id}/hooks?per_page=100&page={page}"), token)).collect()
}

/// Earlier addresses of a source's webhook it keeps (`hook_urls`).
const HOOK_HISTORY: usize = 10;

/// Where a source's webhook may point: where DumbSlab pointed it last and before (`hook_url` and
/// `hook_urls` in its credentials), and `current`, the workspace's address when the server knows
/// it ([`crate::HostConfig::knows_its_address`]).
pub(crate) fn hook_addresses(cred: &Credential, current: Option<&str>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    current
        .into_iter()
        .chain(std::iter::once(cred.field("hook_url")))
        .chain(cred.field("hook_urls").lines())
        .filter(|u| !u.is_empty() && seen.insert(u.to_string()))
        .map(str::to_string)
        .collect()
}

/// Points a source's webhook at `url` in its credentials, after `earlier` addresses: the address
/// it had joins them, as its history (see [`hook_addresses`]).
pub(crate) fn set_hook_url(cred: &mut Credential, url: &str, earlier: &[String]) {
    let mut history: Vec<String> = earlier.to_vec();
    history.extend(cred.field("hook_urls").lines().map(str::to_string));
    history.push(cred.field("hook_url").to_string());
    let mut seen = BTreeSet::new();
    history.retain(|u| !u.is_empty() && u != url && seen.insert(u.clone()));
    let skip = history.len().saturating_sub(HOOK_HISTORY);
    cred.fields.insert("hook_urls".into(), history[skip..].join("\n"));
    cred.fields.insert("hook_url".into(), url.to_string());
}

/// A webhook address, to compare: its scheme, its host and port (lowercase, without the scheme's
/// default port) and its path. `None` with user info, a query or a fragment, which DumbSlab's own
/// never have.
fn address(url: &str) -> Option<(String, String, String)> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "https" | "http") || rest.contains(['?', '#']) {
        return None;
    }
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let authority = authority.to_ascii_lowercase();
    let default = if scheme == "https" { ":443" } else { ":80" };
    let authority = authority.strip_suffix(default).unwrap_or(&authority).to_string();
    Some((scheme, authority, path.to_string()))
}

/// Whether a webhook posts to exactly this source's `/hooks/docs/<id>` at one of `trusted`, the
/// addresses DumbSlab pointed it at ([`hook_addresses`]): the same scheme, host and path, with no
/// query. Someone's own webhook that merely ends the same way (on another host, under another
/// path, or with a query) isn't the source's.
fn points_at(url: &str, source_id: &str, trusted: &[String]) -> bool {
    let Some(found) = address(url) else { return false };
    found.2.ends_with(&format!("/hooks/docs/{source_id}")) && trusted.iter().any(|t| address(t).as_ref() == Some(&found))
}

/// The ids of the project's webhooks that point at this source (see [`points_at`]), from the
/// answers to [`list_hooks_calls`]. `Err` when GitLab didn't list them.
pub(crate) fn source_hooks(replies: &[HttpReply], source_id: &str, trusted: &[String]) -> Result<Vec<i64>, String> {
    let mut out = vec![];
    for r in replies {
        let v = r.json();
        let (true, Some(page)) = (r.ok(), v.as_array()) else { return Err(http_error("GitLab", r)) };
        out.extend(
            page.iter().filter(|h| h["url"].as_str().is_some_and(|u| points_at(u, source_id, trusted))).filter_map(|h| h["id"].as_i64()),
        );
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

pub(crate) fn remove_hook_call(token: &str, project_id: i64, hook_id: i64) -> HttpCall {
    HttpCall { method: "DELETE", url: format!("{API}/projects/{project_id}/hooks/{hook_id}"), headers: vec![], body: None }
        .header("user-agent", "DumbSlab")
        .bearer(token)
}

// ---------------------------------------------------------------------------
// Connecting: the browser routes

fn redirect(url: String) -> Outcome {
    crate::http::done(Response::redirect(&url).with_header("cache-control", "no-store").with_header("referrer-policy", "no-referrer"))
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// GitLab's authorize page, for this state and verifier.
pub(crate) fn authorize_url(app: &OAuthApp, redirect_uri: &str, state: &str, verifier: &str) -> String {
    let query = [
        ("client_id", app.client_id.as_str()),
        ("redirect_uri", redirect_uri),
        ("response_type", "code"),
        ("state", state),
        ("scope", SCOPE),
        ("code_challenge", &pkce_challenge(verifier)),
        ("code_challenge_method", "S256"),
    ];
    let qs = query.iter().map(|(k, v)| format!("{k}={}", enc(v))).collect::<Vec<_>>().join("&");
    format!("https://{HOST}/oauth/authorize?{qs}")
}

/// `GET /sync/gitlab/start`: an admin chose Connect GitLab. Sends them to approve DumbSlab's app.
pub fn start(db: &dyn Db, cfg: &HostConfig, req: &Request) -> Outcome {
    let base = crate::http::base_url(cfg, req);
    let back = |p: Problem| redirect(settings_url(&base, "gitlab", Err(p)));
    let run = || -> ApiResult<Outcome> {
        let Some(app) = app(cfg).filter(|_| available(cfg)) else { return Ok(back(Problem::Unavailable)) };
        let verifier = crate::util::new_secret("") + &crate::util::new_secret("");
        Ok(match begin(db, cfg, req, "gitlab", Some(&verifier))? {
            Ok(state) => redirect(authorize_url(app, &redirect_uri(cfg, &base), &state, &verifier)),
            Err(p) => back(p),
        })
    };
    run().unwrap_or_else(|_| back(Problem::Failed))
}

/// `GET /sync/gitlab/callback`: GitLab sent the admin back. Answers with a job that exchanges the
/// code and keeps the approval until they pick a project.
pub fn callback(db: &dyn Db, cfg: &HostConfig, req: &Request) -> Outcome {
    let base = crate::http::base_url(cfg, req);
    let query = query_map(&req.query);
    let back = |p: Problem| redirect(settings_url(&base, "gitlab", Err(p)));
    let run = || -> ApiResult<Outcome> {
        let state = query.get("state").cloned().unwrap_or_default();
        let who = match returned(db, cfg, req, "gitlab", &state)? {
            Ok(w) => w,
            Err(p) => return Ok(back(p)),
        };
        if !available(cfg) {
            return Ok(back(Problem::Unavailable));
        }
        let code = match (query.get("code").filter(|c| !c.is_empty()), query.get("error")) {
            (Some(c), _) => c.clone(),
            (None, Some(_)) => return Ok(back(Problem::Declined)),
            (None, None) => return Ok(back(Problem::NoCode)),
        };
        let kind =
            Kind::Connect { code, verifier: who.verifier.unwrap_or_default(), redirect_uri: redirect_uri(cfg, &base), approval: None };
        let mut out = back(Problem::Failed);
        out.effects.push(Effect::Connect(Job::GitLab(Box::new(GitLabJob::new(&who.user_id, &base, kind)))));
        Ok(out)
    };
    run().unwrap_or_else(|_| back(Problem::Failed))
}

// ---------------------------------------------------------------------------
// The job

/// A source to add once its webhook is in: everything [`crate::ops::sync`] checked already.
#[derive(Clone, Debug)]
pub struct Draft {
    pub source_id: String,
    /// The project the admin picked, by id; the path (`repo`) is only for reading then.
    pub project_id: Option<i64>,
    pub repo: String,
    pub branch: Option<String>,
    pub folder: String,
    pub topic_id: String,
    pub webhook_url: String,
}

/// A source to reconnect with the admin's newest approval.
#[derive(Clone)]
pub struct Rejoin {
    pub source_id: String,
    /// The source's lease (see [`hold_source`]).
    pub lease: String,
    pub project_id: i64,
    pub hook_id: Option<i64>,
    /// Where its webhook should point: the workspace's address now.
    pub webhook_url: String,
    /// Where its webhook pointed before ([`hook_addresses`]), kept as its history.
    pub earlier: Vec<String>,
    /// The webhook's secret: the source's, or a new one when the stored one can't be read.
    pub secret: String,
}

/// Work with DumbSlab's GitLab app that needs requests to GitLab.
#[derive(Clone)]
pub struct GitLabJob {
    user_id: String,
    base_url: String,
    kind: Kind,
    phase: Phase,
    effects: Vec<Effect>,
    staged: Vec<Effect>,
    /// The last step only stored renewed tokens (see
    /// [`crate::connect::Job::wrote_only_credentials`]).
    rotated: bool,
}

#[derive(Clone)]
enum Kind {
    /// Finishing Connect GitLab: exchange the code, read whose account it is, keep the approval.
    Connect { code: String, verifier: String, redirect_uri: String, approval: Option<Pending> },
    /// The projects the admin can maintain (`list_gitlab_projects`), with their held approval.
    Projects { claim: String, approval: Option<Pending> },
    /// Adding a folder: find the project, add its webhook, then save the source with the approval.
    Create { claim: String, approval: Option<Pending>, draft: Draft, project: Option<Project>, secret: String, hook_id: Option<i64> },
    /// Reconnecting a folder: make sure its webhook is there with its secret and address, then
    /// move the approval onto it. `added` is a webhook this job had to add again.
    Reconnect { claim: String, approval: Option<Pending>, rejoin: Rejoin, added: Option<i64> },
    /// A pass taking a removed source's webhooks off its project (see [`Cleanup`]).
    Cleanup(Box<Cleanup>),
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Phase {
    Start,
    Refreshing,
    Working,
    Finishing,
}

// Carries codes and tokens; never print them.
impl std::fmt::Debug for GitLabJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self.kind {
            Kind::Connect { .. } => "connect",
            Kind::Projects { .. } => "projects",
            Kind::Create { .. } => "create",
            Kind::Reconnect { .. } => "reconnect",
            Kind::Cleanup(_) => "cleanup",
        };
        write!(f, "GitLabJob({kind}, {:?})", self.phase)
    }
}

impl GitLabJob {
    fn new(user_id: &str, base_url: &str, kind: Kind) -> GitLabJob {
        GitLabJob {
            user_id: user_id.into(),
            base_url: base_url.into(),
            kind,
            phase: Phase::Start,
            effects: vec![],
            staged: vec![],
            rotated: false,
        }
    }

    /// Lists the projects `user_id` can maintain, with the approval `claim` holds.
    pub(crate) fn projects(user_id: &str, base_url: &str, claim: String) -> GitLabJob {
        GitLabJob::new(user_id, base_url, Kind::Projects { claim, approval: None })
    }

    /// Adds a folder from a project, with the approval `claim` holds.
    pub(crate) fn create(user_id: &str, base_url: &str, claim: String, draft: Draft) -> GitLabJob {
        let secret = crate::util::new_secret("whsec_");
        GitLabJob::new(user_id, base_url, Kind::Create { claim, approval: None, draft, project: None, secret, hook_id: None })
    }

    /// Reconnects a folder with the approval `claim` holds.
    pub(crate) fn reconnect(user_id: &str, base_url: &str, claim: String, rejoin: Rejoin) -> GitLabJob {
        GitLabJob::new(user_id, base_url, Kind::Reconnect { claim, approval: None, rejoin, added: None })
    }

    /// The step that just ran only stored renewed tokens: an approval's, or a cleanup record's (see
    /// [`crate::connect::Job::wrote_only_credentials`]).
    pub(crate) fn wrote_only_credentials(&self) -> bool {
        self.rotated
    }

    pub(crate) fn take_effects(&mut self) -> Vec<Effect> {
        std::mem::take(&mut self.effects)
    }

    pub(crate) fn settle(&mut self, committed: bool) {
        let staged = std::mem::take(&mut self.staged);
        if committed {
            self.effects.extend(staged);
        }
    }

    /// Notes a webhook GitLab says it just added, before the step that saves it runs (see
    /// [`crate::connect::Job::note`]).
    pub(crate) fn note(&mut self, replies: &[HttpReply]) {
        let Some(reply) = replies.first() else { return };
        match (&mut self.kind, self.phase) {
            (Kind::Create { hook_id, .. }, Phase::Finishing) => *hook_id = read_hook(reply).ok().or(*hook_id),
            (Kind::Reconnect { added, .. }, Phase::Finishing) => *added = read_hook(reply).ok().or(*added),
            // A folder that had no webhook: the first request added one.
            (Kind::Reconnect { added, rejoin, .. }, Phase::Working) if rejoin.hook_id.is_none() => {
                *added = read_hook(reply).ok().or(*added)
            }
            _ => {}
        }
    }

    /// A step that saves a folder failed or was rolled back (say, it grew a full workspace past
    /// its storage): the webhook this job added comes off again, or GitLab would keep sending
    /// pushes for a folder that isn't here. Asked of the job as the failed step left it, which
    /// knows the webhook (see [`crate::connect::guarded_step`]).
    pub(crate) fn failure_notice(&self) -> Option<HttpCall> {
        match &self.kind {
            Kind::Create { approval: Some(a), project: Some(p), hook_id: Some(hook), .. } => {
                Some(remove_hook_call(&a.cred.token, p.id, *hook))
            }
            Kind::Reconnect { approval: Some(a), rejoin, added: Some(hook), .. } => {
                Some(remove_hook_call(&a.cred.token, rejoin.project_id, *hook))
            }
            _ => None,
        }
    }
}

/// What listing projects answers (see `ops::sync::GitLabProjects`).
pub(crate) fn projects_value(base_url: &str, account: &str, projects: &[Project], more: bool) -> Value {
    let items: Vec<Value> = projects
        .iter()
        .map(|p| json!({ "id": p.id, "path": p.path, "default_branch": p.default_branch, "visibility": p.visibility }))
        .collect();
    json!({ "available": true, "connected": true, "connect_url": format!("{base_url}{START_PATH}"), "account": account,
            "projects": items, "more": more })
}

fn failed(message: impl Into<String>) -> ApiResult<Step> {
    Ok(Step::Done(Finish::Fail(ApiError::new(400, "gitlab_failed", message.into()))))
}

fn reconnect_message() -> String {
    "Your GitLab approval can't be used any more. Choose Connect GitLab again.".into()
}

/// What a 401, 403 or 404 from GitLab means while working on a project.
fn project_error(reply: &HttpReply, path: &str) -> String {
    match reply.status {
        401 => reconnect_message(),
        403 => format!("GitLab refused: you need the Maintainer role in {path} for DumbSlab to manage its webhook."),
        404 => format!("GitLab can't find {path} for your account."),
        _ => http_error("GitLab", reply),
    }
}

/// The claim a job holds on an approval, and the approval once loaded.
fn approval_of(kind: &mut Kind) -> Option<(&str, &mut Option<Pending>)> {
    match kind {
        Kind::Projects { claim, approval } | Kind::Create { claim, approval, .. } | Kind::Reconnect { claim, approval, .. } => {
            Some((claim.as_str(), approval))
        }
        _ => None,
    }
}

/// Ends a job that holds an approval without using it up: it's free for the next request, and a
/// source being reconnected is let go.
fn give_up(db: &dyn Db, j: &GitLabJob, message: impl Into<String>) -> ApiResult<Step> {
    match &j.kind {
        Kind::Projects { claim, .. } | Kind::Create { claim, .. } => release(db, &j.user_id, claim)?,
        Kind::Reconnect { claim, rejoin, .. } => {
            release(db, &j.user_id, claim)?;
            let_go_source(db, &rejoin.source_id, &rejoin.lease)?;
        }
        _ => {}
    }
    failed(message)
}

/// Runs a GitLab job's next step (see [`crate::connect::step`]).
pub fn step(db: &dyn Db, cfg: &HostConfig, j: &mut GitLabJob, replies: Vec<HttpReply>, now: DateTime<Utc>) -> ApiResult<Step> {
    j.rotated = false;
    if matches!(j.kind, Kind::Cleanup(_)) {
        return cleanup_step(db, cfg, j, &replies, now);
    }
    let reply = replies.first().cloned().unwrap_or_default();
    let back = |base: &str, p: Problem| Ok(Step::Done(Finish::Redirect(settings_url(base, "gitlab", Err(p)))));
    let Some(app) = app(cfg) else {
        return match j.kind {
            Kind::Connect { .. } => back(&j.base_url, Problem::Unavailable),
            _ => give_up(db, j, "DumbSlab's GitLab app isn't set up on this server any more."),
        };
    };
    match (&mut j.kind, j.phase) {
        // Connecting.
        (Kind::Connect { code, verifier, redirect_uri, .. }, Phase::Start) => {
            let form = [
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", redirect_uri.as_str()),
                ("code_verifier", verifier.as_str()),
            ];
            let call = token_call(app, &form);
            j.phase = Phase::Working;
            Ok(Step::Fetch(vec![call]))
        }
        (Kind::Connect { approval, .. }, Phase::Working) => {
            let Ok(tokens) = read_tokens(&reply) else { return back(&j.base_url, Problem::Failed) };
            let expires_at = expiry(now, &tokens);
            let cred = Credential { token: tokens.access_token, refresh_token: tokens.refresh_token, ..Default::default() };
            let calls = gitlab().profile(&cred);
            *approval = Some(Pending { account: String::new(), cred, expires_at });
            j.phase = Phase::Finishing;
            Ok(Step::Fetch(calls))
        }
        (Kind::Connect { approval: Some(p), .. }, Phase::Finishing) => {
            // Whose account it is; then it waits for the admin to pick a project.
            let Ok(account) = gitlab().read_profile(&p.cred, &replies) else { return back(&j.base_url, Problem::Failed) };
            let admin = db
                .one("SELECT 1 AS ok FROM users WHERE id = ? AND role = 'admin' AND deactivated_at IS NULL", &params![j.user_id.clone()])?;
            if admin.is_none() {
                return back(&j.base_url, Problem::NotAdmin);
            }
            p.account = account.label;
            save_new(db, cfg, &j.user_id, p, now)?;
            let mut ctx = super::ctx(db, cfg, &j.user_id, &j.base_url, now)?;
            crate::events::emit(
                &mut ctx,
                crate::events::Event::new("gitlab.connected", "gitlab_connection", &j.user_id, format!("connected GitLab ({})", p.account))
                    .admin_only(),
            )?;
            j.staged.append(&mut ctx.effects);
            Ok(Step::Done(Finish::Redirect(settings_url(&j.base_url, "gitlab", Ok(())))))
        }

        // Listing projects, adding a folder and reconnecting one: with the held approval,
        // refreshed first if it's about to expire. Only this job refreshes it.
        (Kind::Projects { .. } | Kind::Create { .. } | Kind::Reconnect { .. }, Phase::Start) => {
            let user_id = j.user_id.clone();
            let (claim, approval) = approval_of(&mut j.kind).expect("holds an approval");
            let Some(p) = held(db, cfg, &user_id, claim)? else {
                // Replaced, taken, or unreadable: nothing here can use it.
                take(db, &user_id, claim)?;
                return give_up(db, j, reconnect_message());
            };
            let refresh = needs_refresh(&p.cred, p.expires_at, now).then(|| refresh_call(app, &p.cred));
            *approval = Some(p);
            if let Some(call) = refresh {
                j.phase = Phase::Refreshing;
                return Ok(Step::Fetch(vec![call]));
            }
            j.phase = Phase::Working;
            Ok(Step::Fetch(first_calls(&j.kind)))
        }
        (Kind::Projects { .. } | Kind::Create { .. } | Kind::Reconnect { .. }, Phase::Refreshing) => {
            let user_id = j.user_id.clone();
            let (claim, approval) = approval_of(&mut j.kind).expect("holds an approval");
            let claim = claim.to_string();
            let tokens = match read_refresh(&reply) {
                Ok(t) => t,
                // GitLab refused the approval itself: it's no use to anyone now.
                Err(message) if reply.status != 0 && reply.status < 500 && reply.status != 429 => {
                    take(db, &user_id, &claim)?;
                    return give_up(db, j, message);
                }
                Err(message) => return give_up(db, j, message),
            };
            let p = approval.as_mut().expect("loaded");
            p.expires_at = expiry(now, &tokens);
            apply_tokens(&mut p.cred, tokens);
            // GitLab has replaced the old tokens, so these are kept at once, in a step that stores
            // only them: a full workspace keeps it.
            if !save_held(db, cfg, &user_id, &claim, p)? {
                return give_up(db, j, reconnect_message());
            }
            j.rotated = true;
            j.phase = Phase::Working;
            Ok(Step::Fetch(first_calls(&j.kind)))
        }
        (Kind::Projects { claim, approval: Some(p) }, Phase::Working) => {
            let listed = read_projects(&replies);
            let (account, claim) = (p.account.clone(), claim.clone());
            release(db, &j.user_id, &claim)?;
            match listed {
                Ok((projects, more)) => Ok(Step::Done(Finish::Fill(projects_value(&j.base_url, &account, &projects, more)))),
                Err(_) if reply.status == 401 => failed(reconnect_message()),
                Err(message) => failed(message),
            }
        }

        // Adding a folder.
        (Kind::Create { draft, approval: Some(p), project, secret, .. }, Phase::Working) => {
            if !reply.ok() {
                let message = project_error(&reply, &draft.repo);
                return give_up(db, j, message);
            }
            // The project the admin picked, by its id, whatever its path is now; or, given only a
            // path, the project there now, whose id is kept from here on.
            let found = match draft.project_id {
                Some(id) => reply.json().as_array().and_then(|list| list.iter().filter_map(read_project).find(|p| p.id == id)),
                None => read_project(&reply.json()),
            };
            let Some(found) = found else {
                let message = match draft.project_id {
                    Some(_) => format!(
                        "GitLab no longer shows {} as a project you maintain (it was deleted, or your role changed). Choose it again.",
                        draft.repo
                    ),
                    None => "GitLab's answer had no project in it. Try again.".into(),
                };
                return give_up(db, j, message);
            };
            // Recorded before the webhook is asked for, in this step's transaction: if GitLab adds
            // it but the answer is lost, or the folder isn't saved, a cleanup finds it (see
            // `record_pending_hook`).
            let mut held = Credential { token: p.cred.token.clone(), refresh_token: p.cred.refresh_token.clone(), ..Default::default() };
            held.fields.insert("hook_url".into(), draft.webhook_url.clone());
            record_pending_hook(db, cfg, &j.user_id, &draft.source_id, &found, &held, p.expires_at, now)?;
            let call = add_hook_call(&p.cred.token, found.id, &draft.webhook_url, secret);
            *project = Some(found);
            j.phase = Phase::Finishing;
            Ok(Step::Fetch(vec![call]))
        }
        (Kind::Create { claim, draft, approval: Some(p), project: Some(found), secret, hook_id }, Phase::Finishing) => {
            let hook = match read_hook(&reply) {
                Ok(id) => id,
                Err(message) => return give_up(db, j, message),
            };
            // Known from here on: if saving fails, or the host rolls this step back, it comes off
            // again (see `GitLabJob::failure_notice`).
            *hook_id = Some(hook);
            // This folder's own cleanup record (see `record_pending_hook`) goes with the save, in
            // its transaction, only if no cleanup pass ever claimed it: one that did may have
            // deleted this webhook already. Then nothing is saved, and the admin tries again.
            let mine = db.execute(
                "DELETE FROM docs_hook_cleanup WHERE source_id = ? AND working_until IS NULL AND failures = 0",
                &params![draft.source_id.clone()],
            )? == 1;
            if !mine {
                return give_up(db, j, "Adding the folder took so long that DumbSlab took its webhook off GitLab again. Try again.");
            }
            let mut cred = p.cred.clone();
            cred.fields.insert("webhook_secret".into(), secret.clone());
            cred.fields.insert("hook_url".into(), draft.webhook_url.clone());
            let link = super::docs::Link::GitLabOAuth { project_id: found.id, hook_id: Some(hook), token_expires_at: p.expires_at.map(ts) };
            let mut ctx = super::ctx(db, cfg, &j.user_id, &j.base_url, now)?;
            if ctx.actor.user_id != j.user_id {
                return Err(ApiError::forbidden("only an admin can add a folder"));
            }
            let fresh = super::docs::NewSource {
                id: draft.source_id.clone(),
                provider: super::repo::Provider::GitLab,
                host: HOST.into(),
                repo: found.path.clone(),
                branch: draft.branch.clone().or_else(|| found.default_branch.clone()).unwrap_or_else(|| "main".into()),
                folder: draft.folder.clone(),
                topic_id: draft.topic_id.clone(),
            };
            // Checked again: the topic and other sources may have changed meanwhile.
            crate::ops::sync::insert_source(&mut ctx, &fresh, &cred, &link)?;
            // The approval moves to the source, unless another request replaced it meanwhile.
            if !take(db, &j.user_id, claim)? {
                return Err(ApiError::conflict("Your GitLab approval changed while the folder was being added. Try again."));
            }
            lend_to_source(db, &j.user_id, &draft.source_id)?;
            let created = crate::ops::sync::created_value(&ctx, &draft.source_id)?;
            j.staged.append(&mut ctx.effects);
            Ok(Step::Done(Finish::Fill(created)))
        }

        // Reconnecting a folder: its webhook first (pointed at the workspace's address now, with the
        // folder's secret), then the approval.
        (Kind::Reconnect { approval: Some(p), rejoin, added, .. }, Phase::Working) => match rejoin.hook_id {
            // It had none, so this was adding one.
            None => match read_hook(&reply) {
                Ok(id) => {
                    *added = Some(id);
                    finish_reconnect(db, cfg, j, now)
                }
                Err(message) => give_up(db, j, message),
            },
            Some(_) if reply.ok() => finish_reconnect(db, cfg, j, now),
            // Someone deleted it on GitLab: add it again.
            Some(_) if reply.status == 404 => {
                let call = add_hook_call(&p.cred.token, rejoin.project_id, &rejoin.webhook_url, &rejoin.secret);
                j.phase = Phase::Finishing;
                Ok(Step::Fetch(vec![call]))
            }
            Some(_) => {
                let message = project_error(&reply, "the project");
                give_up(db, j, message)
            }
        },
        (Kind::Reconnect { added, .. }, Phase::Finishing) => match read_hook(&reply) {
            Ok(id) => {
                *added = Some(id);
                finish_reconnect(db, cfg, j, now)
            }
            Err(message) => give_up(db, j, message),
        },

        _ => Err(ApiError::internal("a GitLab job got out of step")),
    }
}

/// Saves a reconnected folder: the approval's tokens and the webhook's secret, sealed to it; its
/// webhook; and it can sync again. Then lets it go.
fn finish_reconnect(db: &dyn Db, cfg: &HostConfig, j: &mut GitLabJob, now: DateTime<Utc>) -> ApiResult<Step> {
    let Kind::Reconnect { claim, approval: Some(p), rejoin, added } = &j.kind else { return Err(ApiError::internal("not reconnecting")) };
    let mut cred = p.cred.clone();
    cred.fields.insert("webhook_secret".into(), rejoin.secret.clone());
    set_hook_url(&mut cred, &rejoin.webhook_url, &rejoin.earlier);
    let sealed = super::seal(cfg, &super::docs::owner(&rejoin.source_id), "gitlab", &cred)?;
    let saved = db.execute(
        "UPDATE docs_sources SET secret = ?, running_until = NULL, updated_at = ? WHERE id = ? AND running_until = ?",
        &params![sealed, ts(now), rejoin.source_id.clone(), rejoin.lease.clone()],
    )?;
    if saved == 0 {
        return Err(ApiError::conflict("The folder changed while it was being reconnected. Try again."));
    }
    db.execute(
        "UPDATE docs_source_links SET token_expires_at = ?, hook_id = ?, disconnected = NULL, refreshing = NULL WHERE source_id = ?",
        &params![p.expires_at.map(ts), added.or(rejoin.hook_id), rejoin.source_id.clone()],
    )?;
    if !take(db, &j.user_id, claim)? {
        return Err(ApiError::conflict("Your GitLab approval changed while the folder was being reconnected. Try again."));
    }
    lend_to_source(db, &j.user_id, &rejoin.source_id)?;
    let mut ctx = super::ctx(db, cfg, &j.user_id, &j.base_url, now)?;
    let repo = db
        .one("SELECT repo FROM docs_sources WHERE id = ?", &params![rejoin.source_id.clone()])?
        .map(|r| r.str("repo"))
        .unwrap_or_default();
    crate::events::emit(
        &mut ctx,
        crate::events::Event::new("docs_source.updated", "docs_source", &rejoin.source_id, format!("reconnected docs sync from {repo}"))
            .admin_only(),
    )?;
    let created = crate::ops::sync::created_value(&ctx, &rejoin.source_id)?;
    j.staged.append(&mut ctx.effects);
    Ok(Step::Done(Finish::Fill(created)))
}

/// What a job holding an approval asks GitLab first, once its token is fresh.
fn first_calls(kind: &Kind) -> Vec<HttpCall> {
    match kind {
        Kind::Projects { approval: Some(p), .. } => project_calls(&p.cred.token),
        Kind::Create { approval: Some(p), draft, .. } => match draft.project_id {
            Some(id) => vec![maintained_project_call(&p.cred.token, id)],
            None => vec![project_call(&p.cred.token, &draft.repo)],
        },
        Kind::Reconnect { approval: Some(p), rejoin, .. } => match rejoin.hook_id {
            Some(hook) => vec![edit_hook_call(&p.cred.token, rejoin.project_id, hook, &rejoin.webhook_url, &rejoin.secret)],
            None => vec![add_hook_call(&p.cred.token, rejoin.project_id, &rejoin.webhook_url, &rejoin.secret)],
        },
        _ => vec![],
    }
}

// ---------------------------------------------------------------------------
// Removed folders' webhooks

/// How long DumbSlab keeps trying, with tokens that only ever fail for a while, to take a removed
/// folder's webhooks off its project.
pub(crate) const CLEANUP_RETENTION_DAYS: i64 = 30;
/// Records one trigger starts passes on.
const CLEANUP_BATCH: i64 = 5;
/// How long one pass may hold a record before another may take it.
const CLEANUP_LEASE_SECS: i64 = 90;
/// The wait after the first failed pass; it doubles after each one, up to a day.
const CLEANUP_FIRST_WAIT_SECS: i64 = 60;
const CLEANUP_MAX_WAIT_SECS: i64 = 24 * 3600;

/// What a cleanup record's tokens are sealed to: that record alone.
fn cleanup_owner(source_id: &str) -> String {
    format!("docs-hook-cleanup:{source_id}")
}

/// A removed GitLab app folder's webhooks, still to take off its project (`docs_hook_cleanup`), as
/// one pass works on them.
///
/// - Removing the folder records them, with its tokens and every address its webhook had, in the
///   same transaction that deletes it; a pass starts at once. Removal waits while a refresh of the
///   folder's tokens may still land (see `ops::sync::remove_sources`), so the tokens recorded are
///   the newest.
/// - A pass renews the tokens if they're about to expire, saving the new ones first (GitLab has
///   spent the old refresh token). It lists the project's webhooks and deletes every one that
///   posts to exactly this folder's `/hooks/docs/<id>` at one of those addresses ([`points_at`]),
///   and the one recorded. Then it drops the record.
/// - A pass that fails (timeouts, 429, 5xx) lets go and waits longer each time (a minute,
///   doubling up to a day). Passes start when a folder is removed, when Settings › Docs sync
///   loads, and with Sync now.
/// - DumbSlab gives up only when GitLab definitely won't let it (it refuses to renew the same
///   tokens twice, answers 401 or 403, or no longer shows the project), or after
///   [`CLEANUP_RETENTION_DAYS`]. Then it says so in the activity log, for admins, with the
///   project and the webhook ids, so they can delete them by hand, and drops the tokens.
#[derive(Clone)]
pub struct Cleanup {
    source_id: String,
    lease: String,
    project_id: i64,
    repo: String,
    known: Vec<i64>,
    cred: Credential,
    expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    /// The refresh token this pass spent, until its answer is in.
    spent: Option<String>,
    /// The webhooks this pass is deleting.
    deleting: Vec<i64>,
    /// A folder being added: whose approval the tokens are borrowed from (see
    /// [`record_pending_hook`]).
    borrowed_from: Option<String>,
    /// That approval, while this pass holds it (its claim) to use its tokens.
    approval: Option<(String, Pending)>,
    /// The folder the approval moved onto since (see [`lend_to_source`]).
    borrowed_source: Option<String>,
    /// That folder and its lease, while this pass holds it like a sync to use its tokens.
    source_lease: Option<(String, String)>,
}

/// An approval moved onto a folder (in the same transaction): cleanup records that borrowed its
/// tokens now borrow that folder's instead (see [`record_pending_hook`]), so they're never left
/// with tokens nobody can renew for them.
fn lend_to_source(db: &dyn Db, user_id: &str, source_id: &str) -> ApiResult<()> {
    db.execute(
        "UPDATE docs_hook_cleanup SET borrowed_source = ? WHERE borrowed_from = ? AND borrowed_source IS NULL AND source_id != ?",
        &params![source_id, user_id, source_id],
    )?;
    Ok(())
}

/// A GitLab app folder's tokens as stored, and when its access token expires.
fn source_tokens(db: &dyn Db, cfg: &HostConfig, source_id: &str) -> ApiResult<Option<(Credential, Option<DateTime<Utc>>)>> {
    let Some(r) = db.one(
        "SELECT s.secret, l.token_expires_at FROM docs_sources s JOIN docs_source_links l ON l.source_id = s.id
         WHERE s.id = ? AND l.connection = 'gitlab_oauth'",
        &params![source_id],
    )?
    else {
        return Ok(None);
    };
    Ok(super::open(cfg, &super::docs::owner(source_id), "gitlab", &r.str("secret"))
        .ok()
        .map(|cred| (cred, r.opt_str("token_expires_at").as_deref().and_then(parse_ts))))
}

/// A renewal of a folder's tokens that a cleanup pass made got its answer: GitLab spent the old
/// refresh token, so the new tokens are kept if the folder still has the spent one (only its token
/// fields change), as a sync keeps its own (see `docs::refreshed`). Otherwise newer ones landed
/// meanwhile, and those are used. The folder's tokens as they are now.
fn keep_renewed(
    db: &dyn Db,
    cfg: &HostConfig,
    source_id: &str,
    spent: &str,
    tokens: TokenSet,
    now: DateTime<Utc>,
) -> ApiResult<Option<Credential>> {
    let Some((mut stored, _)) = source_tokens(db, cfg, source_id)? else { return Ok(None) };
    if stored.refresh_token.as_deref() == Some(spent) {
        let expires_at = expiry(now, &tokens).map(ts);
        apply_tokens(&mut stored, tokens);
        let sealed = super::seal(cfg, &super::docs::owner(source_id), "gitlab", &stored)?;
        db.execute("UPDATE docs_sources SET secret = ?, updated_at = ? WHERE id = ?", &params![sealed, ts(now), source_id])?;
        db.execute(
            "UPDATE docs_source_links SET token_expires_at = ?, refreshing = NULL WHERE source_id = ?",
            &params![expires_at, source_id],
        )?;
    }
    Ok(Some(stored))
}

/// How long a folder being added has to save itself before its webhook counts as left behind. An
/// add takes a few steps of seconds each; this is far longer.
const PENDING_GRACE_SECS: i64 = 600;

/// Before a new folder's webhook is asked for, in the step whose transaction commits before the
/// request goes out: if GitLab adds the webhook but its answer is lost, or the folder then isn't
/// saved, that webhook would post to a folder that never existed, which no Sync now looks after.
/// So the intent is recorded first, as a cleanup record (see [`Cleanup`]) with the webhook's exact
/// address, and the step that saves the folder drops it. Left behind, a pass finds the webhook
/// by that address and deletes it, after [`PENDING_GRACE_SECS`] (the add may still be under way).
///
/// Its tokens are a copy of the admin's approval's, which may live on (another try uses it) or
/// move to a folder. So a pass never renews them: it uses them while they last, and then the
/// approval itself, held like any request ([`claim`]) and renewed its own way. GitLab takes each
/// refresh token once, and only its holder spends it.
#[allow(clippy::too_many_arguments)]
pub(crate) fn record_pending_hook(
    db: &dyn Db,
    cfg: &HostConfig,
    user_id: &str,
    source_id: &str,
    project: &Project,
    cred: &Credential,
    expires_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> ApiResult<()> {
    let secret = super::seal(cfg, &cleanup_owner(source_id), "gitlab", cred)?;
    db.execute(
        "INSERT INTO docs_hook_cleanup (source_id, project_id, repo, known_ids, secret, expires_at, refresh_hash, removed_by, borrowed_from,
           next_attempt_at, created_at)
         VALUES (?, ?, ?, '', ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(source_id) DO NOTHING",
        &params![
            source_id,
            project.id,
            project.path.clone(),
            secret,
            expires_at.map(ts),
            cred.refresh_token.as_deref().map(crate::util::sha256_hex),
            user_id,
            user_id,
            ts(now + Duration::seconds(PENDING_GRACE_SECS)),
            ts(now)
        ],
    )?;
    Ok(())
}

/// Records a removed GitLab app folder's webhooks for cleanup (see [`Cleanup`]): its project, the
/// webhook it knows, and its tokens with the addresses its webhook had (and the workspace's address
/// now, when the server knows it), sealed to the record. The admin removing it owns the record.
pub(crate) fn record_cleanup(
    ctx: &crate::registry::Ctx,
    source: &super::docs::Source,
    project_id: i64,
    hook_id: Option<i64>,
    expires_at: Option<&str>,
) -> ApiResult<()> {
    let mut cred = source.cred.clone();
    let current = ctx.cfg.knows_its_address().then(|| ctx.url(&format!("/hooks/docs/{}", source.id)));
    let addresses = hook_addresses(&cred, current.as_deref());
    cred.fields.insert("hook_urls".into(), addresses.join("\n"));
    let secret = super::seal(ctx.cfg, &cleanup_owner(&source.id), "gitlab", &cred)?;
    // (A record left from adding it, if any, gives way to this one: these are the folder's own.)
    ctx.db.execute(
        "INSERT INTO docs_hook_cleanup (source_id, project_id, repo, known_ids, secret, expires_at, refresh_hash, removed_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(source_id) DO UPDATE SET project_id = excluded.project_id, repo = excluded.repo, known_ids = excluded.known_ids,
           secret = excluded.secret, expires_at = excluded.expires_at, refresh_hash = excluded.refresh_hash, refused = 0, failures = 0,
           next_attempt_at = NULL, removed_by = excluded.removed_by, borrowed_from = NULL, created_at = excluded.created_at",
        &params![
            source.id.clone(),
            project_id,
            source.repo.repo.clone(),
            hook_id.map(|h| h.to_string()).unwrap_or_default(),
            secret,
            expires_at,
            cred.refresh_token.as_deref().map(crate::util::sha256_hex),
            ctx.actor.user_id.clone(),
            ctx.now_s()
        ],
    )?;
    Ok(())
}

/// Starts passes on removed folders' webhooks that are due, a few at a time (see [`Cleanup`]).
pub(crate) fn resume_cleanups(db: &dyn Db, cfg: &HostConfig, base_url: &str, now: DateTime<Utc>) -> ApiResult<Vec<Job>> {
    let due = db.query(
        "SELECT * FROM docs_hook_cleanup WHERE (next_attempt_at IS NULL OR next_attempt_at <= ?)
           AND (working_until IS NULL OR working_until <= ?) ORDER BY created_at LIMIT ?",
        &params![ts(now), ts(now), CLEANUP_BATCH],
    )?;
    let mut jobs = vec![];
    for r in due {
        let source_id = r.str("source_id");
        let lease = format!("{} {}", ts(now + Duration::seconds(CLEANUP_LEASE_SECS)), crate::util::new_id());
        let claimed = db.execute(
            "UPDATE docs_hook_cleanup SET working_until = ? WHERE source_id = ? AND (working_until IS NULL OR working_until <= ?)",
            &params![lease.clone(), source_id.clone(), ts(now)],
        )? > 0;
        if !claimed {
            continue;
        }
        let known: Vec<i64> = r.str("known_ids").split(',').filter_map(|i| i.parse().ok()).collect();
        let mut c = Cleanup {
            source_id: source_id.clone(),
            lease,
            project_id: r.i64("project_id"),
            repo: r.str("repo"),
            known,
            cred: Credential::default(),
            expires_at: r.opt_str("expires_at").as_deref().and_then(parse_ts),
            created_at: parse_ts(&r.str("created_at")).unwrap_or(now),
            spent: None,
            deleting: vec![],
            borrowed_from: r.opt_str("borrowed_from"),
            approval: None,
            borrowed_source: r.opt_str("borrowed_source"),
            source_lease: None,
        };
        match super::open(cfg, &cleanup_owner(&source_id), "gitlab", &r.str("secret")) {
            Ok(cred) => c.cred = cred,
            Err(_) => {
                let why = "its saved GitLab access can't be read (the server's connector key changed)";
                abandon(db, cfg, base_url, &r.str("removed_by"), &c, why, now)?;
                continue;
            }
        }
        jobs.push(Job::GitLab(Box::new(GitLabJob::new(&r.str("removed_by"), base_url, Kind::Cleanup(Box::new(c))))));
    }
    Ok(jobs)
}

/// Whether the pass still holds its record.
fn holds_cleanup(db: &dyn Db, c: &Cleanup) -> ApiResult<bool> {
    Ok(db
        .one(
            "SELECT 1 AS ok FROM docs_hook_cleanup WHERE source_id = ? AND working_until = ?",
            &params![c.source_id.clone(), c.lease.clone()],
        )?
        .is_some())
}

/// Says in the activity log, for admins, that DumbSlab gave up on a removed folder's webhooks, with
/// the project and the webhook ids it knows, and drops the record and its tokens.
fn abandon(db: &dyn Db, cfg: &HostConfig, base_url: &str, removed_by: &str, c: &Cleanup, why: &str, now: DateTime<Utc>) -> ApiResult<()> {
    db.execute("DELETE FROM docs_hook_cleanup WHERE source_id = ? AND working_until = ?", &params![c.source_id.clone(), c.lease.clone()])?;
    let mut ids: Vec<i64> = c.known.iter().chain(&c.deleting).copied().collect();
    ids.sort_unstable();
    ids.dedup();
    let hooks = match ids.as_slice() {
        [] => format!("the webhooks posting to …/hooks/docs/{}", c.source_id),
        [one] => format!("webhook {one}"),
        many => format!("webhooks {}", many.iter().map(i64::to_string).collect::<Vec<_>>().join(", ")),
    };
    let after =
        if c.borrowed_from.is_some() { "after adding a docs sync folder didn't finish" } else { "after removing a docs sync folder" };
    let summary = format!(
        "couldn't take DumbSlab's {hooks} off the GitLab project {} (id {}) {after}: {why}. Delete them in the project's Settings › Webhooks",
        c.repo, c.project_id
    );
    let mut ctx = super::ctx(db, cfg, removed_by, base_url, now)?;
    crate::events::emit(
        &mut ctx,
        crate::events::Event::new("docs_source.webhook_abandoned", "docs_source", &c.source_id, summary)
            .admin_only()
            .data(json!({ "project_id": c.project_id, "hook_ids": ids })),
    )?;
    Ok(())
}

/// A pass that failed lets go, keeps the webhooks it knows, and waits longer before the next.
fn back_off(db: &dyn Db, c: &Cleanup, message: String, now: DateTime<Utc>) -> ApiResult<Step> {
    if let Some(r) = db.one(
        "SELECT failures FROM docs_hook_cleanup WHERE source_id = ? AND working_until = ?",
        &params![c.source_id.clone(), c.lease.clone()],
    )? {
        let failures = r.i64("failures").clamp(0, 20) as u32;
        let wait = (CLEANUP_FIRST_WAIT_SECS << failures.min(12)).min(CLEANUP_MAX_WAIT_SECS);
        let mut known: Vec<i64> = c.known.iter().chain(&c.deleting).copied().collect();
        known.sort_unstable();
        known.dedup();
        let known = known.iter().map(i64::to_string).collect::<Vec<_>>().join(",");
        db.execute(
            "UPDATE docs_hook_cleanup SET failures = failures + 1, next_attempt_at = ?, working_until = NULL, known_ids = ?
             WHERE source_id = ? AND working_until = ?",
            &params![ts(now + Duration::seconds(wait)), known, c.source_id.clone(), c.lease.clone()],
        )?;
    }
    Ok(Step::Done(Finish::Fail(ApiError::new(502, "gitlab_failed", message))))
}

fn cleaned(removed: usize) -> ApiResult<Step> {
    Ok(Step::Done(Finish::Fill(json!({ "ok": true, "removed": removed }))))
}

/// Runs a cleanup pass's next step (see [`Cleanup`]). A pass that's done lets go of the approval or
/// folder it held.
fn cleanup_step(db: &dyn Db, cfg: &HostConfig, j: &mut GitLabJob, replies: &[HttpReply], now: DateTime<Utc>) -> ApiResult<Step> {
    let step = cleanup_pass(db, cfg, j, replies, now)?;
    if let (Step::Done(_), Kind::Cleanup(c)) = (&step, &mut j.kind) {
        if let (Some((claim, _)), Some(user)) = (c.approval.take(), c.borrowed_from.as_deref()) {
            release(db, user, &claim)?;
        }
        if let Some((source, lease)) = c.source_lease.take() {
            db.execute(
                "UPDATE docs_source_links SET refreshing = NULL WHERE source_id = ? AND refreshing LIKE ?",
                &params![source.clone(), format!("%|{lease}|%")],
            )?;
            let_go_source(db, &source, &lease)?;
        }
    }
    Ok(step)
}

fn cleanup_pass(db: &dyn Db, cfg: &HostConfig, j: &mut GitLabJob, replies: &[HttpReply], now: DateTime<Utc>) -> ApiResult<Step> {
    let (base_url, removed_by, phase) = (j.base_url.clone(), j.user_id.clone(), j.phase);
    let Kind::Cleanup(c) = &mut j.kind else { return Err(ApiError::internal("not a cleanup")) };
    let reply = replies.first().cloned().unwrap_or_default();
    // Another pass took over (this one took too long): it's that one's now.
    if !holds_cleanup(db, c)? && phase != Phase::Refreshing {
        return cleaned(0);
    }
    let give_up = |c: &Cleanup, why: &str| -> ApiResult<Step> {
        abandon(db, cfg, &base_url, &removed_by, c, why, now)?;
        Ok(Step::Done(Finish::Fail(ApiError::new(400, "gitlab_failed", why.to_string()))))
    };
    match phase {
        Phase::Start => {
            // A folder being added that was saved after all: its webhook is its own.
            if db.one("SELECT 1 AS ok FROM docs_sources WHERE id = ?", &params![c.source_id.clone()])?.is_some() {
                db.execute(
                    "DELETE FROM docs_hook_cleanup WHERE source_id = ? AND working_until = ?",
                    &params![c.source_id.clone(), c.lease.clone()],
                )?;
                return cleaned(0);
            }
            if now - c.created_at > Duration::days(CLEANUP_RETENTION_DAYS) {
                return give_up(c, &format!("DumbSlab tried for {CLEANUP_RETENTION_DAYS} days"));
            }
            // Borrowed tokens that expired, from an approval that moved onto a folder since: that
            // folder's, held like a sync holds it (see `lend_to_source`), renewed its way if need
            // be: fenced on the refresh token it spends, as a sync's renewal is.
            if c.borrowed_from.is_some()
                && needs_refresh(&c.cred, c.expires_at, now)
                && let Some(source) = c.borrowed_source.clone()
                && let Some((cred, expires_at)) = source_tokens(db, cfg, &source)?
            {
                let Some(lease) = hold_source(db, &source, now)? else {
                    return back_off(db, c, "The folder whose GitLab access it borrows is syncing. Trying again later.".into(), now);
                };
                c.source_lease = Some((source.clone(), lease.clone()));
                if !needs_refresh(&cred, expires_at, now) {
                    c.cred.token = cred.token;
                    j.phase = Phase::Working;
                    return Ok(Step::Fetch(list_hooks_calls(&c.cred.token, c.project_id)));
                }
                let spent = cred.refresh_token.clone().unwrap_or_default();
                if super::docs::renewing(db, &source, &spent, now)? {
                    return back_off(db, c, "The folder's GitLab access is being renewed. Trying again later.".into(), now);
                }
                let Some(app) = app(cfg) else { return back_off(db, c, "DumbSlab's GitLab app isn't set up on this server.".into(), now) };
                db.execute(
                    "UPDATE docs_source_links SET refreshing = ? WHERE source_id = ?",
                    &params![format!("{}|{lease}|{}", ts(now), crate::util::sha256_hex(&spent)), source.clone()],
                )?;
                c.spent = Some(spent);
                j.phase = Phase::Refreshing;
                return Ok(Step::Fetch(vec![refresh_call(app, &cred)]));
            }
            // Borrowed tokens that expired: the approval they came from, held like any request
            // (see `record_pending_hook`), renewed its own way if need be.
            if let Some(user) = c.borrowed_from.clone()
                && needs_refresh(&c.cred, c.expires_at, now)
            {
                let claim = match claim(db, &user, now) {
                    Ok(Some(claim)) => claim,
                    Ok(None) => {
                        let why = "the tokens DumbSlab kept expired, and the admin has no approval of DumbSlab's GitLab app to use instead (Connect GitLab lets it try again)";
                        return back_off(db, c, why.into(), now);
                    }
                    Err(e) => return back_off(db, c, e.message, now),
                };
                let Some(p) = held(db, cfg, &user, &claim)? else {
                    release(db, &user, &claim)?;
                    return back_off(db, c, reconnect_message(), now);
                };
                c.cred.token = p.cred.token.clone();
                let refresh = needs_refresh(&p.cred, p.expires_at, now).then(|| app(cfg).map(|a| refresh_call(a, &p.cred)));
                c.approval = Some((claim, p));
                match refresh {
                    None => {}
                    Some(None) => return back_off(db, c, "DumbSlab's GitLab app isn't set up on this server.".into(), now),
                    Some(Some(call)) => {
                        j.phase = Phase::Refreshing;
                        return Ok(Step::Fetch(vec![call]));
                    }
                }
                j.phase = Phase::Working;
                return Ok(Step::Fetch(list_hooks_calls(&c.cred.token, c.project_id)));
            }
            if needs_refresh(&c.cred, c.expires_at, now) {
                let Some(app) = app(cfg) else { return back_off(db, c, "DumbSlab's GitLab app isn't set up on this server.".into(), now) };
                c.spent = c.cred.refresh_token.clone();
                j.phase = Phase::Refreshing;
                return Ok(Step::Fetch(vec![refresh_call(app, &c.cred)]));
            }
            j.phase = Phase::Working;
            Ok(Step::Fetch(list_hooks_calls(&c.cred.token, c.project_id)))
        }
        // The borrowed folder's renewal: kept in the folder if it still has the spent token; the pass
        // uses the folder's tokens as they are then.
        Phase::Refreshing if c.source_lease.is_some() => {
            let (source, _) = c.source_lease.clone().expect("held");
            let spent = c.spent.take().unwrap_or_default();
            let tokens = match read_refresh(&reply) {
                Ok(tokens) => tokens,
                Err(message) => return back_off(db, c, message, now),
            };
            let current = keep_renewed(db, cfg, &source, &spent, tokens, now)?;
            // This step stored only the folder's renewed tokens: a full workspace keeps it.
            j.rotated = true;
            let Some(current) = current else { return cleaned(0) };
            c.cred.token = current.token;
            if !holds_cleanup(db, c)? {
                return cleaned(0);
            }
            j.phase = Phase::Working;
            Ok(Step::Fetch(list_hooks_calls(&c.cred.token, c.project_id)))
        }
        // The approval's renewal: kept in the approval, as any request would (`save_held`); the
        // pass uses the new access token.
        Phase::Refreshing if c.approval.is_some() => {
            let user = c.borrowed_from.clone().unwrap_or_default();
            let (claim, mut p) = c.approval.take().expect("held");
            let tokens = match read_refresh(&reply) {
                Ok(tokens) => tokens,
                Err(message) => {
                    release(db, &user, &claim)?;
                    return back_off(db, c, message, now);
                }
            };
            p.expires_at = expiry(now, &tokens);
            apply_tokens(&mut p.cred, tokens);
            let saved = save_held(db, cfg, &user, &claim, &p)?;
            // This step stored only the approval's renewed tokens: a full workspace keeps it.
            j.rotated = true;
            c.cred.token = p.cred.token.clone();
            c.approval = Some((claim, p));
            if !saved || !holds_cleanup(db, c)? {
                return cleaned(0);
            }
            j.phase = Phase::Working;
            Ok(Step::Fetch(list_hooks_calls(&c.cred.token, c.project_id)))
        }
        Phase::Refreshing => {
            let hash = crate::util::sha256_hex(&c.spent.take().unwrap_or_default());
            match read_refresh(&reply) {
                // GitLab spent the old refresh token, so the new tokens are kept whether or not this
                // pass still holds the record, as long as it still has the tokens that were spent.
                Ok(tokens) => {
                    c.expires_at = expiry(now, &tokens);
                    apply_tokens(&mut c.cred, tokens);
                    let sealed = super::seal(cfg, &cleanup_owner(&c.source_id), "gitlab", &c.cred)?;
                    let saved = db.execute(
                        "UPDATE docs_hook_cleanup SET secret = ?, expires_at = ?, refresh_hash = ?, refused = 0 WHERE source_id = ? AND refresh_hash = ?",
                        &params![
                            sealed,
                            c.expires_at.map(ts),
                            c.cred.refresh_token.as_deref().map(crate::util::sha256_hex),
                            c.source_id.clone(),
                            hash
                        ],
                    )? > 0;
                    // This step stored only the renewed tokens: a full workspace keeps it.
                    j.rotated = true;
                    if !saved || !holds_cleanup(db, c)? {
                        return cleaned(0);
                    }
                    j.phase = Phase::Working;
                    Ok(Step::Fetch(list_hooks_calls(&c.cred.token, c.project_id)))
                }
                Err(message) => {
                    if !holds_cleanup(db, c)? {
                        return cleaned(0);
                    }
                    let refused = reply.status != 0 && reply.status < 500 && reply.status != 429;
                    if !refused {
                        return back_off(db, c, message, now);
                    }
                    // The second refusal of the same tokens ends it: the first may have been of a
                    // renewal whose answer, with new tokens, was still on its way.
                    let again = db
                        .one(
                            "SELECT 1 AS ok FROM docs_hook_cleanup WHERE source_id = ? AND refused = 1 AND refresh_hash = ?",
                            &params![c.source_id.clone(), hash.clone()],
                        )?
                        .is_some();
                    if again {
                        return give_up(c, "GitLab no longer accepts DumbSlab's access to the project");
                    }
                    db.execute(
                        "UPDATE docs_hook_cleanup SET refused = 1 WHERE source_id = ? AND refresh_hash = ?",
                        &params![c.source_id.clone(), hash],
                    )?;
                    back_off(db, c, message, now)
                }
            }
        }
        Phase::Working => {
            if let Some(bad) = replies.iter().find(|r| !r.ok()) {
                return match bad.status {
                    401 => give_up(c, "GitLab no longer accepts DumbSlab's access to the project"),
                    403 => give_up(c, "the person who connected the folder can no longer manage the project's webhooks"),
                    404 => give_up(
                        c,
                        "GitLab no longer shows DumbSlab the project (it was deleted, or the person who connected the folder lost access)",
                    ),
                    _ => back_off(db, c, http_error("GitLab", bad), now),
                };
            }
            let trusted = hook_addresses(&c.cred, None);
            let mut ids = source_hooks(replies, &c.source_id, &trusted).unwrap_or_default();
            ids.extend(c.known.iter().copied());
            ids.sort_unstable();
            ids.dedup();
            if ids.is_empty() {
                db.execute(
                    "DELETE FROM docs_hook_cleanup WHERE source_id = ? AND working_until = ?",
                    &params![c.source_id.clone(), c.lease.clone()],
                )?;
                return cleaned(0);
            }
            c.deleting = ids;
            j.phase = Phase::Finishing;
            Ok(Step::Fetch(c.deleting.iter().map(|id| remove_hook_call(&c.cred.token, c.project_id, *id)).collect()))
        }
        Phase::Finishing => {
            let deleting = std::mem::take(&mut c.deleting);
            let left: Vec<(i64, u16)> = deleting
                .iter()
                .zip(replies.iter().map(|r| r.status).chain(std::iter::repeat(0)))
                .filter(|(_, status)| !((200..300).contains(status) || *status == 404))
                .map(|(id, status)| (*id, status))
                .collect();
            if left.is_empty() {
                db.execute(
                    "DELETE FROM docs_hook_cleanup WHERE source_id = ? AND working_until = ?",
                    &params![c.source_id.clone(), c.lease.clone()],
                )?;
                return cleaned(deleting.len());
            }
            c.known = left.iter().map(|(id, _)| *id).collect();
            if left.iter().any(|(_, status)| matches!(status, 401 | 403)) {
                return give_up(c, "GitLab refused to let DumbSlab delete them");
            }
            back_off(db, c, format!("GitLab didn't delete {} of the folder's webhooks just now.", left.len()), now)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> OAuthApp {
        OAuthApp { client_id: "gl-client".into(), client_secret: "gl-secret".into() }
    }

    #[test]
    fn a_folders_webhooks_are_only_those_at_its_own_addresses() {
        let trusted = vec!["https://kb.test/hooks/docs/s1".to_string(), "https://old.test/wiki/hooks/docs/s1".into()];
        for ours in ["https://kb.test/hooks/docs/s1", "HTTPS://KB.test:443/hooks/docs/s1", "https://old.test/wiki/hooks/docs/s1"] {
            assert!(points_at(ours, "s1", &trusted), "{ours}");
        }
        for theirs in [
            "https://unrelated.example/custom/hooks/docs/s1?mode=other",
            "https://unrelated.example/hooks/docs/s1",
            "https://kb.test/custom/hooks/docs/s1",
            "https://kb.test/hooks/docs/s1?mode=other",
            "https://kb.test/hooks/docs/s1#x",
            "https://someone@kb.test/hooks/docs/s1",
            "http://kb.test/hooks/docs/s1",
            "https://kb.test:8443/hooks/docs/s1",
            "https://kb.test/hooks/docs/s1/",
            "https://kb.test/hooks/docs/s2",
        ] {
            assert!(!points_at(theirs, "s1", &trusted), "{theirs}");
        }
        assert!(!points_at("https://kb.test/hooks/docs/s1", "s1", &[]), "no address is trusted by default");

        // Each address the webhook had stays trusted, the latest 10.
        let mut cred = Credential::default();
        set_hook_url(&mut cred, "https://a.test/hooks/docs/s1", &[]);
        set_hook_url(&mut cred, "https://b.test/hooks/docs/s1", &[]);
        assert_eq!(
            hook_addresses(&cred, Some("https://c.test/hooks/docs/s1")),
            ["https://c.test/hooks/docs/s1", "https://b.test/hooks/docs/s1", "https://a.test/hooks/docs/s1"]
        );
        for i in 0..20 {
            set_hook_url(&mut cred, &format!("https://w{i}.test/hooks/docs/s1"), &[]);
        }
        assert_eq!(cred.field("hook_urls").lines().count(), HOOK_HISTORY);
        assert_eq!(cred.field("hook_url"), "https://w19.test/hooks/docs/s1");
        assert!(cred.field("hook_urls").lines().last() == Some("https://w18.test/hooks/docs/s1"));
    }

    #[test]
    fn approvals_ask_for_the_api_scope_with_pkce() {
        let url = authorize_url(&app(), "https://dumbslab.com/sync/gitlab/callback", "acme.s1", "v");
        assert!(
            url.starts_with(
                "https://gitlab.com/oauth/authorize?client_id=gl-client&redirect_uri=https%3A%2F%2Fdumbslab.com%2Fsync%2Fgitlab%2Fcallback"
            ),
            "{url}"
        );
        assert!(url.contains("&state=acme.s1&scope=api&") && url.contains(&format!("code_challenge={}", pkce_challenge("v"))));
        let hosted = HostConfig {
            connectors: connect::Connectors { callback_url: Some("https://dumbslab.com/connect/callback".into()), ..Default::default() },
            ..Default::default()
        };
        assert_eq!(redirect_uri(&hosted, "https://acme.dumbslab.com"), "https://dumbslab.com/sync/gitlab/callback");
        assert_eq!(redirect_uri(&HostConfig::default(), "https://wiki.test"), "https://wiki.test/sync/gitlab/callback");
    }

    #[test]
    fn projects_and_hooks() {
        let calls = project_calls("t");
        assert_eq!(calls.len(), PROJECT_PAGES);
        assert_eq!(
            calls[0].url,
            "https://gitlab.com/api/v4/projects?membership=true&min_access_level=40&simple=true&order_by=last_activity_at&per_page=100&page=1"
        );
        let reply = |status, body: Value| HttpReply { status, body: body.to_string() };
        let (projects, more) = read_projects(&[
            reply(
                200,
                json!([
                    { "id": 3, "path_with_namespace": "acme/handbook", "default_branch": "main", "visibility": "private" },
                    { "id": 4, "path_with_namespace": "acme/empty", "visibility": "internal" },
                    { "id": 5, "path_with_namespace": "solo" },
                ]),
            ),
            reply(200, json!([])),
        ])
        .unwrap();
        assert_eq!(
            projects.iter().map(|p| (p.id, p.path.as_str(), p.default_branch.as_deref())).collect::<Vec<_>>(),
            vec![(3, "acme/handbook", Some("main")), (4, "acme/empty", None)]
        );
        assert!(!more);
        assert!(read_projects(&[reply(401, json!({}))]).is_err());
        assert_eq!(project_call("t", "acme/sub/docs").url, "https://gitlab.com/api/v4/projects/acme%2Fsub%2Fdocs");
        let hook = add_hook_call("t", 3, "https://acme.dumbslab.com/hooks/docs/s1", "whsec_x");
        assert_eq!((hook.method, hook.url.as_str()), ("POST", "https://gitlab.com/api/v4/projects/3/hooks"));
        let body: Value = serde_json::from_str(hook.body.as_deref().unwrap()).unwrap();
        assert_eq!(
            (&body["url"], &body["token"], &body["push_events"]),
            (&json!("https://acme.dumbslab.com/hooks/docs/s1"), &json!("whsec_x"), &json!(true))
        );
        assert_eq!(read_hook(&reply(201, json!({ "id": 9 }))).unwrap(), 9);
        assert!(read_hook(&reply(403, json!({}))).unwrap_err().contains("Maintainer"));
        assert_eq!(remove_hook_call("t", 3, 9).url, "https://gitlab.com/api/v4/projects/3/hooks/9");
    }

    #[test]
    fn tokens_refresh_before_they_expire() {
        let now = Utc::now();
        let cred = Credential { token: "a".into(), refresh_token: Some("r".into()), ..Default::default() };
        assert!(needs_refresh(&cred, Some(now + Duration::seconds(60)), now));
        assert!(!needs_refresh(&cred, Some(now + Duration::hours(1)), now));
        assert!(!needs_refresh(&Credential::default(), Some(now), now), "nothing to refresh with");
        let call = refresh_call(&app(), &cred);
        assert_eq!(call.url, "https://gitlab.com/oauth/token");
        assert!(call.body.as_deref().unwrap().contains("grant_type=refresh_token&refresh_token=r"));
        let mut kept = Credential { fields: [("webhook_secret".to_string(), "w".to_string())].into(), ..cred };
        apply_tokens(&mut kept, TokenSet { access_token: "b".into(), refresh_token: Some("r2".into()), ..Default::default() });
        assert_eq!((kept.token.as_str(), kept.refresh_token.as_deref(), kept.field("webhook_secret")), ("b", Some("r2"), "w"));
        assert!(
            read_refresh(&HttpReply { status: 400, body: json!({ "error": "invalid_grant" }).to_string() })
                .unwrap_err()
                .contains("Connect GitLab again")
        );
        assert!(read_refresh(&HttpReply { status: 503, body: String::new() }).unwrap_err().contains("error"));
    }
}
