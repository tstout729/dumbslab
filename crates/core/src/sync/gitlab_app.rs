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
    /// A source was removed: take its webhook off the project, best effort.
    RemoveHook { project_id: i64, hook_id: i64, cred: Credential, expires_at: Option<DateTime<Utc>> },
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
            Kind::RemoveHook { .. } => "remove-hook",
        };
        write!(f, "GitLabJob({kind}, {:?})", self.phase)
    }
}

impl GitLabJob {
    fn new(user_id: &str, base_url: &str, kind: Kind) -> GitLabJob {
        GitLabJob { user_id: user_id.into(), base_url: base_url.into(), kind, phase: Phase::Start, effects: vec![], staged: vec![] }
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

    /// Removes a deleted source's webhook.
    pub(crate) fn remove_hook(project_id: i64, hook_id: i64, cred: Credential, expires_at: Option<DateTime<Utc>>) -> GitLabJob {
        GitLabJob::new("", "", Kind::RemoveHook { project_id, hook_id, cred, expires_at })
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
            // GitLab has replaced the old tokens, so these are kept at once.
            if !save_held(db, cfg, &user_id, &claim, p)? {
                return give_up(db, j, reconnect_message());
            }
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
            let Some(found) = read_project(&reply.json()) else {
                return give_up(db, j, "GitLab's answer had no project in it. Try again.");
            };
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
            let mut cred = p.cred.clone();
            cred.fields.insert("webhook_secret".into(), secret.clone());
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

        // Removing a deleted source's webhook.
        (Kind::RemoveHook { project_id, hook_id, cred, expires_at }, Phase::Start) => {
            if needs_refresh(cred, *expires_at, now) {
                j.phase = Phase::Refreshing;
                return Ok(Step::Fetch(vec![refresh_call(app, cred)]));
            }
            j.phase = Phase::Working;
            Ok(Step::Fetch(vec![remove_hook_call(&cred.token, *project_id, *hook_id)]))
        }
        (Kind::RemoveHook { project_id, hook_id, cred, .. }, Phase::Refreshing) => {
            let Ok(tokens) = read_refresh(&reply) else {
                return failed("GitLab no longer accepts DumbSlab's access; remove the webhook in the project's settings.");
            };
            apply_tokens(cred, tokens);
            j.phase = Phase::Working;
            Ok(Step::Fetch(vec![remove_hook_call(&cred.token, *project_id, *hook_id)]))
        }
        (Kind::RemoveHook { .. }, Phase::Working) => match reply.status {
            200..=299 | 404 => Ok(Step::Done(Finish::Fill(json!({ "ok": true })))),
            _ => failed(http_error("GitLab", &reply)),
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
    let sealed = super::seal(cfg, &super::docs::owner(&rejoin.source_id), "gitlab", &cred)?;
    let saved = db.execute(
        "UPDATE docs_sources SET secret = ?, running_until = NULL, updated_at = ? WHERE id = ? AND running_until = ?",
        &params![sealed, ts(now), rejoin.source_id.clone(), rejoin.lease.clone()],
    )?;
    if saved == 0 {
        return Err(ApiError::conflict("The folder changed while it was being reconnected. Try again."));
    }
    db.execute(
        "UPDATE docs_source_links SET token_expires_at = ?, hook_id = ?, disconnected = NULL WHERE source_id = ?",
        &params![p.expires_at.map(ts), added.or(rejoin.hook_id), rejoin.source_id.clone()],
    )?;
    if !take(db, &j.user_id, claim)? {
        return Err(ApiError::conflict("Your GitLab approval changed while the folder was being reconnected. Try again."));
    }
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
        Kind::Create { approval: Some(p), draft, .. } => vec![project_call(&p.cred.token, &draft.repo)],
        Kind::Reconnect { approval: Some(p), rejoin, .. } => match rejoin.hook_id {
            Some(hook) => vec![edit_hook_call(&p.cred.token, rejoin.project_id, hook, &rejoin.webhook_url, &rejoin.secret)],
            None => vec![add_hook_call(&p.cred.token, rejoin.project_id, &rejoin.webhook_url, &rejoin.secret)],
        },
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> OAuthApp {
        OAuthApp { client_id: "gl-client".into(), client_secret: "gl-secret".into() }
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
