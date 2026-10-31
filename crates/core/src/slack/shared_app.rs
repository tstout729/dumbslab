//! Add to Slack: the host's own Slack app, which an admin connects with one click, and hosted
//! DumbSlab's routing of that app's requests through the root domain. See the parent module for
//! the whole picture and Slack's docs.

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};

use super::{
    API, App, BOT_TOKEN, COMMANDS_PATH, CREATE_APP_URL, CREATE_SHARED_APP_PATH, DIRECTORY, EVENTS_PATH, INSTALL_CALLBACK_PATH, MAX_BODY,
    Phase, SCOPES, SHARED_EVENTS, SlackJob, Snapshot, USER_SCOPES, Work, dead, ephemeral, fail, fill, fingerprint, forget_connection, form,
    job_ctx, key, later, load, open_from_directory, refused, reply, seal, seal_for_directory, slack_error, valid_id, verify,
};
use crate::auth::{Actor, Role, Scopes, Via};
use crate::connect::{self, Finish, HttpCall, HttpReply, Step};
use crate::db::{Db, DbExt};
use crate::error::{ApiError, ApiResult};
use crate::events::{Event, emit};
use crate::tenancy::SlackStatus;
use crate::util::{parse_ts, secure_eq, sha256_hex, ts};
use crate::{Effect, HostConfig, Outcome, Request, Response, params};

/// Where an admin's browser starts Add to Slack.
const AUTHORIZE_URL: &str = "https://slack.com/oauth/v2/authorize";
/// How long Add to Slack may take.
const INSTALL_MINUTES: i64 = 15;

/// The host's own Slack app, which every workspace can add with one click. Its client id and secret
/// are the `slack` connected app's ([`connect::Connectors::apps`]): one Slack app serves Add to
/// Slack, searching Slack and signing in with Slack. Cloudflare: `SLACK_CLIENT_ID`, and the secrets
/// `SLACK_CLIENT_SECRET` and `SLACK_SIGNING_SECRET`. Self-hosted: the same with `DUMBSLAB_` first.
#[derive(Clone, Default)]
pub struct SharedApp {
    /// The app's signing secret. Slack signs every Slack workspace's requests with it.
    pub signing_secret: Option<String>,
    /// Where Slack sends an admin back from Add to Slack. Defaults to this server's
    /// [`INSTALL_CALLBACK_PATH`]; hosted DumbSlab uses the root domain's, which forwards it.
    pub callback_url: Option<String>,
}

impl fmt::Debug for SharedApp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedApp")
            .field("signing_secret", &self.signing_secret.as_ref().map(|_| "…"))
            .field("callback_url", &self.callback_url)
            .finish()
    }
}

/// The shared app's credentials, once the host has all of them.
pub struct Shared<'a> {
    pub client_id: &'a str,
    pub client_secret: &'a str,
    pub signing_secret: &'a str,
}

/// The host's shared Slack app, when Add to Slack works here: it has the app's client id, client
/// secret and signing secret, and a connector key to encrypt the bot token.
pub fn shared(cfg: &HostConfig) -> Option<Shared<'_>> {
    key(cfg)?;
    let app = connect::oauth_app(cfg, "slack")?;
    let signing_secret = cfg.slack.signing_secret.as_deref().filter(|s| !s.is_empty())?;
    Some(Shared { client_id: &app.client_id, client_secret: &app.client_secret, signing_secret })
}

/// Where Slack sends an admin back from Add to Slack.
pub fn install_callback_url(cfg: &HostConfig, base_url: &str) -> String {
    cfg.slack.callback_url.clone().unwrap_or_else(|| format!("{base_url}{INSTALL_CALLBACK_PATH}"))
}

/// Hosted DumbSlab: the workspace's first address, which the directory knows it by.
pub(super) fn home(cfg: &HostConfig) -> Option<&str> {
    cfg.hosting.as_ref().map(|h| h.home.as_str())
}

/// The manifest of the host's shared Slack app, from its root URL (`https://dumbslab.com`, or a
/// self-hosted server's own): the `/dumbslab` command and events go to the root, which forwards
/// them to the right workspace; links to any workspace on the domain are previewed (Slack counts
/// every subdomain of an unfurl domain); and Slack sends people back to the root after connecting
/// an app, signing in with Slack, or Add to Slack. Bot scopes are Add to Slack's, user scopes
/// searching Slack's and signing in's. No org-wide installs and no token rotation: the bot token
/// is stored once and never refreshed. Public distribution has no manifest field; the operator
/// turns it on in the app's Manage Distribution page.
pub fn shared_manifest(root_url: &str) -> Value {
    let root = root_url.trim_end_matches('/');
    let domain = connect::host_of(root).unwrap_or_default();
    json!({
        "_metadata": { "major_version": 2, "minor_version": 1 },
        "display_information": {
            "name": "DumbSlab",
            "description": "Search, preview and draft posts in your DumbSlab knowledge base from Slack.",
            "background_color": "#1f2937",
        },
        "features": {
            "bot_user": { "display_name": "dumbslab", "always_online": true },
            "slash_commands": [{
                "command": "/dumbslab",
                "url": format!("{root}{COMMANDS_PATH}"),
                "description": "Search DumbSlab or start a draft",
                "usage_hint": "search <words> | new <title> | help",
                "should_escape": false,
            }],
            "unfurl_domains": [domain],
        },
        "oauth_config": {
            "redirect_urls": [
                format!("{root}/connect/callback"),
                format!("{root}{}", crate::sso::CALLBACK_PATH),
                format!("{root}{INSTALL_CALLBACK_PATH}"),
            ],
            "scopes": { "bot": SCOPES, "user": USER_SCOPES },
        },
        "settings": {
            "event_subscriptions": { "request_url": format!("{root}{EVENTS_PATH}"), "bot_events": SHARED_EVENTS },
            "org_deploy_enabled": false,
            "socket_mode_enabled": false,
            "token_rotation_enabled": false,
        },
    })
}

/// Slack's app creation page with `manifest` filled in.
pub fn create_app_link(manifest: &Value) -> String {
    format!("{CREATE_APP_URL}&manifest_json={}", urlencoding::encode(&manifest.to_string()))
}

/// `GET /slack/app-manifest.json` and `GET /slack/create-app` on a server that isn't hosted
/// DumbSlab: the shared app's manifest for this server's own URL, or Slack's page to create it.
/// Hosted workspaces don't answer them; the root domain does.
pub fn manifest_route(cfg: &HostConfig, req: &Request) -> Outcome {
    if cfg.workspace.is_some() {
        return crate::http::failed(&ApiError::not_found("route"));
    }
    let manifest = shared_manifest(&crate::http::base_url(cfg, req));
    let response = match req.path.as_str() {
        CREATE_SHARED_APP_PATH => Response::redirect(&create_app_link(&manifest)),
        _ => Response::json(200, &manifest),
    };
    crate::http::done(response.with_header("cache-control", "no-store"))
}

// ---------------------------------------------------------------------------
// Add to Slack

/// Why Add to Slack didn't work. Only these codes go in the link back to Settings › Slack, never
/// Slack's text: anyone can make a link to Settings, and the page says what the code means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallError {
    /// Only admins connect Slack.
    NotAdmin,
    /// The host has no shared Slack app (or no connector key).
    Unavailable,
    /// The link was used already, or never existed.
    Expired,
    TooSlow,
    /// Another person, or another browser session, came back.
    OtherSession,
    /// The admin didn't allow it in Slack.
    Declined,
    /// Slack sent an error, or no code.
    SlackError,
    /// An org-wide (Enterprise Grid) install: DumbSlab connects one Slack workspace at a time.
    EnterpriseInstall,
    /// Another DumbSlab workspace holds this Slack workspace.
    TeamTaken,
    /// This workspace's Slack connection changed while it finished (another Add to Slack, a
    /// disconnect, Slack removing the app): nothing was saved.
    Busy,
    Failed,
}

impl InstallError {
    pub const ALL: [InstallError; 11] = [
        InstallError::NotAdmin,
        InstallError::Unavailable,
        InstallError::Expired,
        InstallError::TooSlow,
        InstallError::OtherSession,
        InstallError::Declined,
        InstallError::SlackError,
        InstallError::EnterpriseInstall,
        InstallError::TeamTaken,
        InstallError::Busy,
        InstallError::Failed,
    ];

    pub fn code(self) -> &'static str {
        match self {
            InstallError::NotAdmin => "not_admin",
            InstallError::Unavailable => "unavailable",
            InstallError::Expired => "expired",
            InstallError::TooSlow => "too_slow",
            InstallError::OtherSession => "other_session",
            InstallError::Declined => "declined",
            InstallError::SlackError => "slack_error",
            InstallError::EnterpriseInstall => "enterprise_install",
            InstallError::TeamTaken => "slack_team_taken",
            InstallError::Busy => "slack_busy",
            InstallError::Failed => "failed",
        }
    }
}

/// Settings › Slack, saying how Add to Slack went.
fn settings_url(base_url: &str, outcome: Result<(), InstallError>) -> String {
    match outcome {
        Ok(()) => format!("{base_url}/settings/slack?slack=connected"),
        Err(e) => format!("{base_url}/settings/slack?slack_error={}", e.code()),
    }
}

fn back(base_url: &str, outcome: Result<(), InstallError>) -> Outcome {
    crate::http::done(Response::redirect(&settings_url(base_url, outcome)).with_header("cache-control", "no-store"))
}

fn query_map(query: &str) -> BTreeMap<String, String> {
    let decode = |s: &str| urlencoding::decode(&s.replace('+', " ")).map(|c| c.into_owned()).unwrap_or_default();
    query.split('&').filter_map(|p| p.split_once('=')).map(|(k, v)| (decode(k), decode(v))).collect()
}

/// `GET /slack/install`: an admin, signed in in this browser, starts Add to Slack. Records the
/// sign-in (its `state` hashed, bound to the admin and this browser session) and sends them to
/// Slack to approve the bot scopes. On hosted DumbSlab the `state` starts with the workspace's
/// address, so the root domain can send them back here.
pub fn install_start(db: &dyn Db, cfg: &HostConfig, req: &Request) -> Outcome {
    let base = crate::http::base_url(cfg, req);
    let now = Utc::now();
    let run = || -> ApiResult<Outcome> {
        let actor = crate::auth::authenticate(db, cfg, req, now).ok().flatten();
        let Some((actor, session)) = actor.and_then(|a| a.session_hash.clone().map(|s| (a, s))) else {
            // A browser route: only a session counts. Sign in, then come back to Settings.
            let login = format!("{base}/login?next={}", urlencoding::encode("/settings/slack"));
            return Ok(crate::http::done(Response::redirect(&login).with_header("cache-control", "no-store")));
        };
        if actor.role != Role::Admin {
            return Ok(back(&base, Err(InstallError::NotAdmin)));
        }
        let Some(app) = shared(cfg) else { return Ok(back(&base, Err(InstallError::Unavailable))) };
        db.execute("DELETE FROM slack_install_requests WHERE created_at < ?", &params![ts(now - Duration::minutes(INSTALL_MINUTES))])?;
        let random = crate::util::new_secret("");
        let state = match &cfg.workspace {
            Some(address) => format!("{address}.{random}"),
            None => random,
        };
        db.execute(
            "INSERT INTO slack_install_requests (state_hash, user_id, session_hash, created_at) VALUES (?, ?, ?, ?)",
            &params![sha256_hex(&state), actor.user_id.clone(), session, ts(now)],
        )?;
        let query = [
            ("client_id", app.client_id.to_string()),
            ("scope", SCOPES.join(",")),
            ("redirect_uri", install_callback_url(cfg, &base)),
            ("state", state),
        ];
        let qs = query.iter().map(|(k, v)| format!("{k}={}", urlencoding::encode(v))).collect::<Vec<_>>().join("&");
        let to = Response::redirect(&format!("{AUTHORIZE_URL}?{qs}"))
            .with_header("cache-control", "no-store")
            .with_header("referrer-policy", "no-referrer");
        Ok(crate::http::done(to))
    };
    run().unwrap_or_else(|_| back(&base, Err(InstallError::Failed)))
}

/// `GET /slack/install/callback`: Slack sent the admin back. The `state` must be one this very
/// browser session started, unused and recent, and the person still an admin. Answers with a job
/// that exchanges the code for the bot token, has the directory record the installation (hosted)
/// and saves it, then sends them to Settings › Slack.
pub fn install_callback(db: &dyn Db, cfg: &HostConfig, req: &Request) -> Outcome {
    let base = crate::http::base_url(cfg, req);
    let query = query_map(&req.query);
    let now = Utc::now();
    let run = || -> ApiResult<Outcome> {
        let state_hash = sha256_hex(query.get("state").map(String::as_str).unwrap_or_default());
        let Some(row) = db.one(
            "SELECT user_id, session_hash, created_at FROM slack_install_requests WHERE state_hash = ?",
            &params![state_hash.clone()],
        )?
        else {
            return Ok(back(&base, Err(InstallError::Expired)));
        };
        // Each link works once.
        db.execute("DELETE FROM slack_install_requests WHERE state_hash = ?", &params![state_hash])?;
        if now - parse_ts(&row.str("created_at")).unwrap_or(now) > Duration::minutes(INSTALL_MINUTES) {
            return Ok(back(&base, Err(InstallError::TooSlow)));
        }
        let actor = crate::auth::authenticate(db, cfg, req, now).ok().flatten();
        let same = actor.as_ref().is_some_and(|a| {
            a.user_id == row.str("user_id") && a.session_hash.as_deref().is_some_and(|h| secure_eq(h, &row.str("session_hash")))
        });
        let Some(actor) = actor.filter(|_| same) else { return Ok(back(&base, Err(InstallError::OtherSession))) };
        if actor.role != Role::Admin {
            return Ok(back(&base, Err(InstallError::NotAdmin)));
        }
        if shared(cfg).is_none() {
            return Ok(back(&base, Err(InstallError::Unavailable)));
        }
        // Slack's own words stay out of the link; only what kind of failure.
        let code = match (query.get("code").filter(|c| !c.is_empty()), query.get("error")) {
            (Some(c), _) => c.clone(),
            (None, Some(e)) if e == "access_denied" => return Ok(back(&base, Err(InstallError::Declined))),
            (None, _) => return Ok(back(&base, Err(InstallError::SlackError))),
        };
        let mut out = back(&base, Err(InstallError::Failed));
        let job = SlackJob::new(
            &base,
            Work::Install {
                admin: actor.user_id,
                via: actor.via,
                code,
                redirect_uri: install_callback_url(cfg, &base),
                home: home(cfg).map(str::to_string),
                // This workspace as it is now: deleted and set up again meanwhile, it's another.
                instance: super::instance(db)?,
            },
        );
        out.effects.push(Effect::Connect(connect::Job::Slack(job)));
        Ok(out)
    };
    run().unwrap_or_else(|_| back(&base, Err(InstallError::Failed)))
}

/// What Slack's `oauth.v2.access` gave for Add to Slack. Never printed.
#[derive(Clone)]
pub(super) struct Installed {
    token: String,
    team_id: String,
    team_name: String,
    bot_user_id: String,
    scopes: Vec<String>,
}

/// How reading `oauth.v2.access`'s answer went.
enum Exchange {
    Installed(Installed),
    /// An org-wide install: refused.
    Enterprise,
    Failed,
}

/// Reads `oauth.v2.access`'s answer: a bot token for one Slack workspace.
fn read_exchange(reply: &HttpReply) -> Exchange {
    if slack_error(reply).is_some() {
        return Exchange::Failed;
    }
    let v = reply.json();
    if v["is_enterprise_install"] == true {
        return Exchange::Enterprise;
    }
    let token = connect::opt(&v["access_token"]);
    let Some(token) = token.filter(|t| t.starts_with("xoxb-") && !t.contains(char::is_whitespace) && t.len() <= 500) else {
        return Exchange::Failed;
    };
    let team_id = connect::s(&v["team"]["id"]);
    if v["token_type"].as_str().is_some_and(|t| t != "bot") || !valid_id(&team_id) {
        return Exchange::Failed;
    }
    Exchange::Installed(Installed {
        token,
        team_id,
        team_name: connect::excerpt(&connect::s(&v["team"]["name"]), 100),
        bot_user_id: Some(connect::s(&v["bot_user_id"])).filter(|b| valid_id(b)).unwrap_or_default(),
        scopes: connect::s(&v["scope"]).split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect(),
    })
}

/// What Slack's answer to `auth.test` says about a token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Answer {
    /// It works.
    Ok,
    /// Slack says it's no good: revoked, or the install is gone.
    Dead,
    /// Slack answered with some other error: nothing says the token is dead.
    Refused,
    /// No answer, a rate limit or a server error.
    Unknown,
}

fn answer_of(reply: &HttpReply) -> Answer {
    match slack_error(reply).as_deref() {
        None => Answer::Ok,
        Some(code) if dead(code) => Answer::Dead,
        Some(
            "no_answer"
            | "ratelimited"
            | "fatal_error"
            | "internal_error"
            | "service_unavailable"
            | "request_timeout"
            | "unreadable_answer",
        ) => Answer::Unknown,
        Some(code) if code.starts_with("http_5") => Answer::Unknown,
        Some(_) => Answer::Refused,
    }
}

fn test_call(token: &str) -> HttpCall {
    HttpCall::post_form(format!("{API}/auth.test"), &[]).bearer(token)
}

/// A call to hosted DumbSlab's directory (see [`DIRECTORY`]). The host adds which workspace asks.
pub(super) fn directory_call(path: &str, body: Value) -> HttpCall {
    HttpCall::post_json(format!("{DIRECTORY}{path}"), &body)
}

/// Lets go of Slack workspaces this workspace holds, if its connection is still at `generation`.
/// `leftovers`: only those installed long enough ago (see `tenancy::SLACK_LEFTOVER_SECS`).
fn release_call(team_ids: &[String], generation: i64, leftovers: bool) -> HttpCall {
    directory_call("/slack/release", json!({ "team_ids": team_ids, "generation": generation, "leftovers": leftovers }))
}

fn status_call(team_id: Option<&str>) -> HttpCall {
    directory_call("/slack/status", json!({ "team_id": team_id }))
}

/// The directory's value for this workspace's connection, from its answer to a status, an install
/// or a release.
fn generation_of(reply: &HttpReply) -> Option<i64> {
    (reply.status == 200).then(|| reply.json()["generation"].as_i64()).flatten()
}

/// The error code in the directory's refusal.
fn refusal(reply: &HttpReply) -> String {
    reply.json()["error"]["code"].as_str().unwrap_or_default().to_string()
}

/// The Slack workspace a request from Slack is for: a command's `team_id`; for an event, the
/// installation it was sent for (`authorizations[0]`, which Slack says names the one installation
/// the event is for), else its `team_id`. `None` when it names none (Slack's URL check) and for an
/// org-wide installation's events, which DumbSlab never accepts.
pub fn team_of(path: &str, body: &[u8]) -> Option<String> {
    let team = if path == COMMANDS_PATH {
        form(body).get("team_id").cloned().unwrap_or_default()
    } else {
        let v: Value = serde_json::from_slice(body).ok()?;
        let auth = &v["authorizations"][0];
        if auth["is_enterprise_install"] == true {
            return None;
        }
        connect::opt(&auth["team_id"]).or_else(|| connect::opt(&v["team_id"])).unwrap_or_default()
    };
    Some(team.trim().to_string()).filter(|t| valid_id(t))
}

/// With the shared app, whether a request is for the Slack workspace this workspace's connection
/// names. Only Slack's own URL and certificate checks may name no Slack workspace.
pub(super) fn ours(app: &App, path: &str, body: &[u8]) -> bool {
    match team_of(path, body) {
        Some(team) => app.team_id.as_deref() == Some(team.as_str()),
        None if path == COMMANDS_PATH => form(body).get("ssl_check").map(|v| v.trim()) == Some("1"),
        None => serde_json::from_slice::<Value>(body).is_ok_and(|v| v["type"] == "url_verification"),
    }
}

/// What the root domain does with a request Slack sent to the shared app.
#[derive(Debug)]
pub enum Routed {
    /// Answer it at the root: a refusal, Slack's URL or certificate check, or a request that names
    /// no Slack workspace.
    Answer(Response),
    /// Send it, as it came, to the workspace that holds this Slack workspace (and answer with
    /// [`unknown_team`] when none does). The workspace checks the signature again: it remembers the
    /// signatures it has seen.
    Forward(String),
    /// The shared app was removed from this Slack workspace, or its bot token revoked: check it at
    /// the root ([`UninstallCheck`]).
    Uninstalled(String),
}

/// `POST /slack/commands` and `POST /slack/events` on hosted DumbSlab's root domain, where the
/// shared app's requests arrive for every Slack workspace. Checks Slack's signature with the shared
/// app's signing secret, answers Slack's own checks, and finds which Slack workspace it's about.
pub fn route(signing_secret: &str, path: &str, timestamp: Option<&str>, signature: Option<&str>, body: &[u8], now_unix: i64) -> Routed {
    let answer = |r: Response| Routed::Answer(r.with_header("cache-control", "no-store"));
    if path != COMMANDS_PATH && path != EVENTS_PATH {
        return answer(Response::error(&ApiError::not_found("route")));
    }
    if body.len() > MAX_BODY {
        return answer(Response::error(&ApiError::new(413, "too_large", "request body too large")));
    }
    if let Err(r) = verify(signing_secret, timestamp, signature, body, now_unix) {
        return answer(Response::error(&refused(r)));
    }
    if path == COMMANDS_PATH {
        if form(body).get("ssl_check").map(|v| v.trim()) == Some("1") {
            return answer(Response::empty(200));
        }
        return match team_of(path, body) {
            Some(team) => Routed::Forward(team),
            None => answer(Response::json(200, &ephemeral("Slack didn't say which Slack workspace this came from. Try again."))),
        };
    }
    let Ok(v) = serde_json::from_slice::<Value>(body) else {
        return answer(Response::error(&ApiError::bad_request("Slack sent an event DumbSlab couldn't read.")));
    };
    let e = &v["event"];
    let ack = || answer(Response::json(200, &json!({ "ok": true })));
    match (v["type"].as_str(), team_of(path, body)) {
        (Some("url_verification"), _) => answer(Response::json(200, &json!({ "challenge": v["challenge"].as_str().unwrap_or_default() }))),
        (Some("event_callback"), Some(team)) if e["type"] == "app_uninstalled" => Routed::Uninstalled(team),
        // Only a bot token's revoke is the shared app's own: people's tokens (searching Slack from
        // DumbSlab) are theirs.
        (Some("event_callback"), Some(team)) if e["type"] == "tokens_revoked" => {
            match e["tokens"]["bot"].as_array().is_some_and(|b| !b.is_empty()) {
                true => Routed::Uninstalled(team),
                false => ack(),
            }
        }
        (Some("event_callback"), Some(team)) => Routed::Forward(team),
        _ => ack(),
    }
}

/// The root's answer for a Slack workspace no DumbSlab workspace holds: a command says how to
/// connect it, only to the person who typed it; an event is acknowledged and dropped.
pub fn unknown_team(path: &str) -> Response {
    let body = match path {
        COMMANDS_PATH => ephemeral(NOT_CONNECTED),
        _ => json!({ "ok": true }),
    };
    Response::json(200, &body).with_header("cache-control", "no-store")
}

const NOT_CONNECTED: &str = "This Slack workspace isn't connected to DumbSlab yet. A DumbSlab admin can connect it: open Settings › Slack in your DumbSlab workspace and click *Add to Slack*.";

/// The root domain's check of `app_uninstalled` and `tokens_revoked` (hosted DumbSlab): it asks
/// the directory for the installation's token, then Slack whether the token still works. If it
/// doesn't, the directory forgets the installation, only while it still holds that very token: an
/// install made since, with another token, stays. No workspace is involved; a workspace whose
/// installation is gone finds out the next time it asks for the token, or opens Settings › Slack.
/// The host sends each call (those to [`DIRECTORY`] straight to the directory, as they are) and
/// answers Slack with the response it ends with: a 500 when the check was unclear, so Slack sends
/// the event again. Never printed with a token: it keeps none.
#[derive(Debug)]
pub struct UninstallCheck {
    team_id: String,
    phase: CheckPhase,
    fingerprint: String,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum CheckPhase {
    /// Waiting for the directory's installation.
    Row,
    /// Waiting for `auth.test`.
    Testing,
    /// Waiting for the directory to forget the dead token.
    Forgetting,
}

/// What [`UninstallCheck`] does next.
#[derive(Debug)]
pub enum CheckStep {
    /// Send this, then call [`UninstallCheck::next`] with the answer.
    Fetch(HttpCall),
    /// Answer Slack with this.
    Done(Response),
}

impl UninstallCheck {
    /// The check for an event about `team_id`, and its first call.
    pub fn start(team_id: &str) -> (UninstallCheck, HttpCall) {
        let check = UninstallCheck { team_id: team_id.to_string(), phase: CheckPhase::Row, fingerprint: String::new() };
        (check, directory_call("/slack/row", json!({ "team_id": team_id })))
    }

    /// The next step, from the answer to the last call. `key` is the host's connector key, which
    /// opens the token the directory holds.
    pub fn next(&mut self, key: Option<&str>, reply: &HttpReply) -> CheckStep {
        let done =
            |status: u16| CheckStep::Done(Response::json(status, &json!({ "ok": status == 200 })).with_header("cache-control", "no-store"));
        match self.phase {
            CheckPhase::Row => match reply.status {
                // Nobody holds it: nothing to forget.
                404 => done(200),
                200 => {
                    let v = reply.json();
                    let token = key
                        .filter(|k| !k.is_empty())
                        .and_then(|k| open_from_directory(k, &self.team_id, v["bot_token"].as_str().unwrap_or_default()));
                    let (Some(token), Some(fingerprint)) = (token, connect::opt(&v["token_fingerprint"])) else { return done(500) };
                    self.fingerprint = fingerprint;
                    self.phase = CheckPhase::Testing;
                    CheckStep::Fetch(test_call(&token))
                }
                _ => done(500),
            },
            CheckPhase::Testing => match answer_of(reply) {
                Answer::Dead => {
                    self.phase = CheckPhase::Forgetting;
                    CheckStep::Fetch(directory_call(
                        "/slack/forget",
                        json!({ "team_id": self.team_id, "token_fingerprint": self.fingerprint }),
                    ))
                }
                Answer::Unknown => done(500),
                // It works: the event was about an earlier install, or a token revoked and replaced.
                Answer::Ok | Answer::Refused => done(200),
            },
            CheckPhase::Forgetting => done(if reply.status == 200 { 200 } else { 500 }),
        }
    }
}

/// Exchanges Add to Slack's code at `oauth.v2.access`.
fn exchange(job: &mut SlackJob, cfg: &HostConfig, code: &str, redirect_uri: &str) -> ApiResult<Step> {
    let Some(app) = shared(cfg) else { return to_settings(&job.base_url, Err(InstallError::Unavailable)) };
    // Basic auth, as Slack prefers, with the client's credentials form-encoded first (RFC 6749, 2.3.1).
    let call = HttpCall::post_form(format!("{API}/oauth.v2.access"), &[("code", code), ("redirect_uri", redirect_uri)])
        .basic(&urlencoding::encode(app.client_id), &urlencoding::encode(app.client_secret));
    job.phase = Phase::Exchanging;
    Ok(Step::Fetch(vec![call]))
}

fn to_settings(base_url: &str, outcome: Result<(), InstallError>) -> ApiResult<Step> {
    Ok(Step::Done(Finish::Redirect(settings_url(base_url, outcome))))
}

fn still_admin(db: &dyn Db, user_id: &str, via: Via) -> ApiResult<Option<Actor>> {
    Ok(crate::model::actor_for_user(db, user_id)?.filter(|a| a.role == Role::Admin).map(|mut a| {
        a.via = via;
        a
    }))
}

/// How saving Add to Slack's connection here went.
enum Saved {
    /// Saved. The previous Add to Slack connection's Slack workspace, when it was another one:
    /// hosted, the directory still holds that one for this workspace.
    Done(Option<String>),
    /// The connection here isn't the one the job started from any more: nothing was written.
    Changed,
}

/// Saves Add to Slack's connection here, as the admin who added it, under a new version, only over
/// `expect` (the connection here when the job recorded the installation): with the token off hosted
/// DumbSlab; on hosted DumbSlab without it (the directory holds it). It replaces whatever app was
/// connected, and another Slack workspace's channels go with it.
fn save_install(
    db: &dyn Db,
    cfg: &HostConfig,
    inst: &Installed,
    token: Option<&str>,
    admin: &str,
    now: DateTime<Utc>,
    expect: &Snapshot,
) -> ApiResult<Saved> {
    let old = load(db, cfg)?;
    if Snapshot::of(old.as_ref()) != *expect {
        return Ok(Saved::Changed);
    }
    let sealed = token.map(|t| seal(cfg, BOT_TOKEN, t)).transpose()?;
    let mut values = params![
        sealed,
        inst.team_id.clone(),
        inst.team_name.clone(),
        Some(inst.bot_user_id.clone()).filter(|b| !b.is_empty()),
        inst.scopes.join(","),
        crate::util::new_id(),
        admin,
        ts(now)
    ];
    let written = match old {
        None => db.execute(
            "INSERT INTO slack_app (id, bot_token, signing_secret, team_id, team_name, bot_user_id, scopes, shared, version, updated_by,
               updated_at) VALUES (1, ?, NULL, ?, ?, ?, ?, 1, ?, ?, ?) ON CONFLICT(id) DO NOTHING",
            &values,
        )?,
        Some(_) => {
            values.extend(params![expect.version.clone()]);
            db.execute(
                "UPDATE slack_app SET bot_token = ?, signing_secret = NULL, team_id = ?, team_name = ?, bot_user_id = ?, scopes = ?,
                   shared = 1, version = ?, updated_by = ?, updated_at = ? WHERE id = 1 AND version IS ?",
                &values,
            )?
        }
    };
    if written != 1 {
        return Ok(Saved::Changed);
    }
    let old_team = old.as_ref().and_then(|a| a.team_id.clone());
    if old_team.as_deref().is_some_and(|t| t != inst.team_id) {
        // Channel IDs belong to one Slack workspace.
        db.execute("DELETE FROM slack_channels", &[])?;
    }
    Ok(Saved::Done(old.filter(|a| a.shared).and_then(|a| a.team_id).filter(|t| *t != inst.team_id)))
}

/// A job, run after this one, that lets go of a Slack workspace if this workspace's connection is
/// still at `generation` (see [`Work::Release`]).
fn release_later(job: &mut SlackJob, team_id: &str, generation: i64) {
    let release = SlackJob::new(&job.base_url, Work::Release { team_id: team_id.to_string(), generation });
    job.effects.push(Effect::Background(connect::Job::Slack(release)));
}

/// Records that Slack is connected, as `actor`.
fn record_install(db: &dyn Db, cfg: &HostConfig, job: &mut SlackJob, inst: &Installed, actor: Actor, now: DateTime<Utc>) -> ApiResult<()> {
    let mut ctx = job_ctx(db, cfg, &job.base_url, actor, now);
    let name = if inst.team_name.is_empty() { "a Slack workspace".to_string() } else { inst.team_name.clone() };
    emit(
        &mut ctx,
        Event::new("slack.installed", "settings", "slack", format!("added DumbSlab to {name} in Slack"))
            .data(json!({ "slack_workspace": inst.team_name, "slack_workspace_id": inst.team_id }))
            .admin_only(),
    )?;
    job.effects.extend(std::mem::take(&mut ctx.effects));
    Ok(())
}

/// The directory says this workspace doesn't hold `team_id`: forgets the connection to it here,
/// only if it's still the version the job saw, and records that.
pub(super) fn forget_stale(db: &dyn Db, cfg: &HostConfig, job: &mut SlackJob, team_id: &str, now: DateTime<Utc>) -> ApiResult<()> {
    if !forget_connection(db, team_id, job.version.as_deref())? {
        return Ok(());
    }
    let mut ctx = job_ctx(db, cfg, &job.base_url.clone(), slack_actor(), now);
    emit(
        &mut ctx,
        Event::new(
            "slack.disconnected",
            "settings",
            "slack",
            "Slack is disconnected: this workspace doesn't hold that Slack workspace any more",
        )
        .data(json!({ "slack_workspace_id": team_id }))
        .admin_only(),
    )?;
    job.effects.extend(std::mem::take(&mut ctx.effects));
    Ok(())
}

fn ok() -> ApiResult<Step> {
    fill(json!({ "ok": true }))
}

/// The answer to Slack once a self-hosted uninstall check is done: 500 when it was unclear, so
/// Slack sends the event again.
fn answer_slack(status: u16) -> ApiResult<Step> {
    let response = Response::json(status, &json!({ "ok": status == 200 })).with_header("cache-control", "no-store");
    Ok(Step::Done(Finish::Respond(response)))
}

fn not_disconnected() -> ApiError {
    ApiError::new(503, "slack_unavailable", "DumbSlab couldn't disconnect Slack just now, so it's still connected. Try again in a minute.")
}

fn unreachable_directory() -> ApiError {
    ApiError::new(503, "slack_unavailable", "DumbSlab couldn't check the Slack connection just now. Try again in a minute.")
}

/// Runs Add to Slack's job, and the ones that disconnect it, ask the directory about it, forget a
/// dead token, and check an uninstall off hosted DumbSlab (see [`super::step`]).
pub(super) fn step(
    db: &dyn Db,
    cfg: &HostConfig,
    job: &mut SlackJob,
    app: &App,
    replies: &[HttpReply],
    now: DateTime<Utc>,
) -> ApiResult<Step> {
    let answer = replies.first().cloned().unwrap_or_default();
    match (job.phase, job.work.clone()) {
        // Add to Slack. Hosted: read where this workspace's connection is, exchange the code, have
        // the directory record the installation, then save the reference here. Off hosted
        // DumbSlab: exchange the code and save the token.
        (Phase::Start, Work::Install { code, redirect_uri, home, .. }) => {
            if home.is_none() {
                return exchange(job, cfg, &code, &redirect_uri);
            }
            // Before the code is exchanged: the token comes after the value the install names, so
            // anything that changed this workspace's connection since (Slack removing the app,
            // another Add to Slack) has it refused.
            job.phase = Phase::Asking;
            Ok(Step::Fetch(vec![status_call(None)]))
        }
        (Phase::Asking, Work::Install { code, redirect_uri, .. }) => {
            let Some(generation) = generation_of(&answer) else { return to_settings(&job.base_url, Err(InstallError::Failed)) };
            job.generation = Some(generation);
            exchange(job, cfg, &code, &redirect_uri)
        }
        (Phase::Exchanging, Work::Install { admin, via, home, instance, .. }) => {
            let base = job.base_url.clone();
            let inst = match read_exchange(&answer) {
                Exchange::Installed(i) => i,
                Exchange::Failed => return to_settings(&base, Err(InstallError::Failed)),
                // Not revoked: an org-wide token also reaches the org's workspaces that installed
                // the app themselves, which other DumbSlab workspaces may hold. An org admin
                // removes it in Slack.
                Exchange::Enterprise => return to_settings(&base, Err(InstallError::EnterpriseInstall)),
            };
            // Still this workspace (not one set up again at this address), and the admin may have
            // lost the role while Slack answered.
            if !super::same_instance(db, &instance)? {
                return to_settings(&base, Err(InstallError::Failed));
            }
            let Some(actor) = still_admin(db, &admin, via)? else { return to_settings(&base, Err(InstallError::NotAdmin)) };
            let expect = Snapshot::of(load(db, cfg)?.as_ref());
            if home.is_none() {
                // No directory: the token is kept here, like a workspace's own app's.
                if let Saved::Changed = save_install(db, cfg, &inst, Some(&inst.token), &admin, now, &expect)? {
                    return to_settings(&base, Err(InstallError::Busy));
                }
                record_install(db, cfg, job, &inst, actor, now)?;
                return to_settings(&base, Ok(()));
            }
            let Some(generation) = job.generation else { return to_settings(&base, Err(InstallError::Failed)) };
            // One Slack workspace belongs to one DumbSlab workspace: the directory records the
            // installation, token and all, unless another workspace holds it, or this one's
            // connection changed since the job started.
            let install = crate::tenancy::SlackInstall {
                team_id: inst.team_id.clone(),
                bot_token: seal_for_directory(cfg, &inst.team_id, &inst.token)?,
                token_fingerprint: fingerprint(&inst.token),
                bot_user_id: Some(inst.bot_user_id.clone()).filter(|b| !b.is_empty()),
                team_name: inst.team_name.clone(),
                scopes: inst.scopes.join(","),
            };
            let mut body = serde_json::to_value(install).map_err(|e| ApiError::internal(e.to_string()))?;
            body["generation"] = json!(generation);
            job.installed = Some(Box::new(inst));
            job.expect = Some(expect);
            job.phase = Phase::Installing;
            Ok(Step::Fetch(vec![directory_call("/slack/install", body)]))
        }
        (Phase::Installing, Work::Install { admin, via, instance, .. }) => {
            let base = job.base_url.clone();
            let (Some(inst), Some(expect)) = (job.installed.clone(), job.expect.clone()) else {
                return to_settings(&base, Err(InstallError::Failed));
            };
            let generation = match (answer.status, generation_of(&answer)) {
                (200, Some(generation)) => generation,
                // Something changed this workspace's connection since the job started: a newer
                // Add to Slack, a disconnect, Slack removing the app, the workspace deleted. That
                // one stays.
                (409, _) if refusal(&answer) == "slack_changed" => return to_settings(&base, Err(InstallError::Busy)),
                (409, _) => return to_settings(&base, Err(InstallError::TeamTaken)),
                // Perhaps recorded: then this workspace holds it there, and Settings › Slack lets
                // go of it later (see `Work::Status`). Adding it again just records it again.
                _ => return to_settings(&base, Err(InstallError::Failed)),
            };
            job.generation = Some(generation);
            // The directory holds it for this workspace now. The reference is saved here, without
            // the token, only in this same workspace (not one deleted and set up again at this
            // address), while the admin still is one, and over exactly the connection here when
            // the job recorded it: a newer Add to Slack that finished meanwhile stands.
            let actor = still_admin(db, &admin, via)?;
            let outcome = match (super::same_instance(db, &instance)?, &actor) {
                (false, _) => Err(InstallError::Failed),
                (true, None) => Err(InstallError::NotAdmin),
                (true, Some(_)) => match save_install(db, cfg, &inst, None, &admin, now, &expect)? {
                    Saved::Done(previous) => Ok(previous),
                    Saved::Changed => Err(InstallError::Busy),
                },
            };
            match outcome {
                Ok(previous) => {
                    record_install(db, cfg, job, &inst, actor.unwrap_or_else(slack_actor), now)?;
                    // Switching Slack workspaces: let go of the previous one. If that doesn't
                    // happen, Settings › Slack does it later.
                    if let Some(previous) = previous {
                        release_later(job, &previous, generation);
                    }
                    to_settings(&base, Ok(()))
                }
                Err(error) => {
                    // Not saved: let go of what the directory just recorded, fenced on this job's
                    // value, so it's refused if something newer moved that on. Not if the
                    // connection here names it now (adding it again while something else changed).
                    let named = load(db, cfg)?
                        .is_some_and(|a| super::via_directory(cfg, &a) && a.team_id.as_deref() == Some(inst.team_id.as_str()));
                    if !named {
                        release_later(job, &inst.team_id, generation);
                    }
                    to_settings(&base, Err(error))
                }
            }
        }

        // After Add to Slack: let go of a Slack workspace, if nothing moved this workspace's
        // connection on since. Refused otherwise; then Settings › Slack lets go of leftovers later.
        (Phase::Start, Work::Release { team_id, generation }) => {
            job.phase = Phase::Releasing;
            Ok(Step::Fetch(vec![release_call(&[team_id], generation, false)]))
        }
        (Phase::Releasing, Work::Release { .. }) => ok(),

        // Disconnecting Add to Slack, hosted: the directory lets go first. Nothing is revoked:
        // every install of the shared app into a Slack workspace gets the same token, so a
        // revoke could reach the next holder's.
        (Phase::Start, Work::Disconnect { .. }) => {
            let bound = job.bound.as_ref().is_some_and(|b| b.matches(Some(app)));
            let Some(team) = app.team_id.clone().filter(|_| bound && super::via_directory(cfg, app)) else { return fail(super::changed()) };
            job.version = app.version.clone();
            job.phase = Phase::Asking;
            Ok(Step::Fetch(vec![status_call(Some(&team))]))
        }
        (Phase::Asking, Work::Disconnect { .. }) => {
            let (Some(generation), Some(team)) = (generation_of(&answer), job.bound.as_ref().and_then(|b| b.team_id.clone())) else {
                return fail(not_disconnected());
            };
            job.phase = Phase::Releasing;
            Ok(Step::Fetch(vec![release_call(&[team], generation, false)]))
        }
        (Phase::Releasing, Work::Disconnect { admin, via }) => {
            if answer.status == 409 {
                return fail(super::changed());
            }
            if answer.status != 200 {
                return fail(not_disconnected());
            }
            let team = job.bound.as_ref().and_then(|b| b.team_id.clone()).unwrap_or_default();
            if !forget_connection(db, &team, job.version.as_deref())? {
                return fail(super::changed());
            }
            let actor = crate::model::actor_for_user(db, &admin)?.map(|mut a| {
                a.via = via;
                a
            });
            let mut ctx = job_ctx(db, cfg, &job.base_url.clone(), actor.unwrap_or_else(slack_actor), now);
            emit(&mut ctx, Event::new("slack.disconnected", "settings", "slack", "disconnected Slack").admin_only())?;
            job.effects.extend(std::mem::take(&mut ctx.effects));
            ok()
        }

        // What the directory says this workspace holds. The connection here names one it doesn't:
        // forgotten. Any other it holds is let go of: a switch that stopped before letting go, or an
        // install this workspace never saved.
        (Phase::Start, Work::Status { .. }) => {
            let team = app.team_id.clone().filter(|_| super::via_directory(cfg, app));
            job.version = app.version.clone();
            job.bound = Some(super::Bound { shared: true, team_id: team.clone() });
            job.phase = Phase::Asking;
            Ok(Step::Fetch(vec![status_call(team.as_deref())]))
        }
        (Phase::Asking, Work::Status { admin }) => {
            let status = Some(&answer).filter(|a| a.status == 200).and_then(|a| serde_json::from_str::<SlackStatus>(&a.body).ok());
            let Some(status) = status else {
                return match admin {
                    Some(_) => fail(unreachable_directory()),
                    None => ok(),
                };
            };
            if let Some(team) = job.bound.as_ref().and_then(|b| b.team_id.clone())
                && !status.owned
            {
                forget_stale(db, cfg, job, &team, now)?;
            }
            // Leftovers only (installed long enough ago that no Add to Slack is still finishing),
            // never the one this workspace's Add to Slack connection names (perhaps just saved
            // meanwhile), and only if nothing changed this workspace's connection since the
            // directory answered. A workspace's own app in the same Slack workspace doesn't count:
            // the directory's installation isn't its.
            let named = app.team_id.as_deref().filter(|_| super::via_directory(cfg, app));
            let leftovers: Vec<String> = status.leftovers.iter().filter(|t| named != Some(t.as_str())).cloned().collect();
            job.held = status.owned;
            if leftovers.is_empty() {
                return status_view(db, cfg, job, admin, now);
            }
            job.phase = Phase::Releasing;
            Ok(Step::Fetch(vec![release_call(&leftovers, status.generation, true)]))
        }
        (Phase::Releasing, Work::Status { admin }) => status_view(db, cfg, job, admin, now),

        // A token Slack called dead: forgotten, only while the directory still holds that one.
        (Phase::Start, Work::Forget { team_id, fingerprint }) => {
            job.phase = Phase::Forgetting;
            Ok(Step::Fetch(vec![directory_call("/slack/forget", json!({ "team_id": team_id, "token_fingerprint": fingerprint }))]))
        }
        (Phase::Forgetting, Work::Forget { .. }) => ok(),

        // Off hosted DumbSlab, Slack says the shared app was removed: believe the token, not the
        // event (Slack's events come out of order), and forget only the connection checked.
        (Phase::Start, Work::Check) => {
            let Some(token) = app.bot_token.clone().filter(|_| app.shared && !super::via_directory(cfg, app)) else {
                return answer_slack(200);
            };
            job.version = app.version.clone();
            job.bound = Some(super::Bound::of(app));
            job.phase = Phase::Checking;
            Ok(Step::Fetch(vec![test_call(&token)]))
        }
        (Phase::Checking, Work::Check) => match answer_of(&answer) {
            Answer::Dead => {
                let team = job.bound.as_ref().and_then(|b| b.team_id.clone()).unwrap_or_default();
                if forget_connection(db, &team, job.version.as_deref())? {
                    let mut ctx = job_ctx(db, cfg, &job.base_url.clone(), slack_actor(), now);
                    emit(
                        &mut ctx,
                        Event::new("slack.uninstalled", "settings", "slack", "Slack removed DumbSlab's app, so Slack is disconnected")
                            .data(json!({ "slack_workspace": app.team_name, "slack_workspace_id": app.team_id }))
                            .admin_only(),
                    )?;
                    job.effects.extend(std::mem::take(&mut ctx.effects));
                }
                answer_slack(200)
            }
            Answer::Unknown => answer_slack(500),
            Answer::Ok | Answer::Refused => answer_slack(200),
        },
        (phase, _) => Err(ApiError::internal(format!("Add to Slack can't continue from {phase:?}"))),
    }
}

/// Settings › Slack, from what the directory said (see [`Work::Status`]); without an admin,
/// nothing.
fn status_view(db: &dyn Db, cfg: &HostConfig, job: &mut SlackJob, admin: Option<(String, Via)>, now: DateTime<Utc>) -> ApiResult<Step> {
    let Some((admin, via)) = admin else { return ok() };
    let Some(mut actor) = crate::model::actor_for_user(db, &admin)?.filter(|a| a.role == Role::Admin) else {
        return fail(ApiError::forbidden("only admins can see Slack's settings"));
    };
    actor.via = via;
    let asked = job.bound.as_ref().and_then(|b| b.team_id.clone());
    let saved = load(db, cfg)?.filter(|a| super::via_directory(cfg, a)).and_then(|a| a.team_id);
    let held = job.held && asked.is_some() && saved == asked;
    let ctx = job_ctx(db, cfg, &job.base_url, actor, now);
    let view = crate::ops::slack::settings_view(&ctx, Some(held))?;
    fill(serde_json::to_value(view).map_err(|e| ApiError::internal(e.to_string()))?)
}

/// Who did it, in the activity log, when Slack removed the app or DumbSlab found it gone.
pub(super) fn slack_actor() -> Actor {
    Actor {
        user_id: String::new(),
        name: "Slack".into(),
        handle: String::new(),
        email: String::new(),
        role: Role::Admin,
        scopes: Scopes::ALL,
        via: Via::Slack,
        token_id: None,
        session_hash: None,
    }
}

/// A request signed with the shared app's secret for a Slack workspace this workspace's connection
/// doesn't name. Hosted, the root routed it here, so the directory says this workspace holds it:
/// left over from a switch that stopped before letting go, or an install this workspace never
/// saved. A command says how to connect, everything is acknowledged, and a job asks the directory
/// what this workspace holds and lets go of the rest (see [`Work::Status`]).
pub(super) fn stray(cfg: &HostConfig, base: &str, path: &str, body: &[u8]) -> ApiResult<Outcome> {
    let mut response = Response::json(200, &json!({ "ok": true }));
    if path == COMMANDS_PATH {
        if form(body).get("ssl_check").map(|v| v.trim()) == Some("1") {
            return Ok(crate::http::done(Response::empty(200)));
        }
        response = Response::json(200, &ephemeral(NOT_CONNECTED));
    } else if let Ok(v) = serde_json::from_slice::<Value>(body)
        && v["type"] == "url_verification"
    {
        return Ok(reply(json!({ "challenge": v["challenge"].as_str().unwrap_or_default() })));
    }
    match (team_of(path, body), home(cfg)) {
        (Some(_), Some(_)) => Ok(later(response, SlackJob::status(base, None))),
        _ => Ok(crate::http::done(response)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hmac_sha256_hex;

    const SECRET: &str = "8f742231b10e8888abcd99yyyzzz85a5";

    const NOW: i64 = 1_800_000_000;

    /// A request signed at `at` with `secret`, reaching the root at [`NOW`].
    fn signed(path: &str, body: &str, at: i64, secret: &str) -> Routed {
        let sig = format!("v0={}", hmac_sha256_hex(secret, &format!("v0:{at}:{body}")));
        route(SECRET, path, Some(&at.to_string()), Some(&sig), body.as_bytes(), NOW)
    }

    fn answered(r: Routed) -> (u16, Value) {
        match r {
            Routed::Answer(resp) => {
                assert!(resp.headers.contains(&("cache-control".into(), "no-store".into())));
                (resp.status, serde_json::from_slice(&resp.body).unwrap_or(Value::Null))
            }
            Routed::Forward(team) => panic!("forwarded for {team}"),
            Routed::Uninstalled(team) => panic!("checks an uninstall for {team}"),
        }
    }

    fn forwarded(r: Routed) -> String {
        match r {
            Routed::Forward(team) => team,
            Routed::Answer(resp) => panic!("answered {} {}", resp.status, String::from_utf8_lossy(&resp.body)),
            Routed::Uninstalled(team) => panic!("checks an uninstall for {team}"),
        }
    }

    #[test]
    fn the_root_forwards_signed_requests_by_slack_workspace() {
        let now = NOW;
        // Commands name their Slack workspace in the form.
        let command = "token=x&team_id=T0ACME&team_domain=acme&channel_id=C1&user_id=U1&command=%2Fdumbslab&text=search+x&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT0ACME%2F1%2Fx";
        assert_eq!(forwarded(signed(super::COMMANDS_PATH, command, now, SECRET)), "T0ACME");
        // Events name the installation they're for; the outer team_id otherwise.
        let event = json!({ "type": "event_callback", "team_id": "T0OUTER", "event": { "type": "link_shared" },
            "authorizations": [{ "enterprise_id": null, "team_id": "T0AUTH", "user_id": "U1", "is_bot": true, "is_enterprise_install": false }] });
        assert_eq!(forwarded(signed(super::EVENTS_PATH, &event.to_string(), now, SECRET)), "T0AUTH");
        let bare = json!({ "type": "event_callback", "team_id": "T0OUTER", "event": { "type": "link_shared" } });
        assert_eq!(forwarded(signed(super::EVENTS_PATH, &bare.to_string(), now, SECRET)), "T0OUTER");
        // An org-wide installation's events are never anyone's here.
        let org = json!({ "type": "event_callback", "team_id": "T0OUTER", "event": { "type": "link_shared" },
            "authorizations": [{ "enterprise_id": "E1", "team_id": null, "is_enterprise_install": true }] });
        assert_eq!(answered(signed(super::EVENTS_PATH, &org.to_string(), now, SECRET)), (200, json!({ "ok": true })));

        // Slack's own checks are answered at the root, signed like everything else.
        let check = json!({ "token": "x", "challenge": "3eZbrw1aBm2rZgRNFdxV", "type": "url_verification" }).to_string();
        assert_eq!(answered(signed(super::EVENTS_PATH, &check, now, SECRET)), (200, json!({ "challenge": "3eZbrw1aBm2rZgRNFdxV" })));
        assert_eq!(answered(signed(super::COMMANDS_PATH, "ssl_check=1&token=x", now, SECRET)).0, 200);
        let (status, reply) = answered(signed(super::COMMANDS_PATH, "token=x&user_id=U1&command=%2Fdumbslab", now, SECRET));
        assert_eq!((status, reply["response_type"].as_str()), (200, Some("ephemeral")));
        for odd in ["team_id=T%3Cx%3E&user_id=U1", "team_id=&user_id=U1"] {
            assert_eq!(answered(signed(super::COMMANDS_PATH, odd, now, SECRET)).1["response_type"], "ephemeral", "{odd}");
        }

        // Nothing unsigned, forged or stale gets near a workspace.
        let code = |r: Routed| answered(r).1["error"]["code"].as_str().unwrap_or_default().to_string();
        assert_eq!(code(signed(super::COMMANDS_PATH, command, now, "another-secret")), "bad_signature");
        assert_eq!(code(signed(super::COMMANDS_PATH, command, now - 400, SECRET)), "stale_request");
        assert_eq!(code(route(SECRET, super::COMMANDS_PATH, None, None, command.as_bytes(), now)), "unsigned");
        assert_eq!(answered(signed("/slack/other", command, now, SECRET)).0, 404);
        let big = "x".repeat(MAX_BODY + 1);
        assert_eq!(answered(signed(super::COMMANDS_PATH, &big, now, SECRET)).0, 413);
        assert_eq!(answered(signed(super::EVENTS_PATH, "not json", now, SECRET)).0, 400);
    }

    /// Slack saying the app was removed is checked at the root, never forwarded: only a bot token's
    /// revoke counts, and the token the directory holds is what's checked.
    #[test]
    fn uninstalls_are_checked_at_the_root() {
        let event = |e: Value| {
            json!({ "type": "event_callback", "team_id": "T0ACME", "event": e,
                "authorizations": [{ "team_id": "T0ACME", "is_enterprise_install": false }] })
            .to_string()
        };
        let routed = |e: Value| signed(super::EVENTS_PATH, &event(e), NOW, SECRET);
        assert!(matches!(routed(json!({ "type": "app_uninstalled" })), Routed::Uninstalled(t) if t == "T0ACME"));
        let bot = json!({ "type": "tokens_revoked", "tokens": { "oauth": [], "bot": ["UBOT"] } });
        assert!(matches!(routed(bot), Routed::Uninstalled(t) if t == "T0ACME"));
        let people = json!({ "type": "tokens_revoked", "tokens": { "oauth": ["U1"], "bot": [] } });
        assert_eq!(answered(routed(people)), (200, json!({ "ok": true })));

        let cfg = HostConfig { connectors: connect::Connectors { key: Some("k".into()), ..Default::default() }, ..Default::default() };
        let row = |token: &str| {
            let sealed = seal_for_directory(&cfg, "T0ACME", token).unwrap();
            HttpReply { status: 200, body: json!({ "bot_token": sealed, "token_fingerprint": "fp-1" }).to_string() }
        };
        let slack = |v: Value| HttpReply { status: 200, body: v.to_string() };
        let fetch = |s: CheckStep| match s {
            CheckStep::Fetch(call) => call,
            CheckStep::Done(r) => panic!("done with {}", r.status),
        };
        let status = |s: CheckStep| match s {
            CheckStep::Done(r) => r.status,
            CheckStep::Fetch(call) => panic!("fetches {}", call.url),
        };
        // Dead: forgotten by the token's fingerprint.
        let (mut check, first) = UninstallCheck::start("T0ACME");
        assert_eq!((first.url.as_str(), first.headers.iter().any(|(k, _)| k == "authorization")), ("dumbslab-directory:/slack/row", false));
        let test = fetch(check.next(Some("k"), &row("xoxb-live")));
        assert_eq!(test.url, "https://slack.com/api/auth.test");
        assert!(test.headers.contains(&("authorization".into(), "Bearer xoxb-live".into())));
        let forget = fetch(check.next(Some("k"), &slack(json!({ "ok": false, "error": "invalid_auth" }))));
        assert_eq!(forget.url, "dumbslab-directory:/slack/forget");
        let body: Value = serde_json::from_str(forget.body.as_deref().unwrap()).unwrap();
        assert_eq!(body, json!({ "team_id": "T0ACME", "token_fingerprint": "fp-1" }));
        assert_eq!(status(check.next(Some("k"), &slack(json!({ "ok": true })))), 200);
        // Still working (the event was about an earlier install): kept.
        let (mut check, _) = UninstallCheck::start("T0ACME");
        fetch(check.next(Some("k"), &row("xoxb-live")));
        assert_eq!(status(check.next(Some("k"), &slack(json!({ "ok": true, "team_id": "T0ACME" })))), 200);
        // Nobody holds it: nothing to do.
        let (mut check, _) = UninstallCheck::start("T0ACME");
        assert_eq!(status(check.next(Some("k"), &HttpReply { status: 404, body: "{}".into() })), 200);
        // Unclear answers have Slack send the event again.
        let (mut check, _) = UninstallCheck::start("T0ACME");
        fetch(check.next(Some("k"), &row("xoxb-live")));
        assert_eq!(status(check.next(Some("k"), &HttpReply::default())), 500);
        let (mut check, _) = UninstallCheck::start("T0ACME");
        fetch(check.next(Some("k"), &row("xoxb-live")));
        fetch(check.next(Some("k"), &slack(json!({ "ok": false, "error": "token_revoked" }))));
        assert_eq!(status(check.next(Some("k"), &HttpReply::default())), 500, "the forget wasn't heard");
        let (mut check, _) = UninstallCheck::start("T0ACME");
        assert_eq!(status(check.next(Some("k"), &HttpReply::default())), 500, "the directory didn't answer");
        let (mut check, _) = UninstallCheck::start("T0ACME");
        assert_eq!(status(check.next(Some("another-key"), &row("xoxb-live"))), 500, "a token it can't open");
    }

    #[test]
    fn unknown_slack_workspaces_hear_how_to_connect() {
        let command = unknown_team(super::COMMANDS_PATH);
        let reply: Value = serde_json::from_slice(&command.body).unwrap();
        assert_eq!(reply["response_type"], "ephemeral");
        assert!(reply["text"].as_str().unwrap().contains("Settings › Slack"), "{reply}");
        let event: Value = serde_json::from_slice(&unknown_team(super::EVENTS_PATH).body).unwrap();
        assert_eq!(event, json!({ "ok": true }));
    }

    #[test]
    fn the_shared_manifest_points_at_the_root() {
        let m = shared_manifest("https://dumbslab.com/");
        assert_eq!(m["display_information"]["name"], "DumbSlab");
        assert!(m["display_information"]["description"].as_str().unwrap().chars().count() <= 140);
        assert_eq!(m["features"]["bot_user"]["display_name"], "dumbslab");
        assert_eq!(m["features"]["slash_commands"][0]["command"], "/dumbslab");
        assert_eq!(m["features"]["slash_commands"][0]["url"], "https://dumbslab.com/slack/commands");
        assert_eq!(m["features"]["unfurl_domains"], json!(["dumbslab.com"]));
        assert_eq!(
            m["oauth_config"]["redirect_urls"],
            json!([
                "https://dumbslab.com/connect/callback",
                "https://dumbslab.com/sso/callback",
                "https://dumbslab.com/slack/install/callback"
            ])
        );
        assert_eq!(m["oauth_config"]["scopes"]["bot"], json!(SCOPES));
        assert_eq!(m["oauth_config"]["scopes"]["user"], json!(["search:read", "openid", "email", "profile"]));
        assert_eq!(m["settings"]["event_subscriptions"]["request_url"], "https://dumbslab.com/slack/events");
        assert_eq!(m["settings"]["event_subscriptions"]["bot_events"], json!(["link_shared", "app_uninstalled", "tokens_revoked"]));
        assert_eq!((&m["settings"]["org_deploy_enabled"], &m["settings"]["token_rotation_enabled"]), (&json!(false), &json!(false)));

        let link = create_app_link(&m);
        let encoded = link.strip_prefix("https://api.slack.com/apps?new_app=1&manifest_json=").expect("Slack's create link");
        assert!(!encoded.contains(['{', '"', ' ', '&', '#']), "{encoded}");
        let back: Value = serde_json::from_str(&urlencoding::decode(encoded).unwrap()).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn exchanges_read_one_slack_workspace() {
        let reply = |v: Value| HttpReply { status: 200, body: v.to_string() };
        let ok = json!({ "ok": true, "access_token": "xoxb-test-bot-token", "token_type": "bot",
            "scope": "commands,chat:write", "bot_user_id": "U0KRQLJ9H", "app_id": "A0KRD7HC3",
            "team": { "name": "Slack Softball Team", "id": "T9TK3CUKW" }, "enterprise": null, "is_enterprise_install": false,
            "authed_user": { "id": "U1234" } });
        let Exchange::Installed(i) = read_exchange(&reply(ok.clone())) else { panic!("installed") };
        assert_eq!((i.team_id.as_str(), i.team_name.as_str(), i.bot_user_id.as_str()), ("T9TK3CUKW", "Slack Softball Team", "U0KRQLJ9H"));
        assert_eq!(i.scopes, vec!["commands", "chat:write"]);
        let mut org = ok.clone();
        org["is_enterprise_install"] = json!(true);
        org["team"] = Value::Null;
        assert!(matches!(read_exchange(&reply(org)), Exchange::Enterprise));
        for broken in [
            json!({ "ok": false, "error": "invalid_code" }),
            json!({ "ok": true, "access_token": "xoxp-user", "token_type": "user", "team": { "id": "T1" } }),
            json!({ "ok": true, "access_token": "xoxb-1", "token_type": "bot", "team": { "id": "T<1>" } }),
            json!({ "ok": true, "access_token": "xoxb-1", "token_type": "bot" }),
        ] {
            assert!(matches!(read_exchange(&reply(broken.clone())), Exchange::Failed), "{broken}");
        }
        assert!(matches!(read_exchange(&HttpReply::default()), Exchange::Failed));
    }

    #[test]
    fn install_errors_are_codes() {
        let codes: Vec<&str> = InstallError::ALL.iter().map(|e| e.code()).collect();
        let mut unique = codes.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), codes.len());
        assert!(codes.iter().all(|c| c.chars().all(|ch| ch.is_ascii_lowercase() || ch == '_')));
        assert_eq!(
            settings_url("https://kb.test", Err(InstallError::TeamTaken)),
            "https://kb.test/settings/slack?slack_error=slack_team_taken"
        );
        assert_eq!(settings_url("https://kb.test", Ok(())), "https://kb.test/settings/slack?slack=connected");
    }
}
