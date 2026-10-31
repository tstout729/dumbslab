//! Add to Slack: the host's own Slack app, which an admin connects with one click, and hosted
//! DumbSlab's routing of that app's requests through the root domain. See the parent module for
//! the whole picture and Slack's docs.

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};

use super::{
    API, App, BOT_TOKEN, COMMANDS_PATH, CREATE_APP_URL, CREATE_SHARED_APP_PATH, DIRECTORY, EVENTS_PATH, INSTALL_CALLBACK_PATH, MAX_BODY,
    Phase, SCOPES, SHARED_EVENTS, SlackJob, USER_SCOPES, Work, ephemeral, fill, form, job_ctx, key, later, load, refused, reply, seal,
    slack_error, unseal, valid_id, verify,
};
use crate::auth::{Actor, Role, Scopes, Via};
use crate::connect::{self, Finish, HttpCall, HttpReply, Step};
use crate::db::{Db, DbExt};
use crate::error::{ApiError, ApiResult};
use crate::events::{Event, emit};
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
    /// Another Add to Slack is finishing, or DumbSlab is still revoking the token Slack just gave
    /// again (a Disconnect a moment ago).
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
        db.execute("DELETE FROM slack_installs WHERE created_at < ?", &params![ts(now - Duration::minutes(INSTALL_MINUTES))])?;
        let random = crate::util::new_secret("");
        let state = match &cfg.workspace {
            Some(address) => format!("{address}.{random}"),
            None => random,
        };
        db.execute(
            "INSERT INTO slack_installs (state_hash, user_id, session_hash, created_at) VALUES (?, ?, ?, ?)",
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
/// that exchanges the code for the bot token, claims the Slack workspace (hosted) and saves it, then
/// sends them to Settings › Slack.
pub fn install_callback(db: &dyn Db, cfg: &HostConfig, req: &Request) -> Outcome {
    let base = crate::http::base_url(cfg, req);
    let query = query_map(&req.query);
    let now = Utc::now();
    let run = || -> ApiResult<Outcome> {
        let state_hash = sha256_hex(query.get("state").map(String::as_str).unwrap_or_default());
        let Some(row) =
            db.one("SELECT user_id, session_hash, created_at FROM slack_installs WHERE state_hash = ?", &params![state_hash.clone()])?
        else {
            return Ok(back(&base, Err(InstallError::Expired)));
        };
        // Each link works once.
        db.execute("DELETE FROM slack_installs WHERE state_hash = ?", &params![state_hash])?;
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
    /// An org-wide install: refused, and its token (when Slack gave one) revoked.
    Enterprise(Option<String>),
    Failed,
}

/// Reads `oauth.v2.access`'s answer: a bot token for one Slack workspace.
fn read_exchange(reply: &HttpReply) -> Exchange {
    if slack_error(reply).is_some() {
        return Exchange::Failed;
    }
    let v = reply.json();
    let token = connect::opt(&v["access_token"]);
    if v["is_enterprise_install"] == true {
        return Exchange::Enterprise(token);
    }
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

/// What Slack's answer to `auth.revoke` or `auth.test` says about a token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Answer {
    /// It works (`auth.test`), or Slack revoked it just now (`auth.revoke`).
    Ok,
    /// Slack says it's no good: revoked already, or the install is gone.
    Dead,
    /// Slack answered with some other error: it did nothing, and nothing of it is under way.
    Refused,
    /// No answer, a rate limit or a server error: Slack may or may not have acted on it.
    Unknown,
}

fn answer_of(reply: &HttpReply) -> Answer {
    match slack_error(reply).as_deref() {
        None => Answer::Ok,
        Some("invalid_auth" | "not_authed" | "token_revoked" | "token_expired" | "account_inactive") => Answer::Dead,
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

fn revoke_call(token: &str) -> HttpCall {
    HttpCall::post_form(format!("{API}/auth.revoke"), &[]).bearer(token)
}

fn test_call(token: &str) -> HttpCall {
    HttpCall::post_form(format!("{API}/auth.test"), &[]).bearer(token)
}

/// A call to hosted DumbSlab's directory (see [`DIRECTORY`]).
fn directory_call(path: &str, team_id: &str, home: &str, claim: Option<&str>) -> HttpCall {
    HttpCall::post_json(format!("{DIRECTORY}{path}"), &json!({ "team_id": team_id, "home": home, "claim": claim }))
}

// ---------------------------------------------------------------------------
// Tokens waiting to be revoked

/// A shared-app bot token waiting in `slack_releases`. Never printed.
#[derive(Clone)]
pub(super) struct Pending {
    team_id: String,
    /// The row's encrypted token, which names the row: a newer token for the same Slack workspace
    /// replaces the row, and work on the old one then changes nothing.
    sealed: String,
    token: String,
}

impl Pending {
    #[cfg(test)]
    pub(super) fn new(team_id: &str, sealed: &str, token: &str) -> Pending {
        Pending { team_id: team_id.into(), sealed: sealed.into(), token: token.into() }
    }
}

/// How long an install may take between claiming and saving before another may start.
const INSTALL_LOCK_SECS: i64 = 60;

/// Hosted: lets one Add to Slack at a time go from claiming to saving. `false` while another holds it.
fn lock(db: &dyn Db, job: &str, now: DateTime<Utc>) -> ApiResult<bool> {
    let taken = db.execute(
        "INSERT INTO slack_install_lock (id, job, until) VALUES (1, ?, ?)
         ON CONFLICT(id) DO UPDATE SET job = excluded.job, until = excluded.until WHERE slack_install_lock.until <= ?",
        &params![job, ts(now + Duration::seconds(INSTALL_LOCK_SECS)), ts(now)],
    )?;
    Ok(taken > 0)
}

fn unlock(db: &dyn Db, job: &SlackJob) -> ApiResult<()> {
    if let Some(claim) = &job.claim {
        db.execute("DELETE FROM slack_install_lock WHERE id = 1 AND job = ?", &params![claim.clone()])?;
    }
    Ok(())
}

/// How long one job may take revoking a token before another may try.
const REVOKE_LEASE_SECS: i64 = 60;

struct PendingRow {
    pending: Pending,
    claim: Option<String>,
    /// A job is revoking it now.
    revoking: bool,
}

fn pending_row(db: &dyn Db, cfg: &HostConfig, team_id: &str, now: DateTime<Utc>) -> ApiResult<Option<PendingRow>> {
    let Some(r) = db.one("SELECT bot_token, claim, revoking_until FROM slack_releases WHERE team_id = ?", &params![team_id])? else {
        return Ok(None);
    };
    let sealed = r.str("bot_token");
    let Some(token) = unseal(cfg, BOT_TOKEN, &sealed) else {
        // A token this server can't read any more (its connector key changed) can't be revoked:
        // forget it, and let a stale claim go the usual way.
        db.execute("DELETE FROM slack_releases WHERE team_id = ? AND bot_token = ?", &params![team_id, sealed])?;
        return Ok(None);
    };
    Ok(Some(PendingRow {
        pending: Pending { team_id: team_id.to_string(), sealed, token },
        claim: r.opt_str("claim"),
        revoking: r.opt_str("revoking_until").is_some_and(|until| until > ts(now)),
    }))
}

/// Puts a shared-app bot token in line to be revoked, then its claim let go of.
pub(crate) fn add_pending(
    db: &dyn Db,
    cfg: &HostConfig,
    team_id: &str,
    token: &str,
    claim: Option<&str>,
    now: DateTime<Utc>,
) -> ApiResult<()> {
    db.execute(
        "INSERT INTO slack_releases (team_id, bot_token, claim, created_at) VALUES (?, ?, ?, ?)
         ON CONFLICT(team_id) DO UPDATE SET bot_token = excluded.bot_token, claim = excluded.claim, revoking_until = NULL,
           created_at = excluded.created_at",
        &params![team_id, seal(cfg, BOT_TOKEN, token)?, claim, ts(now)],
    )?;
    Ok(())
}

/// The Slack workspaces whose bot tokens wait to be revoked.
pub(crate) fn pending_teams(db: &dyn Db) -> ApiResult<Vec<String>> {
    Ok(db.query("SELECT team_id FROM slack_releases ORDER BY created_at", &[])?.iter().map(|r| r.str("team_id")).collect())
}

fn lease(db: &dyn Db, p: &Pending, until: Option<DateTime<Utc>>) -> ApiResult<()> {
    db.execute(
        "UPDATE slack_releases SET revoking_until = ? WHERE team_id = ? AND bot_token = ?",
        &params![until.map(ts), p.team_id.clone(), p.sealed.clone()],
    )?;
    Ok(())
}

fn drop_pending(db: &dyn Db, p: &Pending) -> ApiResult<()> {
    db.execute("DELETE FROM slack_releases WHERE team_id = ? AND bot_token = ?", &params![p.team_id.clone(), p.sealed.clone()])?;
    Ok(())
}

/// How saving an install went.
enum Saved {
    /// Saved. Holds the previous Slack workspace, whose token now waits to be revoked.
    Done(Option<String>),
    /// A revoke of this very token is under way (a Disconnect a moment ago): saving it now could
    /// leave a dead token.
    Busy,
}

/// Saves what Add to Slack gave, as the admin who did it, replacing whatever app was connected;
/// another Slack workspace's channels go with it. The shared app's previous bot token, for another
/// Slack workspace, waits to be revoked (its claim stays until then).
fn save_install(db: &dyn Db, cfg: &HostConfig, job: &mut SlackJob, inst: &Installed, actor: Actor, now: DateTime<Utc>) -> ApiResult<Saved> {
    if let Some(row) = pending_row(db, cfg, &inst.team_id, now)? {
        if row.pending.token == inst.token && row.revoking {
            // The revoking job lets go of this install's claim along with its own.
            db.execute("UPDATE slack_releases SET claim = ? WHERE team_id = ?", &params![job.claim.clone(), inst.team_id.clone()])?;
            return Ok(Saved::Busy);
        }
        // Nothing is revoking it any more, or it's an earlier token (dead: Slack gave a new one).
        // This install takes over; the waiting release is called off.
        drop_pending(db, &row.pending)?;
    }
    let old = load(db, cfg)?;
    let moved_on = old.as_ref().and_then(|a| a.team_id.as_deref()).is_some_and(|t| t != inst.team_id);
    db.execute("INSERT INTO slack_app (id, updated_at) VALUES (1, ?) ON CONFLICT(id) DO NOTHING", &params![ts(now)])?;
    if moved_on {
        // Channel IDs belong to one Slack workspace.
        db.execute("DELETE FROM slack_channels", &[])?;
    }
    db.execute(
        "UPDATE slack_app SET bot_token = ?, signing_secret = NULL, team_id = ?, team_name = ?, bot_user_id = ?, scopes = ?, shared = 1,
           generation = generation + 1, claim = ?, updated_by = ?, updated_at = ? WHERE id = 1",
        &params![
            seal(cfg, BOT_TOKEN, &inst.token)?,
            inst.team_id.clone(),
            inst.team_name.clone(),
            Some(inst.bot_user_id.clone()).filter(|b| !b.is_empty()),
            inst.scopes.join(","),
            job.claim.clone(),
            actor.user_id.clone(),
            ts(now)
        ],
    )?;
    let mut ctx = job_ctx(db, cfg, &job.base_url, actor, now);
    let name = if inst.team_name.is_empty() { "a Slack workspace".to_string() } else { inst.team_name.clone() };
    emit(
        &mut ctx,
        Event::new("slack.installed", "settings", "slack", format!("added DumbSlab to {name} in Slack"))
            .data(json!({ "slack_workspace": inst.team_name, "slack_workspace_id": inst.team_id }))
            .admin_only(),
    )?;
    job.effects.extend(std::mem::take(&mut ctx.effects));
    // The shared app's previous Slack workspace: revoke its token, then let go of it.
    let previous = old.filter(|a| a.shared && moved_on);
    if let Some((team, token)) = previous.as_ref().and_then(|a| Some((a.team_id.clone()?, a.bot_token.clone()?))) {
        add_pending(db, cfg, &team, &token, previous.as_ref().and_then(|a| a.claim.as_deref()), now)?;
        return Ok(Saved::Done(Some(team)));
    }
    Ok(Saved::Done(None))
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

/// With the shared app, whether a request is for the Slack workspace this workspace holds. Only
/// Slack's own URL and certificate checks may name none.
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
    /// Send it, as it came, to the workspace that claimed this Slack workspace (and answer with
    /// [`unknown_team`] when none did). The workspace checks the signature again: it remembers the
    /// signatures it has seen.
    Forward(String),
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
    match (v["type"].as_str(), team_of(path, body)) {
        (Some("url_verification"), _) => answer(Response::json(200, &json!({ "challenge": v["challenge"].as_str().unwrap_or_default() }))),
        (Some("event_callback"), Some(team)) => Routed::Forward(team),
        _ => answer(Response::json(200, &json!({ "ok": true }))),
    }
}

/// The root's answer for a Slack workspace no DumbSlab workspace claimed: a command says how to
/// connect it, only to the person who typed it; an event is acknowledged and dropped.
pub fn unknown_team(path: &str) -> Response {
    let body = match path {
        COMMANDS_PATH => ephemeral(NOT_CONNECTED),
        _ => json!({ "ok": true }),
    };
    Response::json(200, &body).with_header("cache-control", "no-store")
}

const NOT_CONNECTED: &str = "This Slack workspace isn't connected to DumbSlab yet. A DumbSlab admin can connect it: open Settings › Slack in your DumbSlab workspace and click *Add to Slack*.";

fn to_settings(base_url: &str, outcome: Result<(), InstallError>) -> ApiResult<Step> {
    Ok(Step::Done(Finish::Redirect(settings_url(base_url, outcome))))
}

fn still_admin(db: &dyn Db, user_id: &str, via: Via) -> ApiResult<Option<Actor>> {
    Ok(crate::model::actor_for_user(db, user_id)?.filter(|a| a.role == Role::Admin).map(|mut a| {
        a.via = via;
        a
    }))
}

/// The directory call that undoes an install's claim: the claim this workspace had for that Slack
/// workspace goes back, or, when it had none, the install's own is let go of. `None` before the
/// install claimed anything, and off hosted DumbSlab.
pub(super) fn undo_claim(job: &SlackJob) -> Option<HttpCall> {
    let (Work::Install { home: Some(home), .. }, Some(inst), Some(claim)) = (&job.work, &job.installed, &job.claim) else { return None };
    Some(match &job.restore {
        Some(old) => directory_call("/slack/claim", &inst.team_id, home, Some(old)),
        None => directory_call("/slack/release", &inst.team_id, home, Some(claim)),
    })
}

/// Undoes the install's claim, then sends the admin to Settings with `error`.
fn undo(job: &mut SlackJob, error: InstallError) -> ApiResult<Step> {
    let base = job.base_url.clone();
    let Some(call) = undo_claim(job) else { return to_settings(&base, Err(error)) };
    job.then = Some(settings_url(&base, Err(error)));
    job.phase = Phase::Undoing;
    Ok(Step::Fetch(vec![call]))
}

/// Saves Add to Slack's install and sends the admin to Settings › Slack. The previous Slack
/// workspace's token is revoked after the answer, by a job of its own.
fn finish_install(
    db: &dyn Db,
    cfg: &HostConfig,
    job: &mut SlackJob,
    inst: &Installed,
    actor: Actor,
    now: DateTime<Utc>,
) -> ApiResult<Step> {
    let base = job.base_url.clone();
    let saved = save_install(db, cfg, job, inst, actor, now)?;
    unlock(db, job)?;
    match saved {
        Saved::Done(previous) => {
            if let Some(team) = previous {
                job.effects.push(Effect::Background(connect::Job::Slack(SlackJob::release(&base, &team))));
            }
            to_settings(&base, Ok(()))
        }
        // The claim stays: the revoke under way lets go of it once Slack has answered.
        Saved::Busy => to_settings(&base, Err(InstallError::Busy)),
    }
}

/// Runs Add to Slack's job, and the ones that revoke a token and check one (see [`super::step`]).
pub(super) fn step(db: &dyn Db, cfg: &HostConfig, job: &mut SlackJob, app: &App, answer: HttpReply, now: DateTime<Utc>) -> ApiResult<Step> {
    let ok = || fill(json!({ "ok": true }));
    match (job.phase, job.work.clone()) {
        // Add to Slack: exchange the code, claim the Slack workspace (hosted), save.
        (Phase::Start, Work::Install { code, redirect_uri, .. }) => {
            let base = job.base_url.clone();
            let Some(app) = shared(cfg) else { return to_settings(&base, Err(InstallError::Unavailable)) };
            // Basic auth, as Slack prefers, with the client's credentials form-encoded first (RFC 6749, 2.3.1).
            let call =
                HttpCall::post_form(format!("{API}/oauth.v2.access"), &[("code", code.as_str()), ("redirect_uri", redirect_uri.as_str())])
                    .basic(&urlencoding::encode(app.client_id), &urlencoding::encode(app.client_secret));
            job.phase = Phase::Exchanging;
            Ok(Step::Fetch(vec![call]))
        }
        (Phase::Exchanging, Work::Install { admin, via, home, .. }) => {
            let base = job.base_url.clone();
            let inst = match read_exchange(&answer) {
                Exchange::Installed(i) => i,
                Exchange::Failed => return to_settings(&base, Err(InstallError::Failed)),
                // Nobody here can hold an org-wide install (nothing claims one), so its token goes.
                Exchange::Enterprise(token) => {
                    let Some(token) = token else { return to_settings(&base, Err(InstallError::EnterpriseInstall)) };
                    job.then = Some(settings_url(&base, Err(InstallError::EnterpriseInstall)));
                    job.pending = Some(Pending { team_id: String::new(), sealed: String::new(), token: token.clone() });
                    job.attempt = 1;
                    job.phase = Phase::Revoking;
                    return Ok(Step::Fetch(vec![revoke_call(&token)]));
                }
            };
            // The admin may have lost the role while Slack answered.
            let Some(actor) = still_admin(db, &admin, via)? else { return to_settings(&base, Err(InstallError::NotAdmin)) };
            let Some(home) = home else { return finish_install(db, cfg, job, &inst, actor, now) };
            // One Slack workspace belongs to one DumbSlab workspace: the directory says whether this
            // one may have it. The claim's id is this install's; a failure puts back the one this
            // workspace had, if it held this Slack workspace already.
            let claim = crate::util::new_id();
            // One install at a time from here to the save: two at once could each claim, and the
            // one that saved first would hold a claim the directory no longer has.
            if !lock(db, &claim, now)? {
                return to_settings(&base, Err(InstallError::Busy));
            }
            job.restore = app.claim.clone().filter(|_| app.shared && app.team_id.as_deref() == Some(inst.team_id.as_str()));
            let call = directory_call("/slack/claim", &inst.team_id, &home, Some(&claim));
            job.claim = Some(claim);
            job.installed = Some(inst);
            job.phase = Phase::Claiming;
            Ok(Step::Fetch(vec![call]))
        }
        (Phase::Claiming, Work::Install { admin, via, .. }) => {
            let base = job.base_url.clone();
            let Some(inst) = job.installed.clone() else { return to_settings(&base, Err(InstallError::Failed)) };
            match answer.status {
                200 => {}
                // Nothing was claimed. That Slack workspace's token is the other workspace's: it stays.
                409 => {
                    unlock(db, job)?;
                    return to_settings(&base, Err(InstallError::TeamTaken));
                }
                // The claim may or may not have been made.
                _ => return undo(job, InstallError::Failed),
            }
            let Some(actor) = still_admin(db, &admin, via)? else { return undo(job, InstallError::NotAdmin) };
            // A failure from here on (the save refused, say) undoes the claim: see `failure_notice`.
            finish_install(db, cfg, job, &inst, actor, now)
        }
        (Phase::Undoing, Work::Install { .. }) => {
            unlock(db, job)?;
            let then = job.then.take().unwrap_or_else(|| settings_url(&job.base_url, Err(InstallError::Failed)));
            Ok(Step::Done(Finish::Redirect(then)))
        }
        // An org-wide install's token: tried once more when Slack's answer was unclear.
        (Phase::Revoking, Work::Install { .. }) => {
            if let Some(p) = job.pending.clone().filter(|_| answer_of(&answer) == Answer::Unknown && job.attempt < 2) {
                job.attempt += 1;
                return Ok(Step::Fetch(vec![revoke_call(&p.token)]));
            }
            let then = job.then.take().unwrap_or_else(|| settings_url(&job.base_url, Err(InstallError::Failed)));
            Ok(Step::Done(Finish::Redirect(then)))
        }

        // Revoke a waiting token, then let go of the claim: in that order, so no other workspace
        // can be given this token while a revoke of it might still land.
        (Phase::Start, Work::Release { team_id }) => {
            let row = pending_row(db, cfg, &team_id, now)?;
            // This workspace holds that Slack workspace again: its token and claim are in use. The
            // waiting token is called off unless a revoke of another (earlier) token is under way.
            if app.shared && app.team_id.as_deref() == Some(team_id.as_str()) {
                if let Some(r) = row.filter(|r| !r.revoking || app.bot_token.as_deref() == Some(r.pending.token.as_str())) {
                    drop_pending(db, &r.pending)?;
                }
                return ok();
            }
            let Some(row) = row else {
                // No token waits: a claim may still point here for a Slack workspace this workspace
                // doesn't hold. Only a stale one goes (an install between claiming and saving keeps its).
                return match home(cfg) {
                    Some(home) => {
                        job.phase = Phase::Releasing;
                        Ok(Step::Fetch(vec![directory_call("/slack/release", &team_id, home, None)]))
                    }
                    None => ok(),
                };
            };
            if row.revoking {
                return ok();
            }
            lease(db, &row.pending, Some(now + Duration::seconds(REVOKE_LEASE_SECS)))?;
            let call = revoke_call(&row.pending.token);
            job.pending = Some(row.pending);
            job.attempt = 1;
            job.phase = Phase::Revoking;
            Ok(Step::Fetch(vec![call]))
        }
        (Phase::Revoking, Work::Release { team_id }) => {
            let Some(p) = job.pending.clone() else { return ok() };
            if answer_of(&answer) == Answer::Unknown {
                // Slack may or may not have revoked it, so the claim stays. One more try now; after
                // that, Disconnect, Add to Slack or Slack's next request for this Slack workspace
                // tries again.
                if job.attempt < 2 {
                    job.attempt += 1;
                    lease(db, &p, Some(now + Duration::seconds(REVOKE_LEASE_SECS)))?;
                    return Ok(Step::Fetch(vec![revoke_call(&p.token)]));
                }
                lease(db, &p, None)?;
                return fill(json!({ "ok": false }));
            }
            // Slack answered: no revoke of this token is under way any more. The row may have been
            // replaced or called off meanwhile; then there's nothing more to do.
            let Some(row) = pending_row(db, cfg, &team_id, now)?.filter(|r| r.pending.sealed == p.sealed) else { return ok() };
            match (home(cfg), row.claim) {
                (Some(home), Some(claim)) => {
                    job.phase = Phase::Releasing;
                    Ok(Step::Fetch(vec![directory_call("/slack/release", &team_id, home, Some(&claim))]))
                }
                _ => {
                    drop_pending(db, &p)?;
                    ok()
                }
            }
        }
        (Phase::Releasing, Work::Release { .. }) => {
            if let Some(p) = &job.pending {
                // Let go: done. Not: the token stays in line (revoked already) for the next try.
                if answer.status == 200 { drop_pending(db, p)? } else { lease(db, p, None)? }
            }
            ok()
        }

        // Slack says the shared app was removed, or its token revoked: believe the token, not the
        // event's time.
        (Phase::Start, Work::Check { generation }) => {
            let Some(token) = app.bot_token.clone().filter(|_| app.shared && app.generation == generation) else { return ok() };
            job.attempt = 1;
            job.phase = Phase::Testing;
            Ok(Step::Fetch(vec![test_call(&token)]))
        }
        (Phase::Testing, Work::Check { generation }) => {
            if app.generation != generation || !app.shared {
                return ok();
            }
            match answer_of(&answer) {
                Answer::Unknown if job.attempt < 2 => {
                    let Some(token) = app.bot_token.clone() else { return ok() };
                    job.attempt += 1;
                    Ok(Step::Fetch(vec![test_call(&token)]))
                }
                Answer::Dead => {
                    // Only the install the event arrived for: a newer one is left alone.
                    let gone = db.execute("DELETE FROM slack_app WHERE id = 1 AND shared = 1 AND generation = ?", &params![generation])?;
                    if gone == 0 {
                        return ok();
                    }
                    db.execute("DELETE FROM slack_channels", &[])?;
                    let mut ctx = job_ctx(db, cfg, &job.base_url.clone(), slack_actor(), now);
                    emit(
                        &mut ctx,
                        Event::new("slack.uninstalled", "settings", "slack", "Slack removed DumbSlab's app, so Slack is disconnected")
                            .data(json!({ "slack_workspace": app.team_name, "slack_workspace_id": app.team_id }))
                            .admin_only(),
                    )?;
                    job.effects.extend(std::mem::take(&mut ctx.effects));
                    // The token is dead, so nothing can revoke it later: the claim can go now.
                    match (home(cfg), app.team_id.clone(), app.claim.clone()) {
                        (Some(home), Some(team), Some(claim)) => {
                            job.phase = Phase::Releasing;
                            Ok(Step::Fetch(vec![directory_call("/slack/release", &team, home, Some(&claim))]))
                        }
                        _ => ok(),
                    }
                }
                // It works (the event was about an earlier install), or Slack's answer is unclear:
                // keep it. An admin can still disconnect.
                _ => ok(),
            }
        }
        (Phase::Releasing, Work::Check { .. }) => ok(),
        (phase, _) => Err(ApiError::internal(format!("Add to Slack can't continue from {phase:?}"))),
    }
}

/// Who did it, in the activity log, when Slack removed the app.
fn slack_actor() -> Actor {
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

/// A request signed with the shared app's secret for a Slack workspace this workspace doesn't hold:
/// the directory's claim still points here (a token waiting to be revoked, or letting go failed).
/// A command says how to connect, everything is acknowledged, and a job revokes the waiting token
/// and lets go of the claim, so the root stops sending its requests here.
pub(super) fn stray(db: &dyn Db, cfg: &HostConfig, base: &str, path: &str, body: &[u8]) -> ApiResult<Outcome> {
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
    let Some(team) = team_of(path, body) else { return Ok(crate::http::done(response)) };
    if home(cfg).is_some() || pending_teams(db)?.contains(&team) {
        return Ok(later(response, SlackJob::release(base, &team)));
    }
    Ok(crate::http::done(response))
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
        }
    }

    fn forwarded(r: Routed) -> String {
        match r {
            Routed::Forward(team) => team,
            Routed::Answer(resp) => panic!("answered {} {}", resp.status, String::from_utf8_lossy(&resp.body)),
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
        let bare = json!({ "type": "event_callback", "team_id": "T0OUTER", "event": { "type": "app_uninstalled" } });
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
        assert!(matches!(read_exchange(&reply(org)), Exchange::Enterprise(Some(t)) if t.starts_with("xoxb-")));
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
