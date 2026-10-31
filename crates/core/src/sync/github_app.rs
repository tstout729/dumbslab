//! DumbSlab's own GitHub App, so docs sync needs no token and no webhook setup. An admin chooses
//! **Connect GitHub**, installs the App on the repositories they choose, comes back, and picks one.
//! Pushes then sync through the App's own webhook.
//!
//! - **Settings** ([`GitHubApp`]): the host's `GITHUB_APP_*` values (`DUMBSLAB_GITHUB_APP_*`
//!   self-hosted). The private key never goes into a workspace's database.
//! - **Installing** ([`install_start`], [`install_callback`]): `GET /sync/github/install` records a
//!   hashed, single-use state bound to the admin's browser session and sends them to GitHub. The App
//!   asks for user authorization during installation, so GitHub sends them back to the callback with
//!   a `code`. GitHub's `installation_id` there can be forged by anyone, so it's never trusted on its
//!   own: the code is exchanged for the installer's own token, and the installation must be one their
//!   GitHub account can access (`GET /user/installations`).
//! - **Which repositories.** One installation can serve several workspaces (two admins of one GitHub
//!   organization, say). A workspace may only sync repositories its own admin's GitHub account can
//!   read in the installation (`GET /user/installations/{id}/repositories`), read when they connect
//!   and kept in `github_repositories`. The picker lists those, not everything the installation can
//!   see. Connecting again refreshes the list.
//! - **Tokens.** Each sync signs a fresh App JWT ([`jwt`]) and mints an installation token scoped to
//!   the source's one repository, read-only ([`token_call`]). Tokens live only in the running job.
//! - **Webhooks.** GitHub sends every installation's events to one address. Hosted DumbSlab's root
//!   domain checks the signature ([`route_delivery`]) and forwards each delivery to the workspaces
//!   that connected its installation (the directory's `github_installations`); a self-hosted server
//!   gets it directly. Each workspace checks the signature again ([`hook`]) and acts only on
//!   installations it connected: a push syncs the sources on that repository and branch, and an
//!   uninstall, suspension or removed repository marks the affected sources disconnected (posts stay).
//!   Any change to an installation's repositories is checked against its current list
//!   ([`ReposJob`]), since GitHub may not name the ones a switch from all to selected left out.
//! - **Registering with the directory** (hosted) is part of connecting: the job asks the host to
//!   record the installation for this workspace ([`link_call`], which only hosts with a directory
//!   are sent), and says so when the installation already serves as many workspaces as it may.
//!   Until it's recorded, each sync of the installation's sources asks again.
//!
//! **Signing in the core.** The core signs the JWT itself (RS256, PKCS#1 v1.5 with SHA-256, the
//! pure-Rust `rsa` crate) instead of asking the host: there's one implementation for both hosts, it
//! needs no I/O, it's tested natively with a fixed key ([`tests`]), and it compiles for
//! `wasm32-unknown-unknown`. `rsa` 0.10 does its arithmetic with constant-time big integers, and
//! signing is blinded with the core's random numbers (the signature itself is deterministic). The
//! `rsa` crate's advisory (RUSTSEC-2023-0071, the Marvin attack) concerns timing measured over many
//! attacker-chosen operations; here the key signs only claims DumbSlab builds itself, once per sync.
//! Signing with WebCrypto in the Worker (the host) instead would be further hardening, not a fix.
//!
//! Docs:
//! - JWT: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app
//!   (RS256; `iat` 60 seconds in the past for clock drift; `exp` at most 10 minutes ahead; `iss` the
//!   client ID, which GitHub recommends; the downloaded key is PKCS#1 PEM).
//! - Installation tokens: https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app
//!   (`repository_ids`, `permissions`; one hour; the answer lists the `repositories`).
//! - Installing: https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/about-the-setup-url,
//!   https://docs.github.com/en/apps/sharing-github-apps/sharing-your-github-app (`state`),
//!   https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app
//!   (`POST https://github.com/login/oauth/access_token`).
//! - Checking the installer: https://docs.github.com/en/rest/apps/installations#list-app-installations-accessible-to-the-user-access-token,
//!   https://docs.github.com/en/rest/apps/installations#list-repositories-accessible-to-the-user-access-token
//! - Webhooks: https://docs.github.com/en/webhooks/webhook-events-and-payloads (`push`,
//!   `installation`, `installation_repositories`; every App gets the last two),
//!   https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use rsa::RsaPrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use serde_json::{Value, json};
use sha2::Sha256;

use super::{check_plan, hook_answer};
use crate::connect::{Finish, HttpCall, HttpReply, Job, Step, http_error};
use crate::db::{Db, DbExt, SqlValue};
use crate::error::{ApiError, ApiResult};
use crate::events::{Event, emit};
use crate::util::{parse_ts, secure_eq, sha256_hex, ts};
use crate::{Effect, HostConfig, InstallationLink, Outcome, Request, Response, params};

const API: &str = "https://api.github.com";
/// GitHub's REST API version this code was written against (as in [`super::repo`]).
const API_VERSION: &str = "2022-11-28";
/// `iat` this far in the past, for clocks that drift (GitHub's advice).
const JWT_BACKDATE_SECS: i64 = 60;
/// `exp` this far ahead: GitHub allows at most 10 minutes, so this leaves a minute for drift.
const JWT_LIFETIME_SECS: i64 = 9 * 60;
/// How long connecting may take, as for connected apps.
pub(crate) const CONNECT_MINUTES: i64 = 15;
/// Pending connections one admin may have; older ones are dropped.
const MAX_PENDING: i64 = 5;
/// Pages of 100 repositories read per installation when connecting.
pub const REPO_PAGES: usize = 5;
const PER_PAGE: usize = 100;
/// Installations one connection saves when GitHub doesn't say which one was installed; past
/// that, the admin is asked to choose (by starting from the installation on GitHub).
const MAX_AT_ONCE: usize = 10;
/// Pages of 100 of a person's installations read when connecting.
pub const INSTALLATION_PAGES: usize = 3;
/// What a job asks the host to record an installation in its directory with (see [`link_call`]).
/// Not a web address: hosts without a directory never send it anywhere.
pub const DIRECTORY_LINK_URL: &str = "dumbslab:directory/github/link";
/// Where Settings › Docs sync is.
const SETTINGS: &str = "/settings/docs-sync";
pub const INSTALL_PATH: &str = "/sync/github/install";
pub const CALLBACK_PATH: &str = "/sync/github/callback";

/// DumbSlab's GitHub App, as the host configures it. Never printed whole.
#[derive(Clone, Default)]
pub struct GitHubApp {
    /// The App's numeric id (shown on its settings page).
    pub app_id: String,
    /// The App's name in its URL: `https://github.com/apps/<slug>`.
    pub slug: String,
    /// The App's client ID: the JWT's issuer, and the OAuth client for authorizing installers.
    pub client_id: String,
    pub client_secret: String,
    /// The App's private key, PEM (PKCS#1 as GitHub hands it out, or PKCS#8).
    pub private_key: String,
    /// The secret GitHub signs the App's webhook deliveries with.
    pub webhook_secret: String,
}

impl std::fmt::Debug for GitHubApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitHubApp")
            .field("app_id", &self.app_id)
            .field("slug", &self.slug)
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

impl GitHubApp {
    /// The settings' names: Cloudflare reads them as they are (the first three are `[vars]`, the
    /// rest secrets); a self-hosted server reads them with `DUMBSLAB_` in front.
    pub const NAMES: [&'static str; 6] = [
        "GITHUB_APP_ID",
        "GITHUB_APP_SLUG",
        "GITHUB_APP_CLIENT_ID",
        "GITHUB_APP_CLIENT_SECRET",
        "GITHUB_APP_PRIVATE_KEY",
        "GITHUB_APP_WEBHOOK_SECRET",
    ];

    /// Reads the settings with `get` (by [`GitHubApp::NAMES`]). `None` unless every one is set and
    /// the slug is one GitHub could have made.
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Option<GitHubApp> {
        let mut values = GitHubApp::NAMES.iter().map(|n| get(n).map(|v| v.trim().to_string()).filter(|v| !v.is_empty()));
        let mut next = || values.next().flatten();
        let app = GitHubApp {
            app_id: next()?,
            slug: next()?,
            client_id: next()?,
            client_secret: next()?,
            private_key: next()?,
            webhook_secret: next()?,
        };
        valid_slug(&app.slug).then_some(app)
    }

    /// Where an admin installs the App; GitHub hands `state` back with them.
    pub fn install_url(&self, state: &str) -> String {
        format!("https://github.com/apps/{}/installations/new?state={}", self.slug, urlencoding::encode(state))
    }
}

fn valid_slug(slug: &str) -> bool {
    (1..=100).contains(&slug.len()) && slug.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// The host's GitHub App, when it has one.
pub fn app(cfg: &HostConfig) -> Option<&GitHubApp> {
    cfg.github_app.as_ref()
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

const BAD_KEY: &str = "The server's GitHub App private key can't be read. Whoever runs this server can check GITHUB_APP_PRIVATE_KEY.";

fn signing_key(pem: &str) -> Result<SigningKey<Sha256>, String> {
    // A key pasted with `\n` for its line breaks works too.
    let pem = pem.trim().replace("\\n", "\n");
    let key = RsaPrivateKey::from_pkcs1_pem(&pem).or_else(|_| RsaPrivateKey::from_pkcs8_pem(&pem)).map_err(|_| BAD_KEY.to_string())?;
    Ok(SigningKey::<Sha256>::new(key))
}

/// The App's JSON Web Token: RS256 over `{"iat","exp","iss"}`, `iat` a minute back and `exp` nine
/// minutes ahead, issued by the App's client ID.
pub(crate) fn jwt(app: &GitHubApp, now: DateTime<Utc>) -> Result<String, String> {
    let header = b64(br#"{"alg":"RS256","typ":"JWT"}"#);
    let at = now.timestamp();
    let claims =
        format!(r#"{{"iat":{},"exp":{},"iss":{}}}"#, at - JWT_BACKDATE_SECS, at + JWT_LIFETIME_SECS, Value::String(app.client_id.clone()));
    let input = format!("{header}.{}", b64(claims.as_bytes()));
    let signature =
        signing_key(&app.private_key)?.try_sign_with_rng(&mut rand::rng(), input.as_bytes()).map_err(|_| BAD_KEY.to_string())?;
    Ok(format!("{input}.{}", b64(&signature.to_vec())))
}

fn api_call(call: HttpCall) -> HttpCall {
    call.header("accept", "application/vnd.github+json").header("x-github-api-version", API_VERSION).header("user-agent", "DumbSlab")
}

// ---------------------------------------------------------------------------
// Installation tokens

/// The request for an installation token that reads one repository's contents, nothing more.
pub(crate) fn token_call(app: &GitHubApp, installation_id: i64, repo_id: i64, now: DateTime<Utc>) -> Result<HttpCall, String> {
    let body = json!({ "repository_ids": [repo_id], "permissions": { "contents": "read" } });
    let url = format!("{API}/app/installations/{installation_id}/access_tokens");
    Ok(api_call(HttpCall::post_json(url, &body)).bearer(&jwt(app, now)?))
}

/// The request for an installation token that only reads which repositories the installation
/// can see (Metadata, which every App has).
pub(crate) fn listing_token_call(app: &GitHubApp, installation_id: i64, now: DateTime<Utc>) -> Result<HttpCall, String> {
    let body = json!({ "permissions": { "metadata": "read" } });
    let url = format!("{API}/app/installations/{installation_id}/access_tokens");
    Ok(api_call(HttpCall::post_json(url, &body)).bearer(&jwt(app, now)?))
}

/// A minted installation token, and the repository's name now (it may have been renamed).
#[derive(Clone, PartialEq)]
pub(crate) struct Minted {
    pub token: String,
    pub full_name: Option<String>,
}

// Holds a token; never print it.
impl std::fmt::Debug for Minted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Minted").field("full_name", &self.full_name).finish_non_exhaustive()
    }
}

/// Reads the answer to [`token_call`]. An error says what to do, for the admin.
pub(crate) fn read_token(reply: &HttpReply, repo_id: i64) -> Result<Minted, String> {
    let v = reply.json();
    match (reply.status, v["token"].as_str()) {
        (200 | 201, Some(t)) if !t.is_empty() => {
            let full_name = v["repositories"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|r| r["id"].as_i64() == Some(repo_id))
                .and_then(|r| r["full_name"].as_str())
                .and_then(|n| super::repo::github_repo(n).ok());
            Ok(Minted { token: t.to_string(), full_name })
        }
        (401, _) => Err("GitHub refused DumbSlab's GitHub App: the server's App settings (client ID or private key) are wrong. Whoever runs this server can check them.".into()),
        (403, _) => Err("GitHub refused DumbSlab's GitHub App: its installation may be suspended, or GitHub's rate limit was reached. Try again in a minute.".into()),
        (404, _) => Err("DumbSlab's GitHub App isn't installed for this repository any more. Connect GitHub again in Settings › Docs sync.".into()),
        (422, _) => Err("DumbSlab's GitHub App can't reach this repository any more: it was probably taken out of the App's repositories. Add it again on GitHub, or Connect GitHub again.".into()),
        _ => Err(http_error("GitHub", reply)),
    }
}

// ---------------------------------------------------------------------------
// Registering with the directory (hosted DumbSlab)

/// The request a job makes for the host to record, in its directory, that this workspace uses an
/// installation, so the root domain forwards its deliveries here. Only hosts with a directory are
/// sent it (see [`needs_link`]); the Worker answers it with the directory's answer.
pub(crate) fn link_call(installation_id: i64) -> HttpCall {
    HttpCall::post_json(DIRECTORY_LINK_URL, &json!({ "installation_id": installation_id, "linked": true }))
}

/// How registering an installation went.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Forwarding {
    Ok,
    /// It serves as many workspaces as it may.
    Full,
    /// Something went wrong on the way; asked again at the next sync.
    Retry,
}

pub(crate) fn read_link(reply: &HttpReply) -> Forwarding {
    match reply.status {
        200..=299 => Forwarding::Ok,
        409 if reply.json()["error"]["code"] == "installation_full" => Forwarding::Full,
        _ => Forwarding::Retry,
    }
}

/// Keeps how registering went (`github_installations.forwarding`).
pub(crate) fn record_link(db: &dyn Db, installation_id: i64, f: Forwarding) -> ApiResult<()> {
    let value = match f {
        Forwarding::Ok => "ok",
        Forwarding::Full => "full",
        Forwarding::Retry => return Ok(()),
    };
    db.execute("UPDATE github_installations SET forwarding = ? WHERE id = ?", &params![value, installation_id])?;
    Ok(())
}

/// Whether a job should (again) ask the host to register the installation: hosted workspaces, until
/// the directory has it.
pub(crate) fn needs_link(db: &dyn Db, cfg: &HostConfig, installation_id: i64) -> ApiResult<bool> {
    if cfg.hosting.is_none() {
        return Ok(false);
    }
    let row = db.one("SELECT forwarding FROM github_installations WHERE id = ?", &params![installation_id])?;
    Ok(row.is_some_and(|r| r.opt_str("forwarding").as_deref() != Some("ok")))
}

/// What the root domain answers GitHub once it forwarded a delivery: each workspace's (first
/// address, its answer's status, or `None` when it couldn't be reached). Any failure fails the
/// delivery, so GitHub's log shows it and an operator can redeliver it; that's safe, because a
/// workspace that already handled it handles it again the same way (a push syncs or is noted, a
/// change to an installation is applied again), and nothing remembers GitHub's delivery ids to
/// refuse it. Returns the status, the body and the workspaces that failed (to log; their first
/// addresses only).
pub fn forwarded(results: &[(String, Option<u16>)]) -> (u16, Value, Vec<String>) {
    let failed: Vec<String> =
        results.iter().filter(|(_, status)| !status.is_some_and(|s| (200..300).contains(&s))).map(|(home, _)| home.clone()).collect();
    let body = json!({ "ok": failed.is_empty(), "workspaces": results.len(), "delivered": results.len() - failed.len() });
    (if failed.is_empty() { 200 } else { 502 }, body, failed)
}

// ---------------------------------------------------------------------------
// Installing: the browser routes

/// Why connecting didn't work. Only these codes go in the link back to Settings: anyone can make a
/// link to Settings, so the page says what each one means.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Problem {
    /// The link was used already, or never existed.
    ExpiredLink,
    TooSlow,
    /// Someone other than the admin who started, or another browser session, came back.
    WrongPerson,
    /// Only admins connect GitHub.
    NotAdmin,
    /// This server has no GitHub App (or no connector key).
    Unavailable,
    /// An organization owner must approve the installation first.
    ApprovalRequested,
    /// The person didn't authorize the App.
    Declined,
    NoCode,
    /// The installation isn't one the person's GitHub account can access.
    NotYours,
    /// GitHub didn't say which installation, and the person has too many to connect them all.
    ChooseInstallation,
    /// Connected, but the installation already serves as many workspaces as it may, so GitHub's
    /// deliveries for it can't reach this one.
    InstallationFull,
    Failed,
}

impl Problem {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Problem::ExpiredLink => "expired_link",
            Problem::TooSlow => "too_slow",
            Problem::WrongPerson => "wrong_person",
            Problem::NotAdmin => "not_admin",
            Problem::Unavailable => "unavailable",
            Problem::ApprovalRequested => "approval_requested",
            Problem::Declined => "declined",
            Problem::NoCode => "no_code",
            Problem::NotYours => "not_yours",
            Problem::ChooseInstallation => "choose_installation",
            Problem::InstallationFull => "installation_full",
            Problem::Failed => "failed",
        }
    }
}

/// Settings › Docs sync, with how connecting `provider` went.
pub(crate) fn settings_url(base_url: &str, provider: &str, outcome: Result<(), Problem>) -> String {
    match outcome {
        Ok(()) => format!("{base_url}{SETTINGS}?connected={provider}"),
        Err(p) => format!("{base_url}{SETTINGS}?connect_error={}&app={provider}", p.code()),
    }
}

fn redirect(url: String) -> Outcome {
    crate::http::done(Response::redirect(&url).with_header("cache-control", "no-store").with_header("referrer-policy", "no-referrer"))
}

pub(crate) fn query_map(query: &str) -> BTreeMap<String, String> {
    query
        .split('&')
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| {
            let decode = |s: &str| urlencoding::decode(&s.replace('+', " ")).map(|c| c.into_owned()).unwrap_or_default();
            (decode(k), decode(v))
        })
        .collect()
}

/// Records a connection under way for the admin signed in to this browser session, and returns
/// its `state`: hosted workspaces' starts with their address, so the root domain knows where to
/// send the admin back. `Err` says why it can't start.
pub(crate) fn begin(
    db: &dyn Db,
    cfg: &HostConfig,
    req: &Request,
    provider: &str,
    verifier: Option<&str>,
) -> ApiResult<Result<String, Problem>> {
    let now = Utc::now();
    let actor = match crate::auth::authenticate(db, cfg, req, now) {
        Ok(Some(a)) => a,
        _ => return Ok(Err(Problem::WrongPerson)),
    };
    let Some(session) = actor.session_hash.clone() else { return Ok(Err(Problem::WrongPerson)) };
    if !actor.can_admin() {
        return Ok(Err(Problem::NotAdmin));
    }
    db.execute("DELETE FROM docs_connect_requests WHERE created_at < ?", &params![ts(now - Duration::minutes(CONNECT_MINUTES))])?;
    db.execute(
        "DELETE FROM docs_connect_requests WHERE user_id = ? AND state_hash NOT IN
           (SELECT state_hash FROM docs_connect_requests WHERE user_id = ? ORDER BY created_at DESC LIMIT ?)",
        &params![actor.user_id.clone(), actor.user_id.clone(), MAX_PENDING - 1],
    )?;
    let random = crate::util::new_secret("");
    let state = match &cfg.workspace {
        Some(address) => format!("{address}.{random}"),
        None => random,
    };
    db.execute(
        "INSERT INTO docs_connect_requests (state_hash, provider, user_id, session_hash, verifier, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        &params![sha256_hex(&state), provider, actor.user_id, session, verifier, ts(now)],
    )?;
    Ok(Ok(state))
}

/// A connection the browser came back from: who started it, checked to be the same admin in the
/// same browser session, within [`CONNECT_MINUTES`]. The state works once.
pub(crate) struct Returned {
    pub user_id: String,
}

pub(crate) fn returned(db: &dyn Db, cfg: &HostConfig, req: &Request, provider: &str, state: &str) -> ApiResult<Result<Returned, Problem>> {
    let now = Utc::now();
    let hash = sha256_hex(state);
    let Some(row) = db.one(
        "SELECT user_id, session_hash, created_at FROM docs_connect_requests WHERE state_hash = ? AND provider = ?",
        &params![hash.clone(), provider],
    )?
    else {
        return Ok(Err(Problem::ExpiredLink));
    };
    db.execute("DELETE FROM docs_connect_requests WHERE state_hash = ?", &params![hash])?;
    if parse_ts(&row.str("created_at")).is_none_or(|at| now - at > Duration::minutes(CONNECT_MINUTES)) {
        return Ok(Err(Problem::TooSlow));
    }
    let actor = crate::auth::authenticate(db, cfg, req, now).ok().flatten();
    let same = actor.as_ref().is_some_and(|a| {
        a.user_id == row.str("user_id") && a.session_hash.as_deref().is_some_and(|h| secure_eq(h, &row.str("session_hash")))
    });
    if !same {
        return Ok(Err(Problem::WrongPerson));
    }
    if !actor.is_some_and(|a| a.can_admin()) {
        return Ok(Err(Problem::NotAdmin));
    }
    Ok(Ok(Returned { user_id: row.str("user_id") }))
}

fn unavailable(cfg: &HostConfig) -> bool {
    app(cfg).is_none() || !crate::connect::enabled(cfg)
}

/// `GET /sync/github/install`: an admin chose Connect GitHub. Sends them to install the App.
pub fn install_start(db: &dyn Db, cfg: &HostConfig, req: &Request) -> Outcome {
    let base = crate::http::base_url(cfg, req);
    let back = |p: Problem| redirect(settings_url(&base, "github", Err(p)));
    let run = || -> ApiResult<Outcome> {
        let Some(app) = app(cfg).filter(|_| !unavailable(cfg)) else { return Ok(back(Problem::Unavailable)) };
        Ok(match begin(db, cfg, req, "github", None)? {
            Ok(state) => redirect(app.install_url(&state)),
            Err(p) => back(p),
        })
    };
    run().unwrap_or_else(|_| back(Problem::Failed))
}

/// `GET /sync/github/callback`: GitHub sent the admin back after installing (or updating) the App.
/// Answers with a job that checks the installation is theirs and saves it, then sends them to
/// Settings › Docs sync.
pub fn install_callback(db: &dyn Db, cfg: &HostConfig, req: &Request) -> Outcome {
    let base = crate::http::base_url(cfg, req);
    let query = query_map(&req.query);
    let back = |p: Problem| redirect(settings_url(&base, "github", Err(p)));
    let run = || -> ApiResult<Outcome> {
        let state = query.get("state").cloned().unwrap_or_default();
        let who = match returned(db, cfg, req, "github", &state)? {
            Ok(w) => w,
            Err(p) => return Ok(back(p)),
        };
        if unavailable(cfg) {
            return Ok(back(Problem::Unavailable));
        }
        // The installation waits for an organization owner; GitHub tells them, not us.
        if query.get("setup_action").map(String::as_str) == Some("request") {
            return Ok(back(Problem::ApprovalRequested));
        }
        let code = match (query.get("code").filter(|c| !c.is_empty()), query.get("error")) {
            (Some(c), _) => c.clone(),
            (None, Some(_)) => return Ok(back(Problem::Declined)),
            (None, None) => return Ok(back(Problem::NoCode)),
        };
        // Only a hint: checked against the installations the admin's own account can access.
        let installation_id = query.get("installation_id").and_then(|i| i.parse::<i64>().ok()).filter(|i| *i > 0);
        let job = InstallJob {
            user_id: who.user_id,
            code,
            installation_id,
            base_url: base.clone(),
            phase: InstallPhase::Start,
            user_token: String::new(),
            chosen: vec![],
            effects: vec![],
            staged: vec![],
        };
        let mut out = back(Problem::Failed);
        out.effects.push(Effect::Connect(Job::GitHub(Box::new(job))));
        Ok(out)
    };
    run().unwrap_or_else(|_| back(Problem::Failed))
}

// ---------------------------------------------------------------------------
// Installing: the job that checks and saves the installation

/// An installation of the App, as GitHub lists it for a user.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Installation {
    pub id: i64,
    /// The account it's installed on: a user's or organization's login (an enterprise's slug).
    pub account: String,
    /// `User`, `Organization` or `Enterprise`.
    pub account_type: String,
    pub suspended: bool,
}

/// A repository someone's GitHub account can read in an installation.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Repository {
    pub id: i64,
    pub full_name: String,
    pub default_branch: String,
    pub private: bool,
}

pub(crate) fn read_installations(reply: &HttpReply) -> Result<Vec<Installation>, String> {
    let v = reply.json();
    let (true, Some(list)) = (reply.ok(), v["installations"].as_array()) else { return Err(http_error("GitHub", reply)) };
    Ok(list
        .iter()
        .filter_map(|i| {
            let account = i["account"]["login"].as_str().or(i["account"]["slug"].as_str())?;
            Some(Installation {
                id: i["id"].as_i64().filter(|id| *id > 0)?,
                account: account.chars().take(100).collect(),
                account_type: i["target_type"].as_str().or(i["account"]["type"].as_str()).unwrap_or_default().chars().take(40).collect(),
                suspended: !i["suspended_at"].is_null(),
            })
        })
        .collect())
}

/// The repositories in the answers to [`user_repository_calls`], and whether there are more.
pub(crate) fn read_repositories(replies: &[HttpReply]) -> Result<(Vec<Repository>, bool), String> {
    let mut out: Vec<Repository> = vec![];
    let mut total = 0;
    for r in replies {
        let v = r.json();
        let (true, Some(page)) = (r.ok(), v["repositories"].as_array()) else { return Err(http_error("GitHub", r)) };
        total = total.max(v["total_count"].as_u64().unwrap_or_default() as usize);
        out.extend(page.iter().filter_map(|r| {
            Some(Repository {
                id: r["id"].as_i64().filter(|id| *id > 0)?,
                full_name: super::repo::github_repo(r["full_name"].as_str()?).ok()?,
                default_branch: r["default_branch"].as_str().filter(|b| super::repo::valid_branch(b)).unwrap_or("main").to_string(),
                private: r["private"].as_bool().unwrap_or(true),
            })
        }));
    }
    let mut seen = BTreeSet::new();
    out.retain(|r| seen.insert(r.id));
    let more = total > out.len();
    Ok((out, more))
}

fn user_call(url: String, token: &str) -> HttpCall {
    api_call(HttpCall::get(url)).bearer(token)
}

pub(crate) fn user_repository_calls(token: &str, installation_id: i64) -> Vec<HttpCall> {
    (1..=REPO_PAGES)
        .map(|page| user_call(format!("{API}/user/installations/{installation_id}/repositories?per_page={PER_PAGE}&page={page}"), token))
        .collect()
}

/// Finishes connecting GitHub after the install callback (see [`install_callback`]).
#[derive(Clone)]
pub struct InstallJob {
    user_id: String,
    code: String,
    /// What GitHub's link said was installed; not trusted until checked.
    installation_id: Option<i64>,
    base_url: String,
    phase: InstallPhase,
    user_token: String,
    chosen: Vec<Installation>,
    /// Webhooks for the activity it records, once the step that saved them committed.
    effects: Vec<Effect>,
    staged: Vec<Effect>,
}

// Carries a sign-in code and the installer's token; never print them.
impl std::fmt::Debug for InstallJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InstallJob({:?})", self.phase)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum InstallPhase {
    Start,
    Exchanging,
    Installations,
    Repositories,
    /// Hosted: waiting for the directory to record the installations.
    Linking,
}

impl InstallJob {
    pub(crate) fn take_effects(&mut self) -> Vec<Effect> {
        std::mem::take(&mut self.effects)
    }

    pub(crate) fn settle(&mut self, committed: bool) {
        let staged = std::mem::take(&mut self.staged);
        if committed {
            self.effects.extend(staged);
        }
    }
}

/// Runs the install job's next step (see [`crate::connect::step`]).
pub fn install_step(db: &dyn Db, cfg: &HostConfig, j: &mut InstallJob, replies: Vec<HttpReply>, now: DateTime<Utc>) -> ApiResult<Step> {
    let back = |p: Problem| Ok(Step::Done(Finish::Redirect(settings_url(&j.base_url, "github", Err(p)))));
    let Some(app) = app(cfg) else { return back(Problem::Unavailable) };
    match j.phase {
        InstallPhase::Start => {
            j.phase = InstallPhase::Exchanging;
            let form = [("client_id", app.client_id.as_str()), ("client_secret", app.client_secret.as_str()), ("code", j.code.as_str())];
            Ok(Step::Fetch(vec![
                HttpCall::post_form("https://github.com/login/oauth/access_token", &form).header("accept", "application/json"),
            ]))
        }
        InstallPhase::Exchanging => {
            let reply = replies.into_iter().next().unwrap_or_default();
            let v = reply.json();
            let Some(token) = v["access_token"].as_str().filter(|t| reply.ok() && !t.is_empty()) else { return back(Problem::Failed) };
            j.user_token = token.to_string();
            j.phase = InstallPhase::Installations;
            Ok(Step::Fetch(
                (1..=INSTALLATION_PAGES)
                    .map(|page| user_call(format!("{API}/user/installations?per_page={PER_PAGE}&page={page}"), &j.user_token))
                    .collect(),
            ))
        }
        InstallPhase::Installations => {
            let mut list = vec![];
            for r in &replies {
                match read_installations(r) {
                    Ok(page) => list.extend(page),
                    Err(_) => return back(Problem::Failed),
                }
            }
            let mut seen = BTreeSet::new();
            list.retain(|i| seen.insert(i.id));
            j.chosen = match j.installation_id {
                Some(id) => list.into_iter().filter(|i| i.id == id).collect(),
                // GitHub didn't say which: all of the person's own, if there are few enough;
                // otherwise they choose, by starting from the installation on GitHub.
                None if list.len() <= MAX_AT_ONCE => list,
                None => return back(Problem::ChooseInstallation),
            };
            if j.chosen.is_empty() {
                return back(Problem::NotYours);
            }
            j.phase = InstallPhase::Repositories;
            Ok(Step::Fetch(j.chosen.iter().flat_map(|i| user_repository_calls(&j.user_token, i.id)).collect()))
        }
        InstallPhase::Repositories => {
            let mut found = vec![];
            for (i, page) in j.chosen.iter().zip(replies.chunks(REPO_PAGES)) {
                match read_repositories(page) {
                    Ok((repos, more)) => found.push((i.clone(), repos, more)),
                    Err(_) => return back(Problem::Failed),
                }
            }
            // Still an admin here, now that GitHub answered.
            let admin = db
                .one("SELECT 1 AS ok FROM users WHERE id = ? AND role = 'admin' AND deactivated_at IS NULL", &params![j.user_id.clone()])?;
            if admin.is_none() {
                return back(Problem::NotAdmin);
            }
            let mut ctx = super::ctx(db, cfg, &j.user_id, &j.base_url, now)?;
            for (installation, repos, more) in &found {
                save(&mut ctx, installation, repos, *more)?;
            }
            j.staged.append(&mut ctx.effects);
            // Hosted: connecting isn't done until the directory forwards the deliveries here.
            if cfg.hosting.is_some() {
                j.phase = InstallPhase::Linking;
                return Ok(Step::Fetch(j.chosen.iter().map(|i| link_call(i.id)).collect()));
            }
            Ok(Step::Done(Finish::Redirect(settings_url(&j.base_url, "github", Ok(())))))
        }
        InstallPhase::Linking => {
            let mut full = false;
            for (i, reply) in j.chosen.iter().zip(&replies) {
                let f = read_link(reply);
                record_link(db, i.id, f)?;
                full |= f == Forwarding::Full;
            }
            let outcome = if full { Err(Problem::InstallationFull) } else { Ok(()) };
            Ok(Step::Done(Finish::Redirect(settings_url(&j.base_url, "github", outcome))))
        }
    }
}

/// Saves an installation and the repositories the admin's GitHub account can read in it, and
/// puts back to work this workspace's disconnected sources on those repositories.
fn save(ctx: &mut crate::registry::Ctx, i: &Installation, repos: &[Repository], more: bool) -> ApiResult<()> {
    let db = ctx.db;
    let now = ctx.now_s();
    db.execute(
        "INSERT INTO github_installations (id, account, account_type, connected_by, suspended_at, more_repositories, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET account = excluded.account, account_type = excluded.account_type, connected_by = excluded.connected_by,
           suspended_at = excluded.suspended_at, more_repositories = excluded.more_repositories, updated_at = excluded.updated_at",
        &params![i.id, i.account.clone(), i.account_type.clone(), ctx.actor.user_id.clone(), i.suspended.then(|| now.clone()), more, now.clone(), now.clone()],
    )?;
    db.execute("DELETE FROM github_repositories WHERE installation_id = ?", &params![i.id])?;
    for r in repos {
        db.execute(
            "INSERT INTO github_repositories (installation_id, id, full_name, default_branch, private) VALUES (?, ?, ?, ?, ?)",
            &params![i.id, r.id, r.full_name.clone(), r.default_branch.clone(), r.private],
        )?;
    }
    if !i.suspended {
        let ids: BTreeSet<i64> = repos.iter().map(|r| r.id).collect();
        let waiting =
            db.query("SELECT source_id, repo_id FROM docs_source_links WHERE connection = 'github_app' AND disconnected IS NOT NULL", &[])?;
        for s in waiting.iter().filter(|s| s.opt_i64("repo_id").is_some_and(|r| ids.contains(&r))) {
            db.execute(
                "UPDATE docs_source_links SET installation_id = ?, disconnected = NULL WHERE source_id = ?",
                &params![i.id, s.str("source_id")],
            )?;
        }
    }
    emit(
        ctx,
        Event::new("github.connected", "github_installation", &i.id.to_string(), format!("connected GitHub ({})", i.account))
            .data(json!({ "repositories": repos.len() }))
            .admin_only(),
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Webhooks

/// Whether `signature` (`X-Hub-Signature-256`) is GitHub's for `body`, compared in constant time.
pub fn signature_ok(secret: &str, body: &[u8], signature: Option<&str>) -> bool {
    !secret.is_empty() && secure_eq(signature.unwrap_or_default(), &format!("sha256={}", super::hmac_hex(secret, &[body])))
}

/// What a delivery means for docs sync.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Delivery {
    Ping,
    /// A push to a branch (tags and deleted branches are ignored).
    Push {
        installation: i64,
        repo_id: i64,
        full_name: String,
        branch: String,
    },
    Uninstalled {
        installation: i64,
    },
    Suspended {
        installation: i64,
    },
    Unsuspended {
        installation: i64,
    },
    RepositoriesRemoved {
        installation: i64,
        ids: Vec<i64>,
    },
    RepositoriesAdded {
        installation: i64,
        repos: Vec<(i64, String)>,
    },
    Ignored,
}

impl Delivery {
    fn installation(&self) -> Option<i64> {
        match self {
            Delivery::Push { installation, .. }
            | Delivery::Uninstalled { installation }
            | Delivery::Suspended { installation }
            | Delivery::Unsuspended { installation }
            | Delivery::RepositoriesRemoved { installation, .. }
            | Delivery::RepositoriesAdded { installation, .. } => Some(*installation),
            Delivery::Ping | Delivery::Ignored => None,
        }
    }
}

/// Reads a delivery (`X-GitHub-Event` and its body). Only what docs sync acts on is kept: who it's
/// for (`installation.id`) and, for a push, which repository and branch. The sync reads the
/// repository itself.
pub(crate) fn parse(event: &str, body: &[u8]) -> Delivery {
    if event == "ping" {
        return Delivery::Ping;
    }
    let v: Value = serde_json::from_slice(body).unwrap_or_default();
    let Some(installation) = v["installation"]["id"].as_i64().filter(|i| *i > 0) else { return Delivery::Ignored };
    let repos = |key: &str| -> Vec<(i64, String)> {
        v[key]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|r| Some((r["id"].as_i64()?, r["full_name"].as_str().unwrap_or_default().to_string())))
            .collect()
    };
    match (event, v["action"].as_str().unwrap_or_default()) {
        ("push", _) => {
            let branch = v["ref"].as_str().and_then(|r| r.strip_prefix("refs/heads/"));
            match (branch, v["repository"]["id"].as_i64(), v["repository"]["full_name"].as_str()) {
                (Some(b), Some(repo_id), Some(name)) if v["deleted"] != json!(true) => {
                    Delivery::Push { installation, repo_id, full_name: name.to_string(), branch: b.to_string() }
                }
                _ => Delivery::Ignored,
            }
        }
        ("installation", "deleted") => Delivery::Uninstalled { installation },
        ("installation", "suspend") => Delivery::Suspended { installation },
        ("installation", "unsuspend") => Delivery::Unsuspended { installation },
        ("installation_repositories", "removed") => {
            Delivery::RepositoriesRemoved { installation, ids: repos("repositories_removed").into_iter().map(|(id, _)| id).collect() }
        }
        ("installation_repositories", "added") => Delivery::RepositoriesAdded { installation, repos: repos("repositories_added") },
        _ => Delivery::Ignored,
    }
}

/// What hosted DumbSlab's root domain does with a delivery to `/hooks/github`.
#[derive(Debug)]
pub enum Routed {
    /// Answer with this error: the signature is wrong.
    Refused(ApiError),
    /// Answer with this, sending it on to nobody.
    Answer(Value),
    /// Send it on, unchanged, to the workspaces that connected this installation. Each checks the
    /// signature again.
    Forward(i64),
}

/// Decides what the root domain does with a delivery, from its signature, `X-GitHub-Event` and
/// body. Only deliveries docs sync acts on are sent on.
pub fn route_delivery(secret: &str, signature: Option<&str>, event: Option<&str>, body: &[u8]) -> Routed {
    if !signature_ok(secret, body, signature) {
        return Routed::Refused(ApiError::unauthorized("the delivery's signature doesn't match DumbSlab's GitHub App"));
    }
    let d = parse(event.unwrap_or_default(), body);
    match d.installation() {
        _ if d == Delivery::Ping => Routed::Answer(json!({ "ok": true, "status": "pong" })),
        Some(i) => Routed::Forward(i),
        None => Routed::Answer(json!({ "ok": true, "status": "ignored" })),
    }
}

/// Why a source can't sync now. Kept as a code; [`disconnected_message`] says what it means.
pub(crate) const UNINSTALLED: &str = "uninstalled";
pub(crate) const SUSPENDED: &str = "suspended";
pub(crate) const REPOSITORY_REMOVED: &str = "repository_removed";

/// What a source's `disconnected` code means, for the admin.
pub(crate) fn disconnected_message(code: &str) -> String {
    match code {
        UNINSTALLED => "DumbSlab's GitHub App was uninstalled, so this folder doesn't sync. Connect GitHub again to pick it back up; its posts stay.",
        SUSPENDED => "DumbSlab's GitHub App is suspended on GitHub, so this folder doesn't sync. It picks up again when the App is unsuspended; its posts stay.",
        REPOSITORY_REMOVED => "The repository was taken out of DumbSlab's GitHub App on GitHub, so this folder doesn't sync. Add the repository to the App again, or Connect GitHub again; its posts stay.",
        _ => "This folder can't sync. Connect GitHub again; its posts stay.",
    }
    .to_string()
}

/// Marks this installation's sources (those `filter` picks too) as unable to sync, and why.
fn disconnect(db: &dyn Db, installation: i64, filter: &str, code: &str, args: Vec<SqlValue>) -> ApiResult<u64> {
    let mut p = params![code, installation];
    p.extend(args);
    db.execute(
        &format!("UPDATE docs_source_links SET disconnected = ? WHERE connection = 'github_app' AND installation_id = ?{filter}"),
        &p,
    )
}

/// `POST /hooks/github`: a delivery from DumbSlab's GitHub App, sent by GitHub (self-hosted) or
/// forwarded by the root domain (hosted). Only installations an admin here connected count.
pub(crate) fn hook(db: &dyn Db, cfg: &HostConfig, req: &Request, base_url: &str, now: DateTime<Utc>) -> ApiResult<Outcome> {
    let Some(app) = app(cfg) else { return Err(ApiError::not_found("webhook")) };
    if !signature_ok(&app.webhook_secret, &req.body, req.header("x-hub-signature-256")) {
        return Err(ApiError::unauthorized("the delivery's signature doesn't match DumbSlab's GitHub App"));
    }
    let delivery = parse(req.header("x-github-event").unwrap_or_default(), &req.body);
    if delivery == Delivery::Ping {
        return Ok(hook_answer("pong"));
    }
    let Some(installation) = delivery.installation() else { return Ok(hook_answer("ignored")) };
    let Some(row) = db.one("SELECT id, account, connected_by FROM github_installations WHERE id = ?", &params![installation])? else {
        return Ok(hook_answer("ignored"));
    };
    let stamp = ts(now);
    let owner = row.str("connected_by");
    let account = row.str("account");
    let mut ctx = super::ctx(db, cfg, &owner, base_url, now)?;
    let note = |ctx: &mut crate::registry::Ctx, event: &str, summary: String| -> ApiResult<()> {
        emit(ctx, Event::new(event, "github_installation", &installation.to_string(), summary).admin_only()).map(|_| ())
    };
    match delivery {
        Delivery::Push { repo_id, full_name, branch, .. } => {
            let rows = db.query(
                &format!(
                    "{} WHERE l.connection = 'github_app' AND l.installation_id = ? AND l.repo_id = ? AND s.branch = ? AND l.disconnected IS NULL",
                    super::docs::SOURCES_SQL
                ),
                &params![installation, repo_id, branch],
            )?;
            if rows.is_empty() {
                return Ok(hook_answer("ignored"));
            }
            check_plan(db, cfg, now)?;
            let mut out = hook_answer("started");
            for r in rows {
                let mut source = super::docs::Source::from_row(cfg, &r)?;
                // A renamed repository keeps its id; its links follow the new name.
                if let Ok(name) = super::repo::github_repo(&full_name)
                    && name != source.repo.repo
                {
                    db.execute(
                        "UPDATE docs_sources SET repo = ?, updated_at = ? WHERE id = ?",
                        &params![name.clone(), stamp.clone(), source.id.clone()],
                    )?;
                    source.repo.repo = name;
                }
                let id = source.id.clone();
                match super::docs::start(db, source, base_url, now)? {
                    Some(job) => out.effects.push(Effect::Background(job)),
                    None => super::mark_pending(db, super::docs::TABLE, SqlValue::from(id), now)?,
                }
            }
            return Ok(out);
        }
        Delivery::Uninstalled { .. } => {
            disconnect(db, installation, "", UNINSTALLED, vec![])?;
            db.execute("DELETE FROM github_repositories WHERE installation_id = ?", &params![installation])?;
            db.execute("DELETE FROM github_installations WHERE id = ?", &params![installation])?;
            note(&mut ctx, "github.uninstalled", format!("DumbSlab's GitHub App was uninstalled from {account}"))?;
            ctx.effects.push(Effect::GitHubInstallation(InstallationLink { installation_id: installation, linked: false }));
        }
        Delivery::Suspended { .. } => {
            db.execute(
                "UPDATE github_installations SET suspended_at = ?, updated_at = ? WHERE id = ?",
                &params![stamp.clone(), stamp.clone(), installation],
            )?;
            disconnect(db, installation, " AND disconnected IS NULL", SUSPENDED, vec![])?;
            note(&mut ctx, "github.suspended", format!("DumbSlab's GitHub App was suspended on {account}"))?;
        }
        Delivery::Unsuspended { .. } => {
            db.execute(
                "UPDATE github_installations SET suspended_at = NULL, updated_at = ? WHERE id = ?",
                &params![stamp.clone(), installation],
            )?;
            db.execute(
                "UPDATE docs_source_links SET disconnected = NULL WHERE connection = 'github_app' AND installation_id = ? AND disconnected = ?",
                &params![installation, SUSPENDED],
            )?;
            note(&mut ctx, "github.unsuspended", format!("DumbSlab's GitHub App was unsuspended on {account}"))?;
        }
        Delivery::RepositoriesRemoved { ids, .. } => {
            for id in &ids {
                db.execute(
                    "UPDATE github_repositories SET removed_at = ? WHERE installation_id = ? AND id = ?",
                    &params![stamp.clone(), installation, *id],
                )?;
                disconnect(db, installation, " AND repo_id = ? AND disconnected IS NULL", REPOSITORY_REMOVED, params![*id])?;
            }
            note(&mut ctx, "github.repositories_removed", format!("repositories were taken out of DumbSlab's GitHub App on {account}"))?;
            ctx.effects.push(Effect::Background(Job::GitHubRepos(Box::new(ReposJob::new(installation)))));
        }
        Delivery::RepositoriesAdded { repos, .. } => {
            // Only repositories the admin here could already read come back; new ones need
            // Connect GitHub again, which checks their account can read them.
            for (id, name) in &repos {
                let name = super::repo::github_repo(name).ok();
                db.execute(
                    "UPDATE github_repositories SET removed_at = NULL, full_name = COALESCE(?, full_name) WHERE installation_id = ? AND id = ?",
                    &params![name, installation, *id],
                )?;
                db.execute(
                    "UPDATE docs_source_links SET disconnected = NULL WHERE connection = 'github_app' AND installation_id = ? AND repo_id = ? AND disconnected = ?",
                    &params![installation, *id, REPOSITORY_REMOVED],
                )?;
            }
            note(&mut ctx, "github.repositories_added", format!("repositories were added to DumbSlab's GitHub App on {account}"))?;
            ctx.effects.push(Effect::Background(Job::GitHubRepos(Box::new(ReposJob::new(installation)))));
        }
        Delivery::Ping | Delivery::Ignored => return Ok(hook_answer("ignored")),
    }
    let mut out = hook_answer("updated");
    out.effects.append(&mut ctx.effects);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Checking an installation's repositories

/// Brings an installation's repositories here in line with GitHub's list for it, after GitHub
/// reported a change. GitHub may not name every repository a change left out (switching from all
/// repositories to selected ones can leave `repositories_removed` empty), so the list itself is
/// read: repositories no longer on it stop being offered and their sources wait, disconnected;
/// ones back on it come back. New repositories aren't offered until an admin here connects
/// again, which checks their own account can read them.
#[derive(Clone, Debug)]
pub struct ReposJob {
    installation_id: i64,
    phase: ReposPhase,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum ReposPhase {
    Start,
    Minting,
    Listing,
}

impl ReposJob {
    pub(crate) fn new(installation_id: i64) -> ReposJob {
        ReposJob { installation_id, phase: ReposPhase::Start }
    }
}

/// Runs the repository check's next step (see [`crate::connect::step`]).
pub fn repos_step(db: &dyn Db, cfg: &HostConfig, j: &mut ReposJob, replies: Vec<HttpReply>, now: DateTime<Utc>) -> ApiResult<Step> {
    let failed = |message: String| Ok(Step::Done(Finish::Fail(ApiError::new(400, "github_failed", message))));
    let Some(app) = app(cfg) else { return failed("DumbSlab's GitHub App isn't set up on this server any more.".into()) };
    match j.phase {
        ReposPhase::Start => match listing_token_call(app, j.installation_id, now) {
            Ok(call) => {
                j.phase = ReposPhase::Minting;
                Ok(Step::Fetch(vec![call]))
            }
            Err(message) => failed(message),
        },
        ReposPhase::Minting => match read_token(&replies.first().cloned().unwrap_or_default(), 0) {
            Ok(minted) => {
                j.phase = ReposPhase::Listing;
                Ok(Step::Fetch(
                    (1..=REPO_PAGES)
                        .map(|page| {
                            api_call(HttpCall::get(format!("{API}/installation/repositories?per_page={PER_PAGE}&page={page}")))
                                .bearer(&minted.token)
                        })
                        .collect(),
                ))
            }
            Err(message) => failed(message),
        },
        ReposPhase::Listing => {
            let (current, more) = match read_repositories(&replies) {
                Ok(r) => r,
                Err(message) => return failed(message),
            };
            let installation = j.installation_id;
            let names: std::collections::BTreeMap<i64, String> = current.iter().map(|r| (r.id, r.full_name.clone())).collect();
            let stamp = ts(now);
            let mut gone = 0;
            for r in db.query("SELECT id, removed_at FROM github_repositories WHERE installation_id = ?", &params![installation])? {
                let id = r.i64("id");
                match names.get(&id) {
                    Some(name) => {
                        db.execute(
                            "UPDATE github_repositories SET removed_at = NULL, full_name = ? WHERE installation_id = ? AND id = ?",
                            &params![name.clone(), installation, id],
                        )?;
                        db.execute(
                            "UPDATE docs_source_links SET disconnected = NULL WHERE connection = 'github_app' AND installation_id = ? AND repo_id = ? AND disconnected = ?",
                            &params![installation, id, REPOSITORY_REMOVED],
                        )?;
                    }
                    // Only a whole list says what's missing from it.
                    None if !more && r.opt_str("removed_at").is_none() => {
                        db.execute(
                            "UPDATE github_repositories SET removed_at = ? WHERE installation_id = ? AND id = ?",
                            &params![stamp.clone(), installation, id],
                        )?;
                        disconnect(db, installation, " AND repo_id = ? AND disconnected IS NULL", REPOSITORY_REMOVED, params![id])?;
                        gone += 1;
                    }
                    None => {}
                }
            }
            Ok(Step::Done(Finish::Fill(json!({ "ok": true, "repositories": current.len(), "removed": gone }))))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::RsaPublicKey;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::pkcs8::DecodePublicKey;
    use rsa::signature::Verifier;

    /// A throwaway 2048-bit key made for these tests (`openssl genrsa -traditional 2048`), kept
    /// without its PEM lines so secret scanners leave it alone (see `testdata/README.md`).
    fn pem(label: &str, body: &str) -> String {
        format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", body.trim())
    }

    fn test_key() -> String {
        pem("RSA PRIVATE KEY", include_str!("testdata/github-app-test-key.b64"))
    }

    /// `openssl dgst -sha256 -sign` over this JWT's first two parts, with the key above.
    const KNOWN_JWT: &str = include_str!("testdata/github-app-test.jwt");

    fn test_app() -> GitHubApp {
        GitHubApp {
            app_id: "123".into(),
            slug: "dumbslab-test".into(),
            client_id: "Iv23liTEST".into(),
            client_secret: "client-secret".into(),
            private_key: test_key(),
            webhook_secret: "hook-secret".into(),
        }
    }

    fn at(unix: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(unix, 0).unwrap()
    }

    #[test]
    fn jwts_match_openssl_and_verify() {
        let app = test_app();
        let token = jwt(&app, at(1_700_000_000)).unwrap();
        assert_eq!(token, KNOWN_JWT.trim(), "PKCS#1 v1.5 is deterministic, so it matches OpenSSL's signature byte for byte");
        let parts: Vec<&str> = token.split('.').collect();
        let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims, json!({ "iat": 1_699_999_940, "exp": 1_700_000_540, "iss": "Iv23liTEST" }));
        let public_pem = pem("PUBLIC KEY", include_str!("testdata/github-app-test-key.pub.b64"));
        let public = VerifyingKey::<Sha256>::new(RsaPublicKey::from_public_key_pem(&public_pem).unwrap());
        let sig = Signature::try_from(URL_SAFE_NO_PAD.decode(parts[2]).unwrap().as_slice()).unwrap();
        assert!(public.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig).is_ok());

        // PKCS#8, and a key pasted with `\n` for its line breaks, sign the same.
        let pkcs8 = pem("PRIVATE KEY", include_str!("testdata/github-app-test-key.pkcs8.b64"));
        for key in [pkcs8, test_key().trim().replace('\n', "\\n")] {
            let other = GitHubApp { private_key: key, ..test_app() };
            assert_eq!(jwt(&other, at(1_700_000_000)).unwrap(), token);
        }
        let broken = GitHubApp { private_key: "-----BEGIN RSA PRIVATE KEY-----\nnope\n-----END RSA PRIVATE KEY-----".into(), ..test_app() };
        assert_eq!(jwt(&broken, at(0)).unwrap_err(), BAD_KEY);
        assert!(!format!("{app:?}").contains("PRIVATE") && !format!("{app:?}").contains("client-secret"), "never printed");
    }

    #[test]
    fn settings_come_from_the_environment() {
        let env: BTreeMap<&str, &str> = GitHubApp::NAMES.iter().map(|n| (*n, "x")).collect();
        let app = GitHubApp::from_env(|n| env.get(n).map(|v| v.to_string())).unwrap();
        assert_eq!((app.slug.as_str(), app.webhook_secret.as_str()), ("x", "x"));
        let missing = |skip: &str| GitHubApp::from_env(|n| (n != skip).then(|| "x".to_string()));
        for name in GitHubApp::NAMES {
            assert!(missing(name).is_none(), "{name} is needed");
        }
        assert!(GitHubApp::from_env(|n| Some(if n == "GITHUB_APP_SLUG" { "a/b".into() } else { "x".into() })).is_none());
        assert_eq!(test_app().install_url("acme.s t"), "https://github.com/apps/dumbslab-test/installations/new?state=acme.s%20t");
    }

    #[test]
    fn installation_tokens_read_one_repository() {
        let app = test_app();
        let call = token_call(&app, 42, 7, at(1_700_000_000)).unwrap();
        assert_eq!((call.method, call.url.as_str()), ("POST", "https://api.github.com/app/installations/42/access_tokens"));
        assert_eq!(
            serde_json::from_str::<Value>(call.body.as_deref().unwrap()).unwrap(),
            json!({ "repository_ids": [7], "permissions": { "contents": "read" } })
        );
        assert!(call.headers.contains(&("authorization".into(), format!("Bearer {}", KNOWN_JWT.trim()))));
        let reply = |status, body: Value| HttpReply { status, body: body.to_string() };
        let ok = reply(201, json!({ "token": "ghs_x", "expires_at": "…", "repositories": [{ "id": 7, "full_name": "acme/renamed" }] }));
        let minted = read_token(&ok, 7).unwrap();
        assert_eq!((minted.token.as_str(), minted.full_name.as_deref()), ("ghs_x", Some("acme/renamed")));
        assert_eq!(
            read_token(&reply(201, json!({ "token": "t", "repositories": [{ "id": 7, "full_name": "../x" }] })), 7).unwrap().full_name,
            None
        );
        for (status, words) in [(401, "settings"), (404, "isn't installed"), (422, "can't reach"), (500, "had an error")] {
            assert!(read_token(&reply(status, json!({})), 7).unwrap_err().contains(words), "{status}");
        }
    }

    #[test]
    fn installations_and_repositories_are_read() {
        let reply = |body: Value| HttpReply { status: 200, body: body.to_string() };
        let list = read_installations(&reply(json!({ "total_count": 3, "installations": [
            { "id": 1, "account": { "login": "acme", "type": "Organization" }, "target_type": "Organization", "suspended_at": null },
            { "id": 2, "account": { "slug": "big-corp" }, "target_type": "Enterprise", "suspended_at": "2026-01-01T00:00:00Z" },
            { "id": "3", "account": { "login": "bad" } },
        ] })))
        .unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!((list[1].account.as_str(), list[1].account_type.as_str(), list[1].suspended), ("big-corp", "Enterprise", true));
        assert!(read_installations(&HttpReply { status: 401, body: "{}".into() }).is_err());

        let page = |items: Value, total| reply(json!({ "total_count": total, "repositories": items }));
        let (repos, more) = read_repositories(&[
            page(
                json!([{ "id": 5, "full_name": "acme/docs", "default_branch": "trunk", "private": true },
                        { "id": 6, "full_name": "acme/../x", "default_branch": "main" },
                        { "id": 8, "full_name": "acme/site", "default_branch": "a:b", "private": false }]),
                4,
            ),
            page(json!([{ "id": 5, "full_name": "acme/docs" }]), 4),
        ])
        .unwrap();
        assert_eq!(
            repos.iter().map(|r| (r.id, r.full_name.as_str(), r.default_branch.as_str())).collect::<Vec<_>>(),
            vec![(5, "acme/docs", "trunk"), (8, "acme/site", "main")]
        );
        assert!(more, "four there, two read");
        let calls = user_repository_calls("tok", 9);
        assert_eq!(calls.len(), REPO_PAGES);
        assert_eq!(calls[1].url, "https://api.github.com/user/installations/9/repositories?per_page=100&page=2");
    }

    #[test]
    fn deliveries_are_read_and_routed() {
        let body = |v: Value| v.to_string().into_bytes();
        let push =
            body(json!({ "ref": "refs/heads/main", "repository": { "id": 7, "full_name": "acme/docs" }, "installation": { "id": 42 } }));
        assert_eq!(
            parse("push", &push),
            Delivery::Push { installation: 42, repo_id: 7, full_name: "acme/docs".into(), branch: "main".into() }
        );
        let tag = body(json!({ "ref": "refs/tags/v1", "repository": { "id": 7, "full_name": "acme/docs" }, "installation": { "id": 42 } }));
        let gone = body(
            json!({ "ref": "refs/heads/old", "deleted": true, "repository": { "id": 7, "full_name": "a/b" }, "installation": { "id": 42 } }),
        );
        let no_installation = body(json!({ "ref": "refs/heads/main", "repository": { "id": 7, "full_name": "a/b" } }));
        for b in [&tag, &gone, &no_installation] {
            assert_eq!(parse("push", b), Delivery::Ignored);
        }
        let lifecycle = |action: &str| body(json!({ "action": action, "installation": { "id": 42, "account": { "login": "acme" } } }));
        assert_eq!(parse("installation", &lifecycle("deleted")), Delivery::Uninstalled { installation: 42 });
        assert_eq!(parse("installation", &lifecycle("suspend")), Delivery::Suspended { installation: 42 });
        assert_eq!(parse("installation", &lifecycle("unsuspend")), Delivery::Unsuspended { installation: 42 });
        assert_eq!(parse("installation", &lifecycle("created")), Delivery::Ignored);
        let removed = body(
            json!({ "action": "removed", "installation": { "id": 42 }, "repositories_removed": [{ "id": 7, "full_name": "acme/docs" }] }),
        );
        assert_eq!(parse("installation_repositories", &removed), Delivery::RepositoriesRemoved { installation: 42, ids: vec![7] });
        assert_eq!(parse("ping", b"{}"), Delivery::Ping);
        assert_eq!(parse("issues", &lifecycle("opened")), Delivery::Ignored);

        let sign = |b: &[u8]| format!("sha256={}", super::super::hmac_hex("hook-secret", &[b]));
        assert!(signature_ok("hook-secret", &push, Some(&sign(&push))));
        assert!(!signature_ok("hook-secret", &push, Some("sha256=00")) && !signature_ok("hook-secret", &push, None));
        assert!(!signature_ok("", &push, Some(&super::super::hmac_hex("", &[&push]))), "no secret, no deliveries");
        assert!(matches!(route_delivery("hook-secret", Some(&sign(&push)), Some("push"), &push), Routed::Forward(42)));
        assert!(matches!(route_delivery("hook-secret", Some("sha256=00"), Some("push"), &push), Routed::Refused(e) if e.status == 401));
        assert!(
            matches!(route_delivery("hook-secret", Some(&sign(b"{}")), Some("ping"), b"{}"), Routed::Answer(v) if v["status"] == "pong")
        );
        assert!(
            matches!(route_delivery("hook-secret", Some(&sign(&tag)), Some("push"), &tag), Routed::Answer(v) if v["status"] == "ignored")
        );
    }

    #[test]
    fn deliveries_fail_unless_every_workspace_took_them() {
        let all = forwarded(&[("acme".into(), Some(200)), ("beta".into(), Some(202))]);
        assert_eq!((all.0, all.1["delivered"].as_u64(), all.2.len()), (200, Some(2), 0));
        let some = forwarded(&[("acme".into(), Some(200)), ("beta".into(), Some(500)), ("gamma".into(), None)]);
        assert_eq!((some.0, some.1["ok"].as_bool(), some.2), (502, Some(false), vec!["beta".to_string(), "gamma".to_string()]));
        assert_eq!(forwarded(&[]).0, 200, "nobody to tell");
        assert_eq!(read_link(&HttpReply { status: 200, body: "{}".into() }), Forwarding::Ok);
        let full = json!({ "error": { "code": "installation_full", "message": "…" } }).to_string();
        assert_eq!(read_link(&HttpReply { status: 409, body: full }), Forwarding::Full);
        assert_eq!(read_link(&HttpReply::default()), Forwarding::Retry);
        assert_eq!(read_link(&HttpReply { status: 409, body: "{}".into() }), Forwarding::Retry);
    }

    #[test]
    fn settings_links_carry_codes_only() {
        assert_eq!(settings_url("https://kb.test", "github", Ok(())), "https://kb.test/settings/docs-sync?connected=github");
        assert_eq!(
            settings_url("https://kb.test", "github", Err(Problem::ApprovalRequested)),
            "https://kb.test/settings/docs-sync?connect_error=approval_requested&app=github"
        );
    }
}
