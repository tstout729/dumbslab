//! Syncs from other systems, which admins set up for the whole workspace:
//!
//! - [`people`]: profile details (title, department, location, manager…) from BambooHR, for the
//!   people already in the workspace, matched by work email.
//! - [`docs`]: a GitHub or GitLab folder's Markdown files, kept as posts in a topic, one way.
//!
//! Each sync is a [`crate::connect::Job`], like connected apps' requests: the core builds every
//! request and reads every answer, hosts only send HTTP, and each step runs in its own
//! transaction (its writes count against the plan like any request's). Credentials are encrypted
//! with the host's connector key, and no operation returns them.
//!
//! One sync of each source runs at a time: it holds a lease ([`claim`]), which a sync that never
//! finished gives up after [`LEASE_SECS`]. Webhooks (`POST /hooks/…`) start a sync once their
//! secret checks out; they only say that something changed, and the sync reads the source itself.

pub mod docs;
pub mod people;
pub(crate) mod repo;
mod rewrite;

use chrono::{DateTime, Duration, Utc};
use hmac::{KeyInit, Mac};
use schemars::JsonSchema;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::Sha256;

use crate::auth::{Actor, Role, Scopes, Via};
use crate::connect::{self, Credential, PENDING};
use crate::db::{Db, DbExt, Row, SqlValue};
use crate::error::{ApiError, ApiResult};
use crate::registry::Ctx;
use crate::util::{new_id, parse_ts, ts};
use crate::{HostConfig, Outcome, Request, Response, params};

/// How long a sync may run before another may start. A job takes at most
/// [`connect::MAX_STEPS`] steps of at most [`connect::FETCH_TIMEOUT_SECS`] each.
pub const LEASE_SECS: i64 = 90;

/// Encrypts a sync's credentials, bound to the sync (`people-sync`, `docs-source:<id>`) and app.
pub(crate) fn seal(cfg: &HostConfig, owner: &str, app: &str, cred: &Credential) -> ApiResult<String> {
    connect::seal(connect::key_of(cfg)?, owner, app, cred)
}

pub(crate) fn open(cfg: &HostConfig, owner: &str, app: &str, sealed: &str) -> ApiResult<Credential> {
    connect::open(connect::key_of(cfg)?, owner, app, sealed)
        .map_err(|_| ApiError::internal("the saved credentials can't be read (the server's connector key changed); enter them again"))
}

/// Takes the lease on a sync (`table` row `key`) unless another sync holds it. Returns the lease.
/// The sync will read the source anew, so a change a webhook reported earlier is no longer pending.
pub(crate) fn claim(db: &dyn Db, table: &str, key: SqlValue, now: DateTime<Utc>) -> ApiResult<Option<String>> {
    // When it runs out, then a random id: each lease is one run's alone.
    let lease = format!("{} {}", ts(now + Duration::seconds(LEASE_SECS)), new_id());
    let claimed = db.execute(
        &format!(
            "UPDATE {table} SET running_until = ?, last_started_at = ?, pending_since = NULL
               WHERE id = ? AND (running_until IS NULL OR running_until <= ?)"
        ),
        &[lease.clone().into(), ts(now).into(), key, ts(now).into()],
    )? > 0;
    Ok(claimed.then_some(lease))
}

/// Whether this run still holds its lease. A run that took too long may have lost it to another.
pub(crate) fn holds(db: &dyn Db, table: &str, key: SqlValue, lease: &str) -> ApiResult<bool> {
    Ok(db.one(&format!("SELECT 1 AS ok FROM {table} WHERE id = ? AND running_until = ?"), &[key, lease.into()])?.is_some())
}

/// A webhook arrived while a sync was running: remember it, so Settings says to sync again.
pub(crate) fn mark_pending(db: &dyn Db, table: &str, key: SqlValue, now: DateTime<Utc>) -> ApiResult<()> {
    db.execute(&format!("UPDATE {table} SET pending_since = ? WHERE id = ?"), &[ts(now).into(), key])?;
    Ok(())
}

/// How a run ended, for [`finish`].
pub(crate) struct Ended<'a> {
    /// `ok`, `partial` or `failed`.
    pub status: &'a str,
    pub error: Option<&'a str>,
    pub result: Option<Value>,
}

/// Records how a run ended and lets go of its lease. A webhook that arrived while it ran stays
/// pending (see [`claim`]): the run may have read the source before that change.
pub(crate) fn finish(db: &dyn Db, table: &str, key: SqlValue, lease: &str, ended: Ended, now: DateTime<Utc>) -> ApiResult<()> {
    db.execute(
        &format!(
            "UPDATE {table} SET running_until = NULL, last_finished_at = ?, last_status = ?, last_error = ?,
               last_result = COALESCE(?, last_result)
             WHERE id = ? AND running_until = ?"
        ),
        &[ts(now).into(), ended.status.into(), ended.error.into(), ended.result.map(|r| r.to_string()).into(), key, lease.into()],
    )?;
    Ok(())
}

/// Where a sync stands, as Settings shows it.
#[derive(Clone, Debug, Default, Serialize, JsonSchema)]
pub struct SyncState {
    /// A sync is running now.
    pub running: bool,
    /// A webhook reported a change after the last sync started, so it may not be in yet. Sync again.
    pub pending: bool,
    pub last_started_at: Option<String>,
    pub last_finished_at: Option<String>,
    /// `ok`: everything is in. `partial`: more to do; sync again to continue. `failed`: see `last_error`.
    pub last_status: Option<String>,
    pub last_error: Option<String>,
}

pub(crate) fn state_of(r: &Row, now: DateTime<Utc>) -> SyncState {
    let running = r.opt_str("running_until").and_then(|l| l.split(' ').next().and_then(parse_ts)).is_some_and(|until| until > now);
    SyncState {
        running,
        pending: r.opt_str("pending_since").is_some(),
        last_started_at: r.opt_str("last_started_at"),
        last_finished_at: r.opt_str("last_finished_at"),
        last_status: r.opt_str("last_status"),
        last_error: r.opt_str("last_error"),
    }
}

/// Who a sync writes as: the admin who set it up, while they're still an active admin; otherwise
/// the workspace's first active admin. Checked at every sync, however it started: someone who's no
/// longer an admin must not author, or join topics for, content they can't see any more.
pub(crate) fn actor(db: &dyn Db, owner_id: &str) -> ApiResult<Actor> {
    let owner =
        db.one("SELECT id, name, handle, email FROM users WHERE id = ? AND role = 'admin' AND deactivated_at IS NULL", &params![owner_id])?;
    let row = match owner {
        Some(r) => r,
        None => db
            .one(
                "SELECT id, name, handle, email FROM users WHERE role = 'admin' AND deactivated_at IS NULL ORDER BY created_at LIMIT 1",
                &[],
            )?
            .ok_or_else(|| ApiError::internal("the workspace has no admin to sync as"))?,
    };
    Ok(Actor {
        user_id: row.str("id"),
        name: row.str("name"),
        handle: row.str("handle"),
        email: row.str("email"),
        role: Role::Admin,
        scopes: Scopes::ALL,
        via: Via::Api,
        token_id: None,
        session_hash: None,
    })
}

/// A context for a sync's writes, as [`actor`].
pub(crate) fn ctx<'a>(db: &'a dyn Db, cfg: &'a HostConfig, owner_id: &str, base_url: &str, now: DateTime<Utc>) -> ApiResult<Ctx<'a>> {
    Ok(Ctx { db, actor: actor(db, owner_id)?, now, cfg, base_url: base_url.to_string(), effects: vec![] })
}

/// Hex HMAC-SHA256 of raw bytes.
pub(crate) fn hmac_hex(key: &str, parts: &[&[u8]]) -> String {
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
    for p in parts {
        mac.update(p);
    }
    hex::encode(mac.finalize().into_bytes())
}

/// A webhook's answer that isn't a sync: `ignored`, `queued` (a sync is already running) or `pong`.
fn hook_answer(status: &str) -> Outcome {
    crate::http::done(Response::json(200, &json!({ "ok": true, "status": status })))
}

/// The answer to a webhook that started a sync; the host fills in its result.
fn hook_started(job: connect::Job) -> Outcome {
    let mut out = crate::http::done(Response::json(200, &json!(PENDING)));
    out.effects.push(crate::Effect::Connect(job));
    out
}

/// `POST /hooks/people` (BambooHR) and `POST /hooks/docs/<source id>` (GitHub, GitLab): something
/// changed there, so sync. Each checks its own secret.
pub fn hook(db: &dyn Db, cfg: &HostConfig, req: &Request) -> Outcome {
    let run = || -> ApiResult<Outcome> {
        if req.method != "POST" {
            return Err(ApiError::new(405, "method_not_allowed", "webhooks are POSTed"));
        }
        let now = Utc::now();
        let base_url = crate::http::base_url(cfg, req);
        let segments: Vec<&str> = req.path.trim_start_matches("/hooks/").split('/').collect();
        match segments.as_slice() {
            ["people"] => people::hook(db, cfg, req, &base_url, now),
            ["docs", id] if !id.is_empty() => docs::hook(db, cfg, req, id, &base_url, now),
            _ => Err(ApiError::not_found("webhook")),
        }
    };
    run().unwrap_or_else(|e| crate::http::failed(&e))
}

/// Hosted workspaces: a webhook's sync counts against the plan like any change, so it's refused
/// once the day's writes are used up.
fn check_plan(db: &dyn Db, cfg: &HostConfig, now: DateTime<Utc>) -> ApiResult<()> {
    match &cfg.hosting {
        Some(h) => crate::plan::check_write(db, h, now),
        None => Ok(()),
    }
}

/// `github` or `gitlab`.
pub(crate) fn repo_provider(typed: &str) -> ApiResult<repo::Provider> {
    repo::Provider::parse(typed).ok_or_else(|| ApiError::bad_request("`provider` must be `github` or `gitlab`"))
}

/// (host, repository) from what an admin typed.
pub(crate) fn repo_name(provider: repo::Provider, typed: &str, host: &str) -> ApiResult<(String, String)> {
    match provider {
        repo::Provider::GitHub if !host.trim().is_empty() && host.trim().trim_end_matches('/') != "https://github.com" => {
            Err(ApiError::bad_request("docs sync reads GitHub at github.com only; leave out `host`"))
        }
        repo::Provider::GitHub => repo::github_repo(typed).map(|r| ("github.com".to_string(), r)).map_err(ApiError::bad_request),
        repo::Provider::GitLab => repo::gitlab_project(typed, host).map_err(ApiError::bad_request),
    }
}

pub(crate) fn checked_branch(branch: &str) -> ApiResult<String> {
    let b = branch.trim();
    if repo::valid_branch(b) {
        Ok(b.to_string())
    } else {
        Err(ApiError::bad_request(format!("`{b}` isn't a branch name docs sync can use")))
    }
}

pub(crate) fn checked_folder(folder: &str) -> ApiResult<String> {
    repo::valid_folder(folder)
        .ok_or_else(|| ApiError::bad_request("`folder` should be a path like `docs/handbook`, without `..`, `:`, `?`, `#` or `%`"))
}

/// The error a failed sync answers with.
fn sync_failed(message: &str) -> ApiError {
    ApiError::new(400, "sync_failed", message.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_the_string_helper() {
        assert_eq!(hmac_hex("k", &[b"a", b"bc"]), crate::util::hmac_sha256_hex("k", "abc"));
    }
}
