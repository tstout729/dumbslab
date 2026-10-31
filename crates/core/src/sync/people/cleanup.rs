//! Webhooks DumbSlab added in BambooHR and still has to delete, so none is lost when a change stops
//! partway.
//!
//! - A save records the webhook it replaced when BambooHR wouldn't delete it then (its sign-in had
//!   expired, say, or the company changed), with the credentials that may delete it.
//! - A save records the webhook it just added in the step that gets its id, and forgets it once the
//!   save is done. If the save stops partway, the record stays.
//! - Removing the sync records its webhook.
//!
//! Each record holds the webhook's id and company, and its credentials sealed with the connector
//! key: an API key, or a sign-in's tokens, refresh token included. A cleanup job works on them after
//! saves, syncs and removals: it renews a sign-in first when it's about to expire, then deletes the
//! webhook. A record goes once the webhook is deleted or BambooHR says it's gone (404). After
//! [`MAX_ATTEMPTS`] failures DumbSlab gives up and says so in the activity log. One job works on a
//! record at a time (it holds a lease).
//!
//! A record may hold the very sign-in the saved sync uses (a save with the same sign-in whose old
//! webhook BambooHR wouldn't delete then). The cleanup never renews that one, which would spend the
//! refresh token the sync needs: it borrows the saved sign-in's current access token. Every renewal
//! of a sign-in, by a sync, a save or the cleanup, hands its new tokens to the records that held the
//! old refresh token ([`hand_over`]), so they keep working.

use chrono::{DateTime, Duration, Utc};
use serde_json::json;

use super::oauth::{self, Auth, Creds};
use super::setup::{self, PeopleSyncRemoved};
use super::{PROVIDER, PeopleJob, Work};
use crate::connect::{Finish, HttpCall, HttpReply, Job, Step};
use crate::db::{Db, DbExt, Row};
use crate::error::{ApiError, ApiResult};
use crate::events::{Event, emit};
use crate::util::{parse_ts, sha256_hex, ts};
use crate::{HostConfig, params};

/// Failed attempts before DumbSlab gives up on deleting a webhook.
pub(crate) const MAX_ATTEMPTS: i64 = 5;
/// Records one job works on.
const BATCH: i64 = 5;
/// How long one job may work on a record before another may.
const LEASE_SECS: i64 = 60;

/// What a record's credentials are sealed to: that record alone.
fn owner(id: &str) -> String {
    format!("people-sync-cleanup:{id}")
}

/// Records a webhook to delete, with the credentials that may delete it. Returns the record's id.
pub(crate) fn record(
    db: &dyn Db,
    cfg: &HostConfig,
    webhook_id: &str,
    subdomain: &str,
    creds: &Creds,
    now: DateTime<Utc>,
) -> ApiResult<String> {
    let id = crate::util::new_id();
    let secret = crate::sync::seal(cfg, &owner(&id), PROVIDER, &creds.cred)?;
    db.execute(
        "INSERT INTO people_sync_cleanup (id, webhook_id, subdomain, auth, secret, expires_at, refresh_hash, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        &params![
            id.clone(),
            webhook_id,
            subdomain,
            creds.auth.as_str(),
            secret,
            creds.expires_at.map(ts),
            creds.cred.refresh_token.as_deref().map(sha256_hex),
            ts(now)
        ],
    )?;
    Ok(id)
}

/// Records the webhook of the people sync being removed (`row`), when DumbSlab added one and its
/// credentials can still be read. Returns the record's id.
pub(crate) fn record_removed(db: &dyn Db, cfg: &HostConfig, row: &Row, now: DateTime<Utc>) -> ApiResult<Option<String>> {
    let Some(webhook_id) = row.opt_str("webhook_id") else { return Ok(None) };
    let Ok(creds) = Creds::of_row(cfg, row) else { return Ok(None) };
    Ok(Some(record(db, cfg, &webhook_id, &row.str("subdomain"), &creds, now)?))
}

/// Drops a record: its webhook is DumbSlab's to keep after all (a save finished).
pub(crate) fn forget(db: &dyn Db, id: &str) -> ApiResult<()> {
    db.execute("DELETE FROM people_sync_cleanup WHERE id = ?", &params![id])?;
    Ok(())
}

/// Webhooks DumbSlab still has to delete.
pub(crate) fn waiting(db: &dyn Db) -> ApiResult<i64> {
    db.scalar_i64("SELECT COUNT(*) FROM people_sync_cleanup", &[])
}

/// A sign-in was renewed: BambooHR may have spent the refresh token that records hold too, so hand
/// them the new tokens. Otherwise their webhooks could never be deleted.
pub(crate) fn hand_over(db: &dyn Db, cfg: &HostConfig, old_refresh: &str, creds: &Creds) -> ApiResult<()> {
    if old_refresh.is_empty() {
        return Ok(());
    }
    for r in db.query("SELECT id, secret FROM people_sync_cleanup WHERE refresh_hash = ?", &params![sha256_hex(old_refresh)])? {
        let id = r.str("id");
        let Ok(mut stored) = crate::sync::open(cfg, &owner(&id), PROVIDER, &r.str("secret")) else { continue };
        stored.token = creds.cred.token.clone();
        stored.refresh_token = creds.cred.refresh_token.clone();
        save_creds(db, cfg, &id, &Creds { auth: Auth::OAuth, cred: stored, expires_at: creds.expires_at }, None)?;
    }
    Ok(())
}

/// Stores a record's renewed credentials; with `lease`, only while this job holds it.
fn save_creds(db: &dyn Db, cfg: &HostConfig, id: &str, creds: &Creds, lease: Option<&str>) -> ApiResult<()> {
    let secret = crate::sync::seal(cfg, &owner(id), PROVIDER, &creds.cred)?;
    let hash = creds.cred.refresh_token.as_deref().map(sha256_hex);
    db.execute(
        "UPDATE people_sync_cleanup SET secret = ?, expires_at = ?, refresh_hash = ? WHERE id = ? AND (? IS NULL OR working_until = ?)",
        &params![secret, creds.expires_at.map(ts), hash, id, lease, lease],
    )?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq)]
enum State {
    /// Waiting for BambooHR to renew the sign-in.
    Renewing,
    /// Waiting for BambooHR to delete the webhook.
    Deleting,
    Done,
}

#[derive(Clone, Debug)]
struct Item {
    record: String,
    webhook_id: String,
    subdomain: String,
    creds: Creds,
    attempts: i64,
    state: State,
}

#[derive(Clone, Debug, PartialEq)]
enum Phase {
    Start,
    /// Waiting for the first requests: renewals, or deletions.
    First,
    /// Waiting for the deletions after renewals.
    Second,
}

/// Deleting the webhooks DumbSlab still has to (see the module docs).
#[derive(Clone, Debug)]
pub(crate) struct Cleanup {
    base_url: String,
    lease: String,
    items: Vec<Item>,
    /// The record whose fate the answer reports: removing the sync waits for its webhook.
    watch: Option<String>,
    phase: Phase,
}

/// A job that deletes the webhooks DumbSlab still has to. `watch`: answer like
/// `remove_people_sync`, about that record's webhook.
pub(crate) fn cleanup_job(base_url: &str, watch: Option<String>) -> Job {
    let c = Cleanup { base_url: base_url.to_string(), lease: String::new(), items: vec![], watch, phase: Phase::Start };
    Job::People(Box::new(PeopleJob::new(Work::Cleanup(c))))
}

fn creds_of(cfg: &HostConfig, r: &Row) -> ApiResult<Creds> {
    Ok(Creds {
        auth: Auth::parse(&r.str("auth")),
        cred: crate::sync::open(cfg, &owner(&r.str("id")), PROVIDER, &r.str("secret"))?,
        expires_at: r.opt_str("expires_at").and_then(|s| parse_ts(&s)),
    })
}

/// The request for an item: renew its sign-in first when it's about to expire.
fn first_call(cfg: &HostConfig, base_url: &str, item: &mut Item, now: DateTime<Utc>) -> Option<HttpCall> {
    if item.creds.needs_refresh(now) {
        let call = oauth::renew_call(cfg, &item.subdomain, base_url, &item.creds).ok()?;
        item.state = State::Renewing;
        return Some(call);
    }
    item.state = State::Deleting;
    Some(setup::delete_call(&item.subdomain, &item.creds, &item.webhook_id))
}

pub(super) fn step(
    db: &dyn Db,
    cfg: &HostConfig,
    c: &mut Cleanup,
    staged: &mut Vec<crate::Effect>,
    replies: Vec<HttpReply>,
    now: DateTime<Utc>,
) -> ApiResult<Step> {
    match c.phase {
        Phase::Start => {
            c.lease = format!("{} {}", ts(now + Duration::seconds(LEASE_SECS)), crate::util::new_id());
            let live = db.one("SELECT * FROM people_sync WHERE id = 1", &[])?;
            // The saved sign-in, which records may share: its refresh token is the sync's to spend.
            let signed_in = live.as_ref().filter(|l| l.str("auth") == Auth::OAuth.as_str()).and_then(|l| Creds::of_row(cfg, l).ok());
            let signed_in_hash = signed_in.as_ref().and_then(|c| c.cred.refresh_token.as_deref()).map(sha256_hex);
            let rows = db.query(
                "SELECT * FROM people_sync_cleanup WHERE working_until IS NULL OR working_until <= ? ORDER BY created_at LIMIT ?",
                &params![ts(now), BATCH],
            )?;
            let mut calls = vec![];
            for r in rows {
                let id = r.str("id");
                // The saved sync's own webhook is never deleted.
                if live
                    .as_ref()
                    .is_some_and(|l| l.str("subdomain") == r.str("subdomain") && l.opt_str("webhook_id") == r.opt_str("webhook_id"))
                {
                    forget(db, &id)?;
                    continue;
                }
                let claimed = db.execute(
                    "UPDATE people_sync_cleanup SET working_until = ? WHERE id = ? AND (working_until IS NULL OR working_until <= ?)",
                    &params![c.lease.clone(), id.clone(), ts(now)],
                )? > 0;
                if !claimed {
                    continue;
                }
                let Ok(mut creds) = creds_of(cfg, &r) else {
                    // Sealed with another connector key: it can never be deleted.
                    give_up(db, cfg, c, staged, &id, &r.str("subdomain"), now)?;
                    continue;
                };
                let shares = r.opt_str("refresh_hash").is_some() && r.opt_str("refresh_hash") == signed_in_hash;
                if let Some(saved) = signed_in.as_ref().filter(|_| shares) {
                    creds = Creds { cred: crate::connect::Credential { refresh_token: None, ..saved.cred.clone() }, ..saved.clone() };
                }
                let mut item = Item {
                    record: id,
                    webhook_id: r.str("webhook_id"),
                    subdomain: r.str("subdomain"),
                    creds,
                    attempts: r.i64("attempts"),
                    state: State::Done,
                };
                match first_call(cfg, &c.base_url, &mut item, now) {
                    Some(call) => calls.push(call),
                    None => failed(db, cfg, c, staged, &mut item, now)?,
                }
                c.items.push(item);
            }
            if calls.is_empty() {
                return finish(db, c);
            }
            c.phase = Phase::First;
            Ok(Step::Fetch(calls))
        }
        Phase::First | Phase::Second => {
            let waiting = if c.phase == Phase::First { vec![State::Renewing, State::Deleting] } else { vec![State::Deleting] };
            let mut replies = replies.into_iter();
            let mut calls = vec![];
            let mut items = std::mem::take(&mut c.items);
            for item in items.iter_mut().filter(|i| waiting.contains(&i.state)) {
                let reply = replies.next().unwrap_or_default();
                match item.state {
                    State::Renewing => match crate::connect::standard_token("BambooHR", &reply) {
                        Ok(tokens) => {
                            let spent = item.creds.cred.refresh_token.clone().unwrap_or_default();
                            item.creds.take(tokens, now);
                            // This record, and any other holding the same sign-in.
                            save_creds(db, cfg, &item.record, &item.creds, Some(&c.lease))?;
                            hand_over(db, cfg, &spent, &item.creds)?;
                            item.state = State::Deleting;
                            calls.push(setup::delete_call(&item.subdomain, &item.creds, &item.webhook_id));
                        }
                        Err(_) => failed(db, cfg, c, staged, item, now)?,
                    },
                    State::Deleting if setup::deleted(&reply) => {
                        forget(db, &item.record)?;
                        item.state = State::Done;
                    }
                    State::Deleting => failed(db, cfg, c, staged, item, now)?,
                    State::Done => {}
                }
            }
            c.items = items;
            if calls.is_empty() {
                return finish(db, c);
            }
            c.phase = Phase::Second;
            Ok(Step::Fetch(calls))
        }
    }
}

/// One more failed attempt: try again later, or give up after [`MAX_ATTEMPTS`].
fn failed(
    db: &dyn Db,
    cfg: &HostConfig,
    c: &Cleanup,
    staged: &mut Vec<crate::Effect>,
    item: &mut Item,
    now: DateTime<Utc>,
) -> ApiResult<()> {
    item.state = State::Done;
    if item.attempts + 1 >= MAX_ATTEMPTS {
        return give_up(db, cfg, c, staged, &item.record, &item.subdomain, now);
    }
    db.execute(
        "UPDATE people_sync_cleanup SET attempts = attempts + 1, working_until = NULL WHERE id = ? AND working_until = ?",
        &params![item.record.clone(), c.lease.clone()],
    )?;
    Ok(())
}

/// Stops trying, and says so in the activity log for admins.
fn give_up(
    db: &dyn Db,
    cfg: &HostConfig,
    c: &Cleanup,
    staged: &mut Vec<crate::Effect>,
    id: &str,
    subdomain: &str,
    now: DateTime<Utc>,
) -> ApiResult<()> {
    forget(db, id)?;
    // Recorded as the workspace's first admin; a workspace always has one.
    if let Ok(mut ctx) = crate::sync::ctx(db, cfg, "", &c.base_url, now) {
        emit(
            &mut ctx,
            Event::new(
                "people_sync.webhook_abandoned",
                "people_sync",
                "1",
                format!(
                    "couldn't delete an old webhook in BambooHR ({subdomain}.bamboohr.com); it may keep calling, and DumbSlab turns it away"
                ),
            )
            .data(json!({ "subdomain": subdomain }))
            .admin_only(),
        )?;
        staged.append(&mut ctx.effects);
    }
    Ok(())
}

fn finish(db: &dyn Db, c: &Cleanup) -> ApiResult<Step> {
    let value = match &c.watch {
        Some(id) => {
            let gone = db.one("SELECT 1 AS ok FROM people_sync_cleanup WHERE id = ?", &params![id.clone()])?.is_none();
            let removed = PeopleSyncRemoved { ok: true, notice: (!gone).then(|| setup::NOT_DELETED_YET.to_string()) };
            serde_json::to_value(removed).map_err(|e| ApiError::internal(e.to_string()))?
        }
        None => json!({ "ok": true }),
    };
    Ok(Step::Done(Finish::Fill(value)))
}
