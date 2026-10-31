//! Cleaning up the webhooks DumbSlab added in BambooHR, so none outlives its use.
//!
//! A webhook DumbSlab failed to delete is harmless: it posts only an employee's id and the names
//! of the fields that changed (an event-based webhook, with no post fields), and `/hooks/people`
//! turns it away once the sync, or the webhook's private key, is gone. Cleanup is still owed, and it
//! reconciles rather than tracking each webhook's id, which a step that rolled back can lose:
//!
//! - Each webhook DumbSlab adds is named for this workspace: `DumbSlab people sync (<address>)
//!   <tag>`, where the tag is the workspace's own, so it outlives address changes.
//! - A record keeps credentials DumbSlab still has to look through, one per connection: those a
//!   save was about to use and the ones it replaced (recorded before it changes anything in
//!   BambooHR), and a removed sync's. They're sealed with the connector key, refresh token included.
//! - A pass lists the webhooks a record's credentials can see (`GET /api/v1/webhooks`), and deletes
//!   every one with this workspace's tag that posts to `/hooks/people`, except the live one. Then it
//!   drops the record. When the live connection's list lacks the live webhook (a save stopped
//!   partway), Settings says to save again.
//! - Passes run after saves, sign-ins and syncs, when Settings › People sync loads, and when a
//!   delivery arrives for a webhook DumbSlab doesn't recognize: an orphan prompts its own deletion,
//!   also after the sync was removed. A record waits longer after each failed pass (from a minute,
//!   doubling, up to a day).
//! - Timeouts, 429 and 5xx never end a record. DumbSlab gives up only when the credentials are
//!   definitely dead (BambooHR refuses to renew them, or answers 401 or 403 to fresh ones, or the
//!   company is gone), or after [`RETENTION_DAYS`]. Either way it says so in the activity log, with
//!   the company and the webhook ids it knows, so an admin can delete them by hand, and drops the
//!   credentials.
//! - The live connection's record is worked with the saved credentials themselves, renewed through
//!   the sync's renewal lease, never with a copy: a copy's renewal would spend the refresh token the
//!   sync needs. Every renewal of a sign-in hands its new tokens to the records holding the old
//!   refresh token ([`hand_over`]).
//! - Passes wait while a save is under way, and decide what to delete against the live webhook as it
//!   is then, so they never delete a webhook a save is adding.
//! - A record's version goes up whenever a save or a removal records its connection again. A pass
//!   ends, backs off or gives up on a record only at the version it began with; otherwise it lets
//!   go, and leaves the new work to the next pass.
//! - A renewal that finds the connection changed meanwhile (a reconnect) isn't a refusal: its tokens
//!   went to the record, and the pass goes on with them. BambooHR refusing to renew a retired
//!   connection's copy ends the record only the second time: a renewal still under way when it
//!   retired may hand over new tokens meanwhile.
//!
//! A pass takes at most four steps: renew, list, delete, done.

use chrono::{DateTime, Duration, Utc};
use serde_json::json;

use super::oauth::{self, Auth, Creds, Renewal};
use super::setup::{self, PeopleSyncRemoved};
use super::{PROVIDER, PeopleJob, Work};
use crate::connect::{Finish, HttpCall, HttpReply, Job, Step};
use crate::db::{Db, DbExt, Row};
use crate::error::{ApiError, ApiResult};
use crate::events::{Event, emit};
use crate::util::{parse_ts, sha256_hex, ts};
use crate::{HostConfig, params};

/// How long DumbSlab keeps trying with credentials that only ever fail for a while.
pub(crate) const RETENTION_DAYS: i64 = 30;
/// Records one pass works on.
const BATCH: i64 = 5;
/// How long one pass may hold a record before another may take it.
const LEASE_SECS: i64 = 90;
/// The wait after the first failed pass; it doubles after each one, up to [`MAX_WAIT_SECS`].
const FIRST_WAIT_SECS: i64 = 60;
const MAX_WAIT_SECS: i64 = 24 * 3600;

/// What a record's credentials are sealed to: that record alone.
fn owner(connection: &str) -> String {
    format!("people-sync-cleanup:{connection}")
}

/// This workspace's tag, in the name of every webhook it adds. Made once.
pub(crate) fn tag(db: &dyn Db) -> ApiResult<String> {
    let fresh = format!("ds-{}", crate::util::new_id().to_ascii_lowercase());
    db.execute("INSERT INTO settings (key, value) VALUES ('people_sync_tag', ?) ON CONFLICT(key) DO NOTHING", &params![fresh])?;
    Ok(crate::ops::admin::setting(db, "people_sync_tag")?.unwrap_or_default())
}

/// The name of a webhook this workspace adds: its address, for people, and its tag.
pub(crate) fn webhook_name(base_url: &str, tag: &str) -> String {
    let host = base_url.split_once("://").map_or(base_url, |(_, h)| h);
    let host: String = host.chars().take(60).collect();
    format!("DumbSlab people sync ({host}) {tag}")
}

/// One of this workspace's webhooks: it posts to `/hooks/people`, and has the workspace's tag.
fn ours(webhook: &serde_json::Value, tag: &str) -> bool {
    let (name, url) = (webhook["name"].as_str().unwrap_or_default(), webhook["url"].as_str().unwrap_or_default());
    !tag.is_empty() && name.ends_with(&format!(" {tag}")) && url.split(['?', '#']).next().unwrap_or_default().ends_with(setup::HOOK_PATH)
}

/// Records `creds` (of `connection`, for `subdomain`) for a cleanup pass, with `known` webhook ids
/// among theirs. A record that's there already takes the newer credentials and starts over.
pub(crate) fn record(
    db: &dyn Db,
    cfg: &HostConfig,
    connection: &str,
    subdomain: &str,
    creds: &Creds,
    known: Option<&str>,
    now: DateTime<Utc>,
) -> ApiResult<()> {
    let secret = crate::sync::seal(cfg, &owner(connection), PROVIDER, &creds.cred)?;
    db.execute(
        "INSERT INTO people_sync_cleanup (connection, subdomain, auth, secret, expires_at, refresh_hash, known_ids, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(connection) DO UPDATE SET subdomain = excluded.subdomain, auth = excluded.auth, secret = excluded.secret,
           expires_at = excluded.expires_at, refresh_hash = excluded.refresh_hash, failures = 0, next_attempt_at = NULL,
           refused = 0, version = people_sync_cleanup.version + 1, created_at = excluded.created_at",
        &params![
            connection,
            subdomain,
            creds.auth.as_str(),
            secret,
            creds.expires_at.map(ts),
            creds.cred.refresh_token.as_deref().map(sha256_hex),
            "",
            ts(now)
        ],
    )?;
    if let Some(id) = known {
        know(db, connection, id)?;
    }
    Ok(())
}

/// Notes a webhook id among a record's, for the activity log if DumbSlab gives up.
pub(crate) fn know(db: &dyn Db, connection: &str, id: &str) -> ApiResult<()> {
    db.execute(
        "UPDATE people_sync_cleanup SET known_ids = CASE WHEN known_ids = '' THEN ? ELSE known_ids || ',' || ? END
         WHERE connection = ? AND (',' || known_ids || ',') NOT LIKE ?",
        &params![id, id, connection, format!("%,{id},%")],
    )?;
    Ok(())
}

/// A record for `connection` is waiting.
pub(crate) fn exists(db: &dyn Db, connection: &str) -> ApiResult<bool> {
    Ok(db.one("SELECT 1 AS ok FROM people_sync_cleanup WHERE connection = ?", &params![connection])?.is_some())
}

/// Drops a record whose work is done already.
pub(crate) fn drop_record(db: &dyn Db, connection: &str) -> ApiResult<()> {
    db.execute("DELETE FROM people_sync_cleanup WHERE connection = ?", &params![connection])?;
    Ok(())
}

/// Records the people sync being removed (`row`), when DumbSlab added a webhook for it and its
/// credentials can still be read. Returns the record's connection.
pub(crate) fn record_removed(db: &dyn Db, cfg: &HostConfig, row: &Row, now: DateTime<Utc>) -> ApiResult<Option<String>> {
    let Some(webhook_id) = row.opt_str("webhook_id") else { return Ok(None) };
    let Ok(creds) = Creds::of_row(cfg, row) else { return Ok(None) };
    let connection = row.opt_str("connection").unwrap_or_else(crate::util::new_id);
    record(db, cfg, &connection, &row.str("subdomain"), &creds, Some(&webhook_id), now)?;
    Ok(Some(connection))
}

/// Records still to work through.
pub(crate) fn waiting(db: &dyn Db) -> ApiResult<i64> {
    db.scalar_i64("SELECT COUNT(*) FROM people_sync_cleanup", &[])
}

/// A pass is due: a record waits no longer, and no save is under way.
pub(crate) fn due(db: &dyn Db, now: DateTime<Utc>) -> ApiResult<bool> {
    let ready = db.one(
        "SELECT 1 AS ok FROM people_sync_cleanup WHERE (next_attempt_at IS NULL OR next_attempt_at <= ?)
           AND (working_until IS NULL OR working_until <= ?) LIMIT 1",
        &params![ts(now), ts(now)],
    )?;
    Ok(ready.is_some() && !setup::saving(db, now)?)
}

/// A sign-in was renewed: BambooHR may have spent the refresh token that records hold too, so hand
/// them the new tokens. Otherwise their credentials would be dead.
pub(crate) fn hand_over(db: &dyn Db, cfg: &HostConfig, old_refresh: &str, creds: &Creds) -> ApiResult<()> {
    if old_refresh.is_empty() {
        return Ok(());
    }
    for r in db.query("SELECT connection, secret FROM people_sync_cleanup WHERE refresh_hash = ?", &params![sha256_hex(old_refresh)])? {
        let connection = r.str("connection");
        let Ok(mut stored) = crate::sync::open(cfg, &owner(&connection), PROVIDER, &r.str("secret")) else { continue };
        stored.token = creds.cred.token.clone();
        stored.refresh_token = creds.cred.refresh_token.clone();
        save_creds(db, cfg, &connection, &Creds { auth: Auth::OAuth, cred: stored, expires_at: creds.expires_at })?;
    }
    Ok(())
}

fn save_creds(db: &dyn Db, cfg: &HostConfig, connection: &str, creds: &Creds) -> ApiResult<()> {
    let secret = crate::sync::seal(cfg, &owner(connection), PROVIDER, &creds.cred)?;
    let hash = creds.cred.refresh_token.as_deref().map(sha256_hex);
    db.execute(
        "UPDATE people_sync_cleanup SET secret = ?, expires_at = ?, refresh_hash = ?, refused = 0 WHERE connection = ?",
        &params![secret, creds.expires_at.map(ts), hash, connection],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Passes

#[derive(Clone, Debug, PartialEq)]
enum State {
    /// Waiting for BambooHR to renew the sign-in: the live connection's renewal lease, if it is that.
    Renewing(Option<String>),
    /// Waiting for the list of webhooks.
    Listing,
    /// Waiting for this many deletions.
    Deleting(usize),
    Done,
}

#[derive(Clone, Debug)]
struct Item {
    connection: String,
    subdomain: String,
    creds: Creds,
    /// The saved sync's own connection: its credentials are the saved ones.
    live: bool,
    /// The access token was renewed in this pass or is still good: a 401 or 403 then means the
    /// credentials are dead, not stale.
    fresh: bool,
    failures: i64,
    created_at: DateTime<Utc>,
    known_ids: String,
    /// The record's version when this pass took it.
    version: i64,
    /// BambooHR refused to renew these credentials once before.
    refused: bool,
    state: State,
}

#[derive(Clone, Debug, PartialEq)]
enum Phase {
    Start,
    Working,
}

/// A cleanup pass (see the module docs).
#[derive(Clone, Debug)]
pub(crate) struct Cleanup {
    base_url: String,
    lease: String,
    tag: String,
    items: Vec<Item>,
    /// The connection whose fate the answer reports: removing the sync waits for its pass.
    watch: Option<String>,
    phase: Phase,
}

/// A cleanup pass. `watch`: answer like `remove_people_sync`, about that connection's record.
pub(crate) fn cleanup_job(base_url: &str, watch: Option<String>) -> Job {
    let c = Cleanup { base_url: base_url.to_string(), lease: String::new(), tag: String::new(), items: vec![], watch, phase: Phase::Start };
    Job::People(Box::new(PeopleJob::new(Work::Cleanup(c))))
}

fn creds_of(cfg: &HostConfig, r: &Row) -> ApiResult<Creds> {
    Ok(Creds {
        auth: Auth::parse(&r.str("auth")),
        cred: crate::sync::open(cfg, &owner(&r.str("connection")), PROVIDER, &r.str("secret"))?,
        expires_at: r.opt_str("expires_at").and_then(|s| parse_ts(&s)),
    })
}

fn list_call(item: &Item) -> HttpCall {
    item.creds.call(HttpCall::get(super::api_url(&item.subdomain, "webhooks")))
}

/// How a request went, for a record.
enum Outcome {
    Ok,
    /// Try again later: a timeout, a rate limit, BambooHR's own error, or a stale token.
    Later(String),
    /// The credentials will never work: give up.
    Dead(String),
}

fn outcome(item: &Item, reply: &HttpReply, listing: bool) -> Outcome {
    match reply.status {
        s if (200..300).contains(&s) => Outcome::Ok,
        0 | 429 => Outcome::Later(crate::connect::http_error("BambooHR", reply)),
        s if s >= 500 => Outcome::Later(crate::connect::http_error("BambooHR", reply)),
        401 | 403 if item.fresh => {
            Outcome::Dead(format!("BambooHR refused DumbSlab's credentials for {}.bamboohr.com (HTTP {})", item.subdomain, reply.status))
        }
        404 if listing => Outcome::Dead(format!("BambooHR has no company at {}.bamboohr.com any more", item.subdomain)),
        s => Outcome::Later(format!("BambooHR answered HTTP {s}.")),
    }
}

pub(super) fn step(
    db: &dyn Db,
    cfg: &HostConfig,
    c: &mut Cleanup,
    staged: &mut Vec<crate::Effect>,
    replies: Vec<HttpReply>,
    now: DateTime<Utc>,
) -> ApiResult<Step> {
    let mut calls = vec![];
    if c.phase == Phase::Start {
        c.phase = Phase::Working;
        // A save may be adding a webhook: wait for it.
        if setup::saving(db, now)? {
            return finish(db, c);
        }
        c.lease = format!("{} {}", ts(now + Duration::seconds(LEASE_SECS)), crate::util::new_id());
        c.tag = tag(db)?;
        let live = db.one("SELECT * FROM people_sync WHERE id = 1", &[])?;
        let rows = db.query(
            "SELECT * FROM people_sync_cleanup WHERE (next_attempt_at IS NULL OR next_attempt_at <= ?)
               AND (working_until IS NULL OR working_until <= ?) ORDER BY created_at LIMIT ?",
            &params![ts(now), ts(now), BATCH],
        )?;
        for r in rows {
            let connection = r.str("connection");
            let claimed = db.execute(
                "UPDATE people_sync_cleanup SET working_until = ? WHERE connection = ? AND (working_until IS NULL OR working_until <= ?)",
                &params![c.lease.clone(), connection.clone(), ts(now)],
            )? > 0;
            if !claimed {
                continue;
            }
            let is_live = live.as_ref().filter(|l| l.opt_str("connection").as_deref() == Some(connection.as_str()));
            let creds = match is_live {
                Some(l) => Creds::of_row(cfg, l),
                None => creds_of(cfg, &r),
            };
            let mut item = Item {
                connection,
                subdomain: r.str("subdomain"),
                creds: Creds::api_key(String::new()),
                live: is_live.is_some(),
                fresh: true,
                failures: r.i64("failures"),
                created_at: r.opt_str("created_at").and_then(|s| parse_ts(&s)).unwrap_or(now),
                known_ids: r.str("known_ids"),
                version: r.i64("version"),
                refused: r.bool("refused"),
                state: State::Done,
            };
            match creds {
                Ok(creds) => item.creds = creds,
                Err(_) => {
                    // Sealed with another connector key: nothing can use them any more.
                    give_up(db, cfg, c, staged, &mut item, "the saved credentials can't be read any more", now)?;
                    continue;
                }
            }
            if let Some(call) = first_call(db, cfg, c, staged, &mut item, now)? {
                calls.push(call);
            }
            c.items.push(item);
        }
    } else {
        let mut replies = replies.into_iter();
        let mut items = std::mem::take(&mut c.items);
        for item in items.iter_mut() {
            let next = match item.state.clone() {
                State::Renewing(lease) => renewed(db, cfg, c, staged, item, lease, &replies.next().unwrap_or_default(), now)?,
                State::Listing => listed(db, cfg, c, staged, item, &replies.next().unwrap_or_default(), now)?,
                State::Deleting(n) => {
                    let answers: Vec<HttpReply> = (0..n).map(|_| replies.next().unwrap_or_default()).collect();
                    deleted(db, cfg, c, staged, item, &answers, now)?;
                    vec![]
                }
                State::Done => vec![],
            };
            calls.extend(next);
        }
        c.items = items;
    }
    if calls.is_empty() {
        return finish(db, c);
    }
    Ok(Step::Fetch(calls))
}

/// An item's first request: a renewal when its sign-in is about to expire, otherwise the list.
fn first_call(
    db: &dyn Db,
    cfg: &HostConfig,
    c: &Cleanup,
    staged: &mut Vec<crate::Effect>,
    item: &mut Item,
    now: DateTime<Utc>,
) -> ApiResult<Option<HttpCall>> {
    if !item.creds.needs_refresh(now) {
        item.fresh = item.creds.auth == Auth::ApiKey || item.creds.expires_at.is_none_or(|e| e > now);
        item.state = State::Listing;
        return Ok(Some(list_call(item)));
    }
    let lease = match item.live {
        // The saved sign-in: renewed through its own lease, never with a copy.
        true => match oauth::renewal(db, cfg, &item.connection, None, now)? {
            Renewal::Refresh(lease, creds) => {
                item.creds = creds;
                Some(lease)
            }
            Renewal::UseCurrent(creds) => {
                item.creds = creds;
                item.state = State::Listing;
                return Ok(Some(list_call(item)));
            }
            Renewal::Wait | Renewal::Changed => {
                later(db, cfg, c, staged, item, "the sign-in was being renewed or changed", now)?;
                return Ok(None);
            }
        },
        false => None,
    };
    match oauth::renew_call(cfg, &item.subdomain, &c.base_url, &item.creds) {
        Ok(call) => {
            item.state = State::Renewing(lease);
            Ok(Some(call))
        }
        Err(why) => {
            if let Some(l) = &lease {
                db.execute("UPDATE people_sync SET refreshing_until = NULL WHERE id = 1 AND refreshing_until = ?", &params![l.clone()])?;
            }
            give_up(db, cfg, c, staged, item, &why, now)?;
            Ok(None)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn renewed(
    db: &dyn Db,
    cfg: &HostConfig,
    c: &Cleanup,
    staged: &mut Vec<crate::Effect>,
    item: &mut Item,
    lease: Option<String>,
    reply: &HttpReply,
    now: DateTime<Utc>,
) -> ApiResult<Vec<HttpCall>> {
    let transient = reply.status == 0 || reply.status == 429 || reply.status >= 500;
    let result = match &lease {
        Some(l) => oauth::apply_refresh(db, cfg, &mut item.creds, &item.connection, l, reply, now)?,
        None => match crate::connect::standard_token("BambooHR", reply) {
            Ok(tokens) => {
                let spent = item.creds.cred.refresh_token.clone().unwrap_or_default();
                item.creds.take(tokens, now);
                save_creds(db, cfg, &item.connection, &item.creds)?;
                hand_over(db, cfg, &spent, &item.creds)?;
                Ok(())
            }
            Err(why) => Err(why),
        },
    };
    let list = |item: &mut Item| {
        item.fresh = true;
        item.state = State::Listing;
        vec![list_call(item)]
    };
    match result {
        Ok(()) => Ok(list(item)),
        // A reconnect retired the connection while BambooHR renewed it: the new tokens went to its
        // record (handed over), and they work. Go on with them.
        Err(why) if why == oauth::CHANGED => {
            item.live = false;
            Ok(list(item))
        }
        Err(why) if transient => later(db, cfg, c, staged, item, &why, now).map(|_| vec![]),
        // A retired connection's copy: a renewal still under way when it retired may yet hand over
        // new tokens, so only a second refusal ends it.
        Err(why) if lease.is_none() && !item.refused => {
            let refused = "UPDATE people_sync_cleanup SET refused = 1 WHERE connection = ? AND version = ?";
            db.execute(refused, &params![item.connection.clone(), item.version])?;
            later(db, cfg, c, staged, item, &why, now).map(|_| vec![])
        }
        Err(_) => give_up(db, cfg, c, staged, item, "BambooHR refused to renew the sign-in", now).map(|_| vec![]),
    }
}

fn listed(
    db: &dyn Db,
    cfg: &HostConfig,
    c: &Cleanup,
    staged: &mut Vec<crate::Effect>,
    item: &mut Item,
    reply: &HttpReply,
    now: DateTime<Utc>,
) -> ApiResult<Vec<HttpCall>> {
    match outcome(item, reply, true) {
        Outcome::Ok => {}
        Outcome::Later(why) => return later(db, cfg, c, staged, item, &why, now).map(|_| vec![]),
        Outcome::Dead(why) => return give_up(db, cfg, c, staged, item, &why, now).map(|_| vec![]),
    }
    // What to delete is decided now, against the live webhook as it is now. A save under way may be
    // adding one: wait for it.
    if setup::saving(db, now)? {
        return later(db, cfg, c, staged, item, "a save was under way", now).map(|_| vec![]);
    }
    let live = db.one("SELECT subdomain, webhook_id FROM people_sync WHERE id = 1", &[])?;
    let live_id = live.as_ref().filter(|l| l.str("subdomain") == item.subdomain).and_then(|l| l.opt_str("webhook_id"));
    let v = reply.json();
    let mine: Vec<String> =
        v["webhooks"].as_array().into_iter().flatten().filter(|w| ours(w, &c.tag)).map(|w| super::text(&w["id"])).collect();
    if item.live
        && let Some(id) = &live_id
        && !mine.contains(id)
    {
        // The live webhook is gone (a save stopped partway after deleting it): say so in Settings.
        setup::lost(db, id, &item.subdomain)?;
    }
    let doomed: Vec<&String> = mine.iter().filter(|id| Some(*id) != live_id.as_ref() && !id.is_empty()).collect();
    if doomed.is_empty() {
        return done(db, c, item).map(|_| vec![]);
    }
    for id in &doomed {
        know(db, &item.connection, id)?;
    }
    item.state = State::Deleting(doomed.len());
    Ok(doomed.into_iter().map(|id| setup::delete_call(&item.subdomain, &item.creds, id)).collect())
}

fn deleted(
    db: &dyn Db,
    cfg: &HostConfig,
    c: &Cleanup,
    staged: &mut Vec<crate::Effect>,
    item: &mut Item,
    answers: &[HttpReply],
    now: DateTime<Utc>,
) -> ApiResult<()> {
    for reply in answers {
        if reply.status == 404 {
            continue;
        }
        match outcome(item, reply, false) {
            Outcome::Ok => {}
            Outcome::Later(why) => return later(db, cfg, c, staged, item, &why, now),
            Outcome::Dead(why) => return give_up(db, cfg, c, staged, item, &why, now),
        }
    }
    done(db, c, item).map(|_| ())
}

/// Every webhook found is gone: drop the record and its credentials, unless it was recorded again
/// meanwhile (new work for the next pass). `false` then.
fn done(db: &dyn Db, c: &Cleanup, item: &mut Item) -> ApiResult<bool> {
    item.state = State::Done;
    let dropped = db
        .execute("DELETE FROM people_sync_cleanup WHERE connection = ? AND version = ?", &params![item.connection.clone(), item.version])?
        > 0;
    if !dropped {
        let_go(db, c, item)?;
    }
    Ok(dropped)
}

/// Lets go of the record, as it is, for the next pass.
fn let_go(db: &dyn Db, c: &Cleanup, item: &Item) -> ApiResult<()> {
    db.execute(
        "UPDATE people_sync_cleanup SET working_until = NULL WHERE connection = ? AND working_until = ?",
        &params![item.connection.clone(), c.lease.clone()],
    )?;
    Ok(())
}

/// Try again later, waiting longer each time. Only the retention limit ends a record that keeps
/// failing this way.
fn later(
    db: &dyn Db,
    cfg: &HostConfig,
    c: &Cleanup,
    staged: &mut Vec<crate::Effect>,
    item: &mut Item,
    why: &str,
    now: DateTime<Utc>,
) -> ApiResult<()> {
    item.state = State::Done;
    if now - item.created_at > Duration::days(RETENTION_DAYS) {
        let why = format!("it kept failing for {RETENTION_DAYS} days (last: {})", why.trim_end_matches('.'));
        return give_up(db, cfg, c, staged, item, &why, now);
    }
    let failures = item.failures + 1;
    let wait = (FIRST_WAIT_SECS << (failures - 1).clamp(0, 20)).min(MAX_WAIT_SECS);
    // Recorded again meanwhile: the new work starts over, without waiting.
    db.execute(
        "UPDATE people_sync_cleanup SET failures = ?, next_attempt_at = ? WHERE connection = ? AND working_until = ? AND version = ?",
        &params![failures, ts(now + Duration::seconds(wait)), item.connection.clone(), c.lease.clone(), item.version],
    )?;
    let_go(db, c, item)
}

/// Stops trying with these credentials: says so in the activity log for admins, naming the
/// company and the webhooks to delete by hand, and drops the credentials.
fn give_up(
    db: &dyn Db,
    cfg: &HostConfig,
    c: &Cleanup,
    staged: &mut Vec<crate::Effect>,
    item: &mut Item,
    why: &str,
    now: DateTime<Utc>,
) -> ApiResult<()> {
    let known = item.known_ids.clone();
    let ids: Vec<&str> = known.split(',').filter(|s| !s.is_empty()).collect();
    if !done(db, c, item)? {
        // Recorded again meanwhile, maybe with other credentials: the next pass tries those.
        return Ok(());
    }
    let which = match ids.as_slice() {
        [] => format!("the webhooks named \"DumbSlab people sync (…) {}\"", c.tag),
        [one] => format!("webhook {one}"),
        many => format!("webhooks {}", many.join(", ")),
    };
    let summary = format!(
        "stopped trying to delete DumbSlab's old webhooks in BambooHR ({}.bamboohr.com): {why}. Delete {which} there by hand.",
        item.subdomain
    );
    // Recorded as the workspace's first admin; a workspace always has one.
    if let Ok(mut ctx) = crate::sync::ctx(db, cfg, "", &c.base_url, now) {
        emit(
            &mut ctx,
            Event::new("people_sync.webhook_abandoned", "people_sync", "1", summary)
                .data(json!({ "subdomain": item.subdomain, "webhook_ids": ids, "webhook_name_ends_with": c.tag }))
                .admin_only(),
        )?;
        staged.append(&mut ctx.effects);
    }
    Ok(())
}

fn finish(db: &dyn Db, c: &Cleanup) -> ApiResult<Step> {
    let value = match &c.watch {
        Some(connection) => {
            let gone = db.one("SELECT 1 AS ok FROM people_sync_cleanup WHERE connection = ?", &params![connection.clone()])?.is_none();
            let removed = PeopleSyncRemoved { ok: true, notice: (!gone).then(|| setup::NOT_DELETED_YET.to_string()) };
            serde_json::to_value(removed).map_err(|e| ApiError::internal(e.to_string()))?
        }
        None => json!({ "ok": true }),
    };
    Ok(Step::Done(Finish::Fill(value)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhooks_are_this_workspaces_by_name_and_address() {
        let name = webhook_name("https://acme.dumbslab.com", "ds-abc");
        assert_eq!(name, "DumbSlab people sync (acme.dumbslab.com) ds-abc");
        let hook = |name: &str, url: &str| json!({ "id": "1", "name": name, "url": url });
        assert!(ours(&hook(&name, "https://acme.dumbslab.com/hooks/people"), "ds-abc"));
        assert!(ours(&hook(&name, "https://old-name.dumbslab.com/hooks/people"), "ds-abc"), "an earlier address");
        assert!(!ours(&hook(&name, "https://acme.dumbslab.com/hooks/docs/1"), "ds-abc"));
        assert!(!ours(&hook("DumbSlab people sync (x) ds-other", "https://x/hooks/people"), "ds-abc"), "another workspace's");
        assert!(!ours(&hook("Payroll", "https://payroll.test/hooks/people"), "ds-abc"));
        assert!(!ours(&hook(&name, "https://acme.dumbslab.com/hooks/people"), ""));
    }
}
