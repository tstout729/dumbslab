//! Saving and removing the people sync. A save checks DumbSlab's access with BambooHR, then adds
//! BambooHR's webhook itself, so changes there start a sync without anyone copying keys around.
//! It saves with an API key (self-hosted only), with a new Sign in with BambooHR (see [`oauth`]),
//! or again with the saved credentials, to move the webhook after the workspace moved, say.
//!
//! - When BambooHR won't add the webhook (its user may not manage webhooks, say), the sync is
//!   saved anyway, and Settings says why. Adding the webhook by hand and pasting its private key
//!   still works.
//! - Saving again with the saved credentials keeps the webhook DumbSlab added when nothing changed:
//!   same company, same credentials, same workspace address, and BambooHR still has it. Otherwise
//!   the save adds a new one and deletes the old one. Removing the sync deletes it.
//! - One save at a time: a save holds a lease (in `settings`) from when it starts until it ends,
//!   and a second one, or removing the sync meanwhile, is refused.
//! - No webhook is lost when a save stops partway: the save checks the admin may still save before
//!   it changes anything in BambooHR, and first records the credentials it's about to add a
//!   webhook with, and those of the webhook it replaces, for a cleanup pass (see
//!   [`super::cleanup`]). The pass finds every webhook of this workspace's those credentials can
//!   see, even one whose id a rolled-back step lost.
//! - Each save stores a connection id, new whenever the credentials or the company change. Work
//!   begun with the old ones (a sync, a renewal) checks it and stops: it stores nothing.
//!
//! A webhook added through BambooHR's API belongs to the BambooHR user whose API key or sign-in
//! added it: it watches only fields they can see, only their credentials may delete it, it stops
//! if their account is deactivated, and its private key is shown once, when it's added. A
//! sign-in's webhooks are what BambooHR calls application-specific webhooks (the `webhooks.write`
//! scope); they're added, signed and deleted the same way. Docs:
//! https://documentation.bamboohr.com/docs/permissioned-webhooks,
//! https://documentation.bamboohr.com/reference/create-webhook,
//! https://documentation.bamboohr.com/reference/get-webhook,
//! https://documentation.bamboohr.com/reference/delete-webhook,
//! https://documentation.bamboohr.com/reference/list-monitor-fields.

use chrono::{DateTime, Duration, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::oauth::{self, Auth, Creds, Renewal};
use super::{OWNER, PROVIDER, PeopleJob, Work, api_url, refusal, text};
use crate::auth::{Actor, Role, Via};
use crate::connect::{Finish, HttpCall, HttpReply, Job, Step, http_error};
use crate::db::{Db, DbExt, Row};
use crate::error::{ApiError, ApiResult};
use crate::events::{Event, emit};
use crate::registry::Ctx;
use crate::util::ts;
use crate::{HostConfig, params};

/// Where BambooHR's webhook posts, on the workspace's address.
pub(crate) const HOOK_PATH: &str = "/hooks/people";

/// The fields a sync reads, as BambooHR's webhooks call them (their aliases), with their names in
/// BambooHR. The webhook watches those of them its user can see. `status` is there so a rehired
/// employee is synced; a sync reads active employees only.
const WATCHED: &[(&str, &str)] = &[
    ("workEmail", "Work Email"),
    ("jobTitle", "Job Title"),
    ("department", "Department"),
    ("location", "Location"),
    ("workPhone", "Work Phone"),
    ("reportsTo", "Reporting To"),
    ("pronouns", "Pronouns"),
    ("status", "Status"),
];

/// Why automatic syncing is off when BambooHR won't let DumbSlab's user add webhooks.
const NOT_ALLOWED: &str = "BambooHR didn't let DumbSlab add webhooks: the BambooHR user whose API key or sign-in it uses needs access to webhooks. Give them that access and save again, or add the webhook yourself.";
const MOVED: &str = "The workspace's address changed after DumbSlab added BambooHR's webhook, so it still posts to the old address. Save the people sync again to move it.";
const NOT_YET: &str = "Changes in BambooHR don't start a sync yet. Save the people sync again, and DumbSlab adds BambooHR's webhook.";
pub(crate) const NOT_DELETED: &str =
    "DumbSlab couldn't delete the webhook it had added in BambooHR. If that webhook keeps calling, DumbSlab turns its calls away.";
pub(crate) const NOT_DELETED_YET: &str = "DumbSlab couldn't delete the webhook it had added in BambooHR yet. It tries again after the next syncs; meanwhile it turns that webhook's calls away.";
const LOST: &str =
    "A save stopped partway after DumbSlab had deleted its webhook in BambooHR. Save the people sync again to add a new one.";

fn hook_url(base_url: &str) -> String {
    format!("{base_url}{HOOK_PATH}")
}

// ---------------------------------------------------------------------------
// BambooHR's API

/// The cheapest check of the credentials and the company domain: one active employee's work email.
fn check_call(subdomain: &str, creds: &Creds) -> HttpCall {
    creds.call(HttpCall::get(api_url(subdomain, "employees?fields=workEmail&filter%5Bstatus%5D=active&page%5Blimit%5D=1")))
}

fn monitor_fields_call(subdomain: &str, creds: &Creds) -> HttpCall {
    creds.call(HttpCall::get(api_url(subdomain, "webhooks/monitor_fields")))
}

fn webhook_url(subdomain: &str, id: &str) -> String {
    api_url(subdomain, &format!("webhooks/{}", urlencoding::encode(id)))
}

fn get_webhook_call(subdomain: &str, creds: &Creds, id: &str) -> HttpCall {
    creds.call(HttpCall::get(webhook_url(subdomain, id)))
}

fn create_call(subdomain: &str, creds: &Creds, base_url: &str, fields: &[String], tag: &str) -> HttpCall {
    // Event-based, as BambooHR recommends, with no post fields: a delivery says only which employee
    // changed and the names of the fields that did, and the sync reads BambooHR itself. So a webhook
    // DumbSlab failed to delete posts nothing useful. `employee.updated` also fires when an employee
    // is added. The name carries the workspace's tag, so a cleanup pass can find it.
    let body = json!({
        "name": super::cleanup::webhook_name(base_url, tag),
        "url": hook_url(base_url),
        "format": "json",
        "events": ["employee.updated"],
        "monitorFields": fields,
        "postFields": {},
    });
    creds.call(HttpCall::post_json(api_url(subdomain, "webhooks"), &body))
}

pub(super) fn delete_call(subdomain: &str, creds: &Creds, id: &str) -> HttpCall {
    creds.call(HttpCall { method: "DELETE", url: webhook_url(subdomain, id), headers: vec![], body: None })
}

/// Gone, either way: deleted now, or before.
pub(super) fn deleted(reply: &HttpReply) -> bool {
    reply.ok() || reply.status == 404
}

/// Whether the credentials and the company domain work: `Err` has a code for Settings' link and
/// the message.
fn read_check(subdomain: &str, auth: Auth, reply: &HttpReply) -> Result<(), (&'static str, String)> {
    match reply.status {
        401 if auth == Auth::ApiKey => Err((
            "refused",
            format!(
                "BambooHR rejected the API key for {subdomain}.bamboohr.com. Check the key was copied whole, and that it's from that company's BambooHR."
            ),
        )),
        403 => Err(("no_access", refusal(subdomain, auth, reply))),
        _ if !reply.ok() => Err(("failed", refusal(subdomain, auth, reply))),
        _ if !reply.json()["data"].is_array() => {
            Err(("failed", format!("{subdomain}.bamboohr.com didn't answer like BambooHR's API. Check the company domain.")))
        }
        _ => Ok(()),
    }
}

/// The fields the webhook watches: those a sync reads that BambooHR lists for DumbSlab's user.
/// When BambooHR can't list them, the standard ones every account has.
fn watched_fields(reply: &HttpReply) -> Result<Vec<String>, String> {
    if reply.status == 403 {
        return Err(NOT_ALLOWED.into());
    }
    let v = reply.json();
    let Some(listed) = v["fields"].as_array().filter(|_| reply.ok()) else {
        return Ok(WATCHED.iter().filter(|(alias, _)| *alias != "pronouns").map(|(alias, _)| alias.to_string()).collect());
    };
    let mut picked: Vec<String> = vec![];
    for f in listed {
        let (id, name) = (text(&f["id"]), text(&f["name"]));
        let alias = f["alias"].as_str().map(str::trim).filter(|a| !a.is_empty());
        let wanted = WATCHED.iter().any(|(a, n)| alias.is_some_and(|x| x.eq_ignore_ascii_case(a)) || name.eq_ignore_ascii_case(n));
        let field = alias.map(str::to_string).unwrap_or(id);
        if wanted && !field.is_empty() && !picked.contains(&field) {
            picked.push(field);
        }
    }
    if picked.is_empty() {
        return Err("BambooHR doesn't let DumbSlab's BambooHR user watch the fields a sync reads (work email, job title, department…), so DumbSlab couldn't add the webhook.".into());
    }
    Ok(picked)
}

/// BambooHR's words, made safe and short for Settings.
fn said(v: &Value) -> Option<String> {
    let s: String = v.as_str()?.chars().filter(|c| !c.is_control()).take(200).collect();
    Some(s.trim().to_string()).filter(|s| !s.is_empty())
}

/// The added webhook's id and private key; otherwise the id if there is one (to delete it later)
/// and why automatic syncing is off.
fn read_created(reply: &HttpReply) -> Result<(String, String), (Option<String>, String)> {
    if !reply.ok() {
        return Err((None, create_refusal(reply)));
    }
    let v = reply.json();
    let id = Some(text(&v["id"])).filter(|i| !i.is_empty() && i.len() <= 40 && i.bytes().all(|b| b.is_ascii_alphanumeric()));
    let key = v["privateKey"].as_str().map(str::trim).filter(|k| !k.is_empty() && k.len() <= 4096);
    match (id, key) {
        (Some(id), Some(key)) => Ok((id, key.to_string())),
        (id, _) => {
            Err((id, "BambooHR's answer had no webhook private key, so DumbSlab couldn't add the webhook. Save again to retry.".into()))
        }
    }
}

fn create_refusal(reply: &HttpReply) -> String {
    let v = reply.json();
    let errors: Vec<&Value> = match &v["errors"] {
        Value::Array(list) => list.iter().collect(),
        Value::Null => vec![],
        one => vec![one],
    };
    match reply.status {
        403 => {
            let fields: Vec<String> = errors
                .iter()
                .flat_map(|e| ["monitorFields", "monitorFieldViolations", "unknownFields"].map(|k| &e[k]))
                .filter_map(Value::as_array)
                .flatten()
                .filter_map(|f| said(&f["name"]))
                .take(10)
                .collect();
            if fields.is_empty() {
                NOT_ALLOWED.into()
            } else {
                format!(
                    "BambooHR won't let DumbSlab's BambooHR user watch these fields, so DumbSlab couldn't add the webhook: {}.",
                    fields.join(", ")
                )
            }
        }
        400 => {
            let why = errors.iter().find_map(|e| said(&e["error"])).map(|e| format!(" ({e})")).unwrap_or_default();
            format!("BambooHR refused to add the webhook{why}.")
        }
        401 => "BambooHR rejected DumbSlab's credentials when it added the webhook. Save again to retry.".into(),
        _ => format!("{} DumbSlab couldn't add the webhook; save again to retry.", http_error("BambooHR", reply)),
    }
}

// ---------------------------------------------------------------------------
// One save at a time

const SAVING: &str = "people_sync_saving";

/// Takes the save lease unless another save holds it. Returns the lease: when it runs out, then a
/// random id. A save's job takes at most four steps of at most eight seconds each.
pub(crate) fn claim_save(db: &dyn Db, now: DateTime<Utc>) -> ApiResult<Option<String>> {
    let lease = format!("{} {}", ts(now + Duration::seconds(crate::sync::LEASE_SECS)), crate::util::new_id());
    let claimed = db.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value WHERE settings.value <= ?",
        &params![SAVING, lease.clone(), ts(now)],
    )? > 0;
    Ok(claimed.then_some(lease))
}

fn holds_save(db: &dyn Db, lease: &str) -> ApiResult<bool> {
    Ok(db.one("SELECT 1 AS ok FROM settings WHERE key = ? AND value = ?", &params![SAVING, lease])?.is_some())
}

fn release_save(db: &dyn Db, lease: &str) -> ApiResult<()> {
    db.execute("DELETE FROM settings WHERE key = ? AND value = ?", &params![SAVING, lease])?;
    Ok(())
}

/// A save is under way.
pub(crate) fn saving(db: &dyn Db, now: DateTime<Utc>) -> ApiResult<bool> {
    Ok(db.one("SELECT 1 AS ok FROM settings WHERE key = ? AND value > ?", &params![SAVING, ts(now)])?.is_some())
}

pub(crate) fn busy() -> ApiError {
    ApiError::conflict("A change to the people sync is being saved. Try again in a minute.")
}

// ---------------------------------------------------------------------------
// Saving

/// The webhook DumbSlab added before a change, to delete.
#[derive(Clone, Debug)]
struct OldHook {
    subdomain: String,
    id: String,
    /// The credentials that added it, unless they can't be read any more (the connector key changed).
    creds: Option<Creds>,
}

impl OldHook {
    /// Only the BambooHR user who added a webhook may delete it. Their old credentials may be
    /// revoked by now, and new ones for the same company may be theirs too, so both are tried. A
    /// sign-in that's about to expire isn't: the cleanup renews it first.
    fn delete_calls(&self, subdomain: &str, creds: &Creds, now: DateTime<Utc>) -> Vec<HttpCall> {
        let mut with: Vec<&Creds> = self.creds.iter().filter(|c| !c.cred.token.is_empty() && !c.needs_refresh(now)).collect();
        if self.subdomain == subdomain && !with.iter().any(|c| c.cred.token == creds.cred.token) {
            with.push(creds);
        }
        with.into_iter().map(|c| delete_call(&self.subdomain, c, &self.id)).collect()
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Plan {
    /// Add BambooHR's webhook.
    Add,
    /// A webhook private key was pasted in: an admin added the webhook by hand.
    Manual,
    /// Can't, and why.
    Cannot(String),
}

#[derive(Clone, Debug, PartialEq)]
enum Phase {
    Start,
    /// Waiting for BambooHR to exchange a sign-in's code for tokens.
    Exchanging,
    /// Waiting for BambooHR to renew the saved sign-in; this save holds the renewal lease.
    Renewing(String),
    /// Waiting for the access check, the fields the webhook may watch, and the kept webhook.
    Checking,
    /// Waiting for the old webhook's deletion and the new one.
    Adding,
}

/// An admin saving the people sync (see the module docs).
#[derive(Clone, Debug)]
pub(crate) struct Setup {
    admin: String,
    via: Via,
    base_url: String,
    subdomain: String,
    /// What this save signs in with; `cred.fields` also gets the webhook's private key.
    creds: Creds,
    /// A sign-in's code, exchanged for tokens first.
    code: Option<String>,
    /// This save uses the saved credentials (no new API key or sign-in).
    reuses_saved: bool,
    /// The connection this save stores: the saved one when it keeps the same credentials for the
    /// same company, otherwise a new one.
    connection: String,
    /// The saved connection, when there is one.
    saved_connection: Option<String>,
    same_connection: bool,
    /// The workspace's tag, in the webhook's name (see [`super::cleanup`]).
    tag: String,
    /// The replaced connection's cleanup record was made by this save, not before it.
    old_recorded_now: bool,
    /// The save lease.
    lease: String,
    old: Option<OldHook>,
    /// The webhook DumbSlab added before, kept if BambooHR still has it: only when this save
    /// changes nothing it depends on.
    keep: Option<String>,
    plan: Plan,
    phase: Phase,
    /// What the last batch of requests held, to read the answers.
    fields_sent: bool,
    keep_sent: bool,
    deleting: usize,
    adding: bool,
    /// The webhook DumbSlab added (or kept).
    webhook_id: Option<String>,
    webhook_error: Option<String>,
    notice: Option<String>,
    /// The same, as a code for a sign-in's way back to Settings.
    notice_code: Option<&'static str>,
    /// BambooHR deleted the old webhook.
    old_deleted: bool,
    /// A sign-in: finish by sending the browser back to Settings, with a code when it failed.
    sign_in: bool,
}

/// What a save starts from.
struct Start<'a> {
    admin: &'a Actor,
    base_url: &'a str,
    subdomain: String,
    /// New credentials: an API key, or a sign-in (tokens to come). `None` saves again with the
    /// saved ones.
    new: Option<Creds>,
    code: Option<String>,
    webhook_key: Option<String>,
    lease: String,
}

fn begin(db: &dyn Db, cfg: &HostConfig, row: Option<&Row>, start: Start) -> ApiResult<Job> {
    // Unreadable (the connector key changed): new credentials must be given.
    let saved = row.and_then(|r| Creds::of_row(cfg, r).ok());
    let reuses_saved = start.new.is_none();
    let mut creds = match start.new {
        Some(c) => c,
        None => saved
            .clone()
            .ok_or_else(|| ApiError::bad_request("the saved BambooHR credentials can't be read; sign in or enter an API key again"))?,
    };
    let saved_key = saved.as_ref().map(|c| c.cred.field("webhook_key").to_string()).filter(|k| !k.is_empty());
    creds.cred.fields.clear();
    // A pasted private key stays until an admin removes it: that webhook was added by hand.
    let manual = row.is_some_and(|r| r.bool("webhook") && r.opt_str("webhook_id").is_none());
    let webhook_key = match start.webhook_key {
        Some(k) => Some(k).filter(|k| !k.is_empty()),
        None if manual => saved_key.clone(),
        None => None,
    };
    let url = hook_url(start.base_url);
    let plan = match webhook_key {
        Some(k) => {
            creds.cred.fields.insert("webhook_key".into(), k);
            Plan::Manual
        }
        None if !start.base_url.starts_with("https://") => Plan::Cannot(format!(
            "BambooHR sends webhooks only to https addresses, and this workspace's is {}. Syncs still run when you choose Sync now.",
            start.base_url
        )),
        None => Plan::Add,
    };
    let old = row.and_then(|r| Some(OldHook { subdomain: r.str("subdomain"), id: r.opt_str("webhook_id")?, creds: saved.clone() }));
    // Nothing this save changes affects the webhook: keep it if BambooHR still has it.
    let keep = row
        .filter(|r| {
            reuses_saved
                && plan == Plan::Add
                && r.str("subdomain") == start.subdomain
                && r.opt_str("webhook_url").as_deref() == Some(url.as_str())
                && r.bool("webhook")
        })
        .and_then(|r| r.opt_str("webhook_id"));
    if let (Some(_), Some(k)) = (&keep, &saved_key) {
        creds.cred.fields.insert("webhook_key".into(), k.clone());
    }
    let webhook_error = match &plan {
        Plan::Cannot(why) => Some(why.clone()),
        _ => None,
    };
    let saved_connection = row.and_then(|r| r.opt_str("connection"));
    let same_connection = reuses_saved && saved_connection.is_some() && row.is_some_and(|r| r.str("subdomain") == start.subdomain);
    let connection = match (&saved_connection, same_connection) {
        (Some(c), true) => c.clone(),
        _ => crate::util::new_id(),
    };
    Ok(Job::People(Box::new(PeopleJob::new(Work::Setup(Box::new(Setup {
        admin: start.admin.user_id.clone(),
        via: start.admin.via,
        base_url: start.base_url.to_string(),
        subdomain: start.subdomain,
        creds,
        sign_in: start.code.is_some(),
        code: start.code,
        reuses_saved,
        connection,
        saved_connection,
        same_connection,
        tag: super::cleanup::tag(db)?,
        old_recorded_now: false,
        lease: start.lease,
        old,
        keep,
        plan,
        phase: Phase::Start,
        fields_sent: false,
        keep_sent: false,
        deleting: 0,
        adding: false,
        webhook_id: None,
        webhook_error,
        notice: None,
        notice_code: None,
        old_deleted: false,
    }))))))
}

/// Starts saving the people sync for `subdomain` from `set_people_sync`: with a new API key, or
/// with the saved credentials. The host checks them with BambooHR, adds its webhook, then saves.
/// `api_key` and `webhook_key` as `set_people_sync` takes them.
pub(crate) fn setup_job(ctx: &Ctx, subdomain: String, api_key: Option<String>, webhook_key: Option<String>) -> ApiResult<Job> {
    let row = ctx.db.one("SELECT * FROM people_sync WHERE id = 1", &[])?;
    let hosted = oauth::hosted(ctx.cfg);
    let new = match (api_key, &row) {
        (Some(_), _) if hosted => return Err(ApiError::new(400, "api_key_not_allowed", oauth::API_KEYS_REFUSED)),
        (Some(k), _) => Some(Creds::api_key(k)),
        (None, None) if hosted => return Err(ApiError::bad_request("Sign in with BambooHR first (connect_people_sync).")),
        (None, None) => return Err(ApiError::bad_request("a BambooHR API key is required")),
        (None, Some(r)) if hosted && r.str("auth") != Auth::OAuth.as_str() => {
            return Err(ApiError::new(400, "api_key_not_allowed", oauth::API_KEYS_REFUSED));
        }
        (None, Some(r)) if r.str("auth") == Auth::OAuth.as_str() && r.str("subdomain") != subdomain => {
            return Err(ApiError::bad_request(format!(
                "DumbSlab is signed in to {}.bamboohr.com. To sync from {subdomain}.bamboohr.com, sign in with BambooHR for it.",
                r.str("subdomain")
            )));
        }
        (None, Some(_)) => None,
    };
    let Some(lease) = claim_save(ctx.db, ctx.now)? else { return Err(busy()) };
    let start = Start { admin: &ctx.actor, base_url: &ctx.base_url, subdomain, new, code: None, webhook_key, lease };
    begin(ctx.db, ctx.cfg, row.as_ref(), start)
}

/// Finishes a Sign in with BambooHR: exchanges `code` for tokens, then saves like [`setup_job`],
/// and sends the admin back to Settings. The caller took the save lease.
pub(crate) fn sign_in_job(
    db: &dyn Db,
    cfg: &HostConfig,
    base_url: &str,
    admin: &Actor,
    subdomain: String,
    code: String,
    lease: String,
) -> ApiResult<Job> {
    let row = db.one("SELECT * FROM people_sync WHERE id = 1", &[])?;
    let new = Creds { auth: Auth::OAuth, cred: Default::default(), expires_at: None };
    let start = Start { admin, base_url, subdomain, new: Some(new), code: Some(code), webhook_key: None, lease };
    begin(db, cfg, row.as_ref(), start)
}

pub(super) fn step(
    db: &dyn Db,
    cfg: &HostConfig,
    s: &mut Setup,
    staged: &mut Vec<crate::Effect>,
    replies: Vec<HttpReply>,
    now: DateTime<Utc>,
) -> ApiResult<Step> {
    match s.phase.clone() {
        Phase::Start => {
            if let Some(code) = s.code.take() {
                let Some(app) = oauth::app(cfg) else {
                    return fail(db, s, "unavailable", ApiError::bad_request("Sign in with BambooHR isn't set up on this server."));
                };
                s.phase = Phase::Exchanging;
                return Ok(Step::Fetch(vec![oauth::exchange_call(app, &s.subdomain, &oauth::redirect_uri(cfg, &s.base_url), &code)]));
            }
            if s.creds.needs_refresh(now) {
                let connection = s.saved_connection.clone().unwrap_or_default();
                match oauth::renewal(db, cfg, &connection, None, now)? {
                    Renewal::Refresh(lease, stored) => {
                        take_tokens(&mut s.creds, stored);
                        match oauth::renew_call(cfg, &s.subdomain, &s.base_url, &s.creds) {
                            Ok(call) => {
                                s.phase = Phase::Renewing(lease);
                                return Ok(Step::Fetch(vec![call]));
                            }
                            Err(why) => return fail(db, s, "refused", ApiError::new(400, "bamboohr_refused", why)),
                        }
                    }
                    Renewal::UseCurrent(stored) => take_tokens(&mut s.creds, stored),
                    Renewal::Wait => return fail(db, s, "busy", ApiError::conflict(oauth::RENEWING)),
                    Renewal::Changed => return fail(db, s, "busy", ApiError::conflict(oauth::CHANGED)),
                }
            }
            Ok(checking(s))
        }
        Phase::Exchanging => match oauth::read_exchange(&replies.into_iter().next().unwrap_or_default()) {
            Ok((tokens, company)) => {
                // The tokens are for the company BambooHR names.
                if let Some(c) = company {
                    s.subdomain = c;
                }
                s.creds.take(tokens, now);
                Ok(checking(s))
            }
            Err(why) => fail(db, s, "refused", ApiError::new(400, "bamboohr_refused", why)),
        },
        Phase::Renewing(lease) => {
            let reply = replies.into_iter().next().unwrap_or_default();
            let connection = s.saved_connection.clone().unwrap_or_default();
            match oauth::apply_refresh(db, cfg, &mut s.creds, &connection, &lease, &reply, now)? {
                Ok(()) => Ok(checking(s)),
                Err(why) => fail(db, s, "refused", ApiError::new(400, "bamboohr_refused", why)),
            }
        }
        Phase::Checking => {
            let mut replies = replies.into_iter();
            if let Err((code, message)) = read_check(&s.subdomain, s.creds.auth, &replies.next().unwrap_or_default()) {
                // Nothing has changed, here or in BambooHR.
                return fail(db, s, code, ApiError::new(400, "bamboohr_refused", message));
            }
            let fields = s.fields_sent.then(|| watched_fields(&replies.next().unwrap_or_default()));
            let found = s.keep_sent.then(|| replies.next().unwrap_or_default());
            let still_there = found.is_some_and(|r| r.ok() && r.json()["url"].as_str() == Some(hook_url(&s.base_url).as_str()));
            if still_there {
                s.webhook_id = s.keep.clone();
                return save(db, cfg, s, staged, now);
            }
            if s.plan != Plan::Manual {
                s.creds.cred.fields.remove("webhook_key");
            }
            // Nothing in BambooHR changes unless this admin may still save.
            if let Some(stop) = may_save(db, s)? {
                return Ok(stop);
            }
            let mut calls = s.old.as_ref().map(|o| o.delete_calls(&s.subdomain, &s.creds, now)).unwrap_or_default();
            s.deleting = calls.len();
            let fields = match fields {
                Some(Ok(fields)) => Some(fields),
                Some(Err(why)) => {
                    s.webhook_error = Some(why);
                    None
                }
                None => None,
            };
            s.adding = fields.is_some();
            // Before anything changes in BambooHR: the credentials this save adds a webhook with,
            // and the replaced webhook's, are kept for a cleanup pass. If a later step rolls back,
            // the pass still finds what it left in BambooHR.
            if s.adding {
                super::cleanup::record(db, cfg, &s.connection, &s.subdomain, &s.creds, None, now)?;
            }
            record_old(db, cfg, s, now)?;
            if s.old.is_some() && s.deleting == 0 {
                // No credentials that may delete it now (an expired sign-in, or another company's
                // credentials): the cleanup does it.
                s.notice = Some(NOT_DELETED_YET.into());
                s.notice_code = Some("old_webhook");
            }
            if let Some(fields) = fields {
                calls.push(create_call(&s.subdomain, &s.creds, &s.base_url, &fields, &s.tag));
            }
            if calls.is_empty() {
                return save(db, cfg, s, staged, now);
            }
            s.phase = Phase::Adding;
            Ok(Step::Fetch(calls))
        }
        Phase::Adding => {
            let (deletions, added) = replies.split_at(s.deleting.min(replies.len()));
            if s.adding {
                match read_created(&added.first().cloned().unwrap_or_default()) {
                    Ok((id, key)) => {
                        s.creds.cred.fields.insert("webhook_key".into(), key);
                        super::cleanup::know(db, &s.connection, &id)?;
                        s.webhook_id = Some(id);
                    }
                    Err((id, why)) => {
                        // Added without a private key, it's of no use: the cleanup pass deletes it.
                        if let Some(id) = id {
                            super::cleanup::know(db, &s.connection, &id)?;
                        }
                        s.webhook_error = Some(why);
                    }
                }
            }
            s.old_deleted = deletions.iter().any(deleted);
            if s.deleting > 0 && !s.old_deleted {
                s.notice = Some(NOT_DELETED_YET.into());
                s.notice_code = Some("old_webhook");
            }
            if s.old_deleted && s.old_recorded_now {
                // Done already: the replaced credentials have nothing left to clean up.
                super::cleanup::drop_record(db, &old_connection(s))?;
            }
            save(db, cfg, s, staged, now)
        }
    }
}

/// Checks the credentials; asks for the fields the webhook may watch when it adds one, and for the
/// kept webhook when it may keep it.
fn checking(s: &mut Setup) -> Step {
    let mut calls = vec![check_call(&s.subdomain, &s.creds)];
    s.fields_sent = s.plan == Plan::Add;
    if s.fields_sent {
        calls.push(monitor_fields_call(&s.subdomain, &s.creds));
    }
    s.keep_sent = s.keep.is_some();
    if let Some(id) = &s.keep {
        calls.push(get_webhook_call(&s.subdomain, &s.creds, id));
    }
    s.phase = Phase::Checking;
    Step::Fetch(calls)
}

/// Ends without saving: the API's error, or a sign-in's way back to Settings with `code`.
fn fail(db: &dyn Db, s: &Setup, code: &str, error: ApiError) -> ApiResult<Step> {
    release_save(db, &s.lease)?;
    Ok(Step::Done(match s.sign_in {
        true => Finish::Redirect(oauth::settings_url(&s.base_url, Err(code))),
        false => Finish::Fail(error),
    }))
}

/// Whether this save may go on: it still holds the save lease (another save may have started
/// only if this one took longer), and its admin still is one. `Some` is how it stops otherwise.
/// A stop after BambooHR deleted the old webhook says so in Settings; the webhook this save added
/// stays recorded for the cleanup.
fn may_save(db: &dyn Db, s: &Setup) -> ApiResult<Option<Step>> {
    let stop = |code: &str, error: ApiError| -> ApiResult<Option<Step>> {
        if s.old_deleted
            && let Some(old) = &s.old
        {
            lost(db, &old.id, &old.subdomain)?;
        }
        Ok(Some(match s.sign_in {
            true => Step::Done(Finish::Redirect(oauth::settings_url(&s.base_url, Err(code)))),
            false => Step::Done(Finish::Fail(error)),
        }))
    };
    if !holds_save(db, &s.lease)? {
        return stop("busy", busy());
    }
    if crate::model::actor_for_user(db, &s.admin)?.is_none_or(|a| a.role != Role::Admin) {
        release_save(db, &s.lease)?;
        return stop("not_admin", ApiError::forbidden("only admins can set up the people sync"));
    }
    Ok(None)
}

/// The webhook DumbSlab added is gone from BambooHR but still saved (a save stopped partway after
/// deleting it): Settings says to save again, and its calls are turned away.
pub(super) fn lost(db: &dyn Db, id: &str, subdomain: &str) -> ApiResult<()> {
    db.execute(
        "UPDATE people_sync SET webhook = 0, webhook_id = NULL, webhook_url = NULL, webhook_error = ?
         WHERE id = 1 AND webhook_id = ? AND subdomain = ?",
        &params![LOST, id, subdomain],
    )?;
    Ok(())
}

/// The saved connection this save replaces, as its cleanup record names it.
fn old_connection(s: &Setup) -> String {
    s.saved_connection.clone().unwrap_or_else(|| format!("unnamed-{}", s.connection))
}

/// Takes the stored tokens (renewed by another request, maybe) into `creds`, keeping the rest.
fn take_tokens(creds: &mut Creds, stored: Creds) {
    creds.cred.token = stored.cred.token;
    creds.cred.refresh_token = stored.cred.refresh_token;
    creds.expires_at = stored.expires_at;
}

/// Records the replaced webhook's credentials for a cleanup pass, as stored now (a sync may have
/// renewed them since this save began), or else as this save read them, or the new ones for the
/// same company. Without any, its webhook can never be deleted. Nothing to record when this save
/// keeps the connection: the new record covers it.
fn record_old(db: &dyn Db, cfg: &HostConfig, s: &mut Setup, now: DateTime<Utc>) -> ApiResult<()> {
    let Some(old) = s.old.clone() else { return Ok(()) };
    if s.same_connection {
        if !s.adding {
            super::cleanup::record(db, cfg, &s.connection, &s.subdomain, &s.creds, Some(&old.id), now)?;
        }
        return super::cleanup::know(db, &s.connection, &old.id);
    }
    let connection = old_connection(s);
    let stored = db.one("SELECT * FROM people_sync WHERE id = 1", &[])?.and_then(|r| Creds::of_row(cfg, &r).ok());
    let creds = stored.or(old.creds).or_else(|| (old.subdomain == s.subdomain).then(|| s.creds.clone()));
    let Some(creds) = creds else {
        s.notice = Some(NOT_DELETED.into());
        return Ok(());
    };
    s.old_recorded_now = !super::cleanup::exists(db, &connection)?;
    super::cleanup::record(db, cfg, &connection, &old.subdomain, &creds, Some(&old.id), now)
}

fn save(db: &dyn Db, cfg: &HostConfig, s: &mut Setup, staged: &mut Vec<crate::Effect>, now: DateTime<Utc>) -> ApiResult<Step> {
    // Checked again: the admin may have lost the role while BambooHR answered.
    if let Some(stop) = may_save(db, s)? {
        return Ok(stop);
    }
    let Some(mut actor) = crate::model::actor_for_user(db, &s.admin)? else {
        return fail(db, s, "not_admin", ApiError::forbidden("only admins can set up the people sync"));
    };
    actor.via = s.via;
    let row = db.one("SELECT auth, secret, expires_at, subdomain FROM people_sync WHERE id = 1", &[])?;
    // The same company with the saved credentials: syncs and renewals under way stay valid.
    let same_connection = s.same_connection;
    if s.reuses_saved && s.creds.auth == Auth::OAuth {
        // Saved again with the saved sign-in: a sync may have renewed its tokens meanwhile.
        if let Some(r) = row.filter(|r| r.str("auth") == Auth::OAuth.as_str())
            && let Ok(stored) = Creds::of_row(cfg, &r)
        {
            s.creds.cred.token = stored.cred.token;
            s.creds.cred.refresh_token = stored.cred.refresh_token;
            s.creds.expires_at = stored.expires_at;
        }
    }
    let webhook = s.creds.cred.fields.contains_key("webhook_key");
    let automatic = webhook && s.webhook_id.is_some();
    let secret = crate::sync::seal(cfg, OWNER, PROVIDER, &s.creds.cred)?;
    let url = s.webhook_id.as_ref().map(|_| hook_url(&s.base_url));
    let at = ts(now);
    // New credentials or another company end the syncs and renewals under way with the old ones:
    // without their leases they store nothing. Saved again with the same sign-in, a renewal under
    // way may still store the tokens it gets (keeping this save's webhook key).
    db.execute(
        "INSERT INTO people_sync (id, provider, subdomain, secret, auth, connection, expires_at, webhook, webhook_id, webhook_url,
           webhook_error, owner_id, created_at, updated_at)
         VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET subdomain = excluded.subdomain, secret = excluded.secret, auth = excluded.auth,
           connection = excluded.connection,
           expires_at = excluded.expires_at, webhook = excluded.webhook, webhook_id = excluded.webhook_id,
           webhook_url = excluded.webhook_url, webhook_error = excluded.webhook_error, owner_id = excluded.owner_id,
           updated_at = excluded.updated_at, refreshing_until = CASE WHEN ? THEN people_sync.refreshing_until ELSE NULL END,
           running_until = CASE WHEN ? THEN people_sync.running_until ELSE NULL END",
        &params![
            PROVIDER,
            s.subdomain.clone(),
            secret,
            s.creds.auth.as_str(),
            s.connection.clone(),
            s.creds.expires_at.map(ts),
            webhook,
            s.webhook_id.clone(),
            url,
            s.webhook_error.clone(),
            s.admin.clone(),
            at.clone(),
            at,
            same_connection,
            same_connection
        ],
    )?;
    release_save(db, &s.lease)?;
    let mut ctx = Ctx { db, actor, now, cfg, base_url: s.base_url.clone(), effects: vec![] };
    let how = if s.creds.auth == Auth::OAuth { "signed in with BambooHR for" } else { "set up the people sync from" };
    emit(
        &mut ctx,
        Event::new("people_sync.updated", "people_sync", "1", format!("{how} {}.bamboohr.com", s.subdomain))
            .data(json!({ "auth": s.creds.auth.as_str(), "webhook": webhook, "automatic_webhook": automatic }))
            .admin_only(),
    )?;
    staged.append(&mut ctx.effects);
    if s.sign_in {
        return Ok(Step::Done(Finish::Redirect(oauth::settings_url(&s.base_url, Ok(s.notice_code)))));
    }
    let mut view = crate::ops::sync::people_view(&ctx)?;
    view.notice = s.notice.clone();
    Ok(Step::Done(Finish::Fill(serde_json::to_value(view).map_err(|e| ApiError::internal(e.to_string()))?)))
}

/// Why changes in BambooHR don't start a sync on their own, or what needs doing, for Settings.
/// `url` is where BambooHR's webhook should post now.
pub(crate) fn webhook_problem(r: &Row, url: &str) -> Option<String> {
    if let Some(why) = r.opt_str("webhook_error") {
        return Some(why);
    }
    if !r.bool("webhook") {
        return Some(NOT_YET.into());
    }
    let posts_to = r.opt_str("webhook_url").filter(|_| r.opt_str("webhook_id").is_some());
    posts_to.filter(|p| p != url).map(|_| MOVED.into())
}

// ---------------------------------------------------------------------------
// Removing

/// What `remove_people_sync` did.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct PeopleSyncRemoved {
    pub ok: bool,
    /// Something to know, such as a webhook BambooHR wouldn't let DumbSlab delete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connect::Credential;

    fn reply(status: u16, body: Value) -> HttpReply {
        HttpReply { status, body: body.to_string() }
    }

    fn key(k: &str) -> Creds {
        Creds::api_key(k.into())
    }

    #[test]
    fn the_webhook_watches_the_fields_a_sync_reads() {
        let listed = reply(
            200,
            json!({ "fields": [
                { "id": "4175", "name": "Accrual Level Start Date", "alias": null },
                { "id": "15", "name": "Work Email", "alias": "workEmail" },
                { "id": "17", "name": "Job Title", "alias": "jobTitle" },
                { "id": 4, "name": "Department", "alias": null },
                { "id": "91", "name": "Reporting To", "alias": "reportsTo" },
                { "id": "92", "name": "Pronouns", "alias": "PRONOUNS" },
                { "id": "93", "name": "First Name", "alias": "firstName" },
                { "id": "15", "name": "Work Email", "alias": "workEmail" }
            ] }),
        );
        assert_eq!(watched_fields(&listed).unwrap(), ["workEmail", "jobTitle", "4", "reportsTo", "PRONOUNS"]);
        assert_eq!(watched_fields(&reply(403, json!({}))).unwrap_err(), NOT_ALLOWED);
        let unrelated = reply(200, json!({ "fields": [{ "id": "1", "name": "SSN", "alias": "ssn" }] }));
        assert!(watched_fields(&unrelated).unwrap_err().contains("couldn't add the webhook"));
        // BambooHR couldn't list them: the standard fields every account has.
        let standard = watched_fields(&reply(500, json!({}))).unwrap();
        assert!(standard.contains(&"workEmail".to_string()) && !standard.contains(&"pronouns".to_string()), "{standard:?}");
    }

    #[test]
    fn the_webhook_posts_json_to_the_workspace() {
        let call = create_call("acme", &key("k"), "https://kb.test", &["workEmail".into()], "ds-abc");
        assert_eq!((call.method, call.url.as_str()), ("POST", "https://acme.bamboohr.com/api/v1/webhooks"));
        let body: Value = serde_json::from_str(call.body.as_deref().unwrap()).unwrap();
        assert_eq!(
            body,
            json!({ "name": "DumbSlab people sync (kb.test) ds-abc", "url": "https://kb.test/hooks/people", "format": "json",
                    "events": ["employee.updated"], "monitorFields": ["workEmail"], "postFields": {} })
        );
        let delete = delete_call("acme", &key("k"), "41");
        assert_eq!((delete.method, delete.url.as_str()), ("DELETE", "https://acme.bamboohr.com/api/v1/webhooks/41"));
        let get = get_webhook_call("acme", &key("k"), "41");
        assert_eq!((get.method, get.url.as_str()), ("GET", "https://acme.bamboohr.com/api/v1/webhooks/41"));
    }

    #[test]
    fn what_bamboohr_says_about_a_new_webhook() {
        let made = reply(201, json!({ "id": 41, "name": "x", "privateKey": "pk", "url": "https://kb.test/hooks/people" }));
        assert_eq!(read_created(&made).unwrap(), ("41".to_string(), "pk".to_string()));
        let keyless = reply(201, json!({ "id": "42" }));
        assert_eq!(read_created(&keyless).unwrap_err().0.as_deref(), Some("42"), "kept, to delete later");
        let odd_id = reply(201, json!({ "id": "../7", "privateKey": "pk" }));
        assert_eq!(read_created(&odd_id).unwrap_err().0, None);

        let fields = reply(403, json!({ "errors": { "monitorFields": [{ "id": 636, "name": "Work Email" }], "unknownFields": [] } }));
        assert!(read_created(&fields).unwrap_err().1.contains(": Work Email."));
        let older = reply(403, json!({ "errors": [{ "monitorFieldViolations": [{ "id": 4, "name": "Department" }] }] }));
        assert!(read_created(&older).unwrap_err().1.contains("Department"));
        assert_eq!(read_created(&reply(403, json!({ "errors": [{ "error": "no" }] }))).unwrap_err().1, NOT_ALLOWED);
        let bad = reply(400, json!({ "errors": [{ "error": "Invalid request body\u{7}", "issues": ["url"] }] }));
        assert_eq!(read_created(&bad).unwrap_err().1, "BambooHR refused to add the webhook (Invalid request body).");
        assert!(read_created(&reply(503, json!(null))).unwrap_err().1.contains("save again"));
    }

    #[test]
    fn access_checks_say_what_to_fix() {
        let ok = reply(200, json!({ "data": [], "meta": {} }));
        assert!(read_check("acme", Auth::ApiKey, &ok).is_ok());
        let wrong_key = read_check("acme", Auth::ApiKey, &reply(401, json!(null))).unwrap_err();
        assert_eq!(wrong_key.0, "refused");
        assert!(wrong_key.1.contains("rejected the API key for acme.bamboohr.com"));
        assert!(read_check("acme", Auth::OAuth, &reply(401, json!(null))).unwrap_err().1.contains("Sign in with BambooHR again"));
        assert!(read_check("nope", Auth::ApiKey, &reply(404, json!(null))).unwrap_err().1.contains("no company at nope.bamboohr.com"));
        let no_access = read_check("acme", Auth::OAuth, &reply(403, json!(null))).unwrap_err();
        assert_eq!(no_access.0, "no_access");
        assert!(no_access.1.contains("access to employee information"));
        assert!(read_check("acme", Auth::ApiKey, &reply(200, json!("<html>"))).unwrap_err().1.contains("Check the company domain"));
    }

    #[test]
    fn old_webhooks_are_deleted_with_the_credentials_that_may() {
        let old = OldHook { subdomain: "acme".into(), id: "41".into(), creds: Some(key("old")) };
        let auth = |calls: Vec<HttpCall>| calls.iter().map(|c| (c.url.clone(), c.headers[0].1.clone())).collect::<Vec<_>>();
        let basic = |k: &str| format!("Basic {}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("{k}:x")));
        let url = "https://acme.bamboohr.com/api/v1/webhooks/41".to_string();
        let now = Utc::now();
        assert_eq!(auth(old.delete_calls("acme", &key("old"), now)), [(url.clone(), basic("old"))]);
        assert_eq!(auth(old.delete_calls("acme", &key("new"), now)), [(url.clone(), basic("old")), (url.clone(), basic("new"))]);
        assert_eq!(auth(old.delete_calls("other", &key("new"), now)), [(url.clone(), basic("old"))], "another company's key can't");
        let signed_in = Creds { auth: Auth::OAuth, cred: Credential { token: "t".into(), ..Default::default() }, expires_at: None };
        assert_eq!(auth(old.delete_calls("acme", &signed_in, now)), [(url.clone(), basic("old")), (url.clone(), "Bearer t".into())]);
        let unreadable = OldHook { creds: None, ..old.clone() };
        assert_eq!(auth(unreadable.delete_calls("acme", &key("new"), now)), [(url, basic("new"))]);
        // An expired sign-in isn't tried: the cleanup renews it first.
        let expired = Creds {
            auth: Auth::OAuth,
            cred: Credential { token: "t".into(), refresh_token: Some("r".into()), ..Default::default() },
            expires_at: Some(now - chrono::Duration::minutes(1)),
        };
        let old = OldHook { creds: Some(expired), ..old };
        assert!(old.delete_calls("other", &key("new"), now).is_empty());
    }
}
