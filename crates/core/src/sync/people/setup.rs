//! Saving and removing the people sync. Saving checks the API key with BambooHR, then adds
//! BambooHR's webhook itself, so changes there start a sync without anyone copying keys around.
//! When BambooHR won't add it (the key's user may not manage webhooks, say), the sync is saved
//! anyway, and Settings says why; adding the webhook by hand and pasting its private key still
//! works. Each save replaces the webhook DumbSlab added before, so it always posts to the
//! workspace's current address, and removing the sync deletes it.
//!
//! A webhook added through BambooHR's API belongs to the API key's user: it watches only fields
//! they can see, only they can delete it, it stops if their account is deactivated, and its
//! private key is shown once, when it's added. Docs:
//! https://documentation.bamboohr.com/docs/permissioned-webhooks,
//! https://documentation.bamboohr.com/reference/create-webhook,
//! https://documentation.bamboohr.com/reference/delete-webhook,
//! https://documentation.bamboohr.com/reference/list-monitor-fields.

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{OWNER, PROVIDER, PeopleJob, Work, api_call, api_url, refusal, text};
use crate::auth::{Role, Via};
use crate::connect::{Credential, Finish, HttpCall, HttpReply, Job, Step, http_error};
use crate::db::{Db, DbExt, Row};
use crate::error::{ApiError, ApiResult};
use crate::events::{Event, emit};
use crate::registry::Ctx;
use crate::{HostConfig, params};

/// Where BambooHR's webhook posts, on the workspace's address.
pub(crate) const HOOK_PATH: &str = "/hooks/people";

/// The fields a sync reads, as BambooHR's webhooks call them (their aliases), with their names in
/// BambooHR. The webhook watches those of them the API key's user can see. `status` is there so a
/// rehired employee is synced; a sync reads active employees only.
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

/// Why automatic syncing is off when BambooHR won't let the key's user add webhooks.
const NOT_ALLOWED: &str = "BambooHR didn't let the API key's user add webhooks. Give that user access to webhooks in BambooHR and save again, or add the webhook yourself.";
const MOVED: &str = "The workspace's address changed after DumbSlab added BambooHR's webhook, so it still posts to the old address. Save the people sync again to move it.";
const NOT_YET: &str = "Changes in BambooHR don't start a sync yet. Save the people sync again, and DumbSlab adds BambooHR's webhook.";
const NOT_DELETED: &str =
    "DumbSlab couldn't delete the webhook it had added in BambooHR. If that webhook keeps calling, DumbSlab turns its calls away.";

fn hook_url(base_url: &str) -> String {
    format!("{base_url}{HOOK_PATH}")
}

// ---------------------------------------------------------------------------
// BambooHR's API

/// The cheapest check of the key and the company domain: one active employee's work email.
fn check_call(subdomain: &str, key: &str) -> HttpCall {
    api_call(HttpCall::get(api_url(subdomain, "employees?fields=workEmail&filter%5Bstatus%5D=active&page%5Blimit%5D=1")), key)
}

fn monitor_fields_call(subdomain: &str, key: &str) -> HttpCall {
    api_call(HttpCall::get(api_url(subdomain, "webhooks/monitor_fields")), key)
}

fn create_call(subdomain: &str, key: &str, base_url: &str, fields: &[String]) -> HttpCall {
    let host = base_url.split_once("://").map_or(base_url, |(_, h)| h);
    let name: String = format!("DumbSlab people sync ({host})").chars().take(100).collect();
    // Event-based, as BambooHR recommends: the delivery only says an employee changed, and the sync
    // reads BambooHR itself. `employee.updated` also fires when an employee is added.
    let body = json!({
        "name": name,
        "url": hook_url(base_url),
        "format": "json",
        "events": ["employee.updated"],
        "monitorFields": fields,
    });
    api_call(HttpCall::post_json(api_url(subdomain, "webhooks"), &body), key)
}

fn delete_call(subdomain: &str, key: &str, id: &str) -> HttpCall {
    let url = api_url(subdomain, &format!("webhooks/{}", urlencoding::encode(id)));
    api_call(HttpCall { method: "DELETE", url, headers: vec![], body: None }, key)
}

/// Gone, either way: deleted now, or before.
fn deleted(reply: &HttpReply) -> bool {
    reply.ok() || reply.status == 404
}

/// Whether the API key and the company domain work.
fn read_check(subdomain: &str, reply: &HttpReply) -> Result<(), String> {
    match reply.status {
        401 => Err(format!(
            "BambooHR rejected the API key for {subdomain}.bamboohr.com. Check the key was copied whole, and that it's from that company's BambooHR."
        )),
        _ if !reply.ok() => Err(refusal(subdomain, reply)),
        _ if !reply.json()["data"].is_array() => {
            Err(format!("{subdomain}.bamboohr.com didn't answer like BambooHR's API. Check the company domain."))
        }
        _ => Ok(()),
    }
}

/// The fields the webhook watches: those a sync reads that BambooHR lists for the key's user.
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
        return Err("BambooHR doesn't let the API key's user watch the fields a sync reads (work email, job title, department…), so DumbSlab couldn't add the webhook.".into());
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
                    "BambooHR won't let the API key's user watch these fields, so DumbSlab couldn't add the webhook: {}.",
                    fields.join(", ")
                )
            }
        }
        400 => {
            let why = errors.iter().find_map(|e| said(&e["error"])).map(|e| format!(" ({e})")).unwrap_or_default();
            format!("BambooHR refused to add the webhook{why}.")
        }
        401 => "BambooHR rejected the API key when DumbSlab added the webhook. Save again to retry.".into(),
        _ => format!("{} DumbSlab couldn't add the webhook; save again to retry.", http_error("BambooHR", reply)),
    }
}

// ---------------------------------------------------------------------------
// Saving

/// The webhook DumbSlab added before a change, to delete.
#[derive(Clone, Debug)]
struct OldHook {
    subdomain: String,
    id: String,
    /// The key that added it, unless it can't be read any more (the connector key changed).
    cred: Option<Credential>,
}

impl OldHook {
    /// Only the BambooHR user who added a webhook may delete it. Their old key may be revoked by
    /// now, and a new key for the same company may be theirs too, so both are tried.
    fn delete_calls(&self, subdomain: &str, cred: &Credential) -> Vec<HttpCall> {
        let mut keys: Vec<&str> = self.cred.iter().map(|c| c.token.as_str()).filter(|k| !k.is_empty()).collect();
        if self.subdomain == subdomain && !keys.contains(&cred.token.as_str()) {
            keys.push(&cred.token);
        }
        keys.into_iter().map(|k| delete_call(&self.subdomain, k, &self.id)).collect()
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

#[derive(Clone, Copy, Debug, PartialEq)]
enum Phase {
    Start,
    /// Waiting for the key check (and the fields the webhook may watch).
    Checking,
    /// Waiting for the old webhook's deletion and the new one.
    Adding,
    /// Couldn't save: deleting the webhook just added.
    Undoing,
}

/// An admin saving the people sync (see the module docs).
#[derive(Clone, Debug)]
pub(crate) struct Setup {
    admin: String,
    via: Via,
    base_url: String,
    subdomain: String,
    /// The API key, and the webhook's private key once there is one.
    cred: Credential,
    /// The saved settings' sealed credentials when the change began (`None`: there were none), so
    /// a change someone else saved meanwhile isn't overwritten.
    seen: Option<String>,
    old: Option<OldHook>,
    plan: Plan,
    phase: Phase,
    /// Old webhook deletions sent in the last step; then whether a new webhook was asked for.
    deleting: usize,
    adding: bool,
    /// The webhook DumbSlab added now.
    webhook_id: Option<String>,
    webhook_error: Option<String>,
    notice: Option<String>,
    /// Why the change wasn't saved, once the webhook just added is deleted.
    failure: Option<ApiError>,
}

/// Starts saving the people sync for `subdomain`: the host checks the API key with BambooHR,
/// adds BambooHR's webhook, then saves. `api_key` and `webhook_key` as `set_people_sync` takes them.
pub(crate) fn setup_job(ctx: &Ctx, subdomain: String, api_key: Option<String>, webhook_key: Option<String>) -> ApiResult<Job> {
    let row = ctx.db.one("SELECT * FROM people_sync WHERE id = 1", &[])?;
    // Unreadable (the connector key changed): the keys must be entered again.
    let saved = row.as_ref().and_then(|r| crate::sync::open(ctx.cfg, OWNER, PROVIDER, &r.str("secret")).ok());
    let mut cred = Credential { token: saved.as_ref().map(|c| c.token.clone()).unwrap_or_default(), ..Default::default() };
    if let Some(k) = api_key.filter(|k| !k.is_empty()) {
        cred.token = k;
    }
    if cred.token.is_empty() {
        return Err(ApiError::bad_request("a BambooHR API key is required"));
    }
    // A pasted private key stays until an admin removes it: that webhook was added by hand.
    let manual = row.as_ref().is_some_and(|r| r.bool("webhook") && r.opt_str("webhook_id").is_none());
    let webhook_key = match webhook_key {
        Some(k) => Some(k).filter(|k| !k.is_empty()),
        None if manual => saved.as_ref().map(|c| c.field("webhook_key").to_string()).filter(|k| !k.is_empty()),
        None => None,
    };
    let plan = match webhook_key {
        Some(k) => {
            cred.fields.insert("webhook_key".into(), k);
            Plan::Manual
        }
        None if !ctx.base_url.starts_with("https://") => Plan::Cannot(format!(
            "BambooHR sends webhooks only to https addresses, and this workspace's is {}. Syncs still run when you choose Sync now.",
            ctx.base_url
        )),
        None => Plan::Add,
    };
    let old = row.as_ref().and_then(|r| Some(OldHook { subdomain: r.str("subdomain"), id: r.opt_str("webhook_id")?, cred: saved.clone() }));
    let webhook_error = match &plan {
        Plan::Cannot(why) => Some(why.clone()),
        _ => None,
    };
    Ok(Job::People(Box::new(PeopleJob::new(Work::Setup(Box::new(Setup {
        admin: ctx.actor.user_id.clone(),
        via: ctx.actor.via,
        base_url: ctx.base_url.clone(),
        subdomain,
        cred,
        seen: row.as_ref().map(|r| r.str("secret")),
        old,
        plan,
        phase: Phase::Start,
        deleting: 0,
        adding: false,
        webhook_id: None,
        webhook_error,
        notice: None,
        failure: None,
    }))))))
}

pub(super) fn step(
    db: &dyn Db,
    cfg: &HostConfig,
    s: &mut Setup,
    staged: &mut Vec<crate::Effect>,
    replies: Vec<HttpReply>,
    now: DateTime<Utc>,
) -> ApiResult<Step> {
    match s.phase {
        Phase::Start => {
            s.phase = Phase::Checking;
            let mut calls = vec![check_call(&s.subdomain, &s.cred.token)];
            if s.plan == Plan::Add {
                calls.push(monitor_fields_call(&s.subdomain, &s.cred.token));
            }
            Ok(Step::Fetch(calls))
        }
        Phase::Checking => {
            let mut replies = replies.into_iter();
            if let Err(message) = read_check(&s.subdomain, &replies.next().unwrap_or_default()) {
                // Nothing has changed, here or in BambooHR.
                return Ok(Step::Done(Finish::Fail(ApiError::new(400, "bamboohr_refused", message))));
            }
            let mut calls = s.old.as_ref().map(|o| o.delete_calls(&s.subdomain, &s.cred)).unwrap_or_default();
            s.deleting = calls.len();
            if s.old.is_some() && calls.is_empty() {
                // No key that may delete it: the old one can't be read, and the new one is another company's.
                s.notice = Some(NOT_DELETED.into());
            }
            if s.plan == Plan::Add {
                match watched_fields(&replies.next().unwrap_or_default()) {
                    Ok(fields) => {
                        calls.push(create_call(&s.subdomain, &s.cred.token, &s.base_url, &fields));
                        s.adding = true;
                    }
                    Err(why) => s.webhook_error = Some(why),
                }
            }
            if calls.is_empty() {
                return save(db, cfg, s, staged, now);
            }
            s.phase = Phase::Adding;
            Ok(Step::Fetch(calls))
        }
        Phase::Adding => {
            let (deletions, added) = replies.split_at(s.deleting.min(replies.len()));
            if s.deleting > 0 && !deletions.iter().any(deleted) {
                s.notice = Some(NOT_DELETED.into());
            }
            if s.adding {
                match read_created(&added.first().cloned().unwrap_or_default()) {
                    Ok((id, key)) => {
                        s.webhook_id = Some(id);
                        s.cred.fields.insert("webhook_key".into(), key);
                    }
                    Err((id, why)) => {
                        s.webhook_id = id;
                        s.webhook_error = Some(why);
                    }
                }
            }
            save(db, cfg, s, staged, now)
        }
        Phase::Undoing => Ok(Step::Done(Finish::Fail(s.failure.clone().unwrap_or_else(changed_meanwhile)))),
    }
}

fn changed_meanwhile() -> ApiError {
    ApiError::conflict("Someone changed the people sync while this was saving. Check it, then save again.")
}

/// Doesn't save, and deletes the webhook just added, if there is one: nothing would know its key.
fn undo(s: &mut Setup, error: ApiError) -> Step {
    match s.webhook_id.clone() {
        Some(id) => {
            s.failure = Some(error);
            s.phase = Phase::Undoing;
            Step::Fetch(vec![delete_call(&s.subdomain, &s.cred.token, &id)])
        }
        None => Step::Done(Finish::Fail(error)),
    }
}

fn save(db: &dyn Db, cfg: &HostConfig, s: &mut Setup, staged: &mut Vec<crate::Effect>, now: DateTime<Utc>) -> ApiResult<Step> {
    // The admin may have lost the role while BambooHR answered.
    let Some(mut actor) = crate::model::actor_for_user(db, &s.admin)?.filter(|a| a.role == Role::Admin) else {
        return Ok(undo(s, ApiError::forbidden("only admins can set up the people sync")));
    };
    actor.via = s.via;
    let webhook = s.cred.fields.contains_key("webhook_key");
    let automatic = webhook && s.webhook_id.is_some();
    let secret = crate::sync::seal(cfg, OWNER, PROVIDER, &s.cred)?;
    let url = s.webhook_id.as_ref().map(|_| hook_url(&s.base_url));
    let ts = crate::util::ts(now);
    let written = match &s.seen {
        None => db.execute(
            "INSERT INTO people_sync (id, provider, subdomain, secret, webhook, webhook_id, webhook_url, webhook_error, owner_id, created_at, updated_at)
             VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING",
            &params![
                PROVIDER,
                s.subdomain.clone(),
                secret,
                webhook,
                s.webhook_id.clone(),
                url,
                s.webhook_error.clone(),
                s.admin.clone(),
                ts.clone(),
                ts
            ],
        )?,
        Some(seen) => db.execute(
            "UPDATE people_sync SET subdomain = ?, secret = ?, webhook = ?, webhook_id = ?, webhook_url = ?, webhook_error = ?, owner_id = ?,
               updated_at = ?
             WHERE id = 1 AND secret = ?",
            &params![
                s.subdomain.clone(),
                secret,
                webhook,
                s.webhook_id.clone(),
                url,
                s.webhook_error.clone(),
                s.admin.clone(),
                ts,
                seen.clone()
            ],
        )?,
    };
    if written == 0 {
        return Ok(undo(s, changed_meanwhile()));
    }
    let mut ctx = Ctx { db, actor, now, cfg, base_url: s.base_url.clone(), effects: vec![] };
    emit(
        &mut ctx,
        Event::new("people_sync.updated", "people_sync", "1", format!("set up the people sync from {}.bamboohr.com", s.subdomain))
            .data(json!({ "webhook": webhook, "automatic_webhook": automatic }))
            .admin_only(),
    )?;
    staged.append(&mut ctx.effects);
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

/// Deleting the webhook DumbSlab added, after the sync was removed.
#[derive(Clone, Debug)]
pub(crate) struct Removal {
    subdomain: String,
    cred: Credential,
    id: String,
    sent: bool,
}

/// The removed sync's webhook to delete in BambooHR: `Ok(None)` when DumbSlab added none, `Err`
/// with a notice when its key can't be read any more.
pub(crate) fn removal_job(cfg: &HostConfig, row: &Row) -> Result<Option<Job>, String> {
    let Some(id) = row.opt_str("webhook_id") else { return Ok(None) };
    let cred = crate::sync::open(cfg, OWNER, PROVIDER, &row.str("secret")).map_err(|_| NOT_DELETED.to_string())?;
    let r = Removal { subdomain: row.str("subdomain"), cred, id, sent: false };
    Ok(Some(Job::People(Box::new(PeopleJob::new(Work::Remove(r))))))
}

pub(super) fn remove_step(r: &mut Removal, replies: Vec<HttpReply>) -> Step {
    if !r.sent {
        r.sent = true;
        return Step::Fetch(vec![delete_call(&r.subdomain, &r.cred.token, &r.id)]);
    }
    let gone = replies.first().is_some_and(deleted);
    let done = PeopleSyncRemoved { ok: true, notice: (!gone).then(|| NOT_DELETED.to_string()) };
    Step::Done(Finish::Fill(serde_json::to_value(done).unwrap_or_default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(status: u16, body: Value) -> HttpReply {
        HttpReply { status, body: body.to_string() }
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
        let call = create_call("acme", "k", "https://kb.test", &["workEmail".into()]);
        assert_eq!((call.method, call.url.as_str()), ("POST", "https://acme.bamboohr.com/api/v1/webhooks"));
        let body: Value = serde_json::from_str(call.body.as_deref().unwrap()).unwrap();
        assert_eq!(
            body,
            json!({ "name": "DumbSlab people sync (kb.test)", "url": "https://kb.test/hooks/people", "format": "json",
                    "events": ["employee.updated"], "monitorFields": ["workEmail"] })
        );
        let delete = delete_call("acme", "k", "41");
        assert_eq!((delete.method, delete.url.as_str()), ("DELETE", "https://acme.bamboohr.com/api/v1/webhooks/41"));
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
    fn key_checks_say_what_to_fix() {
        let ok = reply(200, json!({ "data": [], "meta": {} }));
        assert!(read_check("acme", &ok).is_ok());
        assert!(read_check("acme", &reply(401, json!(null))).unwrap_err().contains("rejected the API key for acme.bamboohr.com"));
        assert!(read_check("nope", &reply(404, json!(null))).unwrap_err().contains("no company at nope.bamboohr.com"));
        assert!(read_check("acme", &reply(403, json!(null))).unwrap_err().contains("access to employee information"));
        assert!(read_check("acme", &reply(200, json!("<html>"))).unwrap_err().contains("Check the company domain"));
    }

    #[test]
    fn old_webhooks_are_deleted_with_the_keys_that_may() {
        let cred = |k: &str| Credential { token: k.into(), ..Default::default() };
        let old = OldHook { subdomain: "acme".into(), id: "41".into(), cred: Some(cred("old")) };
        let keys = |calls: Vec<HttpCall>| calls.iter().map(|c| (c.url.clone(), c.headers[0].1.clone())).collect::<Vec<_>>();
        let basic = |k: &str| format!("Basic {}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("{k}:x")));
        let url = "https://acme.bamboohr.com/api/v1/webhooks/41".to_string();
        assert_eq!(keys(old.delete_calls("acme", &cred("old"))), [(url.clone(), basic("old"))]);
        assert_eq!(keys(old.delete_calls("acme", &cred("new"))), [(url.clone(), basic("old")), (url.clone(), basic("new"))]);
        assert_eq!(keys(old.delete_calls("other", &cred("new"))), [(url.clone(), basic("old"))], "another company's key can't");
        let unreadable = OldHook { cred: None, ..old };
        assert_eq!(keys(unreadable.delete_calls("acme", &cred("new"))), [(url, basic("new"))]);
    }
}
