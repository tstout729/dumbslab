//! People sync: profile details from BambooHR for the people already in the workspace.
//!
//! A sync reads BambooHR's active employees and updates each DumbSlab person whose email matches
//! an employee's work email (ignoring case). It fills only the fields it owns, kept in
//! `user_profiles`: title, department, location, work phone, pronouns, and the manager when
//! they're in the workspace too. It never adds, deactivates or removes anyone. Fields BambooHR won't show the API key's user are left as
//! they are. Photos are left out: BambooHR's photo links expire, and its photo download needs the
//! API key.
//!
//! Docs: https://documentation.bamboohr.com/reference/list-employees,
//! https://documentation.bamboohr.com/docs/webhooks

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{Ended, check_plan, hook_answer, hook_started};
use crate::connect::{self, Credential, Finish, HttpCall, HttpReply, Job, Step, http_error};
use crate::db::{Db, DbExt, SqlValue};
use crate::error::{ApiError, ApiResult};
use crate::events::{Event, emit};
use crate::util::{secure_eq, ts};
use crate::{HostConfig, Outcome, Request, params};

pub const PROVIDER: &str = "bamboohr";
pub(crate) const TABLE: &str = "people_sync";
/// What the credentials are sealed to.
pub(crate) const OWNER: &str = "people-sync";
/// Employees per page, BambooHR's most.
const PAGE: usize = 2500;
/// Pages one sync reads: a job has [`connect::MAX_STEPS`] steps, and the last applies them.
pub const MAX_PAGES: usize = connect::MAX_STEPS - 1;
/// The most employees one sync reads.
pub const MAX_EMPLOYEES: usize = PAGE * MAX_PAGES;
/// Employees not found here that a result lists by name.
const LISTED: usize = 200;
const FIELDS: &str = "displayName,workEmail,workPhone,departmentName,locationName,reportsToId,pronouns";

pub(crate) fn key() -> SqlValue {
    SqlValue::Integer(1)
}

/// A BambooHR company domain: `acme` from `acme`, `acme.bamboohr.com` or its address.
pub fn valid_subdomain(typed: &str) -> Result<String, String> {
    let t = typed.trim().to_ascii_lowercase();
    let t = t.strip_prefix("https://").unwrap_or(&t);
    let t = t.trim_end_matches('/');
    let t = t.strip_suffix(".bamboohr.com").unwrap_or(t);
    let ok = (1..=63).contains(&t.len())
        && !t.starts_with('-')
        && !t.ends_with('-')
        && t.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if ok { Ok(t.to_string()) } else { Err(format!("The company domain is the `acme` in acme.bamboohr.com; `{typed}` isn't one.")) }
}

/// A BambooHR employee, as a sync uses them. `None` fields are ones the API key may not read:
/// they're left as they are here.
#[derive(Clone, Debug, Default, PartialEq)]
struct Employee {
    id: String,
    name: String,
    email: Option<String>,
    title: Option<String>,
    department: Option<String>,
    location: Option<String>,
    phone: Option<String>,
    pronouns: Option<String>,
    manager: Option<String>,
}

/// Someone in BambooHR, for a result.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Person {
    pub name: String,
    pub email: String,
}

/// What a people sync did.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct PeopleSyncResult {
    /// Active employees read from BambooHR.
    pub employees: usize,
    /// Employees matched to someone here by work email.
    pub matched: usize,
    /// Of those, people whose profile changed.
    pub updated: usize,
    pub unchanged: usize,
    /// Employees left out: no work email, a work email listed twice, or a match that's a bot or deactivated here.
    pub skipped: usize,
    /// Employees whose work email matches nobody here: the first 200.
    pub not_found: Vec<Person>,
    /// How many employees match nobody here.
    pub not_found_count: usize,
    /// Active people here without an active BambooHR employee.
    pub without_record: usize,
    /// BambooHR has more active employees than one sync reads (7,500); the rest weren't read.
    pub truncated: bool,
}

#[derive(Clone, Debug, PartialEq)]
enum Phase {
    Start,
    Reading,
}

#[derive(Clone, Debug)]
pub struct PeopleJob {
    lease: String,
    subdomain: String,
    cred: Credential,
    owner_id: String,
    base_url: String,
    employees: Vec<Employee>,
    pages: usize,
    phase: Phase,
}

/// Starts a sync, unless one is running. `Ok(None)` when one is.
pub(crate) fn start(db: &dyn Db, cfg: &HostConfig, base_url: &str, now: DateTime<Utc>) -> ApiResult<Option<Job>> {
    let row = db.one("SELECT * FROM people_sync WHERE id = 1", &[])?.ok_or_else(|| ApiError::not_found("people sync (set it up first)"))?;
    let cred = super::open(cfg, OWNER, PROVIDER, &row.str("secret"))?;
    let Some(lease) = super::claim(db, TABLE, key(), now)? else { return Ok(None) };
    Ok(Some(Job::People(Box::new(PeopleJob {
        lease,
        subdomain: row.str("subdomain"),
        cred,
        owner_id: row.str("owner_id"),
        base_url: base_url.to_string(),
        employees: vec![],
        pages: 0,
        phase: Phase::Start,
    }))))
}

fn page_call(j: &PeopleJob, after: Option<&str>) -> HttpCall {
    let mut url =
        format!("https://{}.bamboohr.com/api/v1/employees?fields={FIELDS}&filter%5Bstatus%5D=active&page%5Blimit%5D={PAGE}", j.subdomain);
    if let Some(cursor) = after {
        url.push_str(&format!("&page%5Bafter%5D={}", urlencoding::encode(cursor)));
    }
    // BambooHR takes the API key as the user name, with any password.
    HttpCall::get(url).basic(&j.cred.token, "x").header("accept", "application/json").header("user-agent", "DumbSlab")
}

/// A JSON value as text: BambooHR sends ids as strings or numbers.
fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.trim().to_string(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

/// One page of employees and the cursor for the next, if there is one.
fn read_page(subdomain: &str, reply: &HttpReply) -> Result<(Vec<Employee>, Option<String>), String> {
    if !reply.ok() {
        return Err(match reply.status {
            401 => "BambooHR rejected the API key. Check it was copied whole, then save it again.".into(),
            403 => "BambooHR refused: the API key's user needs access to employee information, or BambooHR paused the key after failed attempts. Try again later.".into(),
            404 => format!("BambooHR has no company at {subdomain}.bamboohr.com. Check the company domain."),
            _ => http_error("BambooHR", reply),
        });
    }
    let v = reply.json();
    let Some(data) = v["data"].as_array() else {
        return Err("BambooHR's answer had no employee list. Try again.".into());
    };
    let employees = data
        .iter()
        .map(|e| {
            let restricted: HashSet<&str> = e["_restrictedFields"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
            let field = |name: &str| (!restricted.contains(name)).then(|| text(&e[name]).chars().take(200).collect::<String>());
            let preferred = text(&e["preferredName"]);
            let first = if preferred.is_empty() { text(&e["firstName"]) } else { preferred };
            let display = text(&e["displayName"]);
            let name = if display.is_empty() { format!("{first} {}", text(&e["lastName"])).trim().to_string() } else { display };
            Employee {
                id: text(&e["employeeId"]),
                name,
                email: field("workEmail").filter(|m| !m.is_empty()),
                title: field("jobTitleName"),
                department: field("departmentName"),
                location: field("locationName"),
                phone: field("workPhone"),
                pronouns: field("pronouns"),
                manager: field("reportsToId"),
            }
        })
        .collect();
    let next = v["meta"]["page"]["nextCursor"].as_str().filter(|c| !c.is_empty()).map(str::to_string);
    Ok((employees, next))
}

/// Runs a people sync's next step (see [`connect::step`]).
pub fn step(db: &dyn Db, cfg: &HostConfig, j: &mut PeopleJob, replies: Vec<HttpReply>, now: DateTime<Utc>) -> ApiResult<Step> {
    match j.phase {
        Phase::Start => {
            j.phase = Phase::Reading;
            Ok(Step::Fetch(vec![page_call(j, None)]))
        }
        Phase::Reading => {
            let reply = replies.into_iter().next().unwrap_or_default();
            let (employees, next) = match read_page(&j.subdomain, &reply) {
                Ok(page) => page,
                Err(message) => return fail(db, j, &message, now),
            };
            j.employees.extend(employees);
            j.pages += 1;
            match next {
                Some(cursor) if j.pages < MAX_PAGES => Ok(Step::Fetch(vec![page_call(j, Some(&cursor))])),
                more => apply(db, cfg, j, more.is_some(), now),
            }
        }
    }
}

fn fail(db: &dyn Db, j: &PeopleJob, message: &str, now: DateTime<Utc>) -> ApiResult<Step> {
    super::finish(db, TABLE, key(), &j.lease, Ended { status: "failed", error: Some(message), result: None }, now)?;
    Ok(Step::Done(Finish::Fail(super::sync_failed(message))))
}

struct Here {
    id: String,
    active: bool,
    /// A sync filled in their profile before.
    synced: bool,
    current: [String; 5],
    manager: Option<String>,
}

fn apply(db: &dyn Db, cfg: &HostConfig, j: &PeopleJob, truncated: bool, now: DateTime<Utc>) -> ApiResult<Step> {
    if !super::holds(db, TABLE, key(), &j.lease)? {
        return Ok(Step::Done(Finish::Fail(super::sync_failed("Another sync took over before this one finished."))));
    }
    if !j.employees.is_empty() && j.employees.iter().all(|e| e.email.is_none()) {
        return fail(
            db,
            j,
            "BambooHR shows the API key's user no work emails, so nobody could be matched. Use a key whose user can see them.",
            now,
        );
    }
    let rows = db.query(
        "SELECT u.id, u.email, u.is_bot, u.deactivated_at, p.user_id AS profile, p.title, p.department, p.location, p.phone, p.pronouns,
           p.manager_id FROM users u LEFT JOIN user_profiles p ON p.user_id = u.id",
        &[],
    )?;
    let mut by_email: HashMap<String, Here> = HashMap::new();
    for r in &rows {
        by_email.insert(
            r.str("email").to_lowercase(),
            Here {
                id: r.str("id"),
                active: !r.bool("is_bot") && r.opt_str("deactivated_at").is_none(),
                synced: r.opt_str("profile").is_some(),
                current: [r.str("title"), r.str("department"), r.str("location"), r.str("phone"), r.str("pronouns")],
                manager: r.opt_str("manager_id"),
            },
        );
    }
    let email_of: HashMap<&str, String> =
        j.employees.iter().filter_map(|e| Some((e.id.as_str(), e.email.as_ref()?.to_lowercase()))).collect();
    let mut result = PeopleSyncResult { employees: j.employees.len(), truncated, ..Default::default() };
    let mut seen: HashSet<String> = HashSet::new();
    for e in &j.employees {
        let Some(email) = &e.email else {
            result.skipped += 1;
            continue;
        };
        let key = email.to_lowercase();
        if !seen.insert(key.clone()) {
            result.skipped += 1;
            continue;
        }
        let Some(here) = by_email.get(&key) else {
            result.not_found_count += 1;
            if result.not_found.len() < LISTED {
                result.not_found.push(Person { name: e.name.clone(), email: email.clone() });
            }
            continue;
        };
        if !here.active {
            result.skipped += 1;
            continue;
        }
        result.matched += 1;
        let wanted = [&e.title, &e.department, &e.location, &e.phone, &e.pronouns];
        let fields: Vec<String> = wanted.iter().zip(&here.current).map(|(w, cur)| w.as_deref().unwrap_or(cur).to_string()).collect();
        // The manager links only to someone active here, and never to the person themself.
        let manager = match &e.manager {
            None => here.manager.clone(),
            Some(mid) => {
                email_of.get(mid.as_str()).and_then(|m| by_email.get(m)).filter(|m| m.active && m.id != here.id).map(|m| m.id.clone())
            }
        };
        if here.synced && fields.as_slice() == here.current.as_slice() && manager == here.manager {
            result.unchanged += 1;
            continue;
        }
        db.execute(
            "INSERT INTO user_profiles (user_id, title, department, location, phone, pronouns, manager_id, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(user_id) DO UPDATE SET title = excluded.title, department = excluded.department, location = excluded.location,
               phone = excluded.phone, pronouns = excluded.pronouns, manager_id = excluded.manager_id, updated_at = excluded.updated_at",
            &params![
                here.id.clone(),
                fields[0].clone(),
                fields[1].clone(),
                fields[2].clone(),
                fields[3].clone(),
                fields[4].clone(),
                manager,
                ts(now)
            ],
        )?;
        result.updated += 1;
    }
    result.without_record = by_email.iter().filter(|(email, h)| h.active && !seen.contains(*email)).count();
    let value = serde_json::to_value(&result).map_err(|e| ApiError::internal(e.to_string()))?;
    let status = if truncated { "partial" } else { "ok" };
    let error =
        truncated.then(|| format!("BambooHR has more than {MAX_EMPLOYEES} active employees; only the first {MAX_EMPLOYEES} were read."));
    super::finish(db, TABLE, key(), &j.lease, Ended { status, error: error.as_deref(), result: Some(value.clone()) }, now)?;
    let mut ctx = super::ctx(db, cfg, &j.owner_id, &j.base_url, now)?;
    emit(
        &mut ctx,
        Event::new("people.synced", "people_sync", "1", format!("synced profiles from BambooHR: {} updated", result.updated))
            .data(json!({ "matched": result.matched, "updated": result.updated, "not_found": result.not_found_count }))
            .admin_only(),
    )?;
    Ok(Step::Done(Finish::Fill(value)))
}

/// `POST /hooks/people`: BambooHR says an employee changed. Signed with the webhook's private key:
/// `X-BambooHR-Signature` is the hex HMAC-SHA256 of the body followed by `X-BambooHR-Timestamp`.
pub(crate) fn hook(db: &dyn Db, cfg: &HostConfig, req: &Request, base_url: &str, now: DateTime<Utc>) -> ApiResult<Outcome> {
    let row = db.one("SELECT secret, webhook FROM people_sync WHERE id = 1", &[])?;
    let Some(row) = row.filter(|r| r.bool("webhook")) else {
        return Err(ApiError::not_found("people sync webhook"));
    };
    let cred = super::open(cfg, OWNER, PROVIDER, &row.str("secret"))?;
    let private_key = cred.field("webhook_key");
    let timestamp = req.header("x-bamboohr-timestamp").unwrap_or_default();
    let signature = req.header("x-bamboohr-signature").unwrap_or_default().trim().to_ascii_lowercase();
    let expected = super::hmac_hex(private_key, &[&req.body, timestamp.as_bytes()]);
    if private_key.is_empty() || !secure_eq(&signature, &expected) {
        return Err(ApiError::unauthorized("the webhook's signature doesn't match its private key"));
    }
    check_plan(db, cfg, now)?;
    match start(db, cfg, base_url, now)? {
        Some(job) => Ok(hook_started(job)),
        None => {
            super::mark_pending(db, TABLE, key(), now)?;
            Ok(hook_answer("queued"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn company_domains() {
        assert_eq!(valid_subdomain(" Acme ").unwrap(), "acme");
        assert_eq!(valid_subdomain("https://acme-co.bamboohr.com/").unwrap(), "acme-co");
        for bad in ["", "acme.evil.test", "a b", "-x", "acme/x"] {
            assert!(valid_subdomain(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn pages_are_read_with_restricted_fields_kept() {
        let body = json!({
            "data": [
                { "employeeId": "7", "firstName": "Ada", "lastName": "L", "preferredName": null, "displayName": "Ada Lovelace",
                  "jobTitleName": "Engineer", "workEmail": "ADA@acme.test", "departmentName": null, "locationName": "Remote",
                  "workPhone": "555", "pronouns": "she/her", "reportsToId": 9, "_restrictedFields": ["departmentName"] },
                { "employeeId": 8, "firstName": "Bo", "preferredName": "Bobby", "lastName": "T", "workEmail": "", "_restrictedFields": [] }
            ],
            "meta": { "page": { "nextCursor": "c2" } }
        });
        let (employees, next) = read_page("acme", &HttpReply { status: 200, body: body.to_string() }).unwrap();
        assert_eq!(next.as_deref(), Some("c2"));
        assert_eq!(employees[0].department, None, "restricted: left as it is");
        assert_eq!(employees[0].manager.as_deref(), Some("9"));
        assert_eq!(employees[0].email.as_deref(), Some("ADA@acme.test"));
        assert_eq!((employees[1].name.as_str(), employees[1].email.as_ref()), ("Bobby T", None));
        assert!(read_page("acme", &HttpReply { status: 404, body: String::new() }).unwrap_err().contains("acme.bamboohr.com"));
    }
}
