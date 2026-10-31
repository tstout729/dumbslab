//! The directory of workspaces (multi-tenant hosting): address reservations, sign-up limits,
//! address moves, usage reports and the free plan's capacity, Stripe customers, and the
//! operator's list. Only the front Worker and workspace objects call it.

use std::cell::Cell;

use chrono::Utc;
use dumbslab_core::tenancy::{self, Limits};
use dumbslab_core::{ApiError, ApiResult};
use serde::Deserialize;
use serde_json::{Value, json};
use worker::*;

use crate::billing::free_budget;
use crate::sql::{DoDb, api_error_response, json_response, read_body, transaction, var_i64};

#[durable_object]
pub struct Directory {
    state: State,
    env: Env,
    migrated: Cell<bool>,
}

#[derive(Deserialize)]
struct ReserveInput {
    slug: String,
    name: String,
    ip_hash: String,
}

#[derive(Deserialize)]
struct CheckInput {
    slug: String,
    expires: i64,
}

#[derive(Deserialize)]
struct SlugInput {
    slug: String,
    status: Option<String>,
}

#[derive(Deserialize)]
struct MoveInput {
    home: String,
    to: String,
}

#[derive(Deserialize)]
struct UsageInput {
    home: String,
    plan: String,
    writes_24h: u64,
    storage_bytes: u64,
}

#[derive(Deserialize)]
struct SlackTeamInput {
    team_id: String,
    home: Option<String>,
    install_id: Option<String>,
}

#[derive(Deserialize)]
struct BillingInput {
    customer: String,
    home: Option<String>,
    subscription: Option<String>,
    status: Option<String>,
    kind: Option<String>,
}

impl Directory {
    fn limits(&self) -> Limits {
        Limits {
            per_ip_per_day: var_i64(&self.env, "SIGNUPS_PER_IP_PER_DAY", 3),
            per_day: var_i64(&self.env, "SIGNUPS_PER_DAY", 200),
            max_workspaces: var_i64(&self.env, "MAX_WORKSPACES", 1000),
            free: free_budget(&self.env),
        }
    }

    /// Runs one directory change in a transaction; errors roll back.
    fn run<T: 'static>(&self, f: impl FnOnce(&dyn dumbslab_core::Db) -> ApiResult<T> + 'static) -> Result<ApiResult<T>> {
        let storage = self.state.storage();
        let db = DoDb::new(storage.sql());
        transaction(&storage, db, move |db| {
            let out = f(db);
            let ok = out.is_ok();
            (out, ok)
        })
    }
}

fn respond(result: ApiResult<Value>) -> Result<Response> {
    match result {
        Ok(v) => json_response(200, &v),
        Err(e) => api_error_response(&e),
    }
}

fn parse<T: for<'de> Deserialize<'de>>(body: &[u8]) -> ApiResult<T> {
    serde_json::from_slice(body).map_err(|e| ApiError::bad_request(format!("invalid directory request: {e}")))
}

impl DurableObject for Directory {
    fn new(state: State, env: Env) -> Self {
        Self { state, env, migrated: Cell::new(false) }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        if !self.migrated.get() {
            if let Err(e) = self.run(|db| tenancy::directory_migrate(db))? {
                return api_error_response(&e);
            }
            self.migrated.set(true);
        }
        let path = req.path();
        let body = read_body(&mut req).await?.unwrap_or_default();
        let limits = self.limits();
        let result = match (req.method(), path.as_str()) {
            (Method::Post, "/reserve") => {
                let input: ApiResult<ReserveInput> = parse(&body);
                self.run(move |db| {
                    let input = input?;
                    let until = tenancy::reserve(db, &input.slug, &input.name, &input.ip_hash, Utc::now(), limits)?;
                    Ok(json!({ "reserved_until": until.timestamp() }))
                })?
            }
            (Method::Post, "/available") => {
                let input: ApiResult<SlugInput> = parse(&body);
                self.run(move |db| {
                    let reason = tenancy::address_unavailable(db, &input?.slug, Utc::now())?;
                    Ok(json!({ "available": reason.is_none(), "message": reason }))
                })?
            }
            (Method::Post, "/check") => {
                let input: ApiResult<CheckInput> = parse(&body);
                self.run(move |db| {
                    let input = input?;
                    tenancy::reservation_matches(db, &input.slug, input.expires, Utc::now()).map(|ok| json!({ "ok": ok }))
                })?
            }
            (Method::Post, "/activate") => {
                let input: ApiResult<SlugInput> = parse(&body);
                self.run(move |db| tenancy::activate(db, &input?.slug, Utc::now()).map(|_| json!({ "ok": true })))?
            }
            (Method::Post, "/status") => {
                let input: ApiResult<SlugInput> = parse(&body);
                self.run(move |db| {
                    let input = input?;
                    tenancy::set_status(db, &input.slug, input.status.as_deref().unwrap_or_default()).map(|_| json!({ "ok": true }))
                })?
            }
            (Method::Post, "/remove") => {
                let input: ApiResult<SlugInput> = parse(&body);
                self.run(move |db| tenancy::remove(db, &input?.slug).map(|_| json!({ "ok": true })))?
            }
            (Method::Post, "/move") => {
                let input: ApiResult<MoveInput> = parse(&body);
                self.run(move |db| {
                    let input = input?;
                    tenancy::move_address(db, &input.home, &input.to, Utc::now()).map(|_| json!({ "ok": true }))
                })?
            }
            (Method::Post, "/resolve") => {
                let input: ApiResult<SlugInput> = parse(&body);
                self.run(move |db| match tenancy::resolve(db, &input?.slug)? {
                    Some((home, moved)) => {
                        let paying = tenancy::paying(db, &home)?;
                        Ok(json!({ "home": home, "addresses": moved, "paying": paying }))
                    }
                    None => Err(ApiError::not_found("a workspace at that address")),
                })?
            }
            (Method::Get, "/list") => {
                let budget = limits.free;
                self.run(move |db| {
                    let used = tenancy::free_usage(db, Utc::now())?;
                    let free = json!({
                        "writes_24h": used.writes_24h,
                        "writes_per_day": budget.writes_per_day,
                        "storage_bytes": used.storage_bytes,
                        "storage_budget_bytes": budget.storage_bytes,
                    });
                    tenancy::list(db).map(|items| json!({ "items": items, "free_plan": free }))
                })?
            }
            // A workspace's usage report. The answer tells it whether the free plan is at capacity.
            (Method::Post, "/usage") => {
                let input: ApiResult<UsageInput> = parse(&body);
                self.run(move |db| {
                    let input = input?;
                    let now = Utc::now();
                    tenancy::report_usage(db, &input.home, &input.plan, input.writes_24h, input.storage_bytes, now)?;
                    let capacity = tenancy::free_capacity(db, now, limits.free)?;
                    serde_json::to_value(capacity).map_err(|e| ApiError::internal(e.to_string()))
                })?
            }
            (Method::Post, "/billing/link") => {
                let input: ApiResult<BillingInput> = parse(&body);
                self.run(move |db| {
                    let input = input?;
                    let home = input.home.ok_or_else(|| ApiError::bad_request("send the workspace's home"))?;
                    tenancy::link_customer(db, &input.customer, &home, Utc::now()).map(|_| json!({ "ok": true }))
                })?
            }
            (Method::Post, "/billing/lookup") => {
                let input: ApiResult<BillingInput> = parse(&body);
                self.run(move |db| {
                    Ok(match tenancy::customer_home(db, &input?.customer)? {
                        tenancy::Payer::Unknown => json!({ "home": null }),
                        tenancy::Payer::Workspace(home) => json!({ "home": home }),
                        tenancy::Payer::Detached => json!({ "home": null, "detached": true }),
                    })
                })?
            }
            (Method::Post, "/billing/subscription") => {
                let input: ApiResult<BillingInput> = parse(&body);
                self.run(move |db| {
                    let input = input?;
                    let (sub, status) = (input.subscription.unwrap_or_default(), input.status.unwrap_or_default());
                    tenancy::record_subscription(db, &input.customer, &sub, &status, Utc::now()).map(|_| json!({ "ok": true }))
                })?
            }
            (Method::Post, "/billing/risk") => {
                let input: ApiResult<BillingInput> = parse(&body);
                self.run(move |db| {
                    let input = input?;
                    tenancy::record_risk(db, &input.customer, &input.kind.unwrap_or_default(), Utc::now()).map(|_| json!({ "ok": true }))
                })?
            }
            // Add to Slack: a workspace claims, confirms or lets go of a Slack workspace (from its
            // jobs), and the root domain asks where to send a Slack workspace's commands and events.
            (Method::Post, "/slack/claim") => {
                let input: ApiResult<SlackTeamInput> = parse(&body);
                self.run(move |db| {
                    let input = input?;
                    let home = input.home.ok_or_else(|| ApiError::bad_request("send the workspace's home"))?;
                    let id = input.install_id.unwrap_or_default();
                    tenancy::claim_slack_team(db, &input.team_id, &home, &id, Utc::now()).map(|_| json!({ "ok": true }))
                })?
            }
            (Method::Post, "/slack/confirm") => {
                let input: ApiResult<SlackTeamInput> = parse(&body);
                self.run(move |db| {
                    let input = input?;
                    let home = input.home.ok_or_else(|| ApiError::bad_request("send the workspace's home"))?;
                    let id = input.install_id.unwrap_or_default();
                    tenancy::confirm_slack_team(db, &input.team_id, &home, &id).map(|_| json!({ "ok": true }))
                })?
            }
            (Method::Post, "/slack/release") => {
                let input: ApiResult<SlackTeamInput> = parse(&body);
                self.run(move |db| {
                    let input = input?;
                    let home = input.home.ok_or_else(|| ApiError::bad_request("send the workspace's home"))?;
                    let id = input.install_id.unwrap_or_default();
                    tenancy::release_slack_team(db, &input.team_id, &home, &id).map(|_| json!({ "ok": true }))
                })?
            }
            (Method::Post, "/slack/lookup") => {
                let input: ApiResult<SlackTeamInput> = parse(&body);
                self.run(move |db| match tenancy::slack_team_home(db, &input?.team_id)? {
                    Some((home, address, install_id)) => Ok(json!({ "home": home, "address": address, "install_id": install_id })),
                    None => Err(ApiError::not_found("a workspace for that Slack workspace")),
                })?
            }
            _ => Err(ApiError::not_found("directory route")),
        };
        respond(result)
    }
}
