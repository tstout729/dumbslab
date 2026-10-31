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
    team_id: Option<String>,
    home: Option<String>,
    token_fingerprint: Option<String>,
}

#[derive(Deserialize)]
struct SlackInstallInput {
    home: Option<String>,
    #[serde(flatten)]
    install: tenancy::SlackInstall,
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

/// A workspace's call about one Slack workspace: both named.
fn team_and_home(input: &SlackTeamInput) -> ApiResult<(&str, &str)> {
    let team = input.team_id.as_deref().ok_or_else(|| ApiError::bad_request("send the Slack workspace's team_id"))?;
    let home = input.home.as_deref().ok_or_else(|| ApiError::bad_request("send the workspace's home"))?;
    Ok((team, home))
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
            // Add to Slack. From a workspace's jobs (the Worker names the workspace, `home`): record
            // an installation, let go of one, get its token, ask what it holds, forget a dead
            // token. From the root domain: where to send a Slack workspace's requests, and an
            // installation's token to check when Slack says the app was removed.
            (Method::Post, "/slack/install") => {
                let input: ApiResult<SlackInstallInput> = parse(&body);
                self.run(move |db| {
                    let input = input?;
                    let home = input.home.ok_or_else(|| ApiError::bad_request("send the workspace's home"))?;
                    tenancy::slack_install(db, &home, &input.install, Utc::now()).map(|_| json!({ "ok": true }))
                })?
            }
            (Method::Post, "/slack/release") => {
                let input: ApiResult<SlackTeamInput> = parse(&body);
                self.run(move |db| {
                    let input = input?;
                    let (team, home) = team_and_home(&input)?;
                    tenancy::slack_release(db, team, home).map(|released| json!({ "ok": true, "released": released }))
                })?
            }
            (Method::Post, "/slack/token") => {
                let input: ApiResult<SlackTeamInput> = parse(&body);
                self.run(move |db| {
                    let input = input?;
                    let (team, home) = team_and_home(&input)?;
                    match tenancy::slack_token(db, team, home)? {
                        Some(token) => serde_json::to_value(token).map_err(|e| ApiError::internal(e.to_string())),
                        None => Err(ApiError::not_found("that Slack workspace for this workspace")),
                    }
                })?
            }
            (Method::Post, "/slack/status") => {
                let input: ApiResult<SlackTeamInput> = parse(&body);
                self.run(move |db| {
                    let input = input?;
                    let home = input.home.as_deref().ok_or_else(|| ApiError::bad_request("send the workspace's home"))?;
                    let status = tenancy::slack_status(db, input.team_id.as_deref(), home)?;
                    serde_json::to_value(status).map_err(|e| ApiError::internal(e.to_string()))
                })?
            }
            (Method::Post, "/slack/forget") => {
                let input: ApiResult<SlackTeamInput> = parse(&body);
                self.run(move |db| {
                    let input = input?;
                    let team = input.team_id.as_deref().ok_or_else(|| ApiError::bad_request("send the Slack workspace's team_id"))?;
                    let fingerprint =
                        input.token_fingerprint.as_deref().ok_or_else(|| ApiError::bad_request("send the token's fingerprint"))?;
                    tenancy::slack_forget_if(db, team, fingerprint, input.home.as_deref())
                        .map(|forgot| json!({ "ok": true, "forgot": forgot }))
                })?
            }
            (Method::Post, "/slack/row") => {
                let input: ApiResult<SlackTeamInput> = parse(&body);
                self.run(move |db| {
                    let input = input?;
                    let team = input.team_id.as_deref().ok_or_else(|| ApiError::bad_request("send the Slack workspace's team_id"))?;
                    match tenancy::slack_row(db, team)? {
                        Some(token) => serde_json::to_value(token).map_err(|e| ApiError::internal(e.to_string())),
                        None => Err(ApiError::not_found("an installation for that Slack workspace")),
                    }
                })?
            }
            (Method::Post, "/slack/lookup") => {
                let input: ApiResult<SlackTeamInput> = parse(&body);
                self.run(move |db| {
                    let input = input?;
                    let team = input.team_id.as_deref().ok_or_else(|| ApiError::bad_request("send the Slack workspace's team_id"))?;
                    match tenancy::slack_team_home(db, team)? {
                        Some((home, address)) => Ok(json!({ "home": home, "address": address })),
                        None => Err(ApiError::not_found("a workspace for that Slack workspace")),
                    }
                })?
            }
            _ => Err(ApiError::not_found("directory route")),
        };
        respond(result)
    }
}
