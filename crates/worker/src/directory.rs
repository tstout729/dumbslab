//! The directory of workspaces (multi-tenant hosting): address reservations, sign-up limits and
//! the operator's list. Only the front Worker and workspace objects call it.

use std::cell::Cell;

use chrono::Utc;
use dumbslab_core::tenancy::{self, Limits};
use dumbslab_core::{ApiError, ApiResult};
use serde::Deserialize;
use serde_json::{Value, json};
use worker::*;

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

impl Directory {
    fn limits(&self) -> Limits {
        Limits {
            per_ip_per_day: var_i64(&self.env, "SIGNUPS_PER_IP_PER_DAY", 3),
            per_day: var_i64(&self.env, "SIGNUPS_PER_DAY", 200),
            max_workspaces: var_i64(&self.env, "MAX_WORKSPACES", 1000),
        }
    }

    /// Runs one directory change in a transaction; errors roll back.
    fn run<T: 'static>(&self, f: impl FnOnce(&dyn dumbslab_core::Db) -> ApiResult<T> + 'static) -> Result<ApiResult<T>> {
        let storage = self.state.storage();
        let db = DoDb { sql: storage.sql() };
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
            (Method::Get, "/list") => self.run(|db| tenancy::list(db).map(|items| json!({ "items": items })))?,
            _ => Err(ApiError::not_found("directory route")),
        };
        respond(result)
    }
}
