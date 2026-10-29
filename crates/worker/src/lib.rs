//! DumbSlab on Cloudflare Workers.
//!
//! The Worker serves the web app from static assets and forwards API, MCP and OAuth requests to
//! one SQLite-backed Durable Object that holds the whole workspace. The Durable Object runs the
//! same core as the native server; every request is one `transactionSync` call, so a failed
//! operation rolls back exactly like it does on the native SQLite host.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use dumbslab_core::db::{Db, Row, SqlValue};
use dumbslab_core::{ApiError, ApiResult, Effect, HostConfig, Outcome};
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use worker::*;

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let path = req.path();
    if !dumbslab_core::http::is_core_path(&path) {
        return env.assets("ASSETS")?.fetch_request(req).await;
    }
    let workspace = env.var("WORKSPACE_NAME").map(|v| v.to_string()).unwrap_or_else(|_| "main".into());
    let stub = env.durable_object("WORKSPACE")?.id_from_name(&workspace)?.get_stub()?;
    stub.fetch_with_request(req).await
}

/// SQL access through the Durable Object's synchronous SQL API.
#[derive(Clone)]
struct DoDb {
    sql: SqlStorage,
}

fn to_binding(v: &SqlValue) -> SqlStorageValue {
    match v {
        SqlValue::Null => SqlStorageValue::Null,
        SqlValue::Integer(i) => SqlStorageValue::Integer(*i),
        SqlValue::Real(f) => SqlStorageValue::Float(*f),
        SqlValue::Text(s) => SqlStorageValue::String(s.clone()),
        SqlValue::Blob(b) => SqlStorageValue::Blob(b.clone()),
    }
}

fn from_storage(v: SqlStorageValue) -> SqlValue {
    match v {
        SqlStorageValue::Null => SqlValue::Null,
        SqlStorageValue::Boolean(b) => SqlValue::Integer(b as i64),
        SqlStorageValue::Integer(i) => SqlValue::Integer(i),
        SqlStorageValue::Float(f) => SqlValue::Real(f),
        SqlStorageValue::String(s) => SqlValue::Text(s),
        SqlStorageValue::Blob(b) => SqlValue::Blob(b),
    }
}

fn sql_err(e: worker::Error) -> ApiError {
    let msg = e.to_string();
    if msg.contains("UNIQUE constraint") || msg.contains("constraint failed") {
        ApiError::conflict(format!("conflicts with existing data: {msg}"))
    } else {
        ApiError::internal(format!("database error: {msg}"))
    }
}

impl DoDb {
    fn run(&self, sql: &str, params: &[SqlValue]) -> ApiResult<SqlCursor> {
        let bindings: Vec<SqlStorageValue> = params.iter().map(to_binding).collect();
        self.sql.exec(sql, if bindings.is_empty() { None } else { Some(bindings) }).map_err(sql_err)
    }
}

impl Db for DoDb {
    fn query(&self, sql: &str, params: &[SqlValue]) -> ApiResult<Vec<Row>> {
        let cursor = self.run(sql, params)?;
        let columns = std::sync::Arc::new(cursor.column_names());
        let mut out = vec![];
        for row in cursor.raw() {
            let values = row.map_err(sql_err)?.into_iter().map(from_storage).collect();
            out.push(Row::new(columns.clone(), values));
        }
        Ok(out)
    }

    fn execute(&self, sql: &str, params: &[SqlValue]) -> ApiResult<u64> {
        // Drain the cursor so the statement has fully run before reading changes().
        for row in self.run(sql, params)?.raw() {
            row.map_err(sql_err)?;
        }
        let changes = self.query("SELECT changes() AS n", &[])?;
        Ok(changes.first().map(|r| r.i64("n")).unwrap_or(0).max(0) as u64)
    }

    fn execute_batch(&self, sql: &str) -> ApiResult<()> {
        for row in self.run(sql, &[])?.raw() {
            row.map_err(sql_err)?;
        }
        Ok(())
    }
}

const ROLLBACK: &str = "__dumbslab_rollback__";

/// Runs `f` inside `storage.transactionSync()`. Returning `false` (or panicking) rolls back.
fn transaction<T: 'static>(storage: &Storage, db: DoDb, f: impl FnOnce(&dyn Db) -> (T, bool) + 'static) -> Result<T> {
    let raw: &JsValue = storage.as_raw().as_ref();
    let tx: js_sys::Function = js_sys::Reflect::get(raw, &JsValue::from_str("transactionSync"))?.dyn_into()?;
    let slot: Rc<RefCell<Option<T>>> = Rc::new(RefCell::new(None));
    let out = slot.clone();
    let closure = Closure::once(move || -> std::result::Result<JsValue, JsValue> {
        let (value, commit) = f(&db);
        *out.borrow_mut() = Some(value);
        if commit { Ok(JsValue::UNDEFINED) } else { Err(JsValue::from_str(ROLLBACK)) }
    });
    match tx.call1(raw, closure.as_ref().unchecked_ref()) {
        Ok(_) => {}
        Err(e) if e.as_string().as_deref() == Some(ROLLBACK) => {}
        Err(e) => return Err(worker::Error::from(e)),
    }
    slot.borrow_mut().take().ok_or_else(|| worker::Error::RustError("transaction produced no result".into()))
}

#[durable_object]
pub struct Workspace {
    state: State,
    env: Env,
    migrated: Cell<bool>,
}

impl DurableObject for Workspace {
    fn new(state: State, env: Env) -> Self {
        Self { state, env, migrated: Cell::new(false) }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let storage = self.state.storage();
        let db = DoDb { sql: storage.sql() };
        if !self.migrated.get() {
            transaction(&storage, db.clone(), |db| match dumbslab_core::migrate(db) {
                Ok(()) => ((), true),
                Err(e) => {
                    console_error!("migration failed: {}", e.message);
                    ((), false)
                }
            })?;
            self.migrated.set(true);
        }

        let url = req.url()?;
        let origin = match url.port() {
            Some(p) => format!("{}://{}:{p}", url.scheme(), url.host_str().unwrap_or_default()),
            None => format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default()),
        };
        let headers: Vec<(String, String)> = req.headers().entries().map(|(k, v)| (k.to_lowercase(), v)).collect();
        let core_req = dumbslab_core::Request {
            method: req.method().to_string(),
            path: url.path().to_string(),
            query: url.query().unwrap_or_default().to_string(),
            client_ip: headers.iter().find(|(k, _)| k == "cf-connecting-ip").map(|(_, v)| v.clone()),
            headers,
            body: req.bytes().await.unwrap_or_default(),
            origin,
        };
        let cfg = HostConfig {
            base_url: self.env.var("BASE_URL").ok().map(|v| v.to_string()).filter(|s| !s.is_empty()),
            setup_token: self.env.secret("SETUP_TOKEN").ok().map(|s| s.to_string()).filter(|s| !s.is_empty()),
            open_setup: self.env.var("OPEN_SETUP").map(|v| v.to_string() == "true").unwrap_or(false),
        };

        let outcome: Option<Outcome> = transaction(&storage, db.clone(), move |db| match dumbslab_core::handle(db, &cfg, &core_req) {
            Some(o) => {
                let commit = o.commit;
                (Some(o), commit)
            }
            None => (None, true),
        })?;
        let Some(outcome) = outcome else {
            return Response::error("not found", 404);
        };

        for effect in outcome.effects {
            let Effect::Webhook(d) = effect;
            let db = db.clone();
            self.state.wait_until(async move {
                let headers = Headers::new();
                for (k, v) in &d.headers {
                    let _ = headers.set(k, v);
                }
                let mut init = RequestInit::new();
                init.with_method(Method::Post).with_headers(headers).with_body(Some(JsValue::from_str(&d.body)));
                let result = match Request::new_with_init(&d.url, &init) {
                    Ok(r) => Fetch::Request(r).send().await,
                    Err(e) => Err(e),
                };
                let (status, error) = match result {
                    Ok(resp) if (200..300).contains(&resp.status_code()) => (Some(resp.status_code()), None),
                    Ok(resp) => (Some(resp.status_code()), Some(format!("HTTP {}", resp.status_code()))),
                    Err(e) => (None, Some(e.to_string())),
                };
                let _ = dumbslab_core::record_webhook_result(&db, &d.webhook_id, status, error.as_deref());
            });
        }

        let r = outcome.response;
        // 204/304 responses must not have a body at all, not even an empty one.
        let mut resp = if r.body.is_empty() { Response::empty()? } else { Response::from_bytes(r.body)? }.with_status(r.status);
        let h = resp.headers_mut();
        for (k, v) in &r.headers {
            h.append(k, v)?;
        }
        Ok(resp)
    }
}
