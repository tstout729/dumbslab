//! Durable Object SQL access, transactions and small HTTP helpers shared by both objects.

use std::cell::RefCell;
use std::rc::Rc;

use dumbslab_core::db::{Db, Row, SqlValue};
use dumbslab_core::{ApiError, ApiResult};
use futures_util::StreamExt;
use serde_json::{Value, json};
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use worker::*;

/// SQL access through the Durable Object's synchronous SQL API.
#[derive(Clone)]
pub struct DoDb {
    pub sql: SqlStorage,
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
pub fn transaction<T: 'static>(storage: &Storage, db: DoDb, f: impl FnOnce(&dyn Db) -> (T, bool) + 'static) -> Result<T> {
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

/// Reads the request body, or `None` when it is larger than the core's limit for its path (the
/// same limit the native server applies: uploads get room for a file).
pub async fn read_body(req: &mut Request) -> Result<Option<Vec<u8>>> {
    let max_body = dumbslab_core::http::body_limit(req.url()?.path());
    let declared = req.headers().get("content-length")?.and_then(|v| v.parse::<usize>().ok());
    if declared.is_some_and(|n| n > max_body) {
        return Ok(None);
    }
    let Ok(mut stream) = req.stream() else {
        return Ok(Some(vec![])); // no body
    };
    let mut body = Vec::new();
    let mut too_large = false;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        // Past the limit, keep reading but discard: answering before the upload ends breaks the
        // connection the next request arrives on.
        too_large |= body.len() + chunk.len() > max_body;
        if !too_large {
            body.extend_from_slice(&chunk);
        }
    }
    Ok((!too_large).then_some(body))
}

pub fn json_response(status: u16, value: &Value) -> Result<Response> {
    Ok(Response::from_json(value)?.with_status(status))
}

pub fn error_response(status: u16, code: &str, message: &str) -> Result<Response> {
    json_response(status, &json!({ "error": { "code": code, "message": message } }))
}

pub fn api_error_response(e: &ApiError) -> Result<Response> {
    json_response(e.status, &e.to_json())
}

/// A non-empty string variable or secret.
pub fn var(env: &Env, name: &str) -> Option<String> {
    env.var(name).map(|v| v.to_string()).ok().or_else(|| env.secret(name).map(|v| v.to_string()).ok()).filter(|s| !s.is_empty())
}

pub fn var_i64(env: &Env, name: &str, default: i64) -> i64 {
    var(env, name).and_then(|v| v.parse().ok()).unwrap_or(default)
}

pub fn flag(env: &Env, name: &str) -> bool {
    var(env, name).is_some_and(|v| v == "true")
}

/// Sends a JSON request to a Durable Object and returns (status, body).
pub async fn call_object(env: &Env, binding: &str, name: &str, method: Method, path: &str, body: Option<&Value>) -> Result<(u16, Value)> {
    let stub = env.durable_object(binding)?.id_from_name(name)?.get_stub()?;
    let mut init = RequestInit::new();
    init.with_method(method);
    if let Some(b) = body {
        let headers = Headers::new();
        headers.set("content-type", "application/json")?;
        init.with_headers(headers).with_body(Some(JsValue::from_str(&b.to_string())));
    }
    let mut resp = stub.fetch_with_request(Request::new_with_init(&format!("https://internal{path}"), &init)?).await?;
    let status = resp.status_code();
    let value = resp.json::<Value>().await.unwrap_or(Value::Null);
    Ok((status, value))
}
