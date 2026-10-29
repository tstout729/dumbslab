//! SQLite storage for the native server: one connection, one transaction per request.
//! Serializing requests mirrors the Durable Object model, so both hosts behave the same.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::{Arc, Mutex};

use dumbslab_core::db::{Db, Row, SqlValue};
use dumbslab_core::{ApiError, ApiResult};
use rusqlite::types::{Value as RValue, ValueRef};
use rusqlite::{Connection, ErrorCode, params_from_iter};

pub struct Sqlite<'c>(pub &'c Connection);

fn db_err(e: rusqlite::Error) -> ApiError {
    match &e {
        rusqlite::Error::SqliteFailure(f, msg) if f.code == ErrorCode::ConstraintViolation => {
            ApiError::conflict(format!("conflicts with existing data: {}", msg.clone().unwrap_or_default()))
        }
        _ => ApiError::internal(format!("database error: {e}")),
    }
}

fn to_rusqlite(v: &SqlValue) -> RValue {
    match v {
        SqlValue::Null => RValue::Null,
        SqlValue::Integer(i) => RValue::Integer(*i),
        SqlValue::Real(f) => RValue::Real(*f),
        SqlValue::Text(s) => RValue::Text(s.clone()),
        SqlValue::Blob(b) => RValue::Blob(b.clone()),
    }
}

impl Db for Sqlite<'_> {
    fn query(&self, sql: &str, params: &[SqlValue]) -> ApiResult<Vec<Row>> {
        let mut stmt = self.0.prepare_cached(sql).map_err(db_err)?;
        let columns: Arc<Vec<String>> = Arc::new(stmt.column_names().map(String::from).collect());
        let n = columns.len();
        let mut rows = stmt.query(params_from_iter(params.iter().map(to_rusqlite))).map_err(db_err)?;
        let mut out = vec![];
        while let Some(r) = rows.next().map_err(db_err)? {
            let mut values = Vec::with_capacity(n);
            for i in 0..n {
                values.push(match r.get_ref(i).map_err(db_err)? {
                    ValueRef::Null => SqlValue::Null,
                    ValueRef::Integer(i) => SqlValue::Integer(i),
                    ValueRef::Real(f) => SqlValue::Real(f),
                    ValueRef::Text(t) => SqlValue::Text(String::from_utf8_lossy(t).into_owned()),
                    ValueRef::Blob(b) => SqlValue::Blob(b.to_vec()),
                });
            }
            out.push(Row::new(columns.clone(), values));
        }
        Ok(out)
    }

    fn execute(&self, sql: &str, params: &[SqlValue]) -> ApiResult<u64> {
        let mut stmt = self.0.prepare_cached(sql).map_err(db_err)?;
        stmt.execute(params_from_iter(params.iter().map(to_rusqlite))).map(|n| n as u64).map_err(db_err)
    }

    fn execute_batch(&self, sql: &str) -> ApiResult<()> {
        self.0.execute_batch(sql).map_err(db_err)
    }
}

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(path: &Path) -> anyhow::Result<Store> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;",
        )?;
        let store = Store { conn: Mutex::new(conn) };
        store.with_tx(|db| match dumbslab_core::migrate(db) {
            Ok(()) => (Ok(()), true),
            Err(e) => (Err(e), false),
        })??;
        Ok(store)
    }

    /// Runs `f` in one transaction. `f` returns its result and whether to commit.
    /// A panic rolls back and becomes an error instead of poisoning the store.
    pub fn with_tx<T>(&self, f: impl FnOnce(&dyn Db) -> (T, bool)) -> anyhow::Result<T> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute_batch("BEGIN IMMEDIATE")?;
        match catch_unwind(AssertUnwindSafe(|| f(&Sqlite(&conn)))) {
            Ok((out, true)) => match conn.execute_batch("COMMIT") {
                Ok(()) => Ok(out),
                Err(e) => {
                    let _ = conn.execute_batch("ROLLBACK");
                    Err(e.into())
                }
            },
            Ok((out, false)) => {
                conn.execute_batch("ROLLBACK")?;
                Ok(out)
            }
            Err(_) => {
                let _ = conn.execute_batch("ROLLBACK");
                anyhow::bail!("request handler panicked; transaction rolled back")
            }
        }
    }
}
