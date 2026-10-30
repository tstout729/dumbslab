//! The storage boundary. The core speaks SQLite through this small synchronous trait so the
//! same code runs on a local SQLite file (native server) and inside a Cloudflare Durable
//! Object (whose SQL API is also synchronous).

use std::sync::Arc;

use crate::error::{ApiError, ApiResult};

#[derive(Debug, Clone, PartialEq)]
pub enum SqlValue {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

impl From<&str> for SqlValue {
    fn from(v: &str) -> Self {
        SqlValue::Text(v.to_string())
    }
}
impl From<String> for SqlValue {
    fn from(v: String) -> Self {
        SqlValue::Text(v)
    }
}
impl From<&String> for SqlValue {
    fn from(v: &String) -> Self {
        SqlValue::Text(v.clone())
    }
}
impl From<i64> for SqlValue {
    fn from(v: i64) -> Self {
        SqlValue::Integer(v)
    }
}
impl From<i32> for SqlValue {
    fn from(v: i32) -> Self {
        SqlValue::Integer(v as i64)
    }
}
impl From<u32> for SqlValue {
    fn from(v: u32) -> Self {
        SqlValue::Integer(v as i64)
    }
}
impl From<usize> for SqlValue {
    fn from(v: usize) -> Self {
        SqlValue::Integer(v as i64)
    }
}
impl From<bool> for SqlValue {
    fn from(v: bool) -> Self {
        SqlValue::Integer(v as i64)
    }
}
impl From<f64> for SqlValue {
    fn from(v: f64) -> Self {
        SqlValue::Real(v)
    }
}
impl<T: Into<SqlValue>> From<Option<T>> for SqlValue {
    fn from(v: Option<T>) -> Self {
        match v {
            Some(v) => v.into(),
            None => SqlValue::Null,
        }
    }
}
impl<T: Into<SqlValue> + Clone> From<&Option<T>> for SqlValue {
    fn from(v: &Option<T>) -> Self {
        v.clone().into()
    }
}

/// Builds a `Vec<SqlValue>` from heterogeneous values.
#[macro_export]
macro_rules! params {
    () => { Vec::<$crate::db::SqlValue>::new() };
    ($($v:expr),+ $(,)?) => { <[_]>::into_vec(::std::boxed::Box::new([$($crate::db::SqlValue::from($v)),+])) };
}

/// One result row. Column lookups are by name.
#[derive(Debug, Clone)]
pub struct Row {
    columns: Arc<Vec<String>>,
    values: Vec<SqlValue>,
}

impl Row {
    pub fn new(columns: Arc<Vec<String>>, values: Vec<SqlValue>) -> Self {
        Row { columns, values }
    }

    pub fn get(&self, name: &str) -> &SqlValue {
        match self.columns.iter().position(|c| c == name) {
            Some(i) => &self.values[i],
            None => panic!("column `{name}` is not in the result set"),
        }
    }

    pub fn str(&self, name: &str) -> String {
        self.opt_str(name).unwrap_or_default()
    }

    pub fn opt_str(&self, name: &str) -> Option<String> {
        match self.get(name) {
            SqlValue::Null => None,
            SqlValue::Text(s) => Some(s.clone()),
            SqlValue::Integer(i) => Some(i.to_string()),
            SqlValue::Real(f) => Some(f.to_string()),
            SqlValue::Blob(b) => Some(String::from_utf8_lossy(b).into_owned()),
        }
    }

    pub fn i64(&self, name: &str) -> i64 {
        self.opt_i64(name).unwrap_or(0)
    }

    pub fn opt_i64(&self, name: &str) -> Option<i64> {
        match self.get(name) {
            SqlValue::Integer(i) => Some(*i),
            SqlValue::Real(f) => Some(*f as i64),
            SqlValue::Text(s) => s.parse().ok(),
            _ => None,
        }
    }

    pub fn f64(&self, name: &str) -> f64 {
        match self.get(name) {
            SqlValue::Integer(i) => *i as f64,
            SqlValue::Real(f) => *f,
            SqlValue::Text(s) => s.parse().unwrap_or(0.0),
            _ => 0.0,
        }
    }

    pub fn bool(&self, name: &str) -> bool {
        self.i64(name) != 0
    }
}

/// A synchronous SQLite connection. Every request runs inside one transaction that the host
/// opens before calling the core and commits (or rolls back) afterwards.
pub trait Db {
    fn query(&self, sql: &str, params: &[SqlValue]) -> ApiResult<Vec<Row>>;
    /// Runs a statement and returns the number of rows it changed.
    fn execute(&self, sql: &str, params: &[SqlValue]) -> ApiResult<u64>;
    /// Runs several `;`-separated statements without parameters (used for migrations).
    fn execute_batch(&self, sql: &str) -> ApiResult<()>;
}

pub trait DbExt {
    fn one(&self, sql: &str, params: &[SqlValue]) -> ApiResult<Option<Row>>;
    fn scalar_i64(&self, sql: &str, params: &[SqlValue]) -> ApiResult<i64>;
}

impl<D: Db + ?Sized> DbExt for D {
    fn one(&self, sql: &str, params: &[SqlValue]) -> ApiResult<Option<Row>> {
        Ok(self.query(sql, params)?.into_iter().next())
    }

    fn scalar_i64(&self, sql: &str, params: &[SqlValue]) -> ApiResult<i64> {
        let row = self.one(sql, params)?.ok_or_else(|| ApiError::internal("scalar query returned no rows"))?;
        Ok(match &row.values[0] {
            SqlValue::Integer(i) => *i,
            SqlValue::Real(f) => *f as i64,
            SqlValue::Text(s) => s.parse().unwrap_or(0),
            _ => 0,
        })
    }
}

/// Schema migrations, applied in order. Never edit a shipped migration; append a new one.
pub const MIGRATIONS: &[&str] = &[
    include_str!("migrations/0001_init.sql"),
    include_str!("migrations/0002_oauth_client_seen.sql"),
    include_str!("migrations/0003_token_resource.sql"),
    include_str!("migrations/0004_activity_without_comment_bodies.sql"),
    include_str!("migrations/0005_files.sql"),
    include_str!("migrations/0006_usage.sql"),
    include_str!("migrations/0007_connections.sql"),
    include_str!("migrations/0008_sso.sql"),
    include_str!("migrations/0009_slack.sql"),
];

/// Brings the schema up to date. Safe to call on every start.
pub fn migrate(db: &dyn Db) -> ApiResult<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")?;
    let current =
        db.one("SELECT value FROM meta WHERE key = 'schema_version'", &[])?.and_then(|r| r.opt_i64("value")).unwrap_or(0) as usize;
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(current) {
        db.execute_batch(sql)?;
        db.execute(
            "INSERT INTO meta (key, value) VALUES ('schema_version', ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            &params![((i + 1) as i64).to_string()],
        )?;
    }
    Ok(())
}
