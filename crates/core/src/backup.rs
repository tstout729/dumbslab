//! Operator backup and restore. A Durable Object's data can't move to another Cloudflare account,
//! so an operator copies it: every table of every object, page by page, from one deployment into
//! the same-named objects of a fresh deployment of the same code. The hosts route the requests
//! (see the Worker's operator API and `dumbslab backup`); everything they run on an object's
//! database is here.
//!
//! - [`manifest`] lists an object's tables in the order to restore them (each after the tables it
//!   refers to), with their columns, row counts and a digest of the schema.
//! - [`dump`] reads one page of a table in key order (the rowid, or a `WITHOUT ROWID` table's
//!   primary key): about [`PAGE_BYTES`] at most, and where the next page starts.
//! - [`begin`] prepares an object that holds no data: it creates the schema, refuses a source whose
//!   schema differs, and marks the restore as under way.
//! - [`restore`] writes a page. Rows already there are left alone, so a page sent twice changes
//!   nothing, and a restore that stopped part-way resumes by beginning again.
//! - [`summary`] counts and checksums a table page by page, so both ends can be compared.
//! - [`finish`] checks the row counts, sets the `AUTOINCREMENT` counters and ends the restore.
//! - [`freeze`] stops an object's changes for the copy window: hosts refuse its requests while
//!   [`lock`] says so. Neither the freeze nor the restore mark is ever copied.
//!
//! Sealed secrets (connected apps' credentials, Slack tokens) are copied as they are, so the
//! target needs the same `CONNECTOR_KEY`. Sessions are copied too: people stay signed in.

use std::collections::BTreeSet;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::db::{Db, DbExt, SqlValue};
use crate::error::{ApiError, ApiResult};
use crate::params;

/// The version of what manifests and pages look like. Both ends must speak the same one.
pub const FORMAT: u32 = 1;
/// A page holds about this much row data (blobs and text by length), and always at least one row.
pub const PAGE_BYTES: i64 = 2 * 1024 * 1024;
/// The most rows in one page.
pub const PAGE_ROWS: i64 = 1000;
/// A summary page reads about this much row data.
pub const SUMMARY_BYTES: i64 = 8 * 1024 * 1024;
pub const SUMMARY_ROWS: i64 = 10_000;
/// The largest restore request a host accepts: a page of [`PAGE_BYTES`] can grow several times
/// over as JSON (base64 blobs, escaped text).
pub const MAX_RESTORE_BODY: usize = 32 * 1024 * 1024;

/// The hosted directory's object name.
pub const DIRECTORY_OBJECT: &str = "directory";

/// Tables this module keeps for itself. They're never copied, counted or compared.
const OWN_PREFIX: &str = "_dumbslab_";
const FROZEN_TABLE: &str = "_dumbslab_frozen";
const RESTORE_TABLE: &str = "_dumbslab_restore";
/// The tables SQLite keeps for a virtual table's own storage, by suffix (FTS5, FTS3/4, R*Tree).
/// The virtual table itself is copied through its columns instead.
const SHADOW_SUFFIXES: &[&str] = &["data", "idx", "content", "docsize", "config", "segments", "segdir", "stat", "node", "rowid", "parent"];

/// What an object holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// No tables at all: an address nobody set up, or an object never used.
    Empty,
    /// A workspace's data, in the object named after its first address.
    Workspace,
    /// An address a workspace moved to: only a pointer to its first address.
    Alias,
    /// The hosted directory of addresses.
    Directory,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Empty => "empty",
            Kind::Workspace => "workspace",
            Kind::Alias => "alias",
            Kind::Directory => "directory",
        }
    }
}

/// Which Durable Object class a backup name belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Directory,
    Workspace,
}

/// Where an object name lives on a deployment. Hosted: `directory` and `ws:<address>` (any address
/// that was ever valid, reserved words included). Single workspace: the object's own name.
pub fn target(name: &str, multi_tenant: bool, workspace_name: &str) -> Option<Target> {
    if !multi_tenant {
        return (name == workspace_name).then_some(Target::Workspace);
    }
    if name == DIRECTORY_OBJECT {
        return Some(Target::Directory);
    }
    let address = name.strip_prefix("ws:")?;
    let ok = (1..=63).contains(&address.len()) && address.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    ok.then_some(Target::Workspace)
}

/// The action a backup or restore route names: `/api/operator/backup/dump` → `dump`.
pub fn action(path: &str) -> Option<&'static str> {
    let rest = path.strip_prefix("/api/operator/").or_else(|| path.strip_prefix("/_internal/"))?;
    const ACTIONS: &[&str] = &[
        "backup/manifest",
        "backup/dump",
        "backup/summary",
        "backup/freeze",
        "backup/thaw",
        "restore/begin",
        "restore/page",
        "restore/finish",
        "restore/abort",
    ];
    ACTIONS.iter().find(|a| **a == rest).map(|a| a.split_once('/').map_or(*a, |(_, name)| name))
}

/// One object to copy, as the directory lists it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObjectRef {
    /// The Durable Object's name: `directory`, or `ws:<address>`.
    pub name: String,
    /// What it should hold. Workspaces that were reserved but never set up hold nothing.
    pub kind: Kind,
    /// Workspaces: `reserved`, `active` or `disabled`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Aliases: the first address of the workspace they point to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home: Option<String>,
}

/// Every object a hosted deployment holds data in, from its directory: the directory itself, each
/// workspace's home object (named after its first address) and each address a workspace moved to.
pub fn directory_objects(db: &dyn Db) -> ApiResult<Vec<ObjectRef>> {
    let mut out = vec![ObjectRef { name: DIRECTORY_OBJECT.into(), kind: Kind::Directory, status: None, home: None }];
    for r in db.query("SELECT slug, status FROM workspaces ORDER BY created_at, slug", &[])? {
        out.push(ObjectRef { name: format!("ws:{}", r.str("slug")), kind: Kind::Workspace, status: Some(r.str("status")), home: None });
    }
    for r in db.query("SELECT slug, home FROM addresses ORDER BY created_at, slug", &[])? {
        out.push(ObjectRef { name: format!("ws:{}", r.str("slug")), kind: Kind::Alias, status: None, home: Some(r.str("home")) });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Freezing

/// Whether an object takes requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lock {
    Open,
    /// Frozen for a copy: its data must not change until the copy is checked.
    Frozen,
    /// A restore into it hasn't finished: it holds part of its data.
    Restoring,
}

impl Lock {
    /// The answer for a request the object can't take, if any.
    pub fn refusal(self) -> Option<ApiError> {
        match self {
            Lock::Open => None,
            Lock::Frozen => {
                Some(ApiError::new(503, "moving", "DumbSlab is moving to new servers. It's paused for a few minutes; try again shortly."))
            }
            Lock::Restoring => Some(ApiError::new(503, "restoring", "This workspace is being restored. Try again in a few minutes.")),
        }
    }
}

/// Whether the object is frozen or holds an unfinished restore. Reading `sqlite_master` writes nothing.
pub fn lock(db: &dyn Db) -> ApiResult<Lock> {
    let rows = db.query("SELECT name FROM sqlite_master WHERE type = 'table' AND name IN (?, ?)", &params![FROZEN_TABLE, RESTORE_TABLE])?;
    let has = |t: &str| rows.iter().any(|r| r.str("name") == t);
    Ok(if has(RESTORE_TABLE) {
        Lock::Restoring
    } else if has(FROZEN_TABLE) {
        Lock::Frozen
    } else {
        Lock::Open
    })
}

/// Freezes the object until [`thaw`]. An object with no tables holds nothing to freeze and stays
/// without storage. Whether it's frozen now.
pub fn freeze(db: &dyn Db) -> ApiResult<bool> {
    if kind_of(&schema(db)?.tables)? == Kind::Empty {
        return Ok(false);
    }
    db.execute_batch(&format!("CREATE TABLE IF NOT EXISTS {FROZEN_TABLE} (frozen_at TEXT NOT NULL)"))?;
    if db.one(&format!("SELECT frozen_at FROM {FROZEN_TABLE}"), &[])?.is_none() {
        db.execute(&format!("INSERT INTO {FROZEN_TABLE} (frozen_at) VALUES (?)"), &params![crate::util::ts(chrono::Utc::now())])?;
    }
    Ok(true)
}

pub fn thaw(db: &dyn Db) -> ApiResult<()> {
    db.execute_batch(&format!("DROP TABLE IF EXISTS {FROZEN_TABLE}"))
}

// ---------------------------------------------------------------------------
// Values and checksums

/// One SQLite value in a page: `null`, an integer, text, `{"real": "1.5"}` or `{"blob": "<base64>"}`.
/// Reals travel as text so infinities and every bit survive.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Cell {
    Int(i64),
    Text(String),
    Real { real: String },
    Blob { blob: String },
    Null,
}

impl From<&SqlValue> for Cell {
    fn from(v: &SqlValue) -> Cell {
        match v {
            SqlValue::Null => Cell::Null,
            SqlValue::Integer(i) => Cell::Int(*i),
            SqlValue::Real(f) => Cell::Real { real: f.to_string() },
            SqlValue::Text(s) => Cell::Text(s.clone()),
            SqlValue::Blob(b) => Cell::Blob { blob: STANDARD.encode(b) },
        }
    }
}

impl Cell {
    pub fn to_value(&self) -> ApiResult<SqlValue> {
        Ok(match self {
            Cell::Null => SqlValue::Null,
            Cell::Int(i) => SqlValue::Integer(*i),
            Cell::Text(s) => SqlValue::Text(s.clone()),
            Cell::Real { real } => SqlValue::Real(real.parse().map_err(|_| ApiError::bad_request(format!("`{real}` isn't a number")))?),
            Cell::Blob { blob } => SqlValue::Blob(STANDARD.decode(blob).map_err(|_| ApiError::bad_request("a blob isn't valid base64"))?),
        })
    }
}

/// Rows and an order-independent checksum of them: the sum of each row's SHA-256 (its first 128
/// bits, wrapping). Pages add up to their table's, however the table was split.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Checksum {
    pub rows: i64,
    pub sum: u128,
}

impl Checksum {
    pub fn add_row(&mut self, values: &[SqlValue]) {
        let mut h = Sha256::new();
        for v in values {
            match v {
                SqlValue::Null => h.update([0u8]),
                SqlValue::Integer(i) => {
                    h.update([1u8]);
                    h.update(i.to_be_bytes());
                }
                SqlValue::Real(f) => {
                    h.update([2u8]);
                    h.update(f.to_bits().to_be_bytes());
                }
                SqlValue::Text(s) => {
                    h.update([3u8]);
                    h.update((s.len() as u64).to_be_bytes());
                    h.update(s.as_bytes());
                }
                SqlValue::Blob(b) => {
                    h.update([4u8]);
                    h.update((b.len() as u64).to_be_bytes());
                    h.update(b);
                }
            }
        }
        let digest = h.finalize();
        let mut first = [0u8; 16];
        first.copy_from_slice(&digest[..16]);
        self.rows += 1;
        self.sum = self.sum.wrapping_add(u128::from_be_bytes(first));
    }

    pub fn merge(&mut self, other: Checksum) {
        self.rows += other.rows;
        self.sum = self.sum.wrapping_add(other.sum);
    }

    pub fn hex(&self) -> String {
        format!("{:032x}", self.sum)
    }

    pub fn parse(rows: i64, hex: &str) -> ApiResult<Checksum> {
        let sum = u128::from_str_radix(hex, 16).map_err(|_| ApiError::bad_request("a checksum is 32 hex digits"))?;
        Ok(Checksum { rows, sum })
    }
}

// ---------------------------------------------------------------------------
// Schema

/// One table as pages carry it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Table {
    pub name: String,
    /// The columns of every row in its pages: `rowid` first when the table has a rowid but no
    /// `INTEGER PRIMARY KEY` naming it, then every column by name.
    pub columns: Vec<String>,
    /// The columns pages are ordered and continued by: the rowid (or the column naming it), or a
    /// `WITHOUT ROWID` table's primary key.
    pub key: Vec<String>,
    /// A virtual table (the full-text index): copied through its columns; SQLite rebuilds its storage.
    #[serde(default)]
    pub virtual_table: bool,
    /// Rows when the manifest was taken.
    pub rows: i64,
}

struct Schema {
    /// In restore order, with `rows` unset.
    tables: Vec<Table>,
    /// SHA-256 over every table's name and columns (name, type, NOT NULL, primary key), by name.
    fingerprint: String,
}

fn ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// A column in SQL: the rowid as itself, anything else quoted.
fn col(name: &str) -> String {
    if name == "rowid" { name.to_string() } else { ident(name) }
}

fn schema(db: &dyn Db) -> ApiResult<Schema> {
    let master = db.query("SELECT name, sql FROM sqlite_master WHERE type = 'table' ORDER BY name", &[])?;
    let all: Vec<(String, String)> = master.iter().map(|r| (r.str("name"), r.str("sql"))).collect();
    let is_virtual = |sql: &str| sql.trim_start().to_ascii_uppercase().starts_with("CREATE VIRTUAL TABLE");
    let virtuals: Vec<&str> = all.iter().filter(|(_, sql)| is_virtual(sql)).map(|(n, _)| n.as_str()).collect();
    // SQLite's own tables, Cloudflare's (`_cf_KV` holds key-value storage, which DumbSlab doesn't
    // keep), the local runtime's record of each object's name, and this module's own.
    let skipped = |name: &str| {
        name.starts_with("sqlite_")
            || name.starts_with("_cf_")
            || name.starts_with("__miniflare")
            || name.starts_with(OWN_PREFIX)
            || virtuals
                .iter()
                .any(|v| name.strip_prefix(v).and_then(|r| r.strip_prefix('_')).is_some_and(|suffix| SHADOW_SUFFIXES.contains(&suffix)))
    };
    let mut tables = vec![];
    let mut parents: Vec<Vec<String>> = vec![];
    let mut lines = vec![];
    for (name, sql) in all.iter().filter(|(n, _)| !skipped(n)) {
        let virtual_table = is_virtual(sql);
        let without_rowid =
            !virtual_table && sql.to_ascii_uppercase().split_whitespace().collect::<Vec<_>>().join(" ").contains("WITHOUT ROWID");
        let info = db.query(&format!("PRAGMA table_info({})", ident(name)), &[])?;
        let mut cols: Vec<(String, String, i64, i64)> =
            info.iter().map(|r| (r.str("name"), r.str("type").to_ascii_uppercase(), r.i64("notnull"), r.i64("pk"))).collect();
        cols.sort_by(|a, b| a.0.cmp(&b.0));
        let mut pk: Vec<&(String, String, i64, i64)> = cols.iter().filter(|c| c.3 > 0).collect();
        pk.sort_by_key(|c| c.3);
        let alias = (!virtual_table && !without_rowid && pk.len() == 1 && pk[0].1 == "INTEGER").then(|| pk[0].0.clone());
        let names: Vec<String> = cols.iter().map(|c| c.0.clone()).collect();
        let (columns, key) = match (&alias, without_rowid) {
            (Some(a), _) => (names.clone(), vec![a.clone()]),
            (None, true) => (names.clone(), pk.iter().map(|c| c.0.clone()).collect()),
            (None, false) => {
                if names.iter().any(|n| ["rowid", "oid", "_rowid_"].contains(&n.to_ascii_lowercase().as_str())) {
                    return Err(ApiError::internal(format!("table {name} has a column that hides its rowid; it can't be backed up")));
                }
                (std::iter::once("rowid".to_string()).chain(names.iter().cloned()).collect(), vec!["rowid".to_string()])
            }
        };
        let refs = if virtual_table {
            vec![]
        } else {
            db.query(&format!("PRAGMA foreign_key_list({})", ident(name)), &[])?.iter().map(|r| r.str("table")).collect()
        };
        let described: Vec<String> = cols.iter().map(|(n, t, nn, pk)| format!("{n}:{t}:{nn}:{pk}")).collect();
        lines.push(format!("{name}|{virtual_table}|{without_rowid}|{}", described.join(";")));
        tables.push(Table { name: name.clone(), columns, key, virtual_table, rows: 0 });
        parents.push(refs);
    }
    let fingerprint = hex::encode(Sha256::digest(lines.join("\n").as_bytes()));
    Ok(Schema { tables: restore_order(tables, parents), fingerprint })
}

/// Orders tables so each comes after the tables it refers to (by name otherwise). A cycle is
/// broken by name; rows within one page may refer to each other in any order.
fn restore_order(tables: Vec<Table>, parents: Vec<Vec<String>>) -> Vec<Table> {
    let names: BTreeSet<String> = tables.iter().map(|t| t.name.clone()).collect();
    let mut waiting: Vec<(Table, BTreeSet<String>)> = tables
        .into_iter()
        .zip(parents)
        .map(|(t, p)| {
            let deps = p.into_iter().filter(|d| *d != t.name && names.contains(d)).collect();
            (t, deps)
        })
        .collect();
    let mut done: BTreeSet<String> = BTreeSet::new();
    let mut out = vec![];
    while !waiting.is_empty() {
        let i = waiting.iter().position(|(_, deps)| deps.is_subset(&done)).unwrap_or(0);
        let (t, _) = waiting.remove(i);
        done.insert(t.name.clone());
        out.push(t);
    }
    out
}

fn kind_of(tables: &[Table]) -> ApiResult<Kind> {
    let has = |n: &str| tables.iter().any(|t| t.name == n);
    if tables.is_empty() {
        Ok(Kind::Empty)
    } else if has("meta") {
        Ok(Kind::Workspace)
    } else if has("workspaces") && has("addresses") {
        Ok(Kind::Directory)
    } else if has("alias") {
        Ok(Kind::Alias)
    } else {
        let names: Vec<&str> = tables.iter().map(|t| t.name.as_str()).collect();
        Err(ApiError::internal(format!("this object holds tables backups don't know: {}", names.join(", "))))
    }
}

fn schema_version(db: &dyn Db, kind: Kind) -> ApiResult<Option<i64>> {
    if kind != Kind::Workspace {
        return Ok(None);
    }
    Ok(db.one("SELECT value FROM meta WHERE key = 'schema_version'", &[])?.and_then(|r| r.opt_i64("value")))
}

fn has_table(db: &dyn Db, name: &str) -> ApiResult<bool> {
    Ok(db.one("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", &params![name])?.is_some())
}

// ---------------------------------------------------------------------------
// Backing up

/// An `AUTOINCREMENT` counter: the highest id the table ever handed out.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Sequence {
    pub name: String,
    pub seq: i64,
}

/// What an object holds, and how to restore it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u32,
    pub kind: Kind,
    /// Workspaces: the schema migration they're at (see `db::MIGRATIONS`).
    pub schema_version: Option<i64>,
    /// A digest of every table's columns. Both ends must hold the same schema.
    pub schema: String,
    /// In restore order: each table after the tables it refers to.
    pub tables: Vec<Table>,
    pub sequences: Vec<Sequence>,
    /// Whether the object was frozen (see [`freeze`]), so its data won't change during the copy.
    pub frozen: bool,
}

pub fn manifest(db: &dyn Db) -> ApiResult<Manifest> {
    let mut s = schema(db)?;
    let kind = kind_of(&s.tables)?;
    for t in &mut s.tables {
        t.rows = db.scalar_i64(&format!("SELECT COUNT(*) FROM {}", ident(&t.name)), &[])?;
    }
    let names: BTreeSet<&str> = s.tables.iter().map(|t| t.name.as_str()).collect();
    let sequences = if has_table(db, "sqlite_sequence")? {
        db.query("SELECT name, seq FROM sqlite_sequence ORDER BY name", &[])?
            .iter()
            .map(|r| Sequence { name: r.str("name"), seq: r.i64("seq") })
            .filter(|q| names.contains(q.name.as_str()))
            .collect()
    } else {
        vec![]
    };
    Ok(Manifest {
        format: FORMAT,
        kind,
        schema_version: schema_version(db, kind)?,
        schema: if kind == Kind::Empty { String::new() } else { s.fingerprint },
        tables: s.tables,
        sequences,
        frozen: lock(db)? == Lock::Frozen,
    })
}

/// Which page of a table to read: the first, or the one after a page's `next`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageRequest {
    pub table: String,
    #[serde(default)]
    pub after: Option<Vec<Cell>>,
}

/// One page of a table's rows, in key order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    pub table: String,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Cell>>,
    /// The rows in this page and their checksum (see [`Checksum`]), so the target can tell the page
    /// arrived whole.
    pub count: i64,
    pub checksum: String,
    /// The key of the page's last row, to read the next page from; `null` after the last page.
    pub next: Option<Vec<Cell>>,
}

/// A page's count and checksum, without its rows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Summary {
    pub table: String,
    pub count: i64,
    pub checksum: String,
    pub next: Option<Vec<Cell>>,
}

fn find_table(s: &Schema, name: &str) -> ApiResult<Table> {
    s.tables.iter().find(|t| t.name == name).cloned().ok_or_else(|| ApiError::not_found(format!("a table named {name}")))
}

/// Rows read by [`scan`], and the key to continue from if any are left.
type Scanned = (Vec<Vec<SqlValue>>, Option<Vec<Cell>>);

/// Reads the rows after `after` in key order, up to about `max_bytes` (at least one row) and
/// `max_rows`.
fn scan(db: &dyn Db, t: &Table, after: Option<&[Cell]>, max_bytes: i64, max_rows: i64) -> ApiResult<Scanned> {
    let key: Vec<String> = t.key.iter().map(|k| col(k)).collect();
    let tuple = |items: &[String]| if items.len() == 1 { items[0].clone() } else { format!("({})", items.join(", ")) };
    let marks: Vec<String> = t.key.iter().map(|_| "?".to_string()).collect();
    let (from, mut params) = match after {
        None => ("1 = 1".to_string(), vec![]),
        Some(a) if a.len() == t.key.len() => {
            (format!("{} > {}", tuple(&key), tuple(&marks)), a.iter().map(Cell::to_value).collect::<ApiResult<Vec<_>>>()?)
        }
        Some(_) => return Err(ApiError::bad_request(format!("`after` must hold {} value(s): {}", t.key.len(), t.key.join(", ")))),
    };
    let sizes: Vec<String> = t.columns.iter().filter(|c| *c != "rowid").map(|c| format!("COALESCE(length({}), 0)", ident(c))).collect();
    let size = if sizes.is_empty() { "0".to_string() } else { sizes.join(" + ") };
    let table = ident(&t.name);
    let order = key.join(", ");
    let mut candidate_params = params.clone();
    candidate_params.push(SqlValue::Integer(max_rows + 1));
    let candidates = db.query(
        &format!("SELECT {order}, {size} + {} AS backup_bytes FROM {table} WHERE {from} ORDER BY {order} LIMIT ?", 16 * t.columns.len()),
        &candidate_params,
    )?;
    let (mut taken, mut bytes) = (0usize, 0i64);
    for r in &candidates {
        let b = r.i64("backup_bytes");
        if taken as i64 == max_rows || (taken > 0 && bytes + b > max_bytes) {
            break;
        }
        bytes += b;
        taken += 1;
    }
    if taken == 0 {
        return Ok((vec![], None));
    }
    let last: Vec<SqlValue> = candidates[taken - 1].values()[..t.key.len()].to_vec();
    let more = taken < candidates.len();
    params.extend(last.iter().cloned());
    let columns: Vec<String> = t.columns.iter().map(|c| col(c)).collect();
    let rows = db.query(
        &format!("SELECT {} FROM {table} WHERE {from} AND {} <= {} ORDER BY {order}", columns.join(", "), tuple(&key), tuple(&marks)),
        &params,
    )?;
    let next = more.then(|| last.iter().map(Cell::from).collect());
    Ok((rows.into_iter().map(|r| r.into_values()).collect(), next))
}

/// Reads one page of a table.
pub fn dump(db: &dyn Db, req: &PageRequest) -> ApiResult<Page> {
    let t = find_table(&schema(db)?, &req.table)?;
    let (rows, next) = scan(db, &t, req.after.as_deref(), PAGE_BYTES, PAGE_ROWS)?;
    let mut sum = Checksum::default();
    for r in &rows {
        sum.add_row(r);
    }
    Ok(Page {
        table: t.name,
        columns: t.columns,
        rows: rows.iter().map(|r| r.iter().map(Cell::from).collect()).collect(),
        count: sum.rows,
        checksum: sum.hex(),
        next,
    })
}

/// Counts and checksums one page of a table, for comparing both ends.
pub fn summary(db: &dyn Db, req: &PageRequest) -> ApiResult<Summary> {
    let t = find_table(&schema(db)?, &req.table)?;
    let (rows, next) = scan(db, &t, req.after.as_deref(), SUMMARY_BYTES, SUMMARY_ROWS)?;
    let mut sum = Checksum::default();
    for r in &rows {
        sum.add_row(r);
    }
    Ok(Summary { table: t.name, count: sum.rows, checksum: sum.hex(), next })
}

// ---------------------------------------------------------------------------
// Restoring

/// Names a restore: the source's kind and schema. Beginning again with the same one resumes it.
fn restore_id(m: &Manifest) -> String {
    let tables: Vec<(&str, &[String])> = m.tables.iter().map(|t| (t.name.as_str(), t.columns.as_slice())).collect();
    let described = json!({ "format": m.format, "kind": m.kind, "schema_version": m.schema_version, "schema": m.schema, "tables": tables });
    hex::encode(Sha256::digest(described.to_string().as_bytes()))
}

fn restoring(db: &dyn Db) -> ApiResult<Option<String>> {
    if !has_table(db, RESTORE_TABLE)? {
        return Ok(None);
    }
    Ok(db.one(&format!("SELECT restore_id FROM {RESTORE_TABLE}"), &[])?.map(|r| r.str("restore_id")))
}

fn other_restore() -> ApiError {
    ApiError::new(409, "restore_conflict", "A restore from another source is under way here. Abort it first (restore/abort).")
}

/// Whether the object holds data of its own: a row in any table but `meta`, which a new
/// workspace's schema fills in.
fn holds_data(db: &dyn Db, tables: &[Table]) -> ApiResult<bool> {
    for t in tables.iter().filter(|t| t.name != "meta") {
        if db.one(&format!("SELECT 1 AS found FROM {} LIMIT 1", ident(&t.name)), &[])?.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn create_schema(db: &dyn Db, kind: Kind) -> ApiResult<()> {
    match kind {
        Kind::Workspace => crate::migrate(db),
        Kind::Directory => crate::tenancy::directory_migrate(db),
        Kind::Alias => db.execute_batch(crate::tenancy::ALIAS_SCHEMA),
        Kind::Empty => Ok(()),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Begun {
    /// An unfinished restore from the same source was already under way; pages already written stay.
    pub resumed: bool,
}

/// Starts restoring `source` into this object. Only an object that holds no data qualifies (a new
/// schema without rows is fine), or one whose restore from the same source stopped part-way.
/// `allowed`: what this kind of object can hold. Refuses a source whose schema version or tables
/// differ from this code's.
pub fn begin(db: &dyn Db, allowed: &[Kind], source: &Manifest) -> ApiResult<Begun> {
    if source.format != FORMAT {
        return Err(ApiError::bad_request(format!("this server reads backup format {FORMAT}, not {}", source.format)));
    }
    if source.kind == Kind::Empty {
        return Err(ApiError::bad_request("the source holds nothing to restore"));
    }
    if !allowed.contains(&source.kind) {
        return Err(ApiError::bad_request(format!("a {} can't be restored into this object", source.kind.as_str())));
    }
    let id = restore_id(source);
    match restoring(db)? {
        Some(current) if current == id => return Ok(Begun { resumed: true }),
        Some(_) => return Err(other_restore()),
        None => {}
    }
    let mut s = schema(db)?;
    match kind_of(&s.tables)? {
        Kind::Empty => {
            create_schema(db, source.kind)?;
            s = schema(db)?;
        }
        k if k == source.kind => {
            if holds_data(db, &s.tables)? {
                return Err(not_empty());
            }
        }
        _ => return Err(not_empty()),
    }
    let version = schema_version(db, source.kind)?;
    if version != source.schema_version || s.fingerprint != source.schema {
        return Err(ApiError::new(
            409,
            "schema_mismatch",
            "The source's schema differs from this server's. Deploy the same commit on both, then try again.",
        )
        .with_details(json!({
            "source": { "schema_version": source.schema_version, "schema": source.schema },
            "target": { "schema_version": version, "schema": s.fingerprint },
        })));
    }
    db.execute_batch(&format!("CREATE TABLE {RESTORE_TABLE} (restore_id TEXT NOT NULL, started_at TEXT NOT NULL)"))?;
    db.execute(
        &format!("INSERT INTO {RESTORE_TABLE} (restore_id, started_at) VALUES (?, ?)"),
        &params![id, crate::util::ts(chrono::Utc::now())],
    )?;
    Ok(Begun { resumed: false })
}

fn not_empty() -> ApiError {
    ApiError::new(409, "not_empty", "This object already holds data. Restores only go into an object that holds none.")
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Restored {
    pub rows: i64,
}

/// Writes one page into an object whose restore has begun. Rows already there stay as they are,
/// so the same page can be sent again safely.
pub fn restore(db: &dyn Db, page: &Page) -> ApiResult<Restored> {
    if restoring(db)?.is_none() {
        return Err(ApiError::new(409, "not_restoring", "No restore is under way here. Begin one first (restore/begin)."));
    }
    let t = find_table(&schema(db)?, &page.table)?;
    if page.columns != t.columns {
        return Err(ApiError::new(409, "schema_mismatch", format!("table {} has other columns here", t.name)));
    }
    let mut rows = Vec::with_capacity(page.rows.len());
    let mut sum = Checksum::default();
    for r in &page.rows {
        if r.len() != t.columns.len() {
            return Err(ApiError::bad_request(format!("each row of {} has {} values", t.name, t.columns.len())));
        }
        let values = r.iter().map(Cell::to_value).collect::<ApiResult<Vec<_>>>()?;
        sum.add_row(&values);
        rows.push(values);
    }
    if Checksum::parse(page.count, &page.checksum)? != sum {
        return Err(ApiError::bad_request("the page doesn't match its checksum; it was damaged on the way. Send it again."));
    }
    // A table's rows may refer to rows later in the same page (a topic moved under a newer one).
    db.execute_batch("PRAGMA defer_foreign_keys = ON")?;
    let columns: Vec<String> = t.columns.iter().map(|c| col(c)).collect();
    let marks: Vec<&str> = t.columns.iter().map(|_| "?").collect();
    let table = ident(&t.name);
    let insert = format!("INSERT INTO {table} ({}) VALUES ({})", columns.join(", "), marks.join(", "));
    for values in &rows {
        if t.virtual_table {
            // Virtual tables take no ON CONFLICT clause; their rows refer to nothing.
            db.execute(&format!("DELETE FROM {table} WHERE rowid = ?"), &values[..1])?;
            db.execute(&insert, values)?;
        } else {
            db.execute(&format!("{insert} ON CONFLICT DO NOTHING"), values)?;
        }
    }
    Ok(Restored { rows: rows.len() as i64 })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finished {
    pub tables: usize,
    pub rows: i64,
    /// The restore had already finished: nothing changed.
    pub already_finished: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestRequest {
    pub manifest: Manifest,
}

/// Ends a restore once every table holds as many rows as the source's manifest says: sets the
/// `AUTOINCREMENT` counters and lifts the restore mark, so the object takes requests. Compare the
/// checksums (see [`summary`]) before finishing. Finishing again changes nothing.
pub fn finish(db: &dyn Db, source: &Manifest) -> ApiResult<Finished> {
    let id = restore_id(source);
    let current = restoring(db)?;
    if current.as_ref().is_some_and(|c| *c != id) {
        return Err(other_restore());
    }
    let s = schema(db)?;
    if kind_of(&s.tables)? != source.kind || s.fingerprint != source.schema {
        return Err(ApiError::new(409, "schema_mismatch", "this object's schema differs from the source's"));
    }
    let mut differ = vec![];
    let mut rows = 0;
    for t in &source.tables {
        let here = db.scalar_i64(&format!("SELECT COUNT(*) FROM {}", ident(&t.name)), &[])?;
        rows += here;
        if here != t.rows {
            differ.push(json!({ "table": t.name, "source": t.rows, "target": here }));
        }
    }
    if !differ.is_empty() {
        return Err(ApiError::new(409, "verify_failed", "Some tables hold a different number of rows than the source.")
            .with_details(json!({ "tables": differ })));
    }
    if current.is_none() {
        return Ok(Finished { tables: source.tables.len(), rows, already_finished: true });
    }
    for q in &source.sequences {
        if db.execute("UPDATE sqlite_sequence SET seq = ? WHERE name = ?", &params![q.seq, q.name.clone()])? == 0 {
            db.execute("INSERT INTO sqlite_sequence (name, seq) VALUES (?, ?)", &params![q.name.clone(), q.seq])?;
        }
    }
    db.execute_batch(&format!("DROP TABLE {RESTORE_TABLE}"))?;
    Ok(Finished { tables: source.tables.len(), rows, already_finished: false })
}

/// Wipes an object whose restore hasn't finished, so it can start over. Refuses any other object.
pub fn abort(db: &dyn Db) -> ApiResult<()> {
    if restoring(db)?.is_none() {
        return Err(ApiError::new(409, "not_restoring", "Only an object whose restore hasn't finished can be wiped this way."));
    }
    db.execute_batch("PRAGMA defer_foreign_keys = ON")?;
    // Tables that refer to others first; dropping a virtual table drops its own storage.
    for t in schema(db)?.tables.iter().rev() {
        db.execute_batch(&format!("DROP TABLE {}", ident(&t.name)))?;
    }
    if has_table(db, "sqlite_sequence")? {
        db.execute("DELETE FROM sqlite_sequence", &[])?;
    }
    db.execute_batch(&format!("DROP TABLE IF EXISTS {RESTORE_TABLE}; DROP TABLE IF EXISTS {FROZEN_TABLE}"))
}

/// Runs a backup or restore action (see [`action`]) on an object's database. `allowed`: what this
/// kind of object can hold. The host runs it in one transaction and rolls back on an error.
pub fn handle(db: &dyn Db, action: &str, body: &[u8], allowed: &[Kind]) -> ApiResult<Value> {
    fn input<T: for<'de> Deserialize<'de>>(body: &[u8]) -> ApiResult<T> {
        serde_json::from_slice(body).map_err(|e| ApiError::bad_request(format!("invalid request: {e}")))
    }
    fn out<T: Serialize>(v: ApiResult<T>) -> ApiResult<Value> {
        serde_json::to_value(v?).map_err(|e| ApiError::internal(e.to_string()))
    }
    match action {
        "objects" => {
            if !allowed.contains(&Kind::Directory) {
                return Err(ApiError::not_found("a directory here"));
            }
            Ok(json!({ "objects": directory_objects(db)? }))
        }
        "manifest" => out(manifest(db)),
        "dump" => out(dump(db, &input::<PageRequest>(body)?)),
        "summary" => out(summary(db, &input::<PageRequest>(body)?)),
        "freeze" => Ok(json!({ "frozen": freeze(db)? })),
        "thaw" => thaw(db).map(|_| json!({ "frozen": false })),
        "begin" => out(begin(db, allowed, &input::<ManifestRequest>(body)?.manifest)),
        "page" => out(restore(db, &input::<Page>(body)?)),
        "finish" => out(finish(db, &input::<ManifestRequest>(body)?.manifest)),
        "abort" => abort(db).map(|_| json!({ "ok": true })),
        _ => Err(ApiError::not_found("a backup action by that name")),
    }
}

// ---------------------------------------------------------------------------
// Encrypted backup files

/// How an encrypted backup file starts: these bytes, then a random 16-byte salt.
pub const FILE_MAGIC: &[u8; 8] = b"DSLABBK1";
pub const FILE_HEADER_LEN: usize = FILE_MAGIC.len() + 16;

/// Encrypts and decrypts one backup file's records with a key derived from a passphrase
/// (Argon2id over the file's salt). Each record is AES-256-GCM sealed with a random nonce and
/// bound to the file's header and its position, so records can't be swapped, dropped or moved
/// between files without the file failing to open.
pub struct FileKey {
    cipher: Aes256Gcm,
    header: Vec<u8>,
}

impl FileKey {
    /// A key for a new file, and the header to write first.
    pub fn create(passphrase: &str) -> ApiResult<(FileKey, Vec<u8>)> {
        let salt: [u8; 16] = crate::util::random_bytes();
        let mut header = FILE_MAGIC.to_vec();
        header.extend_from_slice(&salt);
        Ok((FileKey::open_header(passphrase, &header)?, header))
    }

    /// The key for an existing file, from its header.
    pub fn open_header(passphrase: &str, header: &[u8]) -> ApiResult<FileKey> {
        if header.len() != FILE_HEADER_LEN || !header.starts_with(FILE_MAGIC) {
            return Err(ApiError::bad_request("this isn't a DumbSlab backup file"));
        }
        if passphrase.chars().count() < 12 {
            return Err(ApiError::bad_request("the backup passphrase must be at least 12 characters"));
        }
        let mut key = [0u8; 32];
        argon2::Argon2::default()
            .hash_password_into(passphrase.as_bytes(), &header[FILE_MAGIC.len()..], &mut key)
            .map_err(|e| ApiError::internal(format!("couldn't derive the backup key: {e}")))?;
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| ApiError::internal("bad key length"))?;
        Ok(FileKey { cipher, header: header.to_vec() })
    }

    fn aad(&self, index: u64) -> Vec<u8> {
        let mut aad = self.header.clone();
        aad.extend_from_slice(&index.to_be_bytes());
        aad
    }

    /// Seals record number `index`: its nonce, then the ciphertext.
    pub fn seal(&self, index: u64, plain: &[u8]) -> ApiResult<Vec<u8>> {
        let nonce: [u8; 12] = crate::util::random_bytes();
        let aad = self.aad(index);
        let sealed = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plain, aad: &aad })
            .map_err(|_| ApiError::internal("couldn't encrypt the backup"))?;
        let mut out = nonce.to_vec();
        out.extend(sealed);
        Ok(out)
    }

    /// Opens record number `index`, or fails for a wrong passphrase or a damaged file.
    pub fn open(&self, index: u64, sealed: &[u8]) -> ApiResult<Vec<u8>> {
        if sealed.len() < 12 + 16 {
            return Err(ApiError::bad_request("the backup file is damaged"));
        }
        let (nonce, body) = sealed.split_at(12);
        let aad = self.aad(index);
        self.cipher
            .decrypt(Nonce::from_slice(nonce), Payload { msg: body, aad: &aad })
            .map_err(|_| ApiError::bad_request("the backup file can't be opened: wrong passphrase, or the file is damaged"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cells_round_trip_every_sqlite_value() {
        let values = vec![
            SqlValue::Null,
            SqlValue::Integer(i64::MIN),
            SqlValue::Integer(i64::MAX),
            SqlValue::Real(1.5),
            SqlValue::Real(-0.0),
            SqlValue::Real(f64::INFINITY),
            SqlValue::Real(0.1 + 0.2),
            SqlValue::Text("naïve \"quoted\" \u{1F600}".into()),
            SqlValue::Text("42".into()),
            SqlValue::Blob(vec![0, 255, 1, 2, 3]),
            SqlValue::Blob(vec![]),
        ];
        let cells: Vec<Cell> = values.iter().map(Cell::from).collect();
        let wire = serde_json::to_string(&cells).unwrap();
        let back: Vec<Cell> = serde_json::from_str(&wire).unwrap();
        let decoded: Vec<SqlValue> = back.iter().map(|c| c.to_value().unwrap()).collect();
        for (a, b) in values.iter().zip(&decoded) {
            match (a, b) {
                (SqlValue::Real(x), SqlValue::Real(y)) => assert_eq!(x.to_bits(), y.to_bits()),
                _ => assert_eq!(a, b),
            }
        }
        assert!(wire.contains("{\"blob\":\"AP8BAgM=\"}") && wire.contains("\"42\""), "{wire}");
    }

    #[test]
    fn checksums_add_up_however_a_table_is_split() {
        let rows: Vec<Vec<SqlValue>> = (0..10).map(|i| vec![SqlValue::Integer(i), SqlValue::Text(format!("row {i}"))]).collect();
        let mut whole = Checksum::default();
        rows.iter().for_each(|r| whole.add_row(r));
        let (mut a, mut b) = (Checksum::default(), Checksum::default());
        rows[..3].iter().for_each(|r| a.add_row(r));
        rows[3..].iter().for_each(|r| b.add_row(r));
        a.merge(b);
        assert_eq!(a, whole);
        assert_eq!(Checksum::parse(10, &whole.hex()).unwrap(), whole);
        // Values are typed: the integer 1 and the text "1" differ, as do a blob and text.
        let (mut int, mut text) = (Checksum::default(), Checksum::default());
        int.add_row(&[SqlValue::Integer(1)]);
        text.add_row(&[SqlValue::Text("1".into())]);
        assert_ne!(int, text);
        let (mut blob, mut text) = (Checksum::default(), Checksum::default());
        blob.add_row(&[SqlValue::Blob(b"ab".to_vec())]);
        text.add_row(&[SqlValue::Text("ab".into())]);
        assert_ne!(blob, text);
    }

    #[test]
    fn object_names_map_to_their_class() {
        assert_eq!(target("directory", true, "main"), Some(Target::Directory));
        assert_eq!(target("ws:acme", true, "main"), Some(Target::Workspace));
        // Reserved words were once valid addresses; their data must still copy.
        assert_eq!(target("ws:docs", true, "main"), Some(Target::Workspace));
        for bad in ["ws:", "ws:Acme", "ws:a.b", "acme", "ws:a/b", "main"] {
            assert_eq!(target(bad, true, "main"), None, "{bad}");
        }
        assert_eq!(target("main", false, "main"), Some(Target::Workspace));
        assert_eq!(target("directory", false, "main"), None);
        assert_eq!(target("ws:acme", false, "main"), None);
    }

    #[test]
    fn routes_name_their_action() {
        assert_eq!(action("/api/operator/backup/dump"), Some("dump"));
        assert_eq!(action("/_internal/restore/page"), Some("page"));
        assert_eq!(action("/api/operator/restore/abort"), Some("abort"));
        assert_eq!(action("/api/operator/backup/begin"), None);
        assert_eq!(action("/api/operator/restore/dump"), None);
        assert_eq!(action("/api/operator/workspaces"), None);
    }

    #[test]
    fn tables_restore_after_the_tables_they_refer_to() {
        let t = |name: &str| Table { name: name.into(), columns: vec![], key: vec![], virtual_table: false, rows: 0 };
        let tables = vec![t("comments"), t("posts"), t("topics"), t("users")];
        let parents = vec![
            vec!["posts".into(), "users".into(), "comments".into()],
            vec!["users".into()],
            vec!["topics".into(), "users".into()],
            vec![],
        ];
        let names: Vec<String> = restore_order(tables, parents).into_iter().map(|t| t.name).collect();
        assert_eq!(names, ["users", "posts", "comments", "topics"].map(String::from));
        // A cycle still yields every table once.
        let names: Vec<String> =
            restore_order(vec![t("a"), t("b")], vec![vec!["b".into()], vec!["a".into()]]).into_iter().map(|t| t.name).collect();
        assert_eq!(names, ["a", "b"].map(String::from));
    }

    #[test]
    fn backup_files_open_only_with_their_passphrase_in_order() {
        let (key, header) = FileKey::create("correct horse battery").unwrap();
        let first = key.seal(0, b"first record").unwrap();
        let second = key.seal(1, b"second record").unwrap();
        let reader = FileKey::open_header("correct horse battery", &header).unwrap();
        assert_eq!(reader.open(0, &first).unwrap(), b"first record");
        assert_eq!(reader.open(1, &second).unwrap(), b"second record");
        assert!(reader.open(0, &second).is_err(), "records can't be reordered");
        let wrong = FileKey::open_header("battery staple horse", &header).unwrap();
        assert!(wrong.open(0, &first).is_err(), "a wrong passphrase opens nothing");
        let mut tampered = first.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(reader.open(0, &tampered).is_err(), "a changed byte is caught");
        let (_, other_header) = FileKey::create("correct horse battery").unwrap();
        let other = FileKey::open_header("correct horse battery", &other_header).unwrap();
        assert!(other.open(0, &first).is_err(), "records are bound to their file");
        assert!(FileKey::create("short").is_err());
        assert!(FileKey::open_header("correct horse battery", b"not a backup file at all").is_err());
    }
}
