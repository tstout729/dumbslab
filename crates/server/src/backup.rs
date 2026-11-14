//! `dumbslab backup`: copies every object's data from one deployment to another through their
//! operator APIs (see `dumbslab_core::backup` and docs/cloudflare.md), and checks the copy table by
//! table. Rows stream from one end to the other a page at a time; nothing touches the disk unless
//! an encrypted backup file is asked for.
//!
//! Either end can also be a native server's database file, which holds one workspace, or a folder
//! holding one SQLite file per object, laid out like a hosted deployment.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use dumbslab_core::backup::{
    self, Begun, Checksum, FileKey, Finished, Kind, Manifest, ObjectRef, Page, PageRequest, Restored, Summary, Target,
};
use dumbslab_core::{ApiError, ApiResult, Db};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::store::{Sqlite, Store};

/// What a deployment says it holds (`GET /api/operator/backup/objects`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Listing {
    pub format: u32,
    pub version: String,
    pub git_sha: String,
    pub multi_tenant: bool,
    pub objects: Vec<ObjectRef>,
}

/// Why a call failed: the other end refused (an API error), or it couldn't be reached.
#[derive(Debug, Clone)]
pub enum CallError {
    Api { status: u16, code: String, message: String, details: Value },
    Transport(String),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Api { status, code, message, details } if details.is_null() => write!(f, "{message} ({code}, {status})"),
            CallError::Api { status, code, message, details } => write!(f, "{message} ({code}, {status}): {details}"),
            CallError::Transport(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CallError {}

impl CallError {
    fn code(&self) -> Option<&str> {
        match self {
            CallError::Api { code, .. } => Some(code),
            CallError::Transport(_) => None,
        }
    }
}

/// One end of a copy.
pub enum Endpoint {
    /// A deployment's operator API, by its root URL (or workers.dev address).
    Http { base: String, token: String, client: reqwest::Client },
    /// A native server's database: one workspace, listed as `name`.
    Local { store: Arc<Store>, name: String },
    /// A hosted deployment kept as SQLite files in a folder, one per object (`directory.db`,
    /// `ws:acme.db`, …), with the operator API's actions run on them directly. An object's file is
    /// made, holding nothing, the first time it's named.
    Folder { root: PathBuf, objects: Arc<std::sync::Mutex<BTreeMap<String, rusqlite::Connection>>> },
}

fn api_error(e: ApiError) -> CallError {
    CallError::Api {
        status: e.status,
        code: e.code.to_string(),
        message: e.message.clone(),
        details: e.to_json()["error"]["details"].clone(),
    }
}

/// Runs `f` on one object of a folder deployment, in a transaction. The directory's schema is
/// made when it's first opened, as the hosted Directory object does on its first request.
fn in_folder(
    root: &Path,
    objects: &std::sync::Mutex<BTreeMap<String, rusqlite::Connection>>,
    object: &str,
    f: impl FnOnce(&dyn Db) -> ApiResult<Value>,
) -> Result<Value, CallError> {
    let transport = |e: rusqlite::Error| CallError::Transport(e.to_string());
    let mut open = objects.lock().unwrap_or_else(|e| e.into_inner());
    if !open.contains_key(object) {
        let conn = rusqlite::Connection::open(root.join(format!("{object}.db"))).map_err(transport)?;
        conn.execute_batch("PRAGMA foreign_keys = ON").map_err(transport)?;
        if object == backup::DIRECTORY_OBJECT {
            dumbslab_core::tenancy::directory_migrate(&Sqlite(&conn)).map_err(api_error)?;
        }
        open.insert(object.to_string(), conn);
    }
    let conn = &open[object];
    conn.execute_batch("BEGIN IMMEDIATE").map_err(transport)?;
    let result = f(&Sqlite(conn));
    conn.execute_batch(if result.is_ok() { "COMMIT" } else { "ROLLBACK" }).map_err(transport)?;
    result.map_err(api_error)
}

/// Tries per call before giving up on an unreachable server (every call can safely run twice).
const ATTEMPTS: u32 = 5;

impl Endpoint {
    /// A deployment at `base`, with its operator token. Plain HTTP only reaches this machine.
    pub fn http(base: &str, token: String) -> anyhow::Result<Endpoint> {
        let base = base.trim_end_matches('/').to_string();
        let url = reqwest::Url::parse(&base).with_context(|| format!("{base} isn't a URL"))?;
        let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        if url.scheme() != "https" && !(url.scheme() == "http" && local) {
            bail!("{base}: use https (the operator token must not cross the network in the clear)");
        }
        if token.trim().is_empty() {
            bail!("the operator token for {base} is empty");
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .user_agent(concat!("dumbslab-backup/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Endpoint::Http { base, token: token.trim().to_string(), client })
    }

    pub fn local(store: Store, name: &str) -> Endpoint {
        Endpoint::Local { store: Arc::new(store), name: name.to_string() }
    }

    /// A folder deployment (see [`Endpoint::Folder`]), made if it doesn't exist.
    pub fn folder(root: &Path) -> anyhow::Result<Endpoint> {
        std::fs::create_dir_all(root).with_context(|| format!("creating {}", root.display()))?;
        Ok(Endpoint::Folder { root: root.to_path_buf(), objects: Arc::default() })
    }

    /// For messages: the URL or "a local database", never a token.
    pub fn label(&self) -> String {
        match self {
            Endpoint::Http { base, .. } => base.clone(),
            Endpoint::Local { .. } => "the local database".into(),
            Endpoint::Folder { root, .. } => root.display().to_string(),
        }
    }

    pub async fn objects(&self) -> anyhow::Result<Listing> {
        match self {
            Endpoint::Http { base, token, client } => {
                let url = format!("{base}/api/operator/backup/objects");
                let reply = retry(|| client.get(&url).bearer_auth(token).send()).await.map_err(|e| anyhow!("{}: {e}", self.label()))?;
                Ok(serde_json::from_value(reply)?)
            }
            Endpoint::Local { name, .. } => Ok(Listing {
                format: backup::FORMAT,
                version: dumbslab_core::VERSION.into(),
                git_sha: dumbslab_core::GIT_SHA.into(),
                multi_tenant: false,
                objects: vec![ObjectRef { name: name.clone(), kind: Kind::Workspace, status: None, home: None }],
            }),
            Endpoint::Folder { root, objects } => {
                let listed =
                    in_folder(root, objects, backup::DIRECTORY_OBJECT, |db| backup::handle(db, "objects", b"", &[Kind::Directory]))
                        .map_err(|e| anyhow!("{}: {e}", self.label()))?;
                Ok(Listing {
                    format: backup::FORMAT,
                    version: dumbslab_core::VERSION.into(),
                    git_sha: dumbslab_core::GIT_SHA.into(),
                    multi_tenant: true,
                    objects: serde_json::from_value(listed["objects"].clone())?,
                })
            }
        }
    }

    /// Runs a backup or restore action (`backup/dump`, `restore/page`, …) on one object.
    pub async fn call<T: DeserializeOwned>(&self, action: &str, object: &str, body: &impl Serialize) -> Result<T, CallError> {
        let body = serde_json::to_vec(body).map_err(|e| CallError::Transport(e.to_string()))?;
        let reply = match self {
            Endpoint::Http { base, token, client } => {
                let url = format!("{base}/api/operator/{action}?object={}", urlencoding::encode(object));
                retry(|| client.post(&url).bearer_auth(token).header("content-type", "application/json").body(body.clone()).send()).await?
            }
            Endpoint::Local { store, .. } => {
                let name = action.rsplit('/').next().unwrap_or_default();
                let result = store
                    .with_tx(|db| {
                        let r = backup::handle(db, name, &body, &[Kind::Workspace]);
                        let ok = r.is_ok();
                        (r, ok)
                    })
                    .map_err(|e| CallError::Transport(e.to_string()))?;
                result.map_err(api_error)?
            }
            Endpoint::Folder { root, objects } => {
                let name = action.rsplit('/').next().unwrap_or_default();
                let allowed: &[Kind] = match backup::target(object, true, "main") {
                    Some(Target::Directory) => &[Kind::Directory],
                    Some(Target::Workspace) => &[Kind::Workspace, Kind::Alias],
                    None => return Err(api_error(ApiError::not_found(format!("an object named {object}")))),
                };
                in_folder(root, objects, object, |db| backup::handle(db, name, &body, allowed))?
            }
        };
        serde_json::from_value(reply).map_err(|e| CallError::Transport(format!("unexpected answer to {action}: {e}")))
    }
}

/// Sends a request, again after a pause when the server can't be reached or answers 5xx/429.
async fn retry<F, Fut>(send: F) -> Result<Value, CallError>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = reqwest::Result<reqwest::Response>>,
{
    let mut last = CallError::Transport("not sent".into());
    for attempt in 0..ATTEMPTS {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_secs(1 << (attempt - 1))).await;
        }
        let resp = match send().await {
            Ok(r) => r,
            Err(e) => {
                last = CallError::Transport(e.without_url().to_string());
                continue;
            }
        };
        let status = resp.status().as_u16();
        let body: Value = match resp.bytes().await {
            Ok(b) => serde_json::from_slice(&b).unwrap_or(Value::Null),
            Err(e) => {
                last = CallError::Transport(e.without_url().to_string());
                continue;
            }
        };
        if status == 200 {
            return Ok(body);
        }
        let err = &body["error"];
        last = CallError::Api {
            status,
            code: err["code"].as_str().unwrap_or("http_error").to_string(),
            message: err["message"].as_str().map(str::to_string).unwrap_or_else(|| format!("HTTP {status}")),
            details: err["details"].clone(),
        };
        if status < 500 && status != 429 {
            break;
        }
    }
    Err(last)
}

// ---------------------------------------------------------------------------
// Encrypted backup files

/// Writes an encrypted backup file: a header, then sealed records (see [`FileKey`]), each a JSON
/// value: the listing and the objects it covers, then for each object either its manifest, pages
/// and `object_end`, or `empty`; then an end record naming every object. [`BackupWriter::finish`]
/// writes the end record only once every object is in the file. A file left unfinished (an error,
/// a missing object) is removed: it could never be restored.
pub struct BackupWriter {
    file: Option<BufWriter<File>>,
    path: PathBuf,
    key: FileKey,
    index: u64,
    /// The objects the listing covers, and those whose records are all written.
    expected: BTreeSet<String>,
    done: BTreeSet<String>,
}

impl BackupWriter {
    /// Creates `path`, readable by its owner only. Never overwrites a file.
    pub fn create(path: &Path, passphrase: &str) -> anyhow::Result<BackupWriter> {
        let (key, header) = FileKey::create(passphrase).map_err(|e| anyhow!(e.message))?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let file = options.open(path).with_context(|| format!("creating {}", path.display()))?;
        let mut writer = BackupWriter {
            file: Some(BufWriter::new(file)),
            path: path.to_path_buf(),
            key,
            index: 0,
            expected: BTreeSet::new(),
            done: BTreeSet::new(),
        };
        writer.file.as_mut().map(|f| f.write_all(&header)).transpose()?;
        Ok(writer)
    }

    fn record(&mut self, value: &Value) -> anyhow::Result<()> {
        let sealed = self.key.seal(self.index, &serde_json::to_vec(value)?).map_err(|e| anyhow!(e.message))?;
        let file = self.file.as_mut().ok_or_else(|| anyhow!("the backup file is closed"))?;
        file.write_all(&(sealed.len() as u32).to_be_bytes())?;
        file.write_all(&sealed)?;
        self.index += 1;
        Ok(())
    }

    /// The first record: what the source listed, and the objects this file covers.
    pub fn listing(&mut self, listing: &Listing, objects: &[String]) -> anyhow::Result<()> {
        self.expected = objects.iter().cloned().collect();
        self.record(&json!({ "type": "listing", "listing": listing, "objects": objects }))
    }

    pub fn manifest(&mut self, object: &str, manifest: &Manifest) -> anyhow::Result<()> {
        self.record(&json!({ "type": "manifest", "object": object, "manifest": manifest }))
    }

    pub fn page(&mut self, object: &str, page: &Page) -> anyhow::Result<()> {
        self.record(&json!({ "type": "page", "object": object, "page": page }))
    }

    /// Every page of `object` is in the file.
    pub fn object_done(&mut self, object: &str) -> anyhow::Result<()> {
        self.record(&json!({ "type": "object_end", "object": object }))?;
        self.done.insert(object.to_string());
        Ok(())
    }

    /// `object` holds nothing.
    pub fn empty(&mut self, object: &str) -> anyhow::Result<()> {
        self.record(&json!({ "type": "empty", "object": object }))?;
        self.done.insert(object.to_string());
        Ok(())
    }

    /// Writes the end record once every object the listing covers is in the file; otherwise
    /// removes the file and says which objects it lacks.
    pub fn finish(mut self) -> anyhow::Result<()> {
        let missing: Vec<&String> = self.expected.difference(&self.done).collect();
        if !missing.is_empty() {
            let names: Vec<&str> = missing.iter().map(|s| s.as_str()).collect();
            bail!("the backup file was removed: it lacks {}", names.join(", "));
        }
        let records = self.index;
        let objects: Vec<&String> = self.done.iter().collect();
        self.record(&json!({ "type": "end", "records": records, "objects": objects }))?;
        let mut file = self.file.take().ok_or_else(|| anyhow!("the backup file is closed"))?;
        file.flush()?;
        file.get_ref().sync_all()?;
        Ok(())
    }
}

impl Drop for BackupWriter {
    fn drop(&mut self) {
        // Not finished: incomplete, so of no use.
        if self.file.take().is_some() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Reads what [`BackupWriter`] wrote, failing on a wrong passphrase, a changed byte, or a file cut short.
pub struct BackupReader {
    file: BufReader<File>,
    key: FileKey,
    index: u64,
    /// The objects the end record names, once it's read.
    ended: Option<Vec<String>>,
}

/// The largest record a backup file may hold.
const MAX_RECORD: usize = backup::MAX_RESTORE_BODY * 2;

impl BackupReader {
    pub fn open(path: &Path, passphrase: &str) -> anyhow::Result<BackupReader> {
        let mut file = BufReader::new(File::open(path).with_context(|| format!("opening {}", path.display()))?);
        let mut header = vec![0u8; backup::FILE_HEADER_LEN];
        file.read_exact(&mut header).context("this isn't a DumbSlab backup file")?;
        let key = FileKey::open_header(passphrase, &header).map_err(|e| anyhow!(e.message))?;
        Ok(BackupReader { file, key, index: 0, ended: None })
    }

    /// The next record, or `None` after the end record.
    pub fn next_record(&mut self) -> anyhow::Result<Option<Value>> {
        if self.ended.is_some() {
            return Ok(None);
        }
        let mut len = [0u8; 4];
        self.file.read_exact(&mut len).context("the backup file is cut short (it has no end record)")?;
        let len = u32::from_be_bytes(len) as usize;
        if len > MAX_RECORD {
            bail!("the backup file is damaged");
        }
        let mut sealed = vec![0u8; len];
        self.file.read_exact(&mut sealed).context("the backup file is cut short")?;
        let plain = self.key.open(self.index, &sealed).map_err(|e| anyhow!(e.message))?;
        self.index += 1;
        let value: Value = serde_json::from_slice(&plain)?;
        if value["type"] == "end" {
            if value["records"].as_u64() != Some(self.index - 1) {
                bail!("the backup file is damaged");
            }
            self.ended = Some(serde_json::from_value(value["objects"].clone()).context("the backup file's end record names no objects")?);
            return Ok(None);
        }
        Ok(Some(value))
    }
}

/// What a backup file holds once read through and checked: every record opens, the end record is
/// there, and every object the listing covers is in it whole (or recorded as empty).
pub struct Contents {
    pub listing: Listing,
    pub objects: Vec<String>,
}

/// Reads a backup file through and refuses it unless it's whole (see [`Contents`]).
pub fn check_file(path: &Path, passphrase: &str) -> anyhow::Result<Contents> {
    let mut reader = BackupReader::open(path, passphrase)?;
    let first = reader.next_record()?.ok_or_else(|| anyhow!("the backup file holds nothing"))?;
    if first["type"] != "listing" {
        bail!("the backup file doesn't start with its listing");
    }
    let listing: Listing = serde_json::from_value(first["listing"].clone()).context("the backup file's listing can't be read")?;
    let objects: Vec<String> = serde_json::from_value(first["objects"].clone()).context("the backup file names no objects")?;
    let covered: BTreeSet<&String> = objects.iter().collect();
    let mut done = BTreeSet::new();
    let mut open: Option<String> = None;
    while let Some(record) = reader.next_record()? {
        let object = record["object"].as_str().unwrap_or_default().to_string();
        let kind = record["type"].as_str().unwrap_or_default();
        let fresh = covered.contains(&object) && !done.contains(&object);
        match kind {
            "manifest" | "empty" if open.is_none() && fresh => {
                if kind == "manifest" {
                    open = Some(object);
                } else {
                    done.insert(object);
                }
            }
            "page" if open.as_ref() == Some(&object) => {}
            "object_end" if open.as_ref() == Some(&object) => {
                open = None;
                done.insert(object);
            }
            _ => bail!("the backup file is damaged: a {kind} record for {object} is out of place"),
        }
    }
    let missing: Vec<&str> = objects.iter().filter(|o| !done.contains(*o)).map(|o| o.as_str()).collect();
    if !missing.is_empty() {
        bail!("the backup file lacks {}", missing.join(", "));
    }
    let mut ended = reader.ended.clone().unwrap_or_default();
    ended.sort();
    let mut expected = objects.clone();
    expected.sort();
    if ended != expected {
        bail!("the backup file's end record doesn't match its listing");
    }
    Ok(Contents { listing, objects })
}

// ---------------------------------------------------------------------------
// Copying

/// How one object's copy (or check) went.
#[derive(Debug, Clone, PartialEq)]
pub enum Status {
    /// Restored, and both ends hold the same rows.
    Copied,
    /// The target already held the same rows (an earlier run copied it).
    AlreadyCopied,
    /// Both ends hold the same rows (`verify`).
    Same,
    /// Written to the backup file only.
    Saved,
    /// The source holds nothing; there's nothing to copy.
    Empty,
    /// The ends differ in these tables.
    Differs(Vec<String>),
    Failed(String),
}

impl Status {
    pub fn ok(&self) -> bool {
        !matches!(self, Status::Differs(_) | Status::Failed(_))
    }
}

/// One row of the final table.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub object: String,
    pub kind: Kind,
    pub tables: usize,
    pub rows: i64,
    /// A short digest of every table's rows and checksum, at each end.
    pub source: Option<String>,
    pub target: Option<String>,
    pub status: Status,
    /// What else the copy did to it (the directory: workspaces it marked active).
    pub note: Option<String>,
}

impl Outcome {
    fn new(object: &str, kind: Kind, status: Status) -> Outcome {
        Outcome { object: object.into(), kind, tables: 0, rows: 0, source: None, target: None, status, note: None }
    }
}

type Totals = BTreeMap<String, Checksum>;

fn digest(totals: &Totals) -> String {
    let lines: Vec<String> = totals.iter().map(|(t, c)| format!("{t} {} {}", c.rows, c.hex())).collect();
    dumbslab_core::util::sha256_hex(&lines.join("\n"))[..12].to_string()
}

/// What to copy.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Only these objects (all when empty).
    pub objects: Vec<String>,
    /// Freeze the source first, so nothing changes while it's copied.
    pub freeze: bool,
}

/// Progress goes to standard error.
fn say(line: impl AsRef<str>) {
    eprintln!("{}", line.as_ref());
}

fn order(kind: Kind) -> u8 {
    match kind {
        Kind::Directory => 0,
        Kind::Workspace => 1,
        Kind::Alias => 2,
        Kind::Empty => 3,
    }
}

/// The objects to work on, directory first, then workspaces, then the addresses they moved to.
fn select(listing: &Listing, only: &[String]) -> anyhow::Result<Vec<ObjectRef>> {
    for name in only {
        if !listing.objects.iter().any(|o| &o.name == name) {
            bail!("the source holds no object named {name}");
        }
    }
    let mut out: Vec<ObjectRef> = listing.objects.iter().filter(|o| only.is_empty() || only.contains(&o.name)).cloned().collect();
    out.sort_by_key(|o| order(o.kind));
    Ok(out)
}

async fn listing(end: &Endpoint) -> anyhow::Result<Listing> {
    let l = end.objects().await?;
    if l.format != backup::FORMAT {
        bail!("{} speaks backup format {}; this tool speaks {}", end.label(), l.format, backup::FORMAT);
    }
    Ok(l)
}

/// Freezes the source: its directory starts draining first (no sign-ups, moves or new objects
/// from then on, though workspaces can still say their sign-up finished), then every selected
/// object freezes (each drains, waits for its jobs, and seals). Then, before the directory seals,
/// any workspace whose sign-up finished but whose entry still says `reserved` (its activation never
/// arrived) is marked active there, on the source, so the copy and every later check see the same
/// state. Returns the listing once sealed, and the workspaces it marked active.
pub async fn freeze(from: &Endpoint, only: &[String]) -> anyhow::Result<(Listing, Vec<String>)> {
    if matches!(from, Endpoint::Local { .. }) {
        bail!("a local database can't be frozen: stop its server instead");
    }
    let first = listing(from).await?;
    // An object holding an unfinished restore can't be copied: say so before freezing anything.
    for o in select(&first, only)? {
        let m: Manifest = from.call("backup/manifest", &o.name, &json!({})).await.map_err(|e| anyhow!("{}: {e}", o.name))?;
        if m.restoring {
            bail!("{}: {HALF_RESTORED}. Nothing was frozen.", o.name);
        }
    }
    let stuck = |what: &str, e: CallError| {
        anyhow!("freezing {what}: {e}. Objects frozen so far stay frozen; `dumbslab backup thaw --from {}` reopens them", from.label())
    };
    let has_directory = first.objects.iter().any(|o| o.kind == Kind::Directory && (only.is_empty() || only.contains(&o.name)));
    if has_directory {
        from.call::<Value>("backup/drain", backup::DIRECTORY_OBJECT, &json!({})).await.map_err(|e| stuck("the directory", e))?;
    }
    let listing = if has_directory { self::listing(from).await? } else { first };
    for o in select(&listing, only)?.iter().filter(|o| o.kind != Kind::Directory) {
        let frozen: Value = from.call("backup/freeze", &o.name, &json!({})).await.map_err(|e| stuck(&o.name, e))?;
        if let Some(n) = frozen["parked"].as_u64().filter(|n| *n > 0) {
            say(format!("{}: {n} job(s) were still running when it sealed; their later steps write nothing", o.name));
        }
    }
    let mut repaired = vec![];
    if has_directory {
        repaired = repair_directory(from, &listing).await.map_err(|e| stuck("the directory", e))?;
        from.call::<Value>("backup/seal", backup::DIRECTORY_OBJECT, &json!({})).await.map_err(|e| stuck("the directory", e))?;
    }
    let listing = if has_directory { self::listing(from).await? } else { listing };
    say(format!("froze {} on {}", if only.is_empty() { "every object".to_string() } else { only.join(", ") }, from.label()));
    if !repaired.is_empty() {
        say(format!(
            "marked {} active in the source's directory: its sign-up had finished, but the directory never heard",
            repaired.join(", ")
        ));
    }
    Ok((listing, repaired))
}

/// Marks active, in the draining directory, each workspace whose entry says `reserved` though its
/// (frozen) object holds a set-up workspace. Not disabled or deleted ones (their entries don't say
/// `reserved`), nor reservations nobody set up (their objects hold no people).
async fn repair_directory(from: &Endpoint, listing: &Listing) -> Result<Vec<String>, CallError> {
    let mut stale = vec![];
    for o in listing.objects.iter().filter(|o| o.kind == Kind::Workspace && o.status.as_deref() == Some("reserved")) {
        let m: Manifest = from.call("backup/manifest", &o.name, &json!({})).await?;
        let set_up = m.kind == Kind::Workspace && !m.restoring && m.tables.iter().any(|t| t.name == "users" && t.rows > 0);
        if let (true, Some(home)) = (set_up, o.name.strip_prefix("ws:")) {
            stale.push(home.to_string());
        }
    }
    if stale.is_empty() {
        return Ok(vec![]);
    }
    let marked: Value = from.call("backup/activate", backup::DIRECTORY_OBJECT, &json!({ "homes": stale })).await?;
    Ok(serde_json::from_value(marked["activated"].clone()).unwrap_or_default())
}

/// Lifts the freeze from every selected object, directory last.
pub async fn thaw(from: &Endpoint, only: &[String]) -> anyhow::Result<()> {
    let listing = listing(from).await?;
    let mut objects = select(&listing, only)?;
    objects.reverse();
    for o in &objects {
        from.call::<Value>("backup/thaw", &o.name, &json!({})).await.map_err(|e| anyhow!("thawing {}: {e}", o.name))?;
    }
    say(format!("thawed {} object(s) on {}", objects.len(), from.label()));
    Ok(())
}

/// Counts and checksums every table of an object, page by page.
async fn totals(end: &Endpoint, object: &str, manifest: &Manifest) -> Result<Totals, CallError> {
    let mut out = Totals::new();
    for t in &manifest.tables {
        let mut sum = Checksum::default();
        let mut after = None;
        loop {
            let page: Summary = end.call("backup/summary", object, &PageRequest { table: t.name.clone(), after }).await?;
            sum.merge(Checksum::parse(page.count, &page.checksum).map_err(|e| CallError::Transport(e.message))?);
            after = page.next;
            if after.is_none() {
                break;
            }
        }
        out.insert(t.name.clone(), sum);
    }
    Ok(out)
}

fn differing(a: &Totals, b: &Totals) -> Vec<String> {
    let names: std::collections::BTreeSet<&String> = a.keys().chain(b.keys()).collect();
    names.into_iter().filter(|n| a.get(*n) != b.get(*n)).cloned().collect()
}

/// The manifest to finish with: the rows actually copied, which differ from the manifest's
/// counts when the source changed meanwhile (it wasn't frozen).
fn as_copied(manifest: &Manifest, copied: &Totals) -> Manifest {
    let mut m = manifest.clone();
    for t in &mut m.tables {
        t.rows = copied.get(&t.name).map_or(0, |c| c.rows);
    }
    m
}

/// What the target's own manifest says that differs from the source's, besides rows: its kind,
/// schema and schema version, and its `AUTOINCREMENT` counters.
fn manifest_differences(source: &Manifest, target: &Manifest) -> Vec<String> {
    let mut out = vec![];
    if target.kind != source.kind {
        out.push(format!("the target holds a {}", target.kind.as_str()));
    } else if target.schema != source.schema {
        out.push("schema".into());
    }
    if target.schema_version != source.schema_version {
        out.push("schema_version".into());
    }
    if target.sequences != source.sequences {
        out.push("sqlite_sequence".into());
    }
    out
}

/// Checks the target against `expected` and, when `restore_id` names its unfinished restore,
/// finishes it once they match. A target that already held data passes only when its manifest
/// matches the source's too.
async fn check_and_finish(
    to: &Endpoint,
    object: &str,
    manifest: &Manifest,
    expected: &Totals,
    restore_id: Option<&str>,
) -> Result<Outcome, CallError> {
    let mut outcome = Outcome::new(object, manifest.kind, Status::Copied);
    outcome.tables = manifest.tables.len();
    outcome.rows = expected.values().map(|c| c.rows).sum();
    outcome.source = Some(digest(expected));
    let target = totals(to, object, manifest).await?;
    outcome.target = Some(digest(&target));
    let differ = differing(expected, &target);
    if !differ.is_empty() {
        outcome.status = Status::Differs(differ);
        return Ok(outcome);
    }
    let already = match restore_id {
        None => true,
        Some(restore_id) => {
            let request = json!({ "restore_id": restore_id, "manifest": as_copied(manifest, expected) });
            to.call::<Finished>("restore/finish", object, &request).await?.already_finished
        }
    };
    let theirs: Manifest = to.call("backup/manifest", object, &json!({})).await?;
    let differ = manifest_differences(manifest, &theirs);
    outcome.status = match (differ.is_empty(), already) {
        (false, _) => Status::Differs(differ),
        (true, true) => Status::AlreadyCopied,
        (true, false) => Status::Copied,
    };
    Ok(outcome)
}

const HALF_RESTORED: &str = "the source holds an unfinished restore (part of its rows): finish it or wipe it before copying it";

/// How the target took an object.
enum Taken {
    /// Restoring under this id.
    Restoring(String),
    /// It already holds data: only check it.
    Existing,
    Refused(String),
}

async fn begin(to: &Endpoint, object: &str, manifest: &Manifest) -> Taken {
    match to.call::<Begun>("restore/begin", object, &json!({ "object": object, "manifest": manifest })).await {
        Ok(b) => {
            if b.resumed {
                say(format!("{object}: resuming an unfinished restore of the same snapshot"));
            }
            Taken::Restoring(b.restore_id)
        }
        Err(e) if e.code() == Some("not_empty") => Taken::Existing,
        Err(e) => Taken::Refused(e.to_string()),
    }
}

async fn write_page(to: &Endpoint, object: &str, restore_id: &str, page: &Page) -> anyhow::Result<()> {
    to.call::<Restored>("restore/page", object, &json!({ "restore_id": restore_id, "page": page }))
        .await
        .map(|_| ())
        .map_err(|e| anyhow!("{object}: writing {}: {e}", page.table))
}

/// Copies one object: its manifest, then every table page by page, to the target (when there is
/// one) and the backup file (when asked). Then checks the target against a fresh look at the
/// source and finishes the restore.
async fn copy_object(
    from: &Endpoint,
    to: Option<&Endpoint>,
    save: &mut Option<&mut BackupWriter>,
    object: &str,
) -> anyhow::Result<Outcome> {
    let manifest: Manifest = from.call("backup/manifest", object, &json!({})).await.map_err(|e| anyhow!("{object}: {e}"))?;
    if manifest.restoring {
        return Ok(Outcome::new(object, manifest.kind, Status::Failed(HALF_RESTORED.into())));
    }
    if manifest.kind == Kind::Empty {
        if let Some(w) = save.as_deref_mut() {
            w.empty(object)?;
        }
        return Ok(Outcome::new(object, Kind::Empty, Status::Empty));
    }
    if let Some(w) = save.as_deref_mut() {
        w.manifest(object, &manifest)?;
    }
    // A target that refuses the object still leaves the backup file whole.
    let taken = match to {
        None => None,
        Some(to) => Some(begin(to, object, &manifest).await),
    };
    let restore_id = match &taken {
        Some(Taken::Restoring(id)) => Some(id.clone()),
        _ => None,
    };
    let mut copied = Totals::new();
    if restore_id.is_some() || save.is_some() {
        for t in &manifest.tables {
            let mut sum = Checksum::default();
            let mut after = None;
            loop {
                let page: Page = from
                    .call("backup/dump", object, &PageRequest { table: t.name.clone(), after })
                    .await
                    .map_err(|e| anyhow!("{object}: reading {}: {e}", t.name))?;
                sum.merge(Checksum::parse(page.count, &page.checksum).map_err(|e| anyhow!(e.message))?);
                if let Some(w) = save.as_deref_mut() {
                    w.page(object, &page)?;
                }
                if let (Some(to), Some(id)) = (to, &restore_id) {
                    write_page(to, object, id, &page).await?;
                }
                after = page.next;
                if after.is_none() {
                    break;
                }
            }
            if sum.rows > 0 {
                say(format!("{object}: {} rows of {}", sum.rows, t.name));
            }
            copied.insert(t.name.clone(), sum);
        }
        if let Some(w) = save.as_deref_mut() {
            w.object_done(object)?;
        }
    }
    let to = match (to, taken) {
        (None, _) => {
            let mut outcome = Outcome::new(object, manifest.kind, Status::Saved);
            outcome.tables = manifest.tables.len();
            outcome.rows = copied.values().map(|c| c.rows).sum();
            outcome.source = Some(digest(&copied));
            return Ok(outcome);
        }
        (Some(_), Some(Taken::Refused(why))) => {
            let mut outcome = Outcome::new(object, manifest.kind, Status::Failed(why));
            outcome.tables = manifest.tables.len();
            return Ok(outcome);
        }
        (Some(to), _) => to,
    };
    // What the source holds now: when it's frozen, exactly what was copied.
    let source = totals(from, object, &manifest).await.map_err(|e| anyhow!("{object}: {e}"))?;
    if restore_id.is_some() && source != copied {
        let mut outcome = Outcome::new(object, manifest.kind, Status::Differs(differing(&source, &copied)));
        outcome.source = Some(digest(&source));
        outcome.tables = manifest.tables.len();
        say(format!("{object}: the source changed while it was copied; freeze it and copy again"));
        return Ok(outcome);
    }
    check_and_finish(to, object, &manifest, &source, restore_id.as_deref()).await.map_err(|e| anyhow!("{object}: {e}"))
}

/// Copies every selected object from `from` to `to` and/or an encrypted backup file, then checks
/// each one. An object that fails doesn't stop the others; run it again to resume. The backup
/// file, if any, still needs [`BackupWriter::finish`], which refuses a file missing an object.
pub async fn copy(
    from: &Endpoint,
    to: Option<&Endpoint>,
    mut save: Option<&mut BackupWriter>,
    opts: &Options,
) -> anyhow::Result<Vec<Outcome>> {
    if to.is_none() && save.is_none() {
        bail!("copy to a deployment (--to), a backup file (--save), or both");
    }
    let mut source = listing(from).await?;
    if let Some(to) = to {
        let target = listing(to).await?;
        if target.git_sha != source.git_sha {
            say(format!(
                "note: {} runs {} and {} runs {}; objects whose schema differs will be refused",
                from.label(),
                source.git_sha,
                to.label(),
                target.git_sha
            ));
        }
        if matches!(to, Endpoint::Local { .. }) && select(&source, &opts.objects)?.len() != 1 {
            bail!("a local database holds one workspace: pick it with --object ws:<address>");
        }
    }
    let mut repaired = vec![];
    if opts.freeze && matches!(from, Endpoint::Local { .. }) {
        say("a local database can't be frozen: stop its server before copying it");
    } else if opts.freeze {
        (source, repaired) = freeze(from, &opts.objects).await?;
    } else {
        say("not freezing the source: if it changes during the copy, the check says so, and an interrupted copy can't resume");
    }
    let objects = select(&source, &opts.objects)?;
    if let Some(w) = save.as_deref_mut() {
        let names: Vec<String> = objects.iter().map(|o| o.name.clone()).collect();
        w.listing(&source, &names)?;
    }
    let mut outcomes = vec![];
    for o in &objects {
        let mut outcome = match copy_object(from, to, &mut save, &o.name).await {
            Ok(outcome) => outcome,
            Err(e) => Outcome::new(&o.name, o.kind, Status::Failed(e.to_string())),
        };
        if o.kind == Kind::Directory && !repaired.is_empty() {
            outcome.note = Some(format!("marked {} active on the source first: set up, but never activated", repaired.join(", ")));
        }
        say(format!("{}: {}", o.name, status_text(&outcome.status)));
        outcomes.push(outcome);
    }
    Ok(outcomes)
}

/// An object being restored from a backup file.
struct Restoring {
    name: String,
    manifest: Manifest,
    taken: Taken,
    /// The rows the file held for it.
    copied: Totals,
}

async fn close(to: &Endpoint, r: Restoring) -> Outcome {
    let failed = |why: String| Outcome::new(&r.name, r.manifest.kind, Status::Failed(why));
    let restore_id = match &r.taken {
        Taken::Refused(why) => {
            let outcome = failed(why.clone());
            say(format!("{}: {}", r.name, status_text(&outcome.status)));
            return outcome;
        }
        Taken::Restoring(id) => Some(id.as_str()),
        Taken::Existing => None,
    };
    let mut expected = r.copied.clone();
    for t in &r.manifest.tables {
        expected.entry(t.name.clone()).or_default();
    }
    let outcome = check_and_finish(to, &r.name, &r.manifest, &expected, restore_id).await.unwrap_or_else(|e| failed(e.to_string()));
    say(format!("{}: {}", r.name, status_text(&outcome.status)));
    outcome
}

/// Restores an encrypted backup file into `to`, object by object, checking each against the rows
/// the file holds. The file is read through and checked first (see [`check_file`]): one that's
/// damaged, cut short or missing an object restores nothing.
pub async fn restore_file(path: &Path, passphrase: &str, to: &Endpoint, only: &[String]) -> anyhow::Result<Vec<Outcome>> {
    let contents = check_file(path, passphrase)?;
    for name in only {
        if !contents.objects.contains(name) {
            bail!("the backup holds no object named {name}");
        }
    }
    let target = listing(to).await?;
    if contents.listing.git_sha != target.git_sha {
        say(format!("note: the backup is from {} and {} runs {}", contents.listing.git_sha, to.label(), target.git_sha));
    }
    let mut reader = BackupReader::open(path, passphrase)?;
    reader.next_record()?;
    let mut outcomes = vec![];
    let mut current: Option<Restoring> = None;
    while let Some(record) = reader.next_record()? {
        let object = record["object"].as_str().unwrap_or_default().to_string();
        let wanted = only.is_empty() || only.contains(&object);
        match record["type"].as_str().unwrap_or_default() {
            "empty" if wanted => outcomes.push(Outcome::new(&object, Kind::Empty, Status::Empty)),
            "manifest" if wanted => {
                let manifest: Manifest = serde_json::from_value(record["manifest"].clone())?;
                let taken = begin(to, &object, &manifest).await;
                current = Some(Restoring { name: object, manifest, taken, copied: Totals::new() });
            }
            "page" => {
                let Some(r) = current.as_mut().filter(|r| r.name == object) else { continue };
                let page: Page = serde_json::from_value(record["page"].clone())?;
                let sum = Checksum::parse(page.count, &page.checksum).map_err(|e| anyhow!(e.message))?;
                r.copied.entry(page.table.clone()).or_default().merge(sum);
                if let Taken::Restoring(id) = &r.taken {
                    write_page(to, &object, id, &page).await?;
                }
            }
            "object_end" => {
                if let Some(r) = current.take_if(|r| r.name == object) {
                    outcomes.push(close(to, r).await);
                }
            }
            _ => {}
        }
    }
    Ok(outcomes)
}

/// Compares every selected object on two deployments, table by table.
pub async fn verify(from: &Endpoint, to: &Endpoint, only: &[String]) -> anyhow::Result<Vec<Outcome>> {
    let source = listing(from).await?;
    let mut outcomes = vec![];
    for o in select(&source, only)? {
        let outcome = async {
            let manifest: Manifest = from.call("backup/manifest", &o.name, &json!({})).await?;
            if manifest.restoring {
                return Ok::<_, CallError>(Outcome::new(&o.name, manifest.kind, Status::Failed(HALF_RESTORED.into())));
            }
            if manifest.kind == Kind::Empty {
                return Ok(Outcome::new(&o.name, Kind::Empty, Status::Empty));
            }
            let theirs: Manifest = to.call("backup/manifest", &o.name, &json!({})).await?;
            let mut outcome = Outcome::new(&o.name, manifest.kind, Status::Same);
            outcome.tables = manifest.tables.len();
            if theirs.kind != manifest.kind || theirs.schema != manifest.schema {
                outcome.status = Status::Differs(manifest_differences(&manifest, &theirs));
                return Ok(outcome);
            }
            let (a, b) = (totals(from, &o.name, &manifest).await?, totals(to, &o.name, &manifest).await?);
            outcome.rows = a.values().map(|c| c.rows).sum();
            outcome.source = Some(digest(&a));
            outcome.target = Some(digest(&b));
            let mut differ = differing(&a, &b);
            differ.extend(manifest_differences(&manifest, &theirs));
            if !differ.is_empty() {
                outcome.status = Status::Differs(differ);
            }
            Ok(outcome)
        }
        .await
        .unwrap_or_else(|e| Outcome::new(&o.name, o.kind, Status::Failed(e.to_string())));
        outcomes.push(outcome);
    }
    Ok(outcomes)
}

pub fn status_text(s: &Status) -> String {
    match s {
        Status::Copied => "copied, verified".into(),
        Status::AlreadyCopied => "already copied, verified".into(),
        Status::Same => "same".into(),
        Status::Saved => "saved".into(),
        Status::Empty => "empty, skipped".into(),
        Status::Differs(tables) => format!("DIFFERS: {}", tables.join(", ")),
        Status::Failed(e) => format!("FAILED: {e}"),
    }
}

/// The final table, one object per line.
pub fn table(outcomes: &[Outcome]) -> String {
    let rows: Vec<[String; 7]> = outcomes
        .iter()
        .map(|o| {
            [
                o.object.clone(),
                o.kind.as_str().to_string(),
                o.tables.to_string(),
                o.rows.to_string(),
                o.source.clone().unwrap_or_else(|| "-".into()),
                o.target.clone().unwrap_or_else(|| "-".into()),
                match &o.note {
                    Some(note) => format!("{} ({note})", status_text(&o.status)),
                    None => status_text(&o.status),
                },
            ]
        })
        .collect();
    let head = ["OBJECT", "KIND", "TABLES", "ROWS", "SOURCE", "TARGET", "RESULT"].map(String::from);
    let mut widths = head.clone().map(|h| h.len());
    for r in &rows {
        for (w, c) in widths.iter_mut().zip(r) {
            *w = (*w).max(c.len());
        }
    }
    let line = |r: &[String; 7]| {
        let cells: Vec<String> = r.iter().zip(widths).map(|(c, w)| format!("{c:<w$}")).collect();
        cells.join("  ").trim_end().to_string()
    };
    std::iter::once(line(&head)).chain(rows.iter().map(line)).collect::<Vec<_>>().join("\n")
}
