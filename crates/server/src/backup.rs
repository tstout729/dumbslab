//! `dumbslab backup`: copies every object's data from one deployment to another through their
//! operator APIs (see `dumbslab_core::backup` and docs/cloudflare.md), and checks the copy table by
//! table. Rows stream from one end to the other a page at a time; nothing touches the disk unless
//! an encrypted backup file is asked for.
//!
//! Either end can also be a native server's database file, which holds one workspace.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use dumbslab_core::backup::{self, Begun, Checksum, FileKey, Finished, Kind, Manifest, ObjectRef, Page, PageRequest, Restored, Summary};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::store::Store;

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

    /// For messages: the URL or "a local database", never a token.
    pub fn label(&self) -> String {
        match self {
            Endpoint::Http { base, .. } => base.clone(),
            Endpoint::Local { .. } => "the local database".into(),
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
                result.map_err(|e| CallError::Api {
                    status: e.status,
                    code: e.code.to_string(),
                    message: e.message.clone(),
                    details: e.to_json()["error"]["details"].clone(),
                })?
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
/// value: the listing, then each object's manifest and pages, then an end record.
pub struct BackupWriter {
    file: BufWriter<File>,
    key: FileKey,
    index: u64,
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
        let mut file = BufWriter::new(file);
        file.write_all(&header)?;
        Ok(BackupWriter { file, key, index: 0 })
    }

    pub fn record(&mut self, value: &Value) -> anyhow::Result<()> {
        let sealed = self.key.seal(self.index, &serde_json::to_vec(value)?).map_err(|e| anyhow!(e.message))?;
        self.file.write_all(&(sealed.len() as u32).to_be_bytes())?;
        self.file.write_all(&sealed)?;
        self.index += 1;
        Ok(())
    }

    /// Writes the end record, without which the file reads as cut short.
    pub fn finish(mut self) -> anyhow::Result<()> {
        let records = self.index;
        self.record(&json!({ "type": "end", "records": records }))?;
        self.file.flush()?;
        self.file.get_ref().sync_all()?;
        Ok(())
    }
}

/// Reads what [`BackupWriter`] wrote, failing on a wrong passphrase, a changed byte, or a file cut short.
pub struct BackupReader {
    file: BufReader<File>,
    key: FileKey,
    index: u64,
    ended: bool,
}

/// The largest record a backup file may hold.
const MAX_RECORD: usize = backup::MAX_RESTORE_BODY * 2;

impl BackupReader {
    pub fn open(path: &Path, passphrase: &str) -> anyhow::Result<BackupReader> {
        let mut file = BufReader::new(File::open(path).with_context(|| format!("opening {}", path.display()))?);
        let mut header = vec![0u8; backup::FILE_HEADER_LEN];
        file.read_exact(&mut header).context("this isn't a DumbSlab backup file")?;
        let key = FileKey::open_header(passphrase, &header).map_err(|e| anyhow!(e.message))?;
        Ok(BackupReader { file, key, index: 0, ended: false })
    }

    /// The next record, or `None` after the end record.
    pub fn next_record(&mut self) -> anyhow::Result<Option<Value>> {
        if self.ended {
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
            self.ended = true;
            return Ok(None);
        }
        Ok(Some(value))
    }
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
}

impl Outcome {
    fn new(object: &str, kind: Kind, status: Status) -> Outcome {
        Outcome { object: object.into(), kind, tables: 0, rows: 0, source: None, target: None, status }
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

/// Freezes the source's directory first (no sign-ups, moves or new objects from then on), then
/// every selected object. Returns the listing read once the directory was frozen.
pub async fn freeze(from: &Endpoint, only: &[String]) -> anyhow::Result<Listing> {
    if matches!(from, Endpoint::Local { .. }) {
        bail!("a local database can't be frozen: stop its server instead");
    }
    let first = listing(from).await?;
    let has_directory = first.objects.iter().any(|o| o.kind == Kind::Directory && (only.is_empty() || only.contains(&o.name)));
    if has_directory {
        from.call::<Value>("backup/freeze", backup::DIRECTORY_OBJECT, &json!({})).await?;
    }
    let listing = if has_directory { self::listing(from).await? } else { first };
    for o in select(&listing, only)?.iter().filter(|o| o.kind != Kind::Directory) {
        from.call::<Value>("backup/freeze", &o.name, &json!({})).await.map_err(|e| anyhow!("freezing {}: {e}", o.name))?;
    }
    say(format!("froze {} on {}", if only.is_empty() { "every object".to_string() } else { only.join(", ") }, from.label()));
    Ok(listing)
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

/// Checks the target against `expected` and finishes its restore when they match.
async fn check_and_finish(
    to: &Endpoint,
    object: &str,
    manifest: &Manifest,
    expected: &Totals,
    restoring: bool,
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
    if !restoring {
        outcome.status = Status::AlreadyCopied;
        return Ok(outcome);
    }
    let finished: Finished = to.call("restore/finish", object, &json!({ "manifest": as_copied(manifest, expected) })).await?;
    let after: Manifest = to.call("backup/manifest", object, &json!({})).await?;
    if after.sequences != manifest.sequences {
        outcome.status = Status::Differs(vec!["sqlite_sequence".into()]);
    } else if finished.already_finished {
        outcome.status = Status::AlreadyCopied;
    }
    Ok(outcome)
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
    if manifest.kind == Kind::Empty {
        return Ok(Outcome::new(object, Kind::Empty, Status::Empty));
    }
    if let Some(w) = save.as_deref_mut() {
        w.record(&json!({ "type": "manifest", "object": object, "manifest": manifest }))?;
    }
    // `Some(true)`: restoring into the target; `Some(false)`: it already holds this object's data.
    // A target that refuses the object still leaves the backup file whole.
    let mut refused = None;
    let restoring = match to {
        None => None,
        Some(to) => match to.call::<Begun>("restore/begin", object, &json!({ "manifest": manifest })).await {
            Ok(b) => {
                if b.resumed {
                    say(format!("{object}: resuming an unfinished restore"));
                }
                Some(true)
            }
            Err(e) if e.code() == Some("not_empty") => Some(false),
            Err(e) => {
                refused = Some(e.to_string());
                None
            }
        },
    };
    let mut copied = Totals::new();
    if restoring == Some(true) || save.is_some() {
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
                    w.record(&json!({ "type": "page", "object": object, "page": page }))?;
                }
                if let (Some(to), Some(true)) = (to, restoring) {
                    to.call::<Restored>("restore/page", object, &page).await.map_err(|e| anyhow!("{object}: writing {}: {e}", t.name))?;
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
        // Without this, a restore from the file treats the object as cut short.
        if let Some(w) = save.as_deref_mut() {
            w.record(&json!({ "type": "object_end", "object": object }))?;
        }
    }
    if let Some(why) = refused {
        let mut outcome = Outcome::new(object, manifest.kind, Status::Failed(why));
        outcome.tables = manifest.tables.len();
        return Ok(outcome);
    }
    let Some(to) = to else {
        let mut outcome = Outcome::new(object, manifest.kind, Status::Saved);
        outcome.tables = manifest.tables.len();
        outcome.rows = copied.values().map(|c| c.rows).sum();
        outcome.source = Some(digest(&copied));
        return Ok(outcome);
    };
    // What the source holds now: when it's frozen, exactly what was copied.
    let source = totals(from, object, &manifest).await.map_err(|e| anyhow!("{object}: {e}"))?;
    if restoring == Some(true) && source != copied {
        let mut outcome = Outcome::new(object, manifest.kind, Status::Differs(differing(&source, &copied)));
        outcome.source = Some(digest(&source));
        outcome.tables = manifest.tables.len();
        say(format!("{object}: the source changed while it was copied; freeze it and copy again"));
        return Ok(outcome);
    }
    check_and_finish(to, object, &manifest, &source, restoring == Some(true)).await.map_err(|e| anyhow!("{object}: {e}"))
}

/// Copies every selected object from `from` to `to` and/or an encrypted backup file, then checks
/// each one. An object that fails doesn't stop the others; run it again to resume.
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
    if opts.freeze && matches!(from, Endpoint::Local { .. }) {
        say("a local database can't be frozen: stop its server before copying it");
    } else if opts.freeze {
        source = freeze(from, &opts.objects).await?;
    } else {
        say("not freezing the source: if it changes during the copy, the check says so");
    }
    let objects = select(&source, &opts.objects)?;
    if let Some(w) = save.as_deref_mut() {
        w.record(&json!({ "type": "listing", "listing": source }))?;
    }
    let mut outcomes = vec![];
    for o in &objects {
        let outcome = match copy_object(from, to, &mut save, &o.name).await {
            Ok(outcome) => outcome,
            Err(e) => Outcome::new(&o.name, o.kind, Status::Failed(e.to_string())),
        };
        say(format!("{}: {}", o.name, status_text(&outcome.status)));
        outcomes.push(outcome);
    }
    Ok(outcomes)
}

/// An object being restored from a backup file.
struct Restoring {
    name: String,
    manifest: Manifest,
    /// `Some(true)`: the target takes its pages; `Some(false)`: it already holds its data;
    /// `None`: it refused the object.
    restoring: Option<bool>,
    /// The rows the file held for it.
    copied: Totals,
    /// The file held all of it (its end record came).
    complete: bool,
}

async fn close(to: &Endpoint, r: Restoring) -> Outcome {
    let failed = |why: String| Outcome::new(&r.name, r.manifest.kind, Status::Failed(why));
    let outcome = match r.restoring {
        _ if !r.complete => failed("the backup file holds only part of it".into()),
        None => failed("the target refused it".into()),
        Some(restoring) => {
            let mut expected = r.copied.clone();
            for t in &r.manifest.tables {
                expected.entry(t.name.clone()).or_default();
            }
            check_and_finish(to, &r.name, &r.manifest, &expected, restoring).await.unwrap_or_else(|e| failed(e.to_string()))
        }
    };
    say(format!("{}: {}", r.name, status_text(&outcome.status)));
    outcome
}

/// Restores an encrypted backup file into `to`, object by object, checking each against the rows
/// the file holds.
pub async fn restore_file(reader: &mut BackupReader, to: &Endpoint, only: &[String]) -> anyhow::Result<Vec<Outcome>> {
    let target = listing(to).await?;
    let first = reader.next_record()?.unwrap_or_default();
    let source: Listing = serde_json::from_value(first["listing"].clone()).context("the backup file doesn't start with its listing")?;
    if source.git_sha != target.git_sha {
        say(format!("note: the backup is from {} and {} runs {}", source.git_sha, to.label(), target.git_sha));
    }
    select(&source, only)?;
    let mut outcomes = vec![];
    let mut current: Option<Restoring> = None;
    loop {
        let record = match reader.next_record() {
            Ok(Some(r)) => r,
            Ok(None) => break,
            Err(e) => {
                if let Some(mut r) = current.take() {
                    r.complete = false;
                    outcomes.push(close(to, r).await);
                }
                say(format!("{e:#}"));
                break;
            }
        };
        let object = record["object"].as_str().unwrap_or_default().to_string();
        match record["type"].as_str().unwrap_or_default() {
            "manifest" => {
                if let Some(r) = current.take() {
                    outcomes.push(close(to, r).await);
                }
                if !only.is_empty() && !only.contains(&object) {
                    continue;
                }
                let manifest: Manifest = serde_json::from_value(record["manifest"].clone())?;
                let restoring = match to.call::<Begun>("restore/begin", &object, &json!({ "manifest": manifest })).await {
                    Ok(_) => Some(true),
                    Err(e) if e.code() == Some("not_empty") => Some(false),
                    Err(e) => {
                        say(format!("{object}: {e}"));
                        None
                    }
                };
                current = Some(Restoring { name: object, manifest, restoring, copied: Totals::new(), complete: false });
            }
            "page" => {
                let Some(r) = current.as_mut().filter(|r| r.name == object) else { continue };
                let page: Page = serde_json::from_value(record["page"].clone())?;
                let sum = Checksum::parse(page.count, &page.checksum).map_err(|e| anyhow!(e.message))?;
                r.copied.entry(page.table.clone()).or_default().merge(sum);
                if r.restoring == Some(true) {
                    to.call::<Restored>("restore/page", &object, &page)
                        .await
                        .map_err(|e| anyhow!("{object}: writing {}: {e}", page.table))?;
                }
            }
            "object_end" => {
                if let Some(r) = current.as_mut().filter(|r| r.name == object) {
                    r.complete = true;
                }
            }
            _ => bail!("the backup file holds a record this tool doesn't know"),
        }
    }
    if let Some(r) = current.take() {
        outcomes.push(close(to, r).await);
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
            if manifest.kind == Kind::Empty {
                return Ok::<_, CallError>(Outcome::new(&o.name, Kind::Empty, Status::Empty));
            }
            let theirs: Manifest = to.call("backup/manifest", &o.name, &json!({})).await?;
            let mut outcome = Outcome::new(&o.name, manifest.kind, Status::Same);
            outcome.tables = manifest.tables.len();
            if theirs.kind != manifest.kind || theirs.schema != manifest.schema {
                outcome.status = Status::Differs(vec![format!("the target holds a {}", theirs.kind.as_str())]);
                return Ok(outcome);
            }
            let (a, b) = (totals(from, &o.name, &manifest).await?, totals(to, &o.name, &manifest).await?);
            outcome.rows = a.values().map(|c| c.rows).sum();
            outcome.source = Some(digest(&a));
            outcome.target = Some(digest(&b));
            let mut differ = differing(&a, &b);
            if theirs.sequences != manifest.sequences {
                differ.push("sqlite_sequence".into());
            }
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
                status_text(&o.status),
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
