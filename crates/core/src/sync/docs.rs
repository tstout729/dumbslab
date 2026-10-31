//! Docs sync: a folder of Markdown files in a GitHub repository or GitLab project, kept as posts
//! in a topic. One way: the repository is the source of truth, so synced posts can't be edited
//! here ([`refuse_edit`]); each sync that changes one saves a new version, like an edit.
//!
//! - Each Markdown file (`.md`, `.markdown`) is one published post. Its title is the front
//!   matter's `title:`, else a leading `# heading` (taken out of the body), else the file name.
//! - Sub-folders become sub-topics of the source's topic, with its visibility. A post is in the
//!   source's topic and in its folder's sub-topic, so it's never visible to more people than the
//!   source's topic.
//! - Relative links between synced files point at their posts; other relative links point at the
//!   file on GitHub or GitLab. Images in the folder (PNG, JPEG, GIF, WebP, AVIF up to
//!   [`MAX_IMAGE_BYTES`]) are uploaded once and reused until they change.
//! - A file renamed without changes keeps its post. A file gone from the repository has its post
//!   archived (never deleted); if it comes back, the post is published again.
//! - One sync handles at most [`DOCS_PER_RUN`] changed files and [`IMAGES_PER_RUN`] images; it
//!   reports what's `remaining`, and the next sync carries on from there.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::repo::{Entry, Provider, Repo};
use super::rewrite::{self, Target};
use super::{Ended, check_plan, hook_answer, hook_started};
use crate::connect::{Credential, Finish, HttpReply, Job, Step};
use crate::db::{Db, DbExt, Row, SqlValue};
use crate::error::{ApiError, ApiResult};
use crate::events::{Event, emit};
use crate::model::query_in;
use crate::ops::files;
use crate::ops::posts::{self, Synced};
use crate::ops::topics;
use crate::registry::Ctx;
use crate::util::{new_id, secure_eq, ts};
use crate::{HostConfig, Outcome, Request, params};

pub(crate) const TABLE: &str = "docs_sources";
/// The most Markdown files one source may have.
pub const MAX_DOCS: usize = 500;
/// Changed Markdown files one sync reads; the next sync carries on.
pub const DOCS_PER_RUN: usize = 20;
/// Images one sync uploads.
pub const IMAGES_PER_RUN: usize = 10;
/// Larger Markdown files are skipped.
pub const MAX_DOC_BYTES: u64 = 1_000_000;
/// Larger images link to the repository instead: an image arrives as base64 in JSON, which must fit
/// in [`crate::connect::MAX_REPLY_BYTES`].
pub const MAX_IMAGE_BYTES: u64 = 3_000_000;
/// Paths one file's links are remembered by (see `docs_items.refs`).
const MAX_REFS: usize = 200;
/// Skipped files a result lists.
const LISTED: usize = 100;
/// The longest topic name (see `topics::create_topic`).
const MAX_TOPIC_NAME: usize = 120;

const DOC_EXTENSIONS: &[&str] = &["md", "markdown"];
const IMAGE_EXTENSIONS: &[&str] = &["png", "jpg", "jpeg", "gif", "webp", "avif"];

fn extension(path: &str) -> String {
    let name = path.rsplit('/').next().unwrap_or_default();
    name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default()
}

/// Hidden folders (`.github`) and dependencies aren't documentation.
fn ignored(path: &str) -> bool {
    path.split('/').any(|s| s.starts_with('.') || s == "node_modules")
}

fn is_doc(path: &str) -> bool {
    !ignored(path) && DOC_EXTENSIONS.contains(&extension(path).as_str())
}

fn is_image(path: &str) -> bool {
    !ignored(path) && IMAGE_EXTENSIONS.contains(&extension(path).as_str())
}

fn dir_of(path: &str) -> &str {
    path.rsplit_once('/').map(|(d, _)| d).unwrap_or_default()
}

fn name_of(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// What the credentials are sealed to.
pub(crate) fn owner(source_id: &str) -> String {
    format!("docs-source:{source_id}")
}

/// Sources, with how each reads its repository (`docs_source_links`; none for a token). Add a
/// `WHERE` on `s.` columns.
pub(crate) const SOURCES_SQL: &str = "SELECT s.*, l.connection, l.installation_id, l.repo_id, l.disconnected
    FROM docs_sources s LEFT JOIN docs_source_links l ON l.source_id = s.id";

/// How a source reads its repository (`docs_source_links.connection`).
#[derive(Clone, Debug, PartialEq)]
pub enum Link {
    /// A pasted token (none for a public repository), and a push webhook the admin added.
    Token,
    /// DumbSlab's GitHub App: each sync mints a token for this one repository (see
    /// [`super::github_app`]), and the App's own webhook reports pushes.
    GitHubApp { installation_id: i64, repo_id: i64 },
}

impl Link {
    pub fn id(&self) -> &'static str {
        match self {
            Link::Token => "token",
            Link::GitHubApp { .. } => "github_app",
        }
    }
}

/// A source, with its credentials.
#[derive(Clone, Debug)]
pub struct Source {
    pub id: String,
    pub repo: Repo,
    pub topic_id: String,
    pub owner_id: String,
    pub cred: Credential,
    pub link: Link,
    /// Why it can't sync now (see [`super::github_app::disconnected_message`]).
    pub disconnected: Option<String>,
}

impl Source {
    pub(crate) fn from_row(cfg: &HostConfig, r: &Row) -> ApiResult<Source> {
        let mut source = Source::without_credentials(r)?;
        // A GitHub App source keeps no credentials: its tokens are minted for each sync.
        if source.link == Link::Token {
            source.cred = super::open(cfg, &owner(&source.id), source.repo.provider.id(), &r.str("secret"))?;
        }
        Ok(source)
    }

    /// The source with its credentials, or without them when they can't be read (the server's
    /// connector key changed): Settings still shows it, and an admin can enter a new token.
    pub(crate) fn from_row_or_blank(cfg: &HostConfig, r: &Row) -> ApiResult<(Source, bool)> {
        crate::connect::key_of(cfg)?;
        match Source::from_row(cfg, r) {
            Ok(s) => Ok((s, true)),
            Err(_) => Ok((Source::without_credentials(r)?, false)),
        }
    }

    fn without_credentials(r: &Row) -> ApiResult<Source> {
        let provider = Provider::parse(&r.str("provider")).ok_or_else(|| ApiError::internal("unknown docs sync provider"))?;
        let link = match (r.opt_str("connection").as_deref(), r.opt_i64("installation_id"), r.opt_i64("repo_id")) {
            (None, _, _) => Link::Token,
            (Some("github_app"), Some(installation_id), Some(repo_id)) => Link::GitHubApp { installation_id, repo_id },
            _ => return Err(ApiError::internal("a docs sync source's connection is incomplete")),
        };
        Ok(Source {
            id: r.str("id"),
            repo: Repo { provider, host: r.str("host"), repo: r.str("repo"), branch: r.str("branch"), folder: r.str("folder") },
            topic_id: r.str("topic_id"),
            owner_id: r.str("owner_id"),
            cred: Credential::default(),
            link,
            disconnected: r.opt_str("disconnected"),
        })
    }

    pub(crate) fn load(db: &dyn Db, cfg: &HostConfig, id: &str) -> ApiResult<Option<Source>> {
        match db.one(&format!("{SOURCES_SQL} WHERE s.id = ?"), &params![id])? {
            Some(r) => Ok(Some(Source::from_row(cfg, &r)?)),
            None => Ok(None),
        }
    }

    fn token(&self) -> &str {
        &self.cred.token
    }
}

/// A file a sync skipped, and why.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Skipped {
    /// Within the synced folder.
    pub path: String,
    pub reason: String,
}

/// What a docs sync did.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct DocsSyncResult {
    /// Markdown files in the folder.
    pub files: usize,
    pub created: usize,
    pub updated: usize,
    /// Files that hadn't changed (or changed in ways that don't show, like line endings).
    pub unchanged: usize,
    /// Files renamed or moved without changes; their posts kept their links and history.
    pub renamed: usize,
    /// Files gone from the repository; their posts were archived.
    pub archived: usize,
    /// Files back in the repository; their archived posts were published again.
    pub restored: usize,
    pub images_uploaded: usize,
    /// Images already uploaded that changed posts show again.
    pub images_reused: usize,
    /// Changed files not synced yet: sync again to continue.
    pub remaining: usize,
    /// Everything in the folder is in.
    pub done: bool,
    /// Files left out, and why (the first 100).
    pub skipped: Vec<Skipped>,
}

impl DocsSyncResult {
    fn skip(&mut self, path: &str, reason: impl Into<String>) {
        if self.skipped.len() < LISTED {
            self.skipped.push(Skipped { path: path.to_string(), reason: reason.into() });
        }
    }
}

/// Where a synced post's text comes from.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct SyncedFrom {
    /// `github` or `gitlab`.
    pub provider: String,
    /// `owner/name`, or a GitLab project's path.
    pub repository: String,
    pub branch: String,
    /// The file's path in the repository.
    pub path: String,
    /// The file on GitHub or GitLab: edit it there.
    pub url: String,
    /// The file is gone from the repository, so the post was archived.
    pub removed: bool,
}

const SYNCED_SQL: &str = "SELECT i.path, i.removed_at, s.provider, s.host, s.repo, s.branch, s.folder FROM docs_items i
    JOIN docs_sources s ON s.id = i.source_id WHERE i.kind = 'doc' AND i.target_id = ? LIMIT 1";

/// Where a post is synced from, if it is.
pub fn synced_from(db: &dyn Db, post_id: &str) -> ApiResult<Option<SyncedFrom>> {
    let Some(r) = db.one(SYNCED_SQL, &params![post_id])? else { return Ok(None) };
    let Some(provider) = Provider::parse(&r.str("provider")) else { return Ok(None) };
    let repo = Repo { provider, host: r.str("host"), repo: r.str("repo"), branch: r.str("branch"), folder: r.str("folder") };
    let path = repo.repo_path(&r.str("path"));
    Ok(Some(SyncedFrom {
        provider: provider.id().into(),
        repository: repo.repo.clone(),
        branch: repo.branch.clone(),
        url: repo.file_url(&path, false),
        path,
        removed: r.opt_str("removed_at").is_some(),
    }))
}

/// Synced posts change only in their repository.
pub fn refuse_edit(db: &dyn Db, post_id: &str, title: &str) -> ApiResult<()> {
    match synced_from(db, post_id)? {
        Some(s) => Err(ApiError::new(
            409,
            "synced_post",
            format!(
                "“{title}” is synced from {} ({}, {}). Edit it there: the next sync brings the change here. To edit it here instead, remove the docs sync source in Settings › Docs sync, or duplicate the post.",
                if s.provider == "github" { "GitHub" } else { "GitLab" },
                s.repository,
                s.path
            ),
        )
        .with_details(json!({ "synced_from": { "url": s.url } }))),
        None => Ok(()),
    }
}

/// The topic a synced post must stay in: its source's.
pub fn source_topic(db: &dyn Db, post_id: &str) -> ApiResult<Option<String>> {
    Ok(db
        .one(
            "SELECT s.topic_id FROM docs_items i JOIN docs_sources s ON s.id = i.source_id WHERE i.kind = 'doc' AND i.target_id = ? LIMIT 1",
            &params![post_id],
        )?
        .map(|r| r.str("topic_id")))
}

// ---------------------------------------------------------------------------
// The job

#[derive(Clone, Debug)]
pub struct DocsJob {
    source: Source,
    lease: String,
    base_url: String,
    phase: Phase,
    result: DocsSyncResult,
    /// Webhooks for the posts this sync created, changed or archived, from steps that committed,
    /// for the host to send once it finishes, however it finishes (see
    /// [`crate::connect::Job::take_effects`]).
    effects: Vec<crate::Effect>,
    /// The current step's, until the host says whether it committed ([`crate::connect::Job::settle`]).
    staged: Vec<crate::Effect>,
}

impl DocsJob {
    pub(crate) fn take_effects(&mut self) -> Vec<crate::Effect> {
        std::mem::take(&mut self.effects)
    }

    pub(crate) fn settle(&mut self, committed: bool) {
        let staged = std::mem::take(&mut self.staged);
        if committed {
            self.effects.extend(staged);
        }
    }
}

#[derive(Clone, Debug)]
enum Phase {
    Start,
    /// GitHub App sources: waiting for this sync's installation token (and, when `true`, the
    /// directory's answer to registering the installation again).
    Minting(bool),
    Listing,
    /// Waiting for this run's Markdown files.
    Reading(Plan),
    /// Waiting for the images they show.
    Images(Plan, Vec<Text>),
}

/// One file this run syncs.
#[derive(Clone, Debug)]
struct Work {
    path: String,
    sha: String,
    post_id: String,
    /// It was gone and is back: publish its archived post again.
    revive: bool,
}

/// A file read, made into a title and body.
#[derive(Clone, Debug)]
struct Text {
    work: Work,
    title: String,
    body: String,
}

/// An image to upload.
#[derive(Clone, Debug)]
struct Fetching {
    path: String,
    sha: String,
    file_id: String,
}

#[derive(Clone, Debug, Default)]
struct Plan {
    /// Every Markdown file in the folder now, and its post; and files that went or moved, whose
    /// posts links to them keep pointing at.
    docs: BTreeMap<String, String>,
    /// Every image in the folder now.
    images: BTreeMap<String, Entry>,
    /// Images already uploaded at their current version: path → (file id, name).
    uploaded: BTreeMap<String, (String, String)>,
    /// Images that can't be uploaded (too large, not an image): they link to the repository.
    unusable: BTreeSet<String>,
    /// Folders' topics: path → topic id.
    folders: BTreeMap<String, String>,
    /// Folders whose topic is visible to more people than the source's topic: path → why. Their
    /// files aren't synced (see [`Audience`]).
    blocked: BTreeMap<String, String>,
    batch: Vec<Work>,
    fetching: Vec<Fetching>,
}

/// Starts a sync of `source`, unless one is running. `Ok(None)` when one is.
pub(crate) fn start(db: &dyn Db, source: Source, base_url: &str, now: DateTime<Utc>) -> ApiResult<Option<Job>> {
    let Some(lease) = super::claim(db, TABLE, source.id.as_str().into(), now)? else { return Ok(None) };
    Ok(Some(Job::Docs(Box::new(DocsJob {
        source,
        lease,
        base_url: base_url.to_string(),
        phase: Phase::Start,
        result: DocsSyncResult::default(),
        effects: vec![],
        staged: vec![],
    }))))
}

/// Runs a docs sync's next step (see [`crate::connect::step`]).
pub fn step(db: &dyn Db, cfg: &HostConfig, j: &mut DocsJob, replies: Vec<HttpReply>, now: DateTime<Utc>) -> ApiResult<Step> {
    match std::mem::replace(&mut j.phase, Phase::Start) {
        Phase::Start => match j.source.link {
            Link::GitHubApp { installation_id, repo_id } => {
                let Some(app) = super::github_app::app(cfg) else {
                    return fail(db, j, "DumbSlab's GitHub App isn't set up on this server any more, so this folder can't sync.", now);
                };
                match super::github_app::token_call(app, installation_id, repo_id, now) {
                    Ok(call) => {
                        // Hosted, until the directory has the installation, each sync asks again.
                        let link = super::github_app::needs_link(db, cfg, installation_id)?;
                        let mut calls = vec![call];
                        if link {
                            calls.push(super::github_app::link_call(installation_id));
                        }
                        j.phase = Phase::Minting(link);
                        Ok(Step::Fetch(calls))
                    }
                    Err(message) => fail(db, j, &message, now),
                }
            }
            Link::Token => {
                j.phase = Phase::Listing;
                Ok(Step::Fetch(j.source.repo.tree_calls(j.source.token())))
            }
        },
        Phase::Minting(link) => minted(db, j, &replies, link, now),
        Phase::Listing => listing(db, cfg, j, &replies, now),
        Phase::Reading(plan) => reading(db, cfg, j, plan, &replies, now),
        Phase::Images(plan, texts) => images(db, cfg, j, plan, texts, &replies, now),
    }
}

fn fail(db: &dyn Db, j: &DocsJob, message: &str, now: DateTime<Utc>) -> ApiResult<Step> {
    super::finish(db, TABLE, j.source.id.as_str().into(), &j.lease, Ended { status: "failed", error: Some(message), result: None }, now)?;
    Ok(Step::Done(Finish::Fail(super::sync_failed(message))))
}

fn lost() -> Step {
    Step::Done(Finish::Fail(super::sync_failed("Another sync of this source took over before this one finished.")))
}

struct Item {
    target_id: String,
    sha: Option<String>,
    refs: Vec<String>,
    removed: bool,
    /// A blob that can never be synced, and why (see `docs_items.skipped_sha`).
    skipped: Option<(String, String)>,
}

fn items(db: &dyn Db, source_id: &str, kind: &str) -> ApiResult<BTreeMap<String, Item>> {
    let rows = db.query(
        "SELECT path, target_id, sha, refs, removed_at, skipped_sha, skip_reason FROM docs_items WHERE source_id = ? AND kind = ?",
        &params![source_id, kind],
    )?;
    Ok(rows
        .iter()
        .map(|r| {
            let item = Item {
                target_id: r.str("target_id"),
                sha: r.opt_str("sha"),
                refs: r.str("refs").lines().filter(|l| !l.is_empty()).map(str::to_string).collect(),
                removed: r.opt_str("removed_at").is_some(),
                skipped: r.opt_str("skipped_sha").map(|sha| (sha, r.str("skip_reason"))),
            };
            (r.str("path"), item)
        })
        .collect())
}

/// Who can see a topic's posts besides admins (who see everything).
struct Audience {
    name: String,
    private: bool,
    /// Members who aren't admins.
    members: BTreeSet<String>,
}

impl Audience {
    fn of(db: &dyn Db, topic_id: &str) -> ApiResult<Option<Audience>> {
        let Some(t) = db.one("SELECT name, visibility FROM topics WHERE id = ?", &params![topic_id])? else { return Ok(None) };
        let members = db
            .query(
                "SELECT m.user_id FROM topic_members m JOIN users u ON u.id = m.user_id WHERE m.topic_id = ? AND u.role != 'admin'",
                &params![topic_id],
            )?
            .iter()
            .map(|r| r.str("user_id"))
            .collect();
        Ok(Some(Audience { name: t.str("name"), private: t.str("visibility") == "private", members }))
    }

    /// Whether `other` shows posts to someone this topic doesn't: it's public while this one is
    /// private, or it has a member (not an admin) this one lacks.
    fn exceeded_by(&self, other: &Audience) -> bool {
        self.private && (!other.private || !other.members.is_subset(&self.members))
    }
}

/// Why a file's folder (or a folder above it) is blocked, if it is.
fn blocked_by(plan: &Plan, path: &str) -> Option<String> {
    let mut dir = dir_of(path);
    while !dir.is_empty() {
        if let Some(why) = plan.blocked.get(dir) {
            return Some(why.clone());
        }
        dir = dir_of(dir);
    }
    None
}

/// A synced post is never visible to more people than the source's topic. A folder's topic that
/// is, now (made public, or given members the source's topic lacks since the last sync), gets
/// none of the source's posts: each goes back in the source's topic first, so taking it out never
/// leaves it in fewer or wider topics, and then comes out of that one; each repaired post's change
/// of topics is recorded as `post.moved`. Such folders are blocked
/// (`plan.blocked`) and their files wait, marked to be synced again, until it's fixed. No topic's
/// visibility is changed. Runs before reading, and again in the step that writes, since topics can
/// change while files are fetched. `Some` says why the sync can't go on.
fn guard(ctx: &mut Ctx, j: &DocsJob, plan: &mut Plan, now: DateTime<Utc>) -> ApiResult<Option<String>> {
    let db = ctx.db;
    let Some(target) = Audience::of(db, &j.source.topic_id)? else {
        return Ok(Some("The source's topic was deleted.".into()));
    };
    plan.blocked.clear();
    let source_id = j.source.id.clone();
    let writer = super::actor(db, &j.source.owner_id)?.user_id;
    let lapsed = "SELECT id FROM users WHERE role != 'admin' OR deactivated_at IS NOT NULL";
    // Someone who wrote for this source while an admin, and isn't one now, keeps nothing through
    // its authorship: its posts and images pass to the admin it writes as now (authors and
    // uploaders always see their own).
    db.execute(
        &format!(
            "UPDATE posts SET author_id = ? WHERE author_id IN ({lapsed})
               AND id IN (SELECT target_id FROM docs_items WHERE source_id = ? AND kind = 'doc')"
        ),
        &params![writer.clone(), source_id.clone()],
    )?;
    db.execute(
        &format!(
            "UPDATE files SET uploaded_by = ? WHERE uploaded_by IN ({lapsed})
               AND id IN (SELECT target_id FROM docs_items WHERE source_id = ? AND kind = 'image')"
        ),
        &params![writer, source_id.clone()],
    )?;
    // Each repaired post's topics before its first repair, to record what changed once all are done.
    let mut repaired: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let topics_of = |post: &str| -> ApiResult<BTreeSet<String>> {
        Ok(db.query("SELECT topic_id FROM post_topics WHERE post_id = ?", &params![post])?.iter().map(|r| r.str("topic_id")).collect())
    };
    for (folder, topic_id) in &plan.folders {
        // Memberships the sync gave when it made this topic go once their person has left the
        // source's topic. Any other membership is someone's choice and stays; if it lets more
        // people in than the source's topic, the check below keeps the source's posts out.
        let target_members = "SELECT user_id FROM topic_members WHERE topic_id = ?";
        db.execute(
            &format!(
                "DELETE FROM topic_members WHERE topic_id = ? AND user_id NOT IN ({target_members})
                   AND EXISTS (SELECT 1 FROM docs_memberships g WHERE g.topic_id = topic_members.topic_id
                     AND g.user_id = topic_members.user_id AND g.added_at = topic_members.added_at)"
            ),
            &params![topic_id.clone(), j.source.topic_id.clone()],
        )?;
        // Forget grants that are gone, or that someone made again (theirs now).
        db.execute(
            "DELETE FROM docs_memberships WHERE topic_id = ? AND NOT EXISTS (SELECT 1 FROM topic_members m
               WHERE m.topic_id = docs_memberships.topic_id AND m.user_id = docs_memberships.user_id AND m.added_at = docs_memberships.added_at)",
            &params![topic_id.clone()],
        )?;
        let Some(a) = Audience::of(db, topic_id)? else { continue };
        if !target.exceeded_by(&a) {
            continue;
        }
        let synced = "SELECT target_id FROM docs_items WHERE source_id = ? AND kind = 'doc'";
        for p in db.query(
            &format!("SELECT post_id FROM post_topics WHERE topic_id = ? AND post_id IN ({synced})"),
            &params![topic_id.clone(), source_id.clone()],
        )? {
            let post = p.str("post_id");
            if let std::collections::btree_map::Entry::Vacant(slot) = repaired.entry(post) {
                let before = topics_of(slot.key())?;
                slot.insert(before);
            }
        }
        db.execute(
            &format!(
                "INSERT INTO post_topics (post_id, topic_id, pinned, added_at)
                 SELECT pt.post_id, ?, 0, ? FROM post_topics pt WHERE pt.topic_id = ? AND pt.post_id IN ({synced})
                 ON CONFLICT DO NOTHING"
            ),
            &params![j.source.topic_id.clone(), ts(now), topic_id.clone(), source_id.clone()],
        )?;
        db.execute(
            &format!("DELETE FROM post_topics WHERE topic_id = ? AND post_id IN ({synced})"),
            &params![topic_id.clone(), source_id.clone()],
        )?;
        // Synced again once the topic is fixed, to be put back in it.
        let prefix = format!("{folder}/");
        db.execute(
            "UPDATE docs_items SET sha = NULL WHERE source_id = ? AND kind = 'doc' AND substr(path, 1, ?) = ?",
            &params![source_id.clone(), prefix.chars().count() as i64, prefix],
        )?;
        let why = format!(
            "the topic “{}” for its folder shows posts to people who can't see “{}”. Make it private with only their shared members, or delete it and the next sync makes a new one",
            a.name, target.name
        );
        plan.blocked.insert(folder.clone(), why);
    }
    // Each repaired post's change of topics is recorded like any other (see `posts::moved_event`),
    // once, on its topics after every repair.
    for (post, before) in repaired {
        let after = topics_of(&post)?;
        let added: Vec<String> = after.difference(&before).cloned().collect();
        let removed: Vec<String> = before.difference(&after).cloned().collect();
        if !(added.is_empty() && removed.is_empty()) {
            posts::moved_event(ctx, &post, &added, &removed)?;
        }
    }
    Ok(None)
}

/// Archives a synced post (it's gone from the repository) or publishes it again (it's back).
fn set_status(ctx: &mut Ctx, post_id: &str, status: &str) -> ApiResult<bool> {
    let Some(row) = ctx.db.one("SELECT status, deleted_at FROM posts WHERE id = ?", &params![post_id])? else { return Ok(false) };
    if row.opt_str("deleted_at").is_some() || row.str("status") == status {
        return Ok(false);
    }
    posts::update_post(
        ctx,
        posts::UpdatePostInput {
            id: post_id.to_string(),
            title: None,
            content: None,
            topic_ids: None,
            add_topic_ids: None,
            remove_topic_ids: None,
            status: Some(status.to_string()),
            is_template: None,
            base_version: None,
            note: None,
        },
    )?;
    Ok(true)
}

/// A GitHub App source's token arrived: list the folder with it. A repository renamed on GitHub
/// keeps its id; the source follows its new name, so links point at the right place.
fn minted(db: &dyn Db, j: &mut DocsJob, replies: &[HttpReply], link: bool, now: DateTime<Utc>) -> ApiResult<Step> {
    let Link::GitHubApp { installation_id, repo_id } = j.source.link else {
        return Err(ApiError::internal("only GitHub App sources mint tokens"));
    };
    if link && let Some(reply) = replies.get(1) {
        super::github_app::record_link(db, installation_id, super::github_app::read_link(reply))?;
    }
    let reply = replies.first().cloned().unwrap_or_default();
    let minted = match super::github_app::read_token(&reply, repo_id) {
        Ok(m) => m,
        Err(message) => {
            // GitHub says the installation can't reach the repository: it waits, disconnected,
            // until it's put back (see `github_app::ReposJob`).
            if reply.status == 422 {
                db.execute(
                    "UPDATE docs_source_links SET disconnected = ? WHERE source_id = ? AND disconnected IS NULL",
                    &params![super::github_app::REPOSITORY_REMOVED, j.source.id.clone()],
                )?;
            }
            return fail(db, j, &message, now);
        }
    };
    if let Some(name) = minted.full_name.filter(|n| *n != j.source.repo.repo) {
        db.execute("UPDATE docs_sources SET repo = ?, updated_at = ? WHERE id = ?", &params![name.clone(), ts(now), j.source.id.clone()])?;
        j.source.repo.repo = name;
    }
    j.source.cred.token = minted.token;
    j.phase = Phase::Listing;
    Ok(Step::Fetch(j.source.repo.tree_calls(j.source.token())))
}

/// Reads the folder's listing, works out what changed, and asks for this run's files.
fn listing(db: &dyn Db, cfg: &HostConfig, j: &mut DocsJob, replies: &[HttpReply], now: DateTime<Utc>) -> ApiResult<Step> {
    let source_id = j.source.id.clone();
    let has_token = !j.source.token().is_empty();
    let entries = match j.source.repo.read_tree(replies, has_token) {
        Ok(e) => e,
        Err(message) => return fail(db, j, &message, now),
    };
    let tree_docs: BTreeMap<String, Entry> = entries.iter().filter(|e| is_doc(&e.path)).map(|e| (e.path.clone(), e.clone())).collect();
    let tree_images: BTreeMap<String, Entry> = entries.iter().filter(|e| is_image(&e.path)).map(|e| (e.path.clone(), e.clone())).collect();
    if tree_docs.len() > MAX_DOCS {
        let message = format!(
            "{} has {} Markdown files; a docs sync takes at most {MAX_DOCS}. Choose a smaller folder, or split it into several sources.",
            j.source.repo.label(),
            tree_docs.len()
        );
        return fail(db, j, &message, now);
    }
    if !super::holds(db, TABLE, source_id.as_str().into(), &j.lease)? {
        return Ok(lost());
    }
    let mut docs = items(db, &source_id, "doc")?;
    if tree_docs.is_empty() && docs.values().any(|d| !d.removed) {
        let message = format!(
            "{} has no Markdown files on {} now, so nothing was archived. Check the branch and folder.",
            j.source.repo.label(),
            j.source.repo.branch
        );
        return fail(db, j, &message, now);
    }
    let mut ctx = super::ctx(db, cfg, &j.source.owner_id, &j.base_url, now)?;
    j.result.files = tree_docs.len();
    // Topics first: posts leave folder topics that got wider before anything here records an
    // event about them.
    let folders = items(db, &source_id, "folder")?.into_iter().map(|(p, i)| (p, i.target_id)).collect();
    let mut plan = Plan { folders, ..Plan::default() };
    if let Some(message) = guard(&mut ctx, j, &mut plan, now)? {
        return fail(db, j, &message, now);
    }
    // Paths that files appeared at (new, back or moved there) and images that changed: files that
    // link to them are synced again.
    let mut changed: BTreeSet<String> = BTreeSet::new();

    // A file gone from one path whose exact contents appeared at one new path was renamed.
    let gone: Vec<String> = docs.iter().filter(|(p, d)| !d.removed && !tree_docs.contains_key(*p)).map(|(p, _)| p.clone()).collect();
    let fresh: Vec<&Entry> = tree_docs.values().filter(|e| !docs.contains_key(&e.path)).collect();
    let mut moved: HashMap<String, String> = HashMap::new();
    // Links to files that went or moved keep pointing at their posts.
    let mut aliases: BTreeMap<String, String> =
        docs.iter().filter(|(p, d)| d.removed && !tree_docs.contains_key(*p)).map(|(p, d)| (p.clone(), d.target_id.clone())).collect();
    for old in &gone {
        let Some(sha) = docs[old].sha.clone() else { continue };
        let same_sha_gone = gone.iter().filter(|g| docs[*g].sha.as_deref() == Some(sha.as_str())).count();
        let targets: Vec<&&Entry> = fresh.iter().filter(|e| e.sha == sha).collect();
        if same_sha_gone == 1 && targets.len() == 1 && !moved.values().any(|v| v == &targets[0].path) {
            moved.insert(old.clone(), targets[0].path.clone());
        }
    }
    for (old, new) in &moved {
        // Synced again at its new path: its title, links and folder may differ there.
        db.execute(
            "UPDATE docs_items SET path = ?, sha = NULL WHERE source_id = ? AND kind = 'doc' AND path = ?",
            &params![new.clone(), source_id.clone(), old.clone()],
        )?;
        let item = docs.remove(old).expect("a gone file");
        aliases.insert(old.clone(), item.target_id.clone());
        docs.insert(new.clone(), Item { sha: None, ..item });
        changed.insert(new.clone());
        j.result.renamed += 1;
    }
    for old in gone.iter().filter(|g| !moved.contains_key(*g)) {
        let item = &docs[old];
        if item.sha.is_none() && ctx.db.one("SELECT 1 AS ok FROM posts WHERE id = ?", &params![item.target_id.clone()])?.is_none() {
            // Never synced: there's no post to keep.
            db.execute(
                "DELETE FROM docs_items WHERE source_id = ? AND kind = 'doc' AND path = ?",
                &params![source_id.clone(), old.clone()],
            )?;
            continue;
        }
        aliases.insert(old.clone(), item.target_id.clone());
        if set_status(&mut ctx, &item.target_id, "archived")? {
            j.result.archived += 1;
        }
        db.execute(
            "UPDATE docs_items SET removed_at = ? WHERE source_id = ? AND kind = 'doc' AND path = ?",
            &params![ts(now), source_id.clone(), old.clone()],
        )?;
    }
    docs.retain(|p, _| tree_docs.contains_key(p));

    // New files get their post's id now, so links to them work before they're synced.
    let mut revive: BTreeSet<String> = BTreeSet::new();
    for path in tree_docs.keys() {
        match docs.get_mut(path) {
            None => {
                let id = new_id();
                db.execute(
                    "INSERT INTO docs_items (source_id, kind, path, target_id) VALUES (?, 'doc', ?, ?)",
                    &params![source_id.clone(), path.clone(), id.clone()],
                )?;
                docs.insert(path.clone(), Item { target_id: id, sha: None, refs: vec![], removed: false, skipped: None });
                changed.insert(path.clone());
            }
            // Back in the repository. It stays marked removed until it's synced and its post is
            // published again, however many runs that takes.
            Some(item) if item.removed => {
                if item.sha.is_some() {
                    db.execute(
                        "UPDATE docs_items SET sha = NULL WHERE source_id = ? AND kind = 'doc' AND path = ?",
                        &params![source_id.clone(), path.clone()],
                    )?;
                    item.sha = None;
                }
                revive.insert(path.clone());
                changed.insert(path.clone());
            }
            Some(_) => {}
        }
    }
    plan.docs = aliases;
    plan.docs.extend(docs.iter().map(|(p, d)| (p.clone(), d.target_id.clone())));

    // Images: the ones uploaded at their current version are reused.
    let uploaded = items(db, &source_id, "image")?;
    let file_ids: Vec<String> = uploaded.values().map(|i| i.target_id.clone()).filter(|id| !id.is_empty()).collect();
    let stored: HashMap<String, String> = query_in(db, "SELECT id, name FROM files WHERE id IN ({in})", &file_ids, &[])?
        .iter()
        .map(|f| (f.str("id"), f.str("name")))
        .collect();
    for (path, item) in &uploaded {
        let current = tree_images.get(path).is_some_and(|e| item.sha.as_deref() == Some(e.sha.as_str()));
        match (current, item.target_id.as_str()) {
            (true, "") => {
                plan.unusable.insert(path.clone());
            }
            (true, id) if stored.contains_key(id) => {
                plan.uploaded.insert(path.clone(), (id.to_string(), stored[id].clone()));
            }
            _ => {
                changed.insert(path.clone());
            }
        }
    }
    // An image not uploaded yet (it was added, or couldn't be read last time): files that show it
    // try again.
    changed.extend(tree_images.keys().filter(|p| !uploaded.contains_key(*p)).cloned());
    plan.images = tree_images;
    let blocked = |path: &str| blocked_by(&plan, path);
    for (_, d) in docs.iter_mut().filter(|(p, _)| blocked(p).is_some()) {
        d.sha = None;
    }

    // Files that link to a changed path are synced again, now or in a later run.
    let dependents: Vec<String> =
        docs.iter().filter(|(_, d)| d.sha.is_some() && d.refs.iter().any(|x| changed.contains(x))).map(|(p, _)| p.clone()).collect();
    for path in &dependents {
        db.execute(
            "UPDATE docs_items SET sha = NULL WHERE source_id = ? AND kind = 'doc' AND path = ?",
            &params![source_id.clone(), path.clone()],
        )?;
        if let Some(d) = docs.get_mut(path) {
            d.sha = None;
        }
    }

    // What this run reads. Posts in the trash are left alone; erased ones are made again, with
    // the same id, so links to them work again.
    let post_ids: Vec<String> = docs.values().map(|d| d.target_id.clone()).collect();
    let found: HashMap<String, bool> = query_in(db, "SELECT id, deleted_at FROM posts WHERE id IN ({in})", &post_ids, &[])?
        .iter()
        .map(|p| (p.str("id"), p.opt_str("deleted_at").is_some()))
        .collect();
    let trashed: BTreeSet<String> = found.iter().filter(|(_, t)| **t).map(|(id, _)| id.clone()).collect();
    for (path, d) in docs.iter_mut().filter(|(_, d)| d.sha.is_some() && !found.contains_key(&d.target_id)) {
        db.execute(
            "UPDATE docs_items SET sha = NULL WHERE source_id = ? AND kind = 'doc' AND path = ?",
            &params![source_id.clone(), path.clone()],
        )?;
        d.sha = None;
    }
    let mut todo: Vec<Work> = vec![];
    for (path, entry) in &tree_docs {
        let item = &docs[path];
        if item.sha.as_deref() == Some(entry.sha.as_str()) {
            j.result.unchanged += 1;
        } else if let Some(why) = blocked(path) {
            j.result.skip(path, why);
        } else if let Some((_, why)) = item.skipped.as_ref().filter(|(sha, _)| *sha == entry.sha) {
            j.result.skip(path, why.clone());
        } else if trashed.contains(&item.target_id) {
            j.result.skip(path, "its post is in the trash; restore it to sync it again");
        } else if entry.size.is_some_and(|s| s > MAX_DOC_BYTES) {
            j.result.skip(path, format!("larger than {} MB", MAX_DOC_BYTES / 1_000_000));
        } else {
            todo.push(Work { path: path.clone(), sha: entry.sha.clone(), post_id: item.target_id.clone(), revive: revive.contains(path) });
        }
    }
    j.result.remaining = todo.len().saturating_sub(DOCS_PER_RUN);
    todo.truncate(DOCS_PER_RUN);
    if todo.is_empty() {
        return write(&mut ctx, j, plan, vec![], vec![], now);
    }
    let calls = todo.iter().map(|w| j.source.repo.blob_call(&w.sha, j.source.token())).collect();
    plan.batch = todo;
    j.phase = Phase::Reading(plan);
    j.staged.append(&mut ctx.effects);
    Ok(Step::Fetch(calls))
}

/// The title a file gets when it has none of its own: its name, or its folder's for a README.
fn fallback_title(repo: &Repo, path: &str) -> String {
    let file = name_of(path);
    let stem = file.rsplit_once('.').map(|(s, _)| s).unwrap_or(file);
    if matches!(stem.to_ascii_lowercase().as_str(), "readme" | "index") {
        let dir = dir_of(path);
        let folder = if dir.is_empty() { repo.folder.as_str() } else { dir };
        let name = folder.rsplit('/').next().filter(|n| !n.is_empty()).unwrap_or_else(|| repo.repo.rsplit('/').next().unwrap_or("Docs"));
        return rewrite::humanize(name);
    }
    rewrite::humanize(stem)
}

/// Reads this run's files and asks for the images they show that aren't uploaded yet.
fn reading(db: &dyn Db, cfg: &HostConfig, j: &mut DocsJob, mut plan: Plan, replies: &[HttpReply], now: DateTime<Utc>) -> ApiResult<Step> {
    let has_token = !j.source.token().is_empty();
    let mut texts: Vec<Text> = vec![];
    for (work, reply) in plan.batch.iter().zip(replies) {
        let never = match j.source.repo.read_blob(reply, has_token) {
            Ok(bytes) if bytes.len() as u64 > MAX_DOC_BYTES => "larger than 1 MB".to_string(),
            Ok(bytes) => {
                let md = String::from_utf8_lossy(&bytes).replace("\r\n", "\n");
                let (title, body) = rewrite::title_and_body(&md, &fallback_title(&j.source.repo, &work.path));
                texts.push(Text { work: work.clone(), title, body });
                continue;
            }
            // The app answered, but not with a file that fits in an answer: too large.
            Err(_) if reply.ok() => format!("larger than {} MB", crate::connect::MAX_REPLY_BYTES / (1024 * 1024)),
            // Tried again at the next sync.
            Err(message) => {
                j.result.skip(&work.path, message);
                continue;
            }
        };
        // Not read again until the file changes, so files like it can't hold up the rest.
        db.execute(
            "UPDATE docs_items SET skipped_sha = ?, skip_reason = ? WHERE source_id = ? AND kind = 'doc' AND path = ?",
            &params![work.sha.clone(), never.clone(), j.source.id.clone(), work.path.clone()],
        )?;
        j.result.skip(&work.path, never);
    }
    // Images these files show that aren't uploaded at their current version.
    let mut wanted: Vec<String> = vec![];
    let mut needs: Vec<BTreeSet<String>> = vec![];
    for t in &texts {
        let mut mine = BTreeSet::new();
        for site in rewrite::sites(&t.body).iter().filter(|s| s.image) {
            if let Some((Target::Inside(p), _)) = rewrite::resolve(&j.source.repo.folder, dir_of(&t.work.path), &site.dest)
                && let Some(entry) = plan.images.get(&p)
                && !plan.uploaded.contains_key(&p)
                && !plan.unusable.contains(&p)
            {
                if entry.size.is_some_and(|s| s > MAX_IMAGE_BYTES) {
                    plan.unusable.insert(p);
                    continue;
                }
                if !wanted.contains(&p) {
                    wanted.push(p.clone());
                }
                mine.insert(p);
            }
        }
        needs.push(mine);
    }
    let fetch: BTreeSet<String> = wanted.into_iter().take(IMAGES_PER_RUN).collect();
    // Files that show images beyond this run's share wait for the next run.
    let mut kept = vec![];
    for (t, mine) in texts.into_iter().zip(needs) {
        if mine.iter().all(|p| fetch.contains(p)) {
            kept.push(t);
        } else {
            j.result.remaining += 1;
        }
    }
    let mut ctx = super::ctx(db, cfg, &j.source.owner_id, &j.base_url, now)?;
    if fetch.is_empty() {
        return write(&mut ctx, j, plan, kept, vec![], now);
    }
    plan.fetching = fetch.iter().map(|p| Fetching { path: p.clone(), sha: plan.images[p].sha.clone(), file_id: new_id() }).collect();
    let calls = plan.fetching.iter().map(|f| j.source.repo.blob_call(&f.sha, j.source.token())).collect();
    j.phase = Phase::Images(plan, kept);
    Ok(Step::Fetch(calls))
}

/// An image read and checked, ready to store.
struct Ready {
    fetching: Fetching,
    content_type: &'static str,
    bytes: Vec<u8>,
}

fn images(
    db: &dyn Db,
    cfg: &HostConfig,
    j: &mut DocsJob,
    mut plan: Plan,
    texts: Vec<Text>,
    replies: &[HttpReply],
    now: DateTime<Utc>,
) -> ApiResult<Step> {
    let has_token = !j.source.token().is_empty();
    let mut ready = vec![];
    for (f, reply) in std::mem::take(&mut plan.fetching).into_iter().zip(replies) {
        let bytes = match j.source.repo.read_blob(reply, has_token) {
            Ok(b) => b,
            Err(_) if reply.ok() => {
                // Cut short, so too large.
                plan.unusable.insert(f.path.clone());
                continue;
            }
            Err(message) => {
                // Linked to the repository this time; the next sync tries again.
                j.result.skip(&f.path, message);
                continue;
            }
        };
        match files::sniff(&bytes).filter(|t| files::INLINE_TYPES.contains(t)) {
            Some(t) if bytes.len() as u64 <= MAX_IMAGE_BYTES => ready.push(Ready { fetching: f, content_type: t, bytes }),
            _ => {
                plan.unusable.insert(f.path.clone());
            }
        }
    }
    let mut ctx = super::ctx(db, cfg, &j.source.owner_id, &j.base_url, now)?;
    write(&mut ctx, j, plan, texts, ready, now)
}

/// The sub-topic for a folder (creating it, and its parents, as needed); the source's topic for
/// the folder itself.
fn folder_topic(ctx: &mut Ctx, j: &DocsJob, plan: &mut Plan, dir: &str) -> ApiResult<String> {
    if dir.is_empty() {
        return Ok(j.source.topic_id.clone());
    }
    if let Some(id) = plan.folders.get(dir)
        && ctx.db.one("SELECT 1 AS ok FROM topics WHERE id = ?", &params![id.clone()])?.is_some()
    {
        return Ok(id.clone());
    }
    let parent = folder_topic(ctx, j, plan, dir_of(dir))?;
    // As visible as the source's topic: in a private one, private with its members.
    let visibility =
        ctx.db.one("SELECT visibility FROM topics WHERE id = ?", &params![j.source.topic_id.clone()])?.map(|r| r.str("visibility"));
    let members = match visibility.as_deref() {
        Some("private") => Some(
            ctx.db
                .query("SELECT user_id FROM topic_members WHERE topic_id = ?", &params![j.source.topic_id.clone()])?
                .iter()
                .map(|r| r.str("user_id"))
                .collect(),
        ),
        _ => None,
    };
    let name = topic_name(ctx.db, &parent, name_of(dir))?;
    let topic = topics::create_topic(
        ctx,
        topics::CreateTopicInput {
            name,
            description: Some(format!("Synced from {}", j.source.repo.repo_path(dir))),
            icon: None,
            color: None,
            parent_id: Some(parent),
            visibility,
            members,
        },
    )?;
    // Creating a private topic makes the writer a member; that's only right if they're in the
    // source's topic too.
    ctx.db.execute(
        "DELETE FROM topic_members WHERE topic_id = ? AND user_id = ?
           AND NOT EXISTS (SELECT 1 FROM topic_members t WHERE t.topic_id = ? AND t.user_id = ?)",
        &params![topic.topic.id.clone(), ctx.actor.user_id.clone(), j.source.topic_id.clone(), ctx.actor.user_id.clone()],
    )?;
    // Every membership it has now, the sync gave (see `docs_memberships`).
    ctx.db.execute(
        "INSERT INTO docs_memberships (source_id, topic_id, user_id, added_at)
         SELECT ?, topic_id, user_id, added_at FROM topic_members WHERE topic_id = ?
         ON CONFLICT(topic_id, user_id) DO UPDATE SET added_at = excluded.added_at",
        &params![j.source.id.clone(), topic.topic.id.clone()],
    )?;
    ctx.db.execute(
        "INSERT INTO docs_items (source_id, kind, path, target_id) VALUES (?, 'folder', ?, ?)
         ON CONFLICT(source_id, kind, path) DO UPDATE SET target_id = excluded.target_id",
        &params![j.source.id.clone(), dir, topic.topic.id.clone()],
    )?;
    plan.folders.insert(dir.to_string(), topic.topic.id.clone());
    Ok(topic.topic.id)
}

/// A folder's topic name: the folder's name, humanized, cut to [`MAX_TOPIC_NAME`] characters, and
/// numbered when a sibling already has it. The folder's full path stays the mapping's key.
fn topic_name(db: &dyn Db, parent: &str, folder: &str) -> ApiResult<String> {
    let base = rewrite::humanize(folder);
    for n in 1..1000 {
        let suffix = if n == 1 { String::new() } else { format!(" ({n})") };
        let head: String = base.chars().take(MAX_TOPIC_NAME - suffix.chars().count()).collect();
        let name = format!("{}{suffix}", head.trim_end());
        if db.one("SELECT 1 AS ok FROM topics WHERE parent_id = ? AND name = ?", &params![parent, name.clone()])?.is_none() {
            return Ok(name);
        }
    }
    Ok(format!("{} {}", base.chars().take(MAX_TOPIC_NAME - 11).collect::<String>().trim_end(), new_id()))
}

/// Puts a synced post in the source's topic and its folder's, and out of the source's other
/// folders' topics. Topics people added it to stay.
/// Returns the topics it added and removed.
fn place(ctx: &Ctx, j: &DocsJob, plan: &Plan, post_id: &str, folder: &str) -> ApiResult<(Vec<String>, Vec<String>)> {
    let topics = || -> ApiResult<BTreeSet<String>> {
        Ok(ctx
            .db
            .query("SELECT topic_id FROM post_topics WHERE post_id = ?", &params![post_id])?
            .iter()
            .map(|r| r.str("topic_id"))
            .collect())
    };
    let before = topics()?;
    let wanted: BTreeSet<&str> = [j.source.topic_id.as_str(), folder].into_iter().collect();
    for t in plan.folders.values().filter(|t| !wanted.contains(t.as_str())) {
        ctx.db.execute("DELETE FROM post_topics WHERE post_id = ? AND topic_id = ?", &params![post_id, t.clone()])?;
    }
    for t in wanted {
        ctx.db.execute(
            "INSERT INTO post_topics (post_id, topic_id, pinned, added_at) VALUES (?, ?, 0, ?) ON CONFLICT DO NOTHING",
            &params![post_id, t, ctx.now_s()],
        )?;
    }
    let after = topics()?;
    Ok((after.difference(&before).cloned().collect(), before.difference(&after).cloned().collect()))
}

/// A file's Markdown with its links and images pointed at what they are here, and the paths it
/// refers to.
fn rewrite_links(j: &DocsJob, plan: &Plan, t: &Text, used: &mut BTreeSet<String>) -> (String, Vec<String>) {
    let repo = &j.source.repo;
    let dir = dir_of(&t.work.path);
    let mut refs: BTreeSet<String> = BTreeSet::new();
    let mut edits = vec![];
    for site in rewrite::sites(&t.body) {
        let Some((target, fragment)) = rewrite::resolve(&repo.folder, dir, &site.dest) else { continue };
        let to = match target {
            Target::Inside(p) => {
                refs.insert(p.clone());
                if site.image {
                    match plan.uploaded.get(&p) {
                        Some((id, name)) => {
                            used.insert(p.clone());
                            files::file_path(id, name)
                        }
                        None => repo.file_url(&repo.repo_path(&p), true),
                    }
                } else {
                    let doc = [p.clone(), format!("{p}/README.md"), format!("{p}/readme.md"), format!("{p}/index.md")]
                        .into_iter()
                        .find_map(|c| plan.docs.get(c.trim_start_matches('/')));
                    match doc {
                        Some(id) => format!("/p/{id}{fragment}"),
                        None => format!("{}{fragment}", repo.file_url(&repo.repo_path(&p), false)),
                    }
                }
            }
            Target::Repo(p) => format!("{}{fragment}", repo.file_url(&p, site.image)),
        };
        edits.push((site.range, to));
    }
    (rewrite::replace(&t.body, edits), refs.into_iter().take(MAX_REFS).collect())
}

/// Writes this run's posts and images, and records how the sync went.
fn write(ctx: &mut Ctx, j: &mut DocsJob, mut plan: Plan, texts: Vec<Text>, ready: Vec<Ready>, now: DateTime<Utc>) -> ApiResult<Step> {
    let db = ctx.db;
    let source_id = j.source.id.clone();
    if !super::holds(db, TABLE, source_id.as_str().into(), &j.lease)? {
        return Ok(lost());
    }
    // Topics may have changed while the files were fetched.
    if let Some(message) = guard(ctx, j, &mut plan, now)? {
        j.staged.append(&mut ctx.effects);
        return fail(db, j, &message, now);
    }
    for r in &ready {
        let name = files::clean_name(name_of(&r.fetching.path));
        plan.uploaded.insert(r.fetching.path.clone(), (r.fetching.file_id.clone(), name));
    }
    let note = format!("Synced from {} ({}, {})", j.source.repo.provider.name(), j.source.repo.repo, j.source.repo.branch);
    let mut first_post: HashMap<String, String> = HashMap::new();
    let mut reused: BTreeSet<String> = BTreeSet::new();
    for t in &texts {
        if let Some(why) = blocked_by(&plan, &t.work.path) {
            j.result.skip(&t.work.path, why);
            continue;
        }
        let mut used = BTreeSet::new();
        let (body, refs) = rewrite_links(j, &plan, t, &mut used);
        if body.len() > crate::ops::MAX_CONTENT {
            // Its links, pointed here or at the repository, made it longer than a post may be.
            // Skipped until the file changes, so the rest of the batch goes on.
            let why = "longer than a post may be (2 MB) once its links point here";
            db.execute(
                "UPDATE docs_items SET skipped_sha = ?, skip_reason = ? WHERE source_id = ? AND kind = 'doc' AND path = ?",
                &params![t.work.sha.clone(), why, source_id.clone(), t.work.path.clone()],
            )?;
            j.result.skip(&t.work.path, why);
            continue;
        }
        let folder = folder_topic(ctx, j, &mut plan, dir_of(&t.work.path))?;
        let synced = posts::sync_post(ctx, &t.work.post_id, &t.title, &body, &note)?;
        match synced {
            Synced::Created => j.result.created += 1,
            Synced::Updated => j.result.updated += 1,
            Synced::Unchanged => j.result.unchanged += 1,
            Synced::Trashed => {
                j.result.skip(&t.work.path, "its post is in the trash; restore it to sync it again");
                continue;
            }
        }
        // Events only once the post is in its topics (and published again, if it came back): what
        // hears of them decides who may see the post from where it is.
        let (added, removed) = place(ctx, j, &plan, &t.work.post_id, &folder)?;
        if t.work.revive && set_status(ctx, &t.work.post_id, "published")? {
            j.result.restored += 1;
        }
        posts::synced_event(ctx, &t.work.post_id, synced)?;
        // A file that moved to another folder moved its post to another topic, whether or not its
        // text changed: recorded like any change of topics (a new post's first topics aren't one).
        if synced != Synced::Created && !(added.is_empty() && removed.is_empty()) {
            posts::moved_event(ctx, &t.work.post_id, &added, &removed)?;
        }
        // Images this sync stored earlier that belong to no post yet (the file showing them waited
        // for a later run) join this one. Only the sync's own records count: text naming some
        // other upload never attaches it (see `posts::Writer::Sync`).
        let own: Vec<String> = used.iter().filter_map(|p| plan.uploaded.get(p)).map(|(id, _)| id.clone()).collect();
        for id in &own {
            db.execute("UPDATE files SET post_id = ? WHERE id = ? AND post_id IS NULL", &params![t.work.post_id.clone(), id.clone()])?;
        }
        for p in used {
            if ready.iter().any(|r| r.fetching.path == p) {
                first_post.entry(p).or_insert_with(|| t.work.post_id.clone());
            } else {
                reused.insert(p);
            }
        }
        db.execute(
            "UPDATE docs_items SET sha = ?, refs = ?, synced_at = ?, removed_at = NULL, skipped_sha = NULL, skip_reason = NULL
             WHERE source_id = ? AND kind = 'doc' AND path = ?",
            &params![t.work.sha.clone(), refs.join("\n"), ts(now), source_id.clone(), t.work.path.clone()],
        )?;
    }
    j.result.images_reused = reused.len();
    // Images belong to the first post that shows them, and follow its visibility. Every synced post
    // is in the source's topic, so whoever sees one sees the others.
    for r in &ready {
        let (id, name) = plan.uploaded[&r.fetching.path].clone();
        files::store(ctx, &id, &name, r.content_type, &r.bytes, first_post.get(&r.fetching.path).map(String::as_str))?;
        save_image(db, &source_id, &r.fetching.path, &id, &r.fetching.sha)?;
        j.result.images_uploaded += 1;
    }
    for p in &plan.unusable {
        if let Some(entry) = plan.images.get(p) {
            save_image(db, &source_id, p, "", &entry.sha)?;
        }
    }
    j.result.done = j.result.remaining == 0;
    let value = serde_json::to_value(&j.result).map_err(|e| ApiError::internal(e.to_string()))?;
    let status = if j.result.done { "ok" } else { "partial" };
    super::finish(db, TABLE, source_id.as_str().into(), &j.lease, Ended { status, error: None, result: Some(value.clone()) }, now)?;
    let r = &j.result;
    if r.created + r.updated + r.archived + r.restored + r.renamed > 0 {
        emit(
            ctx,
            Event::new("docs.synced", "docs_source", &source_id, format!("synced docs from {}", j.source.repo.label()))
                .topic(&j.source.topic_id)
                .data(json!({ "created": r.created, "updated": r.updated, "archived": r.archived, "remaining": r.remaining }))
                .admin_only(),
        )?;
    }
    j.staged.append(&mut ctx.effects);
    Ok(Step::Done(Finish::Fill(value)))
}

fn save_image(db: &dyn Db, source_id: &str, path: &str, file_id: &str, sha: &str) -> ApiResult<()> {
    db.execute(
        "INSERT INTO docs_items (source_id, kind, path, target_id, sha) VALUES (?, 'image', ?, ?, ?)
         ON CONFLICT(source_id, kind, path) DO UPDATE SET target_id = excluded.target_id, sha = excluded.sha",
        &params![source_id, path, file_id, sha],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Webhooks

/// `POST /hooks/docs/<source id>`: GitHub or GitLab says the repository changed. GitHub signs the
/// body (`X-Hub-Signature-256: sha256=<hex HMAC-SHA256>`) and GitLab sends the secret itself
/// (`X-Gitlab-Token`). A push to another branch is ignored; any other push starts a sync, which
/// reads the repository itself.
pub(crate) fn hook(db: &dyn Db, cfg: &HostConfig, req: &Request, id: &str, base_url: &str, now: DateTime<Utc>) -> ApiResult<Outcome> {
    let Some(source) = Source::load(db, cfg, id)? else { return Err(ApiError::not_found("docs sync source")) };
    let secret = source.cred.field("webhook_secret").to_string();
    let event = match source.repo.provider {
        Provider::GitHub => {
            let expected = format!("sha256={}", super::hmac_hex(&secret, &[&req.body]));
            let given = req.header("x-hub-signature-256").unwrap_or_default();
            if secret.is_empty() || !secure_eq(given, &expected) {
                return Err(ApiError::unauthorized("the webhook's signature doesn't match this source's secret"));
            }
            req.header("x-github-event").unwrap_or_default()
        }
        Provider::GitLab => {
            if secret.is_empty() || !secure_eq(req.header("x-gitlab-token").unwrap_or_default(), &secret) {
                return Err(ApiError::unauthorized("the webhook's secret token doesn't match this source's secret"));
            }
            req.header("x-gitlab-event").unwrap_or_default()
        }
    };
    match event {
        "ping" => return Ok(hook_answer("pong")),
        "push" | "Push Hook" => {}
        _ => return Ok(hook_answer("ignored")),
    }
    let payload: Value = serde_json::from_slice(&req.body).unwrap_or_default();
    if let Some(r) = payload["ref"].as_str()
        && r != format!("refs/heads/{}", source.repo.branch)
    {
        return Ok(hook_answer("ignored"));
    }
    check_plan(db, cfg, now)?;
    let source_id = source.id.clone();
    match start(db, source, base_url, now)? {
        Some(job) => Ok(hook_started(job)),
        None => {
            super::mark_pending(db, TABLE, SqlValue::from(source_id), now)?;
            Ok(hook_answer("queued"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_are_sorted_out() {
        assert!(is_doc("guides/Setup.MD") && is_doc("a.markdown"));
        assert!(!is_doc(".github/ISSUE_TEMPLATE/bug.md") && !is_doc("node_modules/x/README.md") && !is_doc("a.mdx"));
        assert!(is_image("img/a.PNG") && !is_image("img/a.svg"));
        let repo = Repo {
            provider: Provider::GitHub,
            host: "github.com".into(),
            repo: "acme/docs".into(),
            branch: "main".into(),
            folder: "handbook".into(),
        };
        assert_eq!(fallback_title(&repo, "getting-started.md"), "Getting started");
        assert_eq!(fallback_title(&repo, "guides/README.md"), "Guides");
        assert_eq!(fallback_title(&repo, "README.md"), "Handbook");
    }
}
