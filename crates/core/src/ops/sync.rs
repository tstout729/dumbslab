//! People sync (BambooHR) and docs sync (GitHub, GitLab): admins set them up for the whole
//! workspace. The machinery lives in [`crate::sync`].

use chrono::Utc;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{DONE, Done, NoInput, clean};
use crate::connect::{self, Credential, Deferred};
use crate::db::{DbExt, Row};
use crate::error::{ApiError, ApiResult};
use crate::events::{Event, emit};
use crate::model::{TopicRef, UserRef, load_topic, topic_url, user_refs};
use crate::registry::{Access, Ctx, Op, op};
use crate::sync::docs::{self, DocsSyncResult, Source};
use crate::sync::people::{self, PeopleSyncRemoved, PeopleSyncResult};
use crate::sync::{self, SyncState};
use crate::util::new_secret;
use crate::{Effect, params};

/// Docs sync sources a workspace may have.
const MAX_SOURCES: i64 = 20;
const MAX_SECRET_CHARS: usize = 4096;

pub fn ops() -> Vec<Op> {
    vec![
        op("sync", "get_people_sync", "GET", "/people-sync", Access::Admin, get_people_sync)
            .title("People sync settings")
            .desc("The workspace's people sync from BambooHR: its company domain, whether changes in BambooHR start a sync (its webhook) and why not, and how the last sync went. Credentials are never shown.")
            .build(),
        op("sync", "set_people_sync", "PUT", "/people-sync", Access::Admin, set_people_sync)
            .title("Set up the people sync")
            .desc("Set up (or change) the people sync from BambooHR with the company domain and an API key. DumbSlab checks the key with BambooHR first and saves nothing if it doesn't work. Then it adds a webhook in BambooHR (replacing the one it added before), so changes there start a sync. If BambooHR won't let the key's user add webhooks, the sync is saved anyway, and `webhook_error` says why: add the webhook in BambooHR by hand and pass its private key as `webhook_key`. Leave the API key out to keep the saved one. Then run sync_people. A sync fills in title, department, location, work phone, pronouns and manager for people here whose email matches a BambooHR work email; it never adds, deactivates or removes anyone.")
            .idempotent()
            .build(),
        op("sync", "sync_people", "POST", "/people-sync/run", Access::Admin, sync_people)
            .title("Sync people now")
            .desc("Read BambooHR's active employees and update the matching people's profiles. Answers with what changed and which employees match nobody here.")
            .build(),
        op("sync", "remove_people_sync", "DELETE", "/people-sync", Access::Admin, remove_people_sync)
            .title("Remove the people sync")
            .desc("Stop syncing from BambooHR: delete the webhook DumbSlab added there, and forget the credentials. Profile details already synced stay.")
            .destructive()
            .build(),
        op("sync", "list_docs_sources", "GET", "/docs-sources", Access::Admin, list_docs_sources)
            .title("Docs sync sources")
            .desc("Repository folders whose Markdown files are kept as posts (docs sync), with each one's topic, webhook address and how its last sync went.")
            .build(),
        op("sync", "create_docs_source", "POST", "/docs-sources", Access::Admin, create_docs_source)
            .title("Add a docs sync source")
            .desc("Keep a GitHub or GitLab folder's Markdown files as posts in a topic, one way: each file is a post, sub-folders become sub-topics, relative links and images keep working, and synced posts are edited in the repository, not here. Give a read-only token for private repositories. Answers with the webhook secret, once: add a push webhook with it in GitHub or GitLab so pushes sync. Then run sync_docs_source.")
            .build(),
        op("sync", "update_docs_source", "PATCH", "/docs-sources/{id}", Access::Admin, update_docs_source)
            .title("Change a docs sync source")
            .desc("Replace its token (an empty string removes it), switch its branch, or make a new webhook secret (shown once). To sync another repository or folder, add a new source.")
            .build(),
        op("sync", "sync_docs_source", "POST", "/docs-sources/{id}/sync", Access::Admin, sync_docs_source)
            .title("Sync docs now")
            .desc("Sync a source's folder now. One run syncs at most 20 changed files and 10 images; when `remaining` is above 0, run it again to continue.")
            .build(),
        op("sync", "delete_docs_source", "DELETE", "/docs-sources/{id}", Access::Admin, delete_docs_source)
            .title("Remove a docs sync source")
            .desc("Stop syncing a folder and forget its credentials. Its posts and topics stay, as ordinary posts anyone with access can edit.")
            .destructive()
            .build(),
    ]
}

fn key_needed(ctx: &Ctx) -> ApiResult<()> {
    connect::key_of(ctx.cfg).map(|_| ()).map_err(|_| {
        ApiError::new(503, "sync_off", "Syncs aren't available on this server: it has no connector key to encrypt their credentials with.")
    })
}

fn secret_input(value: Option<String>, label: &str) -> ApiResult<Option<String>> {
    let value = value.map(|v| v.trim().to_string());
    if value.as_ref().is_some_and(|v| v.chars().count() > MAX_SECRET_CHARS) {
        return Err(ApiError::bad_request(format!("`{label}` is too long")));
    }
    Ok(value)
}

// ---------------------------------------------------------------------------
// People sync

#[derive(Debug, Serialize, JsonSchema)]
pub struct PeopleSync {
    /// Syncs are available on this server (it has a connector key).
    pub enabled: bool,
    /// A people sync is set up.
    pub configured: bool,
    /// `bamboohr`.
    pub provider: String,
    /// The BambooHR company domain: `acme` for acme.bamboohr.com.
    pub subdomain: Option<String>,
    /// Changes in BambooHR start a sync: a webhook's private key is saved, so its calls are checked.
    pub webhook: bool,
    /// DumbSlab added that webhook in BambooHR itself. When `webhook` is on and this is off, an admin added it by hand and pasted its private key.
    pub automatic_webhook: bool,
    /// Why changes in BambooHR don't start a sync on their own, or what to do about it: BambooHR wouldn't let DumbSlab add the webhook (save again once the key's user may add webhooks, or add it by hand), or the workspace moved address (save again).
    pub webhook_error: Option<String>,
    /// Where BambooHR sends webhooks.
    pub webhook_url: String,
    #[serde(flatten)]
    pub state: SyncState,
    pub last_result: Option<PeopleSyncResult>,
    /// Only in set_people_sync's answer: something to know about this change, such as an old webhook BambooHR wouldn't let DumbSlab delete.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notice: Option<String>,
}

fn people_row(ctx: &Ctx) -> ApiResult<Option<Row>> {
    ctx.db.one("SELECT * FROM people_sync WHERE id = 1", &[])
}

pub(crate) fn people_view(ctx: &Ctx) -> ApiResult<PeopleSync> {
    let row = people_row(ctx)?;
    let webhook_url = ctx.url(people::HOOK_PATH);
    Ok(PeopleSync {
        enabled: connect::enabled(ctx.cfg),
        configured: row.is_some(),
        provider: people::PROVIDER.into(),
        subdomain: row.as_ref().map(|r| r.str("subdomain")),
        webhook: row.as_ref().is_some_and(|r| r.bool("webhook")),
        automatic_webhook: row.as_ref().is_some_and(|r| r.bool("webhook") && r.opt_str("webhook_id").is_some()),
        webhook_error: row.as_ref().and_then(|r| people::webhook_problem(r, &webhook_url)),
        webhook_url,
        state: row.as_ref().map(|r| sync::state_of(r, ctx.now)).unwrap_or_default(),
        last_result: row.as_ref().and_then(|r| r.opt_str("last_result")).and_then(|v| serde_json::from_str(&v).ok()),
        notice: None,
    })
}

fn get_people_sync(ctx: &mut Ctx, _: NoInput) -> ApiResult<PeopleSync> {
    people_view(ctx)
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetPeopleSyncInput {
    /// The BambooHR company domain: `acme` for acme.bamboohr.com. `acme.bamboohr.com` or any address on it works too.
    pub subdomain: String,
    /// A BambooHR API key (in BambooHR: your name › API Keys). Its user must be able to see employees' work emails and job details, and to add webhooks for changes to start a sync. Checked with BambooHR before it's saved. Required the first time; leave out to keep the saved one.
    pub api_key: Option<String>,
    /// Only when DumbSlab can't add BambooHR's webhook itself (see `webhook_error`): the private key of a webhook you added in BambooHR that posts to `webhook_url`. DumbSlab then adds none. An empty string removes it, and DumbSlab adds its own again; leave out to keep the saved one.
    pub webhook_key: Option<String>,
}

fn set_people_sync(ctx: &mut Ctx, input: SetPeopleSyncInput) -> ApiResult<Deferred<PeopleSync>> {
    key_needed(ctx)?;
    let subdomain = people::valid_subdomain(&input.subdomain).map_err(ApiError::bad_request)?;
    let api_key = secret_input(input.api_key, "api_key")?;
    let webhook_key = secret_input(input.webhook_key, "webhook_key")?;
    // The host checks the key with BambooHR and adds its webhook, then saves (see sync::people).
    let job = people::setup_job(ctx, subdomain, api_key, webhook_key)?;
    ctx.effects.push(Effect::Connect(job));
    Ok(Deferred::Pending)
}

fn sync_people(ctx: &mut Ctx, _: NoInput) -> ApiResult<Deferred<PeopleSyncResult>> {
    key_needed(ctx)?;
    match people::start(ctx.db, ctx.cfg, &ctx.base_url, Utc::now())? {
        Some(job) => {
            ctx.effects.push(Effect::Connect(job));
            Ok(Deferred::Pending)
        }
        None => Err(ApiError::conflict("A people sync is already running. Try again in a minute.")),
    }
}

fn remove_people_sync(ctx: &mut Ctx, _: NoInput) -> ApiResult<Deferred<PeopleSyncRemoved>> {
    let row = people_row(ctx)?.ok_or_else(|| ApiError::not_found("people sync"))?;
    ctx.db.execute("DELETE FROM people_sync WHERE id = 1", &[])?;
    emit(ctx, Event::new("people_sync.removed", "people_sync", "1", "removed the people sync").admin_only())?;
    // Then the host deletes the webhook DumbSlab added in BambooHR. The sync is gone either way.
    match people::removal_job(ctx.cfg, &row) {
        Ok(Some(job)) => {
            ctx.effects.push(Effect::Connect(job));
            Ok(Deferred::Pending)
        }
        Ok(None) => Ok(Deferred::Ready(PeopleSyncRemoved { ok: true, notice: None })),
        Err(notice) => Ok(Deferred::Ready(PeopleSyncRemoved { ok: true, notice: Some(notice) })),
    }
}

// ---------------------------------------------------------------------------
// Docs sync

#[derive(Debug, Serialize, JsonSchema)]
pub struct DocsSource {
    pub id: String,
    /// `github` or `gitlab`.
    pub provider: String,
    /// `github.com`, `gitlab.com` or a self-managed GitLab's host.
    pub host: String,
    /// `owner/name`, or a GitLab project's path.
    pub repository: String,
    pub branch: String,
    /// The folder within the repository; empty for all of it.
    pub folder: String,
    /// The folder on GitHub or GitLab.
    pub folder_url: String,
    /// Where synced posts go. Sub-folders become its sub-topics.
    pub topic: Option<TopicRef>,
    /// A token is saved (it's never shown).
    pub has_token: bool,
    /// Where GitHub or GitLab sends push events: add a webhook for pushes there with this source's secret.
    pub webhook_url: String,
    /// Markdown files synced as posts.
    pub synced_files: i64,
    /// Synced posts' writer: the admin who added the source.
    pub owner: Option<UserRef>,
    #[serde(flatten)]
    pub state: SyncState,
    pub last_result: Option<DocsSyncResult>,
    pub created_at: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DocsSourceList {
    /// Syncs are available on this server (it has a connector key).
    pub enabled: bool,
    pub items: Vec<DocsSource>,
}

fn source_view(ctx: &Ctx, r: &Row) -> ApiResult<DocsSource> {
    let (source, readable) = Source::from_row_or_blank(ctx.cfg, r)?;
    let topic =
        ctx.db.one("SELECT id, name, slug, icon, color FROM topics WHERE id = ?", &params![source.topic_id.clone()])?.map(|t| TopicRef {
            id: t.str("id"),
            name: t.str("name"),
            icon: t.str("icon"),
            color: t.str("color"),
            url: topic_url(ctx, &t.str("id"), &t.str("slug")),
        });
    let synced_files = ctx.db.scalar_i64(
        "SELECT COUNT(*) FROM docs_items WHERE source_id = ? AND kind = 'doc' AND sha IS NOT NULL AND removed_at IS NULL",
        &params![source.id.clone()],
    )?;
    let owner = user_refs(ctx.db, std::slice::from_ref(&source.owner_id))?.remove(&source.owner_id);
    Ok(DocsSource {
        provider: source.repo.provider.id().into(),
        host: source.repo.host.clone(),
        repository: source.repo.repo.clone(),
        branch: source.repo.branch.clone(),
        folder: source.repo.folder.clone(),
        folder_url: source.repo.folder_url(),
        topic,
        has_token: !source.cred.token.is_empty(),
        webhook_url: ctx.url(&format!("/hooks/docs/{}", source.id)),
        synced_files,
        owner,
        state: unreadable(sync::state_of(r, ctx.now), readable),
        last_result: r.opt_str("last_result").and_then(|v| serde_json::from_str(&v).ok()),
        created_at: r.str("created_at"),
        id: source.id,
    })
}

/// Says so when a source's credentials can't be read.
fn unreadable(mut state: SyncState, readable: bool) -> SyncState {
    if !readable {
        state.last_status = Some("failed".into());
        state.last_error = Some("The saved token and webhook secret can't be read: the server's connector key changed. Save the token again (a new webhook secret is made) and update the webhook.".into());
    }
    state
}

fn load_source_row(ctx: &Ctx, id: &str) -> ApiResult<Row> {
    ctx.db
        .one("SELECT * FROM docs_sources WHERE id = ?", &params![id.trim()])?
        .ok_or_else(|| ApiError::not_found(format!("docs sync source `{id}`")))
}

fn list_docs_sources(ctx: &mut Ctx, _: NoInput) -> ApiResult<DocsSourceList> {
    let enabled = connect::enabled(ctx.cfg);
    let mut items = vec![];
    if enabled {
        for r in ctx.db.query("SELECT * FROM docs_sources ORDER BY created_at", &[])? {
            items.push(source_view(ctx, &r)?);
        }
    }
    Ok(DocsSourceList { enabled, items })
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateDocsSourceInput {
    /// `github` or `gitlab`.
    pub provider: String,
    /// `owner/name` on GitHub, a GitLab project's path (`group/subgroup/project`), or the repository's web address.
    pub repository: String,
    /// The branch to sync. Default `main`.
    pub branch: Option<String>,
    /// The folder within the repository, e.g. `docs`. Default: the whole repository.
    pub folder: Option<String>,
    /// The topic synced posts go in.
    pub topic_id: String,
    /// A read-only token, for private repositories: on GitHub a fine-grained token with Contents read-only access to the repository; on GitLab a token with the read_api scope. Leave out for public repositories.
    pub token: Option<String>,
    /// A self-managed GitLab's address, e.g. `https://gitlab.example.com`. Default gitlab.com.
    pub host: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DocsSourceCreated {
    pub source: DocsSource,
    /// The webhook secret, shown only now: GitHub's webhook "Secret", or GitLab's "Secret token".
    pub webhook_secret: Option<String>,
}

fn create_docs_source(ctx: &mut Ctx, input: CreateDocsSourceInput) -> ApiResult<DocsSourceCreated> {
    key_needed(ctx)?;
    let provider = sync::repo_provider(&input.provider)?;
    let (host, repo) = sync::repo_name(provider, &input.repository, input.host.as_deref().unwrap_or_default())?;
    let branch = clean(input.branch).unwrap_or_else(|| "main".into());
    let branch = sync::checked_branch(&branch)?;
    let folder = sync::checked_folder(input.folder.as_deref().unwrap_or_default())?;
    let topic = load_topic(ctx, input.topic_id.trim())?;
    let count = ctx.db.scalar_i64("SELECT COUNT(*) FROM docs_sources", &[])?;
    if count >= MAX_SOURCES {
        return Err(ApiError::conflict(format!("a workspace can have at most {MAX_SOURCES} docs sync sources")));
    }
    let duplicate = ctx.db.one(
        "SELECT id FROM docs_sources WHERE provider = ? AND host = ? AND repo = ? AND branch = ? AND folder = ? AND topic_id = ?",
        &params![provider.id(), host.clone(), repo.clone(), branch.clone(), folder.clone(), topic.str("id")],
    )?;
    if duplicate.is_some() {
        return Err(ApiError::conflict("that folder already syncs into that topic"));
    }
    let id = crate::util::new_id();
    let webhook_secret = new_secret("whsec_");
    let mut cred = Credential { token: secret_input(input.token, "token")?.unwrap_or_default(), ..Default::default() };
    cred.fields.insert("webhook_secret".into(), webhook_secret.clone());
    let secret = sync::seal(ctx.cfg, &docs::owner(&id), provider.id(), &cred)?;
    let now = ctx.now_s();
    ctx.db.execute(
        "INSERT INTO docs_sources (id, provider, host, repo, branch, folder, topic_id, secret, owner_id, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        &params![
            id.clone(),
            provider.id(),
            host,
            repo.clone(),
            branch,
            folder,
            topic.str("id"),
            secret,
            ctx.actor.user_id.clone(),
            now.clone(),
            now
        ],
    )?;
    emit(
        ctx,
        Event::new("docs_source.created", "docs_source", &id, format!("added docs sync from {repo}")).topic(&topic.str("id")).admin_only(),
    )?;
    let row = load_source_row(ctx, &id)?;
    Ok(DocsSourceCreated { source: source_view(ctx, &row)?, webhook_secret: Some(webhook_secret) })
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateDocsSourceInput {
    pub id: String,
    /// A new token; an empty string removes it (for public repositories).
    pub token: Option<String>,
    /// Sync another branch. Posts follow it at the next sync.
    pub branch: Option<String>,
    /// Make a new webhook secret, shown only in this answer. The old one stops working.
    pub new_webhook_secret: Option<bool>,
}

fn update_docs_source(ctx: &mut Ctx, input: UpdateDocsSourceInput) -> ApiResult<DocsSourceCreated> {
    key_needed(ctx)?;
    let row = load_source_row(ctx, &input.id)?;
    // Credentials that can't be read any more are replaced: a token, and a new webhook secret.
    let (mut source, readable) = Source::from_row_or_blank(ctx.cfg, &row)?;
    if let Some(t) = secret_input(input.token, "token")? {
        source.cred.token = t;
    }
    if let Some(b) = clean(input.branch) {
        source.repo.branch = sync::checked_branch(&b)?;
    }
    let webhook_secret = (input.new_webhook_secret.unwrap_or(false) || !readable).then(|| new_secret("whsec_"));
    if let Some(s) = &webhook_secret {
        source.cred.fields.insert("webhook_secret".into(), s.clone());
    }
    let secret = sync::seal(ctx.cfg, &docs::owner(&source.id), source.repo.provider.id(), &source.cred)?;
    ctx.db.execute(
        "UPDATE docs_sources SET branch = ?, secret = ?, updated_at = ? WHERE id = ?",
        &params![source.repo.branch.clone(), secret, ctx.now_s(), source.id.clone()],
    )?;
    emit(
        ctx,
        Event::new("docs_source.updated", "docs_source", &source.id, format!("changed docs sync from {}", source.repo.repo)).admin_only(),
    )?;
    let row = load_source_row(ctx, &source.id)?;
    Ok(DocsSourceCreated { source: source_view(ctx, &row)?, webhook_secret })
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceIdInput {
    pub id: String,
}

fn sync_docs_source(ctx: &mut Ctx, input: SourceIdInput) -> ApiResult<Deferred<DocsSyncResult>> {
    key_needed(ctx)?;
    let row = load_source_row(ctx, &input.id)?;
    let source = Source::from_row(ctx.cfg, &row)?;
    match docs::start(ctx.db, source, &ctx.base_url, Utc::now())? {
        Some(job) => {
            ctx.effects.push(Effect::Connect(job));
            Ok(Deferred::Pending)
        }
        None => Err(ApiError::conflict("A sync of this source is already running. Try again in a minute.")),
    }
}

fn delete_docs_source(ctx: &mut Ctx, input: SourceIdInput) -> ApiResult<Done> {
    let row = load_source_row(ctx, &input.id)?;
    let id = row.str("id");
    ctx.db.execute("DELETE FROM docs_items WHERE source_id = ?", &params![id.clone()])?;
    ctx.db.execute("DELETE FROM docs_sources WHERE id = ?", &params![id.clone()])?;
    emit(ctx, Event::new("docs_source.deleted", "docs_source", &id, format!("removed docs sync from {}", row.str("repo"))).admin_only())?;
    Ok(DONE)
}
