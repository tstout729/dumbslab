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
use crate::sync::docs::{self, DocsSyncResult, Link, Source};
use crate::sync::github_app;
use crate::sync::people::{self, PeopleSyncRemoved, PeopleSyncResult};
use crate::sync::{self, SyncState};
use crate::util::new_secret;
use crate::{Effect, params};

/// Docs sync sources a workspace may have.
const MAX_SOURCES: i64 = 20;
/// Two sources may not sync one folder into one topic.
const ALREADY_SYNCED: &str = "that folder already syncs into that topic";
const MAX_SECRET_CHARS: usize = 4096;

pub fn ops() -> Vec<Op> {
    vec![
        op("sync", "get_people_sync", "GET", "/people-sync", Access::Admin, get_people_sync)
            .title("People sync settings")
            .desc("The workspace's people sync from BambooHR: its company domain, whether changes in BambooHR start a sync (its webhook) and why not, and how the last sync went. Credentials are never shown.")
            .build(),
        op("sync", "connect_people_sync", "POST", "/people-sync/sign-in", Access::Admin, connect_people_sync)
            .title("Sign in with BambooHR")
            .desc("Set up the people sync by signing in with BambooHR, the one way on hosted DumbSlab. Give the company domain, then open `authorize_url` in the admin's browser: they approve DumbSlab in BambooHR and come back to Settings › People sync, where DumbSlab checks access, adds BambooHR's webhook so changes there start a sync, and saves. The link works once, for 15 minutes, for the admin who asked. Needs the host's BambooHR app (`sign_in_available` in get_people_sync).")
            .build(),
        op("sync", "set_people_sync", "PUT", "/people-sync", Access::Admin, set_people_sync)
            .title("Set up the people sync")
            .desc("Set up the people sync with the company domain and an API key (self-hosted only: BambooHR's terms let hosted services use Sign in with BambooHR alone, see connect_people_sync), or save it again with the saved credentials, e.g. to move the webhook after the workspace moved. DumbSlab checks access with BambooHR first and saves nothing if it doesn't work. Then it adds a webhook in BambooHR, so changes there start a sync; saving again keeps that webhook when nothing changed and BambooHR still has it, and replaces it otherwise. If BambooHR won't let DumbSlab's user add webhooks, the sync is saved anyway, and `webhook_error` says why: add the webhook in BambooHR by hand and pass its private key as `webhook_key`. Leave the API key out to keep the saved credentials. Then run sync_people. A sync fills in title, department, location, work phone, pronouns and manager for people here whose email matches a BambooHR work email; it never adds, deactivates or removes anyone.")
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
        op("sync", "list_github_repositories", "GET", "/docs-sources/github", Access::Admin, list_github_repositories)
            .title("GitHub repositories for docs sync")
            .desc("The installations of DumbSlab's GitHub App that admins here connected (Settings › Docs sync › Connect GitHub, a browser step at `connect_url`), each with the repositories the connecting admin's GitHub account can read there and their default branches. Give one's `installation_id` and `full_name` to create_docs_source: no token or webhook needed.")
            .build(),
        op("sync", "create_docs_source", "POST", "/docs-sources", Access::Admin, create_docs_source)
            .title("Add a docs sync source")
            .desc("Keep a GitHub or GitLab folder's Markdown files as posts in a topic, one way: each file is a post, sub-folders become sub-topics, relative links and images keep working, and synced posts are edited in the repository, not here. For a repository from list_github_repositories, give its `installation_id`: DumbSlab's GitHub App reads it and reports pushes, with no token or webhook. Otherwise give a read-only token for private repositories; the answer then has the webhook secret, once: add a push webhook with it in GitHub or GitLab so pushes sync. Then run sync_docs_source.")
            .build(),
        op("sync", "update_docs_source", "PATCH", "/docs-sources/{id}", Access::Admin, update_docs_source)
            .title("Change a docs sync source")
            .desc("Replace its token (an empty string removes it), switch its branch, or make a new webhook secret (shown once). Sources read through DumbSlab's GitHub App have no token or webhook secret; only their branch changes. To sync another repository or folder, add a new source.")
            .build(),
        op("sync", "sync_docs_source", "POST", "/docs-sources/{id}/sync", Access::Admin, sync_docs_source)
            .title("Sync docs now")
            .desc("Sync a source's folder now. One run syncs at most 20 changed files and 10 images; when `remaining` is above 0, run it again to continue. For a disconnected GitHub App source, it asks GitHub again instead (`checking` says so) and syncs nothing; sync again once Settings shows it's connected.")
            .build(),
        op("sync", "delete_docs_source", "DELETE", "/docs-sources/{id}", Access::Admin, delete_docs_source)
            .title("Remove a docs sync source")
            .desc("Stop syncing a folder and forget its credentials. Its posts and topics stay, as ordinary posts anyone with access can edit. Refused while a sync of it runs; try again once it's done.")
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
    /// How DumbSlab signs in to BambooHR: `oauth` (Sign in with BambooHR) or `api_key`.
    pub auth: Option<String>,
    /// Sign in with BambooHR works here: the host registered a BambooHR app.
    pub sign_in_available: bool,
    /// API keys are accepted here. Self-hosted only: BambooHR's developer terms allow API keys only in systems a company runs itself (https://www.bamboohr.com/legal/developer-terms-of-service, §3.2–3.3).
    pub api_key_allowed: bool,
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
    /// Sets of credentials (old sign-ins or API keys) DumbSlab still has to look through for its old webhooks in BambooHR, to delete them. It tries again after saves and syncs, and when Settings › People sync opens.
    pub webhook_cleanup: i64,
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
        auth: row.as_ref().map(|r| r.str("auth")),
        sign_in_available: people::sign_in_app(ctx.cfg).is_some(),
        api_key_allowed: !people::hosted(ctx.cfg),
        webhook: row.as_ref().is_some_and(|r| r.bool("webhook")),
        automatic_webhook: row.as_ref().is_some_and(|r| r.bool("webhook") && r.opt_str("webhook_id").is_some()),
        webhook_error: row.as_ref().and_then(|r| people::webhook_problem(r, &webhook_url)),
        webhook_url,
        state: row.as_ref().map(|r| sync::state_of(r, ctx.now)).unwrap_or_default(),
        last_result: row.as_ref().and_then(|r| r.opt_str("last_result")).and_then(|v| serde_json::from_str(&v).ok()),
        webhook_cleanup: people::cleanup_waiting(ctx.db)?,
        notice: None,
    })
}

fn get_people_sync(ctx: &mut Ctx, _: NoInput) -> ApiResult<PeopleSync> {
    // Opening Settings › People sync also runs a cleanup pass that's due (old webhooks to delete).
    if people::cleanup_due(ctx.db, ctx.now)? {
        ctx.effects.push(Effect::Background(people::cleanup_job(&ctx.base_url, None)));
    }
    people_view(ctx)
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetPeopleSyncInput {
    /// The BambooHR company domain: `acme` for acme.bamboohr.com. `acme.bamboohr.com` or any address on it works too.
    pub subdomain: String,
    /// A BambooHR API key (in BambooHR: your name › API Keys), self-hosted only. Its user must be able to see employees' work emails and job details, and to add webhooks for changes to start a sync. Checked with BambooHR before it's saved. Required the first time; leave out to keep the saved one.
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
    // Then, after the response, it deletes the webhooks DumbSlab still has to (the one this save
    // replaced, when BambooHR wouldn't delete it now).
    ctx.effects.push(Effect::Background(people::cleanup_job(&ctx.base_url, None)));
    Ok(Deferred::Pending)
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectPeopleSyncInput {
    /// The BambooHR company domain: `acme` for acme.bamboohr.com. `acme.bamboohr.com` or any address on it works too.
    pub subdomain: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct PeopleSyncSignIn {
    /// BambooHR's sign-in page. Open it in the admin's browser, signed in to DumbSlab as the admin who asked.
    pub authorize_url: String,
}

fn connect_people_sync(ctx: &mut Ctx, input: ConnectPeopleSyncInput) -> ApiResult<PeopleSyncSignIn> {
    key_needed(ctx)?;
    let subdomain = people::valid_subdomain(&input.subdomain).map_err(ApiError::bad_request)?;
    Ok(PeopleSyncSignIn { authorize_url: people::start_sign_in(ctx, &subdomain)? })
}

fn sync_people(ctx: &mut Ctx, _: NoInput) -> ApiResult<Deferred<PeopleSyncResult>> {
    key_needed(ctx)?;
    match people::start(ctx.db, ctx.cfg, &ctx.base_url, Utc::now())? {
        Some(job) => {
            ctx.effects.push(Effect::Connect(job));
            if people::cleanup_due(ctx.db, ctx.now)? {
                ctx.effects.push(Effect::Background(people::cleanup_job(&ctx.base_url, None)));
            }
            Ok(Deferred::Pending)
        }
        None => Err(ApiError::conflict("A people sync is already running. Try again in a minute.")),
    }
}

fn remove_people_sync(ctx: &mut Ctx, _: NoInput) -> ApiResult<Deferred<PeopleSyncRemoved>> {
    let row = people_row(ctx)?.ok_or_else(|| ApiError::not_found("people sync"))?;
    if people::saving(ctx.db, ctx.now)? {
        return Err(people::busy());
    }
    // A renewal under way would spend the refresh token the webhook's deletion needs.
    if people::renewing(&row, ctx.now) {
        return Err(ApiError::conflict(people::RENEWING));
    }
    ctx.db.execute("DELETE FROM people_sync WHERE id = 1", &[])?;
    // A save that stalled past its lease can't bring the sync back.
    people::end_saves(ctx.db)?;
    emit(ctx, Event::new("people_sync.removed", "people_sync", "1", "removed the people sync").admin_only())?;
    // Then the host deletes the webhook DumbSlab added in BambooHR, kept as a cleanup record (with
    // the credentials that may delete it) until it's gone. The sync is gone either way.
    match people::record_removed(ctx.db, ctx.cfg, &row, ctx.now)? {
        Some(record) => {
            ctx.effects.push(Effect::Connect(people::cleanup_job(&ctx.base_url, Some(record))));
            Ok(Deferred::Pending)
        }
        // Its credentials can't be read any more (the connector key changed).
        None if row.opt_str("webhook_id").is_some() => {
            Ok(Deferred::Ready(PeopleSyncRemoved { ok: true, notice: Some(people::NOT_DELETED.into()) }))
        }
        None => Ok(Deferred::Ready(PeopleSyncRemoved { ok: true, notice: None })),
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
    /// How it reads the repository: `token` (a saved token, or none for a public repository, and a
    /// webhook you add) or `github_app` (DumbSlab's GitHub App: no token, and pushes arrive by themselves).
    pub connection: String,
    /// `github_app`: the App's installation that reads the repository.
    pub installation_id: Option<i64>,
    /// Why it can't sync now, e.g. the GitHub App was uninstalled, or an older source syncs the same
    /// folder into the same topic (a repository renamed into another's). Its posts stay. Null when
    /// it can.
    pub disconnected: Option<String>,
    /// A token is saved (it's never shown).
    pub has_token: bool,
    /// `token` sources: where GitHub or GitLab sends push events. Add a webhook for pushes there with
    /// this source's secret. Null for `github_app` sources, whose pushes arrive through the App.
    pub webhook_url: Option<String>,
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
    /// DumbSlab's GitHub App is set up on this server, so GitHub repositories need no token: see
    /// list_github_repositories.
    pub github_app: bool,
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
        connection: source.link.id().into(),
        installation_id: match source.link {
            Link::GitHubApp { installation_id, .. } => Some(installation_id),
            Link::Token => None,
        },
        disconnected: match source.disconnected.as_deref() {
            Some(code) => Some(github_app::disconnected_message(code)),
            None => docs::has_older_twin(ctx.db, &source)?.then(|| docs::DUPLICATE.to_string()),
        },
        has_token: !source.cred.token.is_empty(),
        webhook_url: (source.link == Link::Token).then(|| ctx.url(&format!("/hooks/docs/{}", source.id))),
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
        .one(&format!("{} WHERE s.id = ?", docs::SOURCES_SQL), &params![id.trim()])?
        .ok_or_else(|| ApiError::not_found(format!("docs sync source `{id}`")))
}

fn list_docs_sources(ctx: &mut Ctx, _: NoInput) -> ApiResult<DocsSourceList> {
    let enabled = connect::enabled(ctx.cfg);
    let mut items = vec![];
    if enabled {
        for r in ctx.db.query(&format!("{} ORDER BY s.created_at", docs::SOURCES_SQL), &[])? {
            items.push(source_view(ctx, &r)?);
        }
    }
    Ok(DocsSourceList { enabled, github_app: enabled && github_app::app(ctx.cfg).is_some(), items })
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct GitHubRepositories {
    /// DumbSlab's GitHub App is set up on this server.
    pub available: bool,
    /// Open this in a browser, signed in as an admin, to install the App on GitHub (or change which
    /// repositories it can read) and come back to Settings › Docs sync. Null when it isn't available.
    pub connect_url: Option<String>,
    pub installations: Vec<GitHubInstallation>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct GitHubInstallation {
    pub installation_id: i64,
    /// The GitHub user or organization it's installed on.
    pub account: String,
    /// `User`, `Organization` or `Enterprise`.
    pub account_type: String,
    /// Suspended on GitHub: its sources don't sync until it's unsuspended.
    pub suspended: bool,
    /// The admin who connected it here.
    pub connected_by: Option<UserRef>,
    pub connected_at: String,
    /// The repositories the connecting admin's GitHub account can read in it, as of connecting.
    /// Connect GitHub again to refresh them.
    pub repositories: Vec<GitHubRepository>,
    /// Their account could read more repositories there than are listed (the first 500 are).
    pub more_repositories: bool,
    /// Whether GitHub's deliveries for it reach this workspace: `direct` (this server gets them
    /// itself), `ok`, `pending` (each sync asks the hosted directory again until it's recorded) or
    /// `full` (it already serves as many workspaces as it may, so pushes don't sync by themselves
    /// here; Sync now still works).
    pub forwarding: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct GitHubRepository {
    pub id: i64,
    /// `owner/name`: give it to create_docs_source as `repository`.
    pub full_name: String,
    pub default_branch: String,
    pub private: bool,
}

fn list_github_repositories(ctx: &mut Ctx, _: NoInput) -> ApiResult<GitHubRepositories> {
    let available = connect::enabled(ctx.cfg) && github_app::app(ctx.cfg).is_some();
    let mut installations = vec![];
    let rows = ctx.db.query("SELECT * FROM github_installations ORDER BY account, id", &[])?;
    // Checks of installations that are still owed (one failed earlier) are tried again.
    for r in &rows {
        if let Some(check) = github_app::resume_check(ctx.db, r.i64("id"), &ctx.base_url, ctx.now)? {
            ctx.effects.push(Effect::Background(check));
        }
    }
    let people = user_refs(ctx.db, &rows.iter().map(|r| r.str("connected_by")).collect::<Vec<_>>())?;
    for r in &rows {
        let repositories = ctx
            .db
            .query(
                "SELECT id, full_name, default_branch, private FROM github_repositories WHERE installation_id = ? AND removed_at IS NULL ORDER BY full_name",
                &params![r.i64("id")],
            )?
            .iter()
            .map(|p| GitHubRepository { id: p.i64("id"), full_name: p.str("full_name"), default_branch: p.str("default_branch"), private: p.bool("private") })
            .collect();
        installations.push(GitHubInstallation {
            installation_id: r.i64("id"),
            account: r.str("account"),
            account_type: r.str("account_type"),
            suspended: r.opt_str("suspended_at").is_some(),
            connected_by: people.get(&r.str("connected_by")).cloned(),
            connected_at: r.str("created_at"),
            repositories,
            more_repositories: r.bool("more_repositories"),
            forwarding: match (ctx.cfg.hosting.is_some(), r.opt_str("forwarding")) {
                (false, _) => "direct".into(),
                (true, Some(f)) => f,
                (true, None) => "pending".into(),
            },
        });
    }
    let connect_url = available.then(|| ctx.url(github_app::INSTALL_PATH));
    Ok(GitHubRepositories { available, connect_url, installations })
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
    /// GitHub only: read the repository through this installation of DumbSlab's GitHub App, from
    /// list_github_repositories. Then `repository` must be one listed there, and no token or
    /// webhook is needed. The branch defaults to the repository's default branch.
    pub installation_id: Option<i64>,
    /// With `installation_id`: the repository's `id` from list_github_repositories. Then that very
    /// repository is added, whatever its name is now, and `repository` is only for people to read.
    pub repository_id: Option<i64>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DocsSourceCreated {
    pub source: DocsSource,
    /// The webhook secret, shown only now: GitHub's webhook "Secret", or GitLab's "Secret token".
    /// Null for sources read through DumbSlab's GitHub App, which need no webhook.
    pub webhook_secret: Option<String>,
}

/// A repository from an installation an admin here connected, which their GitHub account can read:
/// (repository id, `owner/name`, default branch). By its id when the picker gave it (the one the
/// admin chose, whatever its name is now), else by name.
fn app_repository(ctx: &Ctx, installation_id: i64, repo: &str, repo_id: Option<i64>) -> ApiResult<(i64, String, String)> {
    if github_app::app(ctx.cfg).is_none() {
        return Err(ApiError::new(503, "github_app_off", "DumbSlab's GitHub App isn't set up on this server; give a token instead."));
    }
    let installation =
        ctx.db.one("SELECT suspended_at FROM github_installations WHERE id = ?", &params![installation_id])?.ok_or_else(|| {
            ApiError::not_found(format!("GitHub installation {installation_id} (Connect GitHub in Settings › Docs sync first)"))
        })?;
    if installation.opt_str("suspended_at").is_some() {
        return Err(ApiError::conflict("that installation of DumbSlab's GitHub App is suspended on GitHub"));
    }
    let found = match repo_id {
        Some(id) => ctx.db.one(
            "SELECT id, full_name, default_branch FROM github_repositories WHERE installation_id = ? AND id = ? AND removed_at IS NULL",
            &params![installation_id, id],
        )?,
        None => ctx.db.one(
            "SELECT id, full_name, default_branch FROM github_repositories WHERE installation_id = ? AND lower(full_name) = lower(?) AND removed_at IS NULL",
            &params![installation_id, repo],
        )?,
    };
    let r = found.ok_or_else(|| {
        ApiError::not_found(format!(
            "{repo} in that installation, among the repositories your GitHub account can read there. To add one, Connect GitHub again and give the App access to it"
        ))
    })?;
    Ok((r.i64("id"), r.str("full_name"), r.str("default_branch")))
}

fn create_docs_source(ctx: &mut Ctx, input: CreateDocsSourceInput) -> ApiResult<DocsSourceCreated> {
    key_needed(ctx)?;
    let provider = sync::repo_provider(&input.provider)?;
    let (host, repo) = sync::repo_name(provider, &input.repository, input.host.as_deref().unwrap_or_default())?;
    // Through DumbSlab's GitHub App: a repository the admin's own GitHub account showed it can read.
    let app = match input.installation_id {
        Some(_) if provider != sync::repo::Provider::GitHub => {
            return Err(ApiError::bad_request("`installation_id` is for GitHub repositories only"));
        }
        Some(_) if clean(input.token.clone()).is_some() => {
            return Err(ApiError::bad_request("a source read through DumbSlab's GitHub App takes no token; leave out `token`"));
        }
        Some(installation) => Some((installation, app_repository(ctx, installation, &repo, input.repository_id)?)),
        None if input.repository_id.is_some() => {
            return Err(ApiError::bad_request("`repository_id` goes with `installation_id`, from list_github_repositories"));
        }
        None => None,
    };
    let repo = app.as_ref().map(|(_, (_, name, _))| name.clone()).unwrap_or(repo);
    let default_branch = app.as_ref().map(|(_, (_, _, b))| b.clone()).unwrap_or_else(|| "main".into());
    let branch = clean(input.branch).unwrap_or(default_branch);
    let branch = sync::checked_branch(&branch)?;
    let folder = sync::checked_folder(input.folder.as_deref().unwrap_or_default())?;
    let topic = load_topic(ctx, input.topic_id.trim())?;
    let count = ctx.db.scalar_i64("SELECT COUNT(*) FROM docs_sources", &[])?;
    if count >= MAX_SOURCES {
        return Err(ApiError::conflict(format!("a workspace can have at most {MAX_SOURCES} docs sync sources")));
    }
    // The same folder twice, by the repository's name or (renamed since) its id.
    let wanted = sync::repo::Repo { provider, host: host.clone(), repo: repo.clone(), branch: branch.clone(), folder: folder.clone() };
    let link = match &app {
        Some((installation_id, (repo_id, _, _))) => Link::GitHubApp { installation_id: *installation_id, repo_id: *repo_id },
        None => Link::Token,
    };
    if !docs::twins(ctx.db, &wanted, &link, &topic.str("id"), "")?.is_empty() {
        return Err(ApiError::conflict(ALREADY_SYNCED));
    }
    let id = crate::util::new_id();
    // A GitHub App source keeps no token and needs no webhook secret.
    let webhook_secret = app.is_none().then(|| new_secret("whsec_"));
    let mut cred = Credential { token: secret_input(input.token, "token")?.unwrap_or_default(), ..Default::default() };
    if let Some(s) = &webhook_secret {
        cred.fields.insert("webhook_secret".into(), s.clone());
    }
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
    if let Some((installation_id, (repo_id, _, _))) = app {
        ctx.db.execute(
            "INSERT INTO docs_source_links (source_id, connection, installation_id, repo_id) VALUES (?, 'github_app', ?, ?)",
            &params![id.clone(), installation_id, repo_id],
        )?;
    }
    emit(
        ctx,
        Event::new("docs_source.created", "docs_source", &id, format!("added docs sync from {repo}")).topic(&topic.str("id")).admin_only(),
    )?;
    let row = load_source_row(ctx, &id)?;
    Ok(DocsSourceCreated { source: source_view(ctx, &row)?, webhook_secret })
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
    if source.link != Link::Token && (input.token.is_some() || input.new_webhook_secret == Some(true)) {
        return Err(ApiError::bad_request(
            "this source is read through DumbSlab's GitHub App: it has no token or webhook secret. Only its branch can change.",
        ));
    }
    if let Some(t) = secret_input(input.token, "token")? {
        source.cred.token = t;
    }
    if let Some(b) = clean(input.branch) {
        let branch = sync::checked_branch(&b)?;
        if branch != source.repo.branch {
            source.repo.branch = branch;
            if !docs::twins(ctx.db, &source.repo, &source.link, &source.topic_id, &source.id)?.is_empty() {
                return Err(ApiError::conflict(ALREADY_SYNCED));
            }
        }
    }
    // (A GitHub App source keeps no credentials, so it's always readable.)
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
    if docs::has_older_twin(ctx.db, &source)? {
        return Err(ApiError::new(409, "duplicate", docs::DUPLICATE));
    }
    if let Link::GitHubApp { installation_id, .. } = source.link {
        // Disconnected: Sync now asks GitHub again (a check already owed or running covers it).
        // The check is asked for in this answer (so it's kept), and decides whether the folder can
        // sync.
        let known = ctx.db.one("SELECT 1 AS ok FROM github_installations WHERE id = ?", &params![installation_id])?.is_some();
        if source.disconnected.is_some() && known {
            if let Some(check) = github_app::recheck(ctx.db, installation_id, &ctx.base_url, ctx.now)? {
                ctx.effects.push(Effect::Background(check));
            }
            let checking =
                "DumbSlab is checking GitHub's access for this folder before it syncs. Settings shows what it finds; sync again then.";
            return Ok(Deferred::Ready(DocsSyncResult { checking: Some(checking.into()), ..Default::default() }));
        }
        // A check of its installation that's still owed (it failed earlier) is tried again too.
        if let Some(check) = github_app::resume_check(ctx.db, installation_id, &ctx.base_url, ctx.now)? {
            ctx.effects.push(Effect::Background(check));
        }
    }
    if let Some(code) = &source.disconnected {
        return Err(ApiError::new(409, "disconnected", github_app::disconnected_message(code)));
    }
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
    remove_sources(ctx, &[row])?;
    Ok(DONE)
}

/// Removes sources (rows of [`docs::SOURCES_SQL`]): removing one, or deleting the topic they sync
/// into. Each must have no sync running: this takes the sync's lease, so none starts either, and
/// whatever the source keeps elsewhere is cleaned up from what's stored now. Their posts stay.
pub(crate) fn remove_sources(ctx: &mut Ctx, rows: &[Row]) -> ApiResult<()> {
    let now = Utc::now();
    for row in rows {
        let id = row.str("id");
        if sync::claim(ctx.db, docs::TABLE, id.as_str().into(), now)?.is_none() {
            return Err(ApiError::conflict(format!("A sync of {} is running. Try again in a moment, once it's done.", row.str("repo"))));
        }
        ctx.db.execute("DELETE FROM docs_items WHERE source_id = ?", &params![id.clone()])?;
        ctx.db.execute("DELETE FROM docs_rerender WHERE source_id = ?", &params![id.clone()])?;
        ctx.db.execute("DELETE FROM docs_sources WHERE id = ?", &params![id.clone()])?;
        emit(
            ctx,
            Event::new("docs_source.deleted", "docs_source", &id, format!("removed docs sync from {}", row.str("repo"))).admin_only(),
        )?;
    }
    Ok(())
}
