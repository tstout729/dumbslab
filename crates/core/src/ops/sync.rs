//! People sync (BambooHR) and docs sync (GitHub, GitLab): admins set them up for the whole
//! workspace. The machinery lives in [`crate::sync`].

use chrono::Utc;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{DONE, Done, NoInput, clean};
use crate::connect::{self, Credential, Deferred, Job};
use crate::db::{DbExt, Row};
use crate::error::{ApiError, ApiResult};
use crate::events::{Event, emit};
use crate::model::{TopicRef, UserRef, load_topic, topic_url, user_refs};
use crate::registry::{Access, Ctx, Op, op};
use crate::sync::docs::{self, DocsSyncResult, Link, Source};
use crate::sync::people::{self, PeopleSyncResult};
use crate::sync::{self, SyncState};
use crate::sync::{github_app, gitlab_app};
use crate::util::new_secret;
use crate::{Effect, InstallationLink, params};

/// Docs sync sources a workspace may have.
const MAX_SOURCES: i64 = 20;
const MAX_SECRET_CHARS: usize = 4096;

pub fn ops() -> Vec<Op> {
    vec![
        op("sync", "get_people_sync", "GET", "/people-sync", Access::Admin, get_people_sync)
            .title("People sync settings")
            .desc("The workspace's people sync from BambooHR: its company domain, whether a webhook is set up, and how the last sync went. Credentials are never shown.")
            .build(),
        op("sync", "set_people_sync", "PUT", "/people-sync", Access::Admin, set_people_sync)
            .title("Set up the people sync")
            .desc("Set up (or change) the people sync from BambooHR: the company domain and an API key, and optionally the private key of a BambooHR webhook so changes there start a sync. Leave a key out to keep the saved one. Then run sync_people. A sync fills in title, department, location, work phone, pronouns and manager for people here whose email matches a BambooHR work email; it never adds, deactivates or removes anyone.")
            .idempotent()
            .build(),
        op("sync", "sync_people", "POST", "/people-sync/run", Access::Admin, sync_people)
            .title("Sync people now")
            .desc("Read BambooHR's active employees and update the matching people's profiles. Answers with what changed and which employees match nobody here.")
            .build(),
        op("sync", "remove_people_sync", "DELETE", "/people-sync", Access::Admin, remove_people_sync)
            .title("Remove the people sync")
            .desc("Stop syncing from BambooHR and forget its credentials. Profile details already synced stay.")
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
        op("sync", "list_gitlab_projects", "GET", "/docs-sources/gitlab", Access::Admin, list_gitlab_projects)
            .title("GitLab projects for docs sync")
            .desc("The gitlab.com projects you can maintain, through your Connect GitLab approval (Settings › Docs sync › Connect GitLab, a browser step at `connect_url`), with their default branches. Give one's `path` to create_docs_source with `gitlab_connection: true`: DumbSlab adds its push webhook, so there's no token or webhook to copy.")
            .build(),
        op("sync", "create_docs_source", "POST", "/docs-sources", Access::Admin, create_docs_source)
            .title("Add a docs sync source")
            .desc("Keep a GitHub or GitLab folder's Markdown files as posts in a topic, one way: each file is a post, sub-folders become sub-topics, relative links and images keep working, and synced posts are edited in the repository, not here. For a repository from list_github_repositories, give its `installation_id`: DumbSlab's GitHub App reads it and reports pushes, with no token or webhook. For a project from list_gitlab_projects, give `gitlab_connection: true`: DumbSlab adds its push webhook. Otherwise give a read-only token for private repositories; the answer then has the webhook secret, once: add a push webhook with it in GitHub or GitLab so pushes sync. Then run sync_docs_source.")
            .build(),
        op("sync", "update_docs_source", "PATCH", "/docs-sources/{id}", Access::Admin, update_docs_source)
            .title("Change a docs sync source")
            .desc("Replace its token (an empty string removes it), switch its branch, or make a new webhook secret (shown once). Sources read through DumbSlab's GitHub App have no token or webhook secret; only their branch changes. A source read through DumbSlab's GitLab app takes `gitlab_connection: true` to use your newest Connect GitLab approval, e.g. after GitLab stopped accepting the old one. To sync another repository or folder, add a new source.")
            .build(),
        op("sync", "sync_docs_source", "POST", "/docs-sources/{id}/sync", Access::Admin, sync_docs_source)
            .title("Sync docs now")
            .desc("Sync a source's folder now. One run syncs at most 20 changed files and 10 images; when `remaining` is above 0, run it again to continue.")
            .build(),
        op("sync", "delete_docs_source", "DELETE", "/docs-sources/{id}", Access::Admin, delete_docs_source)
            .title("Remove a docs sync source")
            .desc("Stop syncing a folder and forget its credentials. Its posts and topics stay, as ordinary posts anyone with access can edit. A webhook DumbSlab added to a GitLab project is removed too.")
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
    /// A webhook private key is saved, so BambooHR's webhooks start syncs.
    pub webhook: bool,
    /// Where BambooHR sends webhooks.
    pub webhook_url: String,
    #[serde(flatten)]
    pub state: SyncState,
    pub last_result: Option<PeopleSyncResult>,
}

fn people_row(ctx: &Ctx) -> ApiResult<Option<Row>> {
    ctx.db.one("SELECT * FROM people_sync WHERE id = 1", &[])
}

fn people_view(ctx: &Ctx) -> ApiResult<PeopleSync> {
    let row = people_row(ctx)?;
    Ok(PeopleSync {
        enabled: connect::enabled(ctx.cfg),
        configured: row.is_some(),
        provider: people::PROVIDER.into(),
        subdomain: row.as_ref().map(|r| r.str("subdomain")),
        webhook: row.as_ref().is_some_and(|r| r.bool("webhook")),
        webhook_url: ctx.url("/hooks/people"),
        state: row.as_ref().map(|r| sync::state_of(r, ctx.now)).unwrap_or_default(),
        last_result: row.as_ref().and_then(|r| r.opt_str("last_result")).and_then(|v| serde_json::from_str(&v).ok()),
    })
}

fn get_people_sync(ctx: &mut Ctx, _: NoInput) -> ApiResult<PeopleSync> {
    people_view(ctx)
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetPeopleSyncInput {
    /// The BambooHR company domain: `acme` for acme.bamboohr.com.
    pub subdomain: String,
    /// A BambooHR API key (in BambooHR: your name › API Keys). Its user must be able to see employees' work emails and job details. Required the first time; leave out to keep the saved one.
    pub api_key: Option<String>,
    /// The private key of a BambooHR webhook that posts to `webhook_url`, so changes there start a sync. An empty string removes it; leave out to keep the saved one.
    pub webhook_key: Option<String>,
}

fn set_people_sync(ctx: &mut Ctx, input: SetPeopleSyncInput) -> ApiResult<PeopleSync> {
    key_needed(ctx)?;
    let subdomain = people::valid_subdomain(&input.subdomain).map_err(ApiError::bad_request)?;
    let existing = people_row(ctx)?;
    let mut cred = match &existing {
        // Unreadable (the connector key changed): the keys must be entered again.
        Some(r) => sync::open(ctx.cfg, people::OWNER, people::PROVIDER, &r.str("secret")).unwrap_or_default(),
        None => Credential::default(),
    };
    if let Some(k) = secret_input(input.api_key, "api_key")?.filter(|k| !k.is_empty()) {
        cred.token = k;
    }
    if cred.token.is_empty() {
        return Err(ApiError::bad_request("a BambooHR API key is required"));
    }
    match secret_input(input.webhook_key, "webhook_key")? {
        Some(k) if k.is_empty() => {
            cred.fields.remove("webhook_key");
        }
        Some(k) => {
            cred.fields.insert("webhook_key".into(), k);
        }
        None => {}
    }
    let webhook = cred.fields.contains_key("webhook_key");
    let secret = sync::seal(ctx.cfg, people::OWNER, people::PROVIDER, &cred)?;
    let now = ctx.now_s();
    ctx.db.execute(
        "INSERT INTO people_sync (id, provider, subdomain, secret, webhook, owner_id, created_at, updated_at) VALUES (1, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET subdomain = excluded.subdomain, secret = excluded.secret, webhook = excluded.webhook,
           owner_id = excluded.owner_id, updated_at = excluded.updated_at",
        &params![people::PROVIDER, subdomain.clone(), secret, webhook, ctx.actor.user_id.clone(), now.clone(), now],
    )?;
    emit(
        ctx,
        Event::new("people_sync.updated", "people_sync", "1", format!("set up the people sync from {subdomain}.bamboohr.com"))
            .data(json!({ "webhook": webhook }))
            .admin_only(),
    )?;
    people_view(ctx)
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

fn remove_people_sync(ctx: &mut Ctx, _: NoInput) -> ApiResult<Done> {
    if ctx.db.execute("DELETE FROM people_sync WHERE id = 1", &[])? == 0 {
        return Err(ApiError::not_found("people sync"));
    }
    emit(ctx, Event::new("people_sync.removed", "people_sync", "1", "removed the people sync").admin_only())?;
    Ok(DONE)
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
    /// webhook you add), `github_app` (DumbSlab's GitHub App: no token, and pushes arrive by
    /// themselves) or `gitlab_oauth` (an approval of DumbSlab's GitLab app, which added the webhook).
    pub connection: String,
    /// `github_app`: the App's installation that reads the repository.
    pub installation_id: Option<i64>,
    /// Why it can't sync now, e.g. the GitHub App was uninstalled. Its posts stay. Null when it can.
    pub disconnected: Option<String>,
    /// A token is saved (it's never shown).
    pub has_token: bool,
    /// `token` sources: where GitHub or GitLab sends push events. Add a webhook for pushes there with
    /// this source's secret. Null for the others: the apps' pushes arrive by themselves.
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
    /// DumbSlab's GitLab app is set up on this server, so gitlab.com projects need no token: see
    /// list_gitlab_projects.
    pub gitlab_app: bool,
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
            _ => None,
        },
        disconnected: source.disconnected.as_deref().map(github_app::disconnected_message),
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
    Ok(DocsSourceList {
        enabled,
        github_app: enabled && github_app::app(ctx.cfg).is_some(),
        gitlab_app: gitlab_app::available(ctx.cfg),
        items,
    })
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct GitLabProjects {
    /// DumbSlab's GitLab app is set up on this server.
    pub available: bool,
    /// You approved DumbSlab's GitLab app and haven't used the approval for a folder yet.
    pub connected: bool,
    /// Open this in a browser, signed in as an admin, to approve DumbSlab's GitLab app and come back
    /// to Settings › Docs sync. Null when it isn't available.
    pub connect_url: Option<String>,
    /// Your GitLab account, e.g. `@ada`.
    pub account: Option<String>,
    /// Projects you can maintain on gitlab.com, most recently active first.
    pub projects: Vec<GitLabProject>,
    /// There are more than the 300 listed.
    pub more: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct GitLabProject {
    pub id: i64,
    /// `group/subgroup/project`: give it to create_docs_source as `repository`.
    pub path: String,
    /// GitLab leaves it out for empty projects.
    pub default_branch: Option<String>,
    /// `private`, `internal` or `public`.
    pub visibility: String,
}

fn list_gitlab_projects(ctx: &mut Ctx, _: NoInput) -> ApiResult<Deferred<GitLabProjects>> {
    let available = gitlab_app::available(ctx.cfg);
    let connect_url = available.then(|| ctx.url(gitlab_app::START_PATH));
    let pending = if available { gitlab_app::pending(ctx.db, ctx.cfg, &ctx.actor.user_id)? } else { None };
    if pending.is_none() {
        return Ok(Deferred::Ready(GitLabProjects {
            available,
            connected: false,
            connect_url,
            account: None,
            projects: vec![],
            more: false,
        }));
    }
    let job = gitlab_app::GitLabJob::projects(&ctx.actor.user_id, &ctx.base_url);
    ctx.effects.push(Effect::Connect(Job::GitLab(Box::new(job))));
    Ok(Deferred::Pending)
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
    /// gitlab.com only: read the project with your Connect GitLab approval (see
    /// list_gitlab_projects) instead of a token. DumbSlab adds the project's push webhook itself,
    /// so you need GitLab's Maintainer role there. The approval moves to this source; connect again
    /// for another. The branch defaults to the project's default branch.
    pub gitlab_connection: Option<bool>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DocsSourceCreated {
    pub source: DocsSource,
    /// The webhook secret, shown only now: GitHub's webhook "Secret", or GitLab's "Secret token".
    /// Null for sources read through DumbSlab's GitHub App, which need no webhook.
    pub webhook_secret: Option<String>,
}

/// A repository from an installation an admin here connected, which their GitHub account can read:
/// (repository id, `owner/name`, default branch).
fn app_repository(ctx: &Ctx, installation_id: i64, repo: &str) -> ApiResult<(i64, String, String)> {
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
    let found = ctx.db.one(
        "SELECT id, full_name, default_branch FROM github_repositories WHERE installation_id = ? AND lower(full_name) = lower(?) AND removed_at IS NULL",
        &params![installation_id, repo],
    )?;
    let r = found.ok_or_else(|| {
        ApiError::not_found(format!(
            "{repo} in that installation, among the repositories your GitHub account can read there. To add one, Connect GitHub again and give the App access to it"
        ))
    })?;
    Ok((r.i64("id"), r.str("full_name"), r.str("default_branch")))
}

fn create_docs_source(ctx: &mut Ctx, input: CreateDocsSourceInput) -> ApiResult<Deferred<DocsSourceCreated>> {
    key_needed(ctx)?;
    let provider = sync::repo_provider(&input.provider)?;
    let (host, repo) = sync::repo_name(provider, &input.repository, input.host.as_deref().unwrap_or_default())?;
    let token = secret_input(input.token, "token")?.filter(|t| !t.is_empty());
    let gitlab = input.gitlab_connection.unwrap_or(false);
    if (input.installation_id.is_some() || gitlab) && token.is_some() {
        return Err(ApiError::bad_request("a source read through DumbSlab's GitHub or GitLab app takes no token; leave out `token`"));
    }
    // Through DumbSlab's GitHub App: a repository the admin's own GitHub account showed it can read.
    let app = match input.installation_id {
        Some(_) if provider != sync::repo::Provider::GitHub => {
            return Err(ApiError::bad_request("`installation_id` is for GitHub repositories only"));
        }
        Some(installation) => Some((installation, app_repository(ctx, installation, &repo)?)),
        None => None,
    };
    if gitlab && (provider != sync::repo::Provider::GitLab || host != gitlab_app::HOST) {
        return Err(ApiError::bad_request("`gitlab_connection` is for projects on gitlab.com only; a self-managed GitLab takes a token"));
    }
    let repo = app.as_ref().map(|(_, (_, name, _))| name.clone()).unwrap_or(repo);
    let default_branch = app.as_ref().map(|(_, (_, _, b))| b.clone()).unwrap_or_else(|| "main".into());
    let typed_branch = clean(input.branch).map(|b| sync::checked_branch(&b)).transpose()?;
    let fresh = docs::NewSource {
        id: crate::util::new_id(),
        provider,
        host,
        repo,
        branch: typed_branch.clone().unwrap_or(default_branch),
        folder: sync::checked_folder(input.folder.as_deref().unwrap_or_default())?,
        topic_id: input.topic_id.trim().to_string(),
    };
    check_new_source(ctx, &fresh)?;
    // Through DumbSlab's GitLab app: GitLab must first find the project for the admin and take
    // the webhook, so a job finishes adding it (see `gitlab_app`).
    if gitlab {
        if !gitlab_app::available(ctx.cfg) {
            return Err(ApiError::new(503, "gitlab_app_off", "DumbSlab's GitLab app isn't set up on this server; give a token instead."));
        }
        if gitlab_app::pending(ctx.db, ctx.cfg, &ctx.actor.user_id)?.is_none() {
            return Err(ApiError::conflict("Connect GitLab first (Settings › Docs sync), then pick the project."));
        }
        let draft = gitlab_app::Draft {
            webhook_url: ctx.url(&format!("/hooks/docs/{}", fresh.id)),
            source_id: fresh.id,
            repo: fresh.repo,
            branch: typed_branch,
            folder: fresh.folder,
            topic_id: fresh.topic_id,
        };
        let job = gitlab_app::GitLabJob::create(&ctx.actor.user_id, &ctx.base_url, draft);
        ctx.effects.push(Effect::Connect(Job::GitLab(Box::new(job))));
        return Ok(Deferred::Pending);
    }
    // A GitHub App source keeps no token and needs no webhook secret.
    let webhook_secret = app.is_none().then(|| new_secret("whsec_"));
    let mut cred = Credential { token: token.unwrap_or_default(), ..Default::default() };
    if let Some(s) = &webhook_secret {
        cred.fields.insert("webhook_secret".into(), s.clone());
    }
    let link = match app {
        Some((installation_id, (repo_id, _, _))) => Link::GitHubApp { installation_id, repo_id },
        None => Link::Token,
    };
    insert_source(ctx, &fresh, &cred, &link)?;
    let row = load_source_row(ctx, &fresh.id)?;
    Ok(Deferred::Ready(DocsSourceCreated { source: source_view(ctx, &row)?, webhook_secret }))
}

/// Refuses a source that can't be added: its topic must be one the admin can see, the workspace
/// has room, and the folder doesn't already sync into that topic.
fn check_new_source(ctx: &Ctx, s: &docs::NewSource) -> ApiResult<()> {
    load_topic(ctx, &s.topic_id)?;
    let count = ctx.db.scalar_i64("SELECT COUNT(*) FROM docs_sources", &[])?;
    if count >= MAX_SOURCES {
        return Err(ApiError::conflict(format!("a workspace can have at most {MAX_SOURCES} docs sync sources")));
    }
    let duplicate = ctx.db.one(
        "SELECT id FROM docs_sources WHERE provider = ? AND host = ? AND repo = ? AND branch = ? AND folder = ? AND topic_id = ?",
        &params![s.provider.id(), s.host.clone(), s.repo.clone(), s.branch.clone(), s.folder.clone(), s.topic_id.clone()],
    )?;
    if duplicate.is_some() {
        return Err(ApiError::conflict("that folder already syncs into that topic"));
    }
    Ok(())
}

/// Adds a source, checked again (see [`check_new_source`]), with its credentials sealed to it and how
/// it connects. Synced posts are written as the admin adding it.
pub(crate) fn insert_source(ctx: &mut Ctx, s: &docs::NewSource, cred: &Credential, link: &Link) -> ApiResult<()> {
    check_new_source(ctx, s)?;
    let secret = sync::seal(ctx.cfg, &docs::owner(&s.id), s.provider.id(), cred)?;
    let now = ctx.now_s();
    ctx.db.execute(
        "INSERT INTO docs_sources (id, provider, host, repo, branch, folder, topic_id, secret, owner_id, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        &params![
            s.id.clone(),
            s.provider.id(),
            s.host.clone(),
            s.repo.clone(),
            s.branch.clone(),
            s.folder.clone(),
            s.topic_id.clone(),
            secret,
            ctx.actor.user_id.clone(),
            now.clone(),
            now
        ],
    )?;
    match link {
        Link::Token => {}
        Link::GitHubApp { installation_id, repo_id } => {
            ctx.db.execute(
                "INSERT INTO docs_source_links (source_id, connection, installation_id, repo_id) VALUES (?, 'github_app', ?, ?)",
                &params![s.id.clone(), *installation_id, *repo_id],
            )?;
            // The directory may have missed this installation's link; asking again does no harm.
            ctx.effects.push(Effect::GitHubInstallation(InstallationLink { installation_id: *installation_id, linked: true }));
        }
        Link::GitLabOAuth { project_id, hook_id, token_expires_at } => {
            ctx.db.execute(
                "INSERT INTO docs_source_links (source_id, connection, project_id, hook_id, token_expires_at) VALUES (?, 'gitlab_oauth', ?, ?, ?)",
                &params![s.id.clone(), *project_id, *hook_id, token_expires_at.clone()],
            )?;
        }
    }
    emit(
        ctx,
        Event::new("docs_source.created", "docs_source", &s.id, format!("added docs sync from {}", s.repo)).topic(&s.topic_id).admin_only(),
    )?;
    Ok(())
}

/// What adding a source answers, for one added by a job (it has no webhook secret to show).
pub(crate) fn created_value(ctx: &Ctx, id: &str) -> ApiResult<serde_json::Value> {
    let row = load_source_row(ctx, id)?;
    let created = DocsSourceCreated { source: source_view(ctx, &row)?, webhook_secret: None };
    serde_json::to_value(created).map_err(|e| ApiError::internal(e.to_string()))
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
    /// Sources read through DumbSlab's GitLab app: use your newest Connect GitLab approval from now
    /// on (it moves to this source), e.g. after GitLab stopped accepting the old one.
    pub gitlab_connection: Option<bool>,
}

fn update_docs_source(ctx: &mut Ctx, input: UpdateDocsSourceInput) -> ApiResult<DocsSourceCreated> {
    key_needed(ctx)?;
    let row = load_source_row(ctx, &input.id)?;
    // Credentials that can't be read any more are replaced: a token, and a new webhook secret.
    let (mut source, readable) = Source::from_row_or_blank(ctx.cfg, &row)?;
    if source.link != Link::Token && (input.token.is_some() || input.new_webhook_secret == Some(true)) {
        return Err(ApiError::bad_request(
            "this source is read through DumbSlab's GitHub or GitLab app: it has no token or webhook secret to change.",
        ));
    }
    if input.gitlab_connection == Some(true) {
        let Link::GitLabOAuth { .. } = source.link else {
            return Err(ApiError::bad_request("`gitlab_connection` is for sources read through DumbSlab's GitLab app"));
        };
        let p = gitlab_app::pending(ctx.db, ctx.cfg, &ctx.actor.user_id)?
            .ok_or_else(|| ApiError::conflict("Connect GitLab first (Settings › Docs sync), then reconnect this folder."))?;
        // The webhook keeps its secret; only the tokens change.
        source.cred.token = p.cred.token;
        source.cred.refresh_token = p.cred.refresh_token;
        gitlab_app::take_pending(ctx.db, &ctx.actor.user_id)?;
        ctx.db.execute(
            "UPDATE docs_source_links SET token_expires_at = ?, disconnected = NULL WHERE source_id = ?",
            &params![p.expires_at.map(crate::util::ts), source.id.clone()],
        )?;
    }
    if let Some(t) = secret_input(input.token, "token")? {
        source.cred.token = t;
    }
    if let Some(b) = clean(input.branch) {
        source.repo.branch = sync::checked_branch(&b)?;
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
    let id = row.str("id");
    // The webhook DumbSlab added to a GitLab project comes off too, once this is done.
    if let Ok(source) = Source::from_row(ctx.cfg, &row)
        && let Link::GitLabOAuth { project_id, hook_id: Some(hook_id), token_expires_at } = source.link
    {
        let expires_at = token_expires_at.as_deref().and_then(crate::util::parse_ts);
        let job = gitlab_app::GitLabJob::remove_hook(project_id, hook_id, source.cred, expires_at);
        ctx.effects.push(Effect::Background(Job::GitLab(Box::new(job))));
    }
    ctx.db.execute("DELETE FROM docs_items WHERE source_id = ?", &params![id.clone()])?;
    ctx.db.execute("DELETE FROM docs_sources WHERE id = ?", &params![id.clone()])?;
    emit(ctx, Event::new("docs_source.deleted", "docs_source", &id, format!("removed docs sync from {}", row.str("repo"))).admin_only())?;
    Ok(DONE)
}
