use chrono::Duration;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{DONE, Done, NoInput, clean, required};
use crate::auth::Role;
use crate::db::{Db, DbExt, Row, SqlValue};
use crate::error::{ApiError, ApiResult};
use crate::events::{Event, emit};
use crate::model::*;
use crate::ops::posts::{CreatePostInput, PostLink};
use crate::params;
use crate::registry::{Access, Ctx, Op, op};
use crate::util::{new_id, new_secret, slugify, ts};

pub fn ops() -> Vec<Op> {
    vec![
        op("admin", "get_settings", "GET", "/settings", Access::Read, get_settings).title("Workspace settings").build(),
        op("admin", "update_settings", "PATCH", "/settings", Access::Admin, update_settings).title("Update workspace settings").build(),
        op("admin", "change_address", "POST", "/settings/address", Access::Admin, change_address)
            .title("Change the workspace address")
            .desc("Hosted workspaces only (such as on dumbslab.com): move the workspace to a new subdomain, e.g. from acme to acme-docs. Posts, people and API tokens all move with it. The old address forwards people to the new one and stays reserved for this workspace. Everyone signs in again at the new address, and MCP clients need the new URL. A workspace can use at most 5 addresses; moving back to an earlier one always works.")
            .build(),
        op("admin", "get_insights", "GET", "/insights", Access::Read, get_insights)
            .title("Knowledge base insights")
            .desc("Counts, most-viewed posts, posts whose verification expired, posts not updated in a long time, and top contributors. Useful for finding docs that need attention.")
            .build(),
        op("admin", "list_webhooks", "GET", "/webhooks", Access::Admin, list_webhooks).title("List webhooks").build(),
        op("admin", "create_webhook", "POST", "/webhooks", Access::Admin, create_webhook)
            .title("Create a webhook")
            .desc("POST every matching event to a URL. Each delivery is signed: `x-dumbslab-signature: sha256=HMAC_SHA256(secret, timestamp + \".\" + body)` with `x-dumbslab-timestamp`. Event filters: `*`, `post.*`, or a list like `post.created,comment.created`.")
            .build(),
        op("admin", "update_webhook", "PATCH", "/webhooks/{id}", Access::Admin, update_webhook).title("Update a webhook").build(),
        op("admin", "delete_webhook", "DELETE", "/webhooks/{id}", Access::Admin, delete_webhook).title("Delete a webhook").destructive().build(),
        op("admin", "export_workspace", "GET", "/export", Access::Admin, export_workspace)
            .title("Export everything")
            .desc("All topics, posts (Markdown), comments and people as JSON, for backups or migration.")
            .build(),
        op("admin", "import_documents", "POST", "/import", Access::Write, import_documents)
            .title("Import Markdown documents")
            .desc("Create many posts at once, e.g. when migrating from Confluence, Guru, a GitHub wiki, Notion or a docs folder. Each document can name a topic path like `Engineering/Runbooks` (inside `topic_id` when given); missing topics are created. Inside a private topic, new topics are private with the same members, and a path through a topic more people can see is refused. Imports don't notify topic followers or mentioned people. Pass `skip_existing: true` to skip documents whose title is already one of your posts in the same topic, so an interrupted import can be re-run without duplicates; a title someone else's post has there is reported in `taken` and not imported. A failing document rolls back the whole call, so send batches (25 is a good size) and retry a failed batch one document at a time. To migrate a whole export: convert each page to Markdown, import the pages (`results` lists the post for each document in order), upload each page's images with upload_file and that page's `post_id`, then use edit_post to put the returned `/files/...` paths and links to the new posts (`/p/<id>`) in place.")
            .build(),
    ]
}

pub fn setting(db: &dyn Db, key: &str) -> ApiResult<Option<String>> {
    Ok(db.one("SELECT value FROM settings WHERE key = ?", &params![key])?.map(|r| r.str("value")))
}

pub fn setting_i64(db: &dyn Db, key: &str, default: i64) -> ApiResult<i64> {
    Ok(setting(db, key)?.and_then(|v| v.parse().ok()).unwrap_or(default))
}

pub fn put_setting(db: &dyn Db, key: &str, value: &str) -> ApiResult<()> {
    db.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        &params![key, value],
    )?;
    Ok(())
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Settings {
    pub workspace_name: String,
    /// Shown on the home page.
    pub welcome_message: String,
    /// Default verification period in days.
    pub default_verification_days: i64,
    /// Hosted workspaces only: the subdomain, e.g. `acme` for acme.dumbslab.com. Change it with `change_address`.
    pub address: Option<String>,
}

fn read_settings(ctx: &Ctx) -> ApiResult<Settings> {
    let db = ctx.db;
    Ok(Settings {
        workspace_name: setting(db, "workspace_name")?.unwrap_or_else(|| "DumbSlab".into()),
        welcome_message: setting(db, "welcome_message")?.unwrap_or_default(),
        default_verification_days: setting_i64(db, "default_verification_days", 90)?,
        address: ctx.cfg.workspace.clone(),
    })
}

fn get_settings(ctx: &mut Ctx, _: NoInput) -> ApiResult<Settings> {
    read_settings(ctx)
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangeAddressInput {
    /// The new subdomain: 3 to 32 lowercase letters, digits and hyphens, e.g. `acme-docs` for acme-docs.dumbslab.com.
    pub address: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct AddressChange {
    /// The new subdomain.
    pub address: String,
    /// The workspace's new web address.
    pub url: String,
    /// The new MCP server URL. Update it in your AI tools.
    pub mcp_url: String,
    /// The old subdomain, which now forwards to the new one.
    pub previous_address: String,
}

fn change_address(ctx: &mut Ctx, input: ChangeAddressInput) -> ApiResult<AddressChange> {
    let Some(from) = ctx.cfg.workspace.clone() else {
        return Err(ApiError::bad_request(
            "only hosted workspaces (like those on dumbslab.com) have an address to change; a self-hosted server lives at its own domain",
        ));
    };
    let to = input.address.trim().to_ascii_lowercase();
    crate::tenancy::validate_slug(&to).map_err(ApiError::bad_request)?;
    if to == from {
        return Err(ApiError::conflict(format!("the workspace is already at {to}")));
    }
    // The host claims the address and records the move; nothing is written here.
    ctx.effects.push(crate::Effect::MoveAddress(crate::AddressMove { from: from.clone(), to: to.clone(), actor: ctx.actor.clone() }));
    let url = crate::tenancy::origin_for(&ctx.base_url, &from, &to);
    Ok(AddressChange { address: to, mcp_url: format!("{url}/mcp"), url, previous_address: from })
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateSettingsInput {
    pub workspace_name: Option<String>,
    pub welcome_message: Option<String>,
    pub default_verification_days: Option<u32>,
}

fn update_settings(ctx: &mut Ctx, input: UpdateSettingsInput) -> ApiResult<Settings> {
    if let Some(n) = input.workspace_name {
        put_setting(ctx.db, "workspace_name", &required(&n, "workspace_name", 80)?)?;
    }
    if let Some(w) = input.welcome_message {
        put_setting(ctx.db, "welcome_message", w.trim())?;
    }
    if let Some(d) = input.default_verification_days {
        put_setting(ctx.db, "default_verification_days", &d.to_string())?;
    }
    emit(ctx, Event::new("settings.updated", "settings", "workspace", "updated workspace settings").admin_only())?;
    read_settings(ctx)
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Counts {
    pub published: i64,
    pub drafts: i64,
    pub archived: i64,
    pub topics: i64,
    pub people: i64,
    pub comments: i64,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Contributor {
    pub user: UserRef,
    pub posts: i64,
    pub edits: i64,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Insights {
    pub counts: Counts,
    pub most_viewed: Vec<PostSummary>,
    /// Verified posts whose verification has expired.
    pub verification_expired: Vec<PostSummary>,
    /// Published posts not updated in `stale_after_days`.
    pub stale: Vec<PostSummary>,
    pub top_contributors: Vec<Contributor>,
    pub stale_after_days: i64,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InsightsInput {
    /// Default 180.
    pub stale_after_days: Option<u32>,
}

fn visible_posts(ctx: &Ctx, cond: &str, cond_params: Vec<SqlValue>, order: &str, limit: i64) -> ApiResult<Vec<PostSummary>> {
    let mut p = cond_params;
    let vis = post_visible_sql(&ctx.actor, "p", &mut p);
    p.push(limit.into());
    let rows = ctx.db.query(
        &format!(
            "SELECT {POST_COLS} FROM posts p WHERE p.deleted_at IS NULL AND p.is_template = 0 AND {cond} AND {vis} ORDER BY {order} LIMIT ?"
        ),
        &p,
    )?;
    summaries(ctx, &rows)
}

fn get_insights(ctx: &mut Ctx, input: InsightsInput) -> ApiResult<Insights> {
    let stale_days = input.stale_after_days.unwrap_or(180) as i64;
    let now = ctx.now_s();
    let count = |status: &str| -> ApiResult<i64> {
        let mut p = params![status];
        let vis = post_visible_sql(&ctx.actor, "p", &mut p);
        ctx.db.scalar_i64(
            &format!("SELECT COUNT(*) FROM posts p WHERE p.status = ? AND p.deleted_at IS NULL AND p.is_template = 0 AND {vis}"),
            &p,
        )
    };
    let mut tp = vec![];
    let tvis = topic_visible_sql(&ctx.actor, "t", &mut tp);
    let counts = Counts {
        published: count("published")?,
        drafts: count("draft")?,
        archived: count("archived")?,
        topics: ctx.db.scalar_i64(&format!("SELECT COUNT(*) FROM topics t WHERE {tvis}"), &tp)?,
        people: ctx.db.scalar_i64("SELECT COUNT(*) FROM users WHERE deactivated_at IS NULL", &[])?,
        comments: {
            let mut p = vec![];
            let vis = post_visible_sql(&ctx.actor, "p", &mut p);
            ctx.db.scalar_i64(
                &format!("SELECT COUNT(*) FROM comments c JOIN posts p ON p.id = c.post_id WHERE c.deleted_at IS NULL AND p.deleted_at IS NULL AND {vis}"),
                &p,
            )?
        },
    };
    let most_viewed = visible_posts(ctx, "p.status = 'published' AND p.view_count > 0", vec![], "p.view_count DESC", 5)?;
    let verification_expired = visible_posts(
        ctx,
        "p.status = 'published' AND p.verified_at IS NOT NULL AND p.verification_expires_at <= ?",
        params![now],
        "p.verification_expires_at",
        20,
    )?;
    let stale = visible_posts(
        ctx,
        "p.status = 'published' AND p.updated_at < ?",
        params![ts(ctx.now - Duration::days(stale_days))],
        "p.updated_at",
        20,
    )?;
    let mut p = vec![];
    let authored_vis = post_visible_sql(&ctx.actor, "ap", &mut p);
    let edited_vis = post_visible_sql(&ctx.actor, "p", &mut p);
    let rows = ctx.db.query(
        &format!(
            "SELECT v.editor_id, COUNT(*) AS edits,
                    (SELECT COUNT(*) FROM posts ap WHERE ap.author_id = v.editor_id AND ap.deleted_at IS NULL AND ap.status = 'published' AND {authored_vis}) AS posts
             FROM post_versions v JOIN posts p ON p.id = v.post_id
             WHERE v.editor_id IS NOT NULL AND p.deleted_at IS NULL AND {edited_vis}
             GROUP BY v.editor_id ORDER BY edits DESC LIMIT 5"
        ),
        &p,
    )?;
    let users = user_refs(ctx.db, &rows.iter().map(|r| r.str("editor_id")).collect::<Vec<_>>())?;
    let top_contributors = rows
        .iter()
        .map(|r| Contributor { user: user_ref(&users, &r.str("editor_id")), posts: r.i64("posts"), edits: r.i64("edits") })
        .collect();
    Ok(Insights { counts, most_viewed, verification_expired, stale, top_contributors, stale_after_days: stale_days })
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Webhook {
    pub id: String,
    pub url: String,
    pub events: String,
    pub description: String,
    pub active: bool,
    pub created_at: String,
    pub last_delivery_at: Option<String>,
    pub last_status: Option<i64>,
    pub last_error: Option<String>,
}

fn to_webhook(r: &Row) -> Webhook {
    Webhook {
        id: r.str("id"),
        url: r.str("url"),
        events: r.str("events"),
        description: r.str("description"),
        active: r.bool("active"),
        created_at: r.str("created_at"),
        last_delivery_at: r.opt_str("last_delivery_at"),
        last_status: r.opt_i64("last_status"),
        last_error: r.opt_str("last_error"),
    }
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct WebhookList {
    pub items: Vec<Webhook>,
}

fn list_webhooks(ctx: &mut Ctx, _: NoInput) -> ApiResult<WebhookList> {
    let rows = ctx.db.query("SELECT * FROM webhooks ORDER BY created_at", &[])?;
    Ok(WebhookList { items: rows.iter().map(to_webhook).collect() })
}

fn check_url(url: &str) -> ApiResult<String> {
    let u = url.trim();
    if !(u.starts_with("https://") || u.starts_with("http://")) || u.len() > 2000 || u.contains(char::is_whitespace) {
        return Err(ApiError::bad_request("url must be an http(s) URL"));
    }
    Ok(u.to_string())
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateWebhookInput {
    pub url: String,
    /// Event filters, e.g. `["post.*", "comment.created"]`. Default `["*"]`.
    pub events: Option<Vec<String>>,
    pub description: Option<String>,
    /// Signing secret. Generated when omitted.
    pub secret: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct CreatedWebhook {
    pub webhook: Webhook,
    /// The signing secret. Shown only now.
    pub secret: String,
}

fn create_webhook(ctx: &mut Ctx, input: CreateWebhookInput) -> ApiResult<CreatedWebhook> {
    let url = check_url(&input.url)?;
    let events = input.events.unwrap_or_else(|| vec!["*".into()]).join(",");
    let secret = clean(input.secret).unwrap_or_else(|| new_secret("whsec_"));
    let id = new_id();
    let now = ctx.now_s();
    ctx.db.execute(
        "INSERT INTO webhooks (id, url, secret, events, description, active, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)",
        &params![id.clone(), url.clone(), secret.clone(), events, clean(input.description).unwrap_or_default(), ctx.actor.user_id.clone(), now.clone(), now],
    )?;
    emit(ctx, Event::new("webhook.created", "webhook", &id, format!("added a webhook to {url}")).admin_only())?;
    let row = ctx.db.one("SELECT * FROM webhooks WHERE id = ?", &params![id])?.ok_or_else(|| ApiError::internal("webhook vanished"))?;
    Ok(CreatedWebhook { webhook: to_webhook(&row), secret })
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateWebhookInput {
    pub id: String,
    pub url: Option<String>,
    pub events: Option<Vec<String>>,
    pub description: Option<String>,
    pub active: Option<bool>,
}

fn update_webhook(ctx: &mut Ctx, input: UpdateWebhookInput) -> ApiResult<Webhook> {
    ctx.db.one("SELECT id FROM webhooks WHERE id = ?", &params![input.id.clone()])?.ok_or_else(|| ApiError::not_found("webhook"))?;
    let mut sets: Vec<&str> = vec![];
    let mut p: Vec<SqlValue> = vec![];
    if let Some(u) = input.url {
        sets.push("url = ?");
        p.push(check_url(&u)?.into());
    }
    if let Some(e) = input.events {
        sets.push("events = ?");
        p.push(e.join(",").into());
    }
    if let Some(d) = input.description {
        sets.push("description = ?");
        p.push(d.trim().to_string().into());
    }
    if let Some(a) = input.active {
        sets.push("active = ?");
        p.push(a.into());
    }
    sets.push("updated_at = ?");
    p.push(ctx.now_s().into());
    p.push(input.id.clone().into());
    ctx.db.execute(&format!("UPDATE webhooks SET {} WHERE id = ?", sets.join(", ")), &p)?;
    emit(ctx, Event::new("webhook.updated", "webhook", &input.id, "updated a webhook").admin_only())?;
    let row = ctx.db.one("SELECT * FROM webhooks WHERE id = ?", &params![input.id])?.ok_or_else(|| ApiError::not_found("webhook"))?;
    Ok(to_webhook(&row))
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebhookIdInput {
    pub id: String,
}

fn delete_webhook(ctx: &mut Ctx, input: WebhookIdInput) -> ApiResult<Done> {
    let n = ctx.db.execute("DELETE FROM webhooks WHERE id = ?", &params![input.id.clone()])?;
    if n == 0 {
        return Err(ApiError::not_found("webhook"));
    }
    emit(ctx, Event::new("webhook.deleted", "webhook", &input.id, "deleted a webhook").admin_only())?;
    Ok(DONE)
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ExportedPost {
    pub id: String,
    pub title: String,
    pub content: String,
    pub status: String,
    pub is_template: bool,
    pub author_email: String,
    pub topic_ids: Vec<String>,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ExportedTopic {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub description: String,
    pub icon: String,
    pub color: String,
    pub visibility: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ExportedComment {
    pub id: String,
    pub post_id: String,
    pub parent_id: Option<String>,
    pub author_email: String,
    pub body: String,
    pub quote: Option<String>,
    pub resolved: bool,
    pub created_at: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Export {
    pub format: String,
    pub exported_at: String,
    pub settings: Settings,
    pub people: Vec<User>,
    pub topics: Vec<ExportedTopic>,
    pub posts: Vec<ExportedPost>,
    pub comments: Vec<ExportedComment>,
}

fn export_workspace(ctx: &mut Ctx, _: NoInput) -> ApiResult<Export> {
    let people: Vec<User> =
        ctx.db.query(&format!("SELECT {USER_COLS} FROM users ORDER BY created_at"), &[])?.iter().map(User::from_row).collect();
    let email_of = |id: &str| people.iter().find(|u| u.id == id).map(|u| u.email.clone()).unwrap_or_default();
    let topics = ctx
        .db
        .query("SELECT * FROM topics ORDER BY created_at", &[])?
        .iter()
        .map(|r| ExportedTopic {
            id: r.str("id"),
            parent_id: r.opt_str("parent_id"),
            name: r.str("name"),
            description: r.str("description"),
            icon: r.str("icon"),
            color: r.str("color"),
            visibility: r.str("visibility"),
        })
        .collect();
    let links = ctx.db.query("SELECT post_id, topic_id FROM post_topics", &[])?;
    let posts = ctx
        .db
        .query("SELECT * FROM posts ORDER BY created_at", &[])?
        .iter()
        .map(|r| ExportedPost {
            topic_ids: links.iter().filter(|l| l.str("post_id") == r.str("id")).map(|l| l.str("topic_id")).collect(),
            id: r.str("id"),
            title: r.str("title"),
            content: r.str("content"),
            status: r.str("status"),
            is_template: r.bool("is_template"),
            author_email: email_of(&r.str("author_id")),
            version: r.i64("version"),
            created_at: r.str("created_at"),
            updated_at: r.str("updated_at"),
            deleted_at: r.opt_str("deleted_at"),
        })
        .collect();
    let comments = ctx
        .db
        .query("SELECT * FROM comments WHERE deleted_at IS NULL ORDER BY created_at", &[])?
        .iter()
        .map(|r| ExportedComment {
            id: r.str("id"),
            post_id: r.str("post_id"),
            parent_id: r.opt_str("parent_id"),
            author_email: email_of(&r.str("author_id")),
            body: r.str("body"),
            quote: r.opt_str("quote"),
            resolved: r.opt_str("resolved_at").is_some(),
            created_at: r.str("created_at"),
        })
        .collect();
    Ok(Export {
        format: "dumbslab-export-v1".into(),
        exported_at: ctx.now_s(),
        settings: read_settings(ctx)?,
        people,
        topics,
        posts,
        comments,
    })
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImportDocument {
    pub title: String,
    /// Markdown body.
    pub content: String,
    /// Topic path such as `Engineering/Runbooks`, inside `topic_id` when that is given. Missing
    /// topics are created; inside a private topic they are private, with its members, and a path
    /// through a topic more people can see than its private parent is refused.
    pub topic: Option<String>,
    /// `published` (default) or `draft`.
    pub status: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImportInput {
    /// Up to 500 documents per call.
    pub documents: Vec<ImportDocument>,
    /// An existing topic to import into, by id: each document's `topic` path is created inside it,
    /// and a document without one goes in this topic. Without it, paths start at the top level.
    pub topic_id: Option<String>,
    /// Skip a document when a post with exactly the same title is already in its topic (for a
    /// document without a topic: among posts with no topic), and report that post instead. Only
    /// your own posts count as already imported: when the post is someone else's, nothing is
    /// created and the document is reported in `taken`. Trashed posts and templates don't count.
    /// Default false.
    pub skip_existing: Option<bool>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ImportedDocument {
    /// The post created for the document, or the existing post it matched.
    pub id: String,
    pub title: String,
    pub url: String,
    /// True when `skip_existing` matched an existing post and nothing was created.
    pub skipped: bool,
    /// With `skipped`: the matching post is someone else's, so the document wasn't imported.
    /// Leave that post alone; rename the document or import it into another topic.
    pub taken: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ImportResult {
    /// Posts this call created.
    pub created: Vec<PostLink>,
    /// Your existing posts that `skip_existing` matched, so their documents weren't imported again.
    pub skipped: Vec<PostLink>,
    /// Someone else's posts that already have a document's title in its topic, so with
    /// `skip_existing` those documents weren't imported.
    pub taken: Vec<PostLink>,
    /// One entry per document, in the order sent.
    pub results: Vec<ImportedDocument>,
    pub topics_created: i64,
}

/// A topic on an import's path.
#[derive(Clone)]
struct PathTopic {
    id: String,
    name: String,
    private: bool,
}

/// Finds or creates each segment of a topic path below `base` (or at the top); returns the leaf
/// topic id. Inside a private topic, nothing an import does is visible to more people than that
/// topic: topics it creates there are private with the same members (and the importer), and an
/// existing topic more people can see is refused rather than used. Visibility doesn't inherit,
/// so a public topic under a private one would otherwise show the import to everyone.
fn ensure_topic_path(ctx: &mut Ctx, base: Option<PathTopic>, path: &str, created: &mut i64) -> ApiResult<Option<String>> {
    let mut parent = base;
    for segment in path.split('/').map(str::trim).filter(|s| !s.is_empty()) {
        let parent_id = parent.as_ref().map(|t| t.id.clone());
        let mut p = params![segment, parent_id.clone()];
        let vis = topic_visible_sql(&ctx.actor, "t", &mut p);
        let existing = ctx.db.one(
            &format!("SELECT t.id, t.name, t.visibility FROM topics t WHERE t.name = ? COLLATE NOCASE AND t.parent_id IS ? AND {vis}"),
            &p,
        )?;
        let next = match existing {
            Some(r) => {
                let topic = PathTopic { id: r.str("id"), name: r.str("name"), private: r.str("visibility") == "private" };
                if let Some(up) = parent.as_ref().filter(|up| up.private) {
                    // Compare who can read, not member lists: admins read every private topic, so an
                    // admin among the members (such as an admin importer this import added) widens
                    // nothing. Anyone else must be a member of the parent too.
                    let wider = !topic.private
                        || ctx.db.scalar_i64(
                            "SELECT COUNT(*) FROM topic_members c JOIN users cu ON cu.id = c.user_id
                             WHERE c.topic_id = ? AND cu.role != 'admin'
                               AND NOT EXISTS (SELECT 1 FROM topic_members u WHERE u.topic_id = ? AND u.user_id = c.user_id)",
                            &params![topic.id.clone(), up.id.clone()],
                        )? > 0;
                    if wider {
                        return Err(ApiError::conflict(format!(
                            "“{}” is inside the private topic “{}”, but more people can see it, so the import won't put pages in it or add topics under it. Make it private with the same members as “{}”, or import somewhere else.",
                            topic.name, up.name, up.name
                        )));
                    }
                }
                topic
            }
            None => {
                let private = parent.as_ref().is_some_and(|t| t.private);
                let id = new_id();
                let now = ctx.now_s();
                ctx.db.execute(
                    "INSERT INTO topics (id, parent_id, name, slug, visibility, position, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)",
                    &params![
                        id.clone(),
                        parent_id.clone(),
                        segment,
                        slugify(segment),
                        if private { "private" } else { "org" },
                        ctx.actor.user_id.clone(),
                        now.clone(),
                        now.clone()
                    ],
                )?;
                if private {
                    ctx.db.execute(
                        "INSERT INTO topic_members (topic_id, user_id, added_at) SELECT ?, user_id, ? FROM topic_members WHERE topic_id = ? ON CONFLICT DO NOTHING",
                        &params![id.clone(), now.clone(), parent_id.clone()],
                    )?;
                    ctx.db.execute(
                        "INSERT INTO topic_members (topic_id, user_id, added_at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
                        &params![id.clone(), ctx.actor.user_id.clone(), now],
                    )?;
                }
                crate::search::index_topic(ctx.db, &id)?;
                let mut event = Event::new("topic.created", "topic", &id, format!("created topic “{segment}” during import")).topic(&id);
                if private {
                    event = event.admin_only();
                }
                emit(ctx, event)?;
                *created += 1;
                PathTopic { id, name: segment.to_string(), private }
            }
        };
        parent = Some(next);
    }
    Ok(parent.map(|t| t.id))
}

/// A post the actor can see with exactly this title in the topic (or, without a topic, in no
/// topic), the actor's own first, and whether it is the actor's. Trashed posts and templates
/// don't count.
fn existing_post(ctx: &Ctx, title: &str, topic_id: Option<&str>) -> ApiResult<Option<(PostLink, bool)>> {
    let mut p = params![ctx.actor.user_id.clone(), title];
    let place = match topic_id {
        Some(tid) => {
            p.push(tid.into());
            "EXISTS (SELECT 1 FROM post_topics ipt WHERE ipt.post_id = p.id AND ipt.topic_id = ?)"
        }
        None => "NOT EXISTS (SELECT 1 FROM post_topics ipt WHERE ipt.post_id = p.id)",
    };
    let vis = post_visible_sql(&ctx.actor, "p", &mut p);
    let row = ctx.db.one(
        &format!(
            "SELECT p.id, p.title, p.slug, p.author_id = ? AS own FROM posts p WHERE p.title = ? AND {place} AND p.deleted_at IS NULL AND p.is_template = 0 AND {vis} ORDER BY own DESC, p.created_at LIMIT 1"
        ),
        &p,
    )?;
    Ok(row.map(|r| (PostLink { url: post_url(ctx, &r.str("id"), &r.str("slug")), id: r.str("id"), title: r.str("title") }, r.bool("own"))))
}

fn import_documents(ctx: &mut Ctx, input: ImportInput) -> ApiResult<ImportResult> {
    ctx.actor.require_role(Role::Member)?;
    if input.documents.len() > 500 {
        return Err(ApiError::bad_request("import at most 500 documents per call"));
    }
    let skip_existing = input.skip_existing.unwrap_or(false);
    let (mut created, mut skipped, mut taken, mut results) = (vec![], vec![], vec![], vec![]);
    let base = match clean(input.topic_id) {
        Some(id) => {
            let t = load_topic(ctx, &id)?;
            Some(PathTopic { id: t.str("id"), name: t.str("name"), private: t.str("visibility") == "private" })
        }
        None => None,
    };
    let mut topics_created = 0;
    for doc in input.documents {
        let topic_id = ensure_topic_path(ctx, base.clone(), doc.topic.as_deref().unwrap_or_default(), &mut topics_created)?;
        // Only the caller's own post counts as this document already imported. Someone else's post
        // with the title is neither adopted (a retry would then change it) nor duplicated.
        if skip_existing && let Some((post, own)) = existing_post(ctx, doc.title.trim(), topic_id.as_deref())? {
            results.push(ImportedDocument {
                id: post.id.clone(),
                title: post.title.clone(),
                url: post.url.clone(),
                skipped: true,
                taken: !own,
            });
            if own {
                skipped.push(post)
            } else {
                taken.push(post)
            }
            continue;
        }
        // Imported text was written elsewhere: its @handles aren't meant for people here, and
        // followers of a topic shouldn't get a notification per imported page.
        let post = crate::ops::posts::insert_post(
            ctx,
            CreatePostInput {
                title: doc.title,
                content: Some(doc.content),
                topic_ids: Some(topic_id.into_iter().collect()),
                status: Some(doc.status.unwrap_or_else(|| "published".into())),
                is_template: None,
                template_id: None,
            },
            false,
        )?;
        let link = PostLink { id: post.summary.id, title: post.summary.title, url: post.summary.url };
        results.push(ImportedDocument {
            id: link.id.clone(),
            title: link.title.clone(),
            url: link.url.clone(),
            skipped: false,
            taken: false,
        });
        created.push(link);
    }
    emit(
        ctx,
        Event::new("import.completed", "workspace", "import", format!("imported {} documents", created.len()))
            .data(json!({ "count": created.len(), "skipped": skipped.len(), "taken": taken.len() })),
    )?;
    Ok(ImportResult { created, skipped, taken, results, topics_created })
}
