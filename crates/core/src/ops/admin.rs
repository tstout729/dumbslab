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
            .desc("Create many posts at once, e.g. when migrating from Slab, Notion or a docs folder. Each document can name a topic path like `Engineering/Runbooks`; missing topics are created.")
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
}

fn read_settings(db: &dyn Db) -> ApiResult<Settings> {
    Ok(Settings {
        workspace_name: setting(db, "workspace_name")?.unwrap_or_else(|| "DumbSlab".into()),
        welcome_message: setting(db, "welcome_message")?.unwrap_or_default(),
        default_verification_days: setting_i64(db, "default_verification_days", 90)?,
    })
}

fn get_settings(ctx: &mut Ctx, _: NoInput) -> ApiResult<Settings> {
    read_settings(ctx.db)
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
    read_settings(ctx.db)
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
        comments: ctx.db.scalar_i64("SELECT COUNT(*) FROM comments WHERE deleted_at IS NULL", &[])?,
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
    let rows = ctx.db.query(
        "SELECT v.editor_id, COUNT(*) AS edits, (SELECT COUNT(*) FROM posts p WHERE p.author_id = v.editor_id AND p.deleted_at IS NULL AND p.status = 'published') AS posts
         FROM post_versions v WHERE v.editor_id IS NOT NULL GROUP BY v.editor_id ORDER BY edits DESC LIMIT 5",
        &[],
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
        settings: read_settings(ctx.db)?,
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
    /// Topic path such as `Engineering/Runbooks`. Missing topics are created.
    pub topic: Option<String>,
    /// `published` (default) or `draft`.
    pub status: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImportInput {
    /// Up to 500 documents per call.
    pub documents: Vec<ImportDocument>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ImportResult {
    pub created: Vec<PostLink>,
    pub topics_created: i64,
}

/// Finds or creates each segment of a topic path; returns the leaf topic id.
fn ensure_topic_path(ctx: &mut Ctx, path: &str, created: &mut i64) -> ApiResult<Option<String>> {
    let mut parent: Option<String> = None;
    for segment in path.split('/').map(str::trim).filter(|s| !s.is_empty()) {
        let mut p = params![segment, parent.clone()];
        let vis = topic_visible_sql(&ctx.actor, "t", &mut p);
        let existing =
            ctx.db.one(&format!("SELECT t.id FROM topics t WHERE t.name = ? COLLATE NOCASE AND t.parent_id IS ? AND {vis}"), &p)?;
        let id = match existing {
            Some(r) => r.str("id"),
            None => {
                let id = new_id();
                let now = ctx.now_s();
                ctx.db.execute(
                    "INSERT INTO topics (id, parent_id, name, slug, visibility, position, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, 'org', 0, ?, ?, ?)",
                    &params![id.clone(), parent.clone(), segment, slugify(segment), ctx.actor.user_id.clone(), now.clone(), now],
                )?;
                crate::search::index_topic(ctx.db, &id)?;
                emit(ctx, Event::new("topic.created", "topic", &id, format!("created topic “{segment}” during import")).topic(&id))?;
                *created += 1;
                id
            }
        };
        parent = Some(id);
    }
    Ok(parent)
}

fn import_documents(ctx: &mut Ctx, input: ImportInput) -> ApiResult<ImportResult> {
    ctx.actor.require_role(Role::Member)?;
    if input.documents.len() > 500 {
        return Err(ApiError::bad_request("import at most 500 documents per call"));
    }
    let mut created = vec![];
    let mut topics_created = 0;
    for doc in input.documents {
        let topic_ids = match clean(doc.topic) {
            Some(path) => ensure_topic_path(ctx, &path, &mut topics_created)?.into_iter().collect(),
            None => vec![],
        };
        let post = crate::ops::posts::create_post(
            ctx,
            CreatePostInput {
                title: doc.title,
                content: Some(doc.content),
                topic_ids: Some(topic_ids),
                status: Some(doc.status.unwrap_or_else(|| "published".into())),
                is_template: None,
                template_id: None,
            },
        )?;
        created.push(PostLink { id: post.summary.id, title: post.summary.title, url: post.summary.url });
    }
    emit(
        ctx,
        Event::new("import.completed", "workspace", "import", format!("imported {} documents", created.len()))
            .data(json!({ "count": created.len() })),
    )?;
    Ok(ImportResult { created, topics_created })
}
