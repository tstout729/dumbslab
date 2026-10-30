use std::collections::HashSet;

use chrono::Duration;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{check_content, clean, required};
use crate::auth::{Role, Via};
use crate::db::{DbExt, Row, SqlValue};
use crate::error::{ApiError, ApiResult};
use crate::events::{Event, emit};
use crate::markdown::{self, Heading};
use crate::model::*;
use crate::notify::{self, Notice};
use crate::ops::comments::{ReactionGroup, reaction_groups};
use crate::params;
use crate::registry::{Access, Ctx, Op, op};
use crate::search;
use crate::util::{new_id, slugify};

pub fn ops() -> Vec<Op> {
    vec![
        op("posts", "list_posts", "GET", "/posts", Access::Read, list_posts)
            .title("List posts")
            .desc("List posts with filters (topic, author, status, template, verification) and sorting. Returns summaries without content; use get_post for the body. Defaults to published, non-template posts sorted by last update.")
            .build(),
        op("posts", "get_post", "GET", "/posts/{id}", Access::Read, get_post)
            .title("Get a post")
            .desc("Get one post with its Markdown content, outline (headings with anchors), topics, verification, reactions and backlinks. Use `version` from the result as `base_version` when editing to avoid overwriting someone else's change.")
            .build(),
        op("posts", "create_post", "POST", "/posts", Access::Write, create_post)
            .title("Create a post")
            .desc("Create a post from Markdown. Status defaults to `draft` (visible only to you and admins); pass `status: \"published\"` to share it with the team. Link other posts with `/p/{id}` URLs and mention people with `@handle`.")
            .build(),
        op("posts", "update_post", "PATCH", "/posts/{id}", Access::Write, update_post)
            .title("Update a post")
            .desc("Change a post's title, full content, topics, status (`draft`, `published`, `archived`) or template flag. Only the fields you pass change. For small changes to long posts prefer edit_post.")
            .build(),
        op("posts", "edit_post", "POST", "/posts/{id}/edit", Access::Write, edit_post)
            .title("Edit part of a post")
            .desc("Apply precise edits without resending the whole post: exact find/replace, append, prepend, and section edits addressed by heading text. Edits apply in order and all-or-nothing. A `replace` must match exactly once unless `all` is true.")
            .build(),
        op("posts", "delete_post", "DELETE", "/posts/{id}", Access::Write, delete_post)
            .title("Delete a post")
            .desc("Move a post to the trash (restorable with restore_post). Authors and admins only. Admins can pass `permanent: true` to erase it and its history.")
            .destructive()
            .build(),
        op("posts", "restore_post", "POST", "/posts/{id}/restore", Access::Write, restore_post)
            .title("Restore a post from the trash")
            .idempotent()
            .build(),
        op("posts", "duplicate_post", "POST", "/posts/{id}/duplicate", Access::Write, duplicate_post)
            .title("Duplicate a post")
            .desc("Copy a post (content and topics) into a new draft.")
            .build(),
        op("posts", "list_post_versions", "GET", "/posts/{id}/versions", Access::Read, list_versions)
            .title("List a post's versions")
            .desc("Version history, newest first. Every save creates a version.")
            .build(),
        op("posts", "get_post_version", "GET", "/posts/{id}/versions/{version}", Access::Read, get_version)
            .title("Get one version of a post")
            .build(),
        op("posts", "diff_post_versions", "GET", "/posts/{id}/diff", Access::Read, diff_versions)
            .title("Diff two versions")
            .desc("Unified diff between two versions of a post. Defaults to the latest change (previous version → current).")
            .build(),
        op("posts", "restore_post_version", "POST", "/posts/{id}/versions/{version}/restore", Access::Write, restore_version)
            .title("Restore an old version")
            .desc("Make an old version current again. This creates a new version; history is never lost.")
            .build(),
        op("posts", "verify_post", "POST", "/posts/{id}/verify", Access::Write, verify_post)
            .title("Verify a post")
            .desc("Mark a post as verified (accurate and current) for a number of days. After that it shows as expired so someone re-checks it.")
            .idempotent()
            .build(),
        op("posts", "unverify_post", "DELETE", "/posts/{id}/verify", Access::Write, unverify_post)
            .title("Remove verification")
            .build(),
    ]
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct PostList {
    pub items: Vec<PostSummary>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct PostLink {
    pub id: String,
    pub title: String,
    pub url: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Post {
    #[serde(flatten)]
    pub summary: PostSummary,
    /// The post body as Markdown.
    pub content: String,
    /// Rendered, sanitized HTML (only when `format` asks for it).
    pub html: Option<String>,
    pub outline: Vec<Heading>,
    /// Posts that link to this one.
    pub backlinks: Vec<PostLink>,
    pub last_editor: Option<UserRef>,
    pub following: bool,
    pub reactions: Vec<ReactionGroup>,
    pub can_edit: bool,
    /// Topic ids where this post is pinned.
    pub pinned_in: Vec<String>,
    /// Set when the post is kept in sync with a file in a repository (docs sync): its title and
    /// content change only there, and edits here are refused. Topics, status, verification,
    /// comments and reactions still work here.
    pub synced_from: Option<crate::sync::docs::SyncedFrom>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListPostsInput {
    /// Only posts in this topic.
    pub topic_id: Option<String>,
    /// With `topic_id`, also include posts in its subtopics. Default true.
    pub include_subtopics: Option<bool>,
    /// Author id, `@handle`, email or `me`.
    pub author: Option<String>,
    /// `published` (default), `draft`, `archived`, `trash`, or `all` (everything not in the trash).
    pub status: Option<String>,
    /// `true` lists templates only. Default false.
    pub is_template: Option<bool>,
    /// `verified`, `expired` or `unverified`.
    pub verification: Option<String>,
    /// Only posts updated at or after this RFC 3339 time.
    pub updated_since: Option<String>,
    /// `updated` (default), `created`, `published`, `title` or `views`.
    pub sort: Option<String>,
    /// 1-200, default 25.
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

fn list_posts(ctx: &mut Ctx, input: ListPostsInput) -> ApiResult<PostList> {
    let (limit, offset) = page(input.limit, &input.cursor)?;
    let mut p: Vec<SqlValue> = vec![];
    let mut prefix = String::new();
    let mut conds: Vec<String> = vec![];
    let topic_id = clean(input.topic_id);
    if let Some(tid) = &topic_id {
        load_topic(ctx, tid)?;
        if input.include_subtopics.unwrap_or(true) {
            prefix = "WITH RECURSIVE sub(id) AS (SELECT ? UNION SELECT t.id FROM topics t JOIN sub ON t.parent_id = sub.id) ".into();
            p.push(tid.into());
            conds.push("EXISTS (SELECT 1 FROM post_topics fpt WHERE fpt.post_id = p.id AND fpt.topic_id IN (SELECT id FROM sub))".into());
        } else {
            conds.push("EXISTS (SELECT 1 FROM post_topics fpt WHERE fpt.post_id = p.id AND fpt.topic_id = ?)".into());
            p.push(tid.into());
        }
    }
    conds.push(
        match input.status.as_deref().unwrap_or("published") {
            "published" => "p.status = 'published' AND p.deleted_at IS NULL",
            "draft" => "p.status = 'draft' AND p.deleted_at IS NULL",
            "archived" => "p.status = 'archived' AND p.deleted_at IS NULL",
            "trash" => "p.deleted_at IS NOT NULL",
            "all" => "p.deleted_at IS NULL",
            other => return Err(ApiError::bad_request(format!("unknown status `{other}`"))),
        }
        .into(),
    );
    conds.push("p.is_template = ?".into());
    p.push(input.is_template.unwrap_or(false).into());
    if let Some(a) = clean(input.author) {
        let uid = find_user(ctx, &a)?.str("id");
        conds.push("p.author_id = ?".into());
        p.push(uid.into());
    }
    if let Some(v) = clean(input.verification) {
        let now = ctx.now_s();
        match v.as_str() {
            "verified" => {
                conds.push("p.verified_at IS NOT NULL AND (p.verification_expires_at IS NULL OR p.verification_expires_at > ?)".into());
                p.push(now.into());
            }
            "expired" => {
                conds.push("p.verified_at IS NOT NULL AND p.verification_expires_at <= ?".into());
                p.push(now.into());
            }
            "unverified" => conds.push("p.verified_at IS NULL".into()),
            other => return Err(ApiError::bad_request(format!("unknown verification filter `{other}`"))),
        }
    }
    if let Some(since) = clean(input.updated_since) {
        conds.push("p.updated_at >= ?".into());
        p.push(since.into());
    }
    let vis = post_visible_sql(&ctx.actor, "p", &mut p);
    conds.push(vis);
    let sort = match input.sort.as_deref().unwrap_or("updated") {
        "updated" => "p.updated_at DESC",
        "created" => "p.created_at DESC",
        "published" => "p.published_at DESC",
        "title" => "p.title COLLATE NOCASE ASC",
        "views" => "p.view_count DESC",
        other => return Err(ApiError::bad_request(format!("unknown sort `{other}`"))),
    };
    let pinned = match &topic_id {
        Some(tid) => {
            p.push(tid.into());
            "(SELECT COALESCE(MAX(pinned), 0) FROM post_topics WHERE post_id = p.id AND topic_id = ?) DESC, "
        }
        None => "",
    };
    p.push((limit + 1).into());
    p.push(offset.into());
    let sql =
        format!("{prefix}SELECT {POST_COLS} FROM posts p WHERE {} ORDER BY {pinned}{sort}, p.id LIMIT ? OFFSET ?", conds.join(" AND "));
    let mut rows = ctx.db.query(&sql, &p)?;
    let next_cursor = next_cursor(rows.len(), limit, offset);
    rows.truncate(limit as usize);
    Ok(PostList { items: summaries(ctx, &rows)?, next_cursor })
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetPostInput {
    pub id: String,
    /// `markdown` (default), `html`, or `both`. HTML is the rendered, sanitized body. In the web app,
    /// fetching HTML counts as a view.
    pub format: Option<String>,
}

fn get_post(ctx: &mut Ctx, input: GetPostInput) -> ApiResult<Post> {
    let row = load_post(ctx, &input.id, true)?;
    let with_html = matches!(input.format.as_deref(), Some("html" | "both"));
    // A person reading the rendered post counts as a view; the editor and agents fetching Markdown don't.
    if with_html && ctx.actor.via == Via::Web && row.opt_str("deleted_at").is_none() {
        record_view(ctx, &row.str("id"))?;
    }
    full_post(ctx, &row, with_html)
}

fn record_view(ctx: &Ctx, post_id: &str) -> ApiResult<()> {
    // A hosted workspace that has used its write allowance stops counting views too.
    if !crate::plan::can_write(ctx.db, ctx.cfg.hosting.as_ref(), ctx.now)? {
        return Ok(());
    }
    let recent = ctx.db.one(
        "SELECT viewed_at FROM post_views WHERE post_id = ? AND user_id = ? AND viewed_at > ?",
        &params![post_id, ctx.actor.user_id.clone(), crate::util::ts(ctx.now - Duration::hours(1))],
    )?;
    ctx.db.execute(
        "INSERT INTO post_views (post_id, user_id, viewed_at) VALUES (?, ?, ?)
         ON CONFLICT(post_id, user_id) DO UPDATE SET viewed_at = excluded.viewed_at",
        &params![post_id, ctx.actor.user_id.clone(), ctx.now_s()],
    )?;
    if recent.is_none() {
        ctx.db.execute("UPDATE posts SET view_count = view_count + 1 WHERE id = ?", &params![post_id])?;
    }
    Ok(())
}

/// Builds the full post response for a row loaded with `POST_COLS, p.content`.
pub fn full_post(ctx: &Ctx, row: &Row, with_html: bool) -> ApiResult<Post> {
    let id = row.str("id");
    let summary = summaries(ctx, std::slice::from_ref(row))?.remove(0);
    let content = row.str("content");
    let mut p = params![id.clone()];
    let vis = post_visible_sql(&ctx.actor, "p", &mut p);
    let backlinks = ctx
        .db
        .query(
            &format!(
                "SELECT p.id, p.title, p.slug FROM post_links l JOIN posts p ON p.id = l.source_id
                 WHERE l.target_id = ? AND p.deleted_at IS NULL AND {vis} ORDER BY p.title"
            ),
            &p,
        )?
        .iter()
        .map(|r| PostLink { url: post_url(ctx, &r.str("id"), &r.str("slug")), id: r.str("id"), title: r.str("title") })
        .collect();
    let last_editor = match row.opt_str("last_editor_id") {
        Some(eid) => user_refs(ctx.db, std::slice::from_ref(&eid))?.remove(&eid),
        None => None,
    };
    let pinned_in = ctx
        .db
        .query("SELECT topic_id FROM post_topics WHERE post_id = ? AND pinned = 1", &params![id.clone()])?
        .iter()
        .map(|r| r.str("topic_id"))
        .collect();
    Ok(Post {
        html: with_html.then(|| markdown::render(&content)),
        outline: markdown::outline(&content),
        backlinks,
        last_editor,
        following: notify::is_following(ctx.db, &ctx.actor.user_id, "post", &id)?,
        reactions: reaction_groups(ctx, "post", &id)?,
        can_edit: ctx.actor.role >= Role::Member && row.opt_str("deleted_at").is_none(),
        pinned_in,
        synced_from: crate::sync::docs::synced_from(ctx.db, &id)?,
        content,
        summary,
    })
}

fn reload(ctx: &Ctx, id: &str) -> ApiResult<Post> {
    let row = load_post(ctx, id, true)?;
    full_post(ctx, &row, false)
}

/// Replaces a post's topics. Every topic must be visible to the actor.
fn set_topics(ctx: &Ctx, post_id: &str, topic_ids: &[String]) -> ApiResult<(Vec<String>, Vec<String>)> {
    let mut wanted: Vec<String> = vec![];
    for t in topic_ids.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if !wanted.iter().any(|w| w == t) {
            load_topic(ctx, t)?;
            wanted.push(t.to_string());
        }
    }
    // Topics the actor can't see stay attached: they can neither see nor manage them.
    let mut p = vec![];
    let vis = topic_visible_sql(&ctx.actor, "t", &mut p);
    p.push(post_id.into());
    let current = ctx.db.query(
        &format!(
            "SELECT pt.topic_id, t.visibility, {vis} AS visible FROM post_topics pt JOIN topics t ON t.id = pt.topic_id WHERE pt.post_id = ?"
        ),
        &p,
    )?;
    let current_ids: Vec<String> = current.iter().map(|r| r.str("topic_id")).collect();
    let added: Vec<String> = wanted.iter().filter(|t| !current_ids.contains(t)).cloned().collect();
    let removed: Vec<String> =
        current.iter().filter(|r| r.bool("visible") && !wanted.contains(&r.str("topic_id"))).map(|r| r.str("topic_id")).collect();
    // A post without topics is visible to everyone, so dropping the last private topic would
    // publish a restricted post to the whole workspace. Sharing it takes an org-wide topic.
    let only_private = !current.is_empty() && current.iter().all(|r| r.str("visibility") == "private");
    if only_private && current.len() - removed.len() + added.len() == 0 {
        return Err(ApiError::conflict(
            "this post is only in private topics; removing them all would make it visible to everyone. Add an org-wide topic first if you mean to share it",
        ));
    }
    for t in &removed {
        ctx.db.execute("DELETE FROM post_topics WHERE post_id = ? AND topic_id = ?", &params![post_id, t.clone()])?;
    }
    for t in &added {
        ctx.db.execute(
            "INSERT INTO post_topics (post_id, topic_id, pinned, added_at) VALUES (?, ?, 0, ?)",
            &params![post_id, t.clone(), ctx.now_s()],
        )?;
    }
    Ok((added, removed))
}

fn update_links(ctx: &Ctx, post_id: &str, content: &str) -> ApiResult<()> {
    ctx.db.execute("DELETE FROM post_links WHERE source_id = ?", &params![post_id])?;
    for target in markdown::post_links(content).into_iter().filter(|t| t != post_id) {
        ctx.db.execute("INSERT INTO post_links (source_id, target_id) VALUES (?, ?) ON CONFLICT DO NOTHING", &params![post_id, target])?;
    }
    Ok(())
}

fn notify_mentions(ctx: &Ctx, post_id: &str, title: &str, handles: &[String]) -> ApiResult<()> {
    if handles.is_empty() {
        return Ok(());
    }
    let users = notify::resolve_handles(ctx.db, handles)?;
    notify::send(
        ctx,
        users,
        &Notice {
            kind: "mention",
            post_id: Some(post_id),
            comment_id: None,
            topic_id: None,
            message: format!("{} mentioned you in “{}”", ctx.actor.name, title),
        },
    )
}

/// Notifies topic followers and mentioned people when a post is first published.
fn on_first_publish(ctx: &Ctx, post_id: &str, title: &str, content: &str) -> ApiResult<()> {
    let topics = ctx.db.query("SELECT topic_id FROM post_topics WHERE post_id = ?", &params![post_id])?;
    for t in topics {
        let tid = t.str("topic_id");
        let followers = notify::followers(ctx.db, "topic", &tid)?;
        notify::send(
            ctx,
            followers,
            &Notice {
                kind: "new_post",
                post_id: Some(post_id),
                comment_id: None,
                topic_id: Some(&tid),
                message: format!("{} published “{}”", ctx.actor.name, title),
            },
        )?;
    }
    notify_mentions(ctx, post_id, title, &markdown::mentions(content))
}

/// Saves a new version when the title or content changed. Returns whether anything changed.
/// Synced posts change only in their repository.
fn save_revision(ctx: &Ctx, post: &Row, title: &str, content: &str, note: &str) -> ApiResult<bool> {
    if title != post.str("title") || content != post.str("content") {
        crate::sync::docs::refuse_edit(ctx.db, &post.str("id"), &post.str("title"))?;
    }
    write_revision(ctx, post, title, content, note, Writer::Person)
}

/// Who changes a post's text.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Writer {
    /// Someone editing here: mentions and followers are notified, and the person's own unattached
    /// uploads the text shows join the post.
    Person,
    /// Docs sync: the text was written in a repository by people who may not be able to see
    /// anything here. Nobody is notified, and no upload joins the post because the text mentions
    /// it; docs sync attaches only the images it stored itself.
    Sync,
}

/// Saves a new version when the title or content changed: the path every change to a post's
/// text takes, edits and docs sync alike (see [`Writer`]).
pub(crate) fn write_revision(ctx: &Ctx, post: &Row, title: &str, content: &str, note: &str, writer: Writer) -> ApiResult<bool> {
    let old_title = post.str("title");
    let old_content = post.str("content");
    if title == old_title && content == old_content {
        return Ok(false);
    }
    check_content(content)?;
    let id = post.str("id");
    let version = post.i64("version") + 1;
    ctx.db.execute(
        "UPDATE posts SET title = ?, slug = ?, content = ?, excerpt = ?, word_count = ?, version = ?, last_editor_id = ?, updated_at = ?
         WHERE id = ?",
        &params![
            title,
            slugify(title),
            content,
            markdown::excerpt(content, 240),
            markdown::word_count(content),
            version,
            ctx.actor.user_id.clone(),
            ctx.now_s(),
            id.clone()
        ],
    )?;
    ctx.db.execute(
        "INSERT INTO post_versions (post_id, version, title, content, editor_id, note, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        &params![id.clone(), version, title, content, ctx.actor.user_id.clone(), note, ctx.now_s()],
    )?;
    update_links(ctx, &id, content)?;
    if writer == Writer::Person {
        crate::ops::files::attach_referenced(ctx, &id, content)?;
    }
    search::index_post(ctx.db, &id)?;
    if title != old_title {
        search::reindex_post_comments(ctx.db, &id)?;
    }
    if writer == Writer::Person && post.str("status") == "published" {
        let before: HashSet<String> = markdown::mentions(&old_content).into_iter().collect();
        let new: Vec<String> = markdown::mentions(content).into_iter().filter(|m| !before.contains(m)).collect();
        notify_mentions(ctx, &id, title, &new)?;
        let followers = notify::followers(ctx.db, "post", &id)?;
        notify::send(
            ctx,
            followers,
            &Notice {
                kind: "post_updated",
                post_id: Some(&id),
                comment_id: None,
                topic_id: None,
                message: format!("{} updated “{}”", ctx.actor.name, title),
            },
        )?;
    }
    Ok(true)
}

fn check_base_version(post: &Row, base: Option<i64>) -> ApiResult<()> {
    let current = post.i64("version");
    match base {
        Some(b) if b != current => Err(ApiError::conflict(format!(
            "the post changed since version {b} (now version {current}); re-read it with get_post and retry"
        ))
        .with_details(json!({ "current_version": current }))),
        _ => Ok(()),
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreatePostInput {
    pub title: String,
    /// Markdown body.
    pub content: Option<String>,
    pub topic_ids: Option<Vec<String>>,
    /// `draft` (default) or `published`.
    pub status: Option<String>,
    /// Save as a reusable template.
    pub is_template: Option<bool>,
    /// Start from this template's content when `content` is empty.
    pub template_id: Option<String>,
}

pub fn create_post(ctx: &mut Ctx, input: CreatePostInput) -> ApiResult<Post> {
    insert_post(ctx, input, true)
}

/// Creates a post. `notify: false` skips the notifications a first publish sends (topic
/// followers and `@mentions`), for imports, whose text was written elsewhere.
pub fn insert_post(ctx: &mut Ctx, input: CreatePostInput, notify: bool) -> ApiResult<Post> {
    ctx.actor.require_role(Role::Member)?;
    let title = required(&input.title, "title", 300)?;
    let mut content = input.content.unwrap_or_default();
    if let Some(tid) = clean(input.template_id) {
        let template = load_post(ctx, &tid, false)?;
        if content.trim().is_empty() {
            content = template.str("content");
        }
    }
    check_content(&content)?;
    let status = match input.status.as_deref().unwrap_or("draft") {
        s @ ("draft" | "published") => s,
        other => return Err(ApiError::bad_request(format!("a new post's status must be draft or published, not `{other}`"))),
    };
    let id = new_id();
    let now = ctx.now_s();
    ctx.db.execute(
        "INSERT INTO posts (id, title, slug, content, excerpt, status, is_template, author_id, last_editor_id, version, word_count,
                            created_at, updated_at, published_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)",
        &params![
            id.clone(),
            title.clone(),
            slugify(&title),
            content.clone(),
            markdown::excerpt(&content, 240),
            status,
            input.is_template.unwrap_or(false),
            ctx.actor.user_id.clone(),
            ctx.actor.user_id.clone(),
            markdown::word_count(&content),
            now.clone(),
            now.clone(),
            (status == "published").then(|| now.clone())
        ],
    )?;
    ctx.db.execute(
        "INSERT INTO post_versions (post_id, version, title, content, editor_id, note, created_at) VALUES (?, 1, ?, ?, ?, 'Created', ?)",
        &params![id.clone(), title.clone(), content.clone(), ctx.actor.user_id.clone(), now],
    )?;
    set_topics(ctx, &id, &input.topic_ids.unwrap_or_default())?;
    update_links(ctx, &id, &content)?;
    crate::ops::files::attach_referenced(ctx, &id, &content)?;
    search::index_post(ctx.db, &id)?;
    let uid = ctx.actor.user_id.clone();
    notify::follow(ctx, &uid, "post", &id)?;
    if status == "published" && notify {
        on_first_publish(ctx, &id, &title, &content)?;
    }
    emit(ctx, Event::new("post.created", "post", &id, format!("created “{title}”")).post(&id).data(json!({ "status": status })))?;
    reload(ctx, &id)
}

/// What [`sync_post`] did.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Synced {
    Created,
    Updated,
    Unchanged,
    /// The post is in the trash; it was left alone.
    Trashed,
}

/// Docs sync: sets a post's title and content, creating it (published) with this id when there's
/// no such post. Changes take the same path as edits ([`write_revision`]), so each one is a version
/// in the history; but they notify nobody and attach no uploads ([`Writer::Sync`]).
pub(crate) fn sync_post(ctx: &mut Ctx, id: &str, title: &str, content: &str, note: &str) -> ApiResult<Synced> {
    let title = required(title, "title", 300)?;
    if let Some(post) = ctx.db.one(&format!("SELECT {POST_COLS}, p.content FROM posts p WHERE p.id = ?"), &params![id])? {
        if post.opt_str("deleted_at").is_some() {
            return Ok(Synced::Trashed);
        }
        if !write_revision(ctx, &post, &title, content, note, Writer::Sync)? {
            return Ok(Synced::Unchanged);
        }
        emit(
            ctx,
            Event::new("post.updated", "post", id, format!("synced “{title}”"))
                .post(id)
                .data(json!({ "fields": ["content"], "version": post.i64("version") + 1, "synced": true })),
        )?;
        return Ok(Synced::Updated);
    }
    check_content(content)?;
    let now = ctx.now_s();
    ctx.db.execute(
        "INSERT INTO posts (id, title, slug, content, excerpt, status, author_id, last_editor_id, version, word_count, created_at, updated_at, published_at)
         VALUES (?, ?, ?, ?, ?, 'published', ?, ?, 1, ?, ?, ?, ?)",
        &params![
            id,
            title.clone(),
            slugify(&title),
            content,
            markdown::excerpt(content, 240),
            ctx.actor.user_id.clone(),
            ctx.actor.user_id.clone(),
            markdown::word_count(content),
            now.clone(),
            now.clone(),
            now.clone()
        ],
    )?;
    ctx.db.execute(
        "INSERT INTO post_versions (post_id, version, title, content, editor_id, note, created_at) VALUES (?, 1, ?, ?, ?, ?, ?)",
        &params![id, title.clone(), content, ctx.actor.user_id.clone(), note, now],
    )?;
    // No upload joins the post because its text mentions one (see `Writer::Sync`).
    update_links(ctx, id, content)?;
    search::index_post(ctx.db, id)?;
    emit(
        ctx,
        Event::new("post.created", "post", id, format!("synced “{title}”")).post(id).data(json!({ "status": "published", "synced": true })),
    )?;
    Ok(Synced::Created)
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdatePostInput {
    pub id: String,
    pub title: Option<String>,
    /// Replaces the whole Markdown body.
    pub content: Option<String>,
    /// Replaces the post's topics.
    pub topic_ids: Option<Vec<String>>,
    /// Adds topics, keeping existing ones.
    pub add_topic_ids: Option<Vec<String>>,
    /// Removes topics.
    pub remove_topic_ids: Option<Vec<String>>,
    /// `draft`, `published` or `archived`.
    pub status: Option<String>,
    pub is_template: Option<bool>,
    /// The version you last read. If the post changed since, the update fails with 409 instead of overwriting.
    pub base_version: Option<i64>,
    /// A short note for the version history.
    pub note: Option<String>,
}

pub(crate) fn update_post(ctx: &mut Ctx, input: UpdatePostInput) -> ApiResult<Post> {
    let post = load_post(ctx, &input.id, false)?;
    require_post_edit(ctx, &post)?;
    let id = post.str("id");
    let changes_text = input.title.is_some() || input.content.is_some();
    if changes_text {
        check_base_version(&post, input.base_version)?;
    }
    let title = match &input.title {
        Some(t) => required(t, "title", 300)?,
        None => post.str("title"),
    };
    let content = input.content.clone().unwrap_or_else(|| post.str("content"));
    let note = clean(input.note).unwrap_or_default();
    let mut fields: Vec<&str> = vec![];
    if save_revision(ctx, &post, &title, &content, &note)? {
        fields.push("content");
    }

    if input.topic_ids.is_some() || input.add_topic_ids.is_some() || input.remove_topic_ids.is_some() {
        let mut ids: Vec<String> = match input.topic_ids {
            Some(ids) => ids,
            None => topics_for_posts(ctx, std::slice::from_ref(&id))?.remove(&id).unwrap_or_default().into_iter().map(|t| t.id).collect(),
        };
        ids.extend(input.add_topic_ids.unwrap_or_default());
        let remove = input.remove_topic_ids.unwrap_or_default();
        ids.retain(|t| !remove.contains(t));
        let (added, removed) = set_topics(ctx, &id, &ids)?;
        if !added.is_empty() || !removed.is_empty() {
            fields.push("topics");
            emit(
                ctx,
                Event::new("post.moved", "post", &id, format!("changed topics of “{title}”"))
                    .post(&id)
                    .data(json!({ "added": added, "removed": removed })),
            )?;
        }
    }

    if let Some(t) = input.is_template
        && t != post.bool("is_template")
    {
        ctx.db.execute("UPDATE posts SET is_template = ?, updated_at = ? WHERE id = ?", &params![t, ctx.now_s(), id.clone()])?;
        fields.push("is_template");
    }

    if let Some(status) = clean(input.status) {
        let current = post.str("status");
        if status != current {
            let now = ctx.now_s();
            match status.as_str() {
                "published" => {
                    ctx.db.execute(
                        "UPDATE posts SET status = 'published', published_at = COALESCE(published_at, ?), archived_at = NULL, updated_at = ? WHERE id = ?",
                        &params![now.clone(), now, id.clone()],
                    )?;
                    if post.opt_str("published_at").is_none() {
                        on_first_publish(ctx, &id, &title, &content)?;
                    }
                    emit(ctx, Event::new("post.published", "post", &id, format!("published “{title}”")).post(&id))?;
                }
                "draft" => {
                    if post.str("author_id") != ctx.actor.user_id && !ctx.actor.sees_all() {
                        return Err(ApiError::forbidden("only the author or an admin can move a post back to drafts"));
                    }
                    ctx.db.execute("UPDATE posts SET status = 'draft', updated_at = ? WHERE id = ?", &params![now, id.clone()])?;
                    emit(ctx, Event::new("post.unpublished", "post", &id, format!("moved “{title}” to drafts")).post(&id))?;
                }
                "archived" => {
                    ctx.db.execute(
                        "UPDATE posts SET status = 'archived', archived_at = ?, updated_at = ? WHERE id = ?",
                        &params![now.clone(), now, id.clone()],
                    )?;
                    emit(ctx, Event::new("post.archived", "post", &id, format!("archived “{title}”")).post(&id))?;
                }
                other => return Err(ApiError::bad_request(format!("unknown status `{other}` (use draft, published or archived)"))),
            }
            fields.push("status");
        }
    }

    if fields.contains(&"content") || fields.contains(&"is_template") {
        let version = post.i64("version") + i64::from(fields.contains(&"content"));
        emit(
            ctx,
            Event::new("post.updated", "post", &id, format!("updated “{title}”"))
                .post(&id)
                .data(json!({ "fields": fields, "version": version })),
        )?;
    }
    reload(ctx, &id)
}

/// One precise edit. Edits apply in order.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EditOp {
    /// Replace exact text. Fails unless it matches exactly once, or `all` is true.
    Replace {
        find: String,
        replace: String,
        #[serde(default)]
        all: bool,
    },
    /// Add Markdown to the end of the post.
    Append { content: String },
    /// Add Markdown to the start of the post.
    Prepend { content: String },
    /// Replace the body under a heading (up to the next heading of the same or higher level). The heading line stays.
    ReplaceSection { heading: String, content: String },
    /// Add Markdown at the end of a section.
    AppendToSection { heading: String, content: String },
    /// Add a new section. By default it goes at the end; with `after` it goes after that section.
    InsertSection {
        heading: String,
        content: String,
        /// Heading level 1-6. Default 2.
        level: Option<u8>,
        after: Option<String>,
    },
    /// Remove a section, including its heading.
    DeleteSection { heading: String },
}

fn block(content: &str) -> String {
    format!("{}\n", content.trim_end_matches('\n'))
}

fn section_or_err(md: &str, heading: &str) -> Result<markdown::Section, String> {
    markdown::find_section(md, heading).ok_or_else(|| {
        let available = markdown::heading_titles(md);
        format!(
            "no heading matching `{heading}`; headings are: {}",
            if available.is_empty() { "(none)".into() } else { available.join(", ") }
        )
    })
}

/// Applies edits to Markdown. Pure, so it is easy to test.
pub fn apply_edits(original: &str, edits: &[EditOp]) -> Result<String, String> {
    let mut md = original.to_string();
    for (i, edit) in edits.iter().enumerate() {
        let n = i + 1;
        md = match edit {
            EditOp::Replace { find, replace, all } => {
                if find.is_empty() {
                    return Err(format!("edit {n}: `find` is empty"));
                }
                let count = md.matches(find.as_str()).count();
                match (count, *all) {
                    (0, _) => return Err(format!("edit {n}: text not found: {find:?}")),
                    (1, _) | (_, true) => {
                        let projected = (md.len() - count * find.len()).saturating_add(count.saturating_mul(replace.len()));
                        if projected > super::MAX_CONTENT {
                            return Err(format!("edit {n}: the post would be larger than 2 MB"));
                        }
                        md.replace(find.as_str(), replace)
                    }
                    (c, false) => {
                        return Err(format!("edit {n}: text matches {c} times; include more surrounding text or set `all: true`"));
                    }
                }
            }
            EditOp::Append { content } => {
                let base = md.trim_end_matches('\n');
                if base.is_empty() { block(content) } else { format!("{base}\n\n{}", block(content)) }
            }
            EditOp::Prepend { content } => {
                let rest = md.trim_start_matches('\n');
                if rest.is_empty() { block(content) } else { format!("{}\n{rest}", block(content)) }
            }
            EditOp::ReplaceSection { heading, content } => {
                let s = section_or_err(&md, heading).map_err(|e| format!("edit {n}: {e}"))?;
                let body = if content.trim().is_empty() { String::new() } else { format!("\n{}", block(content)) };
                format!("{}{body}{}", heading_line(&md, &s), spaced_tail(&md[s.end..]))
            }
            EditOp::AppendToSection { heading, content } => {
                let s = section_or_err(&md, heading).map_err(|e| format!("edit {n}: {e}"))?;
                let existing = md[s.body_start..s.end].trim_matches('\n');
                let body = if existing.trim().is_empty() {
                    format!("\n{}", block(content))
                } else {
                    format!("\n{existing}\n\n{}", block(content))
                };
                format!("{}{body}{}", heading_line(&md, &s), spaced_tail(&md[s.end..]))
            }
            EditOp::InsertSection { heading, content, level, after } => {
                let level = level.unwrap_or(2).clamp(1, 6) as usize;
                let new_section = format!("{} {}\n\n{}", "#".repeat(level), heading.trim(), block(content));
                match after {
                    Some(h) => {
                        let s = section_or_err(&md, h).map_err(|e| format!("edit {n}: {e}"))?;
                        let head = md[..s.end].trim_end_matches('\n');
                        format!("{head}\n\n{new_section}{}", spaced_tail(&md[s.end..]))
                    }
                    None => {
                        let base = md.trim_end_matches('\n');
                        if base.is_empty() { new_section } else { format!("{base}\n\n{new_section}") }
                    }
                }
            }
            EditOp::DeleteSection { heading } => {
                let s = section_or_err(&md, heading).map_err(|e| format!("edit {n}: {e}"))?;
                let head = md[..s.heading_start].trim_end_matches('\n');
                let tail = md[s.end..].trim_start_matches('\n');
                match (head.is_empty(), tail.is_empty()) {
                    (true, _) => tail.to_string(),
                    (false, true) => format!("{head}\n"),
                    (false, false) => format!("{head}\n\n{tail}"),
                }
            }
        };
        if md.len() > super::MAX_CONTENT {
            return Err(format!("edit {n}: the post would be larger than 2 MB"));
        }
    }
    Ok(md)
}

/// Everything up to and including the section's heading line, ending in exactly one newline.
fn heading_line(md: &str, s: &markdown::Section) -> String {
    format!("{}\n", md[..s.body_start].trim_end_matches(['\n', '\r']))
}

/// Keeps a blank line before the next heading after a section edit.
fn spaced_tail(tail: &str) -> String {
    if tail.is_empty() { String::new() } else { format!("\n{}", tail.trim_start_matches('\n')) }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EditPostInput {
    pub id: String,
    pub edits: Vec<EditOp>,
    /// The version you last read; the edit fails with 409 if the post changed since.
    pub base_version: Option<i64>,
    pub note: Option<String>,
}

fn edit_post(ctx: &mut Ctx, input: EditPostInput) -> ApiResult<Post> {
    if input.edits.is_empty() {
        return Err(ApiError::bad_request("`edits` is empty"));
    }
    let post = load_post(ctx, &input.id, false)?;
    require_post_edit(ctx, &post)?;
    check_base_version(&post, input.base_version)?;
    let id = post.str("id");
    let title = post.str("title");
    let content = apply_edits(&post.str("content"), &input.edits).map_err(ApiError::bad_request)?;
    if save_revision(ctx, &post, &title, &content, &clean(input.note).unwrap_or_default())? {
        emit(
            ctx,
            Event::new("post.updated", "post", &id, format!("edited “{title}”"))
                .post(&id)
                .data(json!({ "fields": ["content"], "edits": input.edits.len(), "version": post.i64("version") + 1 })),
        )?;
    }
    reload(ctx, &id)
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeletePostInput {
    pub id: String,
    /// Admins only: erase the post and its history instead of moving it to the trash.
    pub permanent: Option<bool>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DeleteResult {
    pub ok: bool,
    pub id: String,
    pub permanent: bool,
}

fn delete_post(ctx: &mut Ctx, input: DeletePostInput) -> ApiResult<DeleteResult> {
    let post = load_post(ctx, &input.id, true)?;
    let id = post.str("id");
    let title = post.str("title");
    let is_author = post.str("author_id") == ctx.actor.user_id;
    if !is_author && ctx.actor.role != Role::Admin {
        return Err(ApiError::forbidden("only the author or an admin can delete a post; members can archive it instead"));
    }
    let permanent = input.permanent.unwrap_or(false);
    if permanent {
        ctx.actor.require_admin()?;
        for r in ctx.db.query("SELECT id FROM comments WHERE post_id = ?", &params![id.clone()])? {
            search::remove(ctx.db, "comment", &r.str("id"))?;
        }
        search::remove(ctx.db, "post", &id)?;
        let p = params![id.clone()];
        ctx.db.execute(
            "DELETE FROM reactions WHERE target_type = 'comment' AND target_id IN (SELECT id FROM comments WHERE post_id = ?)",
            &p,
        )?;
        ctx.db.execute("DELETE FROM reactions WHERE target_type = 'post' AND target_id = ?", &p)?;
        ctx.db.execute("DELETE FROM follows WHERE target_type = 'post' AND target_id = ?", &p)?;
        ctx.db.execute("DELETE FROM notifications WHERE post_id = ?", &p)?;
        ctx.db.execute("DELETE FROM comments WHERE post_id = ?", &p)?;
        for table in ["post_topics", "post_versions", "post_views"] {
            ctx.db.execute(&format!("DELETE FROM {table} WHERE post_id = ?"), &p)?;
        }
        ctx.db.execute("DELETE FROM post_links WHERE source_id = ?", &p)?;
        crate::ops::files::delete_for_post(ctx.db, &id)?;
        ctx.db.execute("DELETE FROM posts WHERE id = ?", &p)?;
        emit(ctx, Event::new("post.purged", "post", &id, format!("permanently deleted “{title}”")).admin_only())?;
    } else if post.opt_str("deleted_at").is_none() {
        ctx.db.execute(
            "UPDATE posts SET deleted_at = ?, deleted_by = ? WHERE id = ?",
            &params![ctx.now_s(), ctx.actor.user_id.clone(), id.clone()],
        )?;
        search::index_post(ctx.db, &id)?;
        for r in ctx.db.query("SELECT id FROM comments WHERE post_id = ?", &params![id.clone()])? {
            search::remove(ctx.db, "comment", &r.str("id"))?;
        }
        emit(ctx, Event::new("post.deleted", "post", &id, format!("moved “{title}” to the trash")).post(&id))?;
    }
    Ok(DeleteResult { ok: true, id, permanent })
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PostIdInput {
    pub id: String,
}

fn restore_post(ctx: &mut Ctx, input: PostIdInput) -> ApiResult<Post> {
    let post = load_post(ctx, &input.id, true)?;
    ctx.actor.require_role(Role::Member)?;
    let id = post.str("id");
    if post.opt_str("deleted_at").is_some() {
        ctx.db.execute("UPDATE posts SET deleted_at = NULL, deleted_by = NULL WHERE id = ?", &params![id.clone()])?;
        search::index_post(ctx.db, &id)?;
        search::reindex_post_comments(ctx.db, &id)?;
        emit(ctx, Event::new("post.restored", "post", &id, format!("restored “{}” from the trash", post.str("title"))).post(&id))?;
    }
    reload(ctx, &id)
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DuplicatePostInput {
    pub id: String,
    /// Defaults to "Copy of <title>".
    pub title: Option<String>,
}

fn duplicate_post(ctx: &mut Ctx, input: DuplicatePostInput) -> ApiResult<Post> {
    let post = load_post(ctx, &input.id, false)?;
    let topics: Vec<String> = topics_for_posts(ctx, std::slice::from_ref(&post.str("id")))?
        .remove(&post.str("id"))
        .unwrap_or_default()
        .into_iter()
        .map(|t| t.id)
        .collect();
    create_post(
        ctx,
        CreatePostInput {
            title: clean(input.title).unwrap_or_else(|| format!("Copy of {}", post.str("title"))),
            content: Some(post.str("content")),
            topic_ids: Some(topics),
            status: Some("draft".into()),
            is_template: None,
            template_id: None,
        },
    )
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListVersionsInput {
    pub id: String,
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct VersionInfo {
    pub version: i64,
    pub title: String,
    pub editor: Option<UserRef>,
    pub note: String,
    pub created_at: String,
    pub characters: i64,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct VersionList {
    pub items: Vec<VersionInfo>,
    pub current_version: i64,
    pub next_cursor: Option<String>,
}

fn list_versions(ctx: &mut Ctx, input: ListVersionsInput) -> ApiResult<VersionList> {
    let post = load_post(ctx, &input.id, true)?;
    let (limit, offset) = page(input.limit, &input.cursor)?;
    let mut rows = ctx.db.query(
        "SELECT version, title, editor_id, note, created_at, length(content) AS characters FROM post_versions
         WHERE post_id = ? ORDER BY version DESC LIMIT ? OFFSET ?",
        &params![post.str("id"), limit + 1, offset],
    )?;
    let next_cursor = next_cursor(rows.len(), limit, offset);
    rows.truncate(limit as usize);
    let users = user_refs(ctx.db, &rows.iter().filter_map(|r| r.opt_str("editor_id")).collect::<Vec<_>>())?;
    Ok(VersionList {
        items: rows
            .iter()
            .map(|r| VersionInfo {
                version: r.i64("version"),
                title: r.str("title"),
                editor: r.opt_str("editor_id").map(|id| user_ref(&users, &id)),
                note: r.str("note"),
                created_at: r.str("created_at"),
                characters: r.i64("characters"),
            })
            .collect(),
        current_version: post.i64("version"),
        next_cursor,
    })
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VersionInput {
    pub id: String,
    pub version: i64,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct VersionDetail {
    pub post_id: String,
    pub version: i64,
    pub title: String,
    pub content: String,
    pub editor: Option<UserRef>,
    pub note: String,
    pub created_at: String,
}

fn load_version(ctx: &Ctx, post_id: &str, version: i64) -> ApiResult<Row> {
    ctx.db
        .one("SELECT * FROM post_versions WHERE post_id = ? AND version = ?", &params![post_id, version])?
        .ok_or_else(|| ApiError::not_found(format!("version {version}")))
}

fn get_version(ctx: &mut Ctx, input: VersionInput) -> ApiResult<VersionDetail> {
    let post = load_post(ctx, &input.id, true)?;
    let v = load_version(ctx, &post.str("id"), input.version)?;
    let editor = match v.opt_str("editor_id") {
        Some(id) => Some(user_ref(&user_refs(ctx.db, std::slice::from_ref(&id))?, &id)),
        None => None,
    };
    Ok(VersionDetail {
        post_id: post.str("id"),
        version: v.i64("version"),
        title: v.str("title"),
        content: v.str("content"),
        editor,
        note: v.str("note"),
        created_at: v.str("created_at"),
    })
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiffInput {
    pub id: String,
    /// Older version. Defaults to `to - 1`.
    pub from: Option<i64>,
    /// Newer version. Defaults to the current version.
    pub to: Option<i64>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DiffResult {
    pub from: i64,
    pub to: i64,
    pub title_changed: bool,
    pub added_lines: i64,
    pub removed_lines: i64,
    /// Unified diff of the Markdown.
    pub diff: String,
}

fn diff_versions(ctx: &mut Ctx, input: DiffInput) -> ApiResult<DiffResult> {
    let post = load_post(ctx, &input.id, true)?;
    let id = post.str("id");
    let to = input.to.unwrap_or(post.i64("version"));
    let from = input.from.unwrap_or((to - 1).max(1));
    let a = load_version(ctx, &id, from)?;
    let b = load_version(ctx, &id, to)?;
    let (old, new) = (a.str("content"), b.str("content"));
    let diff = similar::TextDiff::from_lines(old.as_str(), new.as_str());
    let (mut added, mut removed) = (0, 0);
    for change in diff.iter_all_changes() {
        match change.tag() {
            similar::ChangeTag::Insert => added += 1,
            similar::ChangeTag::Delete => removed += 1,
            similar::ChangeTag::Equal => {}
        }
    }
    let mut unified = diff.unified_diff();
    unified.context_radius(3).header(&format!("v{from}"), &format!("v{to}"));
    Ok(DiffResult {
        from,
        to,
        title_changed: a.str("title") != b.str("title"),
        added_lines: added,
        removed_lines: removed,
        diff: unified.to_string(),
    })
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RestoreVersionInput {
    pub id: String,
    pub version: i64,
}

fn restore_version(ctx: &mut Ctx, input: RestoreVersionInput) -> ApiResult<Post> {
    let post = load_post(ctx, &input.id, false)?;
    require_post_edit(ctx, &post)?;
    let id = post.str("id");
    let v = load_version(ctx, &id, input.version)?;
    let note = format!("Restored version {}", input.version);
    if save_revision(ctx, &post, &v.str("title"), &v.str("content"), &note)? {
        emit(
            ctx,
            Event::new("post.updated", "post", &id, format!("restored version {} of “{}”", input.version, v.str("title")))
                .post(&id)
                .data(json!({ "fields": ["content"], "restored_version": input.version, "version": post.i64("version") + 1 })),
        )?;
    }
    reload(ctx, &id)
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VerifyInput {
    pub id: String,
    /// Days until the verification expires. Defaults to the workspace setting (90). 0 means it never expires.
    pub expires_in_days: Option<u32>,
}

fn verify_post(ctx: &mut Ctx, input: VerifyInput) -> ApiResult<Post> {
    let post = load_post(ctx, &input.id, false)?;
    require_post_edit(ctx, &post)?;
    let id = post.str("id");
    let days = match input.expires_in_days {
        Some(d) => d as i64,
        None => crate::ops::admin::setting_i64(ctx.db, "default_verification_days", 90)?,
    };
    let expires = (days > 0).then(|| crate::util::ts(ctx.now + Duration::days(days)));
    ctx.db.execute(
        "UPDATE posts SET verified_by = ?, verified_at = ?, verification_expires_at = ? WHERE id = ?",
        &params![ctx.actor.user_id.clone(), ctx.now_s(), expires.clone(), id.clone()],
    )?;
    emit(
        ctx,
        Event::new("post.verified", "post", &id, format!("verified “{}”", post.str("title")))
            .post(&id)
            .data(json!({ "expires_at": expires })),
    )?;
    reload(ctx, &id)
}

fn unverify_post(ctx: &mut Ctx, input: PostIdInput) -> ApiResult<Post> {
    let post = load_post(ctx, &input.id, false)?;
    require_post_edit(ctx, &post)?;
    let id = post.str("id");
    if post.opt_str("verified_at").is_some() {
        ctx.db.execute(
            "UPDATE posts SET verified_by = NULL, verified_at = NULL, verification_expires_at = NULL WHERE id = ?",
            &params![id.clone()],
        )?;
        emit(ctx, Event::new("post.unverified", "post", &id, format!("removed verification from “{}”", post.str("title"))).post(&id))?;
    }
    reload(ctx, &id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rep(find: &str, replace: &str) -> EditOp {
        EditOp::Replace { find: find.into(), replace: replace.into(), all: false }
    }

    #[test]
    fn replace_requires_unique_match() {
        assert_eq!(apply_edits("a b a", &[rep("b", "c")]).unwrap(), "a c a");
        assert!(apply_edits("a b a", &[rep("a", "c")]).unwrap_err().contains("2 times"));
        assert!(apply_edits("a b a", &[rep("z", "c")]).unwrap_err().contains("not found"));
        let all = EditOp::Replace { find: "a".into(), replace: "c".into(), all: true };
        assert_eq!(apply_edits("a b a", &[all]).unwrap(), "c b c");
    }

    #[test]
    fn section_edits() {
        let md = "# Doc\n\nintro\n\n## Setup\n\nold steps\n\n## Usage\n\nuse it\n";
        let out = apply_edits(md, &[EditOp::ReplaceSection { heading: "Setup".into(), content: "new steps".into() }]).unwrap();
        assert_eq!(out, "# Doc\n\nintro\n\n## Setup\n\nnew steps\n\n## Usage\n\nuse it\n");
        let out = apply_edits(md, &[EditOp::AppendToSection { heading: "setup".into(), content: "more".into() }]).unwrap();
        assert_eq!(out, "# Doc\n\nintro\n\n## Setup\n\nold steps\n\nmore\n\n## Usage\n\nuse it\n");
        let out = apply_edits(md, &[EditOp::DeleteSection { heading: "Setup".into() }]).unwrap();
        assert_eq!(out, "# Doc\n\nintro\n\n## Usage\n\nuse it\n");
        let out = apply_edits(
            md,
            &[EditOp::InsertSection { heading: "FAQ".into(), content: "Q?".into(), level: None, after: Some("Setup".into()) }],
        )
        .unwrap();
        assert_eq!(out, "# Doc\n\nintro\n\n## Setup\n\nold steps\n\n## FAQ\n\nQ?\n\n## Usage\n\nuse it\n");
        assert!(apply_edits(md, &[EditOp::DeleteSection { heading: "Nope".into() }]).unwrap_err().contains("Setup"));
    }

    #[test]
    fn edits_cannot_blow_up_the_post() {
        let grow = EditOp::Replace { find: "a".into(), replace: "a".repeat(100), all: true };
        let err = apply_edits("a", &vec![grow; 5]).unwrap_err();
        assert!(err.contains("larger than 2 MB"), "{err}");
    }

    #[test]
    fn append_and_prepend() {
        assert_eq!(apply_edits("body\n", &[EditOp::Append { content: "tail".into() }]).unwrap(), "body\n\ntail\n");
        assert_eq!(apply_edits("body\n", &[EditOp::Prepend { content: "> note".into() }]).unwrap(), "> note\n\nbody\n");
        assert_eq!(apply_edits("", &[EditOp::Append { content: "first".into() }]).unwrap(), "first\n");
    }
}
