//! Shared output types, loaders and the visibility rules.
//!
//! Visibility rules:
//! - Admins see everything.
//! - A draft is visible only to its author (and admins).
//! - A post with no topics, or in at least one org-wide topic, is visible to everyone.
//! - A post whose topics are all private is visible to members of any of those topics.
//! - Authors always see their own posts.
//! - Trashed posts (`deleted_at` set) are excluded unless a query asks for the trash, and even then
//!   only their author (who alone, besides admins, may delete and restore them) sees them.

use std::collections::HashMap;

use chrono::Utc;
use schemars::JsonSchema;
use serde::Serialize;

use crate::auth::{Actor, Role};
use crate::db::{Db, DbExt, Row, SqlValue};
use crate::error::{ApiError, ApiResult};
use crate::params;
use crate::registry::Ctx;
use crate::util::parse_ts;

/// SQL that is true when posts alias `a` is visible to the actor. Pushes its parameters.
pub fn post_visible_sql(actor: &Actor, a: &str, params: &mut Vec<SqlValue>) -> String {
    if actor.sees_all() {
        return "1=1".into();
    }
    let uid = actor.user_id.clone();
    params.extend([uid.clone().into(), uid.clone().into(), uid.clone().into(), uid.into()]);
    format!(
        "(({a}.deleted_at IS NULL OR {a}.author_id = ?) AND ({a}.status != 'draft' OR {a}.author_id = ?) AND ({a}.author_id = ?
          OR NOT EXISTS (SELECT 1 FROM post_topics vpt WHERE vpt.post_id = {a}.id)
          OR EXISTS (SELECT 1 FROM post_topics vpt JOIN topics vt ON vt.id = vpt.topic_id
                     WHERE vpt.post_id = {a}.id AND (vt.visibility = 'org'
                       OR EXISTS (SELECT 1 FROM topic_members vtm WHERE vtm.topic_id = vt.id AND vtm.user_id = ?)))))"
    )
}

/// SQL that is true when topics alias `a` is visible to the actor.
pub fn topic_visible_sql(actor: &Actor, a: &str, params: &mut Vec<SqlValue>) -> String {
    if actor.sees_all() {
        return "1=1".into();
    }
    params.push(actor.user_id.clone().into());
    format!("({a}.visibility = 'org' OR EXISTS (SELECT 1 FROM topic_members vtm WHERE vtm.topic_id = {a}.id AND vtm.user_id = ?))")
}

/// Builds `?, ?, ?` for an `IN` list.
pub fn placeholders(n: usize) -> String {
    vec!["?"; n].join(", ")
}

/// Runs `sql` (containing `{in}`) for each chunk of ids, keeping under bound-parameter limits.
pub fn query_in(db: &dyn Db, sql: &str, ids: &[String], extra: &[SqlValue]) -> ApiResult<Vec<Row>> {
    let mut out = vec![];
    for chunk in ids.chunks(80) {
        let q = sql.replace("{in}", &placeholders(chunk.len()));
        let mut p: Vec<SqlValue> = chunk.iter().map(|s| SqlValue::from(s.as_str())).collect();
        p.extend_from_slice(extra);
        out.extend(db.query(&q, &p)?);
    }
    Ok(out)
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct UserRef {
    pub id: String,
    pub name: String,
    pub handle: String,
    pub avatar_url: Option<String>,
    pub is_bot: bool,
}

impl UserRef {
    fn from_row(r: &Row) -> UserRef {
        UserRef {
            id: r.str("id"),
            name: r.str("name"),
            handle: r.str("handle"),
            avatar_url: r.opt_str("avatar_url"),
            is_bot: r.bool("is_bot"),
        }
    }

    fn unknown(id: &str) -> UserRef {
        UserRef { id: id.to_string(), name: "Unknown user".into(), handle: "unknown".into(), avatar_url: None, is_bot: false }
    }
}

pub fn user_refs(db: &dyn Db, ids: &[String]) -> ApiResult<HashMap<String, UserRef>> {
    let mut unique: Vec<String> = ids.iter().filter(|s| !s.is_empty()).cloned().collect();
    unique.sort();
    unique.dedup();
    let rows = query_in(db, "SELECT id, name, handle, avatar_url, is_bot FROM users WHERE id IN ({in})", &unique, &[])?;
    Ok(rows.iter().map(|r| (r.str("id"), UserRef::from_row(r))).collect())
}

pub fn user_ref(map: &HashMap<String, UserRef>, id: &str) -> UserRef {
    map.get(id).cloned().unwrap_or_else(|| UserRef::unknown(id))
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: String,
    pub handle: String,
    pub role: Role,
    pub bio: String,
    pub avatar_url: Option<String>,
    /// Agent or integration account.
    pub is_bot: bool,
    pub deactivated: bool,
    pub created_at: String,
    pub last_seen_at: Option<String>,
}

pub const USER_COLS: &str = "id, email, name, handle, role, bio, avatar_url, is_bot, deactivated_at, created_at, last_seen_at";

impl User {
    pub fn from_row(r: &Row) -> User {
        User {
            id: r.str("id"),
            email: r.str("email"),
            name: r.str("name"),
            handle: r.str("handle"),
            role: Role::parse(&r.str("role")).unwrap_or(Role::Viewer),
            bio: r.str("bio"),
            avatar_url: r.opt_str("avatar_url"),
            is_bot: r.bool("is_bot"),
            deactivated: r.opt_str("deactivated_at").is_some(),
            created_at: r.str("created_at"),
            last_seen_at: r.opt_str("last_seen_at"),
        }
    }
}

/// Finds a user by id, handle (with or without `@`), email, or `me`.
pub fn find_user(ctx: &Ctx, key: &str) -> ApiResult<Row> {
    let key = key.trim();
    if key == "me" {
        return ctx
            .db
            .one(&format!("SELECT {USER_COLS} FROM users WHERE id = ?"), &params![ctx.actor.user_id.clone()])?
            .ok_or_else(|| ApiError::not_found("user"));
    }
    let handle = key.trim_start_matches('@');
    ctx.db
        .one(&format!("SELECT {USER_COLS} FROM users WHERE id = ? OR handle = ? OR email = ?"), &params![key, handle, key])?
        .ok_or_else(|| ApiError::not_found(format!("user `{key}`")))
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct TopicRef {
    pub id: String,
    pub name: String,
    pub icon: String,
    pub color: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct VerificationInfo {
    /// `verified`, `expired` or `unverified`.
    pub status: String,
    pub verified_by: Option<UserRef>,
    pub verified_at: Option<String>,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct PostSummary {
    pub id: String,
    pub title: String,
    pub slug: String,
    pub url: String,
    pub excerpt: String,
    /// `draft`, `published` or `archived`.
    pub status: String,
    pub is_template: bool,
    pub author: UserRef,
    pub topics: Vec<TopicRef>,
    pub version: i64,
    pub word_count: i64,
    pub view_count: i64,
    pub comment_count: i64,
    pub verification: VerificationInfo,
    pub created_at: String,
    pub updated_at: String,
    pub published_at: Option<String>,
    /// Set when the post is in the trash.
    pub deleted_at: Option<String>,
}

pub const POST_COLS: &str = "p.id, p.title, p.slug, p.excerpt, p.status, p.is_template, p.author_id, p.last_editor_id, p.version,
    p.word_count, p.view_count, p.verified_by, p.verified_at, p.verification_expires_at, p.created_at, p.updated_at,
    p.published_at, p.deleted_at,
    (SELECT COUNT(*) FROM comments cc WHERE cc.post_id = p.id AND cc.deleted_at IS NULL) AS comment_count";

pub fn post_url(ctx: &Ctx, id: &str, slug: &str) -> String {
    ctx.url(&format!("/p/{id}/{slug}"))
}

pub fn topic_url(ctx: &Ctx, id: &str, slug: &str) -> String {
    ctx.url(&format!("/t/{id}/{slug}"))
}

/// Topics (visible to the actor) for each post id.
pub fn topics_for_posts(ctx: &Ctx, post_ids: &[String]) -> ApiResult<HashMap<String, Vec<TopicRef>>> {
    let mut extra = vec![];
    let vis = topic_visible_sql(&ctx.actor, "t", &mut extra);
    let rows = query_in(
        ctx.db,
        &format!(
            "SELECT pt.post_id, t.id, t.name, t.slug, t.icon, t.color FROM post_topics pt JOIN topics t ON t.id = pt.topic_id
             WHERE pt.post_id IN ({{in}}) AND {vis} ORDER BY t.name"
        ),
        post_ids,
        &extra,
    )?;
    let mut map: HashMap<String, Vec<TopicRef>> = HashMap::new();
    for r in rows {
        map.entry(r.str("post_id")).or_default().push(TopicRef {
            id: r.str("id"),
            name: r.str("name"),
            icon: r.str("icon"),
            color: r.str("color"),
            url: topic_url(ctx, &r.str("id"), &r.str("slug")),
        });
    }
    Ok(map)
}

pub fn verification(r: &Row, users: &HashMap<String, UserRef>) -> VerificationInfo {
    let verified_at = r.opt_str("verified_at");
    let expires_at = r.opt_str("verification_expires_at");
    let status = match (&verified_at, &expires_at) {
        (None, _) => "unverified",
        (Some(_), Some(exp)) if parse_ts(exp).is_some_and(|e| e < Utc::now()) => "expired",
        _ => "verified",
    };
    VerificationInfo {
        status: status.into(),
        verified_by: r.opt_str("verified_by").map(|id| user_ref(users, &id)),
        verified_at,
        expires_at,
    }
}

/// Converts rows selected with [`POST_COLS`] into summaries.
pub fn summaries(ctx: &Ctx, rows: &[Row]) -> ApiResult<Vec<PostSummary>> {
    let ids: Vec<String> = rows.iter().map(|r| r.str("id")).collect();
    let mut user_ids: Vec<String> = rows.iter().map(|r| r.str("author_id")).collect();
    user_ids.extend(rows.iter().filter_map(|r| r.opt_str("verified_by")));
    let users = user_refs(ctx.db, &user_ids)?;
    let mut topics = topics_for_posts(ctx, &ids)?;
    Ok(rows
        .iter()
        .map(|r| {
            let id = r.str("id");
            PostSummary {
                url: post_url(ctx, &id, &r.str("slug")),
                topics: topics.remove(&id).unwrap_or_default(),
                title: r.str("title"),
                slug: r.str("slug"),
                excerpt: r.str("excerpt"),
                status: r.str("status"),
                is_template: r.bool("is_template"),
                author: user_ref(&users, &r.str("author_id")),
                version: r.i64("version"),
                word_count: r.i64("word_count"),
                view_count: r.i64("view_count"),
                comment_count: r.i64("comment_count"),
                verification: verification(r, &users),
                created_at: r.str("created_at"),
                updated_at: r.str("updated_at"),
                published_at: r.opt_str("published_at"),
                deleted_at: r.opt_str("deleted_at"),
                id,
            }
        })
        .collect())
}

/// Loads a post row the actor may see, or 404. Trashed posts are found only with `include_trash`.
pub fn load_post(ctx: &Ctx, id: &str, include_trash: bool) -> ApiResult<Row> {
    let mut p = params![id];
    let vis = post_visible_sql(&ctx.actor, "p", &mut p);
    let trash = if include_trash { "" } else { "AND p.deleted_at IS NULL" };
    ctx.db
        .one(&format!("SELECT {POST_COLS}, p.content FROM posts p WHERE p.id = ? {trash} AND {vis}"), &p)?
        .ok_or_else(|| ApiError::not_found(format!("post `{id}`")))
}

pub fn can_view_post(db: &dyn Db, actor: &Actor, post_id: &str) -> ApiResult<bool> {
    let mut p = params![post_id];
    let vis = post_visible_sql(actor, "p", &mut p);
    Ok(db.one(&format!("SELECT 1 AS ok FROM posts p WHERE p.id = ? AND p.deleted_at IS NULL AND {vis}"), &p)?.is_some())
}

/// Members and admins can edit any post they can see; viewers cannot edit.
pub fn require_post_edit(ctx: &Ctx, post: &Row) -> ApiResult<()> {
    ctx.actor.require_role(Role::Member)?;
    if post.opt_str("deleted_at").is_some() {
        return Err(ApiError::conflict("this post is in the trash; restore it first"));
    }
    Ok(())
}

pub fn load_topic(ctx: &Ctx, id: &str) -> ApiResult<Row> {
    let mut p = params![id];
    let vis = topic_visible_sql(&ctx.actor, "t", &mut p);
    ctx.db
        .one(&format!("SELECT t.* FROM topics t WHERE t.id = ? AND {vis}"), &p)?
        .ok_or_else(|| ApiError::not_found(format!("topic `{id}`")))
}

/// A lightweight actor used to check what another user may see (for notifications).
pub fn actor_for_user(db: &dyn Db, user_id: &str) -> ApiResult<Option<Actor>> {
    Ok(db.one("SELECT id, name, handle, email, role FROM users WHERE id = ? AND deactivated_at IS NULL", &params![user_id])?.map(|r| {
        Actor {
            user_id: r.str("id"),
            name: r.str("name"),
            handle: r.str("handle"),
            email: r.str("email"),
            role: Role::parse(&r.str("role")).unwrap_or(Role::Viewer),
            scopes: crate::auth::Scopes::ALL,
            via: crate::auth::Via::Api,
            token_id: None,
            session_hash: None,
        }
    }))
}

/// Cursor pagination: an opaque offset. Returns (limit, offset).
pub fn page(limit: Option<u32>, cursor: &Option<String>) -> ApiResult<(i64, i64)> {
    let limit = limit.unwrap_or(25).clamp(1, 200) as i64;
    let offset = match cursor {
        Some(c) if !c.is_empty() => c.parse::<i64>().map_err(|_| ApiError::bad_request("invalid cursor"))?,
        _ => 0,
    };
    Ok((limit, offset.max(0)))
}

/// Returns the next cursor when a page came back full.
pub fn next_cursor(len: usize, limit: i64, offset: i64) -> Option<String> {
    (len as i64 > limit).then(|| (offset + limit).to_string())
}
