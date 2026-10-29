use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{DONE, Done, NoInput, clean};
use crate::db::{DbExt, SqlValue};
use crate::error::{ApiError, ApiResult};
use crate::model::*;
use crate::notify;
use crate::ops::posts::PostLink;
use crate::params;
use crate::registry::{Access, Ctx, Op, op};

pub fn ops() -> Vec<Op> {
    vec![
        op("notifications", "list_notifications", "GET", "/notifications", Access::Read, list_notifications)
            .title("List notifications")
            .desc("Your notifications (mentions, comments, replies, updates to followed posts, new posts in followed topics), newest first.")
            .build(),
        op("notifications", "mark_notifications_read", "POST", "/notifications/read", Access::Write, mark_read)
            .title("Mark notifications read")
            .desc("Mark specific notifications (`ids`) or everything (`all: true`) as read.")
            .idempotent()
            .build(),
        op("notifications", "follow", "POST", "/follows", Access::Write, follow)
            .title("Follow a post or topic")
            .desc("Get notified about comments and updates on a post, or new posts in a topic.")
            .idempotent()
            .build(),
        op("notifications", "unfollow", "DELETE", "/follows/{target_type}/{target_id}", Access::Write, unfollow)
            .title("Unfollow a post or topic")
            .build(),
        op("notifications", "list_follows", "GET", "/follows", Access::Read, list_follows).title("List what you follow").build(),
        op("notifications", "list_activity", "GET", "/activity", Access::Read, list_activity)
            .title("Activity feed")
            .desc("What happened in the workspace, newest first: creates, edits, comments, verifications, moves. Filter by post, topic, person or event prefix. For polling, pass the highest `id` you have seen as `after_id` to get only newer events (oldest first).")
            .build(),
        op("notifications", "list_recent_views", "GET", "/me/recent", Access::Read, recent_views)
            .title("Recently viewed posts")
            .desc("Posts you opened recently in the web app.")
            .build(),
    ]
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Notification {
    pub id: String,
    /// `mention`, `comment`, `reply`, `post_updated` or `new_post`.
    pub kind: String,
    pub message: String,
    pub actor: Option<UserRef>,
    pub post: Option<PostLink>,
    pub comment_id: Option<String>,
    pub topic_id: Option<String>,
    pub read: bool,
    pub created_at: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListNotificationsInput {
    pub unread_only: Option<bool>,
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct NotificationList {
    pub items: Vec<Notification>,
    pub unread_count: i64,
    pub next_cursor: Option<String>,
}

fn list_notifications(ctx: &mut Ctx, input: ListNotificationsInput) -> ApiResult<NotificationList> {
    let (limit, offset) = page(input.limit, &input.cursor)?;
    let unread = if input.unread_only.unwrap_or(false) { "AND n.read_at IS NULL" } else { "" };
    let mut rows = ctx.db.query(
        &format!(
            "SELECT n.*, p.title AS post_title, p.slug AS post_slug FROM notifications n
             LEFT JOIN posts p ON p.id = n.post_id AND p.deleted_at IS NULL
             WHERE n.user_id = ? {unread} ORDER BY n.created_at DESC, n.id LIMIT ? OFFSET ?"
        ),
        &params![ctx.actor.user_id.clone(), limit + 1, offset],
    )?;
    let next_cursor = next_cursor(rows.len(), limit, offset);
    rows.truncate(limit as usize);
    let users = user_refs(ctx.db, &rows.iter().filter_map(|r| r.opt_str("actor_id")).collect::<Vec<_>>())?;
    let unread_count = ctx
        .db
        .scalar_i64("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND read_at IS NULL", &params![ctx.actor.user_id.clone()])?;
    Ok(NotificationList {
        items: rows
            .iter()
            .map(|r| Notification {
                id: r.str("id"),
                kind: r.str("kind"),
                message: r.str("message"),
                actor: r.opt_str("actor_id").map(|a| user_ref(&users, &a)),
                post: r.opt_str("post_title").map(|title| PostLink {
                    url: post_url(ctx, &r.str("post_id"), &r.str("post_slug")),
                    id: r.str("post_id"),
                    title,
                }),
                comment_id: r.opt_str("comment_id"),
                topic_id: r.opt_str("topic_id"),
                read: r.opt_str("read_at").is_some(),
                created_at: r.str("created_at"),
            })
            .collect(),
        unread_count,
        next_cursor,
    })
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MarkReadInput {
    pub ids: Option<Vec<String>>,
    pub all: Option<bool>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct MarkReadResult {
    pub updated: i64,
}

fn mark_read(ctx: &mut Ctx, input: MarkReadInput) -> ApiResult<MarkReadResult> {
    let now = ctx.now_s();
    let uid = ctx.actor.user_id.clone();
    let updated = if input.all.unwrap_or(false) {
        ctx.db.execute("UPDATE notifications SET read_at = ? WHERE user_id = ? AND read_at IS NULL", &params![now, uid])?
    } else {
        let ids = input.ids.unwrap_or_default();
        if ids.is_empty() {
            return Err(ApiError::bad_request("pass `ids` or `all: true`"));
        }
        let mut n = 0;
        for chunk in ids.chunks(80) {
            let mut p: Vec<SqlValue> = params![now.clone(), uid.clone()];
            p.extend(chunk.iter().map(|s| SqlValue::from(s.as_str())));
            n += ctx.db.execute(
                &format!(
                    "UPDATE notifications SET read_at = ? WHERE user_id = ? AND read_at IS NULL AND id IN ({})",
                    placeholders(chunk.len())
                ),
                &p,
            )?;
        }
        n
    };
    Ok(MarkReadResult { updated: updated as i64 })
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FollowInput {
    /// `post` or `topic`.
    pub target_type: String,
    pub target_id: String,
}

fn check_follow_target(ctx: &Ctx, input: &FollowInput) -> ApiResult<String> {
    match input.target_type.as_str() {
        "post" => Ok(load_post(ctx, &input.target_id, false)?.str("id")),
        "topic" => Ok(load_topic(ctx, &input.target_id)?.str("id")),
        _ => Err(ApiError::bad_request("target_type must be `post` or `topic`")),
    }
}

fn follow(ctx: &mut Ctx, input: FollowInput) -> ApiResult<Done> {
    let id = check_follow_target(ctx, &input)?;
    let uid = ctx.actor.user_id.clone();
    notify::follow(ctx, &uid, &input.target_type, &id)?;
    Ok(DONE)
}

fn unfollow(ctx: &mut Ctx, input: FollowInput) -> ApiResult<Done> {
    ctx.db.execute(
        "DELETE FROM follows WHERE user_id = ? AND target_type = ? AND target_id = ?",
        &params![ctx.actor.user_id.clone(), input.target_type, input.target_id],
    )?;
    Ok(DONE)
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct FollowList {
    pub posts: Vec<PostLink>,
    pub topics: Vec<TopicRef>,
}

fn list_follows(ctx: &mut Ctx, _: NoInput) -> ApiResult<FollowList> {
    let mut p = params![ctx.actor.user_id.clone()];
    let vis = post_visible_sql(&ctx.actor, "p", &mut p);
    let posts = ctx
        .db
        .query(
            &format!(
                "SELECT p.id, p.title, p.slug FROM follows f JOIN posts p ON p.id = f.target_id
                 WHERE f.user_id = ? AND f.target_type = 'post' AND p.deleted_at IS NULL AND {vis} ORDER BY p.title COLLATE NOCASE"
            ),
            &p,
        )?
        .iter()
        .map(|r| PostLink { url: post_url(ctx, &r.str("id"), &r.str("slug")), id: r.str("id"), title: r.str("title") })
        .collect();
    let mut p = params![ctx.actor.user_id.clone()];
    let vis = topic_visible_sql(&ctx.actor, "t", &mut p);
    let topics = ctx
        .db
        .query(
            &format!(
                "SELECT t.id, t.name, t.slug, t.icon, t.color FROM follows f JOIN topics t ON t.id = f.target_id
                 WHERE f.user_id = ? AND f.target_type = 'topic' AND {vis} ORDER BY t.name COLLATE NOCASE"
            ),
            &p,
        )?
        .iter()
        .map(|r| TopicRef {
            url: topic_url(ctx, &r.str("id"), &r.str("slug")),
            id: r.str("id"),
            name: r.str("name"),
            icon: r.str("icon"),
            color: r.str("color"),
        })
        .collect();
    Ok(FollowList { posts, topics })
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ActivityItem {
    /// Increasing id; use as `after_id` when polling.
    pub id: i64,
    /// e.g. `post.created`, `comment.created`, `post.verified`.
    pub event: String,
    pub actor: Option<UserRef>,
    /// `web`, `api`, `mcp` or `cli`.
    pub via: String,
    pub target_type: String,
    pub target_id: String,
    pub post_id: Option<String>,
    pub topic_id: Option<String>,
    pub summary: String,
    pub data: Value,
    pub created_at: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListActivityInput {
    pub post_id: Option<String>,
    pub topic_id: Option<String>,
    /// Who did it: id, @handle, email or `me`.
    pub actor: Option<String>,
    /// Event name or prefix, e.g. `post.` or `comment.created`.
    pub event: Option<String>,
    /// Only events with a higher id, oldest first (for polling).
    pub after_id: Option<i64>,
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ActivityList {
    pub items: Vec<ActivityItem>,
    pub next_cursor: Option<String>,
}

fn list_activity(ctx: &mut Ctx, input: ListActivityInput) -> ApiResult<ActivityList> {
    let (limit, offset) = page(input.limit, &input.cursor)?;
    let mut cond: Vec<String> = vec![];
    let mut p: Vec<SqlValue> = vec![];
    if !ctx.actor.sees_all() {
        cond.push("a.audience = 'all'".into());
    }
    if let Some(pid) = clean(input.post_id) {
        cond.push("a.post_id = ?".into());
        p.push(pid.into());
    }
    if let Some(tid) = clean(input.topic_id) {
        cond.push("(a.topic_id = ? OR a.post_id IN (SELECT post_id FROM post_topics WHERE topic_id = ?))".into());
        p.push(tid.clone().into());
        p.push(tid.into());
    }
    if let Some(a) = clean(input.actor) {
        cond.push("a.actor_id = ?".into());
        p.push(find_user(ctx, &a)?.str("id").into());
    }
    if let Some(e) = clean(input.event) {
        cond.push("a.event LIKE ? ESCAPE '\\'".into());
        p.push(format!("{}%", e.replace('%', "").replace('_', "\\_")).into());
    }
    if let Some(after) = input.after_id {
        cond.push("a.id > ?".into());
        p.push(after.into());
    }
    // Hide events about posts and topics the actor can't see (including purged posts).
    let post_vis = post_visible_sql(&ctx.actor, "vp", &mut p);
    cond.push(format!("(a.post_id IS NULL OR EXISTS (SELECT 1 FROM posts vp WHERE vp.id = a.post_id AND {post_vis}))"));
    let topic_vis = topic_visible_sql(&ctx.actor, "vt", &mut p);
    cond.push(format!("(a.topic_id IS NULL OR NOT EXISTS (SELECT 1 FROM topics vt0 WHERE vt0.id = a.topic_id) OR EXISTS (SELECT 1 FROM topics vt WHERE vt.id = a.topic_id AND {topic_vis}))"));
    let order = if input.after_id.is_some() { "ASC" } else { "DESC" };
    p.push((limit + 1).into());
    p.push(offset.into());
    let mut rows = ctx.db.query(
        &format!(
            "SELECT a.* FROM activity a WHERE {} ORDER BY a.id {order} LIMIT ? OFFSET ?",
            if cond.is_empty() { "1=1".into() } else { cond.join(" AND ") }
        ),
        &p,
    )?;
    let next_cursor = next_cursor(rows.len(), limit, offset);
    rows.truncate(limit as usize);
    let users = user_refs(ctx.db, &rows.iter().filter_map(|r| r.opt_str("actor_id")).collect::<Vec<_>>())?;
    Ok(ActivityList {
        items: rows
            .iter()
            .map(|r| ActivityItem {
                id: r.i64("id"),
                event: r.str("event"),
                actor: r.opt_str("actor_id").map(|a| user_ref(&users, &a)),
                via: r.str("via"),
                target_type: r.str("target_type"),
                target_id: r.str("target_id"),
                post_id: r.opt_str("post_id"),
                topic_id: r.opt_str("topic_id"),
                summary: r.str("summary"),
                data: serde_json::from_str(&r.str("data")).unwrap_or(Value::Null),
                created_at: r.str("created_at"),
            })
            .collect(),
        next_cursor,
    })
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecentInput {
    pub limit: Option<u32>,
}

fn recent_views(ctx: &mut Ctx, input: RecentInput) -> ApiResult<crate::ops::posts::PostList> {
    let limit = input.limit.unwrap_or(10).clamp(1, 50) as i64;
    let mut p = params![ctx.actor.user_id.clone()];
    let vis = post_visible_sql(&ctx.actor, "p", &mut p);
    p.push(limit.into());
    let rows = ctx.db.query(
        &format!(
            "SELECT {POST_COLS} FROM post_views v JOIN posts p ON p.id = v.post_id
             WHERE v.user_id = ? AND p.deleted_at IS NULL AND {vis} ORDER BY v.viewed_at DESC LIMIT ?"
        ),
        &p,
    )?;
    Ok(crate::ops::posts::PostList { items: summaries(ctx, &rows)?, next_cursor: None })
}
