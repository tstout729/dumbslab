use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{DONE, Done, clean, required};
use crate::auth::Role;
use crate::db::{DbExt, Row, SqlValue};
use crate::error::{ApiError, ApiResult};
use crate::events::{Event, emit};
use crate::model::*;
use crate::notify;
use crate::params;
use crate::registry::{Access, Ctx, Op, op};
use crate::search;
use crate::util::{new_id, slugify};

pub fn ops() -> Vec<Op> {
    vec![
        op("topics", "list_topics", "GET", "/topics", Access::Read, list_topics)
            .title("List topics")
            .desc("All topics you can see, as a flat list with `parent_id` so you can build the tree. Topics organize posts; a post can be in several topics.")
            .build(),
        op("topics", "get_topic", "GET", "/topics/{id}", Access::Read, get_topic)
            .title("Get a topic")
            .desc("A topic with its breadcrumbs, subtopics, pinned posts and (for private topics) members. Use list_posts with `topic_id` for its posts.")
            .build(),
        op("topics", "create_topic", "POST", "/topics", Access::Write, create_topic)
            .title("Create a topic")
            .desc("Create a topic, optionally nested under `parent_id`. `visibility: \"private\"` limits it (and posts only in private topics) to its members; you become a member automatically.")
            .build(),
        op("topics", "update_topic", "PATCH", "/topics/{id}", Access::Write, update_topic)
            .title("Update a topic")
            .desc("Rename, describe, restyle, move (`parent_id`, empty string for top level), reorder or change visibility.")
            .build(),
        op("topics", "delete_topic", "DELETE", "/topics/{id}", Access::Write, delete_topic)
            .title("Delete a topic")
            .desc("Delete a topic. Its posts are kept (they just lose this topic) and its subtopics move up to its parent. Creator or admin only.")
            .destructive()
            .build(),
        op("topics", "add_topic_member", "POST", "/topics/{id}/members", Access::Write, add_member)
            .title("Add a member to a private topic")
            .idempotent()
            .build(),
        op("topics", "remove_topic_member", "DELETE", "/topics/{id}/members/{user}", Access::Write, remove_member)
            .title("Remove a member from a private topic")
            .build(),
        op("topics", "pin_post", "POST", "/topics/{id}/pins", Access::Write, pin_post)
            .title("Pin or unpin a post in a topic")
            .desc("Pinned posts are listed first in the topic. The post must already be in the topic.")
            .idempotent()
            .build(),
    ]
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Topic {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub slug: String,
    pub description: String,
    /// An emoji.
    pub icon: String,
    /// A CSS color such as `#4f46e5`.
    pub color: String,
    /// `org` (everyone) or `private` (members only).
    pub visibility: String,
    pub position: i64,
    /// Published posts directly in this topic.
    pub post_count: i64,
    pub following: bool,
    pub url: String,
    pub created_at: String,
    pub updated_at: String,
}

const TOPIC_COLS: &str = "t.id, t.parent_id, t.name, t.slug, t.description, t.icon, t.color, t.visibility, t.position, t.created_by,
    t.created_at, t.updated_at,
    (SELECT COUNT(*) FROM post_topics cpt JOIN posts cp ON cp.id = cpt.post_id
      WHERE cpt.topic_id = t.id AND cp.status = 'published' AND cp.deleted_at IS NULL AND cp.is_template = 0) AS post_count,
    EXISTS (SELECT 1 FROM follows f WHERE f.user_id = ? AND f.target_type = 'topic' AND f.target_id = t.id) AS following";

fn to_topic(ctx: &Ctx, r: &Row) -> Topic {
    Topic {
        url: topic_url(ctx, &r.str("id"), &r.str("slug")),
        id: r.str("id"),
        parent_id: r.opt_str("parent_id"),
        name: r.str("name"),
        slug: r.str("slug"),
        description: r.str("description"),
        icon: r.str("icon"),
        color: r.str("color"),
        visibility: r.str("visibility"),
        position: r.i64("position"),
        post_count: r.i64("post_count"),
        following: r.bool("following"),
        created_at: r.str("created_at"),
        updated_at: r.str("updated_at"),
    }
}

fn query_topics(ctx: &Ctx, cond: &str, extra: Vec<SqlValue>) -> ApiResult<Vec<Topic>> {
    let mut p = params![ctx.actor.user_id.clone()];
    p.extend(extra);
    let vis = topic_visible_sql(&ctx.actor, "t", &mut p);
    let rows = ctx
        .db
        .query(&format!("SELECT {TOPIC_COLS} FROM topics t WHERE {cond} AND {vis} ORDER BY t.position, t.name COLLATE NOCASE"), &p)?;
    Ok(rows.iter().map(|r| to_topic(ctx, r)).collect())
}

fn one_topic(ctx: &Ctx, id: &str) -> ApiResult<Topic> {
    query_topics(ctx, "t.id = ?", params![id]).and_then(|mut v| v.pop().ok_or_else(|| ApiError::not_found(format!("topic `{id}`"))))
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListTopicsInput {
    /// Only direct children of this topic. Use `root` for top-level topics.
    pub parent_id: Option<String>,
    /// Filter by name.
    pub q: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct TopicList {
    pub items: Vec<Topic>,
}

fn list_topics(ctx: &mut Ctx, input: ListTopicsInput) -> ApiResult<TopicList> {
    let mut cond = vec!["1=1".to_string()];
    let mut p: Vec<SqlValue> = vec![];
    match clean(input.parent_id).as_deref() {
        Some("root") => cond.push("t.parent_id IS NULL".into()),
        Some(pid) => {
            cond.push("t.parent_id = ?".into());
            p.push(pid.into());
        }
        None => {}
    }
    if let Some(q) = clean(input.q) {
        cond.push("t.name LIKE ? ESCAPE '\\'".into());
        p.push(format!("%{}%", q.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")).into());
    }
    Ok(TopicList { items: query_topics(ctx, &cond.join(" AND "), p)? })
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TopicIdInput {
    pub id: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct TopicDetail {
    #[serde(flatten)]
    pub topic: Topic,
    /// Ancestors from the top level down.
    pub breadcrumbs: Vec<TopicRef>,
    pub children: Vec<Topic>,
    /// Members of a private topic (empty for org topics).
    pub members: Vec<UserRef>,
    pub pinned_post_ids: Vec<String>,
    pub can_manage: bool,
}

fn ancestors(ctx: &Ctx, topic: &Row) -> ApiResult<Vec<TopicRef>> {
    let mut out = vec![];
    let mut next = topic.opt_str("parent_id");
    let mut guard = 0;
    while let Some(pid) = next {
        guard += 1;
        if guard > 50 {
            break;
        }
        let mut p = vec![];
        let vis = topic_visible_sql(&ctx.actor, "t", &mut p);
        p.push(pid.into());
        let Some(r) = ctx.db.one(
            &format!("SELECT t.id, t.name, t.slug, t.icon, t.color, t.parent_id, {vis} AS visible FROM topics t WHERE t.id = ?"),
            &p,
        )?
        else {
            break;
        };
        next = r.opt_str("parent_id");
        if !r.bool("visible") {
            continue;
        }
        out.push(TopicRef {
            url: topic_url(ctx, &r.str("id"), &r.str("slug")),
            id: r.str("id"),
            name: r.str("name"),
            icon: r.str("icon"),
            color: r.str("color"),
        });
    }
    out.reverse();
    Ok(out)
}

fn is_member(ctx: &Ctx, topic_id: &str, user_id: &str) -> ApiResult<bool> {
    Ok(ctx.db.one("SELECT 1 AS m FROM topic_members WHERE topic_id = ? AND user_id = ?", &params![topic_id, user_id])?.is_some())
}

/// Org topics can be managed by any member; private topics by their members; admins always.
fn can_manage(ctx: &Ctx, topic: &Row) -> ApiResult<bool> {
    if ctx.actor.role == Role::Admin {
        return Ok(true);
    }
    if ctx.actor.role < Role::Member {
        return Ok(false);
    }
    if topic.str("visibility") == "private" {
        return is_member(ctx, &topic.str("id"), &ctx.actor.user_id);
    }
    Ok(true)
}

fn require_manage(ctx: &Ctx, topic: &Row) -> ApiResult<()> {
    if can_manage(ctx, topic)? { Ok(()) } else { Err(ApiError::forbidden("you can't change this topic")) }
}

fn get_topic(ctx: &mut Ctx, input: TopicIdInput) -> ApiResult<TopicDetail> {
    let row = load_topic(ctx, &input.id)?;
    let id = row.str("id");
    let members = if row.str("visibility") == "private" {
        let ids: Vec<String> = ctx
            .db
            .query("SELECT user_id FROM topic_members WHERE topic_id = ? ORDER BY added_at", &params![id.clone()])?
            .iter()
            .map(|r| r.str("user_id"))
            .collect();
        let map = user_refs(ctx.db, &ids)?;
        ids.iter().map(|i| user_ref(&map, i)).collect()
    } else {
        vec![]
    };
    let mut p = params![id.clone()];
    let vis = post_visible_sql(&ctx.actor, "p", &mut p);
    let pinned_post_ids = ctx
        .db
        .query(
            &format!(
                "SELECT pt.post_id FROM post_topics pt JOIN posts p ON p.id = pt.post_id
                 WHERE pt.topic_id = ? AND pt.pinned = 1 AND p.deleted_at IS NULL AND {vis}"
            ),
            &p,
        )?
        .iter()
        .map(|r| r.str("post_id"))
        .collect();
    Ok(TopicDetail {
        breadcrumbs: ancestors(ctx, &row)?,
        children: query_topics(ctx, "t.parent_id = ?", params![id.clone()])?,
        members,
        pinned_post_ids,
        can_manage: can_manage(ctx, &row)?,
        topic: one_topic(ctx, &id)?,
    })
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateTopicInput {
    pub name: String,
    pub description: Option<String>,
    /// An emoji, e.g. "📘".
    pub icon: Option<String>,
    /// A CSS color, e.g. "#4f46e5".
    pub color: Option<String>,
    pub parent_id: Option<String>,
    /// `org` (default) or `private`.
    pub visibility: Option<String>,
    /// For private topics: users (id, @handle or email) to add besides you.
    pub members: Option<Vec<String>>,
}

fn check_visibility(v: &str) -> ApiResult<()> {
    if v == "org" || v == "private" { Ok(()) } else { Err(ApiError::bad_request("visibility must be `org` or `private`")) }
}

fn check_color(c: &str) -> ApiResult<()> {
    let ok = c.is_empty() || (c.len() <= 32 && c.chars().all(|ch| ch.is_ascii_alphanumeric() || "#(),.% ".contains(ch)));
    if ok { Ok(()) } else { Err(ApiError::bad_request("color must be a CSS color like #4f46e5")) }
}

pub fn create_topic(ctx: &mut Ctx, input: CreateTopicInput) -> ApiResult<TopicDetail> {
    ctx.actor.require_role(Role::Member)?;
    let name = required(&input.name, "name", 120)?;
    let visibility = clean(input.visibility).unwrap_or_else(|| "org".into());
    check_visibility(&visibility)?;
    let color = clean(input.color).unwrap_or_default();
    check_color(&color)?;
    let parent_id = clean(input.parent_id);
    if let Some(pid) = &parent_id {
        load_topic(ctx, pid)?;
    }
    let id = new_id();
    let now = ctx.now_s();
    let position =
        ctx.db.scalar_i64("SELECT COALESCE(MAX(position), 0) + 1 FROM topics WHERE parent_id IS ?", &params![parent_id.clone()])?;
    ctx.db.execute(
        "INSERT INTO topics (id, parent_id, name, slug, description, icon, color, visibility, position, created_by, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        &params![
            id.clone(),
            parent_id,
            name.clone(),
            slugify(&name),
            clean(input.description).unwrap_or_default(),
            clean(input.icon).unwrap_or_default(),
            color,
            visibility.clone(),
            position,
            ctx.actor.user_id.clone(),
            now.clone(),
            now
        ],
    )?;
    if visibility == "private" {
        let uid = ctx.actor.user_id.clone();
        insert_member(ctx, &id, &uid)?;
        for m in input.members.unwrap_or_default() {
            let uid = find_user(ctx, &m)?.str("id");
            insert_member(ctx, &id, &uid)?;
        }
    }
    search::index_topic(ctx.db, &id)?;
    let uid = ctx.actor.user_id.clone();
    notify::follow(ctx, &uid, "topic", &id)?;
    let mut e = Event::new("topic.created", "topic", &id, format!("created topic “{name}”")).topic(&id);
    if visibility == "private" {
        e = e.admin_only();
    }
    emit(ctx, e)?;
    get_topic(ctx, TopicIdInput { id })
}

fn insert_member(ctx: &Ctx, topic_id: &str, user_id: &str) -> ApiResult<()> {
    ctx.db.execute(
        "INSERT INTO topic_members (topic_id, user_id, added_at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
        &params![topic_id, user_id, ctx.now_s()],
    )?;
    Ok(())
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateTopicInput {
    pub id: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub icon: Option<String>,
    pub color: Option<String>,
    /// New parent topic id; empty string moves it to the top level.
    pub parent_id: Option<String>,
    /// `org` or `private`.
    pub visibility: Option<String>,
    /// Sort order among siblings (lower first).
    pub position: Option<i64>,
}

fn update_topic(ctx: &mut Ctx, input: UpdateTopicInput) -> ApiResult<TopicDetail> {
    let row = load_topic(ctx, &input.id)?;
    require_manage(ctx, &row)?;
    let id = row.str("id");
    let mut sets: Vec<&str> = vec![];
    let mut p: Vec<SqlValue> = vec![];
    if let Some(name) = &input.name {
        let name = required(name, "name", 120)?;
        sets.extend(["name = ?", "slug = ?"]);
        p.push(name.clone().into());
        p.push(slugify(&name).into());
    }
    if let Some(d) = input.description {
        sets.push("description = ?");
        p.push(d.trim().to_string().into());
    }
    if let Some(i) = input.icon {
        sets.push("icon = ?");
        p.push(i.trim().to_string().into());
    }
    if let Some(c) = input.color {
        check_color(c.trim())?;
        sets.push("color = ?");
        p.push(c.trim().to_string().into());
    }
    if let Some(pid) = input.parent_id {
        let pid = pid.trim().to_string();
        if pid.is_empty() {
            sets.push("parent_id = NULL");
        } else {
            load_topic(ctx, &pid)?;
            // Refuse cycles: the new parent can't be this topic or one of its descendants.
            let mut cursor = Some(pid.clone());
            while let Some(c) = cursor {
                if c == id {
                    return Err(ApiError::bad_request("a topic can't be moved inside itself"));
                }
                cursor = ctx.db.one("SELECT parent_id FROM topics WHERE id = ?", &params![c])?.and_then(|r| r.opt_str("parent_id"));
            }
            sets.push("parent_id = ?");
            p.push(pid.into());
        }
    }
    let mut became_private = false;
    if let Some(v) = clean(input.visibility) {
        check_visibility(&v)?;
        became_private = v == "private" && row.str("visibility") != "private";
        sets.push("visibility = ?");
        p.push(v.into());
    }
    if let Some(pos) = input.position {
        sets.push("position = ?");
        p.push(pos.into());
    }
    if sets.is_empty() {
        return get_topic(ctx, TopicIdInput { id });
    }
    sets.push("updated_at = ?");
    p.push(ctx.now_s().into());
    p.push(id.clone().into());
    ctx.db.execute(&format!("UPDATE topics SET {} WHERE id = ?", sets.join(", ")), &p)?;
    if became_private {
        let uid = ctx.actor.user_id.clone();
        insert_member(ctx, &id, &uid)?;
    }
    search::index_topic(ctx.db, &id)?;
    let name = ctx.db.one("SELECT name FROM topics WHERE id = ?", &params![id.clone()])?.map(|r| r.str("name")).unwrap_or_default();
    emit(ctx, Event::new("topic.updated", "topic", &id, format!("updated topic “{name}”")).topic(&id))?;
    get_topic(ctx, TopicIdInput { id })
}

fn delete_topic(ctx: &mut Ctx, input: TopicIdInput) -> ApiResult<Done> {
    let row = load_topic(ctx, &input.id)?;
    let id = row.str("id");
    if ctx.actor.role != Role::Admin && row.opt_str("created_by").as_deref() != Some(ctx.actor.user_id.as_str()) {
        return Err(ApiError::forbidden("only the topic's creator or an admin can delete it"));
    }
    let private = row.str("visibility") == "private";
    if private {
        // Posts left without topics become visible to everyone, so don't orphan private posts.
        let exposed = ctx.db.scalar_i64(
            "SELECT COUNT(*) FROM post_topics pt WHERE pt.topic_id = ?
             AND NOT EXISTS (SELECT 1 FROM post_topics o WHERE o.post_id = pt.post_id AND o.topic_id != pt.topic_id)",
            &params![id.clone()],
        )?;
        if exposed > 0 {
            return Err(ApiError::conflict(format!(
                "{exposed} post(s) are only in this private topic and would become visible to everyone; move or delete them first"
            )));
        }
    }
    // Docs sync sources into this topic go with it, through the same removal as removing one.
    let sources = ctx.db.query(&format!("{} WHERE s.topic_id = ?", crate::sync::docs::SOURCES_SQL), &params![id.clone()])?;
    crate::ops::sync::remove_sources(ctx, &sources)?;
    ctx.db.execute("UPDATE topics SET parent_id = ? WHERE parent_id = ?", &params![row.opt_str("parent_id"), id.clone()])?;
    for table in ["post_topics", "topic_members"] {
        ctx.db.execute(&format!("DELETE FROM {table} WHERE topic_id = ?"), &params![id.clone()])?;
    }
    ctx.db.execute("DELETE FROM follows WHERE target_type = 'topic' AND target_id = ?", &params![id.clone()])?;
    ctx.db.execute("DELETE FROM topics WHERE id = ?", &params![id.clone()])?;
    search::remove(ctx.db, "topic", &id)?;
    let mut event =
        Event::new("topic.deleted", "topic", &id, format!("deleted topic “{}”", row.str("name"))).data(json!({ "name": row.str("name") }));
    if private {
        event = event.admin_only();
    }
    emit(ctx, event)?;
    Ok(DONE)
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemberInput {
    pub id: String,
    /// User id, @handle or email.
    pub user: String,
}

fn add_member(ctx: &mut Ctx, input: MemberInput) -> ApiResult<TopicDetail> {
    let row = load_topic(ctx, &input.id)?;
    require_manage(ctx, &row)?;
    if row.str("visibility") != "private" {
        return Err(ApiError::bad_request("only private topics have members; everyone can see org topics"));
    }
    let user = find_user(ctx, &input.user)?;
    let id = row.str("id");
    insert_member(ctx, &id, &user.str("id"))?;
    emit(
        ctx,
        Event::new("topic.member_added", "topic", &id, format!("added {} to “{}”", user.str("name"), row.str("name")))
            .topic(&id)
            .admin_only(),
    )?;
    get_topic(ctx, TopicIdInput { id })
}

fn remove_member(ctx: &mut Ctx, input: MemberInput) -> ApiResult<Done> {
    let row = load_topic(ctx, &input.id)?;
    require_manage(ctx, &row)?;
    let user = find_user(ctx, &input.user)?;
    let id = row.str("id");
    let remaining = ctx
        .db
        .scalar_i64("SELECT COUNT(*) FROM topic_members WHERE topic_id = ? AND user_id != ?", &params![id.clone(), user.str("id")])?;
    if remaining == 0 && ctx.actor.role != Role::Admin {
        return Err(ApiError::bad_request("a private topic needs at least one member"));
    }
    ctx.db.execute("DELETE FROM topic_members WHERE topic_id = ? AND user_id = ?", &params![id.clone(), user.str("id")])?;
    emit(
        ctx,
        Event::new("topic.member_removed", "topic", &id, format!("removed {} from “{}”", user.str("name"), row.str("name")))
            .topic(&id)
            .admin_only(),
    )?;
    Ok(DONE)
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PinInput {
    pub id: String,
    pub post_id: String,
    /// Default true; false unpins.
    pub pinned: Option<bool>,
}

fn pin_post(ctx: &mut Ctx, input: PinInput) -> ApiResult<TopicDetail> {
    let row = load_topic(ctx, &input.id)?;
    require_manage(ctx, &row)?;
    let post = load_post(ctx, &input.post_id, false)?;
    let pinned = input.pinned.unwrap_or(true);
    let changed = ctx
        .db
        .execute("UPDATE post_topics SET pinned = ? WHERE post_id = ? AND topic_id = ?", &params![pinned, post.str("id"), row.str("id")])?;
    if changed == 0 {
        return Err(ApiError::bad_request("that post isn't in this topic; add the topic to the post first"));
    }
    let id = row.str("id");
    emit(
        ctx,
        Event::new(
            if pinned { "post.pinned" } else { "post.unpinned" },
            "post",
            &post.str("id"),
            format!("{} “{}” in “{}”", if pinned { "pinned" } else { "unpinned" }, post.str("title"), row.str("name")),
        )
        .post(&post.str("id"))
        .topic(&id),
    )?;
    get_topic(ctx, TopicIdInput { id })
}
