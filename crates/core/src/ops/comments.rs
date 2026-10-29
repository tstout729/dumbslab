use std::collections::HashMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{DONE, Done, clean, required};
use crate::auth::Role;
use crate::db::{DbExt, Row};
use crate::error::{ApiError, ApiResult};
use crate::events::{Event, emit};
use crate::markdown;
use crate::model::*;
use crate::notify::{self, Notice};
use crate::params;
use crate::registry::{Access, Ctx, Op, op};
use crate::search;
use crate::util::new_id;

pub fn ops() -> Vec<Op> {
    vec![
        op("comments", "list_comments", "GET", "/posts/{post_id}/comments", Access::Read, list_comments)
            .title("List a post's comments")
            .desc("Comments in creation order. Replies have `parent_id`. Inline comments carry the `quote` they refer to.")
            .build(),
        op("comments", "create_comment", "POST", "/posts/{post_id}/comments", Access::Write, create_comment)
            .title("Comment on a post")
            .desc("Add a Markdown comment. Reply with `parent_id`; anchor to a passage with `quote`. `@handle` mentions notify people. Viewers can comment too.")
            .build(),
        op("comments", "update_comment", "PATCH", "/comments/{id}", Access::Write, update_comment)
            .title("Edit or resolve a comment")
            .desc("Authors can edit their comment's body. Members and the post's author can resolve or reopen a thread with `resolved`.")
            .build(),
        op("comments", "delete_comment", "DELETE", "/comments/{id}", Access::Write, delete_comment)
            .title("Delete a comment")
            .destructive()
            .build(),
        op("comments", "add_reaction", "POST", "/reactions", Access::Write, add_reaction)
            .title("React with an emoji")
            .desc("Add an emoji reaction to a post or comment.")
            .idempotent()
            .build(),
        op("comments", "remove_reaction", "DELETE", "/reactions", Access::Write, remove_reaction)
            .title("Remove a reaction")
            .build(),
    ]
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ReactionGroup {
    pub emoji: String,
    pub count: i64,
    /// Whether you reacted with this emoji.
    pub reacted: bool,
    /// Names of people who reacted (up to 10).
    pub names: Vec<String>,
}

pub fn reaction_groups(ctx: &Ctx, target_type: &str, target_id: &str) -> ApiResult<Vec<ReactionGroup>> {
    let rows = ctx.db.query(
        "SELECT r.emoji, r.user_id, u.name FROM reactions r JOIN users u ON u.id = r.user_id
         WHERE r.target_type = ? AND r.target_id = ? ORDER BY r.created_at",
        &params![target_type, target_id],
    )?;
    group_reactions(ctx, &rows)
}

fn group_reactions(ctx: &Ctx, rows: &[Row]) -> ApiResult<Vec<ReactionGroup>> {
    let mut groups: Vec<ReactionGroup> = vec![];
    for r in rows {
        let emoji = r.str("emoji");
        let idx = match groups.iter().position(|g| g.emoji == emoji) {
            Some(i) => i,
            None => {
                groups.push(ReactionGroup { emoji, count: 0, reacted: false, names: vec![] });
                groups.len() - 1
            }
        };
        let g = &mut groups[idx];
        g.count += 1;
        g.reacted |= r.str("user_id") == ctx.actor.user_id;
        if g.names.len() < 10 {
            g.names.push(r.str("name"));
        }
    }
    Ok(groups)
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Comment {
    pub id: String,
    pub post_id: String,
    pub parent_id: Option<String>,
    pub author: UserRef,
    /// Markdown.
    pub body: String,
    pub html: String,
    /// The passage an inline comment refers to.
    pub quote: Option<String>,
    pub resolved: bool,
    pub resolved_at: Option<String>,
    pub resolved_by: Option<UserRef>,
    pub reactions: Vec<ReactionGroup>,
    pub edited: bool,
    pub created_at: String,
    pub updated_at: String,
}

fn to_comments(ctx: &Ctx, rows: &[Row]) -> ApiResult<Vec<Comment>> {
    let mut ids: Vec<String> = rows.iter().map(|r| r.str("author_id")).collect();
    ids.extend(rows.iter().filter_map(|r| r.opt_str("resolved_by")));
    let users = user_refs(ctx.db, &ids)?;
    let comment_ids: Vec<String> = rows.iter().map(|r| r.str("id")).collect();
    let reaction_rows = query_in(
        ctx.db,
        "SELECT r.target_id, r.emoji, r.user_id, u.name FROM reactions r JOIN users u ON u.id = r.user_id
         WHERE r.target_type = 'comment' AND r.target_id IN ({in}) ORDER BY r.created_at",
        &comment_ids,
        &[],
    )?;
    let mut by_comment: HashMap<String, Vec<Row>> = HashMap::new();
    for r in reaction_rows {
        by_comment.entry(r.str("target_id")).or_default().push(r);
    }
    rows.iter()
        .map(|r| {
            let id = r.str("id");
            let body = r.str("body");
            Ok(Comment {
                reactions: group_reactions(ctx, by_comment.get(&id).map(Vec::as_slice).unwrap_or(&[]))?,
                post_id: r.str("post_id"),
                parent_id: r.opt_str("parent_id"),
                author: user_ref(&users, &r.str("author_id")),
                html: markdown::render(&body),
                body,
                quote: r.opt_str("quote"),
                resolved: r.opt_str("resolved_at").is_some(),
                resolved_at: r.opt_str("resolved_at"),
                resolved_by: r.opt_str("resolved_by").map(|u| user_ref(&users, &u)),
                edited: r.str("updated_at") != r.str("created_at"),
                created_at: r.str("created_at"),
                updated_at: r.str("updated_at"),
                id,
            })
        })
        .collect()
}

/// Loads a comment whose post the actor can see.
fn load_comment(ctx: &Ctx, id: &str) -> ApiResult<(Row, Row)> {
    let c = ctx
        .db
        .one("SELECT * FROM comments WHERE id = ? AND deleted_at IS NULL", &params![id])?
        .ok_or_else(|| ApiError::not_found(format!("comment `{id}`")))?;
    let post = load_post(ctx, &c.str("post_id"), false).map_err(|_| ApiError::not_found(format!("comment `{id}`")))?;
    Ok((c, post))
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListCommentsInput {
    pub post_id: String,
    /// Default true.
    pub include_resolved: Option<bool>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct CommentList {
    pub items: Vec<Comment>,
}

fn list_comments(ctx: &mut Ctx, input: ListCommentsInput) -> ApiResult<CommentList> {
    let post = load_post(ctx, &input.post_id, true)?;
    let resolved = if input.include_resolved.unwrap_or(true) { "" } else { "AND resolved_at IS NULL" };
    let rows = ctx.db.query(
        &format!("SELECT * FROM comments WHERE post_id = ? AND deleted_at IS NULL {resolved} ORDER BY created_at, id"),
        &params![post.str("id")],
    )?;
    Ok(CommentList { items: to_comments(ctx, &rows)? })
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateCommentInput {
    pub post_id: String,
    /// Markdown.
    pub body: String,
    /// Reply to this comment.
    pub parent_id: Option<String>,
    /// For inline comments: the exact passage being discussed.
    pub quote: Option<String>,
}

fn create_comment(ctx: &mut Ctx, input: CreateCommentInput) -> ApiResult<Comment> {
    let post = load_post(ctx, &input.post_id, false)?;
    let body = required(&input.body, "body", 50_000)?;
    let post_id = post.str("id");
    let mut parent_author = None;
    if let Some(pid) = clean(input.parent_id.clone()) {
        let parent = ctx
            .db
            .one("SELECT author_id, post_id FROM comments WHERE id = ? AND deleted_at IS NULL", &params![pid])?
            .ok_or_else(|| ApiError::not_found("parent comment"))?;
        if parent.str("post_id") != post_id {
            return Err(ApiError::bad_request("the parent comment belongs to another post"));
        }
        parent_author = Some(parent.str("author_id"));
    }
    let id = new_id();
    let now = ctx.now_s();
    ctx.db.execute(
        "INSERT INTO comments (id, post_id, parent_id, author_id, body, quote, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        &params![
            id.clone(),
            post_id.clone(),
            clean(input.parent_id),
            ctx.actor.user_id.clone(),
            body.clone(),
            clean(input.quote),
            now.clone(),
            now
        ],
    )?;
    search::index_comment(ctx.db, &id)?;

    let title = post.str("title");
    let mentioned = notify::resolve_handles(ctx.db, &markdown::mentions(&body))?;
    notify::send(
        ctx,
        mentioned.clone(),
        &Notice {
            kind: "mention",
            post_id: Some(&post_id),
            comment_id: Some(&id),
            topic_id: None,
            message: format!("{} mentioned you in a comment on “{title}”", ctx.actor.name),
        },
    )?;
    if let Some(pa) = parent_author
        && !mentioned.contains(&pa)
    {
        notify::send(
            ctx,
            [pa.clone()],
            &Notice {
                kind: "reply",
                post_id: Some(&post_id),
                comment_id: Some(&id),
                topic_id: None,
                message: format!("{} replied to your comment on “{title}”", ctx.actor.name),
            },
        )?;
    }
    let mut recipients = notify::followers(ctx.db, "post", &post_id)?;
    recipients.push(post.str("author_id"));
    recipients.retain(|u| !mentioned.contains(u));
    notify::send(
        ctx,
        recipients,
        &Notice {
            kind: "comment",
            post_id: Some(&post_id),
            comment_id: Some(&id),
            topic_id: None,
            message: format!("{} commented on “{title}”", ctx.actor.name),
        },
    )?;
    let uid = ctx.actor.user_id.clone();
    notify::follow(ctx, &uid, "post", &post_id)?;
    emit(
        ctx,
        Event::new("comment.created", "comment", &id, format!("commented on “{title}”")).post(&post_id).data(json!({ "body": body })),
    )?;
    one_comment(ctx, &id)
}

fn one_comment(ctx: &Ctx, id: &str) -> ApiResult<Comment> {
    let rows = ctx.db.query("SELECT * FROM comments WHERE id = ?", &params![id])?;
    to_comments(ctx, &rows)?.pop().ok_or_else(|| ApiError::not_found("comment"))
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateCommentInput {
    pub id: String,
    /// New Markdown body (author only).
    pub body: Option<String>,
    /// Resolve (true) or reopen (false) the thread.
    pub resolved: Option<bool>,
}

fn update_comment(ctx: &mut Ctx, input: UpdateCommentInput) -> ApiResult<Comment> {
    let (c, post) = load_comment(ctx, &input.id)?;
    let id = c.str("id");
    let post_id = post.str("id");
    let is_author = c.str("author_id") == ctx.actor.user_id;
    if let Some(body) = input.body {
        if !is_author {
            return Err(ApiError::forbidden("only the comment's author can edit it"));
        }
        let body = required(&body, "body", 50_000)?;
        ctx.db.execute("UPDATE comments SET body = ?, updated_at = ? WHERE id = ?", &params![body.clone(), ctx.now_s(), id.clone()])?;
        search::index_comment(ctx.db, &id)?;
        emit(
            ctx,
            Event::new("comment.updated", "comment", &id, format!("edited a comment on “{}”", post.str("title")))
                .post(&post_id)
                .data(json!({ "body": body })),
        )?;
    }
    if let Some(resolved) = input.resolved {
        let may = is_author || ctx.actor.role >= Role::Member || post.str("author_id") == ctx.actor.user_id;
        if !may {
            return Err(ApiError::forbidden("you can't resolve this comment"));
        }
        if resolved != c.opt_str("resolved_at").is_some() {
            if resolved {
                ctx.db.execute(
                    "UPDATE comments SET resolved_at = ?, resolved_by = ? WHERE id = ?",
                    &params![ctx.now_s(), ctx.actor.user_id.clone(), id.clone()],
                )?;
            } else {
                ctx.db.execute("UPDATE comments SET resolved_at = NULL, resolved_by = NULL WHERE id = ?", &params![id.clone()])?;
            }
            let (event, verb) = if resolved { ("comment.resolved", "resolved") } else { ("comment.reopened", "reopened") };
            emit(ctx, Event::new(event, "comment", &id, format!("{verb} a comment on “{}”", post.str("title"))).post(&post_id))?;
        }
    }
    one_comment(ctx, &id)
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommentIdInput {
    pub id: String,
}

fn delete_comment(ctx: &mut Ctx, input: CommentIdInput) -> ApiResult<Done> {
    let (c, post) = load_comment(ctx, &input.id)?;
    let id = c.str("id");
    if c.str("author_id") != ctx.actor.user_id && ctx.actor.role != Role::Admin {
        return Err(ApiError::forbidden("only the comment's author or an admin can delete it"));
    }
    ctx.db.execute("UPDATE comments SET deleted_at = ? WHERE id = ?", &params![ctx.now_s(), id.clone()])?;
    search::index_comment(ctx.db, &id)?;
    emit(
        ctx,
        Event::new("comment.deleted", "comment", &id, format!("deleted a comment on “{}”", post.str("title"))).post(&post.str("id")),
    )?;
    Ok(DONE)
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReactionInput {
    /// `post` or `comment`.
    pub target_type: String,
    pub target_id: String,
    /// A single emoji, e.g. "👍".
    pub emoji: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ReactionResult {
    pub reactions: Vec<ReactionGroup>,
}

/// Checks the target exists and is visible. Returns the post id it belongs to.
fn reaction_target(ctx: &Ctx, input: &ReactionInput) -> ApiResult<String> {
    match input.target_type.as_str() {
        "post" => Ok(load_post(ctx, &input.target_id, false)?.str("id")),
        "comment" => Ok(load_comment(ctx, &input.target_id)?.1.str("id")),
        _ => Err(ApiError::bad_request("target_type must be `post` or `comment`")),
    }
}

fn check_emoji(e: &str) -> ApiResult<String> {
    let e = e.trim();
    if e.is_empty() || e.chars().count() > 16 || e.chars().any(|c| c.is_ascii_alphanumeric() || c.is_whitespace() || c == '<' || c == '>') {
        return Err(ApiError::bad_request("emoji must be a single emoji character, e.g. 👍"));
    }
    Ok(e.to_string())
}

fn add_reaction(ctx: &mut Ctx, input: ReactionInput) -> ApiResult<ReactionResult> {
    let post_id = reaction_target(ctx, &input)?;
    let emoji = check_emoji(&input.emoji)?;
    let changed = ctx.db.execute(
        "INSERT INTO reactions (target_type, target_id, user_id, emoji, created_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
        &params![input.target_type.clone(), input.target_id.clone(), ctx.actor.user_id.clone(), emoji.clone(), ctx.now_s()],
    )?;
    if changed > 0 {
        emit(
            ctx,
            Event::new("reaction.added", &input.target_type, &input.target_id, format!("reacted {emoji}"))
                .post(&post_id)
                .data(json!({ "emoji": emoji })),
        )?;
    }
    Ok(ReactionResult { reactions: reaction_groups(ctx, &input.target_type, &input.target_id)? })
}

fn remove_reaction(ctx: &mut Ctx, input: ReactionInput) -> ApiResult<ReactionResult> {
    reaction_target(ctx, &input)?;
    ctx.db.execute(
        "DELETE FROM reactions WHERE target_type = ? AND target_id = ? AND user_id = ? AND emoji = ?",
        &params![input.target_type.clone(), input.target_id.clone(), ctx.actor.user_id.clone(), input.emoji.trim()],
    )?;
    Ok(ReactionResult { reactions: reaction_groups(ctx, &input.target_type, &input.target_id)? })
}
