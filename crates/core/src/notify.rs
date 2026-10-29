//! In-app notifications and follows.

use std::collections::HashSet;

use crate::db::{Db, DbExt};
use crate::error::ApiResult;
use crate::model::{actor_for_user, can_view_post};
use crate::params;
use crate::registry::Ctx;
use crate::util::new_id;

pub struct Notice<'a> {
    pub kind: &'a str,
    pub post_id: Option<&'a str>,
    pub comment_id: Option<&'a str>,
    pub topic_id: Option<&'a str>,
    pub message: String,
}

/// Notifies each recipient once, skipping the actor, inactive users, and anyone who can't see
/// the post. `post_updated` notices collapse into an existing unread one.
pub fn send(ctx: &Ctx, recipients: impl IntoIterator<Item = String>, n: &Notice) -> ApiResult<()> {
    let mut seen = HashSet::new();
    for uid in recipients {
        if uid == ctx.actor.user_id || !seen.insert(uid.clone()) {
            continue;
        }
        let Some(target) = actor_for_user(ctx.db, &uid)? else { continue };
        if let Some(pid) = n.post_id
            && !can_view_post(ctx.db, &target, pid)?
        {
            continue;
        }
        if n.kind == "post_updated" {
            let changed = ctx.db.execute(
                "UPDATE notifications SET created_at = ?, actor_id = ?, message = ?
                 WHERE user_id = ? AND kind = 'post_updated' AND post_id = ? AND read_at IS NULL",
                &params![ctx.now_s(), ctx.actor.user_id.clone(), n.message.clone(), uid.clone(), n.post_id],
            )?;
            if changed > 0 {
                continue;
            }
        }
        ctx.db.execute(
            "INSERT INTO notifications (id, user_id, kind, actor_id, post_id, comment_id, topic_id, message, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            &params![new_id(), uid, n.kind, ctx.actor.user_id.clone(), n.post_id, n.comment_id, n.topic_id, n.message.clone(), ctx.now_s()],
        )?;
    }
    Ok(())
}

pub fn followers(db: &dyn Db, target_type: &str, target_id: &str) -> ApiResult<Vec<String>> {
    Ok(db
        .query("SELECT user_id FROM follows WHERE target_type = ? AND target_id = ?", &params![target_type, target_id])?
        .iter()
        .map(|r| r.str("user_id"))
        .collect())
}

pub fn follow(ctx: &Ctx, user_id: &str, target_type: &str, target_id: &str) -> ApiResult<()> {
    ctx.db.execute(
        "INSERT INTO follows (user_id, target_type, target_id, created_at) VALUES (?, ?, ?, ?)
         ON CONFLICT(user_id, target_type, target_id) DO NOTHING",
        &params![user_id, target_type, target_id, ctx.now_s()],
    )?;
    Ok(())
}

pub fn is_following(db: &dyn Db, user_id: &str, target_type: &str, target_id: &str) -> ApiResult<bool> {
    Ok(db
        .one(
            "SELECT 1 AS f FROM follows WHERE user_id = ? AND target_type = ? AND target_id = ?",
            &params![user_id, target_type, target_id],
        )?
        .is_some())
}

/// User ids for `@handle` mentions.
pub fn resolve_handles(db: &dyn Db, handles: &[String]) -> ApiResult<Vec<String>> {
    let rows = crate::model::query_in(db, "SELECT id FROM users WHERE handle IN ({in}) AND deactivated_at IS NULL", handles, &[])?;
    Ok(rows.iter().map(|r| r.str("id")).collect())
}
