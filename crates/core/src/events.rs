//! The activity log, which doubles as the event stream for webhooks and `list_activity`.

use serde_json::{Value, json};

use crate::db::DbExt;
use crate::error::ApiResult;
use crate::registry::Ctx;
use crate::util::hmac_sha256_hex;
use crate::{Effect, WebhookDelivery, params};

pub struct Event<'a> {
    /// e.g. `post.created`, `comment.resolved`.
    pub event: &'a str,
    pub target_type: &'a str,
    pub target_id: &'a str,
    pub post_id: Option<&'a str>,
    pub topic_id: Option<&'a str>,
    pub summary: String,
    pub data: Value,
    /// Fields added to `data` for webhooks only. They aren't kept in the activity log, so content
    /// someone later deletes (a comment's body) doesn't live on there.
    pub content: Value,
    /// Admin-only events (users, tokens, webhooks, settings) are hidden from other people.
    pub admin_only: bool,
}

impl<'a> Event<'a> {
    pub fn new(event: &'a str, target_type: &'a str, target_id: &'a str, summary: impl Into<String>) -> Self {
        Event {
            event,
            target_type,
            target_id,
            post_id: None,
            topic_id: None,
            summary: summary.into(),
            data: json!({}),
            content: json!({}),
            admin_only: false,
        }
    }

    pub fn post(mut self, id: &'a str) -> Self {
        self.post_id = Some(id);
        self
    }

    pub fn topic(mut self, id: &'a str) -> Self {
        self.topic_id = Some(id);
        self
    }

    pub fn data(mut self, data: Value) -> Self {
        self.data = data;
        self
    }

    pub fn content(mut self, content: Value) -> Self {
        self.content = content;
        self
    }

    pub fn admin_only(mut self) -> Self {
        self.admin_only = true;
        self
    }
}

/// Matches an event against a webhook filter such as `*`, `post.*` or `post.created,comment.created`.
pub fn event_matches(filter: &str, event: &str) -> bool {
    filter
        .split([',', ' '])
        .map(str::trim)
        .filter(|f| !f.is_empty())
        .any(|f| f == "*" || f == event || f.strip_suffix(".*").is_some_and(|prefix| event.starts_with(&format!("{prefix}."))))
}

/// Records an event and queues webhook deliveries for it.
pub fn emit(ctx: &mut Ctx, e: Event) -> ApiResult<i64> {
    let now = ctx.now_s();
    let data = e.data.to_string();
    let row = ctx.db.one(
        "INSERT INTO activity (event, actor_id, via, audience, target_type, target_id, post_id, topic_id, summary, data, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
        &params![
            e.event,
            ctx.actor.user_id.clone(),
            ctx.actor.via.as_str(),
            if e.admin_only { "admin" } else { "all" },
            e.target_type,
            e.target_id,
            e.post_id,
            e.topic_id,
            e.summary.clone(),
            data,
            now.clone()
        ],
    )?;
    let id = row.map(|r| r.i64("id")).unwrap_or_default();
    crate::slack::on_event(ctx, e.event, e.post_id)?;

    let hooks = ctx.db.query("SELECT id, url, secret, events FROM webhooks WHERE active = 1", &[])?;
    if hooks.is_empty() {
        return Ok(id);
    }
    let mut data = e.data.clone();
    if let (Some(d), Value::Object(extra)) = (data.as_object_mut(), &e.content) {
        d.extend(extra.clone());
    }
    let payload = json!({
        "id": id,
        "event": e.event,
        "created_at": now,
        "actor": { "id": ctx.actor.user_id, "name": ctx.actor.name, "handle": ctx.actor.handle },
        "via": ctx.actor.via.as_str(),
        "target": { "type": e.target_type, "id": e.target_id },
        "post_id": e.post_id,
        "topic_id": e.topic_id,
        "summary": e.summary,
        "data": data,
    });
    let body = payload.to_string();
    let timestamp = ctx.now.timestamp().to_string();
    for h in hooks.iter().filter(|h| event_matches(&h.str("events"), e.event)) {
        let signature = hmac_sha256_hex(&h.str("secret"), &format!("{timestamp}.{body}"));
        ctx.effects.push(Effect::Webhook(WebhookDelivery {
            webhook_id: h.str("id"),
            url: h.str("url"),
            headers: vec![
                ("content-type".into(), "application/json".into()),
                ("user-agent".into(), format!("DumbSlab-Webhooks/{}", crate::VERSION)),
                ("x-dumbslab-event".into(), e.event.to_string()),
                ("x-dumbslab-delivery".into(), format!("{id}-{}", h.str("id"))),
                ("x-dumbslab-timestamp".into(), timestamp.clone()),
                ("x-dumbslab-signature".into(), format!("sha256={signature}")),
            ],
            body: body.clone(),
        }));
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::event_matches;

    #[test]
    fn filters() {
        assert!(event_matches("*", "post.created"));
        assert!(event_matches("post.*", "post.updated"));
        assert!(!event_matches("post.*", "postal.updated"));
        assert!(event_matches("comment.created, post.created", "post.created"));
        assert!(!event_matches("comment.created", "post.created"));
    }
}
