//! Slack settings: connect Slack (with the host's shared app through Add to Slack, or the
//! workspace's own app), and pick the Slack channels that hear about new and updated posts.
//! Slack's own requests, and Add to Slack's browser routes, are handled in [`crate::slack`].

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{DONE, Done, NoInput};
use crate::connect::Deferred;
use crate::db::{DbExt, SqlValue};
use crate::error::{ApiError, ApiResult};
use crate::events::{Event, emit};
use crate::model::{TopicRef, load_topic, topic_url};
use crate::registry::{Access, Ctx, Op, op};
use crate::slack::{self, Change, SlackJob};
use crate::util::new_id;
use crate::{Effect, params};

pub fn ops() -> Vec<Op> {
    vec![
        op("slack", "get_slack", "GET", "/slack", Access::Admin, get_slack)
            .title("Slack settings")
            .desc("How Slack is connected: `mode` is `shared` (DumbSlab's own Slack app, added with Add to Slack), `own` (this workspace's own Slack app) or null; which Slack workspace it belongs to; whether the bot token and signing secret are saved (they're never shown); and the channels that get posts. To connect, when `install_url` is set, have an admin open it in a browser where they're signed in to DumbSlab, and approve in Slack: that's all. Otherwise create a Slack app at `create_app_url` from `manifest` (this workspace's URLs filled in), install it, then save its bot token and signing secret with update_slack.")
            .build(),
        op("slack", "update_slack", "PATCH", "/slack", Access::Admin, update_slack)
            .title("Connect Slack")
            .desc("Save the workspace's own Slack app credentials, or turn link previews on or off. A bot token is checked with Slack before it's saved. Secrets are encrypted and never shown again. With both saved, people can use /dumbslab in Slack (search, new), and links to posts everyone can see get previews. While DumbSlab's own Slack app is connected (Add to Slack), only `unfurls` can change; disconnect it first to use your own app.")
            .build(),
        op("slack", "disconnect_slack", "DELETE", "/slack", Access::Admin, disconnect_slack)
            .title("Disconnect Slack")
            .desc("Stop using Slack: forget the Slack app's bot token and signing secret, and the channels that get posts. With DumbSlab's own Slack app (Add to Slack), the Slack workspace is free for another DumbSlab workspace when this answers. Its token isn't revoked, since every install of DumbSlab's app in a Slack workspace shares it: the app stays in Slack until a Slack admin removes it there (https://slack.com/help/articles/360003125231). With your own app, delete it at api.slack.com/apps to remove it from Slack too.")
            .destructive()
            .build(),
        op("slack", "add_slack_channel", "POST", "/slack/channels", Access::Admin, add_channel)
            .title("Send posts to a Slack channel")
            .desc("Post a message in a Slack channel when posts are published (`new_posts`) or published posts are updated (`updated_posts`): posts in one topic and its org-wide subtopics, or, without `topic_id`, every post everyone in the workspace can see. A private topic's posts reach a channel only when you pick that topic. The app posts in public channels by itself; invite it to private ones first.")
            .build(),
        op("slack", "update_slack_channel", "PATCH", "/slack/channels/{id}", Access::Admin, update_channel)
            .title("Change a Slack channel's posts")
            .desc("Change which posts a Slack channel gets: its topic (an empty `topic_id` for every post everyone can see), and whether it hears about new posts, updated posts or both.")
            .build(),
        op("slack", "delete_slack_channel", "DELETE", "/slack/channels/{id}", Access::Admin, delete_channel)
            .title("Stop sending posts to a Slack channel")
            .desc("Stop posting messages about posts in a Slack channel. What it already got stays in Slack.")
            .destructive()
            .build(),
        op("slack", "test_slack_channel", "POST", "/slack/channels/{id}/test", Access::Admin, test_channel)
            .title("Send a test message to a Slack channel")
            .desc("Posts a short message in the channel, to check the app can post there. Fails with Slack's reason, e.g. that the app must be invited to a private channel.")
            .unmetered()
            .build(),
    ]
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SlackChannel {
    pub id: String,
    /// The Slack channel's ID, like `C0123ABCD`.
    pub channel: String,
    /// Posts in this topic and its org-wide subtopics go to the channel. Null: every post everyone in the workspace can see.
    pub topic: Option<TopicRef>,
    /// A message when a post is published.
    pub new_posts: bool,
    /// A message when a published post is updated.
    pub updated_posts: bool,
    pub created_at: String,
}

/// Which Slack app connects the workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum SlackMode {
    /// DumbSlab's own Slack app, added with Add to Slack. Its signing secret is the server's.
    Shared,
    /// The workspace's own Slack app, with its bot token and signing secret saved here.
    Own,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SlackSettings {
    /// Slack can be connected on this server: it has a connector key to encrypt the app's secrets.
    pub available: bool,
    /// Which app is connected: `shared` (Add to Slack), `own`, or null when none is.
    pub mode: Option<SlackMode>,
    /// Add to Slack: an admin opens this URL in a browser where they're signed in to DumbSlab, and approves in Slack. Nothing to create or paste. Null when this server has no shared Slack app; then use your own app (`manifest`).
    pub install_url: Option<String>,
    /// The bot token and signing secret are both available, so Slack works.
    pub connected: bool,
    /// A bot token is saved. It's never shown.
    pub bot_token_saved: bool,
    /// Added with Add to Slack, but the server hasn't confirmed this workspace holds that Slack workspace yet. Until it has, DumbSlab posts nothing, answers no commands and previews no links. Reading these settings tries again.
    pub confirming: bool,
    /// A signing secret is saved. It's never shown.
    pub signing_secret_saved: bool,
    /// The Slack workspace the bot token belongs to.
    pub slack_workspace: Option<String>,
    pub slack_workspace_id: Option<String>,
    /// Links to posts pasted in Slack get previews (only posts everyone in the workspace can see).
    pub unfurls: bool,
    /// The slash command's Request URL.
    pub commands_url: String,
    /// The Request URL for Slack's events (link previews).
    pub events_url: String,
    /// Create the Slack app here, choosing "From a manifest".
    pub create_app_url: String,
    /// The Slack app manifest, with this workspace's URLs filled in.
    pub manifest: Value,
    /// The bot scopes the manifest asks for.
    pub scopes: Vec<String>,
    /// The bot scopes Slack granted DumbSlab's own Slack app (Add to Slack).
    pub granted_scopes: Vec<String>,
    pub channels: Vec<SlackChannel>,
}

pub(crate) fn settings_view(ctx: &Ctx) -> ApiResult<SlackSettings> {
    let app = slack::load(ctx.db, ctx.cfg)?;
    let workspace = crate::ops::admin::setting(ctx.db, "workspace_name")?.unwrap_or_else(|| crate::PRODUCT.into());
    let rows = ctx.db.query(
        "SELECT c.*, t.name AS topic_name, t.slug AS topic_slug, t.icon AS topic_icon, t.color AS topic_color FROM slack_channels c
         LEFT JOIN topics t ON t.id = c.topic_id WHERE c.topic_id IS NULL OR t.id IS NOT NULL ORDER BY c.created_at",
        &[],
    )?;
    let channels = rows
        .iter()
        .map(|r| SlackChannel {
            id: r.str("id"),
            channel: r.str("channel"),
            topic: r.opt_str("topic_id").map(|id| TopicRef {
                url: topic_url(ctx, &id, &r.str("topic_slug")),
                name: r.str("topic_name"),
                icon: r.str("topic_icon"),
                color: r.str("topic_color"),
                id,
            }),
            new_posts: r.bool("new_posts"),
            updated_posts: r.bool("updated_posts"),
            created_at: r.str("created_at"),
        })
        .collect();
    // Previews are on until an admin turns them off.
    let unfurls = app.as_ref().is_none_or(|a| a.unfurls);
    let a = app.unwrap_or_default();
    let mode = match &a {
        a if a.shared => Some(SlackMode::Shared),
        a if a.bot_token.is_some() || a.signing_secret.is_some() => Some(SlackMode::Own),
        _ => None,
    };
    Ok(SlackSettings {
        available: slack::available(ctx.cfg),
        mode,
        install_url: slack::shared(ctx.cfg).map(|_| ctx.url(slack::INSTALL_PATH)),
        connected: a.bot_token.is_some() && a.signing_secret.is_some(),
        bot_token_saved: a.token_saved,
        confirming: a.confirming(),
        signing_secret_saved: a.signing_secret.is_some(),
        slack_workspace: Some(a.team_name.clone()).filter(|n| !n.is_empty()),
        slack_workspace_id: a.team_id.clone(),
        unfurls,
        commands_url: ctx.url(slack::COMMANDS_PATH),
        events_url: ctx.url(slack::EVENTS_PATH),
        create_app_url: slack::CREATE_APP_URL.into(),
        manifest: slack::manifest(&workspace, &ctx.base_url),
        scopes: slack::SCOPES.iter().map(|s| s.to_string()).collect(),
        granted_scopes: a.scopes.clone(),
        channels,
    })
}

fn get_slack(ctx: &mut Ctx, _: NoInput) -> ApiResult<SlackSettings> {
    let view = settings_view(ctx)?;
    if ctx.cfg.hosting.is_some() {
        // An Add to Slack whose confirmation never ran (its job died): try again, after the answer.
        if view.confirming
            && let Some(id) = slack::load(ctx.db, ctx.cfg)?.and_then(|a| a.install_id)
        {
            ctx.effects.push(Effect::Background(crate::connect::Job::Slack(SlackJob::confirm(&ctx.base_url, &id))));
        }
        // Claims a disconnect or a switch didn't finish letting go of, each by its exact install.
        for (team, id) in slack::queued_releases(ctx.db)? {
            ctx.effects.push(Effect::Background(crate::connect::Job::Slack(slack::release_job(&ctx.base_url, &team, &id))));
        }
    }
    Ok(view)
}

/// Saving your own app's secrets while DumbSlab's is connected.
pub(crate) fn shared_refusal() -> ApiError {
    ApiError::new(
        409,
        "slack_shared",
        "This workspace is connected with DumbSlab's own Slack app (Add to Slack). Disconnect it first to use your own Slack app.",
    )
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateSlackInput {
    /// The Slack app's Bot User OAuth Token (`xoxb-…`), from its OAuth & Permissions page once it's installed. Checked with Slack before it's saved.
    pub bot_token: Option<String>,
    /// The Slack app's Signing Secret, from its Basic Information page.
    pub signing_secret: Option<String>,
    /// Preview links to posts pasted in Slack. On by default.
    pub unfurls: Option<bool>,
}

fn update_slack(ctx: &mut Ctx, input: UpdateSlackInput) -> ApiResult<Deferred<SlackSettings>> {
    let trimmed = |s: Option<String>| s.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let change = Change { bot_token: trimmed(input.bot_token), signing_secret: trimmed(input.signing_secret), unfurls: input.unfurls };
    if let Some(t) = &change.bot_token
        && (!t.starts_with("xoxb-") || t.len() > 500 || t.contains(char::is_whitespace))
    {
        return Err(ApiError::bad_request(
            "`bot_token` must be the Slack app's Bot User OAuth Token, which starts with xoxb- (from OAuth & Permissions, once the app is installed)",
        ));
    }
    if let Some(s) = &change.signing_secret
        && !(16..=128).contains(&s.len())
    {
        return Err(ApiError::bad_request("`signing_secret` must be the Slack app's Signing Secret, from its Basic Information page"));
    }
    if let Some(s) = &change.signing_secret
        && !s.chars().all(|c| c.is_ascii_alphanumeric())
    {
        return Err(ApiError::bad_request("`signing_secret` must be the Slack app's Signing Secret, from its Basic Information page"));
    }
    if (change.bot_token.is_some() || change.signing_secret.is_some()) && !slack::available(ctx.cfg) {
        return Err(slack::unavailable());
    }
    let there = slack::load(ctx.db, ctx.cfg)?;
    if (change.bot_token.is_some() || change.signing_secret.is_some()) && there.as_ref().is_some_and(|a| a.shared) {
        return Err(shared_refusal());
    }
    if change.bot_token.is_some() {
        // The host checks the token with Slack, then saves the change if the connection is still
        // the one checked against.
        let expect = there.and_then(|a| a.install_id);
        ctx.effects.push(Effect::Connect(crate::connect::Job::Slack(SlackJob::save(&ctx.base_url, &ctx.actor, change, expect))));
        return Ok(Deferred::Pending);
    }
    if change.signing_secret.is_some() || change.unfurls.is_some() {
        slack::save_now(ctx, &change)?;
    }
    Ok(Deferred::Ready(settings_view(ctx)?))
}

fn disconnect_slack(ctx: &mut Ctx, _: NoInput) -> ApiResult<Deferred<Done>> {
    let app = slack::load(ctx.db, ctx.cfg)?;
    if !slack::remove(ctx.db)? {
        return Err(ApiError::not_found("Slack connection"));
    }
    emit(ctx, Event::new("slack.disconnected", "settings", "slack", "disconnected Slack").admin_only())?;
    // DumbSlab's own Slack app, hosted: let go of the Slack workspace before answering, so another
    // DumbSlab workspace can add it at once. Its token isn't revoked: it's every install's.
    // By its exact install; recorded until the directory has let go, so a failure here is
    // finished on the next visit to Settings › Slack.
    match (app.filter(|a| a.shared).and_then(|a| Some((a.team_id?, a.install_id?))), ctx.cfg.hosting.is_some()) {
        (Some((team, id)), true) => {
            slack::queue_release(ctx.db, &team, &id, ctx.now)?;
            ctx.effects.push(Effect::Connect(crate::connect::Job::Slack(slack::release_job(&ctx.base_url, &team, &id))));
            Ok(Deferred::Pending)
        }
        _ => Ok(Deferred::Ready(DONE)),
    }
}

/// A Slack channel's ID, like `C0123ABCD` (`G…` for older private channels). Only IDs: a channel
/// has one ID but its name changes, and two spellings of one channel would each get every post.
fn check_channel(raw: &str) -> ApiResult<String> {
    let c = raw.trim();
    if (9..=24).contains(&c.len()) && c.starts_with(['C', 'G']) && c.chars().all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit()) {
        return Ok(c.to_string());
    }
    Err(ApiError::bad_request(
        "`channel` must be the Slack channel's ID, like C0123ABCD, not its name: open the channel in Slack, click its name at the top, and copy the Channel ID at the bottom of the About tab",
    ))
}

fn check_topic(ctx: &Ctx, topic_id: Option<String>) -> ApiResult<Option<String>> {
    match topic_id.map(|t| t.trim().to_string()).filter(|t| !t.is_empty()) {
        Some(t) => Ok(Some(load_topic(ctx, &t)?.str("id"))),
        None => Ok(None),
    }
}

fn read_channel(ctx: &Ctx, id: &str) -> ApiResult<SlackChannel> {
    settings_view(ctx)?.channels.into_iter().find(|c| c.id == id).ok_or_else(|| ApiError::not_found("Slack channel"))
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddChannelInput {
    /// The Slack channel's ID, like `C0123ABCD`, not its name: open the channel in Slack, click its name at the top, and copy the Channel ID at the bottom of the About tab.
    pub channel: String,
    /// Only posts in this topic and its org-wide subtopics. Leave out for every post everyone in the workspace can see.
    pub topic_id: Option<String>,
    /// A message when a post is published. Default true.
    pub new_posts: Option<bool>,
    /// A message when a published post is updated. Default false.
    pub updated_posts: Option<bool>,
}

fn add_channel(ctx: &mut Ctx, input: AddChannelInput) -> ApiResult<SlackChannel> {
    let channel = check_channel(&input.channel)?;
    let topic_id = check_topic(ctx, input.topic_id)?;
    if ctx.db.scalar_i64("SELECT COUNT(*) FROM slack_channels", &[])? >= 100 {
        return Err(ApiError::bad_request("a workspace can send posts to at most 100 Slack channels"));
    }
    let id = new_id();
    let now = ctx.now_s();
    ctx.db.execute(
        "INSERT INTO slack_channels (id, channel, topic_id, new_posts, updated_posts, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        &params![
            id.clone(),
            channel.clone(),
            topic_id.clone(),
            input.new_posts.unwrap_or(true),
            input.updated_posts.unwrap_or(false),
            ctx.actor.user_id.clone(),
            now.clone(),
            now
        ],
    )?;
    emit(ctx, Event::new("slack.channel_added", "slack_channel", &id, format!("sent posts to the Slack channel {channel}")).admin_only())?;
    read_channel(ctx, &id)
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateChannelInput {
    pub id: String,
    /// The Slack channel's ID, like `C0123ABCD`.
    pub channel: Option<String>,
    /// Only posts in this topic and its org-wide subtopics; an empty string for every post everyone in the workspace can see.
    pub topic_id: Option<String>,
    pub new_posts: Option<bool>,
    pub updated_posts: Option<bool>,
}

fn update_channel(ctx: &mut Ctx, input: UpdateChannelInput) -> ApiResult<SlackChannel> {
    if ctx.db.one("SELECT id FROM slack_channels WHERE id = ?", &params![input.id.clone()])?.is_none() {
        return Err(ApiError::not_found("Slack channel"));
    }
    let mut sets: Vec<&str> = vec![];
    let mut p: Vec<SqlValue> = vec![];
    if let Some(c) = input.channel {
        sets.push("channel = ?");
        p.push(check_channel(&c)?.into());
    }
    if let Some(t) = input.topic_id {
        sets.push("topic_id = ?");
        p.push(check_topic(ctx, Some(t))?.into());
    }
    if let Some(n) = input.new_posts {
        sets.push("new_posts = ?");
        p.push(n.into());
    }
    if let Some(u) = input.updated_posts {
        sets.push("updated_posts = ?");
        p.push(u.into());
    }
    sets.push("updated_at = ?");
    p.push(ctx.now_s().into());
    p.push(input.id.clone().into());
    ctx.db.execute(&format!("UPDATE slack_channels SET {} WHERE id = ?", sets.join(", ")), &p)?;
    emit(ctx, Event::new("slack.channel_updated", "slack_channel", &input.id, "changed a Slack channel's posts").admin_only())?;
    read_channel(ctx, &input.id)
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelIdInput {
    pub id: String,
}

fn delete_channel(ctx: &mut Ctx, input: ChannelIdInput) -> ApiResult<Done> {
    if ctx.db.execute("DELETE FROM slack_channels WHERE id = ?", &params![input.id.clone()])? == 0 {
        return Err(ApiError::not_found("Slack channel"));
    }
    emit(ctx, Event::new("slack.channel_removed", "slack_channel", &input.id, "stopped sending posts to a Slack channel").admin_only())?;
    Ok(DONE)
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SlackTest {
    /// Slack took the message.
    pub ok: bool,
    pub channel: String,
}

fn test_channel(ctx: &mut Ctx, input: ChannelIdInput) -> ApiResult<Deferred<SlackTest>> {
    if slack::channel_row(ctx.db, &input.id)?.is_none() {
        return Err(ApiError::not_found("Slack channel"));
    }
    if !slack::load(ctx.db, ctx.cfg)?.is_some_and(|a| a.bot_token.is_some()) {
        return Err(ApiError::bad_request("Connect Slack first: save the bot token in Settings › Slack."));
    }
    ctx.effects.push(Effect::Connect(crate::connect::Job::Slack(SlackJob::test(&ctx.base_url, &input.id))));
    Ok(Deferred::Pending)
}
