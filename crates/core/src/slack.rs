//! Slack: search DumbSlab, preview links to its posts and start drafts from Slack, and tell Slack
//! channels about new and updated posts.
//!
//! Each workspace uses its own Slack app. An admin creates it from the manifest [`manifest`]
//! builds, installs it, and gives DumbSlab its bot token and signing secret (Settings › Slack,
//! `update_slack`). There's no shared Slack app: Slack lets an app reach other companies' Slack
//! workspaces only through its Marketplace.
//!
//! - Slack calls `/slack/commands` (the `/dumbslab` slash command) and `/slack/events` (link
//!   previews). These endpoints sit outside the session and CSRF checks: Slack's signature
//!   ([`verify`]) is all that admits a request, and a signature seen before is refused.
//! - Who is asking: the Slack user's email, once Slack has confirmed it (`users.info`), matched to
//!   an active DumbSlab person. Search and drafts then run as that person through the same
//!   operations as the API, so they see and do only what that person may. Anyone else gets a
//!   reply that says how to connect, and nothing from the workspace.
//! - Slack shows a link preview to everyone in the conversation, so only posts everyone in the
//!   workspace can see are previewed, and only when the person who shared the link can see them.
//! - Channel messages are webhook deliveries to `chat.postMessage` ([`on_event`]). A post in a
//!   private topic reaches a channel only if an admin picked that topic for the channel.
//! - The core does no I/O: calls to Slack's API run as a [`connect::Job`] the host sends.
//!
//! Slack's docs: https://docs.slack.dev/authentication/verifying-requests-from-slack,
//! https://docs.slack.dev/interactivity/implementing-slash-commands,
//! https://docs.slack.dev/apis/events-api/using-http-request-urls,
//! https://docs.slack.dev/messaging/unfurling-links-in-messages, https://docs.slack.dev/reference/methods/chat.unfurl,
//! https://docs.slack.dev/reference/methods/users.info, https://docs.slack.dev/reference/objects/user-object,
//! https://docs.slack.dev/reference/methods/chat.postMessage, https://docs.slack.dev/reference/app-manifest,
//! https://docs.slack.dev/messaging/formatting-message-text

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Duration, Utc};
use hmac::{KeyInit, Mac};
use serde_json::{Map, Value, json};
use sha2::Sha256;

use crate::auth::{Actor, Role, Scopes, Via};
use crate::connect::{self, Credential, Finish, HttpCall, HttpReply, Step};
use crate::db::{Db, DbExt};
use crate::error::{ApiError, ApiResult};
use crate::events::{Event, emit};
use crate::registry::{Ctx, registry};
use crate::util::{parse_ts, secure_eq, sha256_hex, ts};
use crate::{Effect, HostConfig, Outcome, Request, Response, WebhookDelivery, params};

/// Where Slack sends the slash command.
pub const COMMANDS_PATH: &str = "/slack/commands";
/// Where Slack sends events (link previews) and its URL check.
pub const EVENTS_PATH: &str = "/slack/events";
/// The largest Slack request read. A slash command or a `link_shared` event is a few KB.
pub const MAX_BODY: usize = 64 * 1024;
/// The bot scopes the app asks for, each for one feature: the slash command; posting (in public
/// channels without being invited); link previews; and finding who someone is by confirmed email.
pub const SCOPES: &[&str] = &["commands", "chat:write", "chat:write.public", "links:read", "links:write", "users:read", "users:read.email"];
/// Where an admin creates the Slack app.
pub const CREATE_APP_URL: &str = "https://api.slack.com/apps?new_app=1";

/// How far a request's timestamp may be from now, either way.
const TOLERANCE_SECS: i64 = 300;
/// How long a signature is remembered: longer than any timestamp it could carry stays fresh.
const SIGNATURE_MEMORY_SECS: i64 = 2 * TOLERANCE_SECS + 60;
/// How long an event id is remembered. Slack retries a failed event within minutes and never
/// delivers one more than two hours late.
const EVENT_MEMORY_SECS: i64 = 3 * 3600;
const API: &str = "https://slack.com/api";
/// Whose secrets these are, for the encryption's associated data. Never a person's id.
const OWNER: &str = "@workspace";
const BOT_TOKEN: &str = "slack-bot-token";
const SIGNING_SECRET: &str = "slack-signing-secret";
/// Search results in one reply.
const MAX_RESULTS: u32 = 5;
/// Links previewed from one message.
const MAX_LINKS: usize = 5;
/// Messages one request may send to one channel: a bulk import publishes hundreds of posts.
const MAX_MESSAGES_PER_REQUEST: usize = 3;
/// Marks which post a channel message is about, so one request sends one message per post.
const POST_HEADER: &str = "x-dumbslab-post";

// ---------------------------------------------------------------------------
// The stored app

/// The workspace's Slack app, with its secrets decrypted. Never printed.
#[derive(Clone, Default)]
pub struct App {
    /// `None` when there's none, or it can't be read with the host's connector key.
    pub bot_token: Option<String>,
    pub signing_secret: Option<String>,
    /// The Slack workspace the bot token belongs to, from `auth.test`.
    pub team_id: Option<String>,
    pub team_name: String,
    pub bot_user_id: Option<String>,
    pub unfurls: bool,
}

impl fmt::Debug for App {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("App").field("team_id", &self.team_id).field("unfurls", &self.unfurls).finish_non_exhaustive()
    }
}

fn key(cfg: &HostConfig) -> Option<&str> {
    cfg.connectors.key.as_deref().filter(|k| !k.is_empty())
}

/// Whether Slack can be connected here: the host has a connector key to encrypt its secrets.
pub fn available(cfg: &HostConfig) -> bool {
    key(cfg).is_some()
}

fn seal(cfg: &HostConfig, kind: &str, secret: &str) -> ApiResult<String> {
    let key = key(cfg).ok_or_else(unavailable)?;
    connect::seal(key, OWNER, kind, &Credential { token: secret.to_string(), ..Default::default() })
}

pub fn unavailable() -> ApiError {
    ApiError::new(
        503,
        "slack_unavailable",
        "Slack needs this server's connector key to keep the Slack app's secrets: set DUMBSLAB_CONNECTOR_KEY (self-hosted) or the CONNECTOR_KEY secret (Cloudflare).",
    )
}

/// The stored Slack app, or `None` when nobody connected one.
pub fn load(db: &dyn Db, cfg: &HostConfig) -> ApiResult<Option<App>> {
    let Some(r) = db.one("SELECT * FROM slack_app WHERE id = 1", &[])? else { return Ok(None) };
    let open = |kind: &str, column: &str| -> Option<String> {
        let sealed = r.opt_str(column)?;
        connect::open(key(cfg)?, OWNER, kind, &sealed).ok().map(|c| c.token)
    };
    Ok(Some(App {
        bot_token: open(BOT_TOKEN, "bot_token"),
        signing_secret: open(SIGNING_SECRET, "signing_secret"),
        team_id: r.opt_str("team_id"),
        team_name: r.str("team_name"),
        bot_user_id: r.opt_str("bot_user_id"),
        unfurls: r.bool("unfurls"),
    }))
}

/// What an admin changes about the Slack app. Never printed.
#[derive(Clone, Default)]
pub struct Change {
    pub bot_token: Option<String>,
    pub signing_secret: Option<String>,
    pub unfurls: Option<bool>,
}

/// The Slack workspace a bot token belongs to.
#[derive(Clone, Debug, Default)]
struct Team {
    id: String,
    name: String,
    bot_user_id: String,
}

/// Saves a change. A bot token comes with the Slack workspace `auth.test` said it belongs to.
fn save(db: &dyn Db, cfg: &HostConfig, change: &Change, team: Option<&Team>, actor_id: &str, now: DateTime<Utc>) -> ApiResult<()> {
    db.execute("INSERT INTO slack_app (id, updated_at) VALUES (1, ?) ON CONFLICT(id) DO NOTHING", &params![ts(now)])?;
    if let (Some(token), Some(team)) = (&change.bot_token, team) {
        db.execute(
            "UPDATE slack_app SET bot_token = ?, team_id = ?, team_name = ?, bot_user_id = ? WHERE id = 1",
            &params![
                seal(cfg, BOT_TOKEN, token)?,
                team.id.clone(),
                team.name.clone(),
                Some(team.bot_user_id.clone()).filter(|b| !b.is_empty())
            ],
        )?;
    }
    if let Some(secret) = &change.signing_secret {
        db.execute("UPDATE slack_app SET signing_secret = ? WHERE id = 1", &params![seal(cfg, SIGNING_SECRET, secret)?])?;
    }
    if let Some(on) = change.unfurls {
        db.execute("UPDATE slack_app SET unfurls = ? WHERE id = 1", &params![on])?;
    }
    db.execute("UPDATE slack_app SET updated_by = ?, updated_at = ? WHERE id = 1", &params![actor_id, ts(now)])?;
    Ok(())
}

/// Saves a change that needs no word from Slack (everything but a bot token), and records it.
pub(crate) fn save_now(ctx: &mut Ctx, change: &Change) -> ApiResult<()> {
    save(ctx.db, ctx.cfg, change, None, &ctx.actor.user_id.clone(), ctx.now)?;
    record_change(ctx, change)
}

fn record_change(ctx: &mut Ctx, change: &Change) -> ApiResult<()> {
    let data = json!({
        "bot_token": change.bot_token.is_some(),
        "signing_secret": change.signing_secret.is_some(),
        "unfurls": change.unfurls,
    });
    emit(ctx, Event::new("slack.updated", "settings", "slack", "updated the Slack app").data(data).admin_only())?;
    Ok(())
}

/// Disconnects Slack: forgets the app's secrets and the channels that get posts.
pub(crate) fn remove(db: &dyn Db) -> ApiResult<bool> {
    let app = db.execute("DELETE FROM slack_app", &[])?;
    let channels = db.execute("DELETE FROM slack_channels", &[])?;
    Ok(app + channels > 0)
}

/// The Slack app manifest for this workspace: its slash command, the domain whose links it
/// previews, its events URL and its scopes.
pub fn manifest(workspace_name: &str, base_url: &str) -> Value {
    let domain = connect::host_of(base_url).unwrap_or_default();
    let description = connect::excerpt(&format!("Search, preview and draft posts in {workspace_name} on DumbSlab."), 140);
    json!({
        "_metadata": { "major_version": 2, "minor_version": 1 },
        "display_information": {
            "name": "DumbSlab",
            "description": description,
            "background_color": "#1f2937",
        },
        "features": {
            "bot_user": { "display_name": "dumbslab", "always_online": true },
            "slash_commands": [{
                "command": "/dumbslab",
                "url": format!("{base_url}{COMMANDS_PATH}"),
                "description": "Search DumbSlab or start a draft",
                "usage_hint": "search <words> | new <title> | help",
                "should_escape": false,
            }],
            "unfurl_domains": [domain],
        },
        "oauth_config": { "scopes": { "bot": SCOPES } },
        "settings": {
            "event_subscriptions": { "request_url": format!("{base_url}{EVENTS_PATH}"), "bot_events": ["link_shared"] },
            "org_deploy_enabled": false,
            "socket_mode_enabled": false,
            "token_rotation_enabled": false,
        },
    })
}

// ---------------------------------------------------------------------------
// Requests from Slack

/// Why a request to the Slack endpoints was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// No signature or timestamp.
    Unsigned,
    /// The signature doesn't match the signing secret.
    Forged,
    /// Signed more than five minutes away from now.
    Stale,
}

fn signature(secret: &str, timestamp: &str, body: &[u8]) -> String {
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(b"v0:");
    mac.update(timestamp.as_bytes());
    mac.update(b":");
    mac.update(body);
    format!("v0={}", hex::encode(mac.finalize().into_bytes()))
}

/// Checks Slack's signature: `X-Slack-Signature` is `v0=` and the hex HMAC-SHA256, keyed with the
/// signing secret, of `v0:{X-Slack-Request-Timestamp}:{raw body}`, compared in constant time; and
/// the timestamp is within five minutes of now.
pub fn verify(secret: &str, timestamp: Option<&str>, sig: Option<&str>, body: &[u8], now_unix: i64) -> Result<(), Refusal> {
    fn present(v: Option<&str>) -> Option<&str> {
        v.map(str::trim).filter(|v| !v.is_empty())
    }
    let (Some(t), Some(sig)) = (present(timestamp), present(sig)) else { return Err(Refusal::Unsigned) };
    let sent: i64 = t.parse().map_err(|_| Refusal::Forged)?;
    if !secure_eq(sig, &signature(secret, t, body)) {
        return Err(Refusal::Forged);
    }
    if (now_unix - sent).abs() > TOLERANCE_SECS {
        return Err(Refusal::Stale);
    }
    Ok(())
}

fn refused(r: Refusal) -> ApiError {
    match r {
        Refusal::Unsigned => {
            ApiError::new(401, "unsigned", "Requests here come from Slack, signed with X-Slack-Signature and X-Slack-Request-Timestamp.")
        }
        Refusal::Forged => ApiError::new(401, "bad_signature", "The Slack signature doesn't match this workspace's signing secret."),
        Refusal::Stale => ApiError::new(401, "stale_request", "This Slack request was signed more than five minutes from now."),
    }
}

/// Remembers `key` until `until`. `false` when it's remembered already.
fn remember(db: &dyn Db, key: &str, until: DateTime<Utc>) -> ApiResult<bool> {
    Ok(db.execute("INSERT INTO slack_seen (key, expires_at) VALUES (?, ?) ON CONFLICT(key) DO NOTHING", &params![key, ts(until)])? > 0)
}

/// `POST /slack/commands` and `POST /slack/events`.
pub fn handle(db: &dyn Db, cfg: &HostConfig, req: &Request) -> Outcome {
    let mut out = run(db, cfg, req).unwrap_or_else(|e| crate::http::failed(&e));
    out.response.headers.push(("cache-control".into(), "no-store".into()));
    out
}

fn run(db: &dyn Db, cfg: &HostConfig, req: &Request) -> ApiResult<Outcome> {
    let path = req.path.as_str();
    if path != COMMANDS_PATH && path != EVENTS_PATH {
        return Err(ApiError::not_found("route"));
    }
    if req.method != "POST" {
        return Err(ApiError::new(405, "method_not_allowed", "Slack sends POST requests here."));
    }
    if req.body.len() > MAX_BODY {
        return Err(ApiError::new(413, "too_large", "request body too large"));
    }
    let now = Utc::now();
    let app = load(db, cfg)?;
    let Some((app, secret)) = app.and_then(|a| a.signing_secret.clone().map(|s| (a, s))) else {
        return Err(ApiError::new(404, "slack_off", "Slack isn't connected to this workspace."));
    };
    let sig = req.header("x-slack-signature");
    verify(&secret, req.header("x-slack-request-timestamp"), sig, &req.body, now.timestamp()).map_err(refused)?;
    // Each signed request is handled once: a copy of one is refused.
    db.execute("DELETE FROM slack_seen WHERE expires_at < ?", &params![ts(now)])?;
    let sig_key = format!("signature:{}", sha256_hex(sig.unwrap_or_default().trim()));
    if !remember(db, &sig_key, now + Duration::seconds(SIGNATURE_MEMORY_SECS))? {
        return Err(ApiError::new(401, "replayed", "This Slack request was handled already."));
    }
    let base = crate::http::base_url(cfg, req);
    if path == COMMANDS_PATH { command(db, &app, &base, &req.body) } else { event(db, &app, &base, &req.body, now) }
}

/// A form body, as Slack sends slash commands.
fn form(body: &[u8]) -> BTreeMap<String, String> {
    let decode = |s: &str| urlencoding::decode(&s.replace('+', " ")).map(|c| c.into_owned()).unwrap_or_default();
    String::from_utf8_lossy(body).split('&').filter_map(|p| p.split_once('=')).map(|(k, v)| (decode(k), decode(v))).collect()
}

fn reply(message: Value) -> Outcome {
    crate::http::done(Response::json(200, &message))
}

fn pending(job: SlackJob) -> Outcome {
    let mut out = reply(json!(connect::PENDING));
    out.effects.push(Effect::Connect(connect::Job::Slack(job)));
    out
}

/// A Slack user id: letters and digits.
fn valid_user(id: &str) -> bool {
    !id.is_empty() && id.len() <= 32 && id.chars().all(|c| c.is_ascii_alphanumeric())
}

fn command(db: &dyn Db, app: &App, base: &str, body: &[u8]) -> ApiResult<Outcome> {
    let f = form(body);
    let field = |k: &str| f.get(k).map(|v| v.trim().to_string()).unwrap_or_default();
    // Slack checks the certificate of publicly distributed apps' commands now and then.
    if field("ssl_check") == "1" {
        return Ok(crate::http::done(Response::empty(200)));
    }
    let name = Some(field("command")).filter(|c| c.starts_with('/')).unwrap_or_else(|| "/dumbslab".into());
    let text = field("text");
    let (word, rest) = text.split_once(char::is_whitespace).map(|(w, r)| (w, r.trim())).unwrap_or((text.as_str(), ""));
    let workspace = workspace_name(db)?;
    let work = match word.to_ascii_lowercase().as_str() {
        "search" | "find" => {
            if rest.is_empty() {
                return Ok(reply(ephemeral(&format!("Add the words to search for, like `{} search onboarding`.", escape(&name)))));
            }
            if rest.chars().count() > 200 {
                return Ok(reply(ephemeral("Search for at most 200 characters.")));
            }
            Work::Search { user: field("user_id"), q: rest.to_string() }
        }
        "new" | "draft" => {
            if rest.is_empty() {
                return Ok(reply(ephemeral(&format!("Add the draft's title, like `{} new Onboarding checklist`.", escape(&name)))));
            }
            Work::NewDraft { user: field("user_id"), title: rest.to_string() }
        }
        _ => return Ok(reply(help(&name, &workspace))),
    };
    if !valid_user(&field("user_id")) {
        return Ok(reply(ephemeral("Slack didn't say who's asking. Try again.")));
    }
    if app.bot_token.is_none() {
        return Ok(reply(ephemeral(&format!(
            "{} hasn't finished connecting Slack: an admin needs to paste the bot token in Settings › Slack.",
            escape(&workspace)
        ))));
    }
    Ok(pending(SlackJob::new(base, work)))
}

fn event(db: &dyn Db, app: &App, base: &str, body: &[u8], now: DateTime<Utc>) -> ApiResult<Outcome> {
    let v: Value = serde_json::from_slice(body).map_err(|_| ApiError::bad_request("Slack sent an event DumbSlab couldn't read."))?;
    let ack = || reply(json!({ "ok": true }));
    match v["type"].as_str() {
        // Slack checks the events URL when an admin saves it.
        Some("url_verification") => Ok(reply(json!({ "challenge": v["challenge"].as_str().unwrap_or_default() }))),
        Some("event_callback") => {
            // Slack sends an event again when an answer was slow; it's handled once.
            let id = v["event_id"].as_str().unwrap_or_default();
            if !id.is_empty() && !remember(db, &format!("event:{id}"), now + Duration::seconds(EVENT_MEMORY_SECS))? {
                return Ok(ack());
            }
            let e = &v["event"];
            let user = e["user"].as_str().unwrap_or_default();
            if e["type"] != "link_shared" || !app.unfurls || app.bot_token.is_none() || !valid_user(user) {
                return Ok(ack());
            }
            let links = post_links(base, &e["links"]);
            if links.is_empty() {
                return Ok(ack());
            }
            let target = UnfurlTarget {
                unfurl_id: e["unfurl_id"].as_str().map(str::to_string),
                source: e["source"].as_str().map(str::to_string),
                channel: e["channel"].as_str().unwrap_or_default().to_string(),
                ts: e["message_ts"].as_str().unwrap_or_default().to_string(),
            };
            Ok(pending(SlackJob::new(base, Work::Unfurl { user: user.to_string(), links, target })))
        }
        _ => Ok(ack()),
    }
}

/// Links to this workspace's posts among a `link_shared` event's links: (link as sent, post id).
fn post_links(base: &str, links: &Value) -> Vec<(String, String)> {
    let ours = connect::host_of(base);
    let mut out: Vec<(String, String)> = vec![];
    for url in links.as_array().into_iter().flatten().filter_map(|l| l["url"].as_str()) {
        if connect::host_of(url) != ours || out.iter().any(|(u, _)| u == url) {
            continue;
        }
        let path = connect::path_of(url);
        if let [p, id, ..] = path.as_slice()
            && p == "p"
            && !id.is_empty()
            && id.len() <= 40
            && id.chars().all(|c| c.is_ascii_alphanumeric())
        {
            out.push((url.to_string(), id.clone()));
        }
        if out.len() == MAX_LINKS {
            break;
        }
    }
    out
}

fn workspace_name(db: &dyn Db) -> ApiResult<String> {
    Ok(crate::ops::admin::setting(db, "workspace_name")?.unwrap_or_else(|| crate::PRODUCT.into()))
}

// ---------------------------------------------------------------------------
// Messages

/// Text for Slack's mrkdwn: `&`, `<` and `>` become entities, so nothing in it can turn into a
/// link, a mention or `<!channel>`.
pub fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// A mrkdwn link, `<url|label>`, with the label escaped on one line. The URL is percent-encoded
/// wherever Slack's link syntax would break.
fn link(url: &str, label: &str) -> String {
    let mut safe = String::with_capacity(url.len());
    for ch in url.chars() {
        if ch.is_ascii_graphic() && !matches!(ch, '<' | '>' | '|') {
            safe.push(ch);
        } else {
            let mut buf = [0u8; 4];
            for b in ch.encode_utf8(&mut buf).bytes() {
                safe.push_str(&format!("%{b:02X}"));
            }
        }
    }
    let label = label.split_whitespace().collect::<Vec<_>>().join(" ");
    format!("<{safe}|{}>", escape(&label))
}

/// At most `max` characters (Block Kit's limits).
fn clip(text: &str, max: usize) -> String {
    if text.chars().count() <= max { text.to_string() } else { text.chars().take(max - 1).collect::<String>() + "…" }
}

/// A mrkdwn section. `verbatim` keeps Slack from turning anything in it into links or mentions.
fn section(text: &str) -> Value {
    json!({ "type": "section", "text": { "type": "mrkdwn", "text": clip(text, 3000), "verbatim": true } })
}

fn context(text: &str) -> Value {
    json!({ "type": "context", "elements": [{ "type": "mrkdwn", "text": clip(text, 2000), "verbatim": true }] })
}

/// A reply only the person who typed the command sees. `text` is mrkdwn, already escaped.
fn ephemeral(text: &str) -> Value {
    json!({ "response_type": "ephemeral", "text": clip(text, 3000), "blocks": [section(text)] })
}

fn help(command: &str, workspace: &str) -> Value {
    let (c, ws) = (escape(command), escape(workspace));
    ephemeral(&format!(
        "*{c} search &lt;words&gt;* finds posts in {ws} that you can see.\n*{c} new &lt;title&gt;* starts a draft only you can see.\nPaste a link to a post to preview it. Previews show posts everyone in {ws} can see, and only to people who can see them."
    ))
}

/// A search snippet (escaped HTML with `<mark>`) as plain text.
fn plain_snippet(html: &str) -> String {
    connect::excerpt(&connect::decode_entities(&html.replace("<mark>", "").replace("</mark>", "")), 240)
}

fn search_reply(base: &str, q: &str, results: &Value) -> Value {
    let hits = results["items"].as_array().cloned().unwrap_or_default();
    let all = link(&format!("{base}/search?q={}", urlencoding::encode(q)), "Search in DumbSlab");
    if hits.is_empty() {
        let text = format!("No posts you can see match “{}”.", escape(q));
        return json!({ "response_type": "ephemeral", "text": text, "blocks": [section(&text), context(&all)] });
    }
    let title = format!("Posts matching “{}”", escape(q));
    let mut blocks = vec![section(&format!("*{title}*"))];
    for hit in &hits {
        let name = connect::excerpt(hit["title"].as_str().unwrap_or_default(), 150);
        let draft = if hit["status"] == "draft" { " _(draft)_" } else { "" };
        let snippet = plain_snippet(hit["snippet"].as_str().unwrap_or_default());
        blocks.push(section(&format!("*{}*{draft}\n{}", link(hit["url"].as_str().unwrap_or_default(), &name), escape(&snippet))));
    }
    blocks.push(context(&all));
    json!({ "response_type": "ephemeral", "text": title, "blocks": blocks })
}

/// A published post, as previews and channel messages show it.
struct Card {
    title: String,
    url: String,
    excerpt: String,
    /// Its org-wide topics: private ones' names stay out of Slack.
    topics: Vec<String>,
    author: String,
    updated_at: Option<DateTime<Utc>>,
}

fn card(db: &dyn Db, base: &str, post_id: &str) -> ApiResult<Option<Card>> {
    let Some(r) = db.one(
        "SELECT p.title, p.slug, p.excerpt, p.updated_at, u.name AS author FROM posts p LEFT JOIN users u ON u.id = p.author_id
         WHERE p.id = ? AND p.status = 'published' AND p.deleted_at IS NULL AND p.is_template = 0",
        &params![post_id],
    )?
    else {
        return Ok(None);
    };
    let topics = db
        .query(
            "SELECT t.name FROM post_topics pt JOIN topics t ON t.id = pt.topic_id WHERE pt.post_id = ? AND t.visibility = 'org' ORDER BY t.name",
            &params![post_id],
        )?
        .iter()
        .map(|t| t.str("name"))
        .collect();
    Ok(Some(Card {
        title: connect::excerpt(&r.str("title"), 150),
        url: format!("{base}/p/{post_id}/{}", r.str("slug")),
        excerpt: connect::excerpt(&r.str("excerpt"), 300),
        topics,
        author: r.str("author"),
        updated_at: parse_ts(&r.str("updated_at")),
    }))
}

impl Card {
    fn blocks(&self, line: &str) -> Vec<Value> {
        let mut head = format!("*{}*", link(&self.url, &self.title));
        if !self.excerpt.is_empty() {
            head.push('\n');
            head.push_str(&escape(&self.excerpt));
        }
        vec![section(&head), context(line)]
    }

    /// "Ada · Engineering, Runbooks · Updated Oct 30", escaped.
    fn byline(&self) -> String {
        let mut parts = vec![];
        if !self.author.is_empty() {
            parts.push(escape(&self.author));
        }
        if !self.topics.is_empty() {
            parts.push(escape(&self.topics.join(", ")));
        }
        if let Some(t) = self.updated_at {
            parts.push(format!("Updated <!date^{}^{{date_short_pretty}}|{}>", t.timestamp(), t.format("%Y-%m-%d")));
        }
        parts.join(" · ")
    }
}

/// Whether everyone in the workspace can see a post: it's in no topic, or in an org-wide one.
fn everyone_sees(db: &dyn Db, post_id: &str) -> ApiResult<bool> {
    Ok(db
        .one(
            "SELECT 1 AS ok FROM posts p WHERE p.id = ? AND p.status = 'published' AND p.deleted_at IS NULL
               AND (NOT EXISTS (SELECT 1 FROM post_topics pt WHERE pt.post_id = p.id)
                    OR EXISTS (SELECT 1 FROM post_topics pt JOIN topics t ON t.id = pt.topic_id WHERE pt.post_id = p.id AND t.visibility = 'org'))",
            &params![post_id],
        )?
        .is_some())
}

// ---------------------------------------------------------------------------
// Who's asking

/// What to tell someone DumbSlab can't match to a person.
fn not_linked(workspace: &str) -> String {
    format!(
        "Your Slack account isn't linked to anyone in {}. DumbSlab matches people by the email address Slack has confirmed for them, so sign in to DumbSlab with the same email you use in Slack, or ask an admin to add you.",
        escape(workspace)
    )
}

/// The DumbSlab person a Slack user is, from Slack's answer to `users.info`: an active person
/// (not a bot account) with the Slack user's email, once Slack has confirmed that address, and
/// only for people in the Slack workspace the app belongs to. `Err` says why not, for them.
fn identify(db: &dyn Db, app: &App, reply: &HttpReply) -> ApiResult<Result<Actor, String>> {
    let workspace = workspace_name(db)?;
    if let Some(code) = slack_error(reply) {
        return Ok(Err(match code.as_str() {
            "missing_scope" => "DumbSlab's Slack app can't read email addresses. Ask an admin to update it from the manifest in Settings › Slack and reinstall it.".into(),
            "invalid_auth" | "not_authed" | "token_revoked" | "account_inactive" => {
                "Slack no longer accepts DumbSlab's bot token. Ask an admin to paste a new one in Settings › Slack.".into()
            }
            "user_not_found" | "user_not_visible" => not_linked(&workspace),
            _ => "Slack didn't say who you are just now. Try again in a minute.".into(),
        }));
    }
    let u = &reply.json()["user"];
    if u["deleted"] == true || u["is_bot"] == true {
        return Ok(Err(not_linked(&workspace)));
    }
    // People from other companies, in channels shared with them, are no one here.
    if let Some(team) = app.team_id.as_deref().filter(|t| !t.is_empty()) {
        let home = u["team_id"].as_str() == Some(team);
        let grid = u["enterprise_user"]["teams"].as_array().is_some_and(|ts| ts.iter().any(|t| t.as_str() == Some(team)));
        if !home && !grid {
            return Ok(Err(not_linked(&workspace)));
        }
    }
    if u["is_email_confirmed"].as_bool() != Some(true) {
        return Ok(Err(
            "Slack hasn't confirmed your email address yet, so DumbSlab can't tell who you are. Confirm it in Slack, then try again."
                .into(),
        ));
    }
    let email = u["profile"]["email"].as_str().unwrap_or_default().trim();
    if email.is_empty() {
        return Ok(Err("DumbSlab's Slack app can't read email addresses. Ask an admin to update it from the manifest in Settings › Slack and reinstall it.".into()));
    }
    // Emails are unique, ignoring case.
    let Some(row) = db.one(
        "SELECT id, name, handle, email, role FROM users WHERE email = ? AND deactivated_at IS NULL AND is_bot = 0",
        &params![email],
    )?
    else {
        return Ok(Err(not_linked(&workspace)));
    };
    let role = Role::parse(&row.str("role")).unwrap_or(Role::Viewer);
    Ok(Ok(Actor {
        user_id: row.str("id"),
        name: row.str("name"),
        handle: row.str("handle"),
        email: row.str("email"),
        role,
        scopes: Scopes::for_role(role),
        via: Via::Slack,
        token_id: None,
        session_hash: None,
    }))
}

// ---------------------------------------------------------------------------
// Calls to Slack

/// Slack's error code for a call that failed, or `None` when it worked. Slack answers most
/// failures with HTTP 200 and `"ok": false`.
fn slack_error(reply: &HttpReply) -> Option<String> {
    if reply.status == 0 {
        return Some("no_answer".into());
    }
    if reply.status == 429 {
        return Some("ratelimited".into());
    }
    if !reply.ok() {
        return Some(format!("http_{}", reply.status));
    }
    let v = reply.json();
    if v["ok"].as_bool() == Some(true) {
        return None;
    }
    let code: String =
        v["error"].as_str().unwrap_or("unreadable_answer").chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').take(60).collect();
    Some(code)
}

fn post_json(method: &str, token: &str, body: &Value) -> HttpCall {
    HttpCall {
        method: "POST",
        url: format!("{API}/{method}"),
        headers: vec![("content-type".into(), "application/json; charset=utf-8".into())],
        body: Some(body.to_string()),
    }
    .bearer(token)
}

fn users_info(token: &str, user: &str) -> HttpCall {
    HttpCall::get(format!("{API}/users.info?user={}", urlencoding::encode(user))).bearer(token)
}

fn auth_test(token: &str) -> HttpCall {
    HttpCall::post_form(format!("{API}/auth.test"), &[]).bearer(token)
}

/// A message for `chat.postMessage`: plain `text` for notifications, and the blocks.
fn message(channel: &str, text: &str, blocks: Vec<Value>) -> Value {
    json!({
        "channel": channel,
        "text": clip(text, 3000),
        "blocks": blocks,
        "unfurl_links": false,
        "unfurl_media": false,
        "parse": "none",
        "link_names": false,
    })
}

fn token_refused(code: &str) -> ApiError {
    let message = match code {
        "invalid_auth" | "not_authed" | "token_revoked" | "account_inactive" | "not_allowed_token_type" => {
            "Slack didn't accept that bot token. Copy the Bot User OAuth Token (it starts with xoxb-) from your Slack app's OAuth & Permissions page.".to_string()
        }
        "no_answer" => "Slack didn't answer. Try again in a minute.".into(),
        "ratelimited" => "Slack's rate limit was reached. Try again in a minute.".into(),
        other => format!("Slack refused the bot token ({other})."),
    };
    ApiError::new(400, "slack_refused", message)
}

fn post_refused(code: &str, channel: &str) -> ApiError {
    let c = channel;
    let message = match code {
        "not_in_channel" => {
            format!("The DumbSlab app isn't in {c}. Invite it there (type /invite @dumbslab in the channel), then try again.")
        }
        "channel_not_found" => format!(
            "Slack can't find {c}. Use the channel's ID (open the channel's details; it's at the bottom), and invite the app to a private channel first."
        ),
        "is_archived" => format!("{c} is archived."),
        "missing_scope" => {
            "The Slack app is missing a permission. Update it from the manifest in Settings › Slack, then reinstall it.".into()
        }
        "invalid_auth" | "not_authed" | "token_revoked" | "account_inactive" => {
            "Slack no longer accepts the saved bot token. Paste a new one in Settings › Slack.".into()
        }
        "ratelimited" => "Slack's rate limit was reached. Try again in a minute.".into(),
        "no_answer" => "Slack didn't answer. Try again in a minute.".into(),
        other => format!("Slack refused the message ({other})."),
    };
    ApiError::new(400, "slack_refused", message)
}

// ---------------------------------------------------------------------------
// Jobs

/// Work for Slack that needs its API, run by the host in steps (see [`connect::step`]).
#[derive(Clone)]
pub struct SlackJob {
    base_url: String,
    work: Work,
    phase: Phase,
    /// What the job's operations left for the host to deliver (a new draft's webhooks).
    effects: Vec<Effect>,
}

#[derive(Clone)]
enum Work {
    /// `/dumbslab search`: Slack user, words.
    Search { user: String, q: String },
    /// `/dumbslab new`: Slack user, title.
    NewDraft { user: String, title: String },
    /// Preview links someone shared.
    Unfurl { user: String, links: Vec<(String, String)>, target: UnfurlTarget },
    /// An admin saved a bot token: check it with Slack, then save it with the rest of the change.
    Save { admin: String, via: Via, change: Change },
    /// An admin asked for a test message in a channel.
    Test { channel_id: String },
}

/// The message whose links Slack asked to preview.
#[derive(Clone, Debug)]
struct UnfurlTarget {
    unfurl_id: Option<String>,
    source: Option<String>,
    channel: String,
    ts: String,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Phase {
    Start,
    /// Waiting for `users.info`.
    Identifying,
    /// Waiting for `chat.unfurl`.
    Unfurling,
    /// Waiting for `auth.test`.
    Checking,
    /// Waiting for `chat.postMessage`.
    Posting,
}

// Jobs carry tokens and what people typed; never print them.
impl fmt::Debug for SlackJob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.work {
            Work::Search { .. } => "search",
            Work::NewDraft { .. } => "new_draft",
            Work::Unfurl { .. } => "unfurl",
            Work::Save { .. } => "save",
            Work::Test { .. } => "test",
        };
        write!(f, "SlackJob({kind}, {:?})", self.phase)
    }
}

impl SlackJob {
    fn new(base_url: &str, work: Work) -> SlackJob {
        SlackJob { base_url: base_url.to_string(), work, phase: Phase::Start, effects: vec![] }
    }

    /// Checks a new bot token with Slack, then saves it with the rest of `change`.
    pub(crate) fn save(base_url: &str, admin: &Actor, change: Change) -> SlackJob {
        SlackJob::new(base_url, Work::Save { admin: admin.user_id.clone(), via: admin.via, change })
    }

    /// Sends a test message to a channel.
    pub(crate) fn test(base_url: &str, channel_id: &str) -> SlackJob {
        SlackJob::new(base_url, Work::Test { channel_id: channel_id.to_string() })
    }

    /// What the job's operations left for the host to deliver.
    pub fn take_effects(&mut self) -> Vec<Effect> {
        std::mem::take(&mut self.effects)
    }
}

fn fill(value: Value) -> ApiResult<Step> {
    Ok(Step::Done(Finish::Fill(value)))
}

fn fail(e: ApiError) -> ApiResult<Step> {
    Ok(Step::Done(Finish::Fail(e)))
}

fn job_ctx<'a>(db: &'a dyn Db, cfg: &'a HostConfig, base_url: &str, actor: Actor, now: DateTime<Utc>) -> Ctx<'a> {
    Ctx { db, actor, now, cfg, base_url: base_url.to_string(), effects: vec![] }
}

/// Runs a Slack job's next step.
pub fn step(db: &dyn Db, cfg: &HostConfig, job: &mut SlackJob, replies: Vec<HttpReply>, now: DateTime<Utc>) -> ApiResult<Step> {
    let answer = replies.into_iter().next().unwrap_or_default();
    let app = load(db, cfg)?.unwrap_or_default();
    match (job.phase, job.work.clone()) {
        (Phase::Start, Work::Search { user, .. } | Work::NewDraft { user, .. } | Work::Unfurl { user, .. }) => {
            let Some(token) = app.bot_token.clone() else {
                // Disconnected meanwhile.
                return fill(match job.work {
                    Work::Unfurl { .. } => json!({ "ok": true }),
                    _ => ephemeral("Slack isn't connected to DumbSlab any more."),
                });
            };
            job.phase = Phase::Identifying;
            Ok(Step::Fetch(vec![users_info(&token, &user)]))
        }
        (Phase::Identifying, Work::Search { q, .. }) => {
            let actor = match identify(db, &app, &answer)? {
                Ok(a) => a,
                Err(message) => return fill(ephemeral(&message)),
            };
            let mut ctx = job_ctx(db, cfg, &job.base_url, actor, now);
            let op = registry().get("search").expect("search is an operation");
            match op.call(&mut ctx, json!({ "q": q, "types": ["post"], "limit": MAX_RESULTS })) {
                Ok(results) => fill(search_reply(&job.base_url, &q, &results)),
                Err(e) => fill(ephemeral(&escape(&e.message))),
            }
        }
        (Phase::Identifying, Work::NewDraft { title, .. }) => {
            let actor = match identify(db, &app, &answer)? {
                Ok(a) => a,
                Err(message) => return fill(ephemeral(&message)),
            };
            let mut ctx = job_ctx(db, cfg, &job.base_url, actor, now);
            let op = registry().get("create_post").expect("create_post is an operation");
            match op.call(&mut ctx, json!({ "title": title })) {
                Ok(post) => {
                    job.effects.extend(std::mem::take(&mut ctx.effects));
                    let url = post["url"].as_str().unwrap_or_default();
                    let name = connect::excerpt(post["title"].as_str().unwrap_or_default(), 150);
                    fill(ephemeral(&format!("Started a draft: *{}*. Only you can see it until you publish it.", link(url, &name))))
                }
                // A refusal (a viewer, a title that's too long, a paused workspace) comes before
                // anything is written, so the step's transaction can commit. Anything else rolls back.
                Err(e) if e.status < 500 || e.code == "free_capacity" => fill(ephemeral(&escape(&e.message))),
                Err(e) => Err(e),
            }
        }
        (Phase::Identifying, Work::Unfurl { links, target, .. }) => {
            let Ok(actor) = identify(db, &app, &answer)? else { return fill(json!({ "ok": true })) };
            let mut unfurls = Map::new();
            for (url, id) in &links {
                // Slack shows the preview to everyone in the conversation.
                if !everyone_sees(db, id)? || !crate::model::can_view_post(db, &actor, id)? {
                    continue;
                }
                if let Some(c) = card(db, &job.base_url, id)? {
                    unfurls.insert(url.clone(), json!({ "blocks": c.blocks(&c.byline()) }));
                }
            }
            let Some(token) = app.bot_token.filter(|_| !unfurls.is_empty()) else { return fill(json!({ "ok": true })) };
            let mut body = json!({ "unfurls": unfurls });
            match (&target.unfurl_id, &target.source) {
                (Some(id), Some(source)) => {
                    body["unfurl_id"] = json!(id);
                    body["source"] = json!(source);
                }
                _ => {
                    body["channel"] = json!(target.channel);
                    body["ts"] = json!(target.ts);
                }
            }
            job.phase = Phase::Unfurling;
            Ok(Step::Fetch(vec![post_json("chat.unfurl", &token, &body)]))
        }
        (Phase::Unfurling, _) => fill(json!({ "ok": slack_error(&answer).is_none() })),
        (Phase::Start, Work::Save { change, .. }) => {
            let Some(token) = change.bot_token.as_deref() else { return fail(ApiError::internal("no bot token to check")) };
            job.phase = Phase::Checking;
            Ok(Step::Fetch(vec![auth_test(token)]))
        }
        (Phase::Checking, Work::Save { admin, via, change }) => {
            if let Some(code) = slack_error(&answer) {
                return fail(token_refused(&code));
            }
            let v = answer.json();
            let team = Team { id: connect::s(&v["team_id"]), name: connect::s(&v["team"]), bot_user_id: connect::s(&v["user_id"]) };
            // The admin may have lost the role while Slack answered.
            let Some(mut actor) = crate::model::actor_for_user(db, &admin)?.filter(|a| a.role == Role::Admin) else {
                return fail(ApiError::forbidden("only admins can connect Slack"));
            };
            actor.via = via;
            save(db, cfg, &change, Some(&team), &admin, now)?;
            let mut ctx = job_ctx(db, cfg, &job.base_url, actor, now);
            record_change(&mut ctx, &change)?;
            job.effects.extend(std::mem::take(&mut ctx.effects));
            let view = crate::ops::slack::settings_view(&ctx)?;
            fill(serde_json::to_value(view).map_err(|e| ApiError::internal(e.to_string()))?)
        }
        (Phase::Start, Work::Test { channel_id }) => {
            let Some(token) = app.bot_token.clone() else {
                return fail(ApiError::bad_request("Connect Slack first: paste the bot token in Settings › Slack."));
            };
            let Some(c) = channel_row(db, &channel_id)? else { return fail(ApiError::not_found("Slack channel")) };
            let what = match (c.topic_name.as_deref(), c.new_posts, c.updated_posts) {
                (_, false, false) => "nothing yet: pick new or updated posts in Settings › Slack".to_string(),
                (topic, new, updated) => format!(
                    "{} {}",
                    match (new, updated) {
                        (true, true) => "new and updated posts",
                        (true, false) => "new posts",
                        _ => "updated posts",
                    },
                    match topic {
                        Some(t) => format!("in {}", escape(t)),
                        None => format!("that everyone in {} can see", escape(&workspace_name(db)?)),
                    }
                ),
            };
            let text = format!("DumbSlab is connected. This channel gets {what}.");
            job.phase = Phase::Posting;
            Ok(Step::Fetch(vec![post_json("chat.postMessage", &token, &message(&c.channel, &text, vec![section(&text)]))]))
        }
        (Phase::Posting, Work::Test { channel_id }) => {
            let channel = channel_row(db, &channel_id)?.map(|c| c.channel).unwrap_or_default();
            match slack_error(&answer) {
                Some(code) => fail(post_refused(&code, &channel)),
                None => fill(json!({ "ok": true, "channel": channel })),
            }
        }
        (phase, _) => Err(ApiError::internal(format!("a Slack job can't continue from {phase:?}"))),
    }
}

// ---------------------------------------------------------------------------
// Channel messages

/// A channel mapping, as stored.
pub(crate) struct ChannelRow {
    pub channel: String,
    /// `None` for every post everyone can see.
    pub topic_name: Option<String>,
    pub new_posts: bool,
    pub updated_posts: bool,
}

pub(crate) fn channel_row(db: &dyn Db, id: &str) -> ApiResult<Option<ChannelRow>> {
    Ok(db
        .one(
            "SELECT c.channel, c.new_posts, c.updated_posts, t.name AS topic_name FROM slack_channels c
             LEFT JOIN topics t ON t.id = c.topic_id WHERE c.id = ?",
            &params![id],
        )?
        .map(|r| ChannelRow {
            channel: r.str("channel"),
            topic_name: r.opt_str("topic_name"),
            new_posts: r.bool("new_posts"),
            updated_posts: r.bool("updated_posts"),
        }))
}

/// Whether a post belongs to a channel's topic: it's in the topic itself, or in one of its
/// subtopics that everyone can see. A private subtopic wasn't picked, so its posts stay out.
fn in_topic(db: &dyn Db, post_id: &str, topic_id: &str) -> ApiResult<bool> {
    Ok(db
        .one(
            "WITH RECURSIVE sub(id) AS (SELECT ? UNION SELECT t.id FROM topics t JOIN sub ON t.parent_id = sub.id)
             SELECT 1 AS ok FROM post_topics pt JOIN topics t ON t.id = pt.topic_id
             WHERE pt.post_id = ? AND (t.id = ? OR (t.visibility = 'org' AND t.id IN (SELECT id FROM sub))) LIMIT 1",
            &params![topic_id, post_id, topic_id],
        )?
        .is_some())
}

/// Queues Slack messages about an event: a post published (`post.created` as published, or
/// `post.published`) or a published post updated (`post.updated`), for each channel that wants
/// it. Called for every event; returns at once for the rest.
pub fn on_event(ctx: &mut Ctx, event: &str, post_id: Option<&str>) -> ApiResult<()> {
    let (column, verb) = match event {
        "post.created" | "post.published" => ("new_posts", "Published"),
        "post.updated" => ("updated_posts", "Updated"),
        _ => return Ok(()),
    };
    let Some(post_id) = post_id else { return Ok(()) };
    let channels = ctx.db.query(
        &format!(
            "SELECT c.id, c.channel, c.topic_id, t.name AS topic_name FROM slack_channels c LEFT JOIN topics t ON t.id = c.topic_id
             WHERE c.{column} = 1 AND (c.topic_id IS NULL OR t.id IS NOT NULL) ORDER BY c.created_at"
        ),
        &[],
    )?;
    if channels.is_empty() {
        return Ok(());
    }
    let Some(token) = load(ctx.db, ctx.cfg)?.and_then(|a| a.bot_token) else { return Ok(()) };
    let Some(card) = card(ctx.db, &ctx.base_url, post_id)? else { return Ok(()) };
    let public = everyone_sees(ctx.db, post_id)?;
    for c in channels {
        let mut topics = card.topics.clone();
        match c.opt_str("topic_id") {
            None if public => {}
            None => continue,
            Some(t) if in_topic(ctx.db, post_id, &t)? => {
                // An admin picked this topic for the channel, so its name may show there.
                let name = c.str("topic_name");
                if !topics.contains(&name) {
                    topics.insert(0, name);
                }
            }
            Some(_) => continue,
        }
        let queue = format!("slack:{}", c.str("id"));
        let queued: Vec<&WebhookDelivery> = ctx
            .effects
            .iter()
            .filter_map(|e| match e {
                Effect::Webhook(d) if d.webhook_id == queue => Some(d),
                _ => None,
            })
            .collect();
        let already = queued.iter().any(|d| d.headers.iter().any(|(k, v)| k == POST_HEADER && v == post_id));
        if already || queued.len() >= MAX_MESSAGES_PER_REQUEST {
            continue;
        }
        let actor = escape(&ctx.actor.name);
        let mut line = format!("{verb} by {actor}");
        if !topics.is_empty() {
            line.push_str(&format!(" · {}", escape(&topics.join(", "))));
        }
        let text = format!("{actor} {} “{}”", verb.to_lowercase(), escape(&card.title));
        let body = message(&c.str("channel"), &text, card.blocks(&line));
        ctx.effects.push(Effect::Webhook(WebhookDelivery {
            webhook_id: queue,
            url: format!("{API}/chat.postMessage"),
            headers: vec![
                ("content-type".into(), "application/json; charset=utf-8".into()),
                ("authorization".into(), format!("Bearer {token}")),
                (POST_HEADER.into(), post_id.to_string()),
            ],
            body: body.to_string(),
        }));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_follow_slacks_example() {
        // Slack's documented example request.
        let secret = "8f742231b10e8888abcd99yyyzzz85a5";
        let body = b"token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c";
        let sig = "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503";
        assert_eq!(verify(secret, Some("1531420618"), Some(sig), body, 1531420618 + 10), Ok(()));
        assert_eq!(verify(secret, Some("1531420618"), Some(sig), body, 1531420618 + 301), Err(Refusal::Stale));
        assert_eq!(verify(secret, Some("1531420618"), Some(sig), body, 1531420618 - 301), Err(Refusal::Stale));
        assert_eq!(verify("another", Some("1531420618"), Some(sig), body, 1531420618), Err(Refusal::Forged));
        assert_eq!(verify(secret, Some("1531420619"), Some(sig), body, 1531420618), Err(Refusal::Forged));
        assert_eq!(verify(secret, Some("1531420618"), Some(sig), b"token=changed", 1531420618), Err(Refusal::Forged));
        assert_eq!(verify(secret, None, Some(sig), body, 1531420618), Err(Refusal::Unsigned));
        assert_eq!(verify(secret, Some("1531420618"), Some(" "), body, 1531420618), Err(Refusal::Unsigned));
        assert_eq!(verify(secret, Some("soon"), Some(sig), body, 1531420618), Err(Refusal::Forged));
    }

    #[test]
    fn text_is_escaped_for_mrkdwn() {
        assert_eq!(escape("<!channel> & <@U1|x> > y"), "&lt;!channel&gt; &amp; &lt;@U1|x&gt; &gt; y");
        assert_eq!(link("https://kb.test/p/a1/café", "A <b> &\nB"), "<https://kb.test/p/a1/caf%C3%A9|A &lt;b&gt; &amp; B>");
        assert_eq!(link("https://x.test/a|b>c", "t"), "<https://x.test/a%7Cb%3Ec|t>");
        assert_eq!(plain_snippet("a &lt;b&gt; <mark>c</mark> &amp; d"), "a <b> c & d");
        assert_eq!(clip(&"x".repeat(10), 5), "xxxx…");
    }

    #[test]
    fn post_links_are_this_workspaces_only() {
        let links = json!([
            { "url": "https://kb.test/p/abc123/hello", "domain": "kb.test" },
            { "url": "https://kb.test/p/abc123/hello", "domain": "kb.test" },
            { "url": "https://kb.test/p/def456", "domain": "kb.test" },
            { "url": "https://kb.test/t/abc123", "domain": "kb.test" },
            { "url": "https://kb.test/p/../x", "domain": "kb.test" },
            { "url": "https://evil.test/p/abc123", "domain": "evil.test" },
            { "url": "https://kb.test@evil.test/p/abc123", "domain": "evil.test" },
        ]);
        let found = post_links("https://kb.test", &links);
        assert_eq!(
            found,
            vec![
                ("https://kb.test/p/abc123/hello".to_string(), "abc123".to_string()),
                ("https://kb.test/p/def456".into(), "def456".into())
            ]
        );
    }

    #[test]
    fn manifests_name_this_workspace() {
        let m = manifest("Acme", "https://acme.dumbslab.com");
        assert_eq!(m["features"]["slash_commands"][0]["url"], "https://acme.dumbslab.com/slack/commands");
        assert_eq!(m["settings"]["event_subscriptions"]["request_url"], "https://acme.dumbslab.com/slack/events");
        assert_eq!(m["features"]["unfurl_domains"], json!(["acme.dumbslab.com"]));
        assert!(m["display_information"]["description"].as_str().unwrap().chars().count() <= 140);
        let long = manifest(&"A very long workspace name ".repeat(10), "https://x.test");
        assert!(long["display_information"]["description"].as_str().unwrap().chars().count() <= 140);
    }

    #[test]
    fn jobs_never_print_secrets() {
        let change = Change { bot_token: Some("xoxb-secret".into()), signing_secret: Some("s3cret".into()), unfurls: None };
        let job = SlackJob::new("https://kb.test", Work::Save { admin: "u".into(), via: Via::Web, change });
        let app = App { bot_token: Some("xoxb-secret".into()), signing_secret: Some("s3cret".into()), ..Default::default() };
        let printed = format!("{job:?} {app:?}");
        assert!(!printed.contains("secret"), "{printed}");
    }
}
