//! Multi-tenant hosting: workspace addresses, signed sign-up links and the directory of
//! workspaces. The Cloudflare deployment gives every workspace its own subdomain and Durable
//! Object; the native server stays single-workspace and doesn't use this module.

use chrono::{DateTime, Duration, Utc};
use schemars::JsonSchema;
use serde::Serialize;

use crate::db::{Db, DbExt};
use crate::error::{ApiError, ApiResult};
use crate::events::{Event, emit};
use crate::plan::Capacity;
use crate::registry::Ctx;
use crate::util::{hmac_sha256_hex, secure_eq, ts};
use crate::{AddressMove, Effect, HostConfig, Response, params};

/// Subdomains nobody can claim.
pub const RESERVED: &[&str] = &[
    "about",
    "abuse",
    "admin",
    "administrator",
    "api",
    "app",
    "assets",
    "auth",
    "autodiscover",
    "billing",
    "blog",
    "cdn",
    "console",
    "dashboard",
    "dev",
    "doc",
    "docs",
    "dumbslab",
    "email",
    "ftp",
    "help",
    "internal",
    "localhost",
    "login",
    "mail",
    "mcp",
    "mx",
    "ns1",
    "ns2",
    "oauth",
    "operator",
    "root",
    "security",
    "signup",
    "slab",
    "smtp",
    "staging",
    "static",
    "status",
    "support",
    "system",
    "test",
    "webmail",
    "www",
];

/// 3-32 lowercase letters, digits and hyphens, starting and ending with a letter or digit.
pub fn validate_slug(slug: &str) -> Result<(), String> {
    let len = slug.len();
    if !(3..=32).contains(&len) {
        return Err("the address must be 3 to 32 characters".into());
    }
    if !slug.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
        return Err("use only lowercase letters, digits and hyphens".into());
    }
    if slug.starts_with('-') || slug.ends_with('-') || slug.contains("--") {
        return Err("hyphens can't be at the start or end, or doubled".into());
    }
    if RESERVED.contains(&slug) {
        return Err(format!("`{slug}` is reserved; pick another address"));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKind {
    /// The root domain, e.g. `dumbslab.com`: the sign-up site.
    Root,
    /// A workspace subdomain, e.g. `acme.dumbslab.com`.
    Workspace(String),
    /// Anything else (deeper subdomains, other domains).
    Other,
}

/// Classifies a request host (an optional `:port` is ignored) against the root domain.
pub fn host_kind(host: &str, root: &str) -> HostKind {
    let host = host.rsplit_once(':').map_or(host, |(h, port)| if port.bytes().all(|b| b.is_ascii_digit()) { h } else { host });
    let host = host.to_ascii_lowercase();
    let root = root.to_ascii_lowercase();
    if host == root {
        return HostKind::Root;
    }
    match host.strip_suffix(&format!(".{root}")) {
        Some(label) if !label.is_empty() && !label.contains('.') => HostKind::Workspace(label.to_string()),
        _ => HostKind::Other,
    }
}

/// Whether a host is a development machine (`wrangler dev` serves these over plain HTTP).
pub fn is_local_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host == "localhost" || host.ends_with(".localhost") || host == "127.0.0.1" || host == "[::1]"
}

/// The HTTPS address for a plain-HTTP request, or `None` when it's already HTTPS or for a local
/// host. Sign-in, setup links and session cookies must never cross the network in the clear.
pub fn https_upgrade(url: &str) -> Option<String> {
    let rest = url.strip_prefix("http://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(end);
    let host = match authority.rsplit_once(':') {
        Some((h, port)) if port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => authority,
    };
    if is_local_host(host) {
        return None;
    }
    let path = if path.is_empty() { "/" } else { path };
    Some(format!("https://{}{path}", host.to_ascii_lowercase()))
}

/// The `Strict-Transport-Security` value, so browsers keep to HTTPS after their first visit. A
/// hosted deployment covers its workspace subdomains too; a single workspace leaves the rest of
/// its owner's domain alone.
pub fn hsts(multi_tenant: bool) -> &'static str {
    if multi_tenant { "max-age=31536000; includeSubDomains" } else { "max-age=31536000" }
}

/// The sign-up site's `/robots.txt`. Workspaces answer with their own, which keeps crawlers out.
pub fn root_robots_txt(root: &str) -> String {
    format!("User-agent: *\nAllow: /\nDisallow: /api/\n\nSitemap: https://{root}/sitemap.xml\n")
}

/// The sign-up site's `/sitemap.xml`: it has one public page.
pub fn root_sitemap_xml(root: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n  <url><loc>https://{root}/</loc></url>\n</urlset>\n"
    )
}

/// The sign-up site's `/llms.txt`: what DumbSlab is, and how an agent signs a person up and
/// connects to a workspace. Each workspace serves its own detailed guide.
pub fn root_llms_txt(root: &str) -> String {
    format!(
        "# DumbSlab

> DumbSlab is a free, open-source team wiki and knowledge base, built so AI agents can do everything people can. Every workspace has its own MCP server and REST API.

Hosted workspaces are free at https://{root}/ with no credit card. Each workspace has its own address, such as https://acme.{root}. The same software runs self-hosted as one Rust binary with one SQLite file, or on Cloudflare Workers.

## Create a workspace

- A person signs up at https://{root}/: they pick a workspace name and an address, then create the admin account.
- An agent can start sign-up for a person: `POST https://{root}/api/signup` with the header `x-dumbslab-client: agent` and a JSON body such as `{{\"workspace_name\": \"Acme\", \"address\": \"acme\"}}`. The reply's `setup_url` is a one-hour link; give it to the person to create their admin account.
- `GET https://{root}/api/signup/check?address=acme` answers `{{\"available\": true}}` or `{{\"available\": false, \"message\": \"…\"}}`.
- Addresses are 3 to 32 lowercase letters, digits and single hyphens.

## Connect an agent to a workspace

- MCP server: `https://<address>.{root}/mcp` (Streamable HTTP). Clients that support OAuth, such as Claude, ChatGPT and Cursor, need only the URL; the person approves access in the browser. Other clients send `Authorization: Bearer <token>` with a token from Settings › API tokens.
- `?toolset=core` lists about 15 everyday tools plus `call_operation`, which reaches everything else. `?toolset=read` lists only read-only tools.
- REST API: `https://<address>.{root}/api/v1`, described by OpenAPI 3.1 at `/api/v1/openapi.json`.
- Every workspace serves a full agent guide at `https://<address>.{root}/llms.txt`.
- Edits are precise: find and replace, or change one section by its heading. Pass `base_version` to get a 409 conflict instead of overwriting a teammate's change.

## Self-host

- [Source code](https://github.com/tstout729/dumbslab): Rust, dual-licensed MIT or Apache-2.0.
- [README](https://github.com/tstout729/dumbslab/blob/main/README.md): features, quick start, MCP, REST and the CLI.
- [Deploying to Cloudflare](https://github.com/tstout729/dumbslab/blob/main/docs/cloudflare.md)
"
    )
}

/// A sign-up link token: `{expiry}.{HMAC(secret, "setup|{workspace}|{expiry}")}`.
pub fn signup_token(secret: &str, workspace: &str, expires_unix: i64) -> String {
    format!("{expires_unix}.{}", hmac_sha256_hex(secret, &format!("setup|{workspace}|{expires_unix}")))
}

/// Checks a sign-up token for this workspace that hasn't expired.
pub fn verify_signup_token(secret: &str, workspace: &str, token: &str, now_unix: i64) -> bool {
    let Some((expiry, _)) = token.split_once('.') else { return false };
    let Ok(expires) = expiry.parse::<i64>() else { return false };
    expires >= now_unix && secure_eq(token, &signup_token(secret, workspace, expires))
}

/// How long a reserved address waits for its owner to finish setup.
pub const RESERVATION_MINUTES: i64 = 60;

pub const DIRECTORY_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS workspaces (
  slug TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('reserved', 'active', 'disabled')),
  ip_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  reserved_until TEXT NOT NULL,
  activated_at TEXT
);
CREATE INDEX IF NOT EXISTS workspaces_ip ON workspaces(ip_hash, created_at);
CREATE INDEX IF NOT EXISTS workspaces_created ON workspaces(created_at);
-- Addresses a workspace moved to. `home` is its first address, which names its storage; the
-- workspace lives at the row marked `current`, or at `home` when none is.
CREATE TABLE IF NOT EXISTS addresses (
  slug TEXT PRIMARY KEY,
  home TEXT NOT NULL,
  current INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS addresses_home ON addresses(home);
-- What each workspace (by its first address) last reported: its plan, the rows it wrote in the
-- 24 hours before the report, and its size. The free plan's totals decide whether it's at capacity.
CREATE TABLE IF NOT EXISTS usage (
  home TEXT PRIMARY KEY,
  plan TEXT NOT NULL,
  writes_24h INTEGER NOT NULL,
  storage_bytes INTEGER NOT NULL,
  reported_at TEXT NOT NULL
);
-- Stripe customers and the workspace each one pays for. When the workspace is deleted its rows
-- stay, detached, so Stripe's later events about them never reach a new workspace at that address.
CREATE TABLE IF NOT EXISTS billing (
  customer TEXT PRIMARY KEY,
  home TEXT NOT NULL,
  detached INTEGER NOT NULL DEFAULT 0,
  subscription TEXT,
  status TEXT,
  -- The last refund, dispute or fraud warning, e.g. `charge.dispute.created 2026-11-02T…`.
  risk TEXT,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS billing_home ON billing(home);
-- Slack workspaces added with DumbSlab's own Slack app (Add to Slack): the installation itself,
-- bot token included, and the one workspace (by its first address) that holds it. This table is
-- the only record of who holds a Slack workspace and the only copy of its token: Slack sends
-- every Slack workspace's commands and events to the root domain, which forwards them to the
-- holder, and a workspace gets the token from here each time it acts on Slack, only while it's
-- the holder.
CREATE TABLE IF NOT EXISTS slack_installs (
  team_id TEXT PRIMARY KEY,
  home TEXT NOT NULL,
  -- Sealed with the connector key by the workspace that installed it; opaque here.
  bot_token TEXT NOT NULL,
  -- The SHA-256 of the token: a check that found a token dead forgets the row only while it
  -- still holds that token.
  token_fingerprint TEXT NOT NULL,
  bot_user_id TEXT,
  team_name TEXT NOT NULL DEFAULT '',
  scopes TEXT NOT NULL DEFAULT '',
  installed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS slack_installs_home ON slack_installs(home);
-- Add to Slack: a counter per workspace that moves on with every change to which Slack workspaces
-- it holds (an install, a release, a dead token forgotten). Every change names the value its
-- workflow started from, and is refused once that moved on: a delayed step can't undo a newer
-- one. It outlives the installations.
CREATE TABLE IF NOT EXISTS slack_homes (
  home TEXT PRIMARY KEY,
  generation INTEGER NOT NULL DEFAULT 0
);
";

/// The most addresses one workspace can use, counting its first.
pub const MAX_ADDRESSES: i64 = 5;

pub fn directory_migrate(db: &dyn Db) -> ApiResult<()> {
    db.execute_batch(DIRECTORY_SCHEMA)
}

/// Sign-up limits that keep a free deployment free.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub per_ip_per_day: i64,
    pub per_day: i64,
    pub max_workspaces: i64,
    /// What all free workspaces together may use. Sign-ups pause while it's used up.
    pub free: FreeBudget,
}

/// The free plan's share of the hosting bill: rows all free workspaces may write in 24 hours and
/// what they may store, together. Keep both inside what the hosting plan includes.
#[derive(Debug, Clone, Copy)]
pub struct FreeBudget {
    pub writes_per_day: u64,
    pub storage_bytes: u64,
}

/// Reserves an address for a new workspace. Returns the reservation's expiry.
pub fn reserve(db: &dyn Db, slug: &str, name: &str, ip_hash: &str, now: DateTime<Utc>, limits: Limits) -> ApiResult<DateTime<Utc>> {
    validate_slug(slug).map_err(ApiError::bad_request)?;
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 80 {
        return Err(ApiError::bad_request("the workspace name must be 1 to 80 characters"));
    }
    let now_s = ts(now);
    if is_taken(db, slug, &now_s)? {
        return Err(ApiError::conflict(taken_message(slug)));
    }
    let day_ago = ts(now - Duration::days(1));
    let from_ip =
        db.scalar_i64("SELECT COUNT(*) FROM workspaces WHERE ip_hash = ? AND created_at > ?", &params![ip_hash, day_ago.clone()])?;
    if from_ip >= limits.per_ip_per_day {
        return Err(ApiError::too_many("you've created the maximum number of workspaces for today; try again tomorrow"));
    }
    let today = db.scalar_i64("SELECT COUNT(*) FROM workspaces WHERE created_at > ?", &params![day_ago])?;
    if today >= limits.per_day {
        return Err(ApiError::too_many("sign-ups are busy today; please try again tomorrow"));
    }
    let live =
        db.scalar_i64("SELECT COUNT(*) FROM workspaces WHERE status != 'reserved' OR reserved_until > ?", &params![now_s.clone()])?;
    if live >= limits.max_workspaces {
        return Err(ApiError::new(503, "full", "DumbSlab has reached its workspace limit for now; you can self-host it for free"));
    }
    let capacity = free_capacity(db, now, limits.free)?;
    if capacity.writes_paused || capacity.growth_paused {
        return Err(ApiError::new(
            503,
            "full",
            "DumbSlab's free plan is at capacity right now; try again tomorrow, or self-host it for free",
        ));
    }
    // Whole seconds, so a sign-up link's expiry names exactly this reservation.
    let until = DateTime::from_timestamp(now.timestamp() + RESERVATION_MINUTES * 60, 0).unwrap_or(now);
    db.execute(
        "INSERT INTO workspaces (slug, name, status, ip_hash, created_at, reserved_until) VALUES (?, ?, 'reserved', ?, ?, ?)
         ON CONFLICT(slug) DO UPDATE SET name = excluded.name, status = 'reserved', ip_hash = excluded.ip_hash,
           created_at = excluded.created_at, reserved_until = excluded.reserved_until, activated_at = NULL",
        &params![slug, name, ip_hash, now_s, ts(until)],
    )?;
    Ok(until)
}

/// Whether a workspace, a live reservation or a moved workspace's old address holds `slug`.
fn is_taken(db: &dyn Db, slug: &str, now_s: &str) -> ApiResult<bool> {
    if let Some(row) = db.one("SELECT status, reserved_until FROM workspaces WHERE slug = ?", &params![slug])?
        && (row.str("status") != "reserved" || row.str("reserved_until").as_str() > now_s)
    {
        return Ok(true);
    }
    Ok(db.one("SELECT home FROM addresses WHERE slug = ?", &params![slug])?.is_some())
}

fn taken_message(slug: &str) -> String {
    format!("{slug} is taken; pick another address")
}

/// Why an address can't be claimed, or `None` when it's free. The sign-up form asks while
/// someone types; `reserve` checks again, along with the sign-up limits.
pub fn address_unavailable(db: &dyn Db, slug: &str, now: DateTime<Utc>) -> ApiResult<Option<String>> {
    if let Err(message) = validate_slug(slug) {
        return Ok(Some(message));
    }
    Ok(is_taken(db, slug, &ts(now))?.then(|| taken_message(slug)))
}

/// Whether a sign-up link (by its expiry) matches the address's current, live reservation.
/// Deleted, disabled, activated and re-reserved addresses all fail, so old links die with them.
pub fn reservation_matches(db: &dyn Db, slug: &str, expires_unix: i64, now: DateTime<Utc>) -> ApiResult<bool> {
    let Some(row) = db.one("SELECT status, reserved_until FROM workspaces WHERE slug = ?", &params![slug])? else {
        return Ok(false);
    };
    let until = crate::util::parse_ts(&row.str("reserved_until"));
    Ok(row.str("status") == "reserved" && until.is_some_and(|u| u.timestamp() == expires_unix && u > now))
}

/// Marks a reserved address as an active workspace (called after its first admin is created).
pub fn activate(db: &dyn Db, slug: &str, now: DateTime<Utc>) -> ApiResult<()> {
    db.execute(
        "UPDATE workspaces SET status = 'active', activated_at = ? WHERE slug = ? AND status = 'reserved'",
        &params![ts(now), slug],
    )?;
    Ok(())
}

pub fn set_status(db: &dyn Db, slug: &str, status: &str) -> ApiResult<()> {
    if !matches!(status, "reserved" | "active" | "disabled") {
        return Err(ApiError::bad_request("status must be reserved, active or disabled"));
    }
    let n = db.execute("UPDATE workspaces SET status = ? WHERE slug = ?", &params![status, slug])?;
    if n == 0 {
        return Err(ApiError::not_found(format!("workspace `{slug}`")));
    }
    Ok(())
}

/// Removes a workspace (by its first address) and every address it moved to. Its billing records
/// are detached: someone may claim the address again, and Stripe's later events about the old
/// customers must not reach their workspace. Its Slack workspaces are let go of, and its Slack
/// connection's value moves on.
pub fn remove(db: &dyn Db, home: &str) -> ApiResult<()> {
    db.execute("DELETE FROM workspaces WHERE slug = ?", &params![home])?;
    db.execute("DELETE FROM addresses WHERE home = ?", &params![home])?;
    db.execute("DELETE FROM usage WHERE home = ?", &params![home])?;
    db.execute("UPDATE billing SET detached = 1 WHERE home = ?", &params![home])?;
    db.execute("DELETE FROM slack_installs WHERE home = ?", &params![home])?;
    // Whatever the deleted workspace still had under way (an Add to Slack) names an older value,
    // so it's refused, also once someone sets up a workspace at this address again.
    bump_generation(db, home)?;
    Ok(())
}

/// Claims `to` for an active workspace and makes it the current address. `home` is the
/// workspace's first address. Moving back to an address the workspace already holds always works.
pub fn move_address(db: &dyn Db, home: &str, to: &str, now: DateTime<Utc>) -> ApiResult<()> {
    validate_slug(to).map_err(ApiError::bad_request)?;
    let Some(row) = db.one("SELECT status FROM workspaces WHERE slug = ?", &params![home])? else {
        return Err(ApiError::not_found(format!("workspace `{home}`")));
    };
    if row.str("status") != "active" {
        return Err(ApiError::forbidden("this workspace can't change its address"));
    }
    let taken = || ApiError::conflict(format!("{to} is taken; pick another address"));
    let owner = db.one("SELECT home FROM addresses WHERE slug = ?", &params![to])?.map(|r| r.str("home"));
    match owner {
        Some(h) if h != home => return Err(taken()),
        Some(_) => {}
        None if to == home => {}
        None => {
            // Any reservation blocks a move, even a lapsed one, so a move never races a sign-up
            // that is finishing setup.
            if db.one("SELECT slug FROM workspaces WHERE slug = ?", &params![to])?.is_some() {
                return Err(taken());
            }
            let held = db.query("SELECT slug FROM addresses WHERE home = ? ORDER BY created_at", &params![home])?;
            if held.len() as i64 + 1 >= MAX_ADDRESSES {
                let names: Vec<String> = std::iter::once(home.to_string()).chain(held.iter().map(|r| r.str("slug"))).collect();
                return Err(ApiError::conflict(format!(
                    "this workspace has used {MAX_ADDRESSES} addresses, the most allowed; move back to one of them: {}",
                    names.join(", ")
                )));
            }
            db.execute("INSERT INTO addresses (slug, home, created_at) VALUES (?, ?, ?)", &params![to, home, ts(now)])?;
        }
    }
    db.execute("UPDATE addresses SET current = CASE WHEN slug = ? THEN 1 ELSE 0 END WHERE home = ?", &params![to, home])?;
    Ok(())
}

/// Finds the workspace that holds an address: its first address and every address it moved to.
pub fn resolve(db: &dyn Db, slug: &str) -> ApiResult<Option<(String, Vec<String>)>> {
    let home = if db.one("SELECT slug FROM workspaces WHERE slug = ?", &params![slug])?.is_some() {
        slug.to_string()
    } else {
        match db.one("SELECT home FROM addresses WHERE slug = ?", &params![slug])? {
            Some(r) => r.str("home"),
            None => return Ok(None),
        }
    };
    let moved = db.query("SELECT slug FROM addresses WHERE home = ? ORDER BY created_at", &params![home.clone()])?;
    Ok(Some((home, moved.iter().map(|r| r.str("slug")).collect())))
}

// ---------------------------------------------------------------------------
// Slack workspaces (Add to Slack)

fn check_team(team_id: &str) -> ApiResult<()> {
    let ok = !team_id.is_empty() && team_id.len() <= 32 && team_id.chars().all(|c| c.is_ascii_alphanumeric());
    if ok { Ok(()) } else { Err(ApiError::bad_request("team_id must be a Slack workspace's ID, like T0123ABCD")) }
}

fn active_home(db: &dyn Db, home: &str) -> ApiResult<()> {
    match db.one("SELECT slug FROM workspaces WHERE slug = ? AND status = 'active'", &params![home])? {
        Some(_) => Ok(()),
        None => Err(ApiError::not_found(format!("workspace `{home}`"))),
    }
}

/// An installation of DumbSlab's own Slack app into one Slack workspace, as a workspace sends it
/// to the directory. The token is sealed; the directory never reads it.
#[derive(Debug, Clone, Default, Serialize, serde::Deserialize)]
pub struct SlackInstall {
    pub team_id: String,
    pub bot_token: String,
    pub token_fingerprint: String,
    pub bot_user_id: Option<String>,
    pub team_name: String,
    pub scopes: String,
}

/// The token a workspace may act on Slack with, as stored: sealed, its fingerprint, and the bot's
/// Slack user.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct SlackToken {
    pub bot_token: String,
    pub token_fingerprint: String,
    pub bot_user_id: Option<String>,
}

/// How long an installation is left alone before a workspace that doesn't name it may let go of it
/// as a leftover. Add to Slack finishes within one request, well under this.
pub const SLACK_LEFTOVER_SECS: i64 = 15 * 60;

fn changed() -> ApiError {
    ApiError::new(409, "slack_changed", "This workspace's Slack connection changed meanwhile. Try again.")
}

/// Where `home`'s Slack connection is: the value every change to it starts from.
fn slack_generation(db: &dyn Db, home: &str) -> ApiResult<i64> {
    Ok(db.one("SELECT generation FROM slack_homes WHERE home = ?", &params![home])?.map(|r| r.i64("generation")).unwrap_or(0))
}

/// Refuses a change that started from another value than `home`'s current one.
fn check_generation(db: &dyn Db, home: &str, generation: i64) -> ApiResult<()> {
    if slack_generation(db, home)? != generation {
        return Err(changed());
    }
    Ok(())
}

/// Moves `home`'s value on, after a change; the new value.
fn bump_generation(db: &dyn Db, home: &str) -> ApiResult<i64> {
    db.execute(
        "INSERT INTO slack_homes (home, generation) VALUES (?, 1) ON CONFLICT(home) DO UPDATE SET generation = slack_homes.generation + 1",
        &params![home],
    )?;
    slack_generation(db, home)
}

/// Records the installation for the workspace whose first address is `home`, if its connection is
/// still at `generation`, and moves that on; the new value. Refused with 409 `slack_changed` once `generation`
/// moved on, and 409 `slack_team_taken` while another workspace holds the Slack workspace. The same
/// workspace installing again replaces its own.
pub fn slack_install(db: &dyn Db, home: &str, install: &SlackInstall, generation: i64, now: DateTime<Utc>) -> ApiResult<i64> {
    check_team(&install.team_id)?;
    let sealed = |v: &str| !v.is_empty() && v.len() <= 2000;
    if !sealed(&install.bot_token) || !sealed(&install.token_fingerprint) {
        return Err(ApiError::bad_request("send the sealed bot token and its fingerprint"));
    }
    active_home(db, home)?;
    check_generation(db, home, generation)?;
    let holder = db.one("SELECT home FROM slack_installs WHERE team_id = ?", &params![install.team_id.clone()])?.map(|r| r.str("home"));
    if holder.is_some_and(|h| h != home) {
        return Err(ApiError::new(409, "slack_team_taken", "That Slack workspace is connected to another DumbSlab workspace."));
    }
    db.execute(
        "INSERT INTO slack_installs (team_id, home, bot_token, token_fingerprint, bot_user_id, team_name, scopes, installed_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(team_id) DO UPDATE SET home = excluded.home, bot_token = excluded.bot_token,
           token_fingerprint = excluded.token_fingerprint, bot_user_id = excluded.bot_user_id, team_name = excluded.team_name,
           scopes = excluded.scopes, installed_at = excluded.installed_at",
        &params![
            install.team_id.clone(),
            home,
            install.bot_token.clone(),
            install.token_fingerprint.clone(),
            install.bot_user_id.clone(),
            install.team_name.clone(),
            install.scopes.clone(),
            ts(now)
        ],
    )?;
    bump_generation(db, home)
}

/// Lets go of Slack workspaces `home` holds, if its connection is still at `generation` (409
/// `slack_changed` otherwise). `leftovers`: only those installed more than [`SLACK_LEFTOVER_SECS`]
/// ago. Moves `generation` on when it let go of any. How many it let go of, and the value now.
pub fn slack_release(
    db: &dyn Db,
    home: &str,
    team_ids: &[String],
    generation: i64,
    leftovers: bool,
    now: DateTime<Utc>,
) -> ApiResult<(usize, i64)> {
    for t in team_ids {
        check_team(t)?;
    }
    check_generation(db, home, generation)?;
    let before = ts(now - Duration::seconds(SLACK_LEFTOVER_SECS));
    let mut released = 0;
    for t in team_ids {
        released += match leftovers {
            true => db.execute(
                "DELETE FROM slack_installs WHERE team_id = ? AND home = ? AND installed_at < ?",
                &params![t.clone(), home, before.clone()],
            )?,
            false => db.execute("DELETE FROM slack_installs WHERE team_id = ? AND home = ?", &params![t.clone(), home])?,
        } as usize;
    }
    let generation = if released > 0 { bump_generation(db, home)? } else { generation };
    Ok((released, generation))
}

/// The token to act on a Slack workspace with, only for the workspace that holds it.
pub fn slack_token(db: &dyn Db, team_id: &str, home: &str) -> ApiResult<Option<SlackToken>> {
    check_team(team_id)?;
    Ok(db
        .one(
            "SELECT bot_token, token_fingerprint, bot_user_id FROM slack_installs WHERE team_id = ? AND home = ?",
            &params![team_id, home],
        )?
        .map(|r| SlackToken {
            bot_token: r.str("bot_token"),
            token_fingerprint: r.str("token_fingerprint"),
            bot_user_id: r.opt_str("bot_user_id"),
        }))
}

/// What the directory says about a workspace's Slack connection.
#[derive(Debug, Clone, Default, Serialize, serde::Deserialize, PartialEq)]
pub struct SlackStatus {
    /// `home` holds the Slack workspace it asked about.
    pub owned: bool,
    /// That Slack workspace's name, when it does.
    pub team_name: Option<String>,
    /// Other Slack workspaces `home` holds, installed more than [`SLACK_LEFTOVER_SECS`] ago: left
    /// over from a switch that didn't finish letting go of the previous one, or an install whose
    /// workspace never saved it. Newer ones may be an install still finishing.
    pub leftovers: Vec<String>,
    /// Where `home`'s connection is: the value its next change names.
    pub generation: i64,
}

/// Whether `home` holds `team_id` (none: just what else it holds), and its value.
pub fn slack_status(db: &dyn Db, team_id: Option<&str>, home: &str, now: DateTime<Utc>) -> ApiResult<SlackStatus> {
    if let Some(t) = team_id {
        check_team(t)?;
    }
    let before = ts(now - Duration::seconds(SLACK_LEFTOVER_SECS));
    let mut status = SlackStatus { generation: slack_generation(db, home)?, ..Default::default() };
    for r in db.query("SELECT team_id, team_name, installed_at FROM slack_installs WHERE home = ? ORDER BY team_id", &params![home])? {
        if Some(r.str("team_id").as_str()) == team_id {
            status.owned = true;
            status.team_name = Some(r.str("team_name"));
        } else if r.str("installed_at") < before {
            status.leftovers.push(r.str("team_id"));
        }
    }
    Ok(status)
}

/// Forgets a Slack workspace's installation once its token is known to be dead, only if the row
/// still holds that token (and, when `home` is given, belongs to it): an install made since, with
/// another token, stays. Moves the holder's value on. `false` when nothing was forgotten.
pub fn slack_forget_if(db: &dyn Db, team_id: &str, token_fingerprint: &str, home: Option<&str>) -> ApiResult<bool> {
    check_team(team_id)?;
    let Some(holder) = db
        .one("SELECT home FROM slack_installs WHERE team_id = ? AND token_fingerprint = ?", &params![team_id, token_fingerprint])?
        .map(|r| r.str("home"))
        .filter(|h| home.is_none_or(|asked| asked == h))
    else {
        return Ok(false);
    };
    db.execute("DELETE FROM slack_installs WHERE team_id = ? AND token_fingerprint = ?", &params![team_id, token_fingerprint])?;
    bump_generation(db, &holder)?;
    Ok(true)
}

/// The root domain's own look at an installation (whoever holds it): its sealed token, to check
/// with Slack when Slack says the app was removed.
pub fn slack_row(db: &dyn Db, team_id: &str) -> ApiResult<Option<SlackToken>> {
    check_team(team_id)?;
    Ok(db.one("SELECT bot_token, token_fingerprint, bot_user_id FROM slack_installs WHERE team_id = ?", &params![team_id])?.map(|r| {
        SlackToken { bot_token: r.str("bot_token"), token_fingerprint: r.str("token_fingerprint"), bot_user_id: r.opt_str("bot_user_id") }
    }))
}

/// The workspace that holds a Slack workspace: its first address (which names its storage) and
/// the address it lives at now.
pub fn slack_team_home(db: &dyn Db, team_id: &str) -> ApiResult<Option<(String, String)>> {
    let Some(row) = db.one("SELECT home FROM slack_installs WHERE team_id = ?", &params![team_id])? else {
        return Ok(None);
    };
    let home = row.str("home");
    let current = db.one("SELECT slug FROM addresses WHERE home = ? AND current = 1", &params![home.clone()])?.map(|r| r.str("slug"));
    Ok(Some((home.clone(), current.unwrap_or(home))))
}

// ---------------------------------------------------------------------------
// Usage and billing

/// Records a workspace's report: its plan (`free` or `pro`), rows written in the last 24 hours and size.
pub fn report_usage(db: &dyn Db, home: &str, plan: &str, writes_24h: u64, storage_bytes: u64, now: DateTime<Utc>) -> ApiResult<()> {
    if !matches!(plan, "free" | "pro") {
        return Err(ApiError::bad_request("plan must be free or pro"));
    }
    db.execute(
        "INSERT INTO usage (home, plan, writes_24h, storage_bytes, reported_at) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(home) DO UPDATE SET plan = excluded.plan, writes_24h = excluded.writes_24h,
           storage_bytes = excluded.storage_bytes, reported_at = excluded.reported_at",
        &params![home, plan, writes_24h as i64, storage_bytes as i64, ts(now)],
    )?;
    Ok(())
}

/// What all free workspaces used, by their latest reports: rows written in 24 hours (reports
/// older than a day don't count) and storage.
#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
pub struct FreeUsage {
    pub writes_24h: u64,
    pub storage_bytes: u64,
}

pub fn free_usage(db: &dyn Db, now: DateTime<Utc>) -> ApiResult<FreeUsage> {
    let day_ago = ts(now - Duration::days(1));
    let writes =
        db.scalar_i64("SELECT COALESCE(SUM(writes_24h), 0) FROM usage WHERE plan = 'free' AND reported_at > ?", &params![day_ago])?;
    let storage = db.scalar_i64("SELECT COALESCE(SUM(storage_bytes), 0) FROM usage WHERE plan = 'free'", &[])?;
    Ok(FreeUsage { writes_24h: writes.max(0) as u64, storage_bytes: storage.max(0) as u64 })
}

pub fn free_capacity(db: &dyn Db, now: DateTime<Utc>, budget: FreeBudget) -> ApiResult<Capacity> {
    let used = free_usage(db, now)?;
    Ok(Capacity { writes_paused: used.writes_24h >= budget.writes_per_day, growth_paused: used.storage_bytes >= budget.storage_bytes })
}

/// Checkout finished: `customer` pays for the workspace whose first address is `home`. A
/// customer whose workspace was deleted stays detached.
pub fn link_customer(db: &dyn Db, customer: &str, home: &str, now: DateTime<Utc>) -> ApiResult<()> {
    db.execute(
        "INSERT INTO billing (customer, home, updated_at) VALUES (?, ?, ?)
         ON CONFLICT(customer) DO UPDATE SET home = excluded.home, updated_at = excluded.updated_at WHERE billing.detached = 0",
        &params![customer, home, ts(now)],
    )?;
    Ok(())
}

/// Who a Stripe customer pays for, as far as the directory knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payer {
    Unknown,
    /// Pays for the workspace whose first address this is.
    Workspace(String),
    /// Paid for a workspace that was deleted.
    Detached,
}

pub fn customer_home(db: &dyn Db, customer: &str) -> ApiResult<Payer> {
    Ok(match db.one("SELECT home, detached FROM billing WHERE customer = ?", &params![customer])? {
        None => Payer::Unknown,
        Some(r) if r.i64("detached") != 0 => Payer::Detached,
        Some(r) => Payer::Workspace(r.str("home")),
    })
}

pub fn record_subscription(db: &dyn Db, customer: &str, subscription: &str, status: &str, now: DateTime<Utc>) -> ApiResult<()> {
    db.execute(
        "UPDATE billing SET subscription = ?, status = ?, updated_at = ? WHERE customer = ?",
        &params![subscription, status, ts(now), customer],
    )?;
    Ok(())
}

/// Notes a refund, dispute or fraud warning on the customer's record for the operator.
pub fn record_risk(db: &dyn Db, customer: &str, kind: &str, now: DateTime<Utc>) -> ApiResult<()> {
    db.execute(
        "UPDATE billing SET risk = ?, updated_at = ? WHERE customer = ?",
        &params![format!("{kind} {}", ts(now)), ts(now), customer],
    )?;
    Ok(())
}

/// Whether someone still pays for the workspace. Deleting it would keep charging them.
pub fn paying(db: &dyn Db, home: &str) -> ApiResult<bool> {
    let n = db.scalar_i64(
        "SELECT COUNT(*) FROM billing WHERE home = ? AND detached = 0 AND status IN ('active', 'trialing', 'past_due')",
        &params![home],
    )?;
    Ok(n > 0)
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct DirectoryEntry {
    /// The workspace's first address, which names its storage.
    pub slug: String,
    pub name: String,
    /// `reserved`, `active` or `disabled`.
    pub status: String,
    pub created_at: String,
    pub activated_at: Option<String>,
    /// Where the workspace lives now.
    pub address: String,
    /// Earlier addresses, which forward to `address` and stay reserved for this workspace.
    pub previous_addresses: Vec<String>,
    /// `free` or `pro`, from the workspace's latest usage report.
    pub plan: Option<String>,
    pub writes_24h: Option<i64>,
    pub storage_bytes: Option<i64>,
    pub reported_at: Option<String>,
    /// The Stripe subscription's status, when the workspace has paid.
    pub billing_status: Option<String>,
    /// The last refund, dispute or fraud warning on its payments.
    pub billing_risk: Option<String>,
}

pub fn list(db: &dyn Db) -> ApiResult<Vec<DirectoryEntry>> {
    let moved = db.query("SELECT slug, home, current FROM addresses ORDER BY created_at", &[])?;
    Ok(db
        .query(
            "SELECT w.slug, w.name, w.status, w.created_at, w.activated_at, u.plan, u.writes_24h, u.storage_bytes, u.reported_at,
                    (SELECT b.status FROM billing b WHERE b.home = w.slug AND b.detached = 0 ORDER BY b.updated_at DESC LIMIT 1) AS billing_status,
                    (SELECT b.risk FROM billing b WHERE b.home = w.slug AND b.detached = 0 AND b.risk IS NOT NULL ORDER BY b.updated_at DESC LIMIT 1) AS billing_risk
             FROM workspaces w LEFT JOIN usage u ON u.home = w.slug ORDER BY w.created_at DESC",
            &[],
        )?
        .iter()
        .map(|r| {
            let slug = r.str("slug");
            let mine: Vec<_> = moved.iter().filter(|m| m.str("home") == slug).collect();
            let address = mine.iter().find(|m| m.i64("current") == 1).map(|m| m.str("slug")).unwrap_or_else(|| slug.clone());
            let previous_addresses =
                std::iter::once(slug.clone()).chain(mine.iter().map(|m| m.str("slug"))).filter(|s| *s != address).collect();
            DirectoryEntry {
                slug,
                name: r.str("name"),
                status: r.str("status"),
                created_at: r.str("created_at"),
                activated_at: r.opt_str("activated_at"),
                address,
                previous_addresses,
                plan: r.opt_str("plan"),
                writes_24h: r.opt_i64("writes_24h"),
                storage_bytes: r.opt_i64("storage_bytes"),
                reported_at: r.opt_str("reported_at"),
                billing_status: r.opt_str("billing_status"),
                billing_risk: r.opt_str("billing_risk"),
            }
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Inside a hosted workspace

/// The address a workspace last moved to, if it ever moved. Before that it lives at its first address.
pub fn moved_to(db: &dyn Db) -> ApiResult<Option<String>> {
    crate::ops::admin::setting(db, "address")
}

/// Swaps the workspace address in an origin: `https://acme.dumbslab.com` → `https://docs.dumbslab.com`.
pub fn origin_for(origin: &str, from: &str, to: &str) -> String {
    origin.replacen(&format!("://{from}."), &format!("://{to}."), 1)
}

/// The answer for a request that reached a workspace through an address it moved away from.
/// Browsers opening a page are redirected; API and MCP clients get an error naming the new address.
pub fn moved_response(method: &str, accept: &str, new_origin: &str, path_and_query: &str, to: &str) -> Response {
    let location = format!("{new_origin}{path_and_query}");
    if matches!(method, "GET" | "HEAD") && accept.contains("text/html") {
        // Temporary, so browsers don't cache it: the workspace may move back.
        return Response::empty(307).with_header("location", location).with_header("cache-control", "no-store");
    }
    let err = ApiError::new(
        410,
        "workspace_moved",
        format!("This workspace moved to {new_origin}. Use that address from now on (the MCP server is {new_origin}/mcp); you may need to sign in again."),
    )
    .with_details(serde_json::json!({ "address": to, "url": new_origin }));
    Response::error(&err).with_header("location", location).with_header("cache-control", "no-store")
}

/// Records a move after the host claimed the new address in its directory. Returns the webhook
/// deliveries for the `workspace.address_changed` event.
pub fn finish_move(db: &dyn Db, cfg: &HostConfig, mv: &AddressMove, new_origin: &str) -> ApiResult<Vec<Effect>> {
    crate::ops::admin::put_setting(db, "address", &mv.to)?;
    let mut ctx = Ctx { db, actor: mv.actor.clone(), now: Utc::now(), cfg, base_url: new_origin.to_string(), effects: vec![] };
    let summary = format!("moved the workspace from {} to {}", mv.from, mv.to);
    emit(
        &mut ctx,
        Event::new("workspace.address_changed", "workspace", "address", summary).data(serde_json::json!({ "from": mv.from, "to": mv.to })),
    )?;
    Ok(ctx.effects)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs() {
        assert!(validate_slug("acme").is_ok());
        assert!(validate_slug("acme-docs-2").is_ok());
        assert!(validate_slug("ab").is_err());
        assert!(validate_slug("Acme").is_err());
        assert!(validate_slug("-acme").is_err());
        assert!(validate_slug("ac--me").is_err());
        assert!(validate_slug("www").is_err());
        assert!(validate_slug("a.b").is_err());
    }

    #[test]
    fn hosts() {
        assert_eq!(host_kind("dumbslab.com", "dumbslab.com"), HostKind::Root);
        assert_eq!(host_kind("Acme.DumbSlab.com", "dumbslab.com"), HostKind::Workspace("acme".into()));
        assert_eq!(host_kind("acme.localhost:8787", "localhost"), HostKind::Workspace("acme".into()));
        assert_eq!(host_kind("a.b.dumbslab.com", "dumbslab.com"), HostKind::Other);
        assert_eq!(host_kind("evil.com", "dumbslab.com"), HostKind::Other);
        assert_eq!(host_kind("xdumbslab.com", "dumbslab.com"), HostKind::Other);
    }

    #[test]
    fn plain_http_is_upgraded() {
        assert_eq!(https_upgrade("http://dumbslab.com/"), Some("https://dumbslab.com/".into()));
        assert_eq!(https_upgrade("http://Acme.dumbslab.com:80/setup?token=1"), Some("https://acme.dumbslab.com/setup?token=1".into()));
        assert_eq!(https_upgrade("http://dumbslab.com"), Some("https://dumbslab.com/".into()));
        assert_eq!(https_upgrade("https://dumbslab.com/"), None);
        for local in ["http://localhost:8787/", "http://acme.localhost:8787/x", "http://127.0.0.1:8787/", "http://[::1]:8787/"] {
            assert_eq!(https_upgrade(local), None, "{local}");
        }
        assert!(hsts(true).contains("includeSubDomains") && !hsts(false).contains("includeSubDomains"));
    }

    #[test]
    fn root_site_files_name_the_root_domain() {
        let robots = root_robots_txt("kb.test");
        assert!(robots.contains("Allow: /\n") && robots.contains("Disallow: /api/\n"), "{robots}");
        assert!(robots.ends_with("Sitemap: https://kb.test/sitemap.xml\n"), "{robots}");
        assert!(root_sitemap_xml("kb.test").contains("<loc>https://kb.test/</loc>"));
        let llms = root_llms_txt("kb.test");
        assert!(llms.starts_with("# DumbSlab\n\n> "), "llms.txt opens with a title and summary");
        for want in ["POST https://kb.test/api/signup", "https://<address>.kb.test/mcp", "{\"workspace_name\": \"Acme\""] {
            assert!(llms.contains(want), "missing {want}");
        }
    }

    #[test]
    fn signup_tokens() {
        let t = signup_token("s3cret", "acme", 2_000);
        assert!(verify_signup_token("s3cret", "acme", &t, 1_000));
        assert!(!verify_signup_token("s3cret", "acme", &t, 2_001), "expired");
        assert!(!verify_signup_token("s3cret", "other", &t, 1_000), "wrong workspace");
        assert!(!verify_signup_token("nope", "acme", &t, 1_000), "wrong secret");
        assert!(!verify_signup_token("s3cret", "acme", "9999999999.deadbeef", 1_000), "forged");
    }

    #[test]
    fn moved_addresses() {
        assert_eq!(origin_for("https://acme.dumbslab.com", "acme", "docs"), "https://docs.dumbslab.com");
        assert_eq!(origin_for("http://acme.localhost:8787", "acme", "acme-2"), "http://acme-2.localhost:8787");

        let page = moved_response("GET", "text/html,application/xhtml+xml", "https://docs.x.test", "/oauth/authorize?a=1", "docs");
        assert_eq!(page.status, 307);
        assert!(page.headers.contains(&("location".into(), "https://docs.x.test/oauth/authorize?a=1".into())));

        let api = moved_response("POST", "application/json", "https://docs.x.test", "/mcp", "docs");
        assert_eq!(api.status, 410);
        let body: serde_json::Value = serde_json::from_slice(&api.body).unwrap();
        assert_eq!(body["error"]["code"], "workspace_moved");
        assert_eq!(body["error"]["details"]["url"], "https://docs.x.test");
    }
}
