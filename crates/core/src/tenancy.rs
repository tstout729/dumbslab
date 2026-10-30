//! Multi-tenant hosting: workspace addresses, signed sign-up links and the directory of
//! workspaces. The Cloudflare deployment gives every workspace its own subdomain and Durable
//! Object; the native server stays single-workspace and doesn't use this module.

use chrono::{DateTime, Duration, Utc};
use schemars::JsonSchema;
use serde::Serialize;

use crate::db::{Db, DbExt};
use crate::error::{ApiError, ApiResult};
use crate::events::{Event, emit};
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
}

/// Reserves an address for a new workspace. Returns the reservation's expiry.
pub fn reserve(db: &dyn Db, slug: &str, name: &str, ip_hash: &str, now: DateTime<Utc>, limits: Limits) -> ApiResult<DateTime<Utc>> {
    validate_slug(slug).map_err(ApiError::bad_request)?;
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 80 {
        return Err(ApiError::bad_request("the workspace name must be 1 to 80 characters"));
    }
    let now_s = ts(now);
    if let Some(row) = db.one("SELECT status, reserved_until FROM workspaces WHERE slug = ?", &params![slug])?
        && (row.str("status") != "reserved" || row.str("reserved_until") > now_s)
    {
        return Err(ApiError::conflict(format!("{slug} is taken; pick another address")));
    }
    if db.one("SELECT home FROM addresses WHERE slug = ?", &params![slug])?.is_some() {
        return Err(ApiError::conflict(format!("{slug} is taken; pick another address")));
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

/// Removes a workspace (by its first address) and every address it moved to.
pub fn remove(db: &dyn Db, home: &str) -> ApiResult<()> {
    db.execute("DELETE FROM workspaces WHERE slug = ?", &params![home])?;
    db.execute("DELETE FROM addresses WHERE home = ?", &params![home])?;
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
}

pub fn list(db: &dyn Db) -> ApiResult<Vec<DirectoryEntry>> {
    let moved = db.query("SELECT slug, home, current FROM addresses ORDER BY created_at", &[])?;
    Ok(db
        .query("SELECT slug, name, status, created_at, activated_at FROM workspaces ORDER BY created_at DESC", &[])?
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
