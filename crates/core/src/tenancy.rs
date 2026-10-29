//! Multi-tenant hosting: workspace addresses, signed sign-up links and the directory of
//! workspaces. The Cloudflare deployment gives every workspace its own subdomain and Durable
//! Object; the native server stays single-workspace and doesn't use this module.

use chrono::{DateTime, Duration, Utc};
use schemars::JsonSchema;
use serde::Serialize;

use crate::db::{Db, DbExt};
use crate::error::{ApiError, ApiResult};
use crate::params;
use crate::util::{hmac_sha256_hex, secure_eq, ts};

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
";

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
    let until = now + Duration::minutes(RESERVATION_MINUTES);
    db.execute(
        "INSERT INTO workspaces (slug, name, status, ip_hash, created_at, reserved_until) VALUES (?, ?, 'reserved', ?, ?, ?)
         ON CONFLICT(slug) DO UPDATE SET name = excluded.name, status = 'reserved', ip_hash = excluded.ip_hash,
           created_at = excluded.created_at, reserved_until = excluded.reserved_until, activated_at = NULL",
        &params![slug, name, ip_hash, now_s, ts(until)],
    )?;
    Ok(until)
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
    if !matches!(status, "active" | "disabled") {
        return Err(ApiError::bad_request("status must be active or disabled"));
    }
    let n = db.execute("UPDATE workspaces SET status = ? WHERE slug = ?", &params![status, slug])?;
    if n == 0 {
        return Err(ApiError::not_found(format!("workspace `{slug}`")));
    }
    Ok(())
}

pub fn remove(db: &dyn Db, slug: &str) -> ApiResult<()> {
    db.execute("DELETE FROM workspaces WHERE slug = ?", &params![slug])?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct DirectoryEntry {
    pub slug: String,
    pub name: String,
    /// `reserved`, `active` or `disabled`.
    pub status: String,
    pub created_at: String,
    pub activated_at: Option<String>,
}

pub fn list(db: &dyn Db) -> ApiResult<Vec<DirectoryEntry>> {
    Ok(db
        .query("SELECT slug, name, status, created_at, activated_at FROM workspaces ORDER BY created_at DESC", &[])?
        .iter()
        .map(|r| DirectoryEntry {
            slug: r.str("slug"),
            name: r.str("name"),
            status: r.str("status"),
            created_at: r.str("created_at"),
            activated_at: r.opt_str("activated_at"),
        })
        .collect())
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
    fn signup_tokens() {
        let t = signup_token("s3cret", "acme", 2_000);
        assert!(verify_signup_token("s3cret", "acme", &t, 1_000));
        assert!(!verify_signup_token("s3cret", "acme", &t, 2_001), "expired");
        assert!(!verify_signup_token("s3cret", "other", &t, 1_000), "wrong workspace");
        assert!(!verify_signup_token("nope", "acme", &t, 1_000), "wrong secret");
        assert!(!verify_signup_token("s3cret", "acme", "9999999999.deadbeef", 1_000), "forged");
    }
}
