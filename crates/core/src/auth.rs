//! Who is calling: sessions (browser), API tokens (agents, scripts) and OAuth tokens (MCP clients).

use std::sync::OnceLock;

use argon2::{Argon2, PasswordHasher, PasswordVerifier, password_hash::phc::PasswordHash};
use chrono::{DateTime, Duration, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::db::{Db, DbExt};
use crate::error::{ApiError, ApiResult};
use crate::util::{parse_ts, sha256_hex, ts};
use crate::{HostConfig, Request, params};

pub const SESSION_COOKIE: &str = "dumbslab_session";
pub const SESSION_DAYS: i64 = 30;
/// Browser sessions kept per person. Signing in again past this ends the oldest one, so repeated
/// sign-ins (which work even in a full workspace) can't grow storage.
pub const MAX_SESSIONS: i64 = 50;
/// Browsers must send this header on cookie-authenticated writes (CSRF protection).
pub const CSRF_HEADER: &str = "x-dumbslab-client";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Viewer,
    Member,
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Member => "member",
            Role::Admin => "admin",
        }
    }

    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "viewer" => Some(Role::Viewer),
            "member" => Some(Role::Member),
            "admin" => Some(Role::Admin),
            _ => None,
        }
    }
}

/// How the actor reached us. Recorded in the activity log.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Via {
    Web,
    Api,
    Mcp,
    Cli,
}

impl Via {
    pub fn as_str(self) -> &'static str {
        match self {
            Via::Web => "web",
            Via::Api => "api",
            Via::Mcp => "mcp",
            Via::Cli => "cli",
        }
    }
}

/// What a credential may do. Scopes limit actions; visibility always follows the user's role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scopes {
    pub read: bool,
    pub write: bool,
    pub admin: bool,
}

impl Scopes {
    pub const ALL: Scopes = Scopes { read: true, write: true, admin: true };

    /// Parses `"read write"` or `"read,write"`. Unknown words are errors.
    pub fn parse(s: &str) -> ApiResult<Scopes> {
        let mut out = Scopes { read: false, write: false, admin: false };
        for word in s.split([' ', ',']).filter(|w| !w.is_empty()) {
            match word {
                "read" => out.read = true,
                "write" => out.write = true,
                "admin" => out.admin = true,
                other => return Err(ApiError::bad_request(format!("unknown scope `{other}` (use read, write, admin)"))),
            }
        }
        // Higher scopes imply lower ones.
        if out.admin {
            out.write = true;
        }
        if out.write {
            out.read = true;
        }
        Ok(out)
    }

    pub fn to_list(self) -> Vec<String> {
        let mut v = vec![];
        if self.read {
            v.push("read".to_string());
        }
        if self.write {
            v.push("write".to_string());
        }
        if self.admin {
            v.push("admin".to_string());
        }
        v
    }

    pub fn to_str(self) -> String {
        self.to_list().join(" ")
    }

    /// The scopes a role can actually use.
    pub fn for_role(role: Role) -> Scopes {
        Scopes { read: true, write: true, admin: role == Role::Admin }
    }

    pub fn intersect(self, other: Scopes) -> Scopes {
        Scopes { read: self.read && other.read, write: self.write && other.write, admin: self.admin && other.admin }
    }
}

#[derive(Clone, Debug)]
pub struct Actor {
    pub user_id: String,
    pub name: String,
    pub handle: String,
    pub email: String,
    pub role: Role,
    pub scopes: Scopes,
    pub via: Via,
    pub token_id: Option<String>,
    pub session_hash: Option<String>,
}

impl Actor {
    /// Admins can see everything, including private topics and other people's drafts.
    pub fn sees_all(&self) -> bool {
        self.role == Role::Admin
    }

    pub fn can_admin(&self) -> bool {
        self.role == Role::Admin && self.scopes.admin
    }

    pub fn require_role(&self, min: Role) -> ApiResult<()> {
        if self.role >= min {
            Ok(())
        } else {
            Err(ApiError::forbidden(format!("this needs the {} role or higher; you are a {}", min.as_str(), self.role.as_str())))
        }
    }

    pub fn require_admin(&self) -> ApiResult<()> {
        self.require_role(Role::Admin)?;
        if !self.scopes.admin {
            return Err(ApiError::forbidden("this credential lacks the admin scope"));
        }
        Ok(())
    }
}

pub fn hash_password(password: &str) -> ApiResult<String> {
    validate_password(password)?;
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| ApiError::internal(format!("password hashing failed: {e}")))
}

pub fn validate_password(password: &str) -> ApiResult<()> {
    if password.chars().count() < 8 {
        return Err(ApiError::bad_request("password must be at least 8 characters"));
    }
    if password.len() > 256 {
        return Err(ApiError::bad_request("password is too long"));
    }
    Ok(())
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok(),
        Err(_) => false,
    }
}

/// Spends the same time as a real check so unknown emails can't be detected by timing.
pub fn dummy_verify(password: &str) {
    static DUMMY: OnceLock<String> = OnceLock::new();
    let hash = DUMMY.get_or_init(|| Argon2::default().hash_password(b"dumbslab-dummy-password").map(|h| h.to_string()).unwrap_or_default());
    let _ = verify_password(password, hash);
}

fn cookie_value<'a>(req: &'a Request, name: &str) -> Option<&'a str> {
    let header = req.header("cookie")?;
    header.split(';').map(str::trim).find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == name).then_some(v)
    })
}

pub fn bearer_token(req: &Request) -> Option<&str> {
    let h = req.header("authorization")?;
    let (scheme, token) = h.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
}

const USER_COLS: &str = "u.id, u.name, u.handle, u.email, u.role";

fn actor_from_row(row: &crate::db::Row, scopes: Scopes, via: Via) -> Actor {
    let role = Role::parse(&row.str("role")).unwrap_or(Role::Viewer);
    Actor {
        user_id: row.str("id"),
        name: row.str("name"),
        handle: row.str("handle"),
        email: row.str("email"),
        role,
        scopes: scopes.intersect(Scopes::for_role(role)),
        via,
        token_id: None,
        session_hash: None,
    }
}

/// Resolves the caller from a bearer token or session cookie. `Ok(None)` means anonymous.
pub fn authenticate(db: &dyn Db, cfg: &HostConfig, req: &Request, now: DateTime<Utc>) -> ApiResult<Option<Actor>> {
    let now_s = ts(now);
    if let Some(token) = bearer_token(req) {
        let row = db
            .one(
                &format!(
                    "SELECT {USER_COLS}, t.id AS token_id, t.scopes, t.last_used_at, t.resource FROM api_tokens t
                     JOIN users u ON u.id = t.user_id
                     WHERE t.token_hash = ? AND t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at > ?)
                       AND u.deactivated_at IS NULL"
                ),
                &params![sha256_hex(token), now_s.clone()],
            )?
            .ok_or_else(|| ApiError::unauthorized("invalid, expired or revoked token"))?;
        // A connected app's token works only at the address it was issued for.
        if let Some(resource) = row.opt_str("resource")
            && crate::oauth::canonical_resource(&crate::http::base_url(cfg, req), Some(&resource)).is_none()
        {
            return Err(ApiError::unauthorized("this token was issued for a different address; connect the app again"));
        }
        let scopes = Scopes::parse(&row.str("scopes")).unwrap_or(Scopes { read: true, write: false, admin: false });
        let mut actor = actor_from_row(&row, scopes, Via::Api);
        actor.token_id = Some(row.str("token_id"));
        // Touch at most once a minute to keep reads cheap.
        let stale = row.opt_str("last_used_at").and_then(|s| parse_ts(&s)).is_none_or(|t| now - t > Duration::minutes(1));
        if stale {
            db.execute("UPDATE api_tokens SET last_used_at = ? WHERE id = ?", &params![now_s.clone(), row.str("token_id")])?;
            db.execute("UPDATE users SET last_seen_at = ? WHERE id = ?", &params![now_s, actor.user_id.clone()])?;
        }
        return Ok(Some(actor));
    }
    if let Some(session) = cookie_value(req, SESSION_COOKIE) {
        let hash = sha256_hex(session);
        let row = db.one(
            &format!(
                "SELECT {USER_COLS} FROM sessions s JOIN users u ON u.id = s.user_id
                 WHERE s.token_hash = ? AND s.expires_at > ? AND u.deactivated_at IS NULL"
            ),
            &params![hash.clone(), now_s],
        )?;
        if let Some(row) = row {
            let mut actor = actor_from_row(&row, Scopes::ALL, Via::Web);
            actor.session_hash = Some(hash);
            return Ok(Some(actor));
        }
    }
    Ok(None)
}

/// Creates a session and returns the raw token for the cookie.
pub fn create_session(db: &dyn Db, user_id: &str, user_agent: Option<&str>, now: DateTime<Utc>) -> ApiResult<String> {
    let token = crate::util::new_secret("");
    let hash = sha256_hex(&token);
    db.execute(
        "INSERT INTO sessions (token_hash, user_id, created_at, expires_at, user_agent) VALUES (?, ?, ?, ?, ?)",
        &params![
            hash.clone(),
            user_id,
            ts(now),
            ts(now + Duration::days(SESSION_DAYS)),
            user_agent.map(|s| s.chars().take(200).collect::<String>())
        ],
    )?;
    db.execute("DELETE FROM sessions WHERE expires_at < ?", &params![ts(now)])?;
    db.execute(
        "DELETE FROM sessions WHERE user_id = ? AND token_hash != ? AND token_hash NOT IN
           (SELECT token_hash FROM sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT ?)",
        &params![user_id, hash, user_id, MAX_SESSIONS],
    )?;
    Ok(token)
}

pub fn session_cookie(token: &str, secure: bool) -> String {
    format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}{}",
        SESSION_DAYS * 86400,
        if secure { "; Secure" } else { "" }
    )
}

pub fn clear_session_cookie(secure: bool) -> String {
    format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{}", if secure { "; Secure" } else { "" })
}

/// A per-session CSRF token for server-rendered forms (OAuth consent).
pub fn form_csrf(session_hash: &str) -> String {
    sha256_hex(&format!("csrf:{session_hash}"))
}

const WINDOW_MINUTES: i64 = 15;
/// Failed password checks allowed per window: for one account, from one client address, and in
/// the whole workspace. The last bounds password hashing (and these records) however many
/// emails or addresses someone rotates through.
const MAX_FAILURES: i64 = 10;
const MAX_CLIENT_FAILURES: i64 = 30;
const MAX_WORKSPACE_FAILURES: i64 = 200;

/// The throttle keys a password check counts against, with each one's limit. `client_ip` is the
/// caller's address when the host can vouch for it.
pub fn password_keys(email: &str, client_ip: Option<&str>) -> Vec<(String, i64)> {
    let mut keys = vec![(format!("login:{}", sha256_hex(&email.trim().to_lowercase())), MAX_FAILURES)];
    if let Some(ip) = client_ip {
        keys.push((format!("ip:{}", sha256_hex(ip)), MAX_CLIENT_FAILURES));
    }
    keys.push(("workspace".into(), MAX_WORKSPACE_FAILURES));
    keys
}

/// Rejects a password check, before any hashing, when one of its keys failed too often recently.
pub fn check_throttle(db: &dyn Db, keys: &[(String, i64)], now: DateTime<Utc>) -> ApiResult<()> {
    for (key, limit) in keys {
        if let Some(row) = db.one("SELECT failures, window_start FROM login_attempts WHERE key = ?", &params![key.clone()])? {
            let start = parse_ts(&row.str("window_start")).unwrap_or(now);
            if now - start < Duration::minutes(WINDOW_MINUTES) && row.i64("failures") >= *limit {
                return Err(ApiError::too_many("too many failed attempts; try again in 15 minutes"));
            }
        }
    }
    Ok(())
}

pub fn record_failures(db: &dyn Db, keys: &[(String, i64)], now: DateTime<Utc>) -> ApiResult<()> {
    for (key, _) in keys {
        record_failure(db, key, now)?;
    }
    Ok(())
}

fn record_failure(db: &dyn Db, key: &str, now: DateTime<Utc>) -> ApiResult<()> {
    let window_floor = ts(now - Duration::minutes(WINDOW_MINUTES));
    // Anyone can fail a login with any email, so forget windows that have closed.
    db.execute("DELETE FROM login_attempts WHERE window_start < ?", &params![window_floor.clone()])?;
    db.execute(
        "INSERT INTO login_attempts (key, failures, window_start) VALUES (?, 1, ?)
         ON CONFLICT(key) DO UPDATE SET
           failures = CASE WHEN window_start < ? THEN 1 ELSE failures + 1 END,
           window_start = CASE WHEN window_start < ? THEN excluded.window_start ELSE window_start END",
        &params![key, ts(now), window_floor.clone(), window_floor],
    )?;
    Ok(())
}

pub fn clear_failures(db: &dyn Db, key: &str) -> ApiResult<()> {
    db.execute("DELETE FROM login_attempts WHERE key = ?", &params![key])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_imply_lower_scopes() {
        let s = Scopes::parse("admin").unwrap();
        assert!(s.read && s.write && s.admin);
        let s = Scopes::parse("read").unwrap();
        assert!(s.read && !s.write && !s.admin);
        assert!(Scopes::parse("root").is_err());
    }

    #[test]
    fn roles_are_ordered() {
        assert!(Role::Admin > Role::Member && Role::Member > Role::Viewer);
    }

    #[test]
    fn passwords_round_trip() {
        let h = hash_password("correct horse").unwrap();
        assert!(verify_password("correct horse", &h));
        assert!(!verify_password("wrong horse!", &h));
        assert!(hash_password("short").is_err());
    }
}
