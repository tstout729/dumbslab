use chrono::Duration;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{DONE, Done, NoInput, clean, required};
use crate::auth::{self, Role, Scopes, Via};
use crate::db::{DbExt, Row, SqlValue};
use crate::error::{ApiError, ApiResult};
use crate::events::{Event, emit};
use crate::model::*;
use crate::ops::posts::PostList;
use crate::params;
use crate::registry::{Access, Ctx, Op, op};
use crate::util::{is_valid_email, new_id, new_secret, normalize_handle, sha256_hex, ts};

pub fn ops() -> Vec<Op> {
    vec![
        op("users", "whoami", "GET", "/me", Access::Read, whoami)
            .title("Who am I")
            .desc("Your user, role, the scopes of the credential in use, and the workspace name. A good first call for an agent.")
            .build(),
        op("users", "list_users", "GET", "/users", Access::Read, list_users).title("List people").build(),
        op("users", "get_user", "GET", "/users/{user}", Access::Read, get_user)
            .title("Get a person")
            .desc("A person's profile and recent posts. `user` is an id, @handle, email or `me`.")
            .build(),
        op("users", "create_user", "POST", "/users", Access::Admin, create_user)
            .title("Add a person or bot")
            .desc("Admins add people or bot accounts. Without `password`, a temporary one is generated and returned once. Bots are agent identities: create one, then mint it a token with create_api_token.")
            .build(),
        op("users", "update_user", "PATCH", "/users/{user}", Access::Write, update_user)
            .title("Update a profile")
            .desc("Update your own name, handle, bio or avatar. Admins can also change roles, deactivate accounts and set passwords.")
            .build(),
        op("users", "change_password", "POST", "/me/password", Access::Write, change_password)
            .title("Change your password")
            .desc("Changes your password and signs out your other browser sessions. Only from a signed-in browser or the local CLI, never with a token.")
            .build(),
        op("users", "list_api_tokens", "GET", "/tokens", Access::Read, list_tokens)
            .title("List API tokens")
            .desc("Your API tokens (admins can pass `user`). Token secrets are never shown again after creation.")
            .build(),
        op("users", "create_api_token", "POST", "/tokens", Access::Write, create_token)
            .title("Create an API token")
            .desc("Mint a personal access token for scripts and agents. Scopes: `read`, `write`, `admin` (admins only). Admins can mint tokens for bot accounts with `user`. The secret is returned once.")
            .build(),
        op("users", "revoke_api_token", "DELETE", "/tokens/{id}", Access::Write, revoke_token)
            .title("Revoke an API token")
            .desc("Revoke one of your tokens (admins: anyone's). A connected app can only disconnect itself unless it was granted the admin scope.")
            .destructive()
            .build(),
    ]
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Me {
    pub user: User,
    /// Scopes of the credential in use.
    pub scopes: Vec<String>,
    /// `web`, `api`, `mcp` or `cli`.
    pub via: String,
    pub token_id: Option<String>,
    pub workspace_name: String,
    pub can_edit: bool,
    pub can_admin: bool,
}

fn whoami(ctx: &mut Ctx, _: NoInput) -> ApiResult<Me> {
    let row = find_user(ctx, "me")?;
    Ok(Me {
        user: User::from_row(&row),
        scopes: ctx.actor.scopes.to_list(),
        via: ctx.actor.via.as_str().into(),
        token_id: ctx.actor.token_id.clone(),
        workspace_name: crate::ops::admin::setting(ctx.db, "workspace_name")?.unwrap_or_else(|| "DumbSlab".into()),
        can_edit: ctx.actor.role >= Role::Member && ctx.actor.scopes.write,
        can_admin: ctx.actor.can_admin(),
    })
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListUsersInput {
    /// Matches name, handle or email.
    pub q: Option<String>,
    /// `admin`, `member` or `viewer`.
    pub role: Option<String>,
    pub include_deactivated: Option<bool>,
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct UserList {
    pub items: Vec<User>,
    pub next_cursor: Option<String>,
}

fn list_users(ctx: &mut Ctx, input: ListUsersInput) -> ApiResult<UserList> {
    let (limit, offset) = page(input.limit.or(Some(100)), &input.cursor)?;
    let mut cond = vec!["1=1".to_string()];
    let mut p: Vec<SqlValue> = vec![];
    if !input.include_deactivated.unwrap_or(false) {
        cond.push("deactivated_at IS NULL".into());
    }
    if let Some(role) = clean(input.role) {
        cond.push("role = ?".into());
        p.push(role.into());
    }
    if let Some(q) = clean(input.q) {
        let like = format!("%{}%", q.trim_start_matches('@').replace('%', "").replace('_', "\\_"));
        cond.push("(name LIKE ? ESCAPE '\\' OR handle LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\')".into());
        p.extend([like.clone().into(), like.clone().into(), like.into()]);
    }
    p.push((limit + 1).into());
    p.push(offset.into());
    let mut rows = ctx
        .db
        .query(&format!("SELECT {USER_COLS} FROM users WHERE {} ORDER BY name COLLATE NOCASE LIMIT ? OFFSET ?", cond.join(" AND ")), &p)?;
    let next_cursor = next_cursor(rows.len(), limit, offset);
    rows.truncate(limit as usize);
    Ok(UserList { items: rows.iter().map(User::from_row).collect(), next_cursor })
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UserKeyInput {
    /// User id, @handle, email or `me`.
    pub user: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct UserProfile {
    pub user: User,
    /// Job details from the people sync (BambooHR). Empty strings when unknown.
    pub details: Details,
    /// The person's manager, when the people sync found them in the workspace too.
    pub manager: Option<UserRef>,
    pub recent_posts: PostList,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct Details {
    /// Job title.
    pub title: String,
    pub department: String,
    /// Office or location.
    pub location: String,
    /// Work phone.
    pub phone: String,
    pub pronouns: String,
}

fn get_user(ctx: &mut Ctx, input: UserKeyInput) -> ApiResult<UserProfile> {
    let row = find_user(ctx, &input.user)?;
    let mut p = params![row.str("id")];
    let vis = post_visible_sql(&ctx.actor, "p", &mut p);
    let rows = ctx.db.query(
        &format!(
            "SELECT {POST_COLS} FROM posts p WHERE p.author_id = ? AND p.status = 'published' AND p.deleted_at IS NULL AND {vis}
             ORDER BY p.updated_at DESC LIMIT 10"
        ),
        &p,
    )?;
    let synced = ctx.db.one("SELECT * FROM user_profiles WHERE user_id = ?", &params![row.str("id")])?;
    let details = synced
        .as_ref()
        .map(|d| Details {
            title: d.str("title"),
            department: d.str("department"),
            location: d.str("location"),
            phone: d.str("phone"),
            pronouns: d.str("pronouns"),
        })
        .unwrap_or_default();
    let manager = match synced.and_then(|d| d.opt_str("manager_id")) {
        Some(m) => user_refs(ctx.db, std::slice::from_ref(&m))?.remove(&m),
        None => None,
    };
    let recent_posts = PostList { items: summaries(ctx, &rows)?, next_cursor: None };
    Ok(UserProfile { user: User::from_row(&row), details, manager, recent_posts })
}

fn unique_handle(ctx: &Ctx, wanted: &str, exclude_user: Option<&str>) -> ApiResult<String> {
    let base = normalize_handle(wanted);
    let base = if base.is_empty() { "user".to_string() } else { base };
    for n in 0..1000 {
        let candidate = if n == 0 { base.clone() } else { format!("{base}{n}") };
        let taken = ctx.db.one("SELECT id FROM users WHERE handle = ?", &params![candidate.clone()])?;
        match taken {
            None => return Ok(candidate),
            Some(r) if Some(r.str("id").as_str()) == exclude_user => return Ok(candidate),
            _ => {}
        }
    }
    Err(ApiError::conflict("could not find a free handle"))
}

/// Inserts a user. Shared with first-run setup.
pub fn insert_user(
    ctx: &Ctx,
    email: &str,
    name: &str,
    handle: Option<&str>,
    role: Role,
    password_hash: Option<String>,
    is_bot: bool,
) -> ApiResult<String> {
    if !is_valid_email(email) {
        return Err(ApiError::bad_request("a valid email is required"));
    }
    if ctx.db.one("SELECT id FROM users WHERE email = ?", &params![email.trim()])?.is_some() {
        return Err(ApiError::conflict(format!("someone with email {email} already exists")));
    }
    let name = required(name, "name", 120)?;
    let handle = match handle {
        Some(h) => {
            let h = normalize_handle(h);
            if h.is_empty() {
                return Err(ApiError::bad_request("handle must contain letters or digits"));
            }
            if ctx.db.one("SELECT id FROM users WHERE handle = ?", &params![h.clone()])?.is_some() {
                return Err(ApiError::conflict(format!("@{h} is taken")));
            }
            h
        }
        None => unique_handle(ctx, email.split('@').next().unwrap_or(&name), None)?,
    };
    let id = new_id();
    let now = ctx.now_s();
    ctx.db.execute(
        "INSERT INTO users (id, email, handle, name, role, password_hash, is_bot, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        &params![id.clone(), email.trim(), handle, name, role.as_str(), password_hash, is_bot, now.clone(), now],
    )?;
    Ok(id)
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateUserInput {
    pub email: String,
    pub name: String,
    /// Defaults to the part of the email before `@`.
    pub handle: Option<String>,
    /// `admin`, `member` (default) or `viewer`.
    pub role: Option<Role>,
    /// At least 8 characters. Omit to generate a temporary password.
    pub password: Option<String>,
    /// An agent or integration account (cannot sign in with a password unless one is set).
    pub is_bot: Option<bool>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct CreatedUser {
    pub user: User,
    /// Returned once when no password was supplied (people only).
    pub temporary_password: Option<String>,
}

fn create_user(ctx: &mut Ctx, input: CreateUserInput) -> ApiResult<CreatedUser> {
    let is_bot = input.is_bot.unwrap_or(false);
    let (hash, temporary_password) = match clean(input.password) {
        Some(pw) => (Some(auth::hash_password(&pw)?), None),
        None if is_bot => (None, None),
        None => {
            let pw = new_secret("").chars().take(16).collect::<String>();
            (Some(auth::hash_password(&pw)?), Some(pw))
        }
    };
    let role = input.role.unwrap_or(Role::Member);
    let id = insert_user(ctx, &input.email, &input.name, input.handle.as_deref(), role, hash, is_bot)?;
    let row = find_user(ctx, &id)?;
    emit(
        ctx,
        Event::new("user.created", "user", &id, format!("added {} ({})", row.str("name"), role.as_str()))
            .data(json!({ "role": role.as_str(), "is_bot": is_bot }))
            .admin_only(),
    )?;
    Ok(CreatedUser { user: User::from_row(&row), temporary_password })
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateUserInput {
    /// User id, @handle, email or `me`.
    pub user: String,
    pub name: Option<String>,
    pub handle: Option<String>,
    pub bio: Option<String>,
    pub avatar_url: Option<String>,
    /// Admins only.
    pub role: Option<Role>,
    /// Admins only. Deactivated people can't sign in and their tokens stop working.
    pub deactivated: Option<bool>,
    /// Admins only: set a new password for this person.
    pub new_password: Option<String>,
}

fn active_admins(ctx: &Ctx) -> ApiResult<i64> {
    ctx.db.scalar_i64("SELECT COUNT(*) FROM users WHERE role = 'admin' AND deactivated_at IS NULL", &[])
}

fn update_user(ctx: &mut Ctx, input: UpdateUserInput) -> ApiResult<User> {
    let row = find_user(ctx, &input.user)?;
    let id = row.str("id");
    let is_self = id == ctx.actor.user_id;
    let admin_fields = input.role.is_some() || input.deactivated.is_some() || input.new_password.is_some();
    if admin_fields || !is_self {
        ctx.actor.require_admin()?;
    }
    let mut sets: Vec<&str> = vec![];
    let mut p: Vec<SqlValue> = vec![];
    if let Some(name) = &input.name {
        sets.push("name = ?");
        p.push(required(name, "name", 120)?.into());
    }
    if let Some(h) = &input.handle {
        let normalized = normalize_handle(h);
        if normalized.is_empty() {
            return Err(ApiError::bad_request("handle must contain letters or digits"));
        }
        if let Some(other) = ctx.db.one("SELECT id FROM users WHERE handle = ?", &params![normalized.clone()])?
            && other.str("id") != id
        {
            return Err(ApiError::conflict(format!("@{normalized} is taken")));
        }
        sets.push("handle = ?");
        p.push(normalized.into());
    }
    if let Some(bio) = input.bio {
        sets.push("bio = ?");
        p.push(bio.trim().chars().take(1000).collect::<String>().into());
    }
    if let Some(a) = input.avatar_url {
        let a = a.trim().to_string();
        if !a.is_empty() && !(a.starts_with("https://") || a.starts_with("http://")) {
            return Err(ApiError::bad_request("avatar_url must be an http(s) URL"));
        }
        sets.push("avatar_url = ?");
        p.push(if a.is_empty() { SqlValue::Null } else { a.into() });
    }
    let was_admin = row.str("role") == "admin" && row.opt_str("deactivated_at").is_none();
    if let Some(role) = input.role {
        if was_admin && role != Role::Admin && active_admins(ctx)? <= 1 {
            return Err(ApiError::conflict("you can't demote the last admin"));
        }
        sets.push("role = ?");
        p.push(role.as_str().into());
    }
    if let Some(deactivated) = input.deactivated {
        if deactivated {
            if is_self {
                return Err(ApiError::bad_request("you can't deactivate yourself"));
            }
            if was_admin && active_admins(ctx)? <= 1 {
                return Err(ApiError::conflict("you can't deactivate the last admin"));
            }
            sets.push("deactivated_at = ?");
            p.push(ctx.now_s().into());
            ctx.db.execute("DELETE FROM sessions WHERE user_id = ?", &params![id.clone()])?;
        } else {
            sets.push("deactivated_at = NULL");
        }
    }
    if let Some(pw) = input.new_password {
        sets.push("password_hash = ?");
        p.push(auth::hash_password(&pw)?.into());
        ctx.db.execute("DELETE FROM sessions WHERE user_id = ?", &params![id.clone()])?;
    }
    if !sets.is_empty() {
        sets.push("updated_at = ?");
        p.push(ctx.now_s().into());
        p.push(id.clone().into());
        ctx.db.execute(&format!("UPDATE users SET {} WHERE id = ?", sets.join(", ")), &p)?;
        if admin_fields {
            emit(
                ctx,
                Event::new("user.updated", "user", &id, format!("changed {}'s account", row.str("name")))
                    .data(json!({ "role": input.role.map(|r| r.as_str()), "deactivated": input.deactivated }))
                    .admin_only(),
            )?;
        }
    }
    Ok(User::from_row(&find_user(ctx, &id)?))
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangePasswordInput {
    pub current_password: String,
    pub new_password: String,
}

fn change_password(ctx: &mut Ctx, input: ChangePasswordInput) -> ApiResult<Done> {
    // A token (a connected app's or a script's) must not be a way to guess, or replace, the
    // password that signs in with the account's full role.
    if ctx.actor.session_hash.is_none() && ctx.actor.via != Via::Cli {
        return Err(ApiError::forbidden("change your password in the web app, under Settings → Profile"));
    }
    let row = ctx
        .db
        .one("SELECT email, password_hash FROM users WHERE id = ?", &params![ctx.actor.user_id.clone()])?
        .ok_or_else(|| ApiError::not_found("user"))?;
    // Guesses at the current password count against the same limits as sign-ins.
    let keys = auth::password_keys(&row.str("email"), None);
    auth::check_throttle(ctx.db, &keys, ctx.now)?;
    let ok = row.opt_str("password_hash").is_some_and(|h| auth::verify_password(&input.current_password, &h));
    if !ok {
        auth::record_failures(ctx.db, &keys, ctx.now)?;
        // Keep the failure count although the request fails.
        return Err(ApiError::forbidden("current password is incorrect").keep_writes());
    }
    auth::clear_failures(ctx.db, &keys[0].0)?;
    let hash = auth::hash_password(&input.new_password)?;
    ctx.db.execute(
        "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
        &params![hash, ctx.now_s(), ctx.actor.user_id.clone()],
    )?;
    ctx.db.execute(
        "DELETE FROM sessions WHERE user_id = ? AND token_hash IS NOT ?",
        &params![ctx.actor.user_id.clone(), ctx.actor.session_hash.clone()],
    )?;
    Ok(DONE)
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct TokenInfo {
    pub id: String,
    pub name: String,
    /// The first characters of the secret, to recognize it.
    pub prefix: String,
    pub scopes: Vec<String>,
    /// `personal` or `oauth` (issued to an MCP client).
    pub kind: String,
    pub client_id: Option<String>,
    pub user: UserRef,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub expires_at: Option<String>,
    pub revoked: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct TokenList {
    pub items: Vec<TokenInfo>,
}

fn to_token(r: &Row, users: &std::collections::HashMap<String, UserRef>) -> TokenInfo {
    TokenInfo {
        id: r.str("id"),
        name: r.str("name"),
        prefix: r.str("prefix"),
        scopes: Scopes::parse(&r.str("scopes")).map(|s| s.to_list()).unwrap_or_default(),
        kind: r.str("kind"),
        client_id: r.opt_str("client_id"),
        user: user_ref(users, &r.str("user_id")),
        created_at: r.str("created_at"),
        last_used_at: r.opt_str("last_used_at"),
        expires_at: r.opt_str("expires_at"),
        revoked: r.opt_str("revoked_at").is_some(),
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListTokensInput {
    /// Admins only: list another user's tokens, or `all`.
    pub user: Option<String>,
    pub include_revoked: Option<bool>,
}

fn list_tokens(ctx: &mut Ctx, input: ListTokensInput) -> ApiResult<TokenList> {
    let mut cond = vec![];
    let mut p: Vec<SqlValue> = vec![];
    match clean(input.user).as_deref() {
        None | Some("me") => {
            cond.push("user_id = ?");
            p.push(ctx.actor.user_id.clone().into());
        }
        Some("all") => ctx.actor.require_admin()?,
        Some(other) => {
            ctx.actor.require_admin()?;
            cond.push("user_id = ?");
            p.push(find_user(ctx, other)?.str("id").into());
        }
    }
    if !input.include_revoked.unwrap_or(false) {
        cond.push("revoked_at IS NULL");
        // A connected app's access token expires hourly but its grant lives on while the refresh token does.
        cond.push(
            "(expires_at IS NULL OR expires_at > ? OR id IN (SELECT access_token_id FROM oauth_refresh_tokens
               WHERE access_token_id IS NOT NULL AND revoked_at IS NULL AND expires_at > ?))",
        );
        p.push(ctx.now_s().into());
        p.push(ctx.now_s().into());
    }
    let where_ = if cond.is_empty() { "1=1".to_string() } else { cond.join(" AND ") };
    let rows = ctx.db.query(&format!("SELECT * FROM api_tokens WHERE {where_} ORDER BY created_at DESC"), &p)?;
    let users = user_refs(ctx.db, &rows.iter().map(|r| r.str("user_id")).collect::<Vec<_>>())?;
    Ok(TokenList { items: rows.iter().map(|r| to_token(r, &users)).collect() })
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateTokenInput {
    /// What the token is for, e.g. "Claude Code on my laptop".
    pub name: String,
    /// Any of `read`, `write`, `admin`. Default `read` + `write`.
    pub scopes: Option<Vec<String>>,
    /// Days until it expires. Default: never.
    pub expires_in_days: Option<u32>,
    /// Admins only: mint the token for another account (usually a bot).
    pub user: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct CreatedToken {
    /// The secret. Shown only now; store it safely.
    pub token: String,
    pub info: TokenInfo,
}

/// Creates a token row and returns (id, secret). `app` is a connected app's (client id, resource);
/// without one it's a personal token.
pub fn mint_token(
    ctx: &Ctx,
    user_id: &str,
    name: &str,
    scopes: Scopes,
    app: Option<(&str, &str)>,
    expires_at: Option<String>,
) -> ApiResult<(String, String)> {
    let (kind, prefix) = if app.is_some() { ("oauth", "ds_oat_") } else { ("personal", "ds_pat_") };
    let secret = new_secret(prefix);
    let id = new_id();
    ctx.db.execute(
        "INSERT INTO api_tokens (id, user_id, name, token_hash, prefix, scopes, kind, client_id, resource, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        &params![
            id.clone(),
            user_id,
            name,
            sha256_hex(&secret),
            secret.chars().take(11).collect::<String>(),
            scopes.to_str(),
            kind,
            app.map(|(client, _)| client),
            app.map(|(_, resource)| resource),
            ctx.now_s(),
            expires_at
        ],
    )?;
    Ok((id, secret))
}

/// The connected app (its client id) whose token the caller is using, if any.
fn connected_app(ctx: &Ctx) -> ApiResult<Option<String>> {
    let Some(tid) = &ctx.actor.token_id else { return Ok(None) };
    let row = ctx.db.one("SELECT kind, client_id FROM api_tokens WHERE id = ?", &params![tid.clone()])?;
    Ok(row.filter(|r| r.str("kind") == "oauth").and_then(|r| r.opt_str("client_id")))
}

fn create_token(ctx: &mut Ctx, input: CreateTokenInput) -> ApiResult<CreatedToken> {
    let name = required(&input.name, "name", 100)?;
    let owner = match clean(input.user) {
        Some(u) if u != "me" => {
            ctx.actor.require_admin()?;
            find_user(ctx, &u)?
        }
        _ => find_user(ctx, "me")?,
    };
    let owner_role = Role::parse(&owner.str("role")).unwrap_or(Role::Viewer);
    if owner.opt_str("deactivated_at").is_some() {
        return Err(ApiError::bad_request("that account is deactivated"));
    }
    let requested = Scopes::parse(&input.scopes.unwrap_or_else(|| vec!["read".into(), "write".into()]).join(" "))?;
    if requested.admin && owner_role != Role::Admin {
        return Err(ApiError::forbidden("only admins can have admin-scoped tokens"));
    }
    // A credential can't mint a token more powerful than itself.
    if (requested.write && !ctx.actor.scopes.write) || (requested.admin && !ctx.actor.scopes.admin) {
        return Err(ApiError::forbidden("you can't create a token with more scopes than the credential you're using"));
    }
    let mut expires = input.expires_in_days.filter(|d| *d > 0).map(|d| ts(ctx.now + Duration::days(d as i64)));
    if connected_app(ctx)?.is_some() {
        return Err(ApiError::forbidden("connected apps can't create API tokens; create one in Settings → API tokens"));
    }
    if let Some(tid) = &ctx.actor.token_id {
        let caller = ctx.db.one("SELECT expires_at FROM api_tokens WHERE id = ?", &params![tid.clone()])?;
        if let Some(limit) = caller.and_then(|c| c.opt_str("expires_at")) {
            expires = Some(match expires {
                Some(e) if e < limit => e,
                _ => limit,
            });
        }
    }
    let (id, token) = mint_token(ctx, &owner.str("id"), &name, requested, None, expires)?;
    emit(
        ctx,
        Event::new("token.created", "token", &id, format!("created API token “{name}” for {}", owner.str("name")))
            .data(json!({ "scopes": requested.to_list() }))
            .admin_only(),
    )?;
    let row = ctx.db.one("SELECT * FROM api_tokens WHERE id = ?", &params![id])?.ok_or_else(|| ApiError::internal("token vanished"))?;
    let users = user_refs(ctx.db, &[owner.str("id")])?;
    Ok(CreatedToken { token, info: to_token(&row, &users) })
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TokenIdInput {
    pub id: String,
}

fn revoke_token(ctx: &mut Ctx, input: TokenIdInput) -> ApiResult<Done> {
    let row =
        ctx.db.one("SELECT * FROM api_tokens WHERE id = ?", &params![input.id.clone()])?.ok_or_else(|| ApiError::not_found("token"))?;
    if row.str("user_id") != ctx.actor.user_id {
        ctx.actor.require_admin()?;
    }
    // Consent to a connected app covers content, not the person's other credentials: without the
    // admin scope it may only disconnect itself.
    if let Some(client) = connected_app(ctx)?
        && !ctx.actor.can_admin()
        && !(row.str("kind") == "oauth" && row.opt_str("client_id").as_deref() == Some(client.as_str()))
    {
        return Err(ApiError::forbidden("connected apps can only disconnect themselves; manage other tokens in Settings → API tokens"));
    }
    ctx.db.execute("UPDATE api_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?", &params![ctx.now_s(), input.id.clone()])?;
    ctx.db.execute(
        "UPDATE oauth_refresh_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE access_token_id = ?",
        &params![ctx.now_s(), input.id.clone()],
    )?;
    if let (true, Some(client)) = (row.str("kind") == "oauth", row.opt_str("client_id")) {
        // Refreshes rotate token ids, so disconnect the app's whole grant for this person.
        let p = params![ctx.now_s(), row.str("user_id"), client];
        ctx.db.execute(
            "UPDATE api_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE kind = 'oauth' AND user_id = ? AND client_id = ?",
            &p,
        )?;
        ctx.db.execute("UPDATE oauth_refresh_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE user_id = ? AND client_id = ?", &p)?;
    }
    emit(ctx, Event::new("token.revoked", "token", &input.id, format!("revoked API token “{}”", row.str("name"))).admin_only())?;
    Ok(DONE)
}
