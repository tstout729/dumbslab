//! OAuth 2.1 authorization server for MCP clients: discovery metadata, dynamic client
//! registration, authorization code + PKCE (S256), refresh token rotation and revocation.
//! Access tokens are rows in `api_tokens` (kind `oauth`), so people can see and revoke them.

use std::collections::HashMap;

use base64::Engine;
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::auth::{self, Actor, Role, Scopes, Via};
use crate::db::{Db, DbExt, Row};
use crate::error::ApiError;
use crate::http::{base_url, done, new_ctx};
use crate::mcp::{Toolset, cors, requested_toolset};
use crate::ops::users::mint_token;
use crate::util::{html_escape, new_id, new_secret, parse_ts, secure_eq, sha256_hex, ts};
use crate::{HostConfig, Outcome, Request, Response, params};

const ACCESS_TOKEN_SECONDS: i64 = 3600;
const REFRESH_TOKEN_DAYS: i64 = 60;
const CODE_MINUTES: i64 = 10;
/// Registered (dynamic) clients kept per workspace.
pub const MAX_CLIENTS: i64 = 1000;
/// Hosted workspaces: new app registrations allowed in any hour. Keeps anonymous registration's
/// writes far below a workspace's daily write allowance.
pub const HOSTED_REGISTRATIONS_PER_HOUR: i64 = 120;
/// How long opening a client's consent page protects it from eviction.
pub const CONSENT_PROTECTION_MINUTES: i64 = 15;
/// Grants and codes are written even in a full workspace, so each is capped: an app keeps a
/// person's newest grants (reconnecting replaces the oldest), and a person their newest codes.
pub const MAX_GRANTS_PER_APP: i64 = 5;
pub const MAX_CODES_PER_PERSON: i64 = 10;
/// The read-only MCP URL's resource suffix. Grants for it can only read.
const READ_ONLY: &str = "?toolset=read";

pub fn handle(db: &dyn Db, cfg: &HostConfig, req: &Request) -> Outcome {
    let base = base_url(cfg, req);
    if req.method == "OPTIONS" {
        return cors(done(Response::empty(204)));
    }
    let out = match (req.method.as_str(), req.path.as_str()) {
        ("GET", p) if p.starts_with("/.well-known/oauth-protected-resource") => {
            // The read-only MCP URL is its own resource, and it only offers read access.
            let read_only = requested_toolset(&req.query) == Toolset::Read;
            let (resource, scopes) = if read_only {
                (format!("{base}/mcp{READ_ONLY}"), json!(["read"]))
            } else {
                (format!("{base}/mcp"), json!(["read", "write", "admin"]))
            };
            done(Response::json(
                200,
                &json!({
                    "resource": resource,
                    "authorization_servers": [base],
                    "scopes_supported": scopes,
                    "bearer_methods_supported": ["header"],
                    "resource_name": "DumbSlab",
                    "resource_documentation": format!("{base}/llms.txt"),
                }),
            ))
        }
        ("GET", p) if p.starts_with("/.well-known/oauth-authorization-server") => done(Response::json(
            200,
            &json!({
                "issuer": base,
                "authorization_endpoint": format!("{base}/oauth/authorize"),
                "token_endpoint": format!("{base}/oauth/token"),
                "registration_endpoint": format!("{base}/oauth/register"),
                "revocation_endpoint": format!("{base}/oauth/revoke"),
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["none"],
                "revocation_endpoint_auth_methods_supported": ["none"],
                "scopes_supported": ["read", "write", "admin"],
                "service_documentation": format!("{base}/llms.txt"),
            }),
        )),
        ("POST", "/oauth/register") => register(db, cfg, req),
        ("GET", "/oauth/authorize") => authorize_page(db, cfg, req),
        ("POST", "/oauth/authorize") => authorize_decision(db, cfg, req),
        ("POST", "/oauth/token") => token(db, cfg, req),
        ("POST", "/oauth/revoke") => revoke(db, req),
        _ => done(Response::json(404, &json!({ "error": "not_found" }))),
    };
    cors(out)
}

fn oauth_error(status: u16, error: &str, description: &str) -> Outcome {
    let mut out = done(Response::json(status, &json!({ "error": error, "error_description": description })));
    out.response.headers.push(("cache-control".into(), "no-store".into()));
    out
}

/// Parses `application/x-www-form-urlencoded` (or JSON) bodies and query strings.
pub fn parse_form(s: &str) -> HashMap<String, String> {
    s.split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            let dec = |x: &str| urlencoding::decode(&x.replace('+', " ")).map(|c| c.into_owned()).unwrap_or_default();
            (dec(k), dec(v))
        })
        .collect()
}

fn body_params(req: &Request) -> HashMap<String, String> {
    let is_json = req.header("content-type").is_some_and(|c| c.contains("json"));
    if is_json {
        serde_json::from_slice::<HashMap<String, Value>>(&req.body)
            .map(|m| {
                m.into_iter()
                    .map(|(k, v)| {
                        (
                            k,
                            match v {
                                Value::String(s) => s,
                                other => other.to_string(),
                            },
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    } else {
        parse_form(&String::from_utf8_lossy(&req.body))
    }
}

fn valid_redirect_uri(uri: &str) -> bool {
    let lower = uri.to_ascii_lowercase();
    let Some((scheme, rest)) = lower.split_once("://") else { return false };
    if uri.len() > 2000 || uri.contains('#') || rest.is_empty() {
        return false;
    }
    match scheme {
        "https" => true,
        "http" => {
            let host = rest.split(['/', '?']).next().unwrap_or_default();
            let host = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
            matches!(host, "localhost" | "127.0.0.1" | "[::1]")
        }
        "javascript" | "data" | "file" | "vbscript" => false,
        // Native apps use private-use schemes such as `cursor://`.
        s => s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')),
    }
}

fn register(db: &dyn Db, cfg: &HostConfig, req: &Request) -> Outcome {
    // Hosted workspaces pay for every row written, and registration is anonymous: refuse it while
    // the workspace can't change things, and cap how often it happens.
    if let Some(hosting) = cfg.hosting.as_ref() {
        if let Err(e) = crate::plan::check_write(db, hosting, Utc::now()) {
            return crate::http::failed(&e);
        }
        let hour_ago = ts(Utc::now() - Duration::hours(1));
        if db.scalar_i64("SELECT COUNT(*) FROM oauth_clients WHERE created_at > ?", &params![hour_ago]).unwrap_or(0)
            >= HOSTED_REGISTRATIONS_PER_HOUR
        {
            return oauth_error(429, "invalid_client_metadata", "too many apps registered in the last hour; try again later");
        }
    }
    let body: Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => return oauth_error(400, "invalid_client_metadata", "body must be JSON"),
    };
    let uris: Vec<String> =
        body["redirect_uris"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
    if uris.is_empty() || uris.len() > 5 || uris.iter().any(|u| u.len() > 512) {
        return oauth_error(400, "invalid_redirect_uri", "provide 1-5 redirect_uris of at most 512 characters");
    }
    if let Some(bad) = uris.iter().find(|u| !valid_redirect_uri(u)) {
        return oauth_error(400, "invalid_redirect_uri", &format!("redirect URI not allowed: {bad}"));
    }
    // Registration is anonymous, so keep the table small: drop day-old clients that were never
    // used, and at the cap make room by evicting the oldest never-used one (so a flood of
    // registrations can't lock real clients out). A client whose consent page someone opened
    // is safe for a short while so they can click Allow; the protection expires, so opening
    // consent pages (which a hostile site can trigger) can't pin slots for good.
    const UNUSED: &str = "(seen_at IS NULL OR seen_at < ?)
           AND client_id NOT IN (SELECT client_id FROM api_tokens WHERE client_id IS NOT NULL)
           AND client_id NOT IN (SELECT client_id FROM oauth_codes)
           AND client_id NOT IN (SELECT client_id FROM oauth_refresh_tokens)";
    let now = Utc::now();
    let pending_cutoff = ts(now - Duration::minutes(CONSENT_PROTECTION_MINUTES));
    let day_ago = ts(now - Duration::days(1));
    let _ = db.execute(&format!("DELETE FROM oauth_clients WHERE created_at < ? AND {UNUSED}"), &params![day_ago, pending_cutoff.clone()]);
    let excess = db.scalar_i64("SELECT COUNT(*) FROM oauth_clients", &[]).unwrap_or(0) - MAX_CLIENTS + 1;
    if excess > 0 {
        let _ = db.execute(
            &format!("DELETE FROM oauth_clients WHERE client_id IN (SELECT client_id FROM oauth_clients WHERE {UNUSED} ORDER BY created_at LIMIT ?)"),
            &params![pending_cutoff, excess],
        );
    }
    if db.scalar_i64("SELECT COUNT(*) FROM oauth_clients", &[]).unwrap_or(0) >= MAX_CLIENTS {
        return oauth_error(400, "invalid_client_metadata", "too many registered clients; try again later");
    }
    let name: String = body["client_name"].as_str().unwrap_or("MCP client").chars().take(100).collect();
    let client_id = format!("dsc_{}", new_id());
    if let Err(e) = db.execute(
        "INSERT INTO oauth_clients (client_id, client_name, redirect_uris, created_at) VALUES (?, ?, ?, ?)",
        &params![client_id.clone(), name.clone(), serde_json::to_string(&uris).unwrap_or_default(), ts(now)],
    ) {
        return crate::http::failed(&e);
    }
    done(Response::json(
        201,
        &json!({
            "client_id": client_id,
            "client_id_issued_at": now.timestamp(),
            "client_name": name,
            "redirect_uris": uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        }),
    ))
}

/// The resource (RFC 8707) a connected app's token is for, from the one it asked for. This server
/// issues tokens only for itself, so a resource anywhere else is `None`; that way a token approved
/// here can't be meant for (and replayed by) another server. `?toolset=read` asks for the read-only
/// MCP URL. No resource means this server's MCP endpoint.
pub fn canonical_resource(base: &str, requested: Option<&str>) -> Option<String> {
    let mcp = format!("{base}/mcp");
    let Some(requested) = requested.map(str::trim).filter(|r| !r.is_empty()) else { return Some(mcp) };
    if requested.contains('#') {
        return None;
    }
    let (address, query) = requested.split_once('?').unwrap_or((requested, ""));
    let address = without_default_port(&address.to_ascii_lowercase());
    let rest = address.strip_prefix(&without_default_port(&base.to_ascii_lowercase()))?;
    if !(rest.is_empty() || rest.starts_with('/')) {
        return None;
    }
    Some(if requested_toolset(query) == Toolset::Read { format!("{mcp}{READ_ONLY}") } else { mcp })
}

/// `https://host:443/x` → `https://host/x`, so a default port written out still names this server.
fn without_default_port(url: &str) -> String {
    for (scheme, port) in [("https://", ":443"), ("http://", ":80")] {
        if let Some(rest) = url.strip_prefix(scheme) {
            let (host, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
            if let Some(host) = host.strip_suffix(port) {
                return format!("{scheme}{host}{path}");
            }
        }
    }
    url.to_string()
}

struct AuthRequest {
    client_id: String,
    client_name: String,
    redirect_uri: String,
    state: String,
    code_challenge: String,
    scopes: Scopes,
    resource: String,
}

/// Validates client and redirect URI. Errors here are shown to the user, never redirected.
fn load_client(db: &dyn Db, p: &HashMap<String, String>) -> Result<(String, String), String> {
    let client_id = p.get("client_id").cloned().unwrap_or_default();
    let redirect_uri = p.get("redirect_uri").cloned().unwrap_or_default();
    let row = db
        .one("SELECT client_name, redirect_uris FROM oauth_clients WHERE client_id = ?", &params![client_id.clone()])
        .map_err(|e| e.message)?
        .ok_or("This app isn't registered with this workspace. Try connecting again.")?;
    let allowed: Vec<String> = serde_json::from_str(&row.str("redirect_uris")).unwrap_or_default();
    if !allowed.contains(&redirect_uri) {
        return Err("The app's redirect address doesn't match its registration.".into());
    }
    Ok((row.str("client_name"), redirect_uri))
}

fn redirect_with(redirect_uri: &str, params: &[(&str, &str)]) -> Outcome {
    let sep = if redirect_uri.contains('?') { '&' } else { '?' };
    let q = params.iter().map(|(k, v)| format!("{k}={}", urlencoding::encode(v))).collect::<Vec<_>>().join("&");
    done(Response::redirect(&format!("{redirect_uri}{sep}{q}")))
}

fn parse_auth_request(db: &dyn Db, base: &str, p: &HashMap<String, String>) -> Result<Result<AuthRequest, Outcome>, String> {
    let (client_name, redirect_uri) = load_client(db, p)?;
    let state = p.get("state").cloned().unwrap_or_default();
    let fail =
        |code: &str, desc: &str| Ok(Err(redirect_with(&redirect_uri, &[("error", code), ("error_description", desc), ("state", &state)])));
    if p.get("response_type").map(String::as_str) != Some("code") {
        return fail("unsupported_response_type", "only response_type=code is supported");
    }
    let challenge = p.get("code_challenge").cloned().unwrap_or_default();
    if challenge.len() < 43 || p.get("code_challenge_method").map(String::as_str) != Some("S256") {
        return fail("invalid_request", "PKCE with code_challenge_method=S256 is required");
    }
    let Some(resource) = canonical_resource(base, p.get("resource").map(String::as_str)) else {
        return fail("invalid_target", &format!("this server only issues tokens for itself ({base}/mcp)"));
    };
    let scopes = match p.get("scope").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(s) => match Scopes::parse(&s.split(' ').filter(|w| matches!(*w, "read" | "write" | "admin")).collect::<Vec<_>>().join(" ")) {
            Ok(sc) if sc.read => sc,
            _ => Scopes::parse("read write").expect("valid"),
        },
        None => Scopes::parse("read write").expect("valid"),
    };
    // The read-only MCP URL grants read access, whatever the app asks for.
    let scopes = if resource.ends_with(READ_ONLY) { Scopes { read: true, write: false, admin: false } } else { scopes };
    Ok(Ok(AuthRequest { client_id: p["client_id"].clone(), client_name, redirect_uri, state, code_challenge: challenge, scopes, resource }))
}

fn html_page(status: u16, title: &str, body: &str) -> Outcome {
    let page = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{title}</title><style>\
         :root{{color-scheme:light dark;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif}}\
         body{{margin:0;min-height:100vh;display:grid;place-items:center;background:Canvas;color:CanvasText}}\
         main{{max-width:420px;width:calc(100% - 48px);padding:32px;border:1px solid color-mix(in srgb,CanvasText 15%,transparent);border-radius:16px}}\
         h1{{font-size:20px;margin:0 0 12px}}p,li{{line-height:1.5;color:color-mix(in srgb,CanvasText 80%,transparent)}}\
         .row{{display:flex;gap:12px;margin-top:24px}}button{{flex:1;font:inherit;padding:10px 14px;border-radius:10px;border:1px solid color-mix(in srgb,CanvasText 20%,transparent);background:transparent;color:inherit;cursor:pointer}}\
         button.primary{{background:#4f46e5;border-color:#4f46e5;color:#fff}}code{{font-size:13px}}\
         </style></head><body><main>{body}</main></body></html>"
    );
    let mut out = done(Response::text(status, "text/html; charset=utf-8", page));
    out.response.headers.push(("cache-control".into(), "no-store".into()));
    out.response.headers.push(("x-frame-options".into(), "DENY".into()));
    out.response.headers.push((
        "content-security-policy".into(),
        // No `form-action`: Chrome applies it to the redirect back to the client app.
        "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'".into(),
    ));
    out
}

fn error_page(message: &str) -> Outcome {
    html_page(400, "Can't connect", &format!("<h1>Can't connect this app</h1><p>{}</p>", html_escape(message)))
}

fn session_actor(db: &dyn Db, cfg: &HostConfig, req: &Request) -> Option<Actor> {
    match auth::authenticate(db, cfg, req, Utc::now()) {
        Ok(Some(a)) if a.via == Via::Web => Some(a),
        _ => None,
    }
}

fn authorize_page(db: &dyn Db, cfg: &HostConfig, req: &Request) -> Outcome {
    let p = parse_form(&req.query);
    let ar = match parse_auth_request(db, &base_url(cfg, req), &p) {
        Err(msg) => return error_page(&msg),
        Ok(Err(redirect)) => return redirect,
        Ok(Ok(ar)) => ar,
    };
    let Some(actor) = session_actor(db, cfg, req) else {
        let next = format!("/oauth/authorize?{}", req.query);
        return done(Response::redirect(&format!("/login?next={}", urlencoding::encode(&next))));
    };
    // A person is connecting this client: keep it safe from pruning and eviction.
    let _ = db.execute("UPDATE oauth_clients SET seen_at = ? WHERE client_id = ?", &params![ts(Utc::now()), ar.client_id.clone()]);
    let scopes = effective_scopes(&actor, ar.scopes);
    let workspace = crate::ops::admin::setting(db, "workspace_name").ok().flatten().unwrap_or_else(|| "DumbSlab".into());
    let csrf = auth::form_csrf(actor.session_hash.as_deref().unwrap_or_default());
    let hidden: String =
        ["client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "scope", "response_type", "resource"]
            .iter()
            .filter_map(|k| p.get(*k).map(|v| format!("<input type=\"hidden\" name=\"{k}\" value=\"{}\">", html_escape(v))))
            .collect();
    let mut abilities = vec!["Read posts, topics and comments you can see"];
    if scopes.write {
        abilities.push("Create and edit posts, topics and comments as you");
    }
    if scopes.admin {
        abilities.push("Manage people, tokens, webhooks and settings");
    }
    let list: String = abilities.iter().map(|a| format!("<li>{a}</li>")).collect();
    html_page(
        200,
        "Connect an app",
        &format!(
            "<h1>Connect {app} to {ws}?</h1><p><strong>{app}</strong> wants to use {ws} as <strong>{name}</strong>. It will be able to:</p><ul>{list}</ul>\
             <p><small>Redirects to <code>{redirect}</code>. You can revoke access any time under Settings → API tokens.</small></p>\
             <form method=\"post\" action=\"/oauth/authorize\">{hidden}<input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
             <div class=\"row\"><button name=\"decision\" value=\"deny\">Cancel</button><button class=\"primary\" name=\"decision\" value=\"approve\">Allow</button></div></form>",
            app = html_escape(&ar.client_name),
            ws = html_escape(&workspace),
            name = html_escape(&actor.name),
            redirect = html_escape(&ar.redirect_uri),
        ),
    )
}

/// The scopes a person can grant: admin only for admins.
fn effective_scopes(actor: &Actor, requested: Scopes) -> Scopes {
    Scopes { read: true, write: requested.write && actor.role >= Role::Viewer, admin: requested.admin && actor.role == Role::Admin }
}

fn authorize_decision(db: &dyn Db, cfg: &HostConfig, req: &Request) -> Outcome {
    let p = parse_form(&String::from_utf8_lossy(&req.body));
    let ar = match parse_auth_request(db, &base_url(cfg, req), &p) {
        Err(msg) => return error_page(&msg),
        Ok(Err(redirect)) => return redirect,
        Ok(Ok(ar)) => ar,
    };
    let Some(actor) = session_actor(db, cfg, req) else {
        return error_page("Your session expired. Start connecting again.");
    };
    let expected = auth::form_csrf(actor.session_hash.as_deref().unwrap_or_default());
    if !p.get("csrf").is_some_and(|c| secure_eq(c, &expected)) {
        return error_page("This form expired. Start connecting again.");
    }
    if p.get("decision").map(String::as_str) != Some("approve") {
        return redirect_with(&ar.redirect_uri, &[("error", "access_denied"), ("state", &ar.state)]);
    }
    let scopes = effective_scopes(&actor, ar.scopes);
    let code = new_secret("ds_code_");
    let now = Utc::now();
    let uid = actor.user_id.clone();
    let written = db
        .execute(
            "INSERT INTO oauth_codes (code_hash, client_id, user_id, redirect_uri, code_challenge, scopes, expires_at, resource)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            &params![
                sha256_hex(&code),
                ar.client_id,
                uid.clone(),
                ar.redirect_uri.clone(),
                ar.code_challenge,
                scopes.to_str(),
                ts(now + Duration::minutes(CODE_MINUTES)),
                ar.resource
            ],
        )
        .and_then(|_| db.execute("DELETE FROM oauth_codes WHERE expires_at < ?", &params![ts(now)]))
        .and_then(|_| {
            db.execute(
                "DELETE FROM oauth_codes WHERE user_id = ? AND code_hash != ? AND code_hash NOT IN
                   (SELECT code_hash FROM oauth_codes WHERE user_id = ? ORDER BY expires_at DESC LIMIT ?)",
                &params![uid.clone(), sha256_hex(&code), uid, MAX_CODES_PER_PERSON],
            )
        });
    if let Err(e) = written {
        return crate::http::failed(&e);
    }
    redirect_with(&ar.redirect_uri, &[("code", &code), ("state", &ar.state), ("iss", &base_url(cfg, req))])
}

fn pkce_ok(verifier: &str, challenge: &str) -> bool {
    if verifier.len() < 43 || verifier.len() > 128 {
        return false;
    }
    let digest = Sha256::digest(verifier.as_bytes());
    let computed = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
    secure_eq(&computed, challenge)
}

fn user_actor(db: &dyn Db, user_id: &str) -> Option<Actor> {
    crate::model::actor_for_user(db, user_id).ok().flatten()
}

fn app_token_name(db: &dyn Db, client_id: &str) -> Result<String, ApiError> {
    let name = db.one("SELECT client_name FROM oauth_clients WHERE client_id = ?", &params![client_id])?.map(|r| r.str("client_name"));
    Ok(format!("{} (connected app)", name.unwrap_or_else(|| "MCP client".into())))
}

fn token_response(access: &str, refresh: &str, scopes: Scopes) -> Value {
    json!({
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_SECONDS,
        "refresh_token": refresh,
        "scope": scopes.to_str(),
    })
}

/// Starts a grant for a person and app: an access token and a refresh token, both for `resource`.
fn new_grant(
    db: &dyn Db,
    cfg: &HostConfig,
    req: &Request,
    user_id: &str,
    client_id: &str,
    scopes: Scopes,
    resource: &str,
) -> Result<Value, ApiError> {
    let actor = user_actor(db, user_id).ok_or_else(|| ApiError::bad_request("account is deactivated"))?;
    let scopes = effective_scopes(&actor, scopes);
    let name = app_token_name(db, client_id)?;
    let ctx = new_ctx(db, cfg, req, actor);
    let expires = ts(ctx.now + Duration::seconds(ACCESS_TOKEN_SECONDS));
    let (token_id, access) = mint_token(&ctx, user_id, &name, scopes, Some((client_id, resource)), Some(expires))?;
    let refresh = new_secret("ds_ort_");
    db.execute(
        "INSERT INTO oauth_refresh_tokens (token_hash, client_id, user_id, scopes, access_token_id, created_at, expires_at, resource)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        &params![
            sha256_hex(&refresh),
            client_id,
            user_id,
            scopes.to_str(),
            token_id,
            ctx.now_s(),
            ts(ctx.now + Duration::days(REFRESH_TOKEN_DAYS)),
            resource
        ],
    )?;
    // Reconnecting an app replaces the person's oldest grants for it beyond a few.
    let older = db.query(
        "SELECT token_hash, access_token_id FROM oauth_refresh_tokens WHERE user_id = ? AND client_id = ? AND token_hash != ?
         ORDER BY created_at DESC LIMIT -1 OFFSET ?",
        &params![user_id, client_id, sha256_hex(&refresh), MAX_GRANTS_PER_APP - 1],
    )?;
    for r in older {
        db.execute("DELETE FROM api_tokens WHERE id = ? AND kind = 'oauth'", &params![r.opt_str("access_token_id")])?;
        db.execute("DELETE FROM oauth_refresh_tokens WHERE token_hash = ?", &params![r.str("token_hash")])?;
    }
    // Housekeeping: ended grants, and long-expired connected-app tokens whose grant has also ended.
    db.execute("DELETE FROM oauth_refresh_tokens WHERE revoked_at IS NOT NULL OR expires_at < ?", &params![ctx.now_s()])?;
    db.execute(
        "DELETE FROM api_tokens WHERE kind = 'oauth' AND expires_at < ?
           AND id NOT IN (SELECT access_token_id FROM oauth_refresh_tokens
                          WHERE access_token_id IS NOT NULL AND revoked_at IS NULL AND expires_at > ?)",
        &params![ts(ctx.now - Duration::days(7)), ctx.now_s()],
    )?;
    Ok(token_response(&access, &refresh, scopes))
}

/// Refreshes a grant in place: new secrets in the same rows, so the old ones stop working,
/// refreshing never grows storage, and the grant keeps the id people see (and revoke) in Settings.
fn rotate_grant(db: &dyn Db, cfg: &HostConfig, req: &Request, grant: &Row, resource: &str) -> Result<Value, ApiError> {
    let (user_id, client_id) = (grant.str("user_id"), grant.str("client_id"));
    let actor = user_actor(db, &user_id).ok_or_else(|| ApiError::bad_request("account is deactivated"))?;
    let scopes = effective_scopes(&actor, Scopes::parse(&grant.str("scopes")).unwrap_or(Scopes { read: true, write: false, admin: false }));
    let ctx = new_ctx(db, cfg, req, actor);
    let expires = ts(ctx.now + Duration::seconds(ACCESS_TOKEN_SECONDS));
    let access = new_secret("ds_oat_");
    let rotated = match grant.opt_str("access_token_id") {
        Some(id) => {
            let n = db.execute(
                "UPDATE api_tokens SET token_hash = ?, prefix = ?, scopes = ?, resource = ?, expires_at = ?, revoked_at = NULL
                 WHERE id = ? AND kind = 'oauth'",
                &params![
                    sha256_hex(&access),
                    access.chars().take(11).collect::<String>(),
                    scopes.to_str(),
                    resource,
                    expires.clone(),
                    id.clone()
                ],
            )?;
            (n > 0).then_some((id, access))
        }
        None => None,
    };
    // The access token's row is gone (cleaned up long after it expired): start a new one.
    let (token_id, access) = match rotated {
        Some(t) => t,
        None => mint_token(&ctx, &user_id, &app_token_name(db, &client_id)?, scopes, Some((&client_id, resource)), Some(expires))?,
    };
    let refresh = new_secret("ds_ort_");
    db.execute(
        "UPDATE oauth_refresh_tokens SET token_hash = ?, scopes = ?, access_token_id = ?, resource = ?, created_at = ?, expires_at = ?
         WHERE token_hash = ?",
        &params![
            sha256_hex(&refresh),
            scopes.to_str(),
            token_id,
            resource,
            ctx.now_s(),
            ts(ctx.now + Duration::days(REFRESH_TOKEN_DAYS)),
            grant.str("token_hash")
        ],
    )?;
    Ok(token_response(&access, &refresh, scopes))
}

fn token(db: &dyn Db, cfg: &HostConfig, req: &Request) -> Outcome {
    let base = base_url(cfg, req);
    let p = body_params(req);
    let now = Utc::now();
    let client_id = p.get("client_id").cloned().unwrap_or_default();
    // A `resource` here must name what the grant is for (RFC 8707), so a token can't be retargeted.
    let target = |granted: Option<String>| -> Option<String> {
        let granted = granted.unwrap_or_else(|| format!("{base}/mcp"));
        match p.get("resource") {
            Some(r) if canonical_resource(&base, Some(r)).as_deref() != Some(granted.as_str()) => None,
            _ => Some(granted),
        }
    };
    let wrong_target = || oauth_error(400, "invalid_target", "the resource isn't the one this grant is for");
    let result = match p.get("grant_type").map(String::as_str) {
        Some("authorization_code") => {
            let code = p.get("code").cloned().unwrap_or_default();
            let row = match db.one("SELECT * FROM oauth_codes WHERE code_hash = ?", &params![sha256_hex(&code)]) {
                Ok(Some(r)) => r,
                Ok(None) => return oauth_error(400, "invalid_grant", "unknown or used authorization code"),
                Err(e) => return crate::http::failed(&e),
            };
            // Codes are single use, even when the exchange fails.
            let _ = db.execute("DELETE FROM oauth_codes WHERE code_hash = ?", &params![sha256_hex(&code)]);
            let expired = parse_ts(&row.str("expires_at")).is_none_or(|t| t < now);
            if expired {
                return Outcome { commit: true, ..oauth_error(400, "invalid_grant", "authorization code expired") };
            }
            if row.str("client_id") != client_id || p.get("redirect_uri").map(String::as_str) != Some(row.str("redirect_uri").as_str()) {
                return Outcome { commit: true, ..oauth_error(400, "invalid_grant", "client_id or redirect_uri doesn't match") };
            }
            if !pkce_ok(p.get("code_verifier").map(String::as_str).unwrap_or_default(), &row.str("code_challenge")) {
                return Outcome { commit: true, ..oauth_error(400, "invalid_grant", "PKCE verification failed") };
            }
            let Some(resource) = target(row.opt_str("resource")) else {
                return Outcome { commit: true, ..wrong_target() };
            };
            let scopes = Scopes::parse(&row.str("scopes")).unwrap_or(Scopes { read: true, write: false, admin: false });
            new_grant(db, cfg, req, &row.str("user_id"), &client_id, scopes, &resource)
        }
        Some("refresh_token") => {
            let rt = p.get("refresh_token").cloned().unwrap_or_default();
            let row = match db.one(
                "SELECT * FROM oauth_refresh_tokens WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?",
                &params![sha256_hex(&rt), ts(now)],
            ) {
                Ok(Some(r)) => r,
                Ok(None) => return oauth_error(400, "invalid_grant", "refresh token is invalid, expired or revoked"),
                Err(e) => return crate::http::failed(&e),
            };
            if !client_id.is_empty() && row.str("client_id") != client_id {
                return oauth_error(400, "invalid_grant", "refresh token was issued to another client");
            }
            let Some(resource) = target(row.opt_str("resource")) else {
                return wrong_target();
            };
            rotate_grant(db, cfg, req, &row, &resource)
        }
        _ => return oauth_error(400, "unsupported_grant_type", "use authorization_code or refresh_token"),
    };
    match result {
        Ok(body) => {
            let mut out = done(Response::json(200, &body));
            out.response.headers.push(("cache-control".into(), "no-store".into()));
            out
        }
        Err(e) => oauth_error(400, "invalid_grant", &e.message),
    }
}

fn revoke(db: &dyn Db, req: &Request) -> Outcome {
    let p = body_params(req);
    let token = p.get("token").cloned().unwrap_or_default();
    let hash = sha256_hex(&token);
    let now = ts(Utc::now());
    let _ = db.execute(
        "UPDATE api_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE token_hash = ? AND kind = 'oauth'",
        &params![now.clone(), hash.clone()],
    );
    if let Ok(Some(r)) = db.one("SELECT access_token_id FROM oauth_refresh_tokens WHERE token_hash = ?", &params![hash.clone()]) {
        let _ = db.execute(
            "UPDATE api_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?",
            &params![now.clone(), r.opt_str("access_token_id")],
        );
    }
    let _ = db.execute("UPDATE oauth_refresh_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE token_hash = ?", &params![now, hash]);
    done(Response::json(200, &json!({})))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_uris() {
        assert!(valid_redirect_uri("https://claude.ai/api/mcp/auth_callback"));
        assert!(valid_redirect_uri("http://localhost:6274/oauth/callback"));
        assert!(valid_redirect_uri("http://127.0.0.1:33418/callback"));
        assert!(valid_redirect_uri("cursor://anysphere.cursor-retrieval/oauth/callback"));
        assert!(!valid_redirect_uri("http://evil.example.com/cb"));
        assert!(!valid_redirect_uri("javascript://alert(1)"));
        assert!(!valid_redirect_uri("https://x.com/cb#frag"));
    }

    #[test]
    fn pkce() {
        // RFC 7636 appendix B.
        assert!(pkce_ok("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
        assert!(!pkce_ok("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXX", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
    }
}
