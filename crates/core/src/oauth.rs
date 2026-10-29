//! OAuth 2.1 authorization server for MCP clients: discovery metadata, dynamic client
//! registration, authorization code + PKCE (S256), refresh token rotation and revocation.
//! Access tokens are rows in `api_tokens` (kind `oauth`), so people can see and revoke them.

use std::collections::HashMap;

use base64::Engine;
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::auth::{self, Actor, Role, Scopes, Via};
use crate::db::{Db, DbExt};
use crate::error::ApiError;
use crate::http::{base_url, done, new_ctx};
use crate::mcp::cors;
use crate::ops::users::mint_token;
use crate::util::{html_escape, new_id, new_secret, parse_ts, secure_eq, sha256_hex, ts};
use crate::{HostConfig, Outcome, Request, Response, params};

const ACCESS_TOKEN_SECONDS: i64 = 3600;
const REFRESH_TOKEN_DAYS: i64 = 60;
const CODE_MINUTES: i64 = 10;
/// Registered (dynamic) clients kept per workspace.
pub const MAX_CLIENTS: i64 = 1000;
/// How long opening a client's consent page protects it from eviction.
pub const CONSENT_PROTECTION_MINUTES: i64 = 15;

pub fn handle(db: &dyn Db, cfg: &HostConfig, req: &Request) -> Outcome {
    let base = base_url(cfg, req);
    if req.method == "OPTIONS" {
        return cors(done(Response::empty(204)));
    }
    let out = match (req.method.as_str(), req.path.as_str()) {
        ("GET", p) if p.starts_with("/.well-known/oauth-protected-resource") => done(Response::json(
            200,
            &json!({
                "resource": format!("{base}/mcp"),
                "authorization_servers": [base],
                "scopes_supported": ["read", "write", "admin"],
                "bearer_methods_supported": ["header"],
                "resource_name": "DumbSlab",
                "resource_documentation": format!("{base}/llms.txt"),
            }),
        )),
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
        ("POST", "/oauth/register") => register(db, req),
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

fn register(db: &dyn Db, req: &Request) -> Outcome {
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

struct AuthRequest {
    client_id: String,
    client_name: String,
    redirect_uri: String,
    state: String,
    code_challenge: String,
    scopes: Scopes,
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

fn parse_auth_request(db: &dyn Db, p: &HashMap<String, String>) -> Result<Result<AuthRequest, Outcome>, String> {
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
    let scopes = match p.get("scope").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(s) => match Scopes::parse(&s.split(' ').filter(|w| matches!(*w, "read" | "write" | "admin")).collect::<Vec<_>>().join(" ")) {
            Ok(sc) if sc.read => sc,
            _ => Scopes::parse("read write").expect("valid"),
        },
        None => Scopes::parse("read write").expect("valid"),
    };
    Ok(Ok(AuthRequest { client_id: p["client_id"].clone(), client_name, redirect_uri, state, code_challenge: challenge, scopes }))
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

fn session_actor(db: &dyn Db, req: &Request) -> Option<Actor> {
    match auth::authenticate(db, req, Utc::now()) {
        Ok(Some(a)) if a.via == Via::Web => Some(a),
        _ => None,
    }
}

fn authorize_page(db: &dyn Db, cfg: &HostConfig, req: &Request) -> Outcome {
    let p = parse_form(&req.query);
    let ar = match parse_auth_request(db, &p) {
        Err(msg) => return error_page(&msg),
        Ok(Err(redirect)) => return redirect,
        Ok(Ok(ar)) => ar,
    };
    let Some(actor) = session_actor(db, req) else {
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
    let _ = cfg;
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
    let ar = match parse_auth_request(db, &p) {
        Err(msg) => return error_page(&msg),
        Ok(Err(redirect)) => return redirect,
        Ok(Ok(ar)) => ar,
    };
    let Some(actor) = session_actor(db, req) else {
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
    if let Err(e) = db.execute(
        "INSERT INTO oauth_codes (code_hash, client_id, user_id, redirect_uri, code_challenge, scopes, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        &params![sha256_hex(&code), ar.client_id, actor.user_id.clone(), ar.redirect_uri.clone(), ar.code_challenge, scopes.to_str(), ts(now + Duration::minutes(CODE_MINUTES))],
    ) {
        return crate::http::failed(&e);
    }
    let _ = db.execute("DELETE FROM oauth_codes WHERE expires_at < ?", &params![ts(now)]);
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

fn issue_tokens(db: &dyn Db, cfg: &HostConfig, req: &Request, user_id: &str, client_id: &str, scopes: Scopes) -> Result<Value, ApiError> {
    let actor = user_actor(db, user_id).ok_or_else(|| ApiError::bad_request("account is deactivated"))?;
    let scopes = effective_scopes(&actor, scopes);
    let client_name = db
        .one("SELECT client_name FROM oauth_clients WHERE client_id = ?", &params![client_id])?
        .map(|r| r.str("client_name"))
        .unwrap_or_else(|| "MCP client".into());
    let ctx = new_ctx(db, cfg, req, actor);
    let expires = ts(ctx.now + Duration::seconds(ACCESS_TOKEN_SECONDS));
    let (token_id, access) =
        mint_token(&ctx, user_id, &format!("{client_name} (connected app)"), scopes, "oauth", Some(client_id), Some(expires))?;
    let refresh = new_secret("ds_ort_");
    db.execute(
        "INSERT INTO oauth_refresh_tokens (token_hash, client_id, user_id, scopes, access_token_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        &params![sha256_hex(&refresh), client_id, user_id, scopes.to_str(), token_id, ctx.now_s(), ts(ctx.now + Duration::days(REFRESH_TOKEN_DAYS))],
    )?;
    // Housekeeping: drop long-expired connected-app tokens whose grant has also ended.
    db.execute(
        "DELETE FROM api_tokens WHERE kind = 'oauth' AND expires_at < ?
           AND id NOT IN (SELECT access_token_id FROM oauth_refresh_tokens
                          WHERE access_token_id IS NOT NULL AND revoked_at IS NULL AND expires_at > ?)",
        &params![ts(ctx.now - Duration::days(7)), ctx.now_s()],
    )?;
    Ok(json!({
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_SECONDS,
        "refresh_token": refresh,
        "scope": scopes.to_str(),
    }))
}

fn token(db: &dyn Db, cfg: &HostConfig, req: &Request) -> Outcome {
    let p = body_params(req);
    let now = Utc::now();
    let client_id = p.get("client_id").cloned().unwrap_or_default();
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
            let scopes = Scopes::parse(&row.str("scopes")).unwrap_or(Scopes { read: true, write: false, admin: false });
            issue_tokens(db, cfg, req, &row.str("user_id"), &client_id, scopes)
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
            // Rotate: the old refresh token and its access token stop working.
            let _ =
                db.execute("UPDATE oauth_refresh_tokens SET revoked_at = ? WHERE token_hash = ?", &params![ts(now), row.str("token_hash")]);
            let _ = db.execute(
                "UPDATE api_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?",
                &params![ts(now), row.opt_str("access_token_id")],
            );
            let scopes = Scopes::parse(&row.str("scopes")).unwrap_or(Scopes { read: true, write: false, admin: false });
            issue_tokens(db, cfg, req, &row.str("user_id"), &row.str("client_id"), scopes)
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
