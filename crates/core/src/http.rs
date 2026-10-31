//! Transport-neutral HTTP routing: auth endpoints, REST routes generated from the registry, the
//! generic operations endpoint, MCP, OAuth and agent docs.

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::auth::{self, Actor, CSRF_HEADER, Role, Via};
use crate::db::{Db, DbExt};
use crate::error::{ApiError, ApiResult};
use crate::model::{USER_COLS, User};
use crate::registry::{Ctx, Op, RouteMatch, registry};
use crate::util::{secure_eq, ts};
use crate::{HostConfig, Outcome, Request, Response, params};

pub const API_PREFIX: &str = "/api/v1";

/// The largest request body a host accepts.
pub const MAX_BODY: usize = 8 * 1024 * 1024;
/// Uploads carry a base64 file: the largest (`files::MAX_FILE_SIZE`, 10 MB) is about 13.3 MB
/// encoded, and line breaks and the rest of the JSON need a little more.
pub const MAX_UPLOAD_BODY: usize = 15 * 1024 * 1024;

/// The largest request body a host should read for `path`, before it knows who's asking. Only
/// the routes that can run `upload_file` get room for a file.
pub fn body_limit(path: &str) -> usize {
    match path.trim_end_matches('/') {
        "/api/v1/files" | "/api/v1/operations/upload_file" | "/mcp" => MAX_UPLOAD_BODY,
        p if p.starts_with("/slack/") => crate::slack::MAX_BODY,
        _ => MAX_BODY,
    }
}

/// A workspace's `/robots.txt`. Workspaces are private, so crawlers stay out of their sign-in pages.
pub const WORKSPACE_ROBOTS_TXT: &str = "User-agent: *\nDisallow: /\n";

/// Whether the core handles this path (everything else is the web app's static files).
pub fn is_core_path(path: &str) -> bool {
    path == "/healthz"
        || path == "/llms.txt"
        || path == "/robots.txt"
        || path == "/mcp"
        || path.starts_with("/oauth/")
        || path.starts_with("/.well-known/oauth")
        || path == API_PREFIX
        || path.starts_with("/api/")
        || path.starts_with("/files/")
        || path.starts_with("/connect/")
        || path.starts_with("/sso/")
        || path.starts_with("/slack/")
        || path.starts_with("/hooks/")
        || path.starts_with("/sync/")
}

/// Handles a request. `None` means the path isn't ours (the host serves static files).
pub fn handle(db: &dyn Db, cfg: &HostConfig, req: &Request) -> Option<Outcome> {
    let path = req.path.as_str();
    let outcome = if path == "/healthz" {
        done(Response::json(200, &json!({ "ok": true, "version": crate::VERSION, "git_sha": crate::GIT_SHA })))
    } else if path == "/llms.txt" {
        done(Response::text(200, "text/plain; charset=utf-8", crate::openapi::llms_txt(&base_url(cfg, req))))
    } else if path == "/robots.txt" {
        done(Response::text(200, "text/plain; charset=utf-8", WORKSPACE_ROBOTS_TXT))
    } else if path == "/mcp" {
        crate::mcp::handle_http(db, cfg, req)
    } else if path.starts_with("/oauth/") || path.starts_with("/.well-known/oauth") {
        crate::oauth::handle(db, cfg, req)
    } else if path.starts_with("/files/") {
        crate::ops::files::serve(db, cfg, req)
    } else if path == "/connect/callback" && req.method == "GET" {
        crate::connect::callback(db, cfg, req)
    } else if path.starts_with("/connect/") {
        failed(&ApiError::not_found("route"))
    } else if path == crate::sso::START_PATH && req.method == "GET" {
        crate::sso::start(db, cfg, req)
    } else if path == crate::sso::CALLBACK_PATH && req.method == "GET" {
        crate::sso::callback(db, cfg, req)
    } else if path.starts_with("/sso/") {
        failed(&ApiError::not_found("route"))
    } else if path.starts_with("/slack/") {
        // Slack's own requests: no session or token, only Slack's signature.
        crate::slack::handle(db, cfg, req)
    } else if path == crate::sync::github_app::INSTALL_PATH && req.method == "GET" {
        crate::sync::github_app::install_start(db, cfg, req)
    } else if path == crate::sync::github_app::CALLBACK_PATH && req.method == "GET" {
        crate::sync::github_app::install_callback(db, cfg, req)
    } else if path == crate::sync::gitlab_app::START_PATH && req.method == "GET" {
        crate::sync::gitlab_app::start(db, cfg, req)
    } else if path == crate::sync::gitlab_app::CALLBACK_PATH && req.method == "GET" {
        crate::sync::gitlab_app::callback(db, cfg, req)
    } else if path.starts_with("/sync/") {
        failed(&ApiError::not_found("route"))
    } else if path.starts_with("/hooks/") {
        no_store(crate::sync::hook(db, cfg, req))
    } else {
        let rest = path.strip_prefix(API_PREFIX)?;
        let r = api(db, cfg, req, rest);
        no_store(r)
    };
    Some(outcome)
}

fn no_store(mut o: Outcome) -> Outcome {
    o.response.headers.push(("cache-control".into(), "no-store".into()));
    o
}

pub fn done(response: Response) -> Outcome {
    Outcome { response, commit: true, effects: vec![] }
}

pub fn failed(err: &ApiError) -> Outcome {
    Outcome { response: Response::error(err), commit: err.keep_writes, effects: vec![] }
}

pub fn base_url(cfg: &HostConfig, req: &Request) -> String {
    cfg.base_url.clone().unwrap_or_else(|| req.origin.clone()).trim_end_matches('/').to_string()
}

/// Whether cookies need `Secure`: the public URL decides when it's configured, so a proxy that
/// doesn't forward the scheme can't strip it.
pub fn secure_cookies(cfg: &HostConfig, req: &Request) -> bool {
    base_url(cfg, req).starts_with("https://")
}

pub fn unauthorized(cfg: &HostConfig, req: &Request, message: &str) -> Outcome {
    // The read-only MCP URL points clients at its own metadata, so the access they ask for (and
    // are granted) is read-only too.
    let read_only = req.path == "/mcp" && crate::mcp::requested_toolset(&req.query) == crate::mcp::Toolset::Read;
    let (resource, scope) = if read_only { ("/mcp?toolset=read", ", scope=\"read\"") } else { ("", "") };
    let metadata = format!("{}/.well-known/oauth-protected-resource{resource}", base_url(cfg, req));
    let mut out = failed(&ApiError::unauthorized(message));
    out.response.headers.push(("www-authenticate".into(), format!("Bearer resource_metadata=\"{metadata}\"{scope}")));
    out
}

fn api(db: &dyn Db, cfg: &HostConfig, req: &Request, rest: &str) -> Outcome {
    let now = Utc::now();
    let session_change = matches!((req.method.as_str(), rest), ("POST", "/auth/setup" | "/auth/login" | "/auth/logout"));
    if session_change && req.header(CSRF_HEADER).is_none() {
        return failed(&ApiError::forbidden(format!("missing the {CSRF_HEADER} header")));
    }
    match (req.method.as_str(), rest) {
        ("GET", "/auth/state") => return auth_state(db, cfg, req),
        ("POST", "/auth/setup") => return setup(db, cfg, req),
        ("POST", "/auth/login") => return login(db, cfg, req),
        ("POST", "/auth/logout") => return logout(db, cfg, req),
        ("GET", "/openapi.json") => return done(Response::json(200, &crate::openapi::spec(&base_url(cfg, req)))),
        _ => {}
    }

    let actor = match auth::authenticate(db, cfg, req, now) {
        Ok(Some(a)) => a,
        Ok(None) => return unauthorized(cfg, req, "sign in or send `Authorization: Bearer <token>`"),
        Err(e) if e.status == 401 => return unauthorized(cfg, req, &e.message),
        Err(e) => return failed(&e),
    };
    let writes = !matches!(req.method.as_str(), "GET" | "HEAD");
    if actor.via == Via::Web && writes && req.header(CSRF_HEADER).is_none() {
        return failed(&ApiError::forbidden(format!("missing the {CSRF_HEADER} header")));
    }

    // Generic endpoint: POST /api/v1/operations/{name} with the input as the JSON body.
    if req.method == "POST"
        && let Some(name) = rest.strip_prefix("/operations/")
    {
        let Some(op) = registry().get(name) else {
            return failed(&ApiError::not_found(format!("operation `{name}`")));
        };
        let input = match parse_body(&req.body) {
            Ok(v) => v,
            Err(e) => return failed(&e),
        };
        return run_op(db, cfg, req, actor, op, input);
    }

    match registry().route(&req.method, rest) {
        RouteMatch::Found(op, path_params) => {
            let input = match build_input(op, req, &path_params) {
                Ok(v) => v,
                Err(e) => return failed(&e),
            };
            run_op(db, cfg, req, actor, op, input)
        }
        RouteMatch::MethodNotAllowed => failed(&ApiError::new(405, "method_not_allowed", "method not allowed for this path")),
        RouteMatch::NotFound => failed(&ApiError::not_found(format!("route {} {}{rest}", req.method, API_PREFIX))),
    }
}

pub fn new_ctx<'a>(db: &'a dyn Db, cfg: &'a HostConfig, req: &Request, actor: Actor) -> Ctx<'a> {
    Ctx { db, actor, now: Utc::now(), cfg, base_url: base_url(cfg, req), effects: vec![] }
}

fn run_op(db: &dyn Db, cfg: &HostConfig, req: &Request, actor: Actor, op: &Op, input: Value) -> Outcome {
    let mut ctx = new_ctx(db, cfg, req, actor);
    match op.call(&mut ctx, input) {
        Ok(value) => Outcome { response: Response::json(200, &value), commit: true, effects: ctx.effects },
        Err(e) => failed(&e),
    }
}

pub fn parse_body(body: &[u8]) -> ApiResult<Value> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Object(Map::new()));
    }
    let v: Value = serde_json::from_slice(body).map_err(|e| ApiError::bad_request(format!("body is not valid JSON: {e}")))?;
    if !v.is_object() {
        return Err(ApiError::bad_request("body must be a JSON object"));
    }
    Ok(v)
}

/// The JSON type a schema property expects (ignoring `null`).
fn prop_type<'a>(schema: &'a Value, key: &str) -> (&'a str, Option<&'a str>) {
    let prop = &schema["properties"][key];
    let pick = |t: &'a Value| -> &'a str {
        match t {
            Value::String(s) => s.as_str(),
            Value::Array(a) => a.iter().filter_map(Value::as_str).find(|s| *s != "null").unwrap_or("string"),
            _ => "string",
        }
    };
    let item = prop.get("items").and_then(|i| i.get("type")).map(pick);
    (prop.get("type").map(pick).unwrap_or("string"), item)
}

fn coerce_scalar(kind: &str, raw: &str) -> Value {
    match kind {
        "integer" => raw.parse::<i64>().map(Value::from).unwrap_or_else(|_| Value::from(raw)),
        "number" => raw.parse::<f64>().map(Value::from).unwrap_or_else(|_| Value::from(raw)),
        "boolean" => match raw {
            "true" | "1" | "yes" => Value::Bool(true),
            "false" | "0" | "no" => Value::Bool(false),
            _ => Value::from(raw),
        },
        _ => Value::from(raw),
    }
}

/// Merges JSON body, query string and path parameters into the operation's input object,
/// converting strings to the types the input schema expects.
pub fn build_input(op: &Op, req: &Request, path_params: &[(String, String)]) -> ApiResult<Value> {
    let mut input = match req.method.as_str() {
        "GET" | "HEAD" => Map::new(),
        _ => match parse_body(&req.body)? {
            Value::Object(m) => m,
            _ => Map::new(),
        },
    };
    for pair in req.query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let k = urlencoding::decode(&k.replace('+', " ")).map(|c| c.into_owned()).unwrap_or_default();
        let v = urlencoding::decode(&v.replace('+', " ")).map(|c| c.into_owned()).unwrap_or_default();
        if k.starts_with('_') {
            continue;
        }
        let (kind, item) = prop_type(&op.input_schema, &k);
        if kind == "array" {
            let items: Vec<Value> = v.split(',').filter(|s| !s.is_empty()).map(|s| coerce_scalar(item.unwrap_or("string"), s)).collect();
            match input.get_mut(&k) {
                Some(Value::Array(existing)) => existing.extend(items),
                _ => {
                    input.insert(k, Value::Array(items));
                }
            }
        } else {
            input.insert(k, coerce_scalar(kind, &v));
        }
    }
    for (k, v) in path_params {
        let (kind, _) = prop_type(&op.input_schema, k);
        input.insert(k.clone(), coerce_scalar(kind, v));
    }
    Ok(Value::Object(input))
}

fn set_cookie(mut out: Outcome, cookie: String) -> Outcome {
    out.response.headers.push(("set-cookie".into(), cookie));
    out
}

fn user_count(db: &dyn Db) -> ApiResult<i64> {
    db.scalar_i64("SELECT COUNT(*) FROM users", &[])
}

fn auth_state(db: &dyn Db, cfg: &HostConfig, req: &Request) -> Outcome {
    let run = || -> ApiResult<Value> {
        let needs_setup = user_count(db)? == 0;
        let user = match auth::authenticate(db, cfg, req, Utc::now()) {
            Ok(Some(a)) => db.one(&format!("SELECT {USER_COLS} FROM users WHERE id = ?"), &params![a.user_id])?.map(|r| User::from_row(&r)),
            _ => None,
        };
        Ok(json!({
            "needs_setup": needs_setup,
            "setup_requires_token": needs_setup && !cfg.open_setup,
            "user": user,
            "workspace_name": crate::ops::admin::setting(db, "workspace_name")?.unwrap_or_else(|| "DumbSlab".into()),
            "version": crate::VERSION,
            "mcp_url": format!("{}/mcp", base_url(cfg, req)),
            "api_url": format!("{}{API_PREFIX}", base_url(cfg, req)),
            // Signing in with the workspace's identity provider, when it's set up.
            "sso": crate::sso::sign_in_option(db, cfg, &base_url(cfg, req))?,
            // Session recordings and browser error reports, or null when the host didn't set them up.
            "telemetry": cfg.telemetry.web_config(cfg.workspace.as_deref()),
        }))
    };
    match run() {
        Ok(v) => done(Response::json(200, &v)),
        Err(e) => failed(&e),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupInput {
    setup_token: Option<String>,
    workspace_name: Option<String>,
    name: String,
    email: String,
    password: String,
}

fn setup(db: &dyn Db, cfg: &HostConfig, req: &Request) -> Outcome {
    let run = || -> ApiResult<Outcome> {
        let input: SetupInput = serde_json::from_value(parse_body(&req.body)?)?;
        if user_count(db)? > 0 {
            return Err(ApiError::conflict("this workspace is already set up; sign in instead"));
        }
        let token = input.setup_token.as_deref().map(str::trim);
        let signed_link = matches!((&cfg.signup_secret, &cfg.workspace, token),
            (Some(secret), Some(ws), Some(t)) if crate::tenancy::verify_signup_token(secret, ws, t, Utc::now().timestamp()));
        let static_token = matches!((&cfg.setup_token, token), (Some(expected), Some(t)) if secure_eq(t, expected));
        let open = cfg.open_setup && cfg.setup_token.is_none() && cfg.signup_secret.is_none();
        if !(signed_link || static_token || open) {
            return Err(ApiError::forbidden(if cfg.signup_secret.is_some() {
                "this sign-up link is invalid or has expired; start again from the sign-up page"
            } else if cfg.setup_token.is_some() {
                "the setup token is missing or wrong; find it in the server log or your deployment's SETUP_TOKEN secret"
            } else {
                "setup is locked: start the server with a setup token"
            }));
        }
        let hash = auth::hash_password(&input.password)?;
        let system = Actor {
            user_id: String::new(),
            name: input.name.clone(),
            handle: String::new(),
            email: input.email.clone(),
            role: Role::Admin,
            scopes: auth::Scopes::ALL,
            via: Via::Web,
            token_id: None,
            session_hash: None,
        };
        let mut ctx = new_ctx(db, cfg, req, system);
        let uid = crate::ops::users::insert_user(&ctx, &input.email, &input.name, None, Role::Admin, Some(hash), false)?;
        let workspace = input.workspace_name.map(|w| w.trim().to_string()).filter(|w| !w.is_empty()).unwrap_or_else(|| "DumbSlab".into());
        crate::ops::admin::put_setting(db, "workspace_name", &workspace)?;
        let row = db
            .one(&format!("SELECT {USER_COLS} FROM users WHERE id = ?"), &params![uid.clone()])?
            .ok_or_else(|| ApiError::internal("user vanished"))?;
        ctx.actor = auth_actor_for(&row);
        crate::seed::seed_workspace(&mut ctx, &workspace)?;
        let token = auth::create_session(db, &uid, req.header("user-agent"), Utc::now())?;
        let out = done(Response::json(200, &json!({ "user": User::from_row(&row) })));
        Ok(set_cookie(out, auth::session_cookie(&token, secure_cookies(cfg, req))))
    };
    run().unwrap_or_else(|e| failed(&e))
}

fn auth_actor_for(row: &crate::db::Row) -> Actor {
    Actor {
        user_id: row.str("id"),
        name: row.str("name"),
        handle: row.str("handle"),
        email: row.str("email"),
        role: Role::parse(&row.str("role")).unwrap_or(Role::Viewer),
        scopes: auth::Scopes::ALL,
        via: Via::Web,
        token_id: None,
        session_hash: None,
    }
}

#[derive(Deserialize)]
struct LoginInput {
    email: String,
    password: String,
}

fn login(db: &dyn Db, cfg: &HostConfig, req: &Request) -> Outcome {
    let now = Utc::now();
    let input: LoginInput = match parse_body(&req.body).and_then(|v| serde_json::from_value(v).map_err(ApiError::from)) {
        Ok(i) => i,
        Err(e) => return failed(&e),
    };
    // Logins are anonymous: refuse oversized input before any work, and keep throttle keys fixed-size.
    if input.email.len() > 254 || input.password.len() > 256 {
        return failed(&ApiError::bad_request("email or password is too long"));
    }
    let keys = auth::password_keys(&input.email, req.client_ip.as_deref());
    let run = || -> ApiResult<Outcome> {
        auth::check_throttle(db, &keys, now)?;
        let row =
            db.one("SELECT id, role, password_hash FROM users WHERE email = ? AND deactivated_at IS NULL", &params![input.email.trim()])?;
        let user_id = match row {
            Some(r) if r.opt_str("password_hash").is_some_and(|h| auth::verify_password(&input.password, &h)) => {
                // A workspace that requires single sign-on takes passwords from admins only.
                if let Some(refused) = crate::sso::password_refusal(db, cfg, Role::parse(&r.str("role")).unwrap_or(Role::Viewer))? {
                    return Err(refused);
                }
                r.str("id")
            }
            Some(_) => {
                auth::record_failures(db, &keys, now)?;
                // Commit the failure count even though the request fails.
                return Ok(Outcome {
                    response: Response::error(&ApiError::unauthorized("email or password is incorrect")),
                    commit: true,
                    effects: vec![],
                });
            }
            None => {
                auth::dummy_verify(&input.password);
                auth::record_failures(db, &keys, now)?;
                return Ok(Outcome {
                    response: Response::error(&ApiError::unauthorized("email or password is incorrect")),
                    commit: true,
                    effects: vec![],
                });
            }
        };
        // Only the account's own count resets; the address and workspace counts run out their window.
        auth::clear_failures(db, &keys[0].0)?;
        let token = auth::create_session(db, &user_id, req.header("user-agent"), now)?;
        db.execute("UPDATE users SET last_seen_at = ? WHERE id = ?", &params![ts(now), user_id.clone()])?;
        let user = db.one(&format!("SELECT {USER_COLS} FROM users WHERE id = ?"), &params![user_id])?.map(|r| User::from_row(&r));
        Ok(set_cookie(done(Response::json(200, &json!({ "user": user }))), auth::session_cookie(&token, secure_cookies(cfg, req))))
    };
    run().unwrap_or_else(|e| failed(&e))
}

fn logout(db: &dyn Db, cfg: &HostConfig, req: &Request) -> Outcome {
    if let Ok(Some(actor)) = auth::authenticate(db, cfg, req, Utc::now())
        && let Some(hash) = actor.session_hash
        && let Err(e) = db.execute("DELETE FROM sessions WHERE token_hash = ?", &params![hash])
    {
        return failed(&e);
    }
    set_cookie(done(Response::json(200, &json!({ "ok": true }))), auth::clear_session_cookie(secure_cookies(cfg, req)))
}
