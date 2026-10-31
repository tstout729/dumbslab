//! DumbSlab on Cloudflare Workers.
//!
//! Two hosting modes:
//! - **Single workspace** (default for self-hosters): every request goes to one Durable Object.
//! - **Multi-tenant** (`MULTI_TENANT = "true"`, used by dumbslab.com): the root domain serves the
//!   sign-up site, and each `name.ROOT_DOMAIN` subdomain is its own workspace with its own
//!   SQLite-backed Durable Object. A `Directory` object tracks addresses and sign-up limits.
//!
//! Each workspace object runs the same core as the native server; every request is one
//! `transactionSync` call, so a failed operation rolls back exactly like it does on SQLite.
//!
//! Requests to a workspace are limited per client network before they reach its object (the
//! `REQUEST_LIMITER` binding), so a flood costs no Durable Object time.

mod billing;
mod connect;
mod directory;
mod reporting;
mod sql;
mod workspace;

pub use directory::Directory;
pub use workspace::Workspace;

use chrono::Utc;
use dumbslab_core::http::{WORKSPACE_ROBOTS_TXT, is_core_path};
use dumbslab_core::sync::github_app::{self, Routed};
use dumbslab_core::tenancy::{self, HostKind};
use dumbslab_core::util::{secure_eq, sha256_hex};
use serde::Deserialize;
use serde_json::{Value, json};
use worker::*;

use crate::sql::{api_error_response, call_object, error_response, flag, json_response, read_body, var};
use crate::workspace::{ALIAS_HEADER, HOME_HEADER, WORKSPACE_HEADER};

#[event(fetch)]
async fn fetch(req: Request, env: Env, ctx: Context) -> Result<Response> {
    let destination = var(&env, "SENTRY_DSN").and_then(|dsn| reporting::Destination::parse(&dsn));
    let result = handle_fetch(req, env).await;
    let failure = match &result {
        Err(_) => Some(reporting::Failure::Runtime),
        Ok(response) if response.status_code() >= 500 => Some(reporting::Failure::ServerResponse),
        _ => None,
    };
    if let (Some(destination), Some(failure)) = (destination, failure) {
        ctx.wait_until(async move {
            // Never log transport errors: they can contain the DSN.
            let _ = reporting::send(destination, failure).await;
        });
    }
    result
}

async fn handle_fetch(req: Request, env: Env) -> Result<Response> {
    let url = req.url()?;
    // Passwords, sign-up links and session cookies never travel over plain HTTP.
    if let Some(target) = tenancy::https_upgrade(url.as_str()) {
        let status = if matches!(req.method(), Method::Get | Method::Head) { 301 } else { 308 };
        return Response::redirect_with_status(Url::parse(&target)?, status);
    }
    let hsts = tenancy::hsts(flag(&env, "MULTI_TENANT"));
    let resp = route(req, env, &url).await?;
    if url.scheme() != "https" || tenancy::is_local_host(url.host_str().unwrap_or_default()) {
        return Ok(resp);
    }
    // Fetched responses have immutable headers; a copy can be changed.
    let headers = resp.headers().clone();
    headers.set("strict-transport-security", hsts)?;
    Ok(resp.with_headers(headers))
}

async fn route(req: Request, env: Env, url: &Url) -> Result<Response> {
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    // Serve one canonical host: www.example.com → example.com.
    if let Some(apex) = host.strip_prefix("www.") {
        let mut target = url.clone();
        target.set_host(Some(apex)).map_err(|e| worker::Error::RustError(e.to_string()))?;
        return Response::redirect_with_status(target, 301);
    }
    let path = url.path().to_string();
    if path.starts_with("/_internal") {
        return error_response(404, "not_found", "not found");
    }

    if !flag(&env, "MULTI_TENANT") {
        if !is_core_path(&path) {
            return env.assets("ASSETS")?.fetch_request(req).await;
        }
        if let Some(limited) = rate_limited(&req, &env).await? {
            return Ok(limited);
        }
        let name = var(&env, "WORKSPACE_NAME").unwrap_or_else(|| "main".into());
        return forward(&env, &name, req, None).await;
    }

    let root = var(&env, "ROOT_DOMAIN").ok_or_else(|| worker::Error::RustError("ROOT_DOMAIN is not set".into()))?;
    match tenancy::host_kind(&host, &root) {
        HostKind::Root => root_site(req, &env, &root, &path).await,
        HostKind::Workspace(slug) if tenancy::validate_slug(&slug).is_ok() => {
            // The same answer for every address, claimed or not, without waking a workspace.
            if path == "/robots.txt" {
                return text_response(WORKSPACE_ROBOTS_TXT.into(), "text/plain; charset=utf-8");
            }
            if !is_core_path(&path) {
                return env.assets("ASSETS")?.fetch_request(req).await;
            }
            if let Some(limited) = rate_limited(&req, &env).await? {
                return Ok(limited);
            }
            forward(&env, &format!("ws:{slug}"), req, Some(&slug)).await
        }
        _ => error_response(404, "no_workspace", &format!("There's no workspace at this address. Create one at https://{root}/")),
    }
}

/// Refuses a request once its client network has sent too many this minute. Each request that
/// gets through costs a Durable Object request, and writes cost more; the plans meter those.
async fn rate_limited(req: &Request, env: &Env) -> Result<Option<Response>> {
    let Ok(limiter) = env.rate_limiter("REQUEST_LIMITER") else {
        return Ok(None);
    };
    let Some(ip) = req.headers().get("cf-connecting-ip")? else {
        return Ok(None);
    };
    match limiter.limit(dumbslab_core::auth::client_network(&ip)).await {
        Ok(outcome) if !outcome.success => {
            let mut resp = error_response(429, "rate_limited", "Too many requests from your network. Wait a minute and try again.")?;
            resp.headers_mut().set("retry-after", "60")?;
            Ok(Some(resp))
        }
        _ => Ok(None),
    }
}

/// Sends a request to a workspace object. Bodies are buffered (and bounded) here: if the object
/// answered while this Worker was still streaming an upload into it, the isolate would restart.
async fn forward(env: &Env, object: &str, mut req: Request, workspace: Option<&str>) -> Result<Response> {
    let body = if matches!(req.method(), Method::Get | Method::Head | Method::Options) {
        None
    } else {
        match read_body(&mut req).await? {
            Some(b) => Some(b),
            None => return error_response(413, "too_large", "request body too large"),
        }
    };
    let resp = send(env, object, &req, body.as_deref(), workspace.map(|slug| (slug, slug))).await?;
    // An address a workspace moved to points at the workspace's home object.
    if let Some(slug) = workspace
        && let Some(home) = resp.headers().get(ALIAS_HEADER)?
    {
        if home.is_empty() || home == slug {
            return error_response(500, "internal", "this address points nowhere");
        }
        return send(env, &format!("ws:{home}"), &req, body.as_deref(), Some((slug, &home))).await;
    }
    Ok(resp)
}

/// One request to a workspace object. `route` is (requested address, the workspace's home address).
async fn send(env: &Env, object: &str, req: &Request, body: Option<&[u8]>, route: Option<(&str, &str)>) -> Result<Response> {
    let stub = env.durable_object("WORKSPACE")?.id_from_name(object)?.get_stub()?;
    let headers = req.headers().clone();
    // Only this Worker may say which workspace a request is for.
    match route {
        Some((slug, home)) => {
            headers.set(WORKSPACE_HEADER, slug)?;
            headers.set(HOME_HEADER, home)?;
        }
        None => {
            headers.delete(WORKSPACE_HEADER)?;
            headers.delete(HOME_HEADER)?;
        }
    }
    let mut init = RequestInit::new();
    init.with_method(req.method())
        .with_headers(headers)
        // Pass redirects (e.g. the OAuth consent 302 back to the client) through to the browser.
        .with_redirect(RequestRedirect::Manual);
    if let Some(body) = body {
        init.with_body(Some(js_sys::Uint8Array::from(body).into()));
    }
    stub.fetch_with_request(Request::new_with_init(req.url()?.as_str(), &init)?).await
}

/// The root domain: the sign-up site, sign-up API and operator API.
async fn root_site(req: Request, env: &Env, root: &str, path: &str) -> Result<Response> {
    let method = req.method();
    match (method, path) {
        (Method::Get | Method::Head, "/") => {
            let mut url = req.url()?;
            url.set_path("/welcome");
            env.assets("ASSETS")?.fetch_request(Request::new(url.as_str(), Method::Get)?).await
        }
        (Method::Get, "/healthz") => {
            json_response(200, &json!({ "ok": true, "version": dumbslab_core::VERSION, "git_sha": dumbslab_core::GIT_SHA }))
        }
        (Method::Get | Method::Head, "/llms.txt") => text_response(tenancy::root_llms_txt(root), "text/plain; charset=utf-8"),
        (Method::Get | Method::Head, "/robots.txt") => text_response(tenancy::root_robots_txt(root), "text/plain; charset=utf-8"),
        (Method::Get | Method::Head, "/sitemap.xml") => text_response(tenancy::root_sitemap_xml(root), "application/xml; charset=utf-8"),
        (Method::Get, "/api/signup/check") => check_address(&req, env).await,
        (Method::Post, "/api/signup") => signup(req, env, root).await,
        (Method::Get, "/api/plans") => billing::offer(env),
        (Method::Get, "/connect/callback") => connect::root_callback_redirect(&req.url()?, root, "/connect/callback"),
        (Method::Get, github_app::CALLBACK_PATH) => connect::root_callback_redirect(&req.url()?, root, github_app::CALLBACK_PATH),
        (Method::Post, "/hooks/github") => github_hook(req, env, root).await,
        (Method::Post, "/api/stripe/webhook") => billing::webhook(req, env).await,
        (_, p) if p.starts_with("/api/operator/") => operator(req, env, p).await,
        // Static files the sign-up page uses.
        (Method::Get | Method::Head, p) if p.rsplit('/').next().is_some_and(|f| f.contains('.')) => {
            env.assets("ASSETS")?.fetch_request(req).await
        }
        (_, p) if is_core_path(p) => error_response(
            404,
            "no_workspace",
            &format!(
                "The API and MCP server live at your workspace's address, e.g. https://acme.{root}/api/v1 and https://acme.{root}/mcp"
            ),
        ),
        _ => {
            let mut url = req.url()?;
            url.set_path("/");
            url.set_query(None);
            Response::redirect(url)
        }
    }
}

/// `POST /hooks/github` on the root domain: GitHub sends every installation's deliveries for
/// DumbSlab's GitHub App here. Once the signature checks out, each goes on unchanged to the
/// workspaces that connected its installation (the directory knows which), and each checks it
/// again. The core decides; this only carries.
async fn github_hook(mut req: Request, env: &Env, root: &str) -> Result<Response> {
    let Some(secret) = var(env, "GITHUB_APP_WEBHOOK_SECRET") else {
        return error_response(404, "not_found", "not found");
    };
    let Some(body) = read_body(&mut req).await? else {
        return error_response(413, "too_large", "request body too large");
    };
    let signature = req.headers().get("x-hub-signature-256")?;
    let event = req.headers().get("x-github-event")?;
    let installation_id = match github_app::route_delivery(&secret, signature.as_deref(), event.as_deref(), &body) {
        Routed::Refused(e) => return api_error_response(&e),
        Routed::Answer(v) => return json_response(200, &v),
        Routed::Forward(id) => id,
    };
    let (status, found) =
        call_object(env, "DIRECTORY", "directory", Method::Post, "/github/targets", Some(&json!({ "installation_id": installation_id })))
            .await?;
    if status != 200 {
        return json_response(status, &found);
    }
    let targets: Vec<(String, String)> = found["workspaces"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|w| Some((w["home"].as_str()?.to_string(), w["address"].as_str()?.to_string())))
        .filter(|(home, address)| tenancy::validate_slug(home).is_ok() && tenancy::validate_slug(address).is_ok())
        .collect();
    let url = req.url()?;
    let port = url.port().map(|p| format!(":{p}")).unwrap_or_default();
    let headers = Headers::new();
    for name in ["content-type", "user-agent", "x-github-event", "x-github-delivery", "x-github-hook-id", "x-hub-signature-256"] {
        if let Some(v) = req.headers().get(name)? {
            headers.set(name, &v)?;
        }
    }
    let sends = targets.iter().map(|(home, address)| {
        let target = format!("{}://{address}.{root}{port}/hooks/github", url.scheme());
        let (headers, body) = (headers.clone(), body.as_slice());
        async move {
            let mut init = RequestInit::new();
            init.with_method(Method::Post).with_headers(headers);
            let forwarded = Request::new_with_init(&target, &init)?;
            send(env, &format!("ws:{home}"), &forwarded, Some(body), Some((address, home))).await.map(|r| r.status_code())
        }
    });
    let delivered =
        futures_util::future::join_all(sends).await.into_iter().filter(|r| matches!(r, Ok(s) if (200..300).contains(s))).count();
    json_response(200, &json!({ "ok": true, "workspaces": targets.len(), "delivered": delivered }))
}

/// A plain-text file for crawlers and agents. It changes only when the Worker deploys.
fn text_response(body: String, content_type: &str) -> Result<Response> {
    let headers = Headers::new();
    headers.set("content-type", content_type)?;
    headers.set("cache-control", "public, max-age=3600")?;
    Ok(Response::ok(body)?.with_headers(headers))
}

/// Whether an address is free, so the sign-up form can say so while someone types. `/api/signup`
/// checks again when they submit.
async fn check_address(req: &Request, env: &Env) -> Result<Response> {
    let url = req.url()?;
    let slug = url.query_pairs().find(|(k, _)| k == "address").map(|(_, v)| v.trim().to_ascii_lowercase()).unwrap_or_default();
    // Malformed and reserved addresses never reach the directory.
    if let Err(message) = tenancy::validate_slug(&slug) {
        return json_response(200, &json!({ "available": false, "message": message }));
    }
    let (status, reply) = call_object(env, "DIRECTORY", "directory", Method::Post, "/available", Some(&json!({ "slug": slug }))).await?;
    json_response(status, &reply)
}

#[derive(Deserialize)]
struct SignupInput {
    workspace_name: String,
    address: String,
}

/// Reserves an address and returns a one-hour sign-up link to the new workspace's setup page.
async fn signup(mut req: Request, env: &Env, root: &str) -> Result<Response> {
    // Like the app's own writes, require the client header (a cross-site form can't send it).
    if req.headers().get("x-dumbslab-client")?.is_none() {
        return error_response(403, "forbidden", "missing the x-dumbslab-client header");
    }
    let Some(secret) = var(env, "SIGNUP_SECRET") else {
        return error_response(503, "unavailable", "sign-ups aren't configured on this server");
    };
    let Some(body) = read_body(&mut req).await? else {
        return error_response(413, "too_large", "request body too large");
    };
    let input: SignupInput = match serde_json::from_slice(&body) {
        Ok(i) => i,
        Err(_) => return error_response(400, "bad_request", "send {\"workspace_name\": \"…\", \"address\": \"…\"}"),
    };
    let slug = input.address.trim().to_ascii_lowercase();
    if let Err(message) = tenancy::validate_slug(&slug) {
        return error_response(400, "bad_request", &message);
    }
    let ip = req.headers().get("cf-connecting-ip")?.unwrap_or_else(|| "unknown".into());
    let ip_hash = sha256_hex(&format!("{secret}:{ip}"));
    let name = input.workspace_name.trim().to_string();
    let (status, reply) = call_object(
        env,
        "DIRECTORY",
        "directory",
        Method::Post,
        "/reserve",
        Some(&json!({ "slug": slug, "name": name, "ip_hash": ip_hash })),
    )
    .await?;
    if status != 200 {
        return json_response(status, &reply);
    }
    let expires = reply["reserved_until"].as_i64().unwrap_or_else(|| Utc::now().timestamp() + 3600);
    let token = tenancy::signup_token(&secret, &slug, expires);
    let url = req.url()?;
    let scheme = url.scheme();
    let port = url.port().map(|p| format!(":{p}")).unwrap_or_default();
    let setup_url = format!("{scheme}://{slug}.{root}{port}/setup?token={token}&name={}", urlencoding::encode(&name));
    json_response(200, &json!({ "address": format!("{slug}.{root}"), "setup_url": setup_url }))
}

/// Operator API: `Authorization: Bearer $OPERATOR_TOKEN`.
///
/// - `GET  /api/operator/workspaces`: every workspace with its plan and usage, and the free plan's totals.
/// - `POST /api/operator/workspaces/{address}/disable` (or `enable`, `delete`). Any of a
///   workspace's addresses works; `delete` frees all of them, and refuses while someone pays.
/// - `POST /api/operator/workspaces/{address}/grant-pro` (or `revoke-pro`): Pro without paying.
async fn operator(req: Request, env: &Env, path: &str) -> Result<Response> {
    let Some(expected) = var(env, "OPERATOR_TOKEN") else {
        return error_response(404, "not_found", "not found");
    };
    let provided = req.headers().get("authorization")?.and_then(|h| h.strip_prefix("Bearer ").map(str::to_string));
    if !provided.is_some_and(|t| secure_eq(t.trim(), &expected)) {
        return error_response(401, "unauthorized", "operator token required");
    }
    let rest = path.trim_start_matches("/api/operator/workspaces").trim_matches('/');
    if req.method() == Method::Get && rest.is_empty() {
        let (status, body) = call_object(env, "DIRECTORY", "directory", Method::Get, "/list", None).await?;
        return json_response(status, &body);
    }
    let (slug, action) = match rest.split_once('/') {
        Some((s, a)) if req.method() == Method::Post && tenancy::validate_slug(s).is_ok() => (s.to_string(), a.to_string()),
        _ => return error_response(404, "not_found", "unknown operator route"),
    };
    // A workspace's data lives in the object named after its first address (its home).
    let (status, found) = call_object(env, "DIRECTORY", "directory", Method::Post, "/resolve", Some(&json!({ "slug": slug }))).await?;
    if status != 200 {
        return json_response(status, &found);
    }
    let home = found["home"].as_str().unwrap_or_default().to_string();
    // The workspace's answer decides the directory change: 404 means the address was reserved
    // but never set up.
    let directory: (&str, Value) = match action.as_str() {
        "grant-pro" | "revoke-pro" => {
            let body = json!({ "home": home, "granted": action == "grant-pro" });
            let (status, reply) =
                call_object(env, "WORKSPACE", &format!("ws:{home}"), Method::Post, "/_internal/grant", Some(&body)).await?;
            return json_response(status, &reply);
        }
        "delete" if found["paying"] == json!(true) => {
            return error_response(
                409,
                "paying",
                &format!("{home} has a paid Pro subscription. Cancel it in the Stripe Dashboard first, or it keeps charging."),
            );
        }
        "disable" => {
            // The directory first, so no sign-up link passes its check from now on (disabling a
            // reservation kills its link). Then the object, which also stops a sign-up already past
            // that check: 404 means nobody had finished setting it up.
            let (status, body) =
                call_object(env, "DIRECTORY", "directory", Method::Post, "/status", Some(&json!({ "slug": home, "status": "disabled" })))
                    .await?;
            if status != 200 {
                return json_response(status, &body);
            }
            return match internal_call(env, &home, "/_internal/disable").await? {
                200 | 404 => json_response(200, &json!({ "ok": true })),
                status => error_response(status, "failed", "the workspace couldn't be disabled; try again"),
            };
        }
        "enable" => match internal_call(env, &home, "/_internal/enable").await? {
            200 => ("/status", json!({ "slug": home, "status": "active" })),
            404 => ("/status", json!({ "slug": home, "status": "reserved" })),
            status => return error_response(status, "failed", "the workspace couldn't be enabled"),
        },
        "delete" => {
            // The home object first: it refuses while a move is under way, and once it's empty the
            // workspace can't move again, so the address list read after it is final.
            let status = internal_call(env, &home, "/_internal/delete").await?;
            if status != 200 {
                return error_response(status, "failed", &format!("{home} couldn't be deleted; try again"));
            }
            let (_, found) = call_object(env, "DIRECTORY", "directory", Method::Post, "/resolve", Some(&json!({ "slug": home }))).await?;
            for address in found["addresses"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                let status = internal_call(env, address, "/_internal/delete").await?;
                if status != 200 {
                    return error_response(status, "failed", &format!("{address} couldn't be deleted; try again"));
                }
            }
            ("/remove", json!({ "slug": home }))
        }
        _ => return error_response(404, "not_found", "use disable, enable or delete"),
    };
    let (status, body) = call_object(env, "DIRECTORY", "directory", Method::Post, directory.0, Some(&directory.1)).await?;
    json_response(status, &body)
}

/// Calls an operator action on the object for one address and returns its status.
async fn internal_call(env: &Env, address: &str, path: &str) -> Result<u16> {
    let stub = env.durable_object("WORKSPACE")?.id_from_name(&format!("ws:{address}"))?.get_stub()?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    let resp = stub.fetch_with_request(Request::new_with_init(&format!("https://internal{path}"), &init)?).await?;
    Ok(resp.status_code())
}
