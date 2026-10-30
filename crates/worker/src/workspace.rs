//! One workspace: its own SQLite database inside a Durable Object, running the shared core.
//!
//! In multi-tenant hosting the front Worker passes the workspace address in
//! `x-dumbslab-workspace`. An address nobody has signed up for creates no storage: the object
//! answers from memory until a valid sign-up link sets it up.
//!
//! A workspace keeps its data in the object named after its first address (its "home"). When it
//! moves, the object for the new address only stores a pointer home; the front Worker follows it.
//! The home object sends requests for any address but the current one on to the current one.

use std::cell::{Cell, RefCell};

use chrono::Utc;
use dumbslab_core::db::{Db, DbExt};
use dumbslab_core::{AddressMove, ApiError, ApiResult, Effect, HostConfig, Outcome, params, tenancy};
use serde_json::{Value, json};
use wasm_bindgen::prelude::*;
use worker::*;

use crate::sql::{DoDb, api_error_response, call_object, error_response, flag, json_response, read_body, transaction, var, var_i64};

/// The header the front Worker uses to tell a workspace object its address.
pub const WORKSPACE_HEADER: &str = "x-dumbslab-workspace";
/// The workspace's first address, which names the object holding its data. Set by the front Worker.
pub const HOME_HEADER: &str = "x-dumbslab-home";
/// How an address a workspace moved to answers: it names the workspace's home, and the front
/// Worker sends the request there. It never reaches a client.
pub const ALIAS_HEADER: &str = "x-dumbslab-alias-of";

/// What an object stores.
enum Stored {
    Nothing,
    Workspace,
    /// An address a workspace moved to; the workspace's home address.
    Alias(String),
}

#[durable_object]
pub struct Workspace {
    state: State,
    env: Env,
    migrated: Cell<bool>,
    alias: RefCell<Option<String>>,
    moving: Cell<bool>,
    /// Set when an operator disables this address before anyone set it up. A sign-up that passed
    /// its directory check just before then is still in flight here, and must not finish.
    setup_blocked: Cell<bool>,
}

fn rust_err(e: ApiError) -> worker::Error {
    worker::Error::RustError(e.message)
}

/// Converts a core response, replacing defaults such as `application/octet-stream`. Only cookies repeat.
fn to_response(r: dumbslab_core::Response) -> Result<Response> {
    // 204/304 responses must not have a body at all, not even an empty one.
    let mut resp = if r.body.is_empty() { Response::empty()? } else { Response::from_bytes(r.body)? }.with_status(r.status);
    let h = resp.headers_mut();
    for (k, v) in &r.headers {
        if k == "set-cookie" {
            h.append(k, v)?;
        } else {
            h.set(k, v)?;
        }
    }
    Ok(resp)
}

impl Workspace {
    fn db(&self) -> DoDb {
        DoDb { sql: self.state.storage().sql() }
    }

    /// What this object stores. Reading `sqlite_master` writes nothing.
    fn stored(&self) -> Result<Stored> {
        if self.migrated.get() {
            return Ok(Stored::Workspace);
        }
        if let Some(home) = self.alias.borrow().clone() {
            return Ok(Stored::Alias(home));
        }
        let tables =
            self.db().query("SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('meta', 'alias')", &[]).map_err(rust_err)?;
        if tables.iter().any(|r| r.str("name") == "meta") {
            return Ok(Stored::Workspace);
        }
        if tables.iter().any(|r| r.str("name") == "alias") {
            let home = self.db().one("SELECT home FROM alias", &[]).map_err(rust_err)?.map(|r| r.str("home")).unwrap_or_default();
            *self.alias.borrow_mut() = Some(home.clone());
            return Ok(Stored::Alias(home));
        }
        Ok(Stored::Nothing)
    }

    fn migrate(&self) -> Result<()> {
        if self.migrated.get() {
            return Ok(());
        }
        let storage = self.state.storage();
        let failed = transaction(&storage, self.db(), |db| match dumbslab_core::migrate(db) {
            Ok(()) => (None, true),
            Err(e) => (Some(e.message), false),
        })?;
        if let Some(message) = failed {
            console_error!("migration failed: {message}");
            return Err(worker::Error::RustError(message));
        }
        self.migrated.set(true);
        Ok(())
    }

    fn disabled(&self) -> Result<bool> {
        let row =
            self.db().one("SELECT value FROM settings WHERE key = 'disabled'", &[]).map_err(|e| worker::Error::RustError(e.message))?;
        Ok(row.is_some_and(|r| r.str("value") == "1"))
    }

    /// Operator actions and address moves, reachable only from the front Worker and other objects
    /// (the Worker never forwards `/_internal`).
    async fn internal(&self, path: &str, req: &mut Request) -> Result<Response> {
        match path {
            "/_internal/alias" => {
                let home = req.json::<Value>().await.ok().and_then(|v| v["home"].as_str().map(str::to_string)).unwrap_or_default();
                if home.is_empty() {
                    return error_response(400, "bad_request", "send {\"home\": \"…\"}");
                }
                match self.stored()? {
                    Stored::Workspace => return error_response(409, "conflict", "this address holds a workspace"),
                    Stored::Alias(h) if h != home => return error_response(409, "conflict", "this address belongs to another workspace"),
                    _ => {}
                }
                let storage = self.state.storage();
                let pointer = home.clone();
                let saved = transaction(&storage, self.db(), move |db| {
                    let r = db
                        .execute_batch("CREATE TABLE IF NOT EXISTS alias (home TEXT NOT NULL)")
                        .and_then(|_| db.execute("DELETE FROM alias", &[]))
                        .and_then(|_| db.execute("INSERT INTO alias (home) VALUES (?)", &params![pointer]));
                    let ok = r.is_ok();
                    (r, ok)
                })?;
                saved.map_err(rust_err)?;
                *self.alias.borrow_mut() = Some(home);
                json_response(200, &json!({ "ok": true }))
            }
            "/_internal/disable" | "/_internal/enable" => {
                if !matches!(self.stored()?, Stored::Workspace) {
                    self.setup_blocked.set(path.ends_with("disable"));
                    return error_response(404, "no_workspace", "no workspace here");
                }
                self.migrate()?;
                let sql = if path.ends_with("disable") {
                    "INSERT INTO settings (key, value) VALUES ('disabled', '1') ON CONFLICT(key) DO UPDATE SET value = '1'"
                } else {
                    "DELETE FROM settings WHERE key = 'disabled'"
                };
                self.db().execute(sql, &[]).map_err(|e| worker::Error::RustError(e.message))?;
                json_response(200, &json!({ "ok": true }))
            }
            "/_internal/delete" => {
                // The operator deletes the home object first and then reads the final address
                // list, so no move may be half done.
                if self.moving.get() {
                    return error_response(409, "conflict", "the workspace is changing its address; try again");
                }
                self.state.storage().delete_all().await?;
                self.migrated.set(false);
                *self.alias.borrow_mut() = None;
                json_response(200, &json!({ "ok": true }))
            }
            _ => error_response(404, "not_found", "not found"),
        }
    }

    /// Moves the workspace: claims the new address in the directory, points it here, then records
    /// the move. A failure part-way leaves the workspace at its current address, and trying again
    /// finishes the job. Returns the move's webhook deliveries, or the response to send instead.
    async fn move_address(
        &self,
        mv: &AddressMove,
        home: &str,
        origin: &str,
        cfg: &HostConfig,
    ) -> Result<std::result::Result<Vec<Effect>, Response>> {
        if self.moving.replace(true) {
            return Ok(Err(error_response(409, "conflict", "The workspace is already changing its address. Try again in a moment.")?));
        }
        let result = self.move_steps(mv, home, origin, cfg).await;
        self.moving.set(false);
        result
    }

    async fn move_steps(
        &self,
        mv: &AddressMove,
        home: &str,
        origin: &str,
        cfg: &HostConfig,
    ) -> Result<std::result::Result<Vec<Effect>, Response>> {
        let claim = json!({ "home": home, "to": mv.to });
        let (status, reply) = call_object(&self.env, "DIRECTORY", "directory", Method::Post, "/move", Some(&claim)).await?;
        if status != 200 {
            return Ok(Err(json_response(status, &reply)?));
        }
        // The home address needs no pointer: this object answers it directly.
        if mv.to != home {
            let pointer = json!({ "home": home });
            let (status, _) =
                call_object(&self.env, "WORKSPACE", &format!("ws:{}", mv.to), Method::Post, "/_internal/alias", Some(&pointer)).await?;
            if status != 200 {
                return Ok(Err(error_response(500, "move_failed", "The new address couldn't be set up. Try again.")?));
            }
        }
        let new_origin = tenancy::origin_for(origin, &mv.from, &mv.to);
        let (cfg, mv) = (cfg.clone(), mv.clone());
        let storage = self.state.storage();
        let recorded = transaction(&storage, self.db(), move |db| {
            let r = tenancy::finish_move(db, &cfg, &mv, &new_origin);
            let ok = r.is_ok();
            (r, ok)
        })?;
        match recorded {
            Ok(effects) => Ok(Ok(effects)),
            Err(e) => Ok(Err(api_error_response(&e)?)),
        }
    }

    /// Answers for an address nobody has set up yet, without creating storage.
    fn unclaimed(&self, method: &Method, path: &str, url: &Url, origin: &str, slug: &str) -> Result<Response> {
        let root = var(&self.env, "ROOT_DOMAIN").unwrap_or_default();
        let port = url.port().map(|p| format!(":{p}")).unwrap_or_default();
        let signup_url = format!("{}://{root}{port}/", url.scheme());
        if *method == Method::Get && path == "/api/v1/auth/state" {
            return json_response(
                200,
                &json!({
                    "needs_setup": true,
                    "setup_requires_token": true,
                    "exists": false,
                    "user": null,
                    "workspace_name": slug,
                    "version": dumbslab_core::VERSION,
                    "mcp_url": format!("{origin}/mcp"),
                    "api_url": format!("{origin}/api/v1"),
                    "signup_url": signup_url,
                }),
            );
        }
        error_response(404, "no_workspace", &format!("There's no workspace at this address. Create one at {signup_url}"))
    }
}

impl DurableObject for Workspace {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            migrated: Cell::new(false),
            alias: RefCell::new(None),
            moving: Cell::new(false),
            setup_blocked: Cell::new(false),
        }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let url = req.url()?;
        let path = url.path().to_string();
        if path.starts_with("/_internal/") {
            return self.internal(&path, &mut req).await;
        }
        let method = req.method();
        let origin = match url.port() {
            Some(p) => format!("{}://{}:{p}", url.scheme(), url.host_str().unwrap_or_default()),
            None => format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default()),
        };
        let workspace = req.headers().get(WORKSPACE_HEADER)?;
        // An address a workspace moved to: the front Worker sends the request on to its home.
        if workspace.is_some()
            && let Stored::Alias(home) = self.stored()?
        {
            let mut resp = Response::empty()?.with_status(204);
            resp.headers_mut().set(ALIAS_HEADER, &home)?;
            return Ok(resp);
        }
        let home = req.headers().get(HOME_HEADER)?.or_else(|| workspace.clone());
        // Bound the body before anything else runs: one workspace object serves every request.
        let Some(body) = read_body(&mut req).await? else {
            return error_response(413, "too_large", "request body too large");
        };

        let signup_secret = var(&self.env, "SIGNUP_SECRET");
        // Set when this request creates the workspace: schema and first admin commit together.
        let mut creating = false;
        if let Some(slug) = &workspace {
            if matches!(self.stored()?, Stored::Nothing) {
                // Only a valid sign-up link may create the workspace's storage.
                let token =
                    serde_json::from_slice::<Value>(&body).ok().and_then(|v| v["setup_token"].as_str().map(|t| t.trim().to_string()));
                let signed = method == Method::Post
                    && path == "/api/v1/auth/setup"
                    && matches!((&signup_secret, &token), (Some(secret), Some(t))
                        if dumbslab_core::tenancy::verify_signup_token(secret, slug, t, Utc::now().timestamp()));
                if !signed {
                    return self.unclaimed(&method, &path, &url, &origin, slug);
                }
                // The link must also name the address's live reservation, so links for deleted,
                // disabled or already-used addresses stop working.
                let expires = token.as_deref().and_then(|t| t.split_once('.')).and_then(|(e, _)| e.parse::<i64>().ok()).unwrap_or(0);
                let (status, reply) = call_object(
                    &self.env,
                    "DIRECTORY",
                    "directory",
                    Method::Post,
                    "/check",
                    Some(&json!({ "slug": slug, "expires": expires })),
                )
                .await?;
                if status != 200 || reply["ok"] != json!(true) {
                    return error_response(403, "forbidden", "This sign-up link is no longer valid. Start again from the sign-up page.");
                }
                // A workspace may have moved to this address while the check was running.
                if !matches!(self.stored()?, Stored::Nothing) {
                    return error_response(409, "conflict", "This address was just taken. Start again from the sign-up page.");
                }
                // Or an operator disabled it. Nothing awaits between here and the commit.
                if self.setup_blocked.get() {
                    return error_response(403, "forbidden", "This sign-up link is no longer valid. Start again from the sign-up page.");
                }
                creating = true;
            } else {
                self.migrate()?;
                if self.disabled()? {
                    return error_response(403, "disabled", "This workspace has been disabled for breaking the acceptable use policy.");
                }
                // Reached through an address the workspace moved away from: send people on.
                let current = tenancy::moved_to(&self.db()).map_err(rust_err)?.or_else(|| home.clone()).unwrap_or_else(|| slug.clone());
                if *slug != current {
                    let accept = req.headers().get("accept")?.unwrap_or_default();
                    let target = match url.query() {
                        Some(q) => format!("{path}?{q}"),
                        None => path.clone(),
                    };
                    let new_origin = tenancy::origin_for(&origin, slug, &current);
                    return to_response(tenancy::moved_response(method.as_ref(), &accept, &new_origin, &target, &current));
                }
            }
        } else {
            self.migrate()?;
        }

        // Writes may not grow a full workspace. Reads and sign-in always work, and deletes free space.
        let exempt = matches!(method, Method::Get | Method::Head | Method::Options)
            || matches!(
                path.as_str(),
                "/api/v1/auth/login" | "/api/v1/auth/logout" | "/api/v1/auth/setup" | "/oauth/token" | "/oauth/revoke" | "/oauth/authorize"
            );
        let quota = (workspace.is_some() && !exempt).then(|| var_i64(&self.env, "WORKSPACE_STORAGE_MB", 50).max(1) as usize * 1024 * 1024);

        let headers: Vec<(String, String)> = req.headers().entries().map(|(k, v)| (k.to_lowercase(), v)).collect();
        let core_req = dumbslab_core::Request {
            method: method.to_string(),
            path: path.clone(),
            query: url.query().unwrap_or_default().to_string(),
            client_ip: headers.iter().find(|(k, _)| k == "cf-connecting-ip").map(|(_, v)| v.clone()),
            headers,
            body,
            origin: origin.clone(),
        };
        let multi = workspace.is_some();
        let cfg = HostConfig {
            base_url: if multi { Some(origin.clone()) } else { var(&self.env, "BASE_URL") },
            setup_token: if multi { None } else { var(&self.env, "SETUP_TOKEN") },
            open_setup: flag(&self.env, "OPEN_SETUP"),
            signup_secret: if multi { signup_secret } else { None },
            workspace: workspace.clone(),
        };
        let move_cfg = cfg.clone();

        let storage = self.state.storage();
        let sql = self.db().sql;
        let result: ApiResult<Option<Outcome>> = transaction(&storage, self.db(), move |db| {
            if creating && let Err(e) = dumbslab_core::migrate(db) {
                return (Err(e), false);
            }
            let before = sql.database_size();
            match dumbslab_core::handle(db, &cfg, &core_req) {
                None => (Ok(None), true),
                Some(o) => {
                    // A failed setup leaves no schema behind.
                    let commit = o.commit && (!creating || o.response.status == 200);
                    if let Some(limit) = quota {
                        let after = sql.database_size();
                        if commit && after > before && after > limit {
                            let full = ApiError::new(
                                507,
                                "storage_full",
                                "This workspace has reached its storage limit. Delete old posts or uploaded files, or export it and self-host DumbSlab for unlimited space.",
                            );
                            return (Err(full), false);
                        }
                    }
                    (Ok(Some(o)), commit)
                }
            }
        })?;
        let outcome = match result {
            Ok(Some(o)) => o,
            Ok(None) => return error_response(404, "not_found", "not found"),
            Err(e) => return api_error_response(&e),
        };
        if creating && outcome.response.status == 200 {
            self.migrated.set(true);
        }

        // A new workspace's first admin exists: mark its address active in the directory.
        if let Some(slug) = workspace.filter(|_| path == "/api/v1/auth/setup" && outcome.response.status == 200) {
            let env = self.env.clone();
            self.state.wait_until(async move {
                let _ = call_object(&env, "DIRECTORY", "directory", Method::Post, "/activate", Some(&json!({ "slug": slug }))).await;
            });
        }

        let mut effects = outcome.effects;
        if let Some(i) = effects.iter().position(|e| matches!(e, Effect::MoveAddress(_))) {
            let Effect::MoveAddress(mv) = effects.remove(i) else { unreachable!() };
            let home = home.clone().unwrap_or_else(|| mv.from.clone());
            match self.move_address(&mv, &home, &origin, &move_cfg).await? {
                Ok(more) => effects.extend(more),
                Err(resp) => return Ok(resp),
            }
        }

        for effect in effects {
            let Effect::Webhook(d) = effect else { continue };
            let db = self.db();
            self.state.wait_until(async move {
                let headers = Headers::new();
                for (k, v) in &d.headers {
                    let _ = headers.set(k, v);
                }
                let mut init = RequestInit::new();
                init.with_method(Method::Post).with_headers(headers).with_body(Some(JsValue::from_str(&d.body)));
                let result = match Request::new_with_init(&d.url, &init) {
                    Ok(r) => Fetch::Request(r).send().await,
                    Err(e) => Err(e),
                };
                let (status, error) = match result {
                    Ok(resp) if (200..300).contains(&resp.status_code()) => (Some(resp.status_code()), None),
                    Ok(resp) => (Some(resp.status_code()), Some(format!("HTTP {}", resp.status_code()))),
                    Err(e) => (None, Some(e.to_string())),
                };
                let _ = dumbslab_core::record_webhook_result(&db, &d.webhook_id, status, error.as_deref());
            });
        }

        to_response(outcome.response)
    }
}
