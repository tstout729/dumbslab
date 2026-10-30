//! One workspace: its own SQLite database inside a Durable Object, running the shared core.
//!
//! In multi-tenant hosting the front Worker passes the workspace address in
//! `x-dumbslab-workspace`. An address nobody has signed up for creates no storage: the object
//! answers from memory until a valid sign-up link sets it up.
//!
//! A workspace keeps its data in the object named after its first address (its "home"). When it
//! moves, the object for the new address only stores a pointer home; the front Worker follows it.
//! The home object sends requests for any address but the current one on to the current one.
//!
//! Hosted workspaces have a plan (see `dumbslab_core::plan`). This object measures the database,
//! refuses changes past the storage allowance, counts the rows each request writes, and reports
//! its usage to the directory, which answers whether the free plan is at capacity.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use chrono::Utc;
use dumbslab_core::db::{Db, DbExt};
use dumbslab_core::plan::{self, Capacity, Plan, Subscription};
use dumbslab_core::{AddressMove, ApiError, ApiResult, Effect, HostConfig, Hosting, Outcome, params, tenancy};
use serde_json::{Value, json};
use wasm_bindgen::prelude::*;
use worker::*;

use crate::sql::{DoDb, api_error_response, call_object, error_response, flag, json_response, read_body, transaction, var};

/// How often, at most, a busy workspace reports its usage to the directory.
const REPORT_EVERY_SECS: i64 = 300;

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
    /// The free plan's capacity, from the directory's answer to this workspace's last report.
    capacity: Rc<Cell<Capacity>>,
    /// When this workspace last reported its usage (Unix seconds).
    reported_at: Cell<i64>,
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
        DoDb::new(self.state.storage().sql())
    }

    /// Tells the directory this workspace's plan, recent writes and size, at most every few
    /// minutes unless `now` is asked for. Its answer says whether the free plan is at capacity.
    fn report_usage(&self, home: &str, now: bool) {
        let at = Utc::now();
        if !now && at.timestamp() - self.reported_at.get() < REPORT_EVERY_SECS {
            return;
        }
        self.reported_at.set(at.timestamp());
        let db = self.db();
        let (Ok(state), Ok(writes)) = (plan::current(&db), plan::writes_24h(&db, at)) else { return };
        let body = json!({ "home": home, "plan": state.plan().as_str(), "writes_24h": writes, "storage_bytes": db.sql.database_size() });
        let (env, capacity) = (self.env.clone(), self.capacity.clone());
        self.state.wait_until(async move {
            if let Ok((200, reply)) = call_object(&env, "DIRECTORY", "directory", Method::Post, "/usage", Some(&body)).await
                && let Ok(c) = serde_json::from_value::<Capacity>(reply)
            {
                capacity.set(c);
            }
        });
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
            // From the front Worker: Stripe reported a subscription, or the operator granted Pro.
            "/_internal/subscription" | "/_internal/grant" => {
                if !matches!(self.stored()?, Stored::Workspace) {
                    return error_response(404, "no_workspace", "no workspace here");
                }
                self.migrate()?;
                let body = req.json::<Value>().await.unwrap_or_default();
                let home = body["home"].as_str().unwrap_or_default().to_string();
                if home.is_empty() {
                    return error_response(400, "bad_request", "send the workspace's home");
                }
                let grant = path.ends_with("grant").then(|| body["granted"].as_bool().unwrap_or(false));
                let sub = match grant {
                    Some(_) => None,
                    None => match serde_json::from_value::<Subscription>(body["subscription"].clone()) {
                        Ok(s) => Some(s),
                        Err(e) => return error_response(400, "bad_request", &format!("invalid subscription: {e}")),
                    },
                };
                let storage = self.state.storage();
                let saved = transaction(&storage, self.db(), move |db| {
                    let r = match (grant, &sub) {
                        (Some(g), _) => plan::set_grant(db, g).map(|_| true),
                        (None, Some(s)) => plan::apply_subscription(db, s),
                        (None, None) => Ok(false),
                    };
                    let ok = r.is_ok();
                    (r, ok)
                })?;
                match saved {
                    Ok(applied) => {
                        self.report_usage(&home, true);
                        json_response(200, &json!({ "ok": true, "applied": applied }))
                    }
                    Err(e) => api_error_response(&e),
                }
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
            capacity: Rc::new(Cell::new(Capacity::default())),
            reported_at: Cell::new(0),
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
        // App registrations are exempt too: their table is capped, and refusing one would undo the
        // count that limits them per hour.
        let exempt = matches!(method, Method::Get | Method::Head | Method::Options)
            || matches!(
                path.as_str(),
                "/api/v1/auth/login"
                    | "/api/v1/auth/logout"
                    | "/api/v1/auth/setup"
                    | "/oauth/token"
                    | "/oauth/revoke"
                    | "/oauth/authorize"
                    | "/oauth/register"
            );

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
        let db = self.db();
        let multi = workspace.is_some();
        let hosting = home.clone().filter(|_| multi).map(|home| Hosting {
            plans: crate::billing::plans(&self.env),
            home,
            storage_bytes: db.sql.database_size() as u64,
            capacity: self.capacity.get(),
        });
        let cfg = HostConfig {
            base_url: if multi { Some(origin.clone()) } else { var(&self.env, "BASE_URL") },
            setup_token: if multi { None } else { var(&self.env, "SETUP_TOKEN") },
            open_setup: flag(&self.env, "OPEN_SETUP"),
            signup_secret: if multi { signup_secret } else { None },
            workspace: workspace.clone(),
            hosting,
        };
        let move_cfg = cfg.clone();

        let storage = self.state.storage();
        let sql = db.sql.clone();
        let result: ApiResult<Option<Outcome>> = transaction(&storage, db.clone(), move |db| {
            if creating && let Err(e) = dumbslab_core::migrate(db) {
                return (Err(e), false);
            }
            let before = sql.database_size() as u64;
            match dumbslab_core::handle(db, &cfg, &core_req) {
                None => (Ok(None), true),
                Some(o) => {
                    // A failed setup leaves no schema behind.
                    let commit = o.commit && (!creating || o.response.status == 200);
                    // Upgrading must work when the workspace is full; its first one stores a billing id.
                    let upgrading = o.effects.iter().any(|e| matches!(e, Effect::Stripe(_)));
                    if let Some(h) = cfg.hosting.as_ref().filter(|_| !exempt && !upgrading) {
                        let after = sql.database_size() as u64;
                        if commit && after > before {
                            let plan = plan::current(db).map(|s| s.plan()).unwrap_or(Plan::Free);
                            let shared_full = plan == Plan::Free && h.capacity.growth_paused;
                            let own_full = after > h.plans.allowance(plan).storage_bytes;
                            if own_full || shared_full {
                                return (Err(plan::storage_full(&h.plans, plan, !own_full)), false);
                            }
                        }
                    }
                    (Ok(Some(o)), commit)
                }
            }
        })?;
        // Hosted workspaces count every row a request's statements wrote, even when it was rolled
        // back, against their plan. Signing in doesn't count: anyone can fail to sign in, and the
        // sign-in limits bound those writes. A sign-up that failed left no table to count in.
        if let Some(h) = move_cfg.hosting.as_ref() {
            let metered = !path.starts_with("/api/v1/auth/")
                && (self.migrated.get() || (creating && matches!(&result, Ok(Some(o)) if o.response.status == 200)));
            if metered
                && db.rows_written() > 0
                && let Err(e) = plan::record_writes(&self.db(), Utc::now(), db.rows_written())
            {
                console_error!("recording usage failed: {}", e.message);
            }
            // A paused workspace writes nothing, so it also reports while paused to learn when
            // the free plan has room again.
            let capacity = self.capacity.get();
            if self.migrated.get() && (db.rows_written() > 0 || capacity.writes_paused || capacity.growth_paused) {
                self.report_usage(&h.home, false);
            }
        }
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
        // upgrade_plan and manage_billing: the answer holds a placeholder for the Stripe page's URL.
        if let Some(Effect::Stripe(call)) = effects.iter().find(|e| matches!(e, Effect::Stripe(_))) {
            let filled = crate::billing::page(&self.env, call).await?.and_then(|url| plan::fill_stripe_url(&outcome.response.body, &url));
            let Some(body) = filled else {
                return error_response(502, "billing_unavailable", "Stripe couldn't open that page just now. Try again in a minute.");
            };
            return to_response(dumbslab_core::Response { body, ..outcome.response });
        }
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
