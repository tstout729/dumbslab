//! One workspace: its own SQLite database inside a Durable Object, running the shared core.
//!
//! In multi-tenant hosting the front Worker passes the workspace address in
//! `x-dumbslab-workspace`. An address nobody has signed up for creates no storage: the object
//! answers from memory until a valid sign-up link sets it up.

use std::cell::Cell;

use chrono::Utc;
use dumbslab_core::db::{Db, DbExt};
use dumbslab_core::{ApiError, ApiResult, Effect, HostConfig, Outcome};
use serde_json::{Value, json};
use wasm_bindgen::prelude::*;
use worker::*;

use crate::sql::{DoDb, api_error_response, call_object, error_response, flag, json_response, read_body, transaction, var, var_i64};

/// The header the front Worker uses to tell a workspace object its address.
pub const WORKSPACE_HEADER: &str = "x-dumbslab-workspace";

#[durable_object]
pub struct Workspace {
    state: State,
    env: Env,
    migrated: Cell<bool>,
}

impl Workspace {
    fn db(&self) -> DoDb {
        DoDb { sql: self.state.storage().sql() }
    }

    /// Whether this workspace's schema exists. Reading `sqlite_master` writes nothing.
    fn initialized(&self) -> Result<bool> {
        if self.migrated.get() {
            return Ok(true);
        }
        let rows = self
            .db()
            .query("SELECT COUNT(*) AS n FROM sqlite_master WHERE type = 'table' AND name = 'meta'", &[])
            .map_err(|e| worker::Error::RustError(e.message))?;
        Ok(rows.first().is_some_and(|r| r.i64("n") > 0))
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

    /// Operator actions, reachable only from the front Worker (it never forwards `/_internal`).
    async fn internal(&self, path: &str) -> Result<Response> {
        match path {
            "/_internal/disable" | "/_internal/enable" => {
                if !self.initialized()? {
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
                self.state.storage().delete_all().await?;
                self.migrated.set(false);
                json_response(200, &json!({ "ok": true }))
            }
            _ => error_response(404, "not_found", "not found"),
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
        Self { state, env, migrated: Cell::new(false) }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let url = req.url()?;
        let path = url.path().to_string();
        if path.starts_with("/_internal/") {
            return self.internal(&path).await;
        }
        let method = req.method();
        let origin = match url.port() {
            Some(p) => format!("{}://{}:{p}", url.scheme(), url.host_str().unwrap_or_default()),
            None => format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default()),
        };
        let workspace = req.headers().get(WORKSPACE_HEADER)?;
        // Bound the body before anything else runs: one workspace object serves every request.
        let Some(body) = read_body(&mut req).await? else {
            return error_response(413, "too_large", "request body too large");
        };

        let signup_secret = var(&self.env, "SIGNUP_SECRET");
        // Set when this request creates the workspace: schema and first admin commit together.
        let mut creating = false;
        if let Some(slug) = &workspace {
            if !self.initialized()? {
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
                creating = true;
            } else {
                self.migrate()?;
                if self.disabled()? {
                    return error_response(403, "disabled", "This workspace has been disabled for breaking the acceptable use policy.");
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
            base_url: if multi { Some(origin) } else { var(&self.env, "BASE_URL") },
            setup_token: if multi { None } else { var(&self.env, "SETUP_TOKEN") },
            open_setup: flag(&self.env, "OPEN_SETUP"),
            signup_secret: if multi { signup_secret } else { None },
            workspace: workspace.clone(),
        };

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
                                "This workspace has reached its storage limit. Delete old posts, or export it and self-host DumbSlab for unlimited space.",
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

        for effect in outcome.effects {
            let Effect::Webhook(d) = effect;
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

        let r = outcome.response;
        // 204/304 responses must not have a body at all, not even an empty one.
        let mut resp = if r.body.is_empty() { Response::empty()? } else { Response::from_bytes(r.body)? }.with_status(r.status);
        let h = resp.headers_mut();
        for (k, v) in &r.headers {
            // Replace defaults such as `application/octet-stream`; only cookies repeat.
            if k == "set-cookie" {
                h.append(k, v)?;
            } else {
                h.set(k, v)?;
            }
        }
        Ok(resp)
    }
}
