//! DumbSlab core: everything except the transport and the storage engine.
//!
//! A host (the native server or the Cloudflare Worker) turns an incoming HTTP request into a
//! [`Request`], opens a database transaction, calls [`handle`], commits or rolls back according
//! to [`Outcome::commit`], and then performs the returned [`Effect`]s (webhook deliveries).
//!
//! Every capability is an operation in [`registry`]. Each one is exposed the same way over REST
//! (`/api/v1/...`), the generic operations endpoint (`/api/v1/operations/{name}`), MCP (`/mcp`)
//! and the CLI, so agents can do anything a person can do in the web app.

pub mod auth;
pub mod db;
pub mod error;
pub mod events;
pub mod http;
pub mod markdown;
pub mod mcp;
pub mod model;
pub mod notify;
pub mod oauth;
pub mod openapi;
pub mod ops;
pub mod registry;
pub mod search;
pub mod seed;
pub mod util;

pub use db::{Db, Row, SqlValue, migrate};
pub use error::{ApiError, ApiResult};
pub use http::handle;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PRODUCT: &str = "DumbSlab";

/// Host-provided configuration.
#[derive(Clone, Debug, Default)]
pub struct HostConfig {
    /// The public origin, e.g. `https://dumbslab.com`. Derived from the request when unset.
    pub base_url: Option<String>,
    /// When set, creating the first admin requires this token.
    pub setup_token: Option<String>,
    /// Allows first-run setup without a token (local development only).
    pub open_setup: bool,
}

/// A transport-neutral HTTP request.
#[derive(Clone, Debug, Default)]
pub struct Request {
    pub method: String,
    /// The path without the query string, e.g. `/api/v1/posts`.
    pub path: String,
    /// The raw query string without `?`.
    pub query: String,
    /// Header names must be lowercase.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// `scheme://host[:port]` as seen by the client.
    pub origin: String,
    pub client_ip: Option<String>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    pub fn is_https(&self) -> bool {
        self.origin.starts_with("https://")
    }
}

#[derive(Clone, Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn json(status: u16, value: &serde_json::Value) -> Response {
        Response {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: serde_json::to_vec(value).unwrap_or_default(),
        }
    }

    pub fn text(status: u16, content_type: &str, body: impl Into<String>) -> Response {
        Response { status, headers: vec![("content-type".into(), content_type.into())], body: body.into().into_bytes() }
    }

    pub fn redirect(location: &str) -> Response {
        Response { status: 302, headers: vec![("location".into(), location.into())], body: vec![] }
    }

    pub fn empty(status: u16) -> Response {
        Response { status, headers: vec![], body: vec![] }
    }

    pub fn error(err: &ApiError) -> Response {
        Response::json(err.status, &err.to_json())
    }

    pub fn with_header(mut self, name: &str, value: impl Into<String>) -> Response {
        self.headers.push((name.to_string(), value.into()));
        self
    }
}

/// A webhook the host must deliver after the transaction commits.
#[derive(Clone, Debug)]
pub struct WebhookDelivery {
    pub webhook_id: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

#[derive(Clone, Debug)]
pub enum Effect {
    Webhook(WebhookDelivery),
}

#[derive(Clone, Debug)]
pub struct Outcome {
    pub response: Response,
    /// `false` means the host must roll the transaction back.
    pub commit: bool,
    pub effects: Vec<Effect>,
}

/// Records the result of a webhook delivery. Call it in its own transaction.
pub fn record_webhook_result(db: &dyn Db, webhook_id: &str, status: Option<u16>, error: Option<&str>) -> ApiResult<()> {
    db.execute(
        "UPDATE webhooks SET last_delivery_at = ?, last_status = ?, last_error = ? WHERE id = ?",
        &params![util::ts(chrono::Utc::now()), status.map(|s| s as i64), error, webhook_id],
    )?;
    Ok(())
}
