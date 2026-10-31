//! DumbSlab core: everything except the transport and the storage engine.
//!
//! A host (the native server or the Cloudflare Worker) turns an incoming HTTP request into a
//! [`Request`], opens a database transaction, calls [`handle`], commits or rolls back according
//! to [`Outcome::commit`], and then performs the returned [`Effect`]s (webhook deliveries,
//! requests to connected apps, jobs that run after the response and, for hosted workspaces,
//! address moves and Stripe calls).
//!
//! Every capability is an operation in [`registry`]. Each one is exposed the same way over REST
//! (`/api/v1/...`), the generic operations endpoint (`/api/v1/operations/{name}`), MCP (`/mcp`)
//! and the CLI, so agents can do anything a person can do in the web app.

pub mod auth;
pub mod connect;
pub mod db;
pub mod embed;
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
pub mod plan;
pub mod registry;
pub mod search;
pub mod seed;
pub mod slack;
pub mod sso;
pub mod sync;
pub mod telemetry;
pub mod tenancy;
pub mod util;

pub use db::{Db, Row, SqlValue, migrate};
pub use error::{ApiError, ApiResult};
pub use http::handle;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Full source commit embedded at build time, or `unknown` outside a Git checkout.
pub const GIT_SHA: &str = env!("DUMBSLAB_BUILD_GIT_SHA");
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
    /// Multi-tenant hosting: the secret that signs sign-up links (see [`tenancy`]).
    pub signup_secret: Option<String>,
    /// Multi-tenant hosting: this workspace's address (its subdomain).
    pub workspace: Option<String>,
    /// Multi-tenant hosting: the plans on offer and what the host measured (see [`plan`]).
    /// Self-hosted servers leave it unset and have no limits.
    pub hosting: Option<Hosting>,
    /// Connected apps (see [`connect`]): the key that encrypts credentials, and OAuth apps.
    pub connectors: connect::Connectors,
    /// DumbSlab's own GitHub App, so docs sync needs no token (see [`sync::github_app`]).
    pub github_app: Option<sync::github_app::GitHubApp>,
    /// The host's own Slack app, which admins add with one click (see [`slack::SharedApp`]).
    pub slack: slack::SharedApp,
    /// The host's own Google, Microsoft and Slack sign-in apps, so admins set up single sign-on by
    /// signing in (see [`sso::SharedApps`]). None by default.
    pub sso_apps: sso::SharedApps,
    /// The web app's session recordings and error reports. Off unless the host configures them.
    pub telemetry: telemetry::Telemetry,
}

impl HostConfig {
    /// Whether this server's public address comes from its own settings rather than from a
    /// request: hosted DumbSlab's front Worker sets it to the workspace address it routed (only
    /// `<address>.<root domain>`; an address the workspace moved away from is answered before the
    /// core runs), and a self-hosted server has it when `--base-url` (`BASE_URL` on Cloudflare) is
    /// set. Otherwise the address is the request's `Host`, which anyone can choose, so DumbSlab
    /// never tells another service on its own to call it there (see `sync::docs`'s webhook upkeep).
    pub fn knows_its_address(&self) -> bool {
        self.base_url.is_some()
    }
}

/// What a hosted workspace's plan depends on that only the host knows.
#[derive(Clone, Debug)]
pub struct Hosting {
    pub plans: plan::Plans,
    /// The workspace's first address. It names the workspace's storage and its Stripe customer.
    pub home: String,
    /// The workspace database's size, in bytes, when the request arrived.
    pub storage_bytes: u64,
    /// Whether the free plan is at capacity across the service.
    pub capacity: plan::Capacity,
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
    /// The caller's address, when the host can vouch for it (not a proxy's address, and not a
    /// header anyone could set). Sign-in limits count failures per address.
    pub client_ip: Option<String>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
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

/// A webhook the host must deliver after the transaction commits. Slack channel messages are
/// deliveries too, to `chat.postMessage` with the bot token (see [`slack::on_event`]).
#[derive(Clone)]
pub struct WebhookDelivery {
    pub webhook_id: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

// Headers can carry a bot token; never print them.
impl std::fmt::Debug for WebhookDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookDelivery").field("webhook_id", &self.webhook_id).finish_non_exhaustive()
    }
}

/// Hosted workspaces only: an admin asked to move the workspace from `from` to `to`. The host
/// claims `to` in its directory, then records the move with [`tenancy::finish_move`] in a new
/// transaction. Nothing changes if the claim fails.
#[derive(Clone, Debug)]
pub struct AddressMove {
    pub from: String,
    pub to: String,
    pub actor: auth::Actor,
}

/// Hosted workspaces only: this workspace connected (or stopped using) an installation of
/// DumbSlab's GitHub App. The host records it in its directory, which the root domain reads to
/// forward that installation's webhook deliveries here (see [`sync::github_app`]). Self-hosted
/// servers get the deliveries directly and do nothing.
#[derive(Clone, Debug, PartialEq)]
pub struct InstallationLink {
    pub installation_id: i64,
    /// `false`: the workspace no longer uses it.
    pub linked: bool,
}

#[derive(Clone, Debug)]
pub enum Effect {
    Webhook(WebhookDelivery),
    MoveAddress(AddressMove),
    /// Hosted workspaces only: ask Stripe for a Checkout or customer portal page, and answer the
    /// request with its URL.
    Stripe(plan::StripeCall),
    /// Requests to connected apps: run the job with [`connect::step`] and answer with its result.
    Connect(connect::Job),
    /// A job to run once the response has gone, like [`Effect::Connect`]'s but with nothing
    /// waiting for its result: Slack wants its requests answered within three seconds, so a
    /// command or event is acknowledged first and handled here. Its writes count against the plan
    /// like any job's, and it delivers what [`connect::Job::take_effects`] leaves.
    Background(connect::Job),
    /// See [`InstallationLink`]. Sent after the transaction commits, best effort.
    GitHubInstallation(InstallationLink),
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
    // Slack channel messages have no webhook to record them on.
    if webhook_id.starts_with("slack:") {
        return Ok(());
    }
    db.execute(
        "UPDATE webhooks SET last_delivery_at = ?, last_status = ?, last_error = ? WHERE id = ?",
        &params![util::ts(chrono::Utc::now()), status.map(|s| s as i64), error, webhook_id],
    )?;
    Ok(())
}
