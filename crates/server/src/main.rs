//! `dumbslab`: the self-hosted server and CLI. One binary, one SQLite file.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, anyhow};
use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use clap::{Parser, Subcommand};
use dumbslab_core::auth::{Actor, Role, Scopes, Via};
use dumbslab_core::connect::{self, Connectors, HttpCall, HttpReply, OAuthApp};
use dumbslab_core::db::DbExt;
use dumbslab_core::mcp::Toolset;
use dumbslab_core::registry::registry;
use dumbslab_core::telemetry::Telemetry;
use dumbslab_core::{Effect, HostConfig, Outcome, Request, WebhookDelivery, params};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{Semaphore, mpsc, oneshot};
use tracing::{info, warn};

use dumbslab::store::Store;
use dumbslab::web;

/// Connected apps' settings from the environment: `DUMBSLAB_CONNECTOR_KEY` encrypts people's
/// credentials, and `DUMBSLAB_<APP>_CLIENT_ID` / `_CLIENT_SECRET` (e.g. `DUMBSLAB_GITHUB_CLIENT_ID`,
/// `DUMBSLAB_GOOGLE_DRIVE_CLIENT_SECRET`) let people sign in to that app.
fn connectors_from_env() -> Connectors {
    let var = |k: &str| std::env::var(k).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let mut apps = BTreeMap::new();
    for c in connect::providers::ALL {
        let id = c.info().id;
        let env = id.to_ascii_uppercase().replace('-', "_");
        if let (Some(client_id), Some(client_secret)) =
            (var(&format!("DUMBSLAB_{env}_CLIENT_ID")), var(&format!("DUMBSLAB_{env}_CLIENT_SECRET")))
        {
            apps.insert(id.to_string(), OAuthApp { client_id, client_secret });
        }
    }
    Connectors { key: var("DUMBSLAB_CONNECTOR_KEY"), apps, callback_url: None }
}

#[derive(Parser)]
#[command(name = "dumbslab", version, about = "An open-source team knowledge base for people and AI agents")]
struct Cli {
    /// Path to the SQLite database file.
    #[arg(long, global = true, env = "DUMBSLAB_DB", default_value = "dumbslab.db")]
    db: PathBuf,
    /// Allow webhooks to loopback, private and link-local addresses (off by default to prevent SSRF).
    #[arg(long, global = true, env = "DUMBSLAB_ALLOW_PRIVATE_WEBHOOKS")]
    allow_private_webhooks: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the web app, REST API and MCP server.
    Serve {
        #[arg(long, env = "DUMBSLAB_BIND", default_value = "127.0.0.1:8080")]
        bind: SocketAddr,
        /// Public URL, e.g. https://wiki.example.com (used in links and OAuth metadata).
        #[arg(long, env = "DUMBSLAB_BASE_URL")]
        base_url: Option<String>,
        /// Token required to create the first admin. Generated and logged when unset.
        #[arg(long, env = "DUMBSLAB_SETUP_TOKEN")]
        setup_token: Option<String>,
        /// Let anyone who can reach the server create the first admin (local development only).
        #[arg(long)]
        open_setup: bool,
        /// Record sessions in this Quill (PostHog-compatible) server, e.g. https://t.example.com.
        /// Needs --quill-token too. Off by default.
        #[arg(long, env = "DUMBSLAB_QUILL_HOST")]
        quill_host: Option<String>,
        /// The Quill project's public token (phc_…).
        #[arg(long, env = "DUMBSLAB_QUILL_TOKEN")]
        quill_token: Option<String>,
        /// Report the web app's errors to this Sentry DSN (public; it ships to browsers). Off by default.
        #[arg(long, env = "DUMBSLAB_SENTRY_DSN")]
        sentry_dsn: Option<String>,
    },
    /// Serve MCP over stdio for a local agent, acting as a user.
    Mcp {
        /// User id, @handle or email. Defaults to the first admin.
        #[arg(long = "as")]
        user: Option<String>,
        /// `all` (default), `core` or `read`.
        #[arg(long, default_value = "all")]
        toolset: String,
        /// The server's public URL, as for `serve` (links, and where apps send sign-ins back).
        #[arg(long, env = "DUMBSLAB_BASE_URL")]
        base_url: Option<String>,
    },
    /// Run any operation, e.g. `dumbslab call search '{"q":"onboarding"}'`.
    Call {
        operation: String,
        /// JSON input (default `{}`).
        input: Option<String>,
        #[arg(long = "as")]
        user: Option<String>,
        /// The server's public URL, as for `serve` (links, and where apps send sign-ins back).
        #[arg(long, env = "DUMBSLAB_BASE_URL")]
        base_url: Option<String>,
    },
    /// List every operation.
    Ops,
    /// Print the OpenAPI document.
    Openapi {
        #[arg(long, default_value = "http://localhost:8080")]
        base_url: String,
    },
}

/// Deliveries that may wait for one webhook. Each webhook gets one delivery at a time, so a slow
/// endpoint backs up only its own queue; past this, its new events are dropped (and logged).
const WEBHOOK_QUEUE: usize = 100;
/// Sign-ins checked at once. Each holds the database while it hashes the password.
const MAX_SIGN_INS: usize = 4;

type QueuedDelivery = (WebhookDelivery, oneshot::Sender<()>);

pub struct App {
    pub store: Store,
    pub cfg: HostConfig,
    pub allow_private_webhooks: bool,
    /// The web app's Content-Security-Policy, which names the configured telemetry hosts.
    csp: String,
    webhooks: Mutex<HashMap<String, mpsc::Sender<QueuedDelivery>>>,
    sign_ins: Arc<Semaphore>,
}

impl App {
    fn new(store: Store, cfg: HostConfig, allow_private_webhooks: bool) -> Arc<App> {
        Arc::new(App {
            store,
            csp: web::csp(&cfg.telemetry.connect_origins()),
            cfg,
            allow_private_webhooks,
            webhooks: Mutex::new(HashMap::new()),
            sign_ins: Arc::new(Semaphore::new(MAX_SIGN_INS)),
        })
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,tower_http=warn".into()))
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    match cli.command {
        Command::Ops => {
            for op in &registry().ops {
                println!("{:<26} {:<6} /api/v1{:<40} {}", op.name, op.method, op.path, op.title);
            }
            Ok(())
        }
        Command::Openapi { base_url } => {
            println!("{}", serde_json::to_string_pretty(&dumbslab_core::openapi::spec(&base_url))?);
            Ok(())
        }
        Command::Serve { bind, base_url, setup_token, open_setup, quill_host, quill_token, sentry_dsn } => {
            let (telemetry, problems) = Telemetry::new(quill_host.as_deref(), quill_token.as_deref(), sentry_dsn.as_deref());
            for problem in problems {
                warn!("{problem}");
            }
            serve(cli.db, cli.allow_private_webhooks, bind, base_url, setup_token, open_setup, telemetry).await
        }
        Command::Mcp { user, toolset, base_url } => {
            stdio_mcp(cli.db, cli.allow_private_webhooks, user, Toolset::parse(Some(&toolset)), base_url).await
        }
        Command::Call { operation, input, user, base_url } => {
            call(cli.db, cli.allow_private_webhooks, operation, input, user, base_url).await
        }
    }
}

fn open(path: &std::path::Path) -> anyhow::Result<Store> {
    Store::open(path).with_context(|| format!("opening database {}", path.display()))
}

/// Resolves the local CLI actor: a named user or the first admin.
fn local_actor(store: &Store, user: Option<&str>, via: Via) -> anyhow::Result<Actor> {
    let row = store.with_tx(|db| {
        let r = match user {
            Some(u) => {
                let key = u.trim_start_matches('@');
                db.one("SELECT * FROM users WHERE (id = ? OR handle = ? OR email = ?) AND deactivated_at IS NULL", &params![key, key, key])
            }
            None => db.one("SELECT * FROM users WHERE role = 'admin' AND deactivated_at IS NULL ORDER BY created_at LIMIT 1", &[]),
        };
        (r, true)
    })??;
    let row = row.ok_or_else(|| anyhow!("no such user; run `dumbslab serve` and finish setup first"))?;
    let role = Role::parse(&row.str("role")).unwrap_or(Role::Viewer);
    Ok(Actor {
        user_id: row.str("id"),
        name: row.str("name"),
        handle: row.str("handle"),
        email: row.str("email"),
        role,
        scopes: Scopes::for_role(role),
        via,
        token_id: None,
        session_hash: None,
    })
}

/// Settings for commands that act on the database directly (`call`, `mcp`).
fn local_config(base_url: Option<String>) -> HostConfig {
    HostConfig { base_url: base_url.map(|u| u.trim_end_matches('/').to_string()), connectors: connectors_from_env(), ..Default::default() }
}

async fn call(
    db: PathBuf,
    allow_private_webhooks: bool,
    operation: String,
    input: Option<String>,
    user: Option<String>,
    base_url: Option<String>,
) -> anyhow::Result<()> {
    let app = App::new(open(&db)?, local_config(base_url), allow_private_webhooks);
    let actor = local_actor(&app.store, user.as_deref(), Via::Cli)?;
    let op = registry().get(&operation).ok_or_else(|| anyhow!("unknown operation `{operation}`; run `dumbslab ops`"))?;
    let input: serde_json::Value = serde_json::from_str(input.as_deref().unwrap_or("{}")).context("input must be JSON")?;
    let result = app.store.with_tx(|db| {
        let req = Request { origin: "http://localhost:8080".into(), ..Default::default() };
        let mut ctx = dumbslab_core::http::new_ctx(db, &app.cfg, &req, actor);
        match op.call(&mut ctx, input) {
            Ok(v) => (Ok((v, ctx.effects)), true),
            Err(e) => {
                let keep = e.keep_writes;
                (Err(e), keep)
            }
        }
    })?;
    match result {
        Ok((v, mut effects)) => {
            let v = match take_job(&mut effects) {
                Some(job) => match run_job(&app, job).await {
                    connect::Finish::Fill(filled) => filled,
                    connect::Finish::Redirect(url) => serde_json::json!({ "url": url }),
                    connect::Finish::Respond(_) => return Err(anyhow!("a sign-in can't finish on the command line")),
                    connect::Finish::Fail(e) => return Err(anyhow!("{} ({})", e.message, e.code)),
                },
                None => v,
            };
            println!("{}", serde_json::to_string_pretty(&v)?);
            for delivered in deliver(app, effects) {
                let _ = delivered.await;
            }
            Ok(())
        }
        Err(e) => Err(anyhow!("{} ({})", e.message, e.code)),
    }
}

async fn stdio_mcp(
    db: PathBuf,
    allow_private_webhooks: bool,
    user: Option<String>,
    toolset: Toolset,
    base_url: Option<String>,
) -> anyhow::Result<()> {
    let app = App::new(open(&db)?, local_config(base_url), allow_private_webhooks);
    let mut pending = vec![];
    let actor = local_actor(&app.store, user.as_deref(), Via::Mcp)?;
    info!(user = %actor.email, "serving MCP over stdio");
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let (app2, actor2) = (app.clone(), actor.clone());
        let (reply, effects) = tokio::task::spawn_blocking(move || {
            app2.store.with_tx(|db| {
                let (reply, ok, effects) = dumbslab_core::mcp::handle_stdio(db, &app2.cfg, actor2, toolset, &line);
                ((reply, effects), ok)
            })
        })
        .await??;
        let mut effects = effects;
        let reply = match (take_job(&mut effects), reply) {
            (Some(job), Some(reply)) => {
                let result = match run_job(&app, job).await {
                    connect::Finish::Fill(v) => Ok(v),
                    connect::Finish::Fail(e) => Err(e),
                    connect::Finish::Redirect(_) | connect::Finish::Respond(_) => {
                        Err(dumbslab_core::ApiError::internal("a sign-in can't finish over stdio"))
                    }
                };
                let id = reply["id"].clone();
                Some(connect::fill(reply, result).unwrap_or_else(|e| dumbslab_core::mcp::rpc_error(id, -32603, &e.message)))
            }
            (_, reply) => reply,
        };
        pending.extend(deliver(app.clone(), effects));
        pending.retain_mut(|d: &mut oneshot::Receiver<()>| d.try_recv().is_err_and(|e| e == oneshot::error::TryRecvError::Empty));
        if let Some(reply) = reply {
            stdout.write_all(format!("{reply}\n").as_bytes()).await?;
            stdout.flush().await?;
        }
    }
    for delivered in pending {
        let _ = delivered.await;
    }
    Ok(())
}

async fn serve(
    db: PathBuf,
    allow_private_webhooks: bool,
    bind: SocketAddr,
    base_url: Option<String>,
    setup_token: Option<String>,
    open_setup: bool,
    telemetry: Telemetry,
) -> anyhow::Result<()> {
    let store = open(&db)?;
    let needs_setup = store.with_tx(|db| (db.scalar_i64("SELECT COUNT(*) FROM users", &[]), true))?? == 0;
    let setup_token = match (needs_setup && !open_setup, setup_token) {
        (true, None) => Some(dumbslab_core::util::new_secret("")),
        (_, t) => t,
    };
    let shown_url = base_url.clone().unwrap_or_else(|| format!("http://{bind}"));
    if needs_setup {
        match &setup_token {
            Some(t) if !open_setup => info!("first run: create the admin account at {shown_url}/setup?token={t}"),
            _ => info!("first run: create the admin account at {shown_url}/setup"),
        }
    }
    if telemetry.quill_host.is_some() {
        info!("the web app records sessions in Quill");
    }
    if telemetry.sentry.is_some() {
        info!("the web app reports its errors to Sentry");
    }
    let cfg = HostConfig {
        base_url: base_url.map(|u| u.trim_end_matches('/').to_string()),
        setup_token,
        open_setup,
        telemetry,
        connectors: connectors_from_env(),
        ..Default::default()
    };
    let app = App::new(store, cfg, allow_private_webhooks);
    let router = Router::new()
        .fallback(handle)
        .with_state(app)
        .layer(tower_http::compression::CompressionLayer::new())
        .layer(tower_http::trace::TraceLayer::new_for_http());
    let listener = tokio::net::TcpListener::bind(bind).await.with_context(|| format!("binding {bind}"))?;
    info!("DumbSlab {} listening on http://{bind}", dumbslab_core::VERSION);
    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

async fn handle(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: axum::extract::Request,
) -> axum::response::Response {
    let (parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();
    if !dumbslab_core::http::is_core_path(&path) {
        return web::serve(&path, &parts.headers, &app.csp);
    }
    // Uploads get room for a base64 file; every other route keeps the smaller limit.
    let body = match axum::body::to_bytes(body, dumbslab_core::http::body_limit(&path)).await {
        Ok(b) => b.to_vec(),
        Err(_) => return plain(StatusCode::PAYLOAD_TOO_LARGE, "request body too large"),
    };
    // Rotating emails can't get around this: the core's sign-in limits stop repeated failures, and
    // this keeps a burst from queueing password checks in front of every other request. Taken only
    // once the body has arrived, so slow uploads can't hold the slots.
    let _sign_in = if path == "/api/v1/auth/login" {
        match app.sign_ins.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => return plain(StatusCode::TOO_MANY_REQUESTS, "too many sign-ins at once; try again in a moment"),
        }
    } else {
        None
    };
    let header = |name: &str| parts.headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_string);
    let scheme = header("x-forwarded-proto").unwrap_or_else(|| "http".into());
    let host = header("x-forwarded-host").or_else(|| header("host")).unwrap_or_else(|| "localhost".into());
    let core_req = Request {
        method: parts.method.as_str().to_string(),
        path,
        query: parts.uri.query().unwrap_or_default().to_string(),
        headers: parts.headers.iter().filter_map(|(k, v)| Some((k.as_str().to_lowercase(), v.to_str().ok()?.to_string()))).collect(),
        body,
        origin: format!("{scheme}://{host}"),
        // A private or loopback peer is usually a reverse proxy, whose address says nothing about
        // the client; sign-in limits then count per account and per workspace only.
        client_ip: is_public(peer.ip()).then(|| peer.ip().to_string()),
    };
    let app2 = app.clone();
    let result = tokio::task::spawn_blocking(move || {
        app2.store.with_tx(|db| match dumbslab_core::handle(db, &app2.cfg, &core_req) {
            Some(o) => {
                let commit = o.commit;
                (Some(o), commit)
            }
            None => (None, true),
        })
    })
    .await;
    match result {
        Ok(Ok(Some(outcome))) => {
            let outcome = finish_jobs(&app, outcome).await;
            respond(app, outcome)
        }
        Ok(Ok(None)) => plain(StatusCode::NOT_FOUND, "not found"),
        Ok(Err(e)) => {
            warn!("request failed: {e:#}");
            plain(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
        Err(e) => {
            warn!("request task failed: {e}");
            plain(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}

fn plain(status: StatusCode, msg: &str) -> axum::response::Response {
    axum::response::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::json!({ "error": { "code": "error", "message": msg } }).to_string()))
        .unwrap_or_default()
}

fn respond(app: Arc<App>, outcome: Outcome) -> axum::response::Response {
    let Outcome { response, effects, .. } = outcome;
    deliver(app, effects);
    let mut builder = axum::response::Response::builder().status(StatusCode::from_u16(response.status).unwrap_or(StatusCode::OK));
    for (k, v) in &response.headers {
        if let (Ok(name), Ok(value)) = (HeaderName::try_from(k.as_str()), HeaderValue::from_str(v)) {
            builder = builder.header(name, value);
        }
    }
    builder.body(Body::from(response.body)).unwrap_or_default()
}

/// Queues webhook deliveries. Returns, for each one accepted, a receiver that fires once it's done.
fn deliver(app: Arc<App>, effects: Vec<Effect>) -> Vec<oneshot::Receiver<()>> {
    let mut accepted = vec![];
    // Address moves and Stripe calls only exist for hosted workspaces, which this server never is.
    for d in effects.into_iter().filter_map(|effect| match effect {
        Effect::Webhook(d) => Some(d),
        // Slack's commands and events, answered already: run the job on its own. It delivers the
        // webhooks its operations leave (see `run_job`).
        Effect::Background(job) => {
            let app = app.clone();
            tokio::spawn(async move {
                if let connect::Finish::Fail(e) = run_job(&app, job).await {
                    warn!(code = e.code, "a background job failed: {}", e.message);
                }
            });
            None
        }
        // Jobs for connected apps ran before the response was sent.
        Effect::MoveAddress(_) | Effect::Stripe(_) | Effect::Connect(_) => None,
    }) {
        let mut queues = app.webhooks.lock().unwrap_or_else(|e| e.into_inner());
        let queue = queues.entry(d.webhook_id.clone()).or_insert_with(|| webhook_queue(&app));
        if queue.is_closed() {
            *queue = webhook_queue(&app);
        }
        let (done, delivered) = oneshot::channel();
        match queue.try_send((d, done)) {
            Ok(()) => accepted.push(delivered),
            Err(e) => {
                let (d, _) = e.into_inner();
                warn!(webhook = %d.webhook_id, host = %url_host(&d.url), "webhook is backed up; dropped a delivery");
            }
        }
    }
    accepted
}

/// Starts the task that sends one webhook's deliveries, in order.
fn webhook_queue(app: &Arc<App>) -> mpsc::Sender<QueuedDelivery> {
    let (queue, mut pending) = mpsc::channel::<QueuedDelivery>(WEBHOOK_QUEUE);
    let app = app.clone();
    tokio::spawn(async move {
        while let Some((d, done)) = pending.recv().await {
            let mut last: (Option<u16>, Option<String>) = (None, None);
            for (attempt, delay) in [0u64, 2, 10].into_iter().enumerate() {
                if delay > 0 {
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                }
                last = send_webhook(&d, app.allow_private_webhooks).await;
                if last.1.is_none() {
                    break;
                }
                warn!(webhook = %d.webhook_id, host = %url_host(&d.url), attempt = attempt + 1, error = ?last.1, "webhook delivery failed");
            }
            let (app, id) = (app.clone(), d.webhook_id.clone());
            let _ = tokio::task::spawn_blocking(move || {
                app.store.with_tx(|db| (dumbslab_core::record_webhook_result(db, &id, last.0, last.1.as_deref()), true))
            })
            .await;
            let _ = done.send(());
        }
    });
    queue
}

/// A webhook URL's host, for logs. Its path, query and user info can hold credentials.
fn url_host(url: &str) -> String {
    reqwest::Url::parse(url).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_else(|| "(invalid URL)".into())
}

/// Removes the request's connected-apps job, if it has one.
fn take_job(effects: &mut Vec<Effect>) -> Option<connect::Job> {
    let i = effects.iter().position(|e| matches!(e, Effect::Connect(_)))?;
    match effects.remove(i) {
        Effect::Connect(job) => Some(job),
        _ => None,
    }
}

/// Runs a connected-apps job (see `connect::step`), each step in its own transaction.
async fn run_job(app: &Arc<App>, mut job: connect::Job) -> connect::Finish {
    let mut replies = vec![];
    for _ in 0..connect::MAX_STEPS {
        // Who to tell if this step can't even run (the job goes with it). Like any failure
        // notice, it's decided from the job as it is before the step.
        let unran = job.failure_notice(&dumbslab_core::ApiError::internal("the step didn't run"));
        let app2 = app.clone();
        let ran = tokio::task::spawn_blocking(move || {
            app2.store.with_tx(|db| {
                // This server has no check of its own after a step (no plan, no storage limit).
                let (step, notice) = connect::guarded_step(db, &app2.cfg, &mut job, replies, chrono::Utc::now(), |_| None);
                let ok = step.is_ok();
                ((step, notice, job), ok)
            })
        })
        .await;
        let (step, notice, next) = match ran {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                warn!("connected-apps job failed: {e:#}");
                notify_failure(app, unran).await;
                return connect::Finish::Fail(dumbslab_core::ApiError::internal("connected apps failed"));
            }
            Err(e) => {
                warn!("connected-apps task failed: {e}");
                notify_failure(app, unran).await;
                return connect::Finish::Fail(dumbslab_core::ApiError::internal("connected apps failed"));
            }
        };
        job = next;
        match step {
            Err(e) => {
                // The step rolled back; whoever is waiting elsewhere (a Slack command) hears so.
                notify_failure(app, notice).await;
                return connect::Finish::Fail(e);
            }
            Ok(connect::Step::Done(finish)) => {
                // A job's operations can leave webhooks to send (a draft started from Slack).
                deliver(app.clone(), job.take_effects());
                return finish;
            }
            Ok(connect::Step::Fetch(calls)) => {
                // All at once; answers keep the requests' order.
                let allow = app.allow_private_webhooks;
                let sent: Vec<_> = calls.into_iter().map(|c| tokio::spawn(async move { send_app_call(&c, allow).await })).collect();
                replies = Vec::with_capacity(sent.len());
                for s in sent {
                    replies.push(s.await.unwrap_or_default());
                }
            }
        }
    }
    connect::Finish::Fail(dumbslab_core::ApiError::internal("connected apps took too many steps"))
}

/// Sends a failed job's notice (see `connect::Job::failure_notice`), best effort.
async fn notify_failure(app: &Arc<App>, notice: Option<HttpCall>) {
    if let Some(call) = notice {
        send_app_call(&call, app.allow_private_webhooks).await;
    }
}

/// Answers with a connected-apps job's result, when the request started one.
async fn finish_jobs(app: &Arc<App>, mut outcome: Outcome) -> Outcome {
    if let Some(job) = take_job(&mut outcome.effects) {
        let finish = run_job(app, job).await;
        outcome.response = connect::respond(outcome.response, finish);
    }
    outcome
}

/// Sends one request to a connected app, like a webhook: https only, the host resolved once and
/// pinned, private addresses refused (unless allowed), no redirects. Reads at most
/// `connect::MAX_REPLY_BYTES`. Failures answer status 0.
async fn send_app_call(call: &HttpCall, allow_private: bool) -> HttpReply {
    let attempt = async {
        let url = reqwest::Url::parse(&call.url)?;
        if url.scheme() != "https" {
            anyhow::bail!("apps are reached over https only");
        }
        let port = url.port_or_known_default().unwrap_or(443);
        let host = url.host_str().unwrap_or_default().trim_start_matches('[').trim_end_matches(']').to_string();
        let addrs: Vec<SocketAddr> = match host.parse::<IpAddr>() {
            Ok(ip) => vec![SocketAddr::new(ip, port)],
            Err(_) => tokio::net::lookup_host((host.as_str(), port)).await?.collect(),
        };
        if addrs.is_empty() {
            anyhow::bail!("the app's host did not resolve");
        }
        if !allow_private && addrs.iter().any(|a| !is_public(a.ip())) {
            anyhow::bail!("the app's address is private (start the server with --allow-private-webhooks to permit this)");
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(connect::FETCH_TIMEOUT_SECS))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(&host, &addrs)
            .build()?;
        let mut req = client.request(reqwest::Method::from_bytes(call.method.as_bytes())?, url);
        for (k, v) in &call.headers {
            req = req.header(k, v);
        }
        if let Some(body) = &call.body {
            req = req.body(body.clone());
        }
        // Errors name the URL, which may hold a credential.
        let mut resp = req.send().await.map_err(reqwest::Error::without_url)?;
        let status = resp.status().as_u16();
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(reqwest::Error::without_url)? {
            body.extend_from_slice(&chunk);
            if body.len() > connect::MAX_REPLY_BYTES {
                body.truncate(connect::MAX_REPLY_BYTES);
                break;
            }
        }
        Ok::<_, anyhow::Error>(HttpReply { status, body: String::from_utf8_lossy(&body).into_owned() })
    };
    attempt.await.unwrap_or_else(|e| {
        warn!(host = %url_host(&call.url), error = %e, "request to a connected app failed");
        HttpReply::default()
    })
}

/// Whether an address is on the public internet (not loopback, private, link-local, CGNAT, …).
/// IPv6 is an allowlist of global unicast; forms that embed an IPv4 address are judged by it.
fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_documentation()
                || v4.is_multicast()
                || o[0] == 0
                || o[0] >= 240
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 198 && (o[1] & 0xfe) == 18))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let s = v6.segments();
            if s[0] == 0x2002 {
                // 6to4 carries an IPv4 address in bits 16-48.
                let v4 = std::net::Ipv4Addr::new((s[1] >> 8) as u8, s[1] as u8, (s[2] >> 8) as u8, s[2] as u8);
                return is_public(IpAddr::V4(v4));
            }
            let global_unicast = (s[0] & 0xe000) == 0x2000;
            let teredo = s[0] == 0x2001 && s[1] == 0;
            let documentation = s[0] == 0x2001 && s[1] == 0x0db8;
            global_unicast && !teredo && !documentation
        }
    }
}

/// Sends one delivery. Resolves the host once, refuses private targets (unless allowed), pins the
/// connection to the checked addresses, and never follows redirects.
async fn send_webhook(d: &WebhookDelivery, allow_private: bool) -> (Option<u16>, Option<String>) {
    let attempt = async {
        let url = reqwest::Url::parse(&d.url)?;
        let port = url.port_or_known_default().unwrap_or(443);
        let host = url.host_str().unwrap_or_default().trim_start_matches('[').trim_end_matches(']').to_string();
        let addrs: Vec<SocketAddr> = match host.parse::<IpAddr>() {
            Ok(ip) => vec![SocketAddr::new(ip, port)],
            Err(_) => tokio::net::lookup_host((host.as_str(), port)).await?.collect(),
        };
        if addrs.is_empty() {
            anyhow::bail!("webhook host did not resolve");
        }
        if !allow_private && addrs.iter().any(|a| !is_public(a.ip())) {
            anyhow::bail!("webhook URL points to a private address (start the server with --allow-private-webhooks to permit this)");
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(&host, &addrs)
            .build()?;
        let mut req = client.post(url).body(d.body.clone());
        for (k, v) in &d.headers {
            req = req.header(k, v);
        }
        // Errors name the URL, which may hold a credential; they're logged and shown to admins.
        Ok::<_, anyhow::Error>(req.send().await.map_err(reqwest::Error::without_url)?.status())
    };
    match attempt.await {
        Ok(status) if status.is_success() => (Some(status.as_u16()), None),
        Ok(status) => (Some(status.as_u16()), Some(format!("HTTP {status}"))),
        Err(e) => (None, Some(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delivery(url: &str) -> WebhookDelivery {
        WebhookDelivery { webhook_id: "hook".into(), url: url.into(), headers: vec![], body: "{}".into() }
    }

    #[tokio::test]
    async fn webhook_errors_hide_the_url() {
        // Nothing listens on the discard port, so the request fails with a connection error.
        let (_, error) = send_webhook(&delivery("http://user:hunter2@127.0.0.1:9/hooks/s3cr3t-path?token=abc"), true).await;
        let error = error.expect("delivery fails");
        for secret in ["hunter2", "s3cr3t-path", "token=abc"] {
            assert!(!error.contains(secret), "{error}");
        }
    }

    #[tokio::test]
    async fn jobs_keep_the_requests_own_webhooks() {
        // Saving single sign-on settings both checks the provider (a job) and records
        // `sso.updated` (a webhook): running the job must leave the webhook to be delivered.
        let dir = tempfile::tempdir().unwrap();
        let app = App::new(Store::open(&dir.path().join("t.db")).unwrap(), HostConfig::default(), false);
        let job = connect::Job::Sso(dumbslab_core::sso::SsoJob::check("https://kb.test"));
        let outcome = Outcome {
            response: dumbslab_core::Response::json(200, &serde_json::json!(connect::PENDING)),
            commit: true,
            effects: vec![Effect::Connect(job), Effect::Webhook(delivery("https://hooks.test/sso"))],
        };
        let done = finish_jobs(&app, outcome).await;
        assert!(!String::from_utf8_lossy(&done.response.body).contains(connect::PENDING), "the job's result is filled in");
        assert_eq!(done.effects.len(), 1);
        assert!(matches!(&done.effects[0], Effect::Webhook(d) if d.url == "https://hooks.test/sso"));
    }

    #[tokio::test]
    async fn webhook_deliveries_are_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let app = App::new(Store::open(&dir.path().join("t.db")).unwrap(), HostConfig::default(), false);
        // A private address is refused and retried later, so this webhook's deliveries back up.
        let effects = (0..500).map(|_| Effect::Webhook(delivery("https://10.0.0.1/hook"))).collect();
        let accepted = deliver(app, effects).len();
        assert!(accepted <= 101, "{accepted} deliveries in flight for one webhook");
    }

    #[tokio::test]
    async fn sign_ins_beyond_the_limit_wait_their_turn() {
        let dir = tempfile::tempdir().unwrap();
        let app = App::new(Store::open(&dir.path().join("t.db")).unwrap(), HostConfig::default(), false);
        let _busy: Vec<_> = (0..MAX_SIGN_INS).map(|_| app.sign_ins.clone().try_acquire_owned().unwrap()).collect();
        let login = axum::extract::Request::builder().method("POST").uri("/api/v1/auth/login").body(Body::from("{}")).unwrap();
        let resp = handle(State(app.clone()), ConnectInfo("203.0.113.1:5000".parse().unwrap()), login).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let other = axum::extract::Request::builder().uri("/healthz").body(Body::empty()).unwrap();
        assert_eq!(handle(State(app), ConnectInfo("203.0.113.1:5000".parse().unwrap()), other).await.status(), StatusCode::OK);
    }

    #[test]
    fn private_addresses_are_refused() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.169.254",
            "100.100.1.1",
            "0.0.0.0",
            "::1",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "224.0.0.1",
            "240.0.0.1",
            "::127.0.0.1",
            "64:ff9b::a00:1",
            "2002:7f00:1::",
            "2001:0:4136:e378::1",
            "2001:db8::1",
            "ff02::1",
            "fec0::1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "93.184.216.34", "2606:4700::1111", "2002:5db8:d822::1"] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
    }
}
