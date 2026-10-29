//! `dumbslab`: the self-hosted server and CLI. One binary, one SQLite file.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow};
use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use clap::{Parser, Subcommand};
use dumbslab_core::auth::{Actor, Role, Scopes, Via};
use dumbslab_core::db::DbExt;
use dumbslab_core::mcp::Toolset;
use dumbslab_core::registry::registry;
use dumbslab_core::{Effect, HostConfig, Outcome, Request, params};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{info, warn};

use dumbslab::store::Store;
use dumbslab::web;

#[derive(Parser)]
#[command(name = "dumbslab", version, about = "An open-source team knowledge base for people and AI agents")]
struct Cli {
    /// Path to the SQLite database file.
    #[arg(long, global = true, env = "DUMBSLAB_DB", default_value = "dumbslab.db")]
    db: PathBuf,
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
    },
    /// Serve MCP over stdio for a local agent, acting as a user.
    Mcp {
        /// User id, @handle or email. Defaults to the first admin.
        #[arg(long = "as")]
        user: Option<String>,
        /// `all` (default), `core` or `read`.
        #[arg(long, default_value = "all")]
        toolset: String,
    },
    /// Run any operation, e.g. `dumbslab call search '{"q":"onboarding"}'`.
    Call {
        operation: String,
        /// JSON input (default `{}`).
        input: Option<String>,
        #[arg(long = "as")]
        user: Option<String>,
    },
    /// List every operation.
    Ops,
    /// Print the OpenAPI document.
    Openapi {
        #[arg(long, default_value = "http://localhost:8080")]
        base_url: String,
    },
}

pub struct App {
    pub store: Store,
    pub cfg: HostConfig,
    pub http: reqwest::Client,
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
        Command::Serve { bind, base_url, setup_token, open_setup } => serve(cli.db, bind, base_url, setup_token, open_setup).await,
        Command::Mcp { user, toolset } => stdio_mcp(cli.db, user, Toolset::parse(Some(&toolset))).await,
        Command::Call { operation, input, user } => call(cli.db, operation, input, user),
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

fn call(db: PathBuf, operation: String, input: Option<String>, user: Option<String>) -> anyhow::Result<()> {
    let store = open(&db)?;
    let actor = local_actor(&store, user.as_deref(), Via::Cli)?;
    let op = registry().get(&operation).ok_or_else(|| anyhow!("unknown operation `{operation}`; run `dumbslab ops`"))?;
    let input: serde_json::Value = serde_json::from_str(input.as_deref().unwrap_or("{}")).context("input must be JSON")?;
    let cfg = HostConfig::default();
    let result = store.with_tx(|db| {
        let req = Request { origin: "http://localhost:8080".into(), ..Default::default() };
        let mut ctx = dumbslab_core::http::new_ctx(db, &cfg, &req, actor);
        match op.call(&mut ctx, input) {
            Ok(v) => (Ok(v), true),
            Err(e) => (Err(e), false),
        }
    })?;
    match result {
        Ok(v) => {
            println!("{}", serde_json::to_string_pretty(&v)?);
            Ok(())
        }
        Err(e) => Err(anyhow!("{} ({})", e.message, e.code)),
    }
}

async fn stdio_mcp(db: PathBuf, user: Option<String>, toolset: Toolset) -> anyhow::Result<()> {
    let app = Arc::new(App { store: open(&db)?, cfg: HostConfig::default(), http: reqwest::Client::new() });
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
        deliver(app.clone(), effects);
        if let Some(reply) = reply {
            stdout.write_all(format!("{reply}\n").as_bytes()).await?;
            stdout.flush().await?;
        }
    }
    Ok(())
}

async fn serve(
    db: PathBuf,
    bind: SocketAddr,
    base_url: Option<String>,
    setup_token: Option<String>,
    open_setup: bool,
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
    let cfg = HostConfig { base_url: base_url.map(|u| u.trim_end_matches('/').to_string()), setup_token, open_setup };
    let http = reqwest::Client::builder().timeout(Duration::from_secs(10)).build()?;
    let app = Arc::new(App { store, cfg, http });
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

const MAX_BODY: usize = 8 * 1024 * 1024;

async fn handle(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: axum::extract::Request,
) -> axum::response::Response {
    let (parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();
    if !dumbslab_core::http::is_core_path(&path) {
        return web::serve(&path, &parts.headers);
    }
    let body = match axum::body::to_bytes(body, MAX_BODY).await {
        Ok(b) => b.to_vec(),
        Err(_) => return plain(StatusCode::PAYLOAD_TOO_LARGE, "request body too large"),
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
        client_ip: Some(peer.ip().to_string()),
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
        Ok(Ok(Some(outcome))) => respond(app, outcome),
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

/// Delivers webhooks in the background with a few retries, then records the outcome.
fn deliver(app: Arc<App>, effects: Vec<Effect>) {
    for effect in effects {
        let Effect::Webhook(d) = effect;
        let app = app.clone();
        tokio::spawn(async move {
            let mut last: (Option<u16>, Option<String>) = (None, None);
            for (attempt, delay) in [0u64, 2, 10].into_iter().enumerate() {
                if delay > 0 {
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                }
                let mut req = app.http.post(&d.url).body(d.body.clone());
                for (k, v) in &d.headers {
                    req = req.header(k, v);
                }
                last = match req.send().await {
                    Ok(r) if r.status().is_success() => (Some(r.status().as_u16()), None),
                    Ok(r) => (Some(r.status().as_u16()), Some(format!("HTTP {}", r.status()))),
                    Err(e) => (None, Some(e.to_string())),
                };
                if last.1.is_none() {
                    break;
                }
                warn!(url = %d.url, attempt = attempt + 1, error = ?last.1, "webhook delivery failed");
            }
            let id = d.webhook_id.clone();
            let _ = tokio::task::spawn_blocking(move || {
                app.store.with_tx(|db| (dumbslab_core::record_webhook_result(db, &id, last.0, last.1.as_deref()), true))
            })
            .await;
        });
    }
}
