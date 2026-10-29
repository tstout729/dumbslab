//! `dumbslab`: the self-hosted server and CLI. One binary, one SQLite file.

use std::net::{IpAddr, SocketAddr};
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
use dumbslab_core::{Effect, HostConfig, Outcome, Request, WebhookDelivery, params};
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
    pub allow_private_webhooks: bool,
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
        Command::Serve { bind, base_url, setup_token, open_setup } => {
            serve(cli.db, cli.allow_private_webhooks, bind, base_url, setup_token, open_setup).await
        }
        Command::Mcp { user, toolset } => stdio_mcp(cli.db, cli.allow_private_webhooks, user, Toolset::parse(Some(&toolset))).await,
        Command::Call { operation, input, user } => call(cli.db, cli.allow_private_webhooks, operation, input, user).await,
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

async fn call(
    db: PathBuf,
    allow_private_webhooks: bool,
    operation: String,
    input: Option<String>,
    user: Option<String>,
) -> anyhow::Result<()> {
    let app = Arc::new(App { store: open(&db)?, cfg: HostConfig::default(), allow_private_webhooks });
    let actor = local_actor(&app.store, user.as_deref(), Via::Cli)?;
    let op = registry().get(&operation).ok_or_else(|| anyhow!("unknown operation `{operation}`; run `dumbslab ops`"))?;
    let input: serde_json::Value = serde_json::from_str(input.as_deref().unwrap_or("{}")).context("input must be JSON")?;
    let result = app.store.with_tx(|db| {
        let req = Request { origin: "http://localhost:8080".into(), ..Default::default() };
        let mut ctx = dumbslab_core::http::new_ctx(db, &app.cfg, &req, actor);
        match op.call(&mut ctx, input) {
            Ok(v) => (Ok((v, ctx.effects)), true),
            Err(e) => (Err(e), false),
        }
    })?;
    match result {
        Ok((v, effects)) => {
            println!("{}", serde_json::to_string_pretty(&v)?);
            for handle in deliver(app, effects) {
                let _ = handle.await;
            }
            Ok(())
        }
        Err(e) => Err(anyhow!("{} ({})", e.message, e.code)),
    }
}

async fn stdio_mcp(db: PathBuf, allow_private_webhooks: bool, user: Option<String>, toolset: Toolset) -> anyhow::Result<()> {
    let app = Arc::new(App { store: open(&db)?, cfg: HostConfig::default(), allow_private_webhooks });
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
        pending.extend(deliver(app.clone(), effects));
        pending.retain(|h: &tokio::task::JoinHandle<()>| !h.is_finished());
        if let Some(reply) = reply {
            stdout.write_all(format!("{reply}\n").as_bytes()).await?;
            stdout.flush().await?;
        }
    }
    for handle in pending {
        let _ = handle.await;
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
    let app = Arc::new(App { store, cfg, allow_private_webhooks });
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
fn deliver(app: Arc<App>, effects: Vec<Effect>) -> Vec<tokio::task::JoinHandle<()>> {
    effects
        .into_iter()
        .map(|effect| {
            let Effect::Webhook(d) = effect;
            let app = app.clone();
            tokio::spawn(async move {
                let mut last: (Option<u16>, Option<String>) = (None, None);
                for (attempt, delay) in [0u64, 2, 10].into_iter().enumerate() {
                    if delay > 0 {
                        tokio::time::sleep(Duration::from_secs(delay)).await;
                    }
                    last = send_webhook(&d, app.allow_private_webhooks).await;
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
            })
        })
        .collect()
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
        Ok::<_, anyhow::Error>(req.send().await?.status())
    };
    match attempt.await {
        Ok(status) if status.is_success() => (Some(status.as_u16()), None),
        Ok(status) => (Some(status.as_u16()), Some(format!("HTTP {status}"))),
        Err(e) => (None, Some(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::is_public;

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
