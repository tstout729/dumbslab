//! Connected apps. Each person can connect their own accounts in other apps (GitHub, Google
//! Drive, Jira, Slack…) and search them from the workspace, next to its own posts. Everyone sees
//! only what their own account can see in that app.
//!
//! - Credentials are encrypted at rest with the host's connector key ([`Connectors::key`]); no
//!   operation ever returns them.
//! - A person connects by signing in to the app (OAuth, once the host registered an app with it)
//!   or by pasting a personal token, for apps that have them.
//! - The core builds every request to an app and reads every answer; hosts only send HTTP. A
//!   [`Job`] runs in steps, each in its own database transaction: [`step`] answers either with
//!   requests for the host to send ([`Step::Fetch`]) or with the result ([`Step::Done`]).
//! - Each app is a [`Connector`] in [`providers`].

pub mod providers;

use std::collections::BTreeMap;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::db::{Db, DbExt};
use crate::error::{ApiError, ApiResult};
use crate::util::{parse_ts, sha256_hex, ts};
use crate::{HostConfig, Request, params};

/// How long a host waits for any one request to an app.
pub const FETCH_TIMEOUT_SECS: u64 = 8;
/// The most steps a job may take; a host stops a job that asks for more.
pub const MAX_STEPS: usize = 4;
/// How long a sign-in with another app may take.
const SIGN_IN_MINUTES: i64 = 15;
/// Tokens this close to expiring are refreshed before use.
const REFRESH_MARGIN_SECS: i64 = 60;

/// An OAuth app registered with a provider, so people can connect by signing in.
#[derive(Clone, Debug)]
pub struct OAuthApp {
    pub client_id: String,
    pub client_secret: String,
}

/// The host's settings for connected apps.
#[derive(Clone, Debug, Default)]
pub struct Connectors {
    /// Encrypts the credentials people connect. Without it, connecting apps is off.
    pub key: Option<String>,
    /// OAuth apps by provider id (`github`, `google-drive`…). A provider without one can still be
    /// connected with a personal token, if it has them.
    pub apps: BTreeMap<String, OAuthApp>,
    /// Where apps send people back after they sign in. Defaults to this server's
    /// `/connect/callback`; hosted DumbSlab uses the root domain's, which forwards to the workspace.
    pub callback_url: Option<String>,
}

// ---------------------------------------------------------------------------
// HTTP, as the core describes it to hosts

/// One request for the host to send.
#[derive(Clone, PartialEq)]
pub struct HttpCall {
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

// Requests carry tokens; never print them.
impl std::fmt::Debug for HttpCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.method, self.url.split('?').next().unwrap_or_default())
    }
}

impl HttpCall {
    pub fn get(url: impl Into<String>) -> HttpCall {
        HttpCall { method: "GET", url: url.into(), headers: vec![], body: None }
    }

    pub fn post_form(url: impl Into<String>, form: &[(&str, &str)]) -> HttpCall {
        let body = form.iter().map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v))).collect::<Vec<_>>().join("&");
        HttpCall {
            method: "POST",
            url: url.into(),
            headers: vec![("content-type".into(), "application/x-www-form-urlencoded".into())],
            body: Some(body),
        }
    }

    pub fn post_json(url: impl Into<String>, body: &Value) -> HttpCall {
        HttpCall {
            method: "POST",
            url: url.into(),
            headers: vec![("content-type".into(), "application/json".into())],
            body: Some(body.to_string()),
        }
    }

    pub fn header(mut self, name: &str, value: impl Into<String>) -> HttpCall {
        self.headers.push((name.to_string(), value.into()));
        self
    }

    pub fn bearer(self, token: &str) -> HttpCall {
        self.header("authorization", format!("Bearer {token}"))
    }

    pub fn basic(self, user: &str, password: &str) -> HttpCall {
        self.header("authorization", format!("Basic {}", STANDARD.encode(format!("{user}:{password}"))))
    }
}

/// The answer to an [`HttpCall`]. Status 0 means none arrived (a network error or timeout).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HttpReply {
    pub status: u16,
    pub body: String,
}

impl HttpReply {
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

// ---------------------------------------------------------------------------
// Providers

/// Something a person fills in to connect with a personal token.
#[derive(Clone, Copy, Debug, Serialize, JsonSchema)]
pub struct Field {
    pub key: &'static str,
    pub label: &'static str,
    pub help: &'static str,
    /// Stored encrypted and never shown again.
    pub secret: bool,
    pub optional: bool,
}

/// How a provider's OAuth sign-in works.
#[derive(Clone, Copy, Debug)]
pub struct OAuthSpec {
    pub authorize_url: &'static str,
    pub token_url: &'static str,
    pub scopes: &'static [&'static str],
    /// `scope`, or Slack's `user_scope` for user tokens.
    pub scope_param: &'static str,
    pub scope_separator: &'static str,
    /// Extra query parameters for the authorize URL.
    pub extra: &'static [(&'static str, &'static str)],
    pub pkce: bool,
}

/// What the workspace shows about a provider.
#[derive(Clone, Copy, Debug)]
pub struct ProviderInfo {
    /// `github`, `google-drive`…
    pub id: &'static str,
    pub name: &'static str,
    /// What connecting it gives you, for Settings, e.g. "Search issues and pull requests, and
    /// preview linked ones."
    pub about: &'static str,
    /// [`Connector::search`] works: search_connected includes this app.
    pub search: bool,
    /// [`Connector::preview_target`] recognizes links to this app's items.
    pub preview: bool,
    pub oauth: Option<OAuthSpec>,
    /// What a person fills in to connect with a personal token instead of signing in. Empty when
    /// the app has no such tokens. The one with key `token` is the token itself.
    pub token_fields: &'static [Field],
    /// Where to make such a token.
    pub token_help: &'static str,
}

/// A connected account's secrets. Encrypted at rest; never printed.
#[derive(Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Credential {
    pub token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Other fields the person filled in, e.g. a Zendesk subdomain or an Atlassian email.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credential(…)")
    }
}

impl Credential {
    pub fn field(&self, key: &str) -> &str {
        self.fields.get(key).map(String::as_str).unwrap_or_default()
    }
}

/// Who a connected account is, and settings found when connecting it (not secret).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Account {
    /// Shown in Settings, e.g. `@ada` or `ada@acme.com`.
    pub label: String,
    pub settings: Value,
}

/// Tokens from an OAuth token endpoint.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TokenSet {
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// Seconds until the access token expires, when it does.
    pub expires_in: Option<i64>,
    /// Anything else the answer says that later requests need (e.g. Wrike's API host); kept with
    /// the credential's fields.
    pub fields: BTreeMap<String, String>,
}

/// One result from a connected app.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Hit {
    /// The app, e.g. `github`.
    pub provider: String,
    /// What it is there: `issue`, `pull_request`, `repository`, `file`, `message`, `page`, `ticket`, `task`…
    pub kind: String,
    pub title: String,
    pub url: String,
    /// Where it lives, e.g. `acme/api #12 · open`, a folder or a channel.
    pub context: String,
    /// Plain text from it, when the app gives some.
    pub snippet: String,
    pub updated_at: Option<String>,
    pub author: Option<String>,
}

/// A label and value worth showing in a preview, e.g. ("Board", "Platform").
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Detail {
    pub label: String,
    pub value: String,
}

/// A linked item, previewed from the viewer's own connected account.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Preview {
    /// The app, e.g. `github`.
    pub provider: String,
    /// `issue`, `pull_request`, `ticket`, `task`, `card`…
    pub kind: String,
    pub title: String,
    pub url: String,
    /// How the app names it, e.g. `acme/api #12` or `PROJ-123`.
    pub reference: String,
    /// e.g. `open`, `In progress`, `closed`.
    pub status: Option<String>,
    pub assignee: Option<String>,
    pub author: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    /// Plain text, shortened.
    pub description: String,
    /// Other facts worth showing.
    pub details: Vec<Detail>,
}

/// One app DumbSlab can connect to.
pub trait Connector: Sync {
    fn info(&self) -> &'static ProviderInfo;

    /// Requests that check the credentials and say whose account they are.
    fn profile(&self, cred: &Credential) -> Vec<HttpCall>;

    /// Reads the answers to [`Connector::profile`]. An error explains what's wrong, for the person.
    fn read_profile(&self, cred: &Credential, replies: &[HttpReply]) -> Result<Account, String>;

    /// Requests that search the app for `q`.
    fn search(&self, cred: &Credential, account: &Account, q: &str, limit: usize) -> Vec<HttpCall>;

    /// Reads the answers to [`Connector::search`], best first, at most `limit`.
    fn read_search(&self, account: &Account, replies: &[HttpReply], limit: usize) -> Result<Vec<Hit>, String>;

    /// The request that exchanges a sign-in code (or a refresh token) for tokens. `form` holds
    /// the standard OAuth fields; most apps take them, with the client's, as a form.
    fn token_request(&self, app: &OAuthApp, form: Vec<(String, String)>) -> HttpCall {
        let spec = self.info().oauth.expect("only OAuth providers exchange tokens");
        let mut all = form;
        all.push(("client_id".into(), app.client_id.clone()));
        all.push(("client_secret".into(), app.client_secret.clone()));
        let pairs: Vec<(&str, &str)> = all.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        HttpCall::post_form(spec.token_url, &pairs).header("accept", "application/json")
    }

    /// Reads the token endpoint's answer. Most apps answer with standard OAuth JSON.
    fn read_token(&self, reply: &HttpReply) -> Result<TokenSet, String> {
        standard_token(self.info().name, reply)
    }

    /// Recognizes a link to one of this app's items and returns what identifies it, for
    /// [`Connector::preview`]. `account` matters for apps on their own domains (a Jira site, a
    /// Zendesk subdomain). Apps without previews keep the default.
    fn preview_target(&self, _account: &Account, _url: &str) -> Option<String> {
        None
    }

    /// Requests that read the item [`Connector::preview_target`] found.
    fn preview(&self, _cred: &Credential, _account: &Account, _target: &str) -> Vec<HttpCall> {
        vec![]
    }

    /// Reads the answers to [`Connector::preview`].
    fn read_preview(&self, _account: &Account, _target: &str, _replies: &[HttpReply]) -> Result<Preview, String> {
        Err(format!("{} has no previews.", self.info().name))
    }
}

/// A URL's host, lowercase, without port or `www.`.
pub fn host_of(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    let host = rest.split(['/', '?', '#']).next()?.rsplit('@').next()?.split(':').next()?.to_ascii_lowercase();
    Some(host.strip_prefix("www.").map(str::to_string).unwrap_or(host)).filter(|h| !h.is_empty())
}

/// A URL's path segments, without the query or fragment.
pub fn path_of(url: &str) -> Vec<String> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let path = rest.split(['?', '#']).next().unwrap_or_default();
    path.split('/')
        .skip(1)
        .filter(|s| !s.is_empty())
        .map(|s| urlencoding::decode(s).map(|c| c.into_owned()).unwrap_or_else(|_| s.to_string()))
        .collect()
}

/// Reads a standard OAuth token answer.
pub fn standard_token(name: &str, reply: &HttpReply) -> Result<TokenSet, String> {
    let v = reply.json();
    match v["access_token"].as_str() {
        Some(t) if reply.ok() && !t.is_empty() => Ok(TokenSet {
            access_token: t.to_string(),
            refresh_token: v["refresh_token"].as_str().map(str::to_string),
            expires_in: v["expires_in"].as_i64(),
            fields: BTreeMap::new(),
        }),
        _ => Err(format!(
            "{name} didn't accept the sign-in ({}). Try connecting again.",
            v["error_description"].as_str().or(v["error"].as_str()).unwrap_or(&format!("HTTP {}", reply.status))
        )),
    }
}

/// The message for a failed request, from the usual statuses.
pub fn http_error(name: &str, reply: &HttpReply) -> String {
    match reply.status {
        0 => format!("{name} didn't answer in time."),
        401 => format!("{name} rejected the saved credentials. Reconnect {name} in Settings › Connected apps."),
        403 => format!("{name} refused: the connected account may lack access, or the rate limit was reached. Try again in a minute."),
        429 => format!("{name}'s rate limit was reached. Try again in a minute."),
        s if s >= 500 => format!("{name} had an error (HTTP {s}). Try again later."),
        s => format!("{name} answered HTTP {s}."),
    }
}

/// Only web links leave the core: an app's answer could hold a `javascript:` URL.
fn web_link(url: &str) -> String {
    let lower = url.trim().to_ascii_lowercase();
    if lower.starts_with("https://") || lower.starts_with("http://") { url.trim().to_string() } else { String::new() }
}

/// Plain text, whitespace collapsed, at most `max` characters.
pub fn excerpt(text: &str, max: usize) -> String {
    let collapsed: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() <= max {
        return collapsed;
    }
    let mut cut: String = collapsed.chars().take(max).collect();
    if let Some(i) = cut.rfind(' ') {
        cut.truncate(i);
    }
    format!("{cut}…")
}

/// A Markdown description (GitHub, GitLab, Linear…) as a plain-text excerpt.
pub fn markdown_excerpt(md: &str, max: usize) -> String {
    excerpt(&crate::markdown::plain_text(head(md, 64 * 1024)), max)
}

/// HTML as plain text, in time linear in its length: tags dropped (all but inline ones leave a
/// space), scripts and styles skipped with their content, entities decoded. Reads at most 64 KB;
/// previews and snippets need far less.
pub fn html_text(html: &str) -> String {
    const INLINE: &[&str] = &["a", "abbr", "b", "code", "em", "i", "mark", "s", "small", "span", "strong", "sub", "sup", "u"];
    let html = head(html, 64 * 1024);
    // ASCII lowercasing keeps every byte offset, so `lower` and `html` index alike.
    let lower = html.to_ascii_lowercase();
    let mut out = String::with_capacity(html.len());
    let mut at = 0;
    while let Some(found) = html[at..].find('<') {
        let start = at + found;
        out.push_str(&html[at..start]);
        let end = html[start..].find('>').map_or(html.len(), |e| start + e + 1);
        let tag = &lower[start + 1..end];
        let closing = tag.starts_with('/');
        let name: String = tag.trim_start_matches('/').chars().take_while(char::is_ascii_alphanumeric).collect();
        at = end;
        if !closing && matches!(name.as_str(), "script" | "style") {
            // Searching on from here only: each byte is looked at a bounded number of times.
            at = match lower[at..].find(&format!("</{name}")) {
                Some(i) => html[at + i..].find('>').map_or(html.len(), |e| at + i + e + 1),
                None => html.len(),
            };
        }
        if !INLINE.contains(&name.as_str()) {
            out.push(' ');
        }
    }
    out.push_str(&html[at..]);
    decode_entities(&out)
}

/// `&amp;`, `&lt;`, `&#39;`, `&#x27;` and the like decoded; anything else left as it is. Linear:
/// an entity's `;` is looked for only in the next few bytes.
pub fn decode_entities(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let from = &rest[i..];
        let semi = from.bytes().take(12).position(|b| b == b';');
        let decoded = semi.and_then(|e| {
            let name = &from[1..e];
            let ch = match name {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                "nbsp" => Some(' '),
                "hellip" => Some('…'),
                _ => match name.strip_prefix("#x").or_else(|| name.strip_prefix("#X")) {
                    Some(hex) => u32::from_str_radix(hex, 16).ok(),
                    None => name.strip_prefix('#').and_then(|d| d.parse().ok()),
                }
                .and_then(char::from_u32),
            };
            ch.map(|c| (c, e))
        });
        match decoded {
            Some((c, e)) => {
                out.push(c);
                rest = &from[e + 1..];
            }
            None => {
                out.push('&');
                rest = &from[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// At most `max` bytes of `s`, cut at a character boundary.
fn head(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// A JSON string field, or "".
pub fn s(v: &Value) -> String {
    v.as_str().unwrap_or_default().to_string()
}

/// A JSON string field, or None.
pub fn opt(v: &Value) -> Option<String> {
    v.as_str().filter(|x| !x.is_empty()).map(str::to_string)
}

// ---------------------------------------------------------------------------
// Encryption

fn cipher(key: &str) -> Aes256Gcm {
    let digest = Sha256::digest(format!("dumbslab-connections|{key}").as_bytes());
    Aes256Gcm::new_from_slice(digest.as_slice()).expect("SHA-256 gives a 32-byte key")
}

fn aad(user_id: &str, provider: &str) -> String {
    format!("{user_id}|{provider}")
}

/// Encrypts a credential for one person's connection to one app.
pub fn seal(key: &str, user_id: &str, provider: &str, cred: &Credential) -> ApiResult<String> {
    let plain = serde_json::to_vec(cred).map_err(|e| ApiError::internal(e.to_string()))?;
    let nonce: [u8; 12] = crate::util::random_bytes();
    let aad = aad(user_id, provider);
    let sealed = cipher(key)
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: &plain, aad: aad.as_bytes() })
        .map_err(|_| ApiError::internal("couldn't encrypt the credentials"))?;
    let mut out = nonce.to_vec();
    out.extend(sealed);
    Ok(format!("v1.{}", URL_SAFE_NO_PAD.encode(out)))
}

/// Decrypts what [`seal`] made. Fails for another person's or app's credentials, or another key.
pub fn open(key: &str, user_id: &str, provider: &str, sealed: &str) -> ApiResult<Credential> {
    let bad = || ApiError::internal("stored credentials can't be read; reconnect the app");
    let bytes = URL_SAFE_NO_PAD.decode(sealed.strip_prefix("v1.").ok_or_else(bad)?).map_err(|_| bad())?;
    if bytes.len() < 13 {
        return Err(bad());
    }
    let (nonce, body) = bytes.split_at(12);
    let aad = aad(user_id, provider);
    let plain = cipher(key).decrypt(Nonce::from_slice(nonce), Payload { msg: body, aad: aad.as_bytes() }).map_err(|_| bad())?;
    serde_json::from_slice(&plain).map_err(|_| bad())
}

// ---------------------------------------------------------------------------
// Stored connections

/// One person's connection to one app, decrypted.
#[derive(Clone, Debug)]
pub struct Connection {
    pub provider: &'static str,
    pub account: Account,
    pub cred: Credential,
    pub expires_at: Option<DateTime<Utc>>,
    pub connected_at: String,
}

fn key_of(cfg: &HostConfig) -> ApiResult<&str> {
    cfg.connectors
        .key
        .as_deref()
        .filter(|k| !k.is_empty())
        .ok_or_else(|| ApiError::new(503, "connections_off", "Connected apps aren't set up on this server: it has no connector key."))
}

pub fn enabled(cfg: &HostConfig) -> bool {
    key_of(cfg).is_ok()
}

fn read_row(cfg: &HostConfig, user_id: &str, r: &crate::db::Row) -> ApiResult<Option<Connection>> {
    let Some(p) = providers::get(&r.str("provider")) else { return Ok(None) };
    let cred = open(key_of(cfg)?, user_id, p.info().id, &r.str("secret"))?;
    Ok(Some(Connection {
        provider: p.info().id,
        account: Account { label: r.str("account"), settings: serde_json::from_str(&r.str("settings")).unwrap_or(json!({})) },
        cred,
        expires_at: r.opt_str("expires_at").and_then(|s| parse_ts(&s)),
        connected_at: r.str("created_at"),
    }))
}

/// A person's connections, for the apps this server knows.
pub fn connections(db: &dyn Db, cfg: &HostConfig, user_id: &str) -> ApiResult<Vec<Connection>> {
    let rows = db.query(
        "SELECT provider, account, settings, secret, expires_at, created_at FROM connections WHERE user_id = ? ORDER BY provider",
        &params![user_id],
    )?;
    let mut out = vec![];
    for r in &rows {
        if let Some(c) = read_row(cfg, user_id, r)? {
            out.push(c);
        }
    }
    Ok(out)
}

/// Saves the connection a [`ConnectJob`] made.
fn save(db: &dyn Db, cfg: &HostConfig, j: &ConnectJob, account: &Account, now: DateTime<Utc>) -> ApiResult<()> {
    let secret = seal(key_of(cfg)?, &j.user_id, j.provider, &j.cred)?;
    db.execute(
        "INSERT INTO connections (user_id, provider, account, settings, secret, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(user_id, provider) DO UPDATE SET account = excluded.account, settings = excluded.settings, secret = excluded.secret,
           expires_at = excluded.expires_at, updated_at = excluded.updated_at",
        &params![j.user_id.clone(), j.provider, account.label.clone(), account.settings.to_string(), secret, j.expires_at.map(ts), ts(now), ts(now)],
    )?;
    Ok(())
}

/// Saves a refreshed token, keeping everything else.
fn save_token(db: &dyn Db, cfg: &HostConfig, user_id: &str, conn: &Connection, now: DateTime<Utc>) -> ApiResult<()> {
    let secret = seal(key_of(cfg)?, user_id, conn.provider, &conn.cred)?;
    db.execute(
        "UPDATE connections SET secret = ?, expires_at = ?, updated_at = ? WHERE user_id = ? AND provider = ?",
        &params![secret, conn.expires_at.map(ts), ts(now), user_id, conn.provider],
    )?;
    Ok(())
}

pub fn remove(db: &dyn Db, user_id: &str, provider: &str) -> ApiResult<bool> {
    Ok(db.execute("DELETE FROM connections WHERE user_id = ? AND provider = ?", &params![user_id, provider])? > 0)
}

// ---------------------------------------------------------------------------
// Signing in with an app (OAuth)

/// Where apps send people back after they sign in.
pub fn callback_url(cfg: &HostConfig, base_url: &str) -> String {
    cfg.connectors.callback_url.clone().unwrap_or_else(|| format!("{base_url}/connect/callback"))
}

pub fn oauth_app<'a>(cfg: &'a HostConfig, provider: &str) -> Option<&'a OAuthApp> {
    cfg.connectors.apps.get(provider).filter(|a| !a.client_id.is_empty() && !a.client_secret.is_empty())
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Starts signing in with an app: records who asked, and returns the app's sign-in URL. On
/// hosted DumbSlab the `state` starts with the workspace address, so the root domain can send the
/// person back to their workspace.
pub fn start_sign_in(
    db: &dyn Db,
    cfg: &HostConfig,
    base_url: &str,
    user_id: &str,
    connector: &dyn Connector,
    now: DateTime<Utc>,
) -> ApiResult<String> {
    key_of(cfg)?;
    let info = connector.info();
    let (Some(spec), Some(app)) = (info.oauth, oauth_app(cfg, info.id)) else {
        return Err(ApiError::bad_request(format!(
            "signing in with {} isn't set up on this server; connect with a token instead",
            info.name
        )));
    };
    db.execute("DELETE FROM connect_requests WHERE created_at < ?", &params![ts(now - Duration::minutes(SIGN_IN_MINUTES))])?;
    let random = crate::util::new_secret("");
    let state = match &cfg.workspace {
        Some(address) => format!("{address}.{random}"),
        None => random,
    };
    let verifier = spec.pkce.then(|| crate::util::new_secret("") + &crate::util::new_secret(""));
    db.execute(
        "INSERT INTO connect_requests (state_hash, user_id, provider, verifier, created_at) VALUES (?, ?, ?, ?, ?)",
        &params![sha256_hex(&state), user_id, info.id, verifier.clone(), ts(now)],
    )?;
    let mut query: Vec<(String, String)> = vec![
        ("client_id".into(), app.client_id.clone()),
        ("redirect_uri".into(), callback_url(cfg, base_url)),
        ("response_type".into(), "code".into()),
        ("state".into(), state),
    ];
    if !spec.scopes.is_empty() {
        query.push((spec.scope_param.into(), spec.scopes.join(spec.scope_separator)));
    }
    for (k, v) in spec.extra {
        query.push(((*k).into(), (*v).into()));
    }
    if let Some(v) = &verifier {
        query.push(("code_challenge".into(), pkce_challenge(v)));
        query.push(("code_challenge_method".into(), "S256".into()));
    }
    let qs = query.iter().map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v))).collect::<Vec<_>>().join("&");
    Ok(format!("{}?{qs}", spec.authorize_url))
}

/// The settings page, with a result for the person to see.
fn settings_url(base_url: &str, outcome: Result<&str, &str>) -> String {
    match outcome {
        Ok(provider) => format!("{base_url}/settings/connections?connected={}", urlencoding::encode(provider)),
        Err(message) => format!("{base_url}/settings/connections?connect_error={}", urlencoding::encode(message)),
    }
}

/// `GET /connect/callback`: an app sent the person back after they signed in. The signed-in
/// person must be the one who started it. Answers with a job that finishes connecting and then
/// sends them to Settings.
pub fn callback(db: &dyn Db, cfg: &HostConfig, req: &Request) -> crate::Outcome {
    let base = crate::http::base_url(cfg, req);
    let redirect = |url: String| crate::http::done(crate::Response::redirect(&url));
    let query: BTreeMap<String, String> = req
        .query
        .split('&')
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| {
            let decode = |s: &str| urlencoding::decode(&s.replace('+', " ")).map(|c| c.into_owned()).unwrap_or_default();
            (decode(k), decode(v))
        })
        .collect();
    let now = Utc::now();
    let run = || -> ApiResult<crate::Outcome> {
        let state = query.get("state").cloned().unwrap_or_default();
        let Some(row) = db.one(
            "SELECT user_id, provider, verifier, created_at FROM connect_requests WHERE state_hash = ?",
            &params![sha256_hex(&state)],
        )?
        else {
            return Ok(redirect(settings_url(&base, Err("That sign-in link is no longer valid. Start connecting again."))));
        };
        let started = parse_ts(&row.str("created_at")).unwrap_or(now);
        let provider = row.str("provider");
        db.execute("DELETE FROM connect_requests WHERE state_hash = ?", &params![sha256_hex(&state)])?;
        let actor = crate::auth::authenticate(db, cfg, req, now)?;
        if actor.as_ref().map(|a| a.user_id.as_str()) != Some(row.str("user_id").as_str()) {
            return Ok(redirect(settings_url(
                &base,
                Err("Sign in to the workspace as the person who started connecting, then try again."),
            )));
        }
        if now - started > Duration::minutes(SIGN_IN_MINUTES) {
            return Ok(redirect(settings_url(&base, Err("Signing in took too long. Start connecting again."))));
        }
        let Some(connector) = providers::get(&provider) else {
            return Ok(redirect(settings_url(&base, Err("That app isn't available any more."))));
        };
        let code = match (query.get("code"), query.get("error")) {
            (Some(c), _) if !c.is_empty() => c.clone(),
            (_, Some(e)) => {
                let why = query.get("error_description").cloned().unwrap_or_else(|| e.clone());
                return Ok(redirect(settings_url(&base, Err(&format!("{} didn't connect: {why}", connector.info().name)))));
            }
            _ => return Ok(redirect(settings_url(&base, Err("The app sent no sign-in code. Try again.")))),
        };
        let job = Job::Connect(ConnectJob {
            user_id: row.str("user_id"),
            provider: connector.info().id,
            sign_in: Some(SignIn { code, verifier: row.opt_str("verifier"), redirect_uri: callback_url(cfg, &base) }),
            cred: Credential::default(),
            expires_at: None,
            phase: ConnectPhase::Start,
            back_to: Some(base.clone()),
        });
        let mut out = redirect(settings_url(&base, Err("Connecting didn't finish. Try again.")));
        out.effects.push(crate::Effect::Connect(job));
        Ok(out)
    };
    run().unwrap_or_else(|e| redirect(settings_url(&base, Err(&e.message))))
}

// ---------------------------------------------------------------------------
// Jobs

/// Stands in for a result the host fills in once a job finishes.
pub const PENDING: &str = "dumbslab:connect-pending";

/// An operation's answer that's either ready, or filled in by the host when its job finishes.
/// Its schema is `T`'s.
#[derive(Debug)]
pub enum Deferred<T> {
    Ready(T),
    Pending,
}

impl<T: Serialize> Serialize for Deferred<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Deferred::Ready(v) => v.serialize(serializer),
            Deferred::Pending => serializer.serialize_str(PENDING),
        }
    }
}

impl<T: JsonSchema> JsonSchema for Deferred<T> {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        T::schema_name()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        T::json_schema(generator)
    }

    fn inline_schema() -> bool {
        T::inline_schema()
    }
}

/// Puts a job's result into the response in place of [`PENDING`]: as JSON where the placeholder
/// is a JSON string (REST, MCP's structured content), and as escaped JSON where it sits inside a
/// string (MCP's text content).
pub fn fill_pending(body: &[u8], value: &Value) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(body).ok()?;
    if !text.contains(PENDING) {
        return None;
    }
    let raw = serde_json::to_string(value).ok()?;
    let escaped = serde_json::to_string(&raw).ok()?;
    let escaped = &escaped[1..escaped.len() - 1];
    Some(text.replace(&format!("\\\"{PENDING}\\\""), escaped).replace(&format!("\"{PENDING}\""), &raw).into_bytes())
}

/// The answer to send once a job finished: `response` with the result filled in, a redirect, or
/// an error.
pub fn respond(mut response: crate::Response, finish: Finish) -> crate::Response {
    match finish {
        Finish::Fill(value) => match fill_pending(&response.body, &value) {
            Some(body) => {
                response.body = body;
                response
            }
            None => crate::Response::error(&ApiError::internal("the result had nowhere to go")),
        },
        Finish::Redirect(url) => crate::Response::redirect(&url).with_header("cache-control", "no-store"),
        Finish::Fail(e) => crate::Response::error(&e),
    }
}

/// Response bodies read from an app, at most. Larger answers are cut off (and won't parse).
pub const MAX_REPLY_BYTES: usize = 4 * 1024 * 1024;

/// What a job does next.
#[derive(Debug)]
pub enum Step {
    /// Send these requests, then call [`step`] again with the answers, in the same order.
    Fetch(Vec<HttpCall>),
    Done(Finish),
}

/// How a job ends.
#[derive(Debug)]
pub enum Finish {
    /// Answer the request with this result in place of [`PENDING`].
    Fill(Value),
    /// Send the browser here.
    Redirect(String),
    /// Answer with this error.
    Fail(ApiError),
}

/// Work that needs requests to other apps.
#[derive(Clone, Debug)]
pub enum Job {
    Search(SearchJob),
    Preview(PreviewJob),
    Connect(ConnectJob),
}

#[derive(Clone, Debug)]
pub struct SearchJob {
    pub user_id: String,
    pub q: String,
    pub limit: usize,
    /// Only these apps; every connected one when empty.
    pub only: Vec<String>,
    phase: SearchPhase,
}

#[derive(Clone, Debug)]
enum SearchPhase {
    Start,
    /// Refreshing these connections' tokens first.
    Refreshing(Vec<Connection>, Vec<Connection>),
    /// Waiting for search answers: each connection and how many requests it sent.
    Searching(Vec<(Connection, usize)>, Vec<AppResult>),
}

impl SearchJob {
    pub fn new(user_id: &str, q: &str, limit: usize, only: Vec<String>) -> SearchJob {
        SearchJob { user_id: user_id.into(), q: q.into(), limit, only, phase: SearchPhase::Start }
    }
}

#[derive(Clone, Debug)]
pub struct PreviewJob {
    pub user_id: String,
    conn: Connection,
    target: String,
    phase: PreviewPhase,
}

#[derive(Clone, Copy, Debug)]
enum PreviewPhase {
    Start,
    Refreshing,
    Fetching,
}

impl PreviewJob {
    /// Previews `target` (from [`Connector::preview_target`]) with the person's connection.
    pub fn new(user_id: &str, conn: Connection, target: String) -> PreviewJob {
        PreviewJob { user_id: user_id.into(), conn, target, phase: PreviewPhase::Start }
    }
}

/// A link's preview, from the viewer's own account in the app it points to.
#[derive(Clone, Debug, Default, Serialize, JsonSchema)]
pub struct LinkPreview {
    /// The app the link points to, when one recognizes it.
    pub app: Option<String>,
    /// You have that app connected; previews use your own account.
    pub connected: bool,
    pub preview: Option<Preview>,
    /// Why there's no preview, for the person.
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SignIn {
    pub code: String,
    pub verifier: Option<String>,
    pub redirect_uri: String,
}

#[derive(Clone, Debug)]
pub struct ConnectJob {
    pub user_id: String,
    pub provider: &'static str,
    /// Set when the person signed in with the app; otherwise `cred` holds their token.
    pub sign_in: Option<SignIn>,
    pub cred: Credential,
    pub expires_at: Option<DateTime<Utc>>,
    phase: ConnectPhase,
    /// Where to send the browser at the end (sign-ins); `None` fills the operation's answer.
    pub back_to: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum ConnectPhase {
    Start,
    Exchanging,
    Profiling,
}

impl ConnectJob {
    /// Connecting with a personal token.
    pub fn with_token(user_id: &str, provider: &'static str, cred: Credential) -> ConnectJob {
        ConnectJob { user_id: user_id.into(), provider, sign_in: None, cred, expires_at: None, phase: ConnectPhase::Start, back_to: None }
    }
}

/// How one app's search went.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct AppResult {
    pub provider: String,
    pub name: String,
    pub ok: bool,
    /// Why it failed, for the person.
    pub error: Option<String>,
    pub count: usize,
}

/// Results from a person's connected apps.
#[derive(Clone, Debug, Default, Serialize, JsonSchema)]
pub struct ConnectedResults {
    /// Each app's results in turn, best first within each.
    pub items: Vec<Hit>,
    /// How each connected app's search went.
    pub apps: Vec<AppResult>,
}

/// A connected account, as Settings shows it.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ConnectedAccount {
    pub provider: String,
    pub name: String,
    /// e.g. `@ada` or `ada@acme.com`.
    pub account: String,
    pub connected_at: String,
}

/// The token expires soon and can be refreshed.
fn needs_refresh(cfg: &HostConfig, conn: &Connection, now: DateTime<Utc>) -> bool {
    conn.cred.refresh_token.is_some()
        && conn.expires_at.is_some_and(|e| e - Duration::seconds(REFRESH_MARGIN_SECS) <= now)
        && oauth_app(cfg, conn.provider).is_some()
}

fn refresh_call(cfg: &HostConfig, conn: &Connection) -> HttpCall {
    let p = providers::get(conn.provider).expect("known provider");
    let app = oauth_app(cfg, conn.provider).expect("checked by needs_refresh");
    let refresh = conn.cred.refresh_token.clone().unwrap_or_default();
    p.token_request(app, vec![("grant_type".into(), "refresh_token".into()), ("refresh_token".into(), refresh)])
}

/// Saves a refreshed token. `false` when the app refused: the person must connect again.
fn apply_refresh(
    db: &dyn Db,
    cfg: &HostConfig,
    user_id: &str,
    conn: &mut Connection,
    reply: &HttpReply,
    now: DateTime<Utc>,
) -> ApiResult<bool> {
    let p = providers::get(conn.provider).expect("known provider");
    let Ok(tokens) = p.read_token(reply) else {
        // Apps that hand out a new refresh token each time (Box, Atlassian, monday) refuse the old
        // one once another request used it first. That request saved fresh tokens: use them.
        let saved = connections(db, cfg, user_id)?.into_iter().find(|c| c.provider == conn.provider);
        if let Some(saved) = saved.filter(|s| s.cred.token != conn.cred.token && !needs_refresh(cfg, s, now)) {
            *conn = saved;
            return Ok(true);
        }
        return Ok(false);
    };
    conn.cred.token = tokens.access_token.clone();
    if let Some(r) = tokens.refresh_token.clone() {
        conn.cred.refresh_token = Some(r);
    }
    conn.cred.fields.extend(tokens.fields.clone());
    conn.expires_at = expiry(now, &tokens);
    save_token(db, cfg, user_id, conn, now)?;
    Ok(true)
}

fn reconnect_message(name: &str) -> String {
    format!("{name} needs you to connect it again (Settings › Connected apps).")
}

fn expiry(now: DateTime<Utc>, tokens: &TokenSet) -> Option<DateTime<Utc>> {
    tokens.expires_in.filter(|s| *s > 0).map(|s| now + Duration::seconds(s))
}

/// Runs a job's next step. Call it first with no replies, then with the answers to each
/// [`Step::Fetch`] until it's [`Step::Done`]. Each call reads or writes the database, so hosts run
/// it in its own transaction.
pub fn step(db: &dyn Db, cfg: &HostConfig, job: &mut Job, replies: Vec<HttpReply>, now: DateTime<Utc>) -> ApiResult<Step> {
    match job {
        Job::Search(j) => search_step(db, cfg, j, replies, now),
        Job::Preview(j) => preview_step(db, cfg, j, replies, now),
        Job::Connect(j) => connect_step(db, cfg, j, replies, now),
    }
}

fn preview_step(db: &dyn Db, cfg: &HostConfig, j: &mut PreviewJob, replies: Vec<HttpReply>, now: DateTime<Utc>) -> ApiResult<Step> {
    let p = providers::get(j.conn.provider).expect("known provider");
    let done = |preview: Result<Preview, String>| -> ApiResult<Step> {
        let (preview, error) = match preview {
            Ok(mut v) => {
                v.url = web_link(&v.url);
                (Some(v), None)
            }
            Err(e) => (None, Some(e)),
        };
        let value = LinkPreview { app: Some(p.info().id.into()), connected: true, preview, error };
        Ok(Step::Done(Finish::Fill(serde_json::to_value(value).map_err(|e| ApiError::internal(e.to_string()))?)))
    };
    match j.phase {
        PreviewPhase::Start if needs_refresh(cfg, &j.conn, now) => {
            j.phase = PreviewPhase::Refreshing;
            Ok(Step::Fetch(vec![refresh_call(cfg, &j.conn)]))
        }
        PreviewPhase::Refreshing
            if !apply_refresh(db, cfg, &j.user_id, &mut j.conn, &replies.first().cloned().unwrap_or_default(), now)? =>
        {
            done(Err(reconnect_message(p.info().name)))
        }
        PreviewPhase::Start | PreviewPhase::Refreshing => {
            j.phase = PreviewPhase::Fetching;
            Ok(Step::Fetch(p.preview(&j.conn.cred, &j.conn.account, &j.target)))
        }
        PreviewPhase::Fetching => done(p.read_preview(&j.conn.account, &j.target, &replies)),
    }
}

fn search_calls(j: &SearchJob, conns: Vec<Connection>) -> (Vec<HttpCall>, Vec<(Connection, usize)>) {
    let mut calls = vec![];
    let mut plan = vec![];
    for c in conns {
        let Some(p) = providers::get(c.provider).filter(|p| p.info().search) else { continue };
        let these = p.search(&c.cred, &c.account, &j.q, j.limit);
        plan.push((c, these.len()));
        calls.extend(these);
    }
    (calls, plan)
}

fn search_step(db: &dyn Db, cfg: &HostConfig, j: &mut SearchJob, replies: Vec<HttpReply>, now: DateTime<Utc>) -> ApiResult<Step> {
    match std::mem::replace(&mut j.phase, SearchPhase::Start) {
        SearchPhase::Start => {
            let conns: Vec<Connection> = connections(db, cfg, &j.user_id)?
                .into_iter()
                .filter(|c| j.only.is_empty() || j.only.iter().any(|o| o == c.provider))
                .collect();
            let (stale, fresh): (Vec<_>, Vec<_>) = conns.into_iter().partition(|c| needs_refresh(cfg, c, now));
            if !stale.is_empty() {
                let calls = stale.iter().map(|c| refresh_call(cfg, c)).collect();
                j.phase = SearchPhase::Refreshing(stale, fresh);
                return Ok(Step::Fetch(calls));
            }
            start_searching(j, fresh, vec![])
        }
        SearchPhase::Refreshing(stale, mut fresh) => {
            let mut failed = vec![];
            for (mut c, reply) in stale.into_iter().zip(replies) {
                if apply_refresh(db, cfg, &j.user_id, &mut c, &reply, now)? {
                    fresh.push(c);
                } else {
                    let name = providers::get(c.provider).expect("known provider").info().name;
                    failed.push(AppResult {
                        provider: c.provider.into(),
                        name: name.into(),
                        ok: false,
                        error: Some(reconnect_message(name)),
                        count: 0,
                    });
                }
            }
            start_searching(j, fresh, failed)
        }
        SearchPhase::Searching(plan, mut apps) => {
            let mut items = vec![];
            let mut replies = replies.into_iter();
            for (c, n) in plan {
                let p = providers::get(c.provider).expect("known provider");
                let these: Vec<HttpReply> = replies.by_ref().take(n).collect();
                match p.read_search(&c.account, &these, j.limit) {
                    Ok(mut hits) => {
                        hits.truncate(j.limit);
                        for hit in &mut hits {
                            hit.url = web_link(&hit.url);
                        }
                        apps.push(AppResult {
                            provider: c.provider.into(),
                            name: p.info().name.into(),
                            ok: true,
                            error: None,
                            count: hits.len(),
                        });
                        items.extend(hits);
                    }
                    Err(e) => apps.push(AppResult {
                        provider: c.provider.into(),
                        name: p.info().name.into(),
                        ok: false,
                        error: Some(e),
                        count: 0,
                    }),
                }
            }
            let value = serde_json::to_value(ConnectedResults { items, apps }).map_err(|e| ApiError::internal(e.to_string()))?;
            Ok(Step::Done(Finish::Fill(value)))
        }
    }
}

fn start_searching(j: &mut SearchJob, conns: Vec<Connection>, failed: Vec<AppResult>) -> ApiResult<Step> {
    let (calls, plan) = search_calls(j, conns);
    if calls.is_empty() {
        let value =
            serde_json::to_value(ConnectedResults { items: vec![], apps: failed }).map_err(|e| ApiError::internal(e.to_string()))?;
        return Ok(Step::Done(Finish::Fill(value)));
    }
    j.phase = SearchPhase::Searching(plan, failed);
    Ok(Step::Fetch(calls))
}

fn connect_step(db: &dyn Db, cfg: &HostConfig, j: &mut ConnectJob, replies: Vec<HttpReply>, now: DateTime<Utc>) -> ApiResult<Step> {
    let connector = providers::get(j.provider).ok_or_else(|| ApiError::bad_request("unknown app"))?;
    let name = connector.info().name;
    let fail = |j: &ConnectJob, message: String| -> Step {
        match &j.back_to {
            Some(base) => Step::Done(Finish::Redirect(settings_url(base, Err(&message)))),
            None => Step::Done(Finish::Fail(ApiError::new(400, "connect_failed", message))),
        }
    };
    match j.phase {
        ConnectPhase::Start => match &j.sign_in {
            Some(sign_in) => {
                let Some(app) = oauth_app(cfg, j.provider) else {
                    return Ok(fail(j, format!("Signing in with {name} isn't set up on this server any more.")));
                };
                let mut form = vec![
                    ("grant_type".into(), "authorization_code".into()),
                    ("code".into(), sign_in.code.clone()),
                    ("redirect_uri".into(), sign_in.redirect_uri.clone()),
                ];
                if let Some(v) = &sign_in.verifier {
                    form.push(("code_verifier".into(), v.clone()));
                }
                j.phase = ConnectPhase::Exchanging;
                Ok(Step::Fetch(vec![connector.token_request(app, form)]))
            }
            None => {
                j.phase = ConnectPhase::Profiling;
                Ok(Step::Fetch(connector.profile(&j.cred)))
            }
        },
        ConnectPhase::Exchanging => {
            let reply = replies.into_iter().next().unwrap_or_default();
            match connector.read_token(&reply) {
                Ok(tokens) => {
                    j.cred.token = tokens.access_token.clone();
                    j.cred.refresh_token = tokens.refresh_token.clone();
                    j.cred.fields.extend(tokens.fields.clone());
                    j.expires_at = expiry(now, &tokens);
                    j.phase = ConnectPhase::Profiling;
                    Ok(Step::Fetch(connector.profile(&j.cred)))
                }
                Err(e) => Ok(fail(j, e)),
            }
        }
        ConnectPhase::Profiling => match connector.read_profile(&j.cred, &replies) {
            Ok(account) => {
                save(db, cfg, j, &account, now)?;
                match &j.back_to {
                    Some(base) => Ok(Step::Done(Finish::Redirect(settings_url(base, Ok(j.provider))))),
                    None => {
                        let shown = ConnectedAccount {
                            provider: j.provider.into(),
                            name: name.into(),
                            account: account.label,
                            connected_at: ts(now),
                        };
                        let value = json!({ "authorize_url": null, "connection": shown });
                        Ok(Step::Done(Finish::Fill(value)))
                    }
                }
            }
            Err(e) => Ok(fail(j, e)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_are_sealed_per_person_and_app() {
        let cred = Credential { token: "ghp_secret".into(), refresh_token: Some("r".into()), fields: BTreeMap::new() };
        let sealed = seal("k1", "u1", "github", &cred).unwrap();
        assert!(!sealed.contains("ghp_secret"));
        assert_eq!(open("k1", "u1", "github", &sealed).unwrap(), cred);
        assert!(open("k2", "u1", "github", &sealed).is_err(), "another key");
        assert!(open("k1", "u2", "github", &sealed).is_err(), "another person's");
        assert!(open("k1", "u1", "gitlab", &sealed).is_err(), "another app's");
        assert_ne!(seal("k1", "u1", "github", &cred).unwrap(), sealed, "a fresh nonce each time");
        assert!(format!("{cred:?}").find("ghp_secret").is_none(), "never printed");
    }

    #[test]
    fn pending_results_fill_any_envelope() {
        let value = json!({ "items": [{ "title": "Say \"hi\"" }] });
        let rest = serde_json::to_vec(&json!(PENDING)).unwrap();
        let filled: Value = serde_json::from_slice(&fill_pending(&rest, &value).unwrap()).unwrap();
        assert_eq!(filled, value);
        let text = serde_json::to_string(&json!(PENDING)).unwrap();
        let mcp = serde_json::to_vec(&json!({ "result": { "content": [{ "type": "text", "text": text }], "structuredContent": PENDING } }))
            .unwrap();
        let filled: Value = serde_json::from_slice(&fill_pending(&mcp, &value).unwrap()).unwrap();
        assert_eq!(filled["result"]["structuredContent"], value);
        let inner: Value = serde_json::from_str(filled["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(inner, value);
        assert!(fill_pending(b"{}", &value).is_none());
    }

    #[test]
    fn only_web_links_leave() {
        assert_eq!(web_link(" https://x.test/a "), "https://x.test/a");
        assert_eq!(web_link("HTTP://x.test"), "HTTP://x.test");
        for bad in ["javascript:alert(1)", "data:text/html,x", "//x.test", "JaVaScRiPt:x"] {
            assert_eq!(web_link(bad), "", "{bad}");
        }
    }

    #[test]
    fn html_becomes_text_in_linear_time() {
        assert_eq!(html_text("<p>One</p><p>Two <b>bold</b>er</p>"), " One  Two bolder ");
        assert_eq!(html_text("a<script>alert('<p>')</script>b<STYLE>p{}</STYLE>c"), "a b c");
        assert_eq!(html_text("&lt;tag&gt; &amp;amp; &#39;x&#x27; &nbsp;&bogus; & done"), "<tag> &amp; 'x'  &bogus; & done");
        assert_eq!(html_text("unclosed <a href"), "unclosed ");
        assert_eq!(html_text("<!-- never closed"), " ");
        assert_eq!(html_text("é<b>ü</b>"), "éü");
        // Inputs built to make naive versions quadratic finish quickly.
        let started = std::time::Instant::now();
        html_text(&"<script>".repeat(200_000));
        html_text(&"<style>x".repeat(200_000));
        decode_entities(&"&".repeat(2_000_000));
        decode_entities(&"&amp".repeat(500_000));
        assert!(started.elapsed() < std::time::Duration::from_secs(2), "took {:?}", started.elapsed());
        assert_eq!(html_text(&"a".repeat(100_000)).len(), 64 * 1024, "capped");
    }

    #[test]
    fn excerpts() {
        assert_eq!(excerpt("  a \n b  ", 10), "a b");
        assert_eq!(excerpt("one two three four", 9), "one two…");
    }
}
