//! Single sign-on: people sign in to the workspace with their organization's identity provider
//! (Google Workspace, Microsoft Entra ID, Okta, OneLogin, Slack or any OpenID Connect provider).
//!
//! - Admins set it up for the workspace (`get_sso` and `update_sso` in [`crate::ops::sso`]). They
//!   register their own OIDC app with the provider; its redirect URI is the workspace's
//!   `/sso/callback`. The client secret is encrypted with the host's connector key, and no
//!   operation returns it. Without the key, single sign-on is off.
//! - Signing in is OpenID Connect's authorization code flow with PKCE (S256), a `state` (stored
//!   hashed, used once, within 15 minutes, by the browser that started) and a `nonce`. The core
//!   does no I/O: each network step is a [`crate::connect::Job`] the host runs, as for connected
//!   apps.
//! - The ID token comes straight from the token endpoint over TLS, so (OpenID Connect Core 1.0,
//!   3.1.3.7, step 6) its signature isn't checked. Its issuer, audience, authorized party, expiry,
//!   issue time and nonce are.
//! - Accounts are linked by (issuer, subject). A first sign-in attaches to an existing person by
//!   email only when the provider vouches for the address and its domain is one of the
//!   workspace's ([`vouched_email`]). Otherwise people link their accounts while signed in
//!   (`link_sso`), or join on their own when the workspace turns on auto-provisioning.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::auth::{self, Actor, Role, Scopes, Via};
use crate::connect::{self, Finish, HttpCall, HttpReply, Job, Step};
use crate::db::{Db, DbExt};
use crate::error::{ApiError, ApiResult};
use crate::events::{Event, emit};
use crate::registry::Ctx;
use crate::util::{parse_ts, sha256_hex, ts};
use crate::{Effect, HostConfig, Outcome, Request, Response, params};

/// Where the sign-in page sends people to sign in with the provider.
pub const START_PATH: &str = "/sso/start";
/// Where the provider sends them back: the redirect URI admins register.
pub const CALLBACK_PATH: &str = "/sso/callback";
/// Names the browser that started signing in, so nobody can finish it in someone else's.
const BROWSER_COOKIE: &str = "dumbslab_sso";
/// How long a sign-in may take.
const SIGN_IN_MINUTES: i64 = 15;
/// Sign-ins under way that are kept at most. Starting one needs no account, so this bounds them.
const MAX_PENDING: i64 = 1000;
/// Clock differences tolerated between this server and the provider.
const SKEW_SECS: i64 = 300;
const SCOPES: &str = "openid email profile";
/// The settings key the configuration is stored under.
const SETTING: &str = "sso";
/// Binds the sealed client secret to its use, apart from people's connected-app credentials.
const SECRET_AAD: &str = "sso-client-secret";

/// An identity provider, or rather the presets that fill in its issuer and its rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    /// Google Workspace (issuer `https://accounts.google.com`). Needs `allowed_domains`: only
    /// accounts whose hosted domain (`hd`) is one of them may sign in.
    Google,
    /// Microsoft Entra ID, for one directory (`tenant`).
    Microsoft,
    /// Okta: the org's issuer URL, e.g. `https://acme.okta.com`.
    Okta,
    /// OneLogin: the issuer URL, e.g. `https://acme.onelogin.com/oidc/2`.
    Onelogin,
    /// Sign in with Slack (issuer `https://slack.com`).
    Slack,
    /// Any other OpenID Connect provider, by its issuer URL.
    Oidc,
}

impl Provider {
    pub fn as_str(self) -> &'static str {
        match self {
            Provider::Google => "google",
            Provider::Microsoft => "microsoft",
            Provider::Okta => "okta",
            Provider::Onelogin => "onelogin",
            Provider::Slack => "slack",
            Provider::Oidc => "oidc",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Provider::Google => "Google",
            Provider::Microsoft => "Microsoft",
            Provider::Okta => "Okta",
            Provider::Onelogin => "OneLogin",
            Provider::Slack => "Slack",
            Provider::Oidc => "SSO",
        }
    }

    /// The issuer of providers that have just one.
    pub fn fixed_issuer(self) -> Option<&'static str> {
        match self {
            Provider::Google => Some("https://accounts.google.com"),
            Provider::Slack => Some("https://slack.com"),
            _ => None,
        }
    }
}

/// Microsoft's issuer for one directory. Only tenant-specific issuers: the shared `common` and
/// `organizations` endpoints would let any directory's accounts in.
pub fn microsoft_issuer(tenant: &str) -> String {
    format!("https://login.microsoftonline.com/{tenant}/v2.0")
}

// ---------------------------------------------------------------------------
// Configuration

/// The workspace's single sign-on settings, as stored.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub enabled: bool,
    pub provider: Option<Provider>,
    /// Exactly as the provider's discovery document gives it.
    pub issuer: String,
    /// Microsoft: the directory (tenant) ID.
    pub tenant: String,
    /// Slack: only this Slack workspace's people, when set.
    pub team: String,
    pub client_id: String,
    /// Sealed with the connector key; never returned.
    pub client_secret: Option<String>,
    /// Lowercase domains, e.g. `acme.com`.
    pub allowed_domains: Vec<String>,
    pub auto_provision: bool,
    pub require_sso: bool,
    /// Other OIDC providers: the name on the button.
    pub label: String,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("enabled", &self.enabled)
            .field("provider", &self.provider)
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

impl Config {
    /// The provider's name, as on the sign-in button.
    pub fn name(&self) -> String {
        match self.provider {
            Some(Provider::Oidc) | None if !self.label.trim().is_empty() => self.label.trim().to_string(),
            Some(p) => p.name().to_string(),
            None => "SSO".to_string(),
        }
    }

    /// Everything signing in needs is filled in.
    pub fn complete(&self) -> bool {
        let Some(provider) = self.provider else { return false };
        let specific = match provider {
            Provider::Google => !self.allowed_domains.is_empty(),
            Provider::Microsoft => !self.tenant.is_empty(),
            _ => true,
        };
        specific && !self.issuer.is_empty() && !self.client_id.is_empty() && self.client_secret.is_some()
    }

    /// What a sign-in must still match when it finishes: the same app at the same provider.
    fn fingerprint(&self) -> String {
        let provider = self.provider.map(Provider::as_str).unwrap_or_default();
        sha256_hex(&format!("{provider}|{}|{}|{}|{}", self.issuer, self.client_id, self.tenant, self.team))
    }

    fn domain_allowed(&self, domain: &str) -> bool {
        self.allowed_domains.iter().any(|d| d.eq_ignore_ascii_case(domain))
    }
}

pub fn load(db: &dyn Db) -> ApiResult<Config> {
    Ok(crate::ops::admin::setting(db, SETTING)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default())
}

pub fn save(db: &dyn Db, conf: &Config) -> ApiResult<()> {
    let value = serde_json::to_string(conf).map_err(|e| ApiError::internal(e.to_string()))?;
    crate::ops::admin::put_setting(db, SETTING, &value)
}

/// Encrypts a client secret for storing.
pub fn seal_secret(cfg: &HostConfig, secret: &str) -> ApiResult<String> {
    let key = connect::key(cfg).ok_or_else(off)?;
    connect::seal_bytes(key, SECRET_AAD, secret.as_bytes())
}

fn client_secret(cfg: &HostConfig, conf: &Config) -> Option<String> {
    let key = connect::key(cfg)?;
    let plain = connect::open_bytes(key, SECRET_AAD, conf.client_secret.as_deref()?)?;
    String::from_utf8(plain).ok()
}

/// The error for setting up single sign-on on a server without a connector key.
pub fn off() -> ApiError {
    ApiError::new(
        503,
        "sso_off",
        "Single sign-on isn't available on this server: it has no connector key to encrypt the client secret with.",
    )
}

/// People can sign in with the provider now: it's on, set up, and the server can read the secret.
pub fn active(cfg: &HostConfig, conf: &Config) -> bool {
    conf.enabled && conf.complete() && connect::key(cfg).is_some()
}

pub fn callback_url(base_url: &str) -> String {
    format!("{base_url}{CALLBACK_PATH}")
}

/// What the sign-in page shows about single sign-on. Public: no secrets.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct SignInOption {
    /// The provider's name, for "Sign in with …".
    pub name: String,
    /// Open this to sign in with the provider. Add `?next=/path` to land there afterwards.
    pub url: String,
    /// Password sign-in is for admins only.
    pub required: bool,
}

pub fn sign_in_option(db: &dyn Db, cfg: &HostConfig, base_url: &str) -> ApiResult<Option<SignInOption>> {
    let conf = load(db)?;
    Ok(active(cfg, &conf).then(|| SignInOption { name: conf.name(), url: format!("{base_url}{START_PATH}"), required: conf.require_sso }))
}

/// Why `role` may not sign in with a password, if it may not: a workspace that requires single
/// sign-on lets only admins use passwords, as a way in should the provider fail. It applies only
/// while single sign-on works, so a broken setup never locks everyone out.
pub fn password_refusal(db: &dyn Db, cfg: &HostConfig, role: Role) -> ApiResult<Option<ApiError>> {
    let conf = load(db)?;
    if role == Role::Admin || !conf.require_sso || !active(cfg, &conf) {
        return Ok(None);
    }
    let name = conf.name();
    Ok(Some(ApiError::new(403, "sso_required", format!("This workspace signs in with {name}. Use “Sign in with {name}” instead."))))
}

/// A domain as stored: lowercase, without `@` or a trailing dot. `None` when it isn't one.
pub fn normalize_domain(d: &str) -> Option<String> {
    let d = d.trim().trim_start_matches('@').trim_end_matches('.').to_ascii_lowercase();
    let ok = d.len() <= 253
        && d.contains('.')
        && d.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
    ok.then_some(d)
}

/// An issuer URL admins may enter: https, a host, no user, query or fragment.
pub fn valid_issuer(issuer: &str) -> bool {
    issuer.len() <= 300
        && issuer.starts_with("https://")
        && !issuer.contains(|c: char| c.is_whitespace() || c == '?' || c == '#' || c == '\\')
        && connect::host_of(issuer).is_some_and(|h| h.contains('.') || h == "localhost")
}

/// A Microsoft directory (tenant) ID: a GUID, lowercase. Domain names and `common` don't do: the
/// issuer the provider gives always names the GUID.
pub fn normalize_tenant(t: &str) -> Option<String> {
    let t = t.trim().to_ascii_lowercase();
    let groups: Vec<&str> = t.split('-').collect();
    let lens = [8, 4, 4, 4, 12];
    let ok = groups.len() == 5 && groups.iter().zip(lens).all(|(g, n)| g.len() == n && g.chars().all(|c| c.is_ascii_hexdigit()));
    ok.then_some(t)
}

// ---------------------------------------------------------------------------
// What admins see

/// Whether the provider's discovery document checked out.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct SsoCheck {
    pub ok: bool,
    /// What's wrong, for the admin.
    pub error: Option<String>,
    /// Where people sign in, from the discovery document.
    pub authorization_endpoint: Option<String>,
}

/// The workspace's single sign-on settings. The client secret is never shown.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct SsoSettings {
    /// This server can encrypt a client secret (it has a connector key). Without it, single sign-on is off.
    pub available: bool,
    /// People can sign in with the provider now: turned on, fully set up and available.
    pub active: bool,
    pub enabled: bool,
    /// `google`, `microsoft`, `okta`, `onelogin`, `slack` or `oidc`.
    pub provider: Option<Provider>,
    /// The name on the sign-in button.
    pub name: String,
    pub issuer: String,
    /// Microsoft: the directory (tenant) ID.
    pub tenant: Option<String>,
    /// Slack: the Slack workspace (team) ID people must belong to, if any.
    pub team: Option<String>,
    pub client_id: String,
    /// A client secret is saved.
    pub client_secret_set: bool,
    /// Email domains whose verified addresses may sign in to existing accounts, and join when `auto_provision` is on.
    pub allowed_domains: Vec<String>,
    pub auto_provision: bool,
    pub require_sso: bool,
    /// Other OIDC providers: the name on the button.
    pub label: Option<String>,
    /// Register this as the redirect URI in the provider's app.
    pub redirect_uri: String,
    /// How many people have linked an account at this issuer.
    pub linked_people: i64,
    /// `update_sso` only: whether the provider's discovery document checked out.
    pub check: Option<SsoCheck>,
}

pub fn settings_view(db: &dyn Db, cfg: &HostConfig, base_url: &str, check: Option<SsoCheck>) -> ApiResult<SsoSettings> {
    let conf = load(db)?;
    let some = |s: &str| Some(s.to_string()).filter(|s| !s.is_empty());
    Ok(SsoSettings {
        available: connect::key(cfg).is_some(),
        active: active(cfg, &conf),
        enabled: conf.enabled,
        provider: conf.provider,
        name: conf.name(),
        tenant: some(&conf.tenant),
        team: some(&conf.team),
        client_id: conf.client_id.clone(),
        client_secret_set: conf.client_secret.is_some(),
        allowed_domains: conf.allowed_domains.clone(),
        auto_provision: conf.auto_provision,
        require_sso: conf.require_sso,
        label: some(&conf.label),
        redirect_uri: callback_url(base_url),
        linked_people: db
            .scalar_i64("SELECT COUNT(DISTINCT user_id) FROM sso_identities WHERE issuer = ?", &params![conf.issuer.clone()])?,
        issuer: conf.issuer,
        check,
    })
}

// ---------------------------------------------------------------------------
// The provider's answers

/// What the provider's discovery document says, checked.
#[derive(Clone, Debug, PartialEq)]
struct Discovery {
    authorize: String,
    token: String,
    userinfo: Option<String>,
    /// Send the client secret with HTTP Basic (`client_secret_basic`); otherwise in the form.
    basic_auth: bool,
}

fn discovery_url(issuer: &str) -> String {
    format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'))
}

fn https_url(v: &Value) -> Option<String> {
    let url = v.as_str()?.trim();
    let ok = url.starts_with("https://") && url.len() <= 2000 && !url.contains(char::is_whitespace) && connect::host_of(url).is_some();
    ok.then(|| url.to_string())
}

/// Reads the discovery document. Its `issuer` must be the configured one exactly (OpenID Connect
/// Discovery 1.0, 4.3), and its endpoints https.
fn read_discovery(conf: &Config, reply: &HttpReply) -> Result<Discovery, String> {
    let url = discovery_url(&conf.issuer);
    match reply.status {
        0 => return Err(format!("{url} didn't answer in time.")),
        s if !reply.ok() => return Err(format!("{url} answered HTTP {s}. Check the issuer URL.")),
        _ => {}
    }
    let v = reply.json();
    let Some(issuer) = v["issuer"].as_str() else {
        return Err(format!("{url} isn't an OpenID Connect discovery document."));
    };
    if issuer != conf.issuer {
        return Err(format!(
            "The provider names its issuer “{}”, not “{}”. They must match exactly.",
            connect::excerpt(issuer, 200),
            conf.issuer
        ));
    }
    let (Some(authorize), Some(token)) = (https_url(&v["authorization_endpoint"]), https_url(&v["token_endpoint"])) else {
        return Err("The provider's discovery document lacks an https authorization or token endpoint.".into());
    };
    let methods: Option<Vec<&str>> =
        v["token_endpoint_auth_methods_supported"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect());
    // Without a list, providers take Basic (OpenID Connect Discovery 1.0, 3).
    let basic_auth = methods.as_ref().is_none_or(|m| m.contains(&"client_secret_basic"));
    if !basic_auth && !methods.as_ref().is_some_and(|m| m.contains(&"client_secret_post")) {
        return Err("The provider doesn't take a client secret at its token endpoint.".into());
    }
    Ok(Discovery { authorize, token, userinfo: https_url(&v["userinfo_endpoint"]), basic_auth })
}

/// A JWT's claims, without checking its signature (see the module docs).
fn jwt_claims(token: &str) -> Result<Value, String> {
    let parts: Vec<&str> = token.split('.').collect();
    let decode = |s: &str| URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok());
    let (Some(header), Some(claims)) = (parts.first().and_then(|p| decode(p)), parts.get(1).and_then(|p| decode(p))) else {
        return Err("it isn't a readable ID token".into());
    };
    if parts.len() != 3 || header["alg"].as_str().is_none_or(|a| a.eq_ignore_ascii_case("none")) || !claims.is_object() {
        return Err("it isn't a signed ID token".into());
    }
    Ok(claims)
}

fn number(v: &Value) -> Option<i64> {
    v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))
}

/// `true` as JSON, or as the string some providers send.
fn truthy(v: &Value) -> bool {
    v.as_bool() == Some(true) || v.as_str().is_some_and(|s| s.eq_ignore_ascii_case("true")) || v.as_i64() == Some(1)
}

/// Checks an ID token's claims (OpenID Connect Core 1.0, 3.1.3.7): who issued it, for whom, when,
/// and for which sign-in. Says what's wrong, for the person.
fn check_claims(conf: &Config, claims: &Value, nonce: &str, now: DateTime<Utc>) -> Result<(), String> {
    let iss = claims["iss"].as_str().unwrap_or_default();
    // Google's ID tokens may name its issuer without the scheme.
    let google_short = conf.provider == Some(Provider::Google) && iss == "accounts.google.com";
    if iss != conf.issuer && !google_short {
        return Err("it came from another issuer".into());
    }
    let audiences: Vec<&str> = match &claims["aud"] {
        Value::String(a) => vec![a.as_str()],
        Value::Array(list) => list.iter().filter_map(Value::as_str).collect(),
        _ => vec![],
    };
    if !audiences.contains(&conf.client_id.as_str()) {
        return Err("it was meant for another app".into());
    }
    match claims["azp"].as_str() {
        Some(azp) if azp != conf.client_id => return Err("it was meant for another app".into()),
        None if audiences.len() > 1 => return Err("it names several apps and none it was given to".into()),
        _ => {}
    }
    let now_s = now.timestamp();
    match number(&claims["exp"]) {
        Some(exp) if exp + SKEW_SECS / 5 > now_s => {}
        Some(_) => return Err("it has expired".into()),
        None => return Err("it has no expiry".into()),
    }
    match number(&claims["iat"]) {
        Some(iat) if iat > now_s + SKEW_SECS => return Err("it was issued in the future".into()),
        Some(iat) if iat < now_s - 3600 => return Err("it was issued too long ago".into()),
        Some(_) => {}
        None => return Err("it has no issue time".into()),
    }
    if number(&claims["nbf"]).is_some_and(|nbf| nbf > now_s + SKEW_SECS) {
        return Err("it isn't valid yet".into());
    }
    let matches = claims["nonce"].as_str().is_some_and(|n| crate::util::secure_eq(n, nonce));
    if !matches {
        return Err("it doesn't belong to this sign-in".into());
    }
    if claims["sub"].as_str().is_none_or(|s| s.is_empty() || s.len() > 255) {
        return Err("it names no account".into());
    }
    Ok(())
}

fn domains_text(conf: &Config) -> String {
    match conf.allowed_domains.as_slice() {
        [] => "your organization's".into(),
        [one] => one.clone(),
        many => format!("{} or {}", many[..many.len() - 1].join(", "), many[many.len() - 1]),
    }
}

/// Whether the account belongs to the organization at all. Some issuers serve everyone (Google,
/// Slack), others every directory's accounts; this narrows them to the workspace's.
fn org_check(conf: &Config, claims: &Value) -> Result<(), String> {
    let (belongs, message) = match conf.provider {
        Some(Provider::Google) => {
            let hd = claims["hd"].as_str().unwrap_or_default();
            (!hd.is_empty() && conf.domain_allowed(hd), format!("Sign in with your {} Google account.", domains_text(conf)))
        }
        Some(Provider::Microsoft) => (
            claims["tid"].as_str().is_some_and(|t| t.eq_ignore_ascii_case(&conf.tenant)),
            "Sign in with a Microsoft account from your organization's directory.".to_string(),
        ),
        Some(Provider::Slack) => (
            conf.team.is_empty() || claims["https://slack.com/team_id"].as_str() == Some(conf.team.as_str()),
            "Sign in with your account in your organization's Slack workspace.".to_string(),
        ),
        _ => (true, String::new()),
    };
    if belongs { Ok(()) } else { Err(message) }
}

/// The email address the provider vouches for, which a first sign-in may match to an existing
/// account (or join with): the provider must say it's verified, and its domain must be one of the
/// workspace's. Microsoft's `email` is only trusted with `xms_edov` (the domain's owner verified
/// it), never alone and never `upn`, so another directory can't claim an address it doesn't own.
fn vouched_email(conf: &Config, claims: &Value) -> Result<String, String> {
    let name = conf.name();
    let email = claims["email"].as_str().map(|e| e.trim().to_ascii_lowercase()).unwrap_or_default();
    let link_hint = format!("Sign in with your password and link {name} in Settings › Profile, or ask a workspace admin.");
    if email.is_empty() {
        return Err(format!("{name} didn't share your email address, so it can't be matched to an account here. {link_hint}"));
    }
    let verified = match conf.provider {
        Some(Provider::Microsoft) => truthy(&claims["xms_edov"]),
        _ => truthy(&claims["email_verified"]),
    };
    if !verified {
        return Err(match conf.provider {
            Some(Provider::Microsoft) => format!(
                "Your Microsoft account isn't linked to an account here yet, and Microsoft didn't confirm who owns {email}. {link_hint}"
            ),
            _ => format!("{name} didn't confirm that {email} is verified, so it can't be matched to an account here. {link_hint}"),
        });
    }
    let domain = email.rsplit_once('@').map(|(_, d)| d).unwrap_or_default();
    if !conf.domain_allowed(domain) {
        return Err(format!("{domain} isn't one of this workspace's sign-in domains. Ask a workspace admin to add you."));
    }
    Ok(email)
}

/// A provider's error code, safe to show: short, and only the characters codes use.
fn error_code(code: &str) -> String {
    code.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')).take(60).collect()
}

// ---------------------------------------------------------------------------
// Responses

fn no_store(r: Response) -> Response {
    r.with_header("cache-control", "no-store").with_header("referrer-policy", "no-referrer")
}

fn secure(base_url: &str) -> bool {
    base_url.starts_with("https://")
}

fn browser_cookie(value: &str, secure: bool) -> String {
    format!(
        "{BROWSER_COOKIE}={value}; Path=/sso; HttpOnly; SameSite=Lax; Max-Age={}{}",
        SIGN_IN_MINUTES * 60,
        if secure { "; Secure" } else { "" }
    )
}

fn clear_browser_cookie(secure: bool) -> String {
    format!("{BROWSER_COOKIE}=; Path=/sso; HttpOnly; SameSite=Lax; Max-Age=0{}", if secure { "; Secure" } else { "" })
}

/// Only paths on this site, so a sign-in link can't send people elsewhere.
pub fn safe_next(next: Option<&str>) -> String {
    match next.map(str::trim) {
        Some(n) if n.starts_with('/') && !n.starts_with("//") && !n.contains(['\\', '\r', '\n']) && n.len() <= 2000 => n.to_string(),
        _ => "/".to_string(),
    }
}

/// Back to the sign-in page, with a message for the person.
fn to_login(base_url: &str, message: &str, next: &str) -> Response {
    let mut url = format!("{base_url}/login?sso_error={}", urlencoding::encode(message));
    if next != "/" {
        url.push_str(&format!("&next={}", urlencoding::encode(next)));
    }
    no_store(Response::redirect(&url)).with_header("set-cookie", clear_browser_cookie(secure(base_url)))
}

/// Back to Settings › Profile after linking an account.
fn to_profile(base_url: &str, outcome: Result<(), &str>) -> Response {
    let url = match outcome {
        Ok(()) => format!("{base_url}/settings/profile?sso_linked=1"),
        Err(message) => format!("{base_url}/settings/profile?sso_error={}", urlencoding::encode(message)),
    };
    no_store(Response::redirect(&url))
}

fn query_map(query: &str) -> BTreeMap<String, String> {
    query
        .split('&')
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| {
            let decode = |s: &str| urlencoding::decode(&s.replace('+', " ")).map(|c| c.into_owned()).unwrap_or_default();
            (decode(k), decode(v))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Signing in

/// What a sign-in started with, kept (as JSON) until the provider sends the person back.
#[derive(Clone, Serialize, Deserialize)]
struct Flow {
    nonce: String,
    verifier: String,
    fingerprint: String,
    redirect_uri: String,
    token_endpoint: String,
    userinfo_endpoint: Option<String>,
    basic_auth: bool,
    next: String,
}

/// A single sign-on job (see [`crate::connect::Job`]).
#[derive(Clone)]
pub struct SsoJob {
    base_url: String,
    kind: Kind,
    phase: Phase,
}

#[derive(Clone)]
enum Kind {
    /// Someone signing in from the sign-in page.
    SignIn { next: String },
    /// A signed-in person linking their account (`link_sso`).
    Link { user_id: String },
    /// An admin saved the settings (`update_sso`): check the provider's discovery document.
    Check,
    /// The provider sent someone back.
    Finish(Box<Returned>),
}

#[derive(Clone)]
struct Returned {
    code: String,
    flow: Flow,
    /// Linking: who.
    link_user: Option<String>,
    user_agent: Option<String>,
}

#[derive(Clone)]
enum Phase {
    Start,
    Discovering,
    Exchanging,
    /// The ID token had no email: asking the userinfo endpoint, with the access token.
    UserInfo {
        claims: Value,
    },
}

// Jobs carry sign-in codes and tokens; never print them.
impl std::fmt::Debug for SsoJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self.kind {
            Kind::SignIn { .. } => "sign-in",
            Kind::Link { .. } => "link",
            Kind::Check => "check",
            Kind::Finish(_) => "finish",
        };
        let phase = match self.phase {
            Phase::Start => "start",
            Phase::Discovering => "discovering",
            Phase::Exchanging => "exchanging",
            Phase::UserInfo { .. } => "userinfo",
        };
        write!(f, "SsoJob({kind}, {phase})")
    }
}

impl SsoJob {
    /// Checks the provider's discovery document, then fills in the settings with the result.
    pub fn check(base_url: &str) -> SsoJob {
        SsoJob { base_url: base_url.into(), kind: Kind::Check, phase: Phase::Start }
    }

    /// Starts linking `user_id`'s account at the provider; fills in `{ "authorize_url": … }`.
    pub fn link(base_url: &str, user_id: &str) -> SsoJob {
        SsoJob { base_url: base_url.into(), kind: Kind::Link { user_id: user_id.into() }, phase: Phase::Start }
    }
}

/// `GET /sso/start`: signs in with the provider. Answers with a job that reads the provider's
/// discovery document and then sends the browser there.
pub fn start(db: &dyn Db, cfg: &HostConfig, req: &Request) -> Outcome {
    let base = crate::http::base_url(cfg, req);
    let query = query_map(&req.query);
    let next = safe_next(query.get("next").map(String::as_str));
    let run = || -> ApiResult<Outcome> {
        if !active(cfg, &load(db)?) {
            return Ok(crate::http::done(to_login(&base, "Single sign-on isn't set up for this workspace.", &next)));
        }
        let mut out = crate::http::done(to_login(&base, "Signing in didn't start. Try again.", &next));
        let job = SsoJob { base_url: base.clone(), kind: Kind::SignIn { next: next.clone() }, phase: Phase::Start };
        out.effects.push(Effect::Connect(Job::Sso(job)));
        Ok(out)
    };
    run().unwrap_or_else(|e| crate::http::done(to_login(&base, &e.message, &next)))
}

/// `GET /sso/callback`: the provider sent someone back. The sign-in must be one this browser
/// started (or, when linking, the signed-in person's own), unused and recent, for the same app.
/// Answers with a job that exchanges the code and signs them in.
pub fn callback(db: &dyn Db, cfg: &HostConfig, req: &Request) -> Outcome {
    let base = crate::http::base_url(cfg, req);
    let query = query_map(&req.query);
    let now = Utc::now();
    let redirect = |r: Response| crate::http::done(r);
    let run = || -> ApiResult<Outcome> {
        let state_hash = sha256_hex(query.get("state").map(String::as_str).unwrap_or_default());
        let Some(row) =
            db.one("SELECT browser_hash, user_id, flow, created_at FROM sso_requests WHERE state_hash = ?", &params![state_hash.clone()])?
        else {
            return Ok(redirect(to_login(&base, "That sign-in link is no longer valid. Sign in again.", "/")));
        };
        // Each sign-in link works once.
        db.execute("DELETE FROM sso_requests WHERE state_hash = ?", &params![state_hash])?;
        let flow: Flow = serde_json::from_str(&row.str("flow")).map_err(|e| ApiError::internal(e.to_string()))?;
        let link_user = row.opt_str("user_id");
        let back = |message: &str| match link_user {
            Some(_) => redirect(to_profile(&base, Err(message))),
            None => redirect(to_login(&base, message, &flow.next)),
        };
        let started = parse_ts(&row.str("created_at")).unwrap_or(now);
        if now - started > Duration::minutes(SIGN_IN_MINUTES) {
            return Ok(back("Signing in took too long. Sign in again."));
        }
        match &link_user {
            Some(user_id) => {
                let actor = auth::authenticate(db, cfg, req, now).ok().flatten();
                if actor.is_none_or(|a| a.user_id != *user_id || a.session_hash.is_none()) {
                    return Ok(back("Sign in as the person who started linking, then try again."));
                }
            }
            None => {
                let cookie = auth::cookie_value(req, BROWSER_COOKIE).unwrap_or_default();
                let expected = row.str("browser_hash");
                if cookie.is_empty() || !crate::util::secure_eq(&sha256_hex(cookie), &expected) {
                    return Ok(back("Start signing in from this browser's sign-in page, then try again."));
                }
            }
        }
        let conf = load(db)?;
        if !active(cfg, &conf) {
            return Ok(back("Single sign-on isn't set up for this workspace any more."));
        }
        if conf.fingerprint() != flow.fingerprint {
            return Ok(back("The workspace's single sign-on settings changed while you were signing in. Try again."));
        }
        let name = conf.name();
        let code = match (query.get("code").filter(|c| !c.is_empty()), query.get("error")) {
            (Some(c), _) => c.clone(),
            (None, Some(e)) if e == "access_denied" => return Ok(back(&format!("You didn't finish signing in with {name}."))),
            (None, Some(e)) => {
                let why = query.get("error_description").map(|d| connect::excerpt(d, 200)).filter(|d| !d.is_empty());
                let why = why.unwrap_or_else(|| error_code(e));
                return Ok(back(&format!("{name} couldn't sign you in: {why}")));
            }
            (None, None) => return Ok(back(&format!("{name} sent no sign-in code. Try again."))),
        };
        let mut out = back("Signing in didn't finish. Try again.");
        let returned = Returned { code, flow, link_user, user_agent: req.header("user-agent").map(str::to_string) };
        let job = SsoJob { base_url: base.clone(), kind: Kind::Finish(Box::new(returned)), phase: Phase::Start };
        out.effects.push(Effect::Connect(Job::Sso(job)));
        Ok(out)
    };
    run().unwrap_or_else(|e| redirect(to_login(&base, &e.message, "/")))
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Records a sign-in under way and returns the provider's sign-in URL and, for a sign-in from the
/// sign-in page, the cookie naming this browser.
fn begin(
    db: &dyn Db,
    conf: &Config,
    d: &Discovery,
    base_url: &str,
    next: &str,
    link_user: Option<&str>,
    now: DateTime<Utc>,
) -> ApiResult<(String, Option<String>)> {
    db.execute("DELETE FROM sso_requests WHERE created_at < ?", &params![ts(now - Duration::minutes(SIGN_IN_MINUTES))])?;
    // Starting needs no account, so keep the newest only.
    db.execute(
        "DELETE FROM sso_requests WHERE state_hash NOT IN (SELECT state_hash FROM sso_requests ORDER BY created_at DESC LIMIT ?)",
        &params![MAX_PENDING - 1],
    )?;
    let state = crate::util::new_secret("");
    let nonce = crate::util::new_secret("");
    let verifier = crate::util::new_secret("") + &crate::util::new_secret("");
    let browser = link_user.is_none().then(|| crate::util::new_secret(""));
    let flow = Flow {
        nonce: nonce.clone(),
        verifier: verifier.clone(),
        fingerprint: conf.fingerprint(),
        redirect_uri: callback_url(base_url),
        token_endpoint: d.token.clone(),
        userinfo_endpoint: d.userinfo.clone(),
        basic_auth: d.basic_auth,
        next: next.to_string(),
    };
    db.execute(
        "INSERT INTO sso_requests (state_hash, browser_hash, user_id, flow, created_at) VALUES (?, ?, ?, ?, ?)",
        &params![
            sha256_hex(&state),
            browser.as_deref().map(sha256_hex),
            link_user,
            serde_json::to_string(&flow).map_err(|e| ApiError::internal(e.to_string()))?,
            ts(now)
        ],
    )?;
    let mut query: Vec<(&str, String)> = vec![
        ("response_type", "code".into()),
        ("client_id", conf.client_id.clone()),
        ("redirect_uri", flow.redirect_uri.clone()),
        ("scope", SCOPES.into()),
        ("state", state),
        ("nonce", nonce),
        ("code_challenge", pkce_challenge(&verifier)),
        ("code_challenge_method", "S256".into()),
    ];
    match conf.provider {
        Some(Provider::Google) => {
            query.push(("prompt", "select_account".into()));
            // A hint only: the `hd` claim is what's checked.
            if let [domain] = conf.allowed_domains.as_slice() {
                query.push(("hd", domain.clone()));
            }
        }
        Some(Provider::Slack) if !conf.team.is_empty() => query.push(("team", conf.team.clone())),
        _ => {}
    }
    let qs = query.iter().map(|(k, v)| format!("{k}={}", urlencoding::encode(v))).collect::<Vec<_>>().join("&");
    let sep = if d.authorize.contains('?') { '&' } else { '?' };
    Ok((format!("{}{sep}{qs}", d.authorize), browser))
}

fn token_call(conf: &Config, flow: &Flow, code: &str, secret: &str) -> HttpCall {
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", flow.redirect_uri.as_str()),
        ("code_verifier", flow.verifier.as_str()),
    ];
    if !flow.basic_auth {
        form.push(("client_id", conf.client_id.as_str()));
        form.push(("client_secret", secret));
    }
    let call = HttpCall::post_form(flow.token_endpoint.clone(), &form).header("accept", "application/json");
    if flow.basic_auth {
        // Form-encoded first (RFC 6749, 2.3.1).
        call.basic(&urlencoding::encode(&conf.client_id), &urlencoding::encode(secret))
    } else {
        call
    }
}

/// Runs a single sign-on job's next step (see [`crate::connect::step`]).
pub fn step(db: &dyn Db, cfg: &HostConfig, j: &mut SsoJob, replies: Vec<HttpReply>, now: DateTime<Utc>) -> ApiResult<Step> {
    let reply = replies.into_iter().next().unwrap_or_default();
    let conf = load(db)?;
    let base = j.base_url.clone();
    let phase = std::mem::replace(&mut j.phase, Phase::Start);
    match (&j.kind, phase) {
        (Kind::Finish(r), phase) => {
            let r = r.clone();
            finish_step(db, cfg, j, &conf, &r, phase, reply, now)
        }
        (_, Phase::Start) => {
            let usable = match j.kind {
                Kind::Check => !conf.issuer.is_empty(),
                _ => active(cfg, &conf),
            };
            if !usable {
                return Ok(match &j.kind {
                    Kind::SignIn { next } => respond(to_login(&base, "Single sign-on isn't set up for this workspace.", next)),
                    Kind::Check => fill(settings_view(db, cfg, &base, None)?)?,
                    _ => Step::Done(Finish::Fail(ApiError::bad_request("single sign-on isn't set up for this workspace"))),
                });
            }
            j.phase = Phase::Discovering;
            Ok(Step::Fetch(vec![HttpCall::get(discovery_url(&conf.issuer)).header("accept", "application/json")]))
        }
        (Kind::Check, _) => {
            let check = match read_discovery(&conf, &reply) {
                Ok(d) => SsoCheck { ok: true, error: None, authorization_endpoint: Some(d.authorize) },
                Err(e) => SsoCheck { ok: false, error: Some(e), authorization_endpoint: None },
            };
            fill(settings_view(db, cfg, &base, Some(check))?)
        }
        (Kind::SignIn { next }, _) => match read_discovery(&conf, &reply) {
            Ok(d) => {
                let (url, browser) = begin(db, &conf, &d, &base, next, None, now)?;
                let cookie = browser_cookie(&browser.unwrap_or_default(), secure(&base));
                Ok(respond(no_store(Response::redirect(&url)).with_header("set-cookie", cookie)))
            }
            Err(_) => Ok(respond(to_login(
                &base,
                &format!(
                    "Signing in with {} isn't working right now: its settings don't check out. A workspace admin can check Settings › Single sign-on.",
                    conf.name()
                ),
                next,
            ))),
        },
        (Kind::Link { user_id }, _) => match read_discovery(&conf, &reply) {
            Ok(d) => {
                let (url, _) = begin(db, &conf, &d, &base, "/settings/profile", Some(user_id), now)?;
                fill(json!({ "authorize_url": url }))
            }
            Err(e) => Ok(Step::Done(Finish::Fail(ApiError::new(502, "sso_unavailable", e)))),
        },
    }
}

fn respond(r: Response) -> Step {
    Step::Done(Finish::Respond(r))
}

fn fill(value: impl Serialize) -> ApiResult<Step> {
    Ok(Step::Done(Finish::Fill(serde_json::to_value(value).map_err(|e| ApiError::internal(e.to_string()))?)))
}

#[allow(clippy::too_many_arguments)]
fn finish_step(
    db: &dyn Db,
    cfg: &HostConfig,
    j: &mut SsoJob,
    conf: &Config,
    r: &Returned,
    phase: Phase,
    reply: HttpReply,
    now: DateTime<Utc>,
) -> ApiResult<Step> {
    let base = j.base_url.clone();
    let name = conf.name();
    let back = |message: &str| match r.link_user {
        Some(_) => respond(to_profile(&base, Err(message))),
        None => respond(to_login(&base, message, &r.flow.next)),
    };
    if !active(cfg, conf) || conf.fingerprint() != r.flow.fingerprint {
        return Ok(back("The workspace's single sign-on settings changed while you were signing in. Try again."));
    }
    match phase {
        Phase::Start | Phase::Discovering => {
            let Some(secret) = client_secret(cfg, conf) else {
                return Ok(back(&format!("Signing in with {name} needs its client secret entered again. Ask a workspace admin.")));
            };
            j.phase = Phase::Exchanging;
            Ok(Step::Fetch(vec![token_call(conf, &r.flow, &r.code, &secret)]))
        }
        Phase::Exchanging => {
            let v = reply.json();
            let id_token = v["id_token"].as_str().filter(|t| reply.ok() && !t.is_empty());
            let Some(id_token) = id_token else {
                let why = match reply.status {
                    0 => "it didn't answer in time".to_string(),
                    s => v["error"].as_str().map(error_code).filter(|e| !e.is_empty()).unwrap_or_else(|| format!("HTTP {s}")),
                };
                return Ok(back(&format!(
                    "{name} didn't accept the sign-in ({why}). Try again; if it keeps happening, a workspace admin can check Settings › Single sign-on."
                )));
            };
            let claims = match jwt_claims(id_token).and_then(|c| check_claims(conf, &c, &r.flow.nonce, now).map(|()| c)) {
                Ok(c) => c,
                Err(why) => return Ok(back(&format!("{name}'s answer didn't check out: {why}. Sign in again."))),
            };
            // Some providers put the email in the userinfo answer only. Microsoft's would never
            // be trusted on its own (see `vouched_email`), so it isn't asked.
            let access = v["access_token"].as_str().filter(|t| !t.is_empty());
            let asks = claims.get("email").is_none() && conf.provider != Some(Provider::Microsoft);
            if let (true, Some(url), Some(access)) = (asks, r.flow.userinfo_endpoint.clone(), access) {
                j.phase = Phase::UserInfo { claims };
                return Ok(Step::Fetch(vec![HttpCall::get(url).bearer(access).header("accept", "application/json")]));
            }
            complete(db, cfg, &base, conf, r, &claims, now)
        }
        Phase::UserInfo { mut claims } => {
            let info = reply.json();
            // The answer must be about the same account (OpenID Connect Core 1.0, 5.3.2).
            if reply.ok() && info["sub"].as_str().is_some() && info["sub"] == claims["sub"] {
                for key in ["email", "email_verified", "name", "given_name", "family_name"] {
                    if claims.get(key).is_none() && !info[key].is_null() {
                        claims[key] = info[key].clone();
                    }
                }
            }
            complete(db, cfg, &base, conf, r, &claims, now)
        }
    }
}

/// A person's account, as sign-ins need it.
struct Person {
    id: String,
    name: String,
    handle: String,
    email: String,
    role: Role,
    is_bot: bool,
    deactivated: bool,
}

fn person(row: &crate::db::Row) -> Person {
    Person {
        id: row.str("id"),
        name: row.str("name"),
        handle: row.str("handle"),
        email: row.str("email"),
        role: Role::parse(&row.str("role")).unwrap_or(Role::Viewer),
        is_bot: row.bool("is_bot"),
        deactivated: row.opt_str("deactivated_at").is_some(),
    }
}

const PERSON_COLS: &str = "u.id, u.name, u.handle, u.email, u.role, u.is_bot, u.deactivated_at";

fn find_person(db: &dyn Db, user_id: &str) -> ApiResult<Option<Person>> {
    Ok(db.one(&format!("SELECT {PERSON_COLS} FROM users u WHERE u.id = ?"), &params![user_id])?.map(|r| person(&r)))
}

/// Why `p` may not sign in, if they may not.
fn refusal(p: &Person) -> Option<&'static str> {
    if p.deactivated {
        Some("Your account here is deactivated. Ask a workspace admin to reactivate it.")
    } else if p.is_bot {
        Some("Bot accounts sign in with API tokens, not single sign-on.")
    } else {
        None
    }
}

/// An operation context for writes made while signing in, acting as `p`. Activity is recorded;
/// sign-ins run as jobs, which send no webhooks, so these events reach the activity log only.
fn ctx_for<'a>(db: &'a dyn Db, cfg: &'a HostConfig, base_url: &str, p: &Person, now: DateTime<Utc>) -> Ctx<'a> {
    let actor = Actor {
        user_id: p.id.clone(),
        name: p.name.clone(),
        handle: p.handle.clone(),
        email: p.email.clone(),
        role: p.role,
        scopes: Scopes::for_role(p.role),
        via: Via::Web,
        token_id: None,
        session_hash: None,
    };
    Ctx { db, actor, now, cfg, base_url: base_url.to_string(), effects: vec![] }
}

fn link_identity(db: &dyn Db, user_id: &str, conf: &Config, claims: &Value, now: DateTime<Utc>) -> ApiResult<()> {
    let shown = claims["email"].as_str().or(claims["preferred_username"].as_str()).unwrap_or_default();
    // One account per person at each issuer.
    db.execute("DELETE FROM sso_identities WHERE user_id = ? AND issuer = ?", &params![user_id, conf.issuer.clone()])?;
    db.execute(
        "INSERT INTO sso_identities (id, user_id, issuer, subject, email, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        &params![
            crate::util::new_id(),
            user_id,
            conf.issuer.clone(),
            claims["sub"].as_str().unwrap_or_default(),
            shown.chars().take(254).collect::<String>(),
            ts(now),
            ts(now)
        ],
    )?;
    Ok(())
}

/// The ID token checked out: link the account, or sign the person in.
fn complete(db: &dyn Db, cfg: &HostConfig, base: &str, conf: &Config, r: &Returned, claims: &Value, now: DateTime<Utc>) -> ApiResult<Step> {
    let name = conf.name();
    let back = |message: &str| match r.link_user {
        Some(_) => respond(to_profile(base, Err(message))),
        None => respond(to_login(base, message, &r.flow.next)),
    };
    if let Err(message) = org_check(conf, claims) {
        return Ok(back(&message));
    }
    let subject = claims["sub"].as_str().unwrap_or_default();
    let linked = db.one(
        &format!("SELECT {PERSON_COLS}, i.id AS identity_id FROM sso_identities i JOIN users u ON u.id = i.user_id WHERE i.issuer = ? AND i.subject = ?"),
        &params![conf.issuer.clone(), subject],
    )?;

    if let Some(user_id) = &r.link_user {
        let Some(p) = find_person(db, user_id)? else { return Ok(back("Your account here no longer exists.")) };
        if let Some(why) = refusal(&p) {
            return Ok(back(why));
        }
        match linked {
            Some(row) if row.str("id") != p.id => return Ok(back(&format!("That {name} account is already linked to someone else here."))),
            Some(_) => {}
            None => {
                link_identity(db, &p.id, conf, claims, now)?;
                let mut ctx = ctx_for(db, cfg, base, &p, now);
                emit(&mut ctx, Event::new("sso.linked", "user", &p.id, format!("linked their {name} account")).admin_only())?;
            }
        }
        return Ok(respond(to_profile(base, Ok(()))));
    }

    let p = match linked {
        Some(row) => {
            db.execute("UPDATE sso_identities SET last_used_at = ? WHERE id = ?", &params![ts(now), row.str("identity_id")])?;
            person(&row)
        }
        None => {
            let email = match vouched_email(conf, claims) {
                Ok(e) => e,
                Err(message) => return Ok(back(&message)),
            };
            match db.one(&format!("SELECT {PERSON_COLS} FROM users u WHERE u.email = ?"), &params![email.clone()])?.map(|r| person(&r)) {
                Some(p) => {
                    if let Some(why) = refusal(&p) {
                        return Ok(back(why));
                    }
                    // Linked to another account at this issuer: the address may have changed hands.
                    let other = db.scalar_i64(
                        "SELECT COUNT(*) FROM sso_identities WHERE user_id = ? AND issuer = ?",
                        &params![p.id.clone(), conf.issuer.clone()],
                    )?;
                    if other > 0 {
                        return Ok(back(&format!(
                            "{email} is linked to a different {name} account here. Ask a workspace admin to unlink it in Settings › Single sign-on."
                        )));
                    }
                    link_identity(db, &p.id, conf, claims, now)?;
                    p
                }
                None if conf.auto_provision => provision(db, cfg, base, conf, claims, &email, now)?,
                None => return Ok(back(&format!("No one here has the email {email}. Ask a workspace admin to add you."))),
            }
        }
    };
    if let Some(why) = refusal(&p) {
        return Ok(back(why));
    }
    let token = auth::create_session(db, &p.id, r.user_agent.as_deref(), now)?;
    db.execute("UPDATE users SET last_seen_at = ? WHERE id = ?", &params![ts(now), p.id.clone()])?;
    let secure = secure(base);
    let to = format!("{base}{}", r.flow.next);
    Ok(respond(
        no_store(Response::redirect(&to))
            .with_header("set-cookie", auth::session_cookie(&token, secure))
            .with_header("set-cookie", clear_browser_cookie(secure)),
    ))
}

/// Adds someone the provider vouches for as a member (auto-provisioning).
fn provision(
    db: &dyn Db,
    cfg: &HostConfig,
    base: &str,
    conf: &Config,
    claims: &Value,
    email: &str,
    now: DateTime<Utc>,
) -> ApiResult<Person> {
    let given = [claims["given_name"].as_str(), claims["family_name"].as_str()].into_iter().flatten().collect::<Vec<_>>().join(" ");
    let local = email.split('@').next().unwrap_or(email);
    let name = [claims["name"].as_str().unwrap_or_default(), given.as_str(), local]
        .into_iter()
        .map(str::trim)
        .find(|n| !n.is_empty())
        .unwrap_or(local)
        .chars()
        .take(120)
        .collect::<String>();
    let placeholder = Person {
        id: String::new(),
        name: name.clone(),
        handle: String::new(),
        email: email.into(),
        role: Role::Member,
        is_bot: false,
        deactivated: false,
    };
    let uid = crate::ops::users::insert_user(&ctx_for(db, cfg, base, &placeholder, now), email, &name, None, Role::Member, None, false)?;
    link_identity(db, &uid, conf, claims, now)?;
    let p = find_person(db, &uid)?.ok_or_else(|| ApiError::internal("user vanished"))?;
    let mut ctx = ctx_for(db, cfg, base, &p, now);
    emit(
        &mut ctx,
        Event::new("user.created", "user", &uid, format!("{} joined by signing in with {}", p.name, conf.name()))
            .data(json!({ "role": "member", "is_bot": false, "sso": true }))
            .admin_only(),
    )?;
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conf(provider: Provider) -> Config {
        Config {
            enabled: true,
            provider: Some(provider),
            issuer: "https://idp.test".into(),
            client_id: "app".into(),
            allowed_domains: vec!["acme.com".into()],
            ..Default::default()
        }
    }

    #[test]
    fn domains_tenants_and_issuers() {
        assert_eq!(normalize_domain(" @Acme.COM. ").as_deref(), Some("acme.com"));
        for bad in ["acme", "-acme.com", "acme..com", "ac me.com", "acme.com/x", ""] {
            assert!(normalize_domain(bad).is_none(), "{bad}");
        }
        let guid = "72F988BF-86F1-41AF-91AB-2D7CD011DB47";
        assert_eq!(normalize_tenant(guid).as_deref(), Some("72f988bf-86f1-41af-91ab-2d7cd011db47"));
        for bad in ["common", "organizations", "consumers", "contoso.onmicrosoft.com", "72f988bf-86f1-41af-91ab"] {
            assert!(normalize_tenant(bad).is_none(), "{bad}");
        }
        assert!(valid_issuer("https://acme.okta.com"));
        assert!(valid_issuer("https://acme.onelogin.com/oidc/2"));
        for bad in ["http://acme.okta.com", "https://a@b.test", "https://acme.okta.com?x=1", "https:// x.test", "https://intranet"] {
            assert!(!valid_issuer(bad), "{bad}");
        }
        assert_eq!(discovery_url("https://tenant.auth0.test/"), "https://tenant.auth0.test/.well-known/openid-configuration");
    }

    #[test]
    fn next_stays_on_this_site() {
        assert_eq!(safe_next(Some("/p/abc?x=1")), "/p/abc?x=1");
        for bad in ["//evil.test", "https://evil.test", "/\\evil.test", "", "p/abc"] {
            assert_eq!(safe_next(Some(bad)), "/", "{bad}");
        }
        assert_eq!(safe_next(None), "/");
    }

    #[test]
    fn only_vouched_emails_from_allowed_domains() {
        let google = conf(Provider::Google);
        assert_eq!(vouched_email(&google, &json!({ "email": "Ada@Acme.com", "email_verified": true })).unwrap(), "ada@acme.com");
        assert!(vouched_email(&google, &json!({ "email": "ada@acme.com", "email_verified": false })).is_err());
        assert!(vouched_email(&google, &json!({ "email": "ada@acme.com" })).is_err());
        assert!(vouched_email(&google, &json!({ "email": "ada@evil.com", "email_verified": true })).is_err());
        assert!(vouched_email(&conf(Provider::Okta), &json!({ "email": "ada@acme.com", "email_verified": "true" })).is_ok());
        // Microsoft: `email_verified` means nothing there; only `xms_edov` does.
        let ms = conf(Provider::Microsoft);
        assert!(vouched_email(&ms, &json!({ "email": "ada@acme.com", "email_verified": true, "upn": "ada@acme.com" })).is_err());
        assert!(vouched_email(&ms, &json!({ "email": "ada@acme.com", "xms_edov": true })).is_ok());
    }

    #[test]
    fn id_token_claims_are_checked() {
        let c = conf(Provider::Okta);
        let now = Utc::now();
        let t = now.timestamp();
        let good = json!({ "iss": "https://idp.test", "aud": "app", "sub": "u1", "exp": t + 300, "iat": t, "nonce": "n" });
        assert!(check_claims(&c, &good, "n", now).is_ok());
        let with = |k: &str, v: Value| {
            let mut x = good.clone();
            x[k] = v;
            check_claims(&c, &x, "n", now).unwrap_err()
        };
        assert!(with("iss", json!("https://other.test")).contains("issuer"));
        assert!(with("aud", json!("other")).contains("another app"));
        assert!(with("aud", json!(["app", "other"])).contains("several"));
        assert!(with("azp", json!("other")).contains("another app"));
        assert!(with("exp", json!(t - 120)).contains("expired"));
        assert!(with("iat", json!(t + 3600)).contains("future"));
        assert!(with("nonce", json!("m")).contains("this sign-in"));
        assert!(with("sub", json!("")).contains("no account"));
        let mut multi = good.clone();
        multi["aud"] = json!(["app", "other"]);
        multi["azp"] = json!("app");
        assert!(check_claims(&c, &multi, "n", now).is_ok());
        // Google's short issuer, for Google only.
        let mut short = good.clone();
        short["iss"] = json!("accounts.google.com");
        assert!(check_claims(&c, &short, "n", now).is_err());
        let g = Config { issuer: "https://accounts.google.com".into(), ..conf(Provider::Google) };
        assert!(check_claims(&g, &short, "n", now).is_ok());
    }

    #[test]
    fn unsigned_tokens_are_refused() {
        let part = |v: Value| URL_SAFE_NO_PAD.encode(v.to_string());
        let claims = part(json!({ "sub": "u1" }));
        assert!(jwt_claims(&format!("{}.{claims}.sig", part(json!({ "alg": "RS256" })))).is_ok());
        assert!(jwt_claims(&format!("{}.{claims}.", part(json!({ "alg": "none" })))).is_err());
        assert!(jwt_claims(&format!("{}.{claims}", part(json!({ "alg": "RS256" })))).is_err());
        assert!(jwt_claims("not a token").is_err());
    }

    #[test]
    fn secrets_are_never_printed() {
        let mut c = conf(Provider::Okta);
        c.client_secret = Some("v1.sealed-secret".into());
        assert!(!format!("{c:?}").contains("sealed-secret"));
        let flow = Flow {
            nonce: "the-nonce".into(),
            verifier: "the-verifier".into(),
            fingerprint: String::new(),
            redirect_uri: String::new(),
            token_endpoint: "https://idp.test/token".into(),
            userinfo_endpoint: None,
            basic_auth: true,
            next: "/".into(),
        };
        let returned = Returned { code: "the-code".into(), flow, link_user: None, user_agent: None };
        let job = SsoJob { base_url: "https://kb.test".into(), kind: Kind::Finish(Box::new(returned)), phase: Phase::Exchanging };
        let printed = format!("{job:?}");
        for secret in ["the-nonce", "the-verifier", "the-code"] {
            assert!(!printed.contains(secret), "{printed}");
        }
    }
}
