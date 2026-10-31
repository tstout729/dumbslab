//! Single sign-on: people sign in to the workspace with their organization's identity provider
//! (Google Workspace, Microsoft Entra ID, Okta, OneLogin, Slack or any OpenID Connect provider).
//!
//! - Admins set it up for the workspace (`get_sso`, `update_sso` and `setup_sso` in
//!   [`crate::ops::sso`]), in one of two ways:
//!   - **Shared mode** (Google, Microsoft and Slack): the host registered its own app with the
//!     provider once ([`SharedApps`]), so an admin sets single sign-on up by signing in with their
//!     organization's account (`setup_sso`). The organization comes from that ID token: Google's
//!     hosted domain (`hd`), Microsoft's directory (`tid`) or Slack's workspace (team). If the host
//!     later lacks the app, single sign-on is off, so "Require single sign-on" never locks anyone
//!     out. Hosted DumbSlab sends every workspace's sign-ins back through the root domain's
//!     `/sso/callback`, which forwards to the workspace the `state` names (`{address}.{random}`).
//!   - **Their own app**, for any provider: they register an OIDC app whose redirect URI is the
//!     workspace's `/sso/callback`. The client secret is encrypted with the host's connector key,
//!     and no operation returns it. Without the key, this mode is off.
//! - Signing in is OpenID Connect's authorization code flow with PKCE (S256), a `state` (stored
//!   hashed, used once, within 15 minutes, by the browser that started) and a `nonce`. The core
//!   does no I/O: each network step is a [`crate::connect::Job`] the host runs, as for connected
//!   apps. Setting up is the same flow, bound to the admin's browser session like linking.
//! - The ID token comes straight from the token endpoint over TLS, so (OpenID Connect Core 1.0,
//!   3.1.3.7, step 6) its signature isn't checked. Its issuer, audience, authorized party, expiry,
//!   issue time and nonce are.
//! - Accounts are linked by (issuer, subject). A first sign-in attaches to an existing person by
//!   email only when the provider vouches for the address and its domain is one of the
//!   workspace's ([`vouched_email`]). Otherwise people link their accounts while signed in
//!   (`link_sso`), or join on their own when the workspace turns on auto-provisioning.
//!
//! What the providers document, which setting up relies on:
//! - Google: `hd` is in the ID token only for a Google Workspace or Cloud Identity account, and is
//!   what to check to restrict sign-in to an organization; `hd=*` asks the account chooser for such
//!   accounts; the issuer is `https://accounts.google.com` or `accounts.google.com`.
//!   <https://developers.google.com/identity/openid-connect/openid-connect>. An app that asks only
//!   for non-sensitive scopes (`openid email profile`) needn't go through Google's app verification;
//!   brand verification shows its name and logo:
//!   <https://support.google.com/cloud/answer/13463073>,
//!   <https://developers.google.com/identity/protocols/oauth2/production-readiness/brand-verification>.
//! - Microsoft: the `organizations` discovery document names the issuer
//!   `https://login.microsoftonline.com/{tenantid}/v2.0`; a multi-tenant app checks that `tid` is
//!   a GUID and that `iss` is exactly that issuer with the token's own `tid`
//!   (<https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration>,
//!   <https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens>). Personal accounts'
//!   directory is `9188040d-6c67-4c5b-b112-36a304b66dad`. `xms_edov` says the email's domain owner
//!   is verified, and comes only with `email`
//!   (<https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims-reference>); new
//!   multi-tenant apps drop unverified emails from tokens
//!   (<https://learn.microsoft.com/en-us/graph/applications-authenticationbehaviors>). A directory
//!   can require an administrator to approve a new app (AADSTS90094, or AADSTS90095 with the admin
//!   consent workflow; <https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes>,
//!   <https://learn.microsoft.com/en-us/entra/identity-platform/howto-convert-app-to-be-multi-tenant>).
//! - Slack: Sign in with Slack's issuer is `https://slack.com`, its token endpoint
//!   `openid.connect.token`, its user scopes `openid email profile`, and its ID token names the
//!   Slack workspace in `https://slack.com/team_id`
//!   (<https://docs.slack.dev/authentication/sign-in-with-slack/>).

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::auth::{self, Actor, Role, Scopes, Via};
use crate::connect::{self, Finish, HttpCall, HttpReply, Job, OAuthApp, Step};
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
/// Settings › Single sign-on, where setting it up by signing in ends.
pub const SETTINGS_PATH: &str = "/settings/sso";
/// Microsoft's endpoints for every organization's accounts, where setting up starts: the
/// directory isn't known until the admin signs in.
const MICROSOFT_ORGANIZATIONS: &str = "https://login.microsoftonline.com/organizations/v2.0";
/// The issuer `organizations`' discovery document names: a template for each directory.
const MICROSOFT_ISSUER_TEMPLATE: &str = "https://login.microsoftonline.com/{tenantid}/v2.0";
/// The directory of personal Microsoft accounts (`consumers`).
const MICROSOFT_CONSUMERS: &str = "9188040d-6c67-4c5b-b112-36a304b66dad";

/// The providers a host can have its own app for (shared mode). Okta, OneLogin and other OIDC
/// providers have an issuer per organization, so each workspace registers its own app there.
pub const SHARED: [Provider; 3] = [Provider::Google, Provider::Microsoft, Provider::Slack];

/// The host's own sign-in apps, registered once with each provider so admins set up single sign-on
/// by signing in. Cloudflare reads `SSO_GOOGLE_CLIENT_ID`, `SSO_MICROSOFT_CLIENT_ID` and
/// `SLACK_CLIENT_ID` (vars) with the secrets `SSO_GOOGLE_CLIENT_SECRET`,
/// `SSO_MICROSOFT_CLIENT_SECRET` and `SLACK_CLIENT_SECRET`; self-hosted servers the same names
/// prefixed `DUMBSLAB_` ([`SharedApps::from_vars`]). Slack's is the one Slack app the host uses
/// for everything, connected-app search included.
#[derive(Clone, Debug, Default)]
pub struct SharedApps {
    pub google: Option<OAuthApp>,
    pub microsoft: Option<OAuthApp>,
    pub slack: Option<OAuthApp>,
    /// Where providers send people back. Hosted DumbSlab uses the root domain's `/sso/callback`,
    /// which forwards to the workspace named in the `state`; unset, it's the workspace's own.
    pub callback_url: Option<String>,
}

impl SharedApps {
    /// Reads the apps with `var`, which looks up a setting by name (the host adds any prefix). An
    /// app needs both its client ID and its secret.
    pub fn from_vars(var: impl Fn(&str) -> Option<String>) -> SharedApps {
        let app = |id: &str, secret: &str| {
            let (client_id, client_secret) = (var(id)?, var(secret)?);
            Some(OAuthApp { client_id, client_secret })
        };
        SharedApps {
            google: app("SSO_GOOGLE_CLIENT_ID", "SSO_GOOGLE_CLIENT_SECRET"),
            microsoft: app("SSO_MICROSOFT_CLIENT_ID", "SSO_MICROSOFT_CLIENT_SECRET"),
            slack: app("SLACK_CLIENT_ID", "SLACK_CLIENT_SECRET"),
            callback_url: None,
        }
    }

    /// The host's app for `p`, if it has a complete one.
    pub fn get(&self, p: Provider) -> Option<&OAuthApp> {
        let app = match p {
            Provider::Google => self.google.as_ref(),
            Provider::Microsoft => self.microsoft.as_ref(),
            Provider::Slack => self.slack.as_ref(),
            _ => None,
        };
        app.filter(|a| !a.client_id.trim().is_empty() && !a.client_secret.trim().is_empty())
    }

    /// The providers the host has an app for, in [`SHARED`]'s order.
    pub fn providers(&self) -> Vec<Provider> {
        SHARED.into_iter().filter(|p| self.get(*p).is_some()).collect()
    }
}

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
    /// Signs in through the host's own app for the provider ([`SharedApps`]): no client ID or
    /// secret is stored, and single sign-on works only while the host has that app.
    pub shared: bool,
    /// Exactly as the provider's discovery document gives it.
    pub issuer: String,
    /// Microsoft: the directory (tenant) ID.
    pub tenant: String,
    /// Slack: only this Slack workspace's people, when set.
    pub team: String,
    /// The workspace's own app. Empty in shared mode (see [`effective`]).
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
            .field("shared", &self.shared)
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

    /// Everything signing in needs is filled in. In shared mode the app is the host's, which
    /// [`active`] checks.
    pub fn complete(&self) -> bool {
        let Some(provider) = self.provider else { return false };
        let specific = match provider {
            Provider::Google => !self.allowed_domains.is_empty(),
            Provider::Microsoft => !self.tenant.is_empty(),
            Provider::Slack => !self.team.is_empty(),
            _ => true,
        };
        let app = if self.shared { SHARED.contains(&provider) } else { !self.client_id.is_empty() && self.client_secret.is_some() };
        specific && !self.issuer.is_empty() && app
    }

    /// What a sign-in must still match when it finishes: the same app at the same provider. Call
    /// it on [`effective`] settings, so a shared app's client ID counts.
    fn fingerprint(&self) -> String {
        let provider = self.provider.map(Provider::as_str).unwrap_or_default();
        let mode = if self.shared { "|shared" } else { "" };
        sha256_hex(&format!("{provider}|{}|{}|{}|{}{mode}", self.issuer, self.client_id, self.tenant, self.team))
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

/// A client secret is saved, but this server can't read it: its connector key changed since.
/// An admin must enter the secret again.
pub fn secret_unreadable(cfg: &HostConfig, conf: &Config) -> bool {
    conf.client_secret.is_some() && connect::key(cfg).is_some() && client_secret(cfg, conf).is_none()
}

/// The client ID and secret signing in uses: in shared mode the host's app for the provider,
/// otherwise the workspace's own, whose secret this server must be able to read.
fn credentials(cfg: &HostConfig, conf: &Config) -> Option<(String, String)> {
    if conf.shared {
        let app = cfg.sso_apps.get(conf.provider?)?;
        return Some((app.client_id.clone(), app.client_secret.clone()));
    }
    Some((conf.client_id.clone(), client_secret(cfg, conf)?))
}

/// The settings as signing in uses them: in shared mode, with the host app's client ID.
fn effective(cfg: &HostConfig, mut conf: Config) -> Config {
    if conf.shared {
        conf.client_id = conf.provider.and_then(|p| cfg.sso_apps.get(p)).map(|a| a.client_id.clone()).unwrap_or_default();
    }
    conf
}

/// Shared mode, but the host doesn't have the provider's app (any more). Single sign-on is off
/// until it's back or an admin sets up their own app.
pub fn shared_app_missing(cfg: &HostConfig, conf: &Config) -> bool {
    conf.shared && conf.provider.and_then(|p| cfg.sso_apps.get(p)).is_none()
}

/// People can sign in with the provider now: it's on, set up, and the app is there (in shared mode
/// the host's, otherwise one whose secret the server can read). Everything that depends on single
/// sign-on working (the sign-in button, requiring it) checks this.
pub fn active(cfg: &HostConfig, conf: &Config) -> bool {
    conf.enabled && conf.complete() && credentials(cfg, conf).is_some()
}

pub fn callback_url(base_url: &str) -> String {
    format!("{base_url}{CALLBACK_PATH}")
}

/// Where the provider sends people back. In shared mode on hosted DumbSlab, that's the root
/// domain's callback (the redirect URI the host registered once); otherwise the workspace's own.
fn redirect_uri(cfg: &HostConfig, conf: &Config, base_url: &str) -> String {
    match &cfg.sso_apps.callback_url {
        Some(url) if conf.shared => url.clone(),
        _ => callback_url(base_url),
    }
}

/// Domains anyone can have an address at. Setting up never makes one an allowed domain: every
/// account there could then match people here by email.
const FREE_MAIL: &[&str] = &[
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "passport.com",
    "yahoo.com",
    "ymail.com",
    "rocketmail.com",
    "icloud.com",
    "me.com",
    "mac.com",
    "aol.com",
    "aim.com",
    "proton.me",
    "protonmail.com",
    "protonmail.ch",
    "pm.me",
    "gmx.com",
    "gmx.net",
    "gmx.de",
    "web.de",
    "mail.com",
    "zoho.com",
    "zohomail.com",
    "yandex.com",
    "yandex.ru",
    "mail.ru",
    "hey.com",
    "fastmail.com",
    "tutanota.com",
    "tuta.io",
    "duck.com",
    "qq.com",
    "163.com",
    "126.com",
    "naver.com",
    "hanmail.net",
    "comcast.net",
    "att.net",
    "verizon.net",
    "orange.fr",
    "free.fr",
    "t-online.de",
    "libero.it",
    "rediffmail.com",
    "hushmail.com",
];
/// Free-mail brands with a domain in many countries, such as `yahoo.co.uk` or `hotmail.fr`.
const FREE_MAIL_BRANDS: &[&str] = &["gmail", "googlemail", "outlook", "hotmail", "live", "msn", "yahoo", "aol", "gmx", "yandex", "proton"];

/// Whether `domain` is a free-mail domain (see [`FREE_MAIL`]).
pub fn free_mail(domain: &str) -> bool {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if FREE_MAIL.contains(&d.as_str()) {
        return true;
    }
    // A brand under a country's suffix: `hotmail.fr`, `yahoo.co.uk`, `outlook.com.br`.
    let Some((brand, suffix)) = d.split_once('.') else { return false };
    let labels: Vec<&str> = suffix.split('.').collect();
    let country = labels.len() <= 2 && labels.iter().all(|l| l.len() <= 3) && labels.last().is_some_and(|tld| tld.len() == 2);
    country && FREE_MAIL_BRANDS.contains(&brand)
}

/// A Slack workspace (team) ID as stored: uppercase, like `T0123ABCD`. `None` when it isn't one.
pub fn normalize_team(team: &str) -> Option<String> {
    let team = team.trim().to_ascii_uppercase();
    let ok = team.starts_with('T') && team.len() > 1 && team.len() <= 30 && team.chars().all(|c| c.is_ascii_alphanumeric());
    ok.then_some(team)
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
    /// This server can encrypt a client secret (it has a connector key), so admins can use their
    /// own app. Without it, only `shared_providers` work.
    pub available: bool,
    /// The providers this server has its own sign-in app for (`google`, `microsoft`, `slack`).
    /// Set any of them up by signing in once (`setup_sso`), or with `update_sso` and `shared`:
    /// nothing to register. Empty when the server has none.
    pub shared_providers: Vec<Provider>,
    /// People can sign in with the provider now: turned on, fully set up and available.
    pub active: bool,
    pub enabled: bool,
    /// `google`, `microsoft`, `okta`, `onelogin`, `slack` or `oidc`.
    pub provider: Option<Provider>,
    /// Signs in through this server's own app for the provider, not one the workspace registered.
    pub shared: bool,
    /// Signs in through this server's own app, but the server doesn't have it any more. Single
    /// sign-on is off (so passwords work for everyone) until it's back, or an admin sets up their
    /// own app.
    pub shared_app_missing: bool,
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
    /// The saved client secret can't be read: the server's connector key changed since it was
    /// saved. Single sign-on is off until an admin enters the secret again.
    pub client_secret_unreadable: bool,
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
        shared_providers: cfg.sso_apps.providers(),
        active: active(cfg, &conf),
        enabled: conf.enabled,
        provider: conf.provider,
        shared: conf.shared,
        shared_app_missing: shared_app_missing(cfg, &conf),
        name: conf.name(),
        tenant: some(&conf.tenant),
        team: some(&conf.team),
        client_id: conf.client_id.clone(),
        client_secret_set: conf.client_secret.is_some(),
        client_secret_unreadable: secret_unreadable(cfg, &conf),
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

/// The issuer the discovery document at `conf.issuer` must name. That's the issuer itself, except
/// for Microsoft's `organizations` endpoints, where setting up starts: they name a template, filled
/// in with each ID token's own directory (see [`setup_org`]).
fn expected_issuer(conf: &Config) -> &str {
    if conf.provider == Some(Provider::Microsoft) && conf.issuer == MICROSOFT_ORGANIZATIONS {
        MICROSOFT_ISSUER_TEMPLATE
    } else {
        &conf.issuer
    }
}

/// Reads the discovery document. Its `issuer` must be the expected one exactly (OpenID Connect
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
    let expected = expected_issuer(conf);
    if issuer != expected {
        return Err(format!(
            "The provider names its issuer “{}”, not “{expected}”. They must match exactly.",
            connect::excerpt(issuer, 200),
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

/// Whether the account belongs to the organization at all. Some issuers serve everyone (Google,
/// Slack), others every directory's accounts; this narrows them to the workspace's.
fn org_check(conf: &Config, claims: &Value) -> Result<(), Problem> {
    let belongs = match conf.provider {
        Some(Provider::Google) => claims["hd"].as_str().is_some_and(|hd| !hd.is_empty() && conf.domain_allowed(hd)),
        Some(Provider::Microsoft) => claims["tid"].as_str().is_some_and(|t| t.eq_ignore_ascii_case(&conf.tenant)),
        // Required, like Microsoft's tenant: without it, anyone's Slack account would do.
        Some(Provider::Slack) => !conf.team.is_empty() && claims["https://slack.com/team_id"].as_str() == Some(conf.team.as_str()),
        _ => true,
    };
    if belongs { Ok(()) } else { Err(Problem::NotInOrg) }
}

/// The email address the provider vouches for, which a first sign-in may match to an existing
/// account (or join with): the provider must say it's verified, and its domain must be one of the
/// workspace's. Microsoft's `email` is only trusted with `xms_edov` (the domain's owner verified
/// it), never alone and never `upn`, so another directory can't claim an address it doesn't own.
fn vouched_email(conf: &Config, claims: &Value) -> Result<String, Problem> {
    let email = claims["email"].as_str().map(|e| e.trim().to_ascii_lowercase()).unwrap_or_default();
    let verified = match conf.provider {
        Some(Provider::Microsoft) => truthy(&claims["xms_edov"]),
        _ => truthy(&claims["email_verified"]),
    };
    if email.is_empty() || !verified {
        return Err(Problem::UnverifiedEmail);
    }
    let domain = email.rsplit_once('@').map(|(_, d)| d).unwrap_or_default();
    if !conf.domain_allowed(domain) {
        return Err(Problem::DomainNotAllowed);
    }
    Ok(email)
}

/// Setting up: reads the admin's organization from their own ID token and checks the token
/// against it. `target` is where setting up started ([`setup_target`]). Answers with the settings
/// for that organization (Google's hosted domain, Microsoft's directory and its issuer, Slack's
/// workspace) and the email domain to allow, when the provider vouches for one that isn't free
/// mail. Microsoft's directory must be in the issuer exactly, as Microsoft says multi-tenant apps
/// check; personal Google and Microsoft accounts have no organization.
fn setup_org(target: &Config, claims: &Value, nonce: &str, now: DateTime<Utc>) -> Result<(Config, Option<String>), Problem> {
    let mut conf = target.clone();
    let provider = conf.provider.ok_or(Problem::Failed)?;
    if provider == Provider::Microsoft {
        let tid = claims["tid"].as_str().unwrap_or_default();
        let tenant = normalize_tenant(tid).filter(|t| t != MICROSOFT_CONSUMERS).ok_or(Problem::PersonalAccount)?;
        // The token's own `tid`, exactly: `iss` must name it.
        conf.issuer = microsoft_issuer(tid);
        check_claims(&conf, claims, nonce, now).map_err(|_| Problem::InvalidToken)?;
        conf.issuer = microsoft_issuer(&tenant);
        conf.tenant = tenant;
    } else {
        check_claims(&conf, claims, nonce, now).map_err(|_| Problem::InvalidToken)?;
    }
    // An email domain the provider vouches for, unless anyone can have an address there.
    let vouched_domain = |vouched: bool| {
        let email = claims["email"].as_str().filter(|_| vouched)?;
        normalize_domain(email.rsplit_once('@')?.1).filter(|d| !free_mail(d))
    };
    let domain = match provider {
        Provider::Google => {
            let hd = claims["hd"].as_str().and_then(normalize_domain).filter(|d| !free_mail(d)).ok_or(Problem::PersonalAccount)?;
            conf.allowed_domains = vec![hd.clone()];
            Some(hd)
        }
        Provider::Microsoft => vouched_domain(truthy(&claims["xms_edov"])),
        Provider::Slack => {
            conf.team = claims["https://slack.com/team_id"].as_str().and_then(normalize_team).ok_or(Problem::NotInOrg)?;
            vouched_domain(truthy(&claims["email_verified"]))
        }
        _ => return Err(Problem::Failed),
    };
    Ok((conf, domain))
}

/// What a provider's refusal (`?error=…` on the way back) means. Microsoft says that a directory
/// needs its administrator to approve the app only in `error_description`'s AADSTS code, so only
/// that code is looked for there, to choose the message; the text itself goes nowhere.
fn provider_refused(error: &str, description: &str) -> Problem {
    let consent = error == "consent_required" || ["AADSTS90094", "AADSTS90095", "AADSTS65001"].iter().any(|c| description.contains(c));
    match error {
        _ if consent => Problem::AdminConsent,
        "access_denied" => Problem::Denied,
        _ => Problem::ProviderError,
    }
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

/// Why a sign-in, or linking an account, didn't work. Redirects carry only its code
/// (`?sso_error=…`), never text: the web app shows its own message for each code, so a link to
/// the sign-in page can't make it say anything else, and nothing from the provider reaches it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Problem {
    /// Single sign-on isn't on, or isn't fully set up.
    NotConfigured,
    /// The sign-in link was used, took too long, or the settings changed meanwhile.
    Expired,
    /// Finished in a browser other than the one that started.
    OtherBrowser,
    /// The person said no at the provider.
    Denied,
    /// The provider refused, didn't answer, or its settings don't check out.
    ProviderError,
    /// The ID token didn't check out.
    InvalidToken,
    /// An account outside the organization (Google's hosted domain, Microsoft's directory, Slack's workspace).
    NotInOrg,
    /// The provider didn't vouch for the email address.
    UnverifiedEmail,
    DomainNotAllowed,
    /// Nobody here has the email, and auto-provisioning is off.
    NoAccount,
    Deactivated,
    Bot,
    /// The person with that email has a different account at the provider linked.
    EmailLinked,
    /// Linking: finished in another browser session than the one that started (or it was signed out).
    OtherSession,
    /// Linking: the provider account is someone else's here.
    AlreadyLinked,
    /// Setting up: a personal account (Google without a Workspace domain, a personal Microsoft
    /// account), which has no organization to set up.
    PersonalAccount,
    /// The Microsoft directory needs an administrator to approve the app first.
    AdminConsent,
    /// Setting up: the person finishing isn't a workspace admin (any more).
    NotAdmin,
    /// Setting up: the server doesn't have its own app for that provider (any more).
    Unavailable,
    /// Anything else.
    Failed,
}

impl Problem {
    pub const ALL: [Problem; 20] = [
        Problem::NotConfigured,
        Problem::Expired,
        Problem::OtherBrowser,
        Problem::Denied,
        Problem::ProviderError,
        Problem::InvalidToken,
        Problem::NotInOrg,
        Problem::UnverifiedEmail,
        Problem::DomainNotAllowed,
        Problem::NoAccount,
        Problem::Deactivated,
        Problem::Bot,
        Problem::EmailLinked,
        Problem::OtherSession,
        Problem::AlreadyLinked,
        Problem::PersonalAccount,
        Problem::AdminConsent,
        Problem::NotAdmin,
        Problem::Unavailable,
        Problem::Failed,
    ];

    pub fn code(self) -> &'static str {
        match self {
            Problem::NotConfigured => "not_configured",
            Problem::Expired => "expired",
            Problem::OtherBrowser => "other_browser",
            Problem::Denied => "denied",
            Problem::ProviderError => "provider_error",
            Problem::InvalidToken => "invalid_token",
            Problem::NotInOrg => "not_in_org",
            Problem::UnverifiedEmail => "unverified_email",
            Problem::DomainNotAllowed => "domain_not_allowed",
            Problem::NoAccount => "no_account",
            Problem::Deactivated => "deactivated",
            Problem::Bot => "bot",
            Problem::EmailLinked => "email_linked",
            Problem::OtherSession => "other_session",
            Problem::AlreadyLinked => "already_linked",
            Problem::PersonalAccount => "personal_account",
            Problem::AdminConsent => "admin_consent",
            Problem::NotAdmin => "not_admin",
            Problem::Unavailable => "unavailable",
            Problem::Failed => "failed",
        }
    }
}

/// How setting up by signing in went, for Settings › Single sign-on (`?sso_setup=…`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetUp {
    /// Set up, with an allowed email domain.
    Done,
    /// Set up, but no email domain could be taken from the sign-in: first sign-ins can't match
    /// people by email until an admin adds one.
    DomainNeeded,
}

impl SetUp {
    pub fn code(self) -> &'static str {
        match self {
            SetUp::Done => "done",
            SetUp::DomainNeeded => "domain_needed",
        }
    }
}

/// Back to the sign-in page, saying what went wrong.
fn to_login(base_url: &str, problem: Problem, next: &str) -> Response {
    let mut url = format!("{base_url}/login?sso_error={}", problem.code());
    if next != "/" {
        url.push_str(&format!("&next={}", urlencoding::encode(next)));
    }
    no_store(Response::redirect(&url)).with_header("set-cookie", clear_browser_cookie(secure(base_url)))
}

/// Back to Settings › Profile after linking an account.
fn to_profile(base_url: &str, outcome: Result<(), Problem>) -> Response {
    let url = match outcome {
        Ok(()) => format!("{base_url}/settings/profile?sso_linked=1"),
        Err(problem) => format!("{base_url}/settings/profile?sso_error={}", problem.code()),
    };
    no_store(Response::redirect(&url))
}

/// Back to Settings › Single sign-on after setting it up by signing in.
fn to_settings(base_url: &str, outcome: Result<SetUp, Problem>) -> Response {
    let url = match outcome {
        Ok(done) => format!("{base_url}{SETTINGS_PATH}?sso_setup={}", done.code()),
        Err(problem) => format!("{base_url}{SETTINGS_PATH}?sso_error={}", problem.code()),
    };
    no_store(Response::redirect(&url))
}

/// Where a problem sends someone back to: the sign-in page, Settings › Profile when linking, or
/// Settings › Single sign-on when setting up.
fn back_to(base_url: &str, bound: bool, setup: bool, next: &str, problem: Problem) -> Response {
    match (bound, setup) {
        (true, true) => to_settings(base_url, Err(problem)),
        (true, false) => to_profile(base_url, Err(problem)),
        (false, _) => to_login(base_url, problem, next),
    }
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
    /// Setting up with the host's app for this provider (`setup_sso`), not signing in or linking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    setup: Option<Provider>,
}

/// A single sign-on job (see [`crate::connect::Job`]).
#[derive(Clone)]
pub struct SsoJob {
    base_url: String,
    kind: Kind,
    phase: Phase,
    /// Webhooks for the settings change setting up made, which the host delivers when the job ends.
    effects: Vec<Effect>,
}

#[derive(Clone)]
enum Kind {
    /// Someone signing in from the sign-in page.
    SignIn { next: String },
    /// A signed-in person linking their account (`link_sso`), from one browser session.
    Link { user_id: String, session_hash: String },
    /// An admin setting single sign-on up by signing in with the host's app (`setup_sso`), from
    /// one browser session.
    Setup { user_id: String, session_hash: String, provider: Provider },
    /// An admin saved the settings (`update_sso`): check the provider's discovery document.
    Check,
    /// The provider sent someone back.
    Finish(Box<Returned>),
}

#[derive(Clone)]
struct Returned {
    code: String,
    flow: Flow,
    /// Linking or setting up: who.
    link_user: Option<String>,
    /// Linking or setting up: the session that started it, which must still be signed in to finish.
    link_session: Option<String>,
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
            Kind::Setup { .. } => "setup",
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
    fn new(base_url: &str, kind: Kind) -> SsoJob {
        SsoJob { base_url: base_url.into(), kind, phase: Phase::Start, effects: vec![] }
    }

    /// Checks the provider's discovery document, then fills in the settings with the result.
    pub fn check(base_url: &str) -> SsoJob {
        SsoJob::new(base_url, Kind::Check)
    }

    /// Starts linking `user_id`'s account at the provider, for the browser session whose token
    /// hashes to `session_hash`; fills in `{ "authorize_url": … }`.
    pub fn link(base_url: &str, user_id: &str, session_hash: &str) -> SsoJob {
        SsoJob::new(base_url, Kind::Link { user_id: user_id.into(), session_hash: session_hash.into() })
    }

    /// Starts setting single sign-on up with the host's app for `provider`, by admin `user_id`
    /// signing in from the browser session whose token hashes to `session_hash`; fills in
    /// `{ "authorize_url": … }`.
    pub fn setup(base_url: &str, user_id: &str, session_hash: &str, provider: Provider) -> SsoJob {
        SsoJob::new(base_url, Kind::Setup { user_id: user_id.into(), session_hash: session_hash.into(), provider })
    }

    /// What the job left for the host to deliver (see [`crate::connect::Job::take_effects`]).
    pub(crate) fn take_effects(&mut self) -> Vec<Effect> {
        std::mem::take(&mut self.effects)
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
            return Ok(crate::http::done(to_login(&base, Problem::NotConfigured, &next)));
        }
        let mut out = crate::http::done(to_login(&base, Problem::Failed, &next));
        let job = SsoJob::new(&base, Kind::SignIn { next: next.clone() });
        out.effects.push(Effect::Connect(Job::Sso(job)));
        Ok(out)
    };
    run().unwrap_or_else(|_| crate::http::done(to_login(&base, Problem::Failed, &next)))
}

/// `GET /sso/callback`: the provider sent someone back. The sign-in must be one this browser
/// started (or, when linking or setting up, one this very browser session started, still signed
/// in), unused and recent, for the same app. Setting up also needs the settings to be as they were
/// when it started. Answers with a job that exchanges the code and signs them in (or links their
/// account, or saves the settings setting up found).
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
            return Ok(redirect(to_login(&base, Problem::Expired, "/")));
        };
        // Each sign-in link works once.
        db.execute("DELETE FROM sso_requests WHERE state_hash = ?", &params![state_hash])?;
        let flow: Flow = serde_json::from_str(&row.str("flow")).map_err(|e| ApiError::internal(e.to_string()))?;
        let link_user = row.opt_str("user_id");
        let setup = flow.setup;
        let back = |problem: Problem| redirect(back_to(&base, link_user.is_some(), setup.is_some(), &flow.next, problem));
        let started = parse_ts(&row.str("created_at")).unwrap_or(now);
        if now - started > Duration::minutes(SIGN_IN_MINUTES) {
            return Ok(back(Problem::Expired));
        }
        let link_session = link_user.as_ref().map(|_| row.str("browser_hash"));
        match (&link_user, &link_session) {
            (Some(user_id), Some(expected)) => {
                // The session that started linking (or setting up), and still a live one: one
                // started in a session that was signed out (or stolen, then revoked) can't be
                // finished elsewhere.
                let actor = auth::authenticate(db, cfg, req, now).ok().flatten();
                let same =
                    actor.is_some_and(|a| a.user_id == *user_id && a.session_hash.is_some_and(|h| crate::util::secure_eq(&h, expected)));
                if !same {
                    return Ok(back(Problem::OtherSession));
                }
            }
            _ => {
                let cookie = auth::cookie_value(req, BROWSER_COOKIE).unwrap_or_default();
                let expected = row.str("browser_hash");
                if cookie.is_empty() || !crate::util::secure_eq(&sha256_hex(cookie), &expected) {
                    return Ok(back(Problem::OtherBrowser));
                }
            }
        }
        let stored = load(db)?;
        match setup {
            Some(p) => match setup_fingerprint(cfg, p, &stored) {
                None => return Ok(back(Problem::Unavailable)),
                Some(f) if f != flow.fingerprint => return Ok(back(Problem::Expired)),
                Some(_) => {}
            },
            None => {
                let conf = effective(cfg, stored);
                if !active(cfg, &conf) {
                    return Ok(back(Problem::NotConfigured));
                }
                if conf.fingerprint() != flow.fingerprint {
                    return Ok(back(Problem::Expired));
                }
            }
        }
        // The provider's own error text never reaches the page; only what kind of failure.
        let code = match (query.get("code").filter(|c| !c.is_empty()), query.get("error")) {
            (Some(c), _) => c.clone(),
            (None, Some(e)) => {
                let description = query.get("error_description").map(String::as_str).unwrap_or_default();
                return Ok(back(provider_refused(e, description)));
            }
            (None, None) => return Ok(back(Problem::ProviderError)),
        };
        let mut out = back(Problem::Failed);
        let returned = Returned { code, flow, link_user, link_session, user_agent: req.header("user-agent").map(str::to_string) };
        let job = SsoJob::new(&base, Kind::Finish(Box::new(returned)));
        out.effects.push(Effect::Connect(Job::Sso(job)));
        Ok(out)
    };
    run().unwrap_or_else(|_| redirect(to_login(&base, Problem::Failed, "/")))
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Where setting up with the host's app for `p` starts, before the organization is known: the
/// provider's own issuer (Microsoft's `organizations` endpoints) and the host's client ID. `None`
/// when the host has no app for it.
fn setup_target(cfg: &HostConfig, p: Provider) -> Option<Config> {
    let app = cfg.sso_apps.get(p)?;
    let issuer = match p {
        Provider::Microsoft => MICROSOFT_ORGANIZATIONS,
        _ => p.fixed_issuer()?,
    };
    Some(Config {
        enabled: true,
        provider: Some(p),
        shared: true,
        issuer: issuer.into(),
        client_id: app.client_id.clone(),
        ..Default::default()
    })
}

/// What setting up must still match when it finishes: the host's same app, and the workspace's
/// settings exactly as they were when it started, so it never overwrites a change made meanwhile.
/// `None` when the host has no app for `p`.
fn setup_fingerprint(cfg: &HostConfig, p: Provider, stored: &Config) -> Option<String> {
    let app = cfg.sso_apps.get(p)?;
    let settings = serde_json::to_string(stored).unwrap_or_default();
    Some(sha256_hex(&format!("setup|{}|{}|{}", p.as_str(), app.client_id, sha256_hex(&settings))))
}

/// What a sign-in under way is for.
struct Purpose<'a> {
    /// Where to land afterwards.
    next: &'a str,
    /// Linking or setting up: (who, the hash of the browser session that started it), which alone
    /// may finish it. Otherwise a cookie names the browser.
    bound: Option<(&'a str, &'a str)>,
    /// Setting up with the host's app for this provider.
    setup: Option<Provider>,
    /// What the settings must still match when it finishes.
    fingerprint: String,
}

/// Records a sign-in under way and returns the provider's sign-in URL and, for a sign-in from the
/// sign-in page, the cookie naming this browser. `conf` is [`effective`]. In shared mode on hosted
/// DumbSlab the `state` starts with the workspace's address, so the root domain's callback knows
/// where to send the browser.
fn begin(
    db: &dyn Db,
    cfg: &HostConfig,
    conf: &Config,
    d: &Discovery,
    base_url: &str,
    purpose: Purpose,
    now: DateTime<Utc>,
) -> ApiResult<(String, Option<String>)> {
    db.execute("DELETE FROM sso_requests WHERE created_at < ?", &params![ts(now - Duration::minutes(SIGN_IN_MINUTES))])?;
    // Starting needs no account, so keep the newest only.
    db.execute(
        "DELETE FROM sso_requests WHERE state_hash NOT IN (SELECT state_hash FROM sso_requests ORDER BY created_at DESC LIMIT ?)",
        &params![MAX_PENDING - 1],
    )?;
    let random = crate::util::new_secret("");
    let state = match (&cfg.workspace, &cfg.sso_apps.callback_url) {
        (Some(address), Some(_)) if conf.shared => format!("{address}.{random}"),
        _ => random,
    };
    let nonce = crate::util::new_secret("");
    let verifier = crate::util::new_secret("") + &crate::util::new_secret("");
    let browser = purpose.bound.is_none().then(|| crate::util::new_secret(""));
    let binding = match purpose.bound {
        Some((_, session_hash)) => session_hash.to_string(),
        None => sha256_hex(browser.as_deref().unwrap_or_default()),
    };
    let flow = Flow {
        nonce: nonce.clone(),
        verifier: verifier.clone(),
        fingerprint: purpose.fingerprint,
        redirect_uri: redirect_uri(cfg, conf, base_url),
        token_endpoint: d.token.clone(),
        userinfo_endpoint: d.userinfo.clone(),
        basic_auth: d.basic_auth,
        next: purpose.next.to_string(),
        setup: purpose.setup,
    };
    db.execute(
        "INSERT INTO sso_requests (state_hash, browser_hash, user_id, flow, created_at) VALUES (?, ?, ?, ?, ?)",
        &params![
            sha256_hex(&state),
            binding,
            purpose.bound.map(|(user_id, _)| user_id),
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
            // A hint only: the `hd` claim is what's checked. Setting up asks for any Google
            // Workspace account (`hd=*`).
            match conf.allowed_domains.as_slice() {
                [domain] => query.push(("hd", domain.clone())),
                [] if flow.setup.is_some() => query.push(("hd", "*".into())),
                _ => {}
            }
        }
        // Setting up: let the admin pick their work account.
        Some(Provider::Microsoft) if flow.setup.is_some() => query.push(("prompt", "select_account".into())),
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

/// The error for setting up with a provider the host has no app for.
pub fn shared_unavailable(p: Provider) -> ApiError {
    ApiError::new(
        400,
        "sso_shared_unavailable",
        format!("This server has no {} app of its own to sign in with. Set up your own app instead (`update_sso`).", p.name()),
    )
}

/// Runs a single sign-on job's next step (see [`crate::connect::step`]).
pub fn step(db: &dyn Db, cfg: &HostConfig, j: &mut SsoJob, replies: Vec<HttpReply>, now: DateTime<Utc>) -> ApiResult<Step> {
    let reply = replies.into_iter().next().unwrap_or_default();
    let stored = load(db)?;
    let conf = effective(cfg, stored.clone());
    let base = j.base_url.clone();
    let phase = std::mem::replace(&mut j.phase, Phase::Start);
    match (&j.kind, phase) {
        (Kind::Finish(r), phase) => {
            let r = r.clone();
            finish_step(db, cfg, j, &conf, &r, phase, reply, now)
        }
        (Kind::Setup { provider, .. }, Phase::Start) => {
            let Some(target) = setup_target(cfg, *provider) else {
                return Ok(Step::Done(Finish::Fail(shared_unavailable(*provider))));
            };
            j.phase = Phase::Discovering;
            Ok(Step::Fetch(vec![HttpCall::get(discovery_url(&target.issuer)).header("accept", "application/json")]))
        }
        (Kind::Setup { user_id, session_hash, provider }, _) => {
            let (Some(target), Some(fingerprint)) = (setup_target(cfg, *provider), setup_fingerprint(cfg, *provider, &stored)) else {
                return Ok(Step::Done(Finish::Fail(shared_unavailable(*provider))));
            };
            match read_discovery(&target, &reply) {
                Ok(d) => {
                    let purpose =
                        Purpose { next: SETTINGS_PATH, bound: Some((user_id, session_hash)), setup: Some(*provider), fingerprint };
                    let (url, _) = begin(db, cfg, &target, &d, &base, purpose, now)?;
                    fill(json!({ "authorize_url": url }))
                }
                Err(e) => Ok(Step::Done(Finish::Fail(ApiError::new(502, "sso_unavailable", e)))),
            }
        }
        (_, Phase::Start) => {
            let usable = match j.kind {
                Kind::Check => !conf.issuer.is_empty(),
                _ => active(cfg, &conf),
            };
            if !usable {
                return Ok(match &j.kind {
                    Kind::SignIn { next } => respond(to_login(&base, Problem::NotConfigured, next)),
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
                let purpose = Purpose { next, bound: None, setup: None, fingerprint: conf.fingerprint() };
                let (url, browser) = begin(db, cfg, &conf, &d, &base, purpose, now)?;
                let cookie = browser_cookie(&browser.unwrap_or_default(), secure(&base));
                Ok(respond(no_store(Response::redirect(&url)).with_header("set-cookie", cookie)))
            }
            Err(_) => Ok(respond(to_login(&base, Problem::ProviderError, next))),
        },
        (Kind::Link { user_id, session_hash }, _) => match read_discovery(&conf, &reply) {
            Ok(d) => {
                let purpose = Purpose {
                    next: "/settings/profile",
                    bound: Some((user_id, session_hash)),
                    setup: None,
                    fingerprint: conf.fingerprint(),
                };
                let (url, _) = begin(db, cfg, &conf, &d, &base, purpose, now)?;
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

/// Finishes a sign-in, a link or setting up, once the provider sent the person back. `conf` is
/// the workspace's [`effective`] settings.
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
    let back = |problem: Problem| respond(back_to(&base, r.link_user.is_some(), r.flow.setup.is_some(), &r.flow.next, problem));
    // The app and settings this sign-in uses: the workspace's, unchanged since it started; or,
    // setting up, the host's app, with the workspace's settings unchanged.
    let target = match r.flow.setup {
        Some(p) => match (setup_target(cfg, p), setup_fingerprint(cfg, p, &load(db)?)) {
            (Some(t), Some(f)) if f == r.flow.fingerprint => t,
            (Some(_), Some(_)) => return Ok(back(Problem::Expired)),
            _ => return Ok(back(Problem::Unavailable)),
        },
        None if !active(cfg, conf) || conf.fingerprint() != r.flow.fingerprint => return Ok(back(Problem::Expired)),
        None => conf.clone(),
    };
    match phase {
        Phase::Start | Phase::Discovering => {
            let Some((_, secret)) = credentials(cfg, &target) else {
                return Ok(back(Problem::ProviderError));
            };
            j.phase = Phase::Exchanging;
            Ok(Step::Fetch(vec![token_call(&target, &r.flow, &r.code, &secret)]))
        }
        Phase::Exchanging => {
            let v = reply.json();
            let id_token = v["id_token"].as_str().filter(|t| reply.ok() && !t.is_empty());
            let Some(id_token) = id_token else {
                return Ok(back(Problem::ProviderError));
            };
            let Ok(claims) = jwt_claims(id_token) else {
                return Ok(back(Problem::InvalidToken));
            };
            if r.flow.setup.is_some() {
                return match setup_org(&target, &claims, &r.flow.nonce, now) {
                    Ok((org, domain)) => complete_setup(db, cfg, j, r, &org, domain, &claims, now),
                    Err(problem) => Ok(back(problem)),
                };
            }
            if check_claims(&target, &claims, &r.flow.nonce, now).is_err() {
                return Ok(back(Problem::InvalidToken));
            }
            // A first sign-in matches people by email, and some providers give the address, or
            // say whether it's verified, only in their userinfo answer: ask it then. Microsoft's
            // would never be trusted on its own (see `vouched_email`), so it isn't asked.
            let access = v["access_token"].as_str().filter(|t| !t.is_empty());
            let lacks_email = claims.get("email").is_none() || claims.get("email_verified").is_none();
            let asks = lacks_email
                && r.link_user.is_none()
                && target.provider != Some(Provider::Microsoft)
                && !is_linked(db, &target, claims["sub"].as_str().unwrap_or_default())?;
            if let (true, Some(url), Some(access)) = (asks, r.flow.userinfo_endpoint.clone(), access) {
                j.phase = Phase::UserInfo { claims };
                return Ok(Step::Fetch(vec![HttpCall::get(url).bearer(access).header("accept", "application/json")]));
            }
            complete(db, cfg, &base, &target, r, &claims, now)
        }
        Phase::UserInfo { mut claims } => {
            // No answer, or one that isn't JSON, adds nothing: the sign-in goes on with the ID token alone.
            if reply.ok() {
                merge_userinfo(&mut claims, &reply.json());
            }
            complete(db, cfg, &base, &target, r, &claims, now)
        }
    }
}

/// Setting up checked out: saves the settings for the admin's organization (`org`, from
/// [`setup_org`]) and links the admin's own account. The admin must still be signed in to the
/// session that started, and still an admin; their account at the provider can't be someone
/// else's here. `require_sso` and `auto_provision` stay as they were. Allowed domains: the one
/// the sign-in vouched for, plus the ones already allowed when it's the same organization again.
#[allow(clippy::too_many_arguments)]
fn complete_setup(
    db: &dyn Db,
    cfg: &HostConfig,
    j: &mut SsoJob,
    r: &Returned,
    org: &Config,
    domain: Option<String>,
    claims: &Value,
    now: DateTime<Utc>,
) -> ApiResult<Step> {
    let base = j.base_url.clone();
    let back = |problem: Problem| Ok(respond(to_settings(&base, Err(problem))));
    let user_id = r.link_user.clone().unwrap_or_default();
    let live = db.scalar_i64(
        "SELECT COUNT(*) FROM sessions WHERE token_hash = ? AND user_id = ? AND expires_at > ?",
        &params![r.link_session.clone().unwrap_or_default(), user_id.clone(), ts(now)],
    )? > 0;
    if !live {
        return back(Problem::OtherSession);
    }
    let Some(p) = find_person(db, &user_id)? else { return back(Problem::Failed) };
    if let Some(problem) = refusal(&p) {
        return back(problem);
    }
    if p.role != Role::Admin {
        return back(Problem::NotAdmin);
    }
    let subject = claims["sub"].as_str().unwrap_or_default();
    let owner = db.one("SELECT user_id FROM sso_identities WHERE issuer = ? AND subject = ?", &params![org.issuer.clone(), subject])?;
    if owner.as_ref().is_some_and(|o| o.str("user_id") != p.id) {
        return back(Problem::AlreadyLinked);
    }

    let before = load(db)?;
    let provider = org.provider.ok_or_else(|| ApiError::internal("setting up without a provider"))?;
    let same_org = before.provider == Some(provider)
        && match provider {
            Provider::Google => domain.as_deref().is_some_and(|d| before.domain_allowed(d)),
            Provider::Microsoft => before.tenant == org.tenant,
            Provider::Slack => before.team == org.team,
            _ => false,
        };
    let mut allowed_domains = if same_org { before.allowed_domains.clone() } else { vec![] };
    if let Some(d) = &domain
        && !allowed_domains.contains(d)
    {
        allowed_domains.push(d.clone());
    }
    let saved = Config {
        enabled: true,
        provider: Some(provider),
        shared: true,
        issuer: org.issuer.clone(),
        tenant: org.tenant.clone(),
        team: org.team.clone(),
        client_id: String::new(),
        client_secret: None,
        allowed_domains,
        auto_provision: before.auto_provision,
        require_sso: before.require_sso,
        label: String::new(),
    };
    save(db, &saved)?;
    let newly_linked = owner.is_none();
    if newly_linked {
        link_identity(db, &p.id, &saved, claims, now)?;
    }

    let name = saved.name();
    let mut ctx = ctx_for(db, cfg, &base, &p, now);
    let data = json!({
        "provider": provider.as_str(),
        "shared": true,
        "enabled": true,
        "require_sso": saved.require_sso,
        "auto_provision": saved.auto_provision,
        "tenant": Some(&saved.tenant).filter(|t| !t.is_empty()),
        "team": Some(&saved.team).filter(|t| !t.is_empty()),
        "allowed_domains": saved.allowed_domains,
        "replaced": before.provider.filter(|_| !same_org).map(Provider::as_str),
        "client_secret_changed": before.client_secret.is_some(),
    });
    emit(&mut ctx, Event::new("sso.updated", "settings", "sso", format!("set up single sign-on with {name}")).data(data).admin_only())?;
    if newly_linked {
        let data = json!({ "issuer": saved.issuer, "matched_by": "setup" });
        let summary = format!("linked their {name} account while setting up single sign-on");
        emit(&mut ctx, Event::new("sso.linked", "user", &p.id, summary).data(data).admin_only())?;
    }
    // Unlike a sign-in's, a settings change goes to webhooks, as `update_sso`'s does.
    j.effects.extend(ctx.effects);
    let outcome = if saved.allowed_domains.is_empty() { SetUp::DomainNeeded } else { SetUp::Done };
    Ok(respond(to_settings(&base, Ok(outcome))))
}

/// Whether an account at the provider is linked to someone here already.
fn is_linked(db: &dyn Db, conf: &Config, subject: &str) -> ApiResult<bool> {
    let n =
        db.scalar_i64("SELECT COUNT(*) FROM sso_identities WHERE issuer = ? AND subject = ?", &params![conf.issuer.clone(), subject])?;
    Ok(n > 0)
}

/// Adds what the userinfo answer says to what the ID token didn't. Only an answer about the same
/// account counts (OpenID Connect Core 1.0, 5.3.2), and its `email_verified` only with its own
/// `email`, which must be the ID token's address when the token has one. Nothing the ID token
/// says is replaced.
fn merge_userinfo(claims: &mut Value, info: &Value) {
    let same_account = info["sub"].as_str().is_some_and(|s| !s.is_empty() && Some(s) == claims["sub"].as_str());
    if !same_account {
        return;
    }
    let normalize = |v: &Value| v.as_str().map(|e| e.trim().to_ascii_lowercase()).filter(|e| !e.is_empty());
    let mut keys = vec!["name", "given_name", "family_name"];
    match (normalize(&claims["email"]), normalize(&info["email"])) {
        (Some(token), Some(answer)) if token != answer => {}
        (_, Some(_)) => keys.extend(["email", "email_verified"]),
        (_, None) => {}
    }
    for key in keys {
        if claims.get(key).is_none() && !info[key].is_null() {
            claims[key] = info[key].clone();
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
fn refusal(p: &Person) -> Option<Problem> {
    if p.deactivated {
        Some(Problem::Deactivated)
    } else if p.is_bot {
        Some(Problem::Bot)
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

/// How an account at the provider came to be linked to someone here.
#[derive(Clone, Copy)]
enum Matched {
    /// They linked it while signed in.
    Themselves,
    /// Their first sign-in, by the email the provider vouched for.
    Email,
    /// They joined by signing in (auto-provisioning).
    Provisioned,
}

/// Records a new link in the admins' activity log: it's a new way into the account.
fn record_link(db: &dyn Db, cfg: &HostConfig, base: &str, p: &Person, conf: &Config, how: Matched, now: DateTime<Utc>) -> ApiResult<()> {
    let name = conf.name();
    let (matched, summary) = match how {
        Matched::Themselves => ("self", format!("linked their {name} account")),
        Matched::Email => ("email", format!("signed in with {name} for the first time, linked by their verified email")),
        Matched::Provisioned => ("provisioned", format!("joined with their {name} account")),
    };
    let mut ctx = ctx_for(db, cfg, base, p, now);
    let data = json!({ "issuer": conf.issuer, "matched_by": matched });
    emit(&mut ctx, Event::new("sso.linked", "user", &p.id, summary).data(data).admin_only())?;
    Ok(())
}

/// The ID token checked out: link the account, or sign the person in.
fn complete(db: &dyn Db, cfg: &HostConfig, base: &str, conf: &Config, r: &Returned, claims: &Value, now: DateTime<Utc>) -> ApiResult<Step> {
    let back = |problem: Problem| match r.link_user {
        Some(_) => respond(to_profile(base, Err(problem))),
        None => respond(to_login(base, problem, &r.flow.next)),
    };
    if let Err(problem) = org_check(conf, claims) {
        return Ok(back(problem));
    }
    let subject = claims["sub"].as_str().unwrap_or_default();
    let linked = db.one(
        &format!("SELECT {PERSON_COLS}, i.id AS identity_id FROM sso_identities i JOIN users u ON u.id = i.user_id WHERE i.issuer = ? AND i.subject = ?"),
        &params![conf.issuer.clone(), subject],
    )?;

    if let Some(user_id) = &r.link_user {
        // The session that started linking must still be signed in as it finishes.
        let live = db.scalar_i64(
            "SELECT COUNT(*) FROM sessions WHERE token_hash = ? AND user_id = ? AND expires_at > ?",
            &params![r.link_session.clone().unwrap_or_default(), user_id.clone(), ts(now)],
        )? > 0;
        if !live {
            return Ok(back(Problem::OtherSession));
        }
        let Some(p) = find_person(db, user_id)? else { return Ok(back(Problem::Failed)) };
        if let Some(problem) = refusal(&p) {
            return Ok(back(problem));
        }
        match linked {
            Some(row) if row.str("id") != p.id => return Ok(back(Problem::AlreadyLinked)),
            Some(_) => {}
            None => {
                link_identity(db, &p.id, conf, claims, now)?;
                record_link(db, cfg, base, &p, conf, Matched::Themselves, now)?;
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
                Err(problem) => return Ok(back(problem)),
            };
            match db.one(&format!("SELECT {PERSON_COLS} FROM users u WHERE u.email = ?"), &params![email.clone()])?.map(|r| person(&r)) {
                Some(p) => {
                    if let Some(problem) = refusal(&p) {
                        return Ok(back(problem));
                    }
                    // Linked to another account at this issuer: the address may have changed hands.
                    let other = db.scalar_i64(
                        "SELECT COUNT(*) FROM sso_identities WHERE user_id = ? AND issuer = ?",
                        &params![p.id.clone(), conf.issuer.clone()],
                    )?;
                    if other > 0 {
                        return Ok(back(Problem::EmailLinked));
                    }
                    link_identity(db, &p.id, conf, claims, now)?;
                    record_link(db, cfg, base, &p, conf, Matched::Email, now)?;
                    p
                }
                None if conf.auto_provision => provision(db, cfg, base, conf, claims, &email, now)?,
                None => return Ok(back(Problem::NoAccount)),
            }
        }
    };
    if let Some(problem) = refusal(&p) {
        return Ok(back(problem));
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
    record_link(db, cfg, base, &p, conf, Matched::Provisioned, now)?;
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
    fn userinfo_fills_in_only_for_the_same_account_and_address() {
        let token = || json!({ "sub": "u1", "email": "Ada@acme.com" });
        let merged = |claims: Value, info: Value| {
            let mut c = claims;
            merge_userinfo(&mut c, &info);
            c
        };
        let c = merged(token(), json!({ "sub": "u1", "email": "ada@acme.com", "email_verified": true, "name": "Ada" }));
        assert_eq!(
            (c["email_verified"].as_bool(), c["name"].as_str(), c["email"].as_str()),
            (Some(true), Some("Ada"), Some("Ada@acme.com"))
        );
        // Another account, another address, or no address to vouch for: nothing about the email.
        assert!(merged(token(), json!({ "sub": "u2", "email": "ada@acme.com", "email_verified": true })).get("email_verified").is_none());
        assert!(merged(token(), json!({ "sub": "u1", "email": "eve@acme.com", "email_verified": true })).get("email_verified").is_none());
        assert!(merged(token(), json!({ "sub": "u1", "email_verified": true })).get("email_verified").is_none());
        assert!(merged(token(), json!({ "email": "ada@acme.com", "email_verified": true })).get("email_verified").is_none());
        // A token without an address takes the answer's.
        let c = merged(json!({ "sub": "u1" }), json!({ "sub": "u1", "email": "ada@acme.com", "email_verified": "true" }));
        assert_eq!((c["email"].as_str(), c["email_verified"].as_str()), (Some("ada@acme.com"), Some("true")));
        // What the token says stands.
        let c = merged(
            json!({ "sub": "u1", "email": "ada@acme.com", "email_verified": false }),
            json!({ "sub": "u1", "email": "ada@acme.com", "email_verified": true }),
        );
        assert_eq!(c["email_verified"], false);
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
            setup: Some(Provider::Google),
        };
        let returned = Returned { code: "the-code".into(), flow, link_user: None, link_session: None, user_agent: None };
        let mut job = SsoJob::new("https://kb.test", Kind::Finish(Box::new(returned)));
        job.phase = Phase::Exchanging;
        let printed = format!("{job:?}");
        for secret in ["the-nonce", "the-verifier", "the-code"] {
            assert!(!printed.contains(secret), "{printed}");
        }
    }

    fn shared_apps() -> HostConfig {
        let app = |id: &str| Some(OAuthApp { client_id: format!("{id}-app"), client_secret: format!("{id}-secret") });
        HostConfig {
            sso_apps: SharedApps { google: app("google"), microsoft: app("microsoft"), slack: app("slack"), callback_url: None },
            ..Default::default()
        }
    }

    #[test]
    fn shared_apps_come_from_the_hosts_settings() {
        let vars: BTreeMap<&str, &str> = [
            ("SSO_GOOGLE_CLIENT_ID", "g-id"),
            ("SSO_GOOGLE_CLIENT_SECRET", "g-secret"),
            // Half an app is no app.
            ("SSO_MICROSOFT_CLIENT_ID", "m-id"),
            ("SLACK_CLIENT_ID", "s-id"),
            ("SLACK_CLIENT_SECRET", "s-secret"),
        ]
        .into();
        let apps = SharedApps::from_vars(|k| vars.get(k).map(|v| v.to_string()));
        assert_eq!(apps.providers(), vec![Provider::Google, Provider::Slack]);
        assert_eq!(apps.get(Provider::Google).map(|a| a.client_id.as_str()), Some("g-id"));
        assert!(apps.get(Provider::Okta).is_none());
        assert!(!format!("{apps:?}").contains("g-secret"), "{apps:?}");
    }

    #[test]
    fn shared_mode_needs_the_hosts_app() {
        let cfg = shared_apps();
        let conf = Config {
            enabled: true,
            provider: Some(Provider::Slack),
            shared: true,
            issuer: "https://slack.com".into(),
            team: "T0ACME".into(),
            ..Default::default()
        };
        assert!(conf.complete() && active(&cfg, &conf));
        assert_eq!(credentials(&cfg, &conf), Some(("slack-app".into(), "slack-secret".into())));
        assert_eq!(effective(&cfg, conf.clone()).client_id, "slack-app");
        // The host loses the app: single sign-on is off, and says why.
        let without = HostConfig::default();
        assert!(!active(&without, &conf) && shared_app_missing(&without, &conf));
        // Only Google, Microsoft and Slack have shared apps.
        let okta = Config { provider: Some(Provider::Okta), issuer: "https://acme.okta.com".into(), ..conf.clone() };
        assert!(!okta.complete());
        // The shared app's client ID is part of what a sign-in must still match.
        let mut other = shared_apps();
        other.sso_apps.slack.as_mut().unwrap().client_id = "another-app".into();
        assert_ne!(effective(&cfg, conf.clone()).fingerprint(), effective(&other, conf).fingerprint());
    }

    #[test]
    fn free_mail_domains_are_never_derived() {
        for free in [
            "gmail.com",
            "GoogleMail.com",
            "outlook.com",
            "hotmail.co.uk",
            "yahoo.co.jp",
            "live.fr",
            "outlook.com.br",
            "icloud.com",
            "proton.me",
        ] {
            assert!(free_mail(free), "{free}");
        }
        for org in ["acme.com", "live.acmecorp.com", "gmail-tools.io", "outlook.acme.com", "yahoo.example.org"] {
            assert!(!free_mail(org), "{org}");
        }
        assert_eq!(normalize_team(" t0acme ").as_deref(), Some("T0ACME"));
        for bad in ["", "T", "U0ACME", "T0 ACME"] {
            assert!(normalize_team(bad).is_none(), "{bad}");
        }
    }

    fn token(iss: &str, aud: &str, extra: Value) -> Value {
        let t = Utc::now().timestamp();
        let mut c = json!({ "iss": iss, "aud": aud, "sub": "admin-sub", "exp": t + 300, "iat": t, "nonce": "n" });
        for (k, v) in extra.as_object().unwrap() {
            c[k] = v.clone();
        }
        c
    }

    #[test]
    fn setting_up_reads_the_organization_from_the_admins_token() {
        let cfg = shared_apps();
        let now = Utc::now();
        let target = |p| setup_target(&cfg, p).unwrap();
        let org = |p, claims: Value| setup_org(&target(p), &claims, "n", now);

        // Google: the Workspace domain, which must be there.
        let g = "https://accounts.google.com";
        let (c, domain) = org(Provider::Google, token(g, "google-app", json!({ "hd": "Acme.com", "email": "ada@acme.com" }))).unwrap();
        assert_eq!((c.allowed_domains, domain.as_deref(), c.issuer.as_str()), (vec!["acme.com".to_string()], Some("acme.com"), g));
        assert_eq!(
            org(Provider::Google, token(g, "google-app", json!({ "email": "ada@gmail.com", "email_verified": true }))).unwrap_err(),
            Problem::PersonalAccount
        );
        assert_eq!(org(Provider::Google, token(g, "google-app", json!({ "hd": "gmail.com" }))).unwrap_err(), Problem::PersonalAccount);
        // The usual checks: another app's token, another sign-in's.
        assert_eq!(org(Provider::Google, token(g, "someone-elses", json!({ "hd": "acme.com" }))).unwrap_err(), Problem::InvalidToken);
        let mut replayed = token(g, "google-app", json!({ "hd": "acme.com" }));
        replayed["nonce"] = json!("other");
        assert_eq!(org(Provider::Google, replayed).unwrap_err(), Problem::InvalidToken);

        // Microsoft: the token's own directory, which its issuer must name exactly.
        let tid = "72f988bf-86f1-41af-91ab-2d7cd011db47";
        let iss = microsoft_issuer(tid);
        let ms = |iss: &str, extra: Value| org(Provider::Microsoft, token(iss, "microsoft-app", extra));
        let (c, domain) = ms(&iss, json!({ "tid": tid, "email": "ada@acme.com", "xms_edov": true })).unwrap();
        assert_eq!((c.tenant.as_str(), c.issuer.as_str(), domain.as_deref()), (tid, iss.as_str(), Some("acme.com")));
        // Without xms_edov the domain is left for the admin.
        assert_eq!(ms(&iss, json!({ "tid": tid, "email": "ada@acme.com", "email_verified": true })).unwrap().1, None);
        let other = "00000000-0000-0000-0000-000000000001";
        assert_eq!(ms(&microsoft_issuer(other), json!({ "tid": tid })).unwrap_err(), Problem::InvalidToken, "iss names another directory");
        assert_eq!(ms(MICROSOFT_ISSUER_TEMPLATE, json!({ "tid": tid })).unwrap_err(), Problem::InvalidToken);
        assert_eq!(ms(&iss, json!({})).unwrap_err(), Problem::PersonalAccount, "no directory");
        assert_eq!(ms(&iss, json!({ "tid": "organizations" })).unwrap_err(), Problem::PersonalAccount);
        let consumers = microsoft_issuer(MICROSOFT_CONSUMERS);
        assert_eq!(ms(&consumers, json!({ "tid": MICROSOFT_CONSUMERS })).unwrap_err(), Problem::PersonalAccount);

        // Slack: the workspace, and the domain only when Slack vouches for the address.
        let s = "https://slack.com";
        let slack = |extra: Value| org(Provider::Slack, token(s, "slack-app", extra));
        let (c, domain) = slack(json!({ "https://slack.com/team_id": "T0ACME", "email": "ada@acme.com", "email_verified": true })).unwrap();
        assert_eq!((c.team.as_str(), domain.as_deref()), ("T0ACME", Some("acme.com")));
        assert_eq!(slack(json!({ "https://slack.com/team_id": "T0ACME", "email": "ada@acme.com" })).unwrap().1, None);
        assert_eq!(
            slack(json!({ "https://slack.com/team_id": "T0ACME", "email": "ada@gmail.com", "email_verified": true })).unwrap().1,
            None
        );
        assert_eq!(slack(json!({ "email": "ada@acme.com", "email_verified": true })).unwrap_err(), Problem::NotInOrg);
    }

    #[test]
    fn microsofts_organizations_discovery_names_a_template() {
        let cfg = shared_apps();
        let target = setup_target(&cfg, Provider::Microsoft).unwrap();
        let doc = |issuer: &str| HttpReply {
            status: 200,
            body: json!({
                "issuer": issuer,
                "authorization_endpoint": "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize",
                "token_endpoint": "https://login.microsoftonline.com/organizations/oauth2/v2.0/token",
            })
            .to_string(),
        };
        assert!(read_discovery(&target, &doc(MICROSOFT_ISSUER_TEMPLATE)).is_ok());
        assert!(read_discovery(&target, &doc(MICROSOFT_ORGANIZATIONS)).is_err());
        // Only setting up accepts the template: a directory's own settings need its own issuer.
        let tenant = Config { issuer: microsoft_issuer("72f988bf-86f1-41af-91ab-2d7cd011db47"), ..target };
        assert!(read_discovery(&tenant, &doc(MICROSOFT_ISSUER_TEMPLATE)).is_err());
    }

    #[test]
    fn provider_refusals_are_codes() {
        assert_eq!(provider_refused("access_denied", "AADSTS65004: User declined to consent"), Problem::Denied);
        assert_eq!(provider_refused("access_denied", "AADSTS90094: Admin consent is required"), Problem::AdminConsent);
        assert_eq!(provider_refused("invalid_request", "AADSTS90095: needs approval"), Problem::AdminConsent);
        assert_eq!(provider_refused("consent_required", ""), Problem::AdminConsent);
        assert_eq!(provider_refused("server_error", ""), Problem::ProviderError);
    }
}
