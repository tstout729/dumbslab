//! Sign in with BambooHR (OAuth 2.0), and how requests to BambooHR authenticate.
//!
//! BambooHR's developer terms (https://www.bamboohr.com/legal/developer-terms-of-service, §3.2 and
//! §3.3) allow API keys only in systems a company runs on its own infrastructure; an integration
//! hosted by someone else must sign in with BambooHR's OAuth. So hosted DumbSlab takes no API keys
//! and signs in with BambooHR. Self-hosted DumbSlab, run by the company itself, may use an API key,
//! or sign in too when its operator registered a BambooHR app.
//!
//! The host's BambooHR app is `BAMBOOHR_CLIENT_ID` and `BAMBOOHR_CLIENT_SECRET`
//! (`DUMBSLAB_BAMBOOHR_…` self-hosted), kept as the connectors' `bamboohr` app. Its redirect URI
//! is [`CALLBACK_PATH`] on the root domain when hosted (which forwards to the workspace named at
//! the start of the state, like connected apps' sign-ins), or on the server's own address. See
//! docs/hosting/bamboohr-app.md.
//!
//! BambooHR's OAuth (https://documentation.bamboohr.com/docs/getting-started): the authorize and
//! token URLs are on the company's own domain, access tokens last an hour, and `offline_access`
//! gives a refresh token. BambooHR documents no PKCE, so none is sent. The state guards the
//! callback instead: kept hashed, it works once, for 15 minutes, for the admin who started it and,
//! when they started in a browser, that browser session.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};

use super::{OWNER, PROVIDER, setup};
use crate::auth::Role;
use crate::connect::{self, Credential, HttpCall, HttpReply, OAuthApp, TokenSet, http_error};
use crate::db::{Db, DbExt, Row};
use crate::error::{ApiError, ApiResult};
use crate::registry::Ctx;
use crate::util::{parse_ts, sha256_hex, ts};
use crate::{HostConfig, Outcome, Request, Response, params};

/// Where BambooHR sends an admin back after they sign in.
pub const CALLBACK_PATH: &str = "/sync/bamboohr/callback";
/// What a sync needs: employees' names, contact and job details, and webhooks; `offline_access`
/// for a refresh token. The host's app must have these scopes in BambooHR's Developer Portal.
pub const SCOPES: &[&str] =
    &["openid", "offline_access", "employee", "employee:contact", "employee:job", "employee:name", "webhooks", "webhooks.write"];
const SIGN_IN_MINUTES: i64 = 15;
/// Tokens this close to expiring are renewed before use.
const REFRESH_MARGIN_SECS: i64 = 300;
/// How long one request may take renewing the token before another may try.
const REFRESH_LEASE_SECS: i64 = 30;

pub(crate) const RENEWING: &str = "BambooHR is renewing DumbSlab's sign-in. Try again in a moment.";
pub(crate) const CHANGED: &str = "The people sync's BambooHR sign-in changed while this was under way, so it stopped. Try again.";
const SIGNED_OUT: &str = "BambooHR no longer accepts DumbSlab's sign-in. Sign in with BambooHR again in Settings › People sync.";
pub(crate) const API_KEYS_REFUSED: &str = "Hosted DumbSlab can't use BambooHR API keys: BambooHR's developer terms allow them only in systems a company runs itself. Use Sign in with BambooHR instead (Settings › People sync, or connect_people_sync).";

/// How DumbSlab signs in to BambooHR.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Auth {
    /// An API key, as the user name of Basic authentication (self-hosted only).
    ApiKey,
    /// Sign in with BambooHR: a bearer access token, renewed with the refresh token.
    OAuth,
}

impl Auth {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Auth::ApiKey => "api_key",
            Auth::OAuth => "oauth",
        }
    }

    pub(crate) fn parse(s: &str) -> Auth {
        if s == "oauth" { Auth::OAuth } else { Auth::ApiKey }
    }
}

/// BambooHR credentials: an API key, or a sign-in's tokens. `cred.fields` also holds the
/// webhook's private key.
#[derive(Clone, Debug)]
pub(crate) struct Creds {
    pub auth: Auth,
    pub cred: Credential,
    pub expires_at: Option<DateTime<Utc>>,
}

impl Creds {
    pub(crate) fn api_key(key: String) -> Creds {
        Creds { auth: Auth::ApiKey, cred: Credential { token: key, ..Default::default() }, expires_at: None }
    }

    /// The saved people sync's credentials.
    pub(crate) fn of_row(cfg: &HostConfig, r: &Row) -> ApiResult<Creds> {
        Ok(Creds {
            auth: Auth::parse(&r.str("auth")),
            cred: crate::sync::open(cfg, OWNER, PROVIDER, &r.str("secret"))?,
            expires_at: r.opt_str("expires_at").and_then(|s| parse_ts(&s)),
        })
    }

    /// `call`, authenticated.
    pub(crate) fn call(&self, call: HttpCall) -> HttpCall {
        let call = match self.auth {
            // BambooHR takes the API key as the user name, with any password.
            Auth::ApiKey => call.basic(&self.cred.token, "x"),
            Auth::OAuth => call.bearer(&self.cred.token),
        };
        call.header("accept", "application/json").header("user-agent", "DumbSlab")
    }

    /// A sign-in whose access token expires soon, and can be renewed.
    pub(crate) fn needs_refresh(&self, now: DateTime<Utc>) -> bool {
        self.auth == Auth::OAuth
            && self.cred.refresh_token.is_some()
            && self.expires_at.is_some_and(|e| e - Duration::seconds(REFRESH_MARGIN_SECS) <= now)
    }

    /// Takes new tokens, keeping the refresh token when BambooHR sends none.
    pub(crate) fn take(&mut self, tokens: TokenSet, now: DateTime<Utc>) {
        self.auth = Auth::OAuth;
        self.cred.token = tokens.access_token;
        if tokens.refresh_token.is_some() {
            self.cred.refresh_token = tokens.refresh_token;
        }
        self.expires_at = tokens.expires_in.filter(|s| *s > 0).map(|s| now + Duration::seconds(s));
    }
}

/// Why BambooHR refused a request for employees or webhooks with these credentials (401).
pub(crate) fn rejected(auth: Auth) -> &'static str {
    match auth {
        Auth::ApiKey => "BambooHR rejected the API key. Check it was copied whole, then save it again.",
        Auth::OAuth => SIGNED_OUT,
    }
}

/// The host's BambooHR app, when it registered one.
pub(crate) fn app(cfg: &HostConfig) -> Option<&OAuthApp> {
    connect::oauth_app(cfg, PROVIDER)
}

/// Multi-tenant hosting: BambooHR's terms rule out API keys here.
pub(crate) fn hosted(cfg: &HostConfig) -> bool {
    cfg.hosting.is_some()
}

/// The redirect URI registered with BambooHR: on the root domain when hosted (connected apps'
/// callback names it), otherwise on this server's address.
pub(crate) fn redirect_uri(cfg: &HostConfig, base_url: &str) -> String {
    let root = cfg.connectors.callback_url.as_deref().and_then(|u| {
        let (scheme, rest) = u.split_once("://")?;
        Some(format!("{scheme}://{}", rest.split('/').next()?))
    });
    format!("{}{CALLBACK_PATH}", root.as_deref().unwrap_or(base_url))
}

fn token_call(app: &OAuthApp, subdomain: &str, form: &[(&str, &str)]) -> HttpCall {
    let mut all: Vec<(&str, &str)> = form.to_vec();
    all.push(("client_id", &app.client_id));
    all.push(("client_secret", &app.client_secret));
    HttpCall::post_form(format!("https://{subdomain}.bamboohr.com/token.php?request=token"), &all)
        .header("accept", "application/json")
        .header("user-agent", "DumbSlab")
}

/// Exchanges a sign-in's code for tokens.
pub(crate) fn exchange_call(app: &OAuthApp, subdomain: &str, redirect_uri: &str, code: &str) -> HttpCall {
    token_call(app, subdomain, &[("grant_type", "authorization_code"), ("code", code), ("redirect_uri", redirect_uri)])
}

fn refresh_call(app: &OAuthApp, subdomain: &str, redirect_uri: &str, refresh_token: &str) -> HttpCall {
    token_call(app, subdomain, &[("grant_type", "refresh_token"), ("refresh_token", refresh_token), ("redirect_uri", redirect_uri)])
}

/// The tokens a sign-in gave, and the company domain BambooHR says they're for.
pub(crate) fn read_exchange(reply: &HttpReply) -> Result<(TokenSet, Option<String>), String> {
    let tokens = connect::standard_token("BambooHR", reply)?;
    let company = reply.json()["companyDomain"].as_str().and_then(|d| super::valid_subdomain(d).ok());
    Ok((tokens, company))
}

/// What a request does about a sign-in that expires soon. Each answer that goes on carries the
/// credentials as stored now: another request may have renewed them since this one read them.
#[derive(Debug)]
pub(crate) enum Renewal {
    /// Renew them with this request: the lease it holds.
    Refresh(String, Creds),
    /// They still work: another request renewed them, or is renewing them.
    UseCurrent(Creds),
    /// Another request is renewing them, and they've expired.
    Wait,
    /// Not the same connection any more (new credentials or another company were saved, or the
    /// sync was removed), or the sync lost its lease: stop.
    Changed,
}

/// Lets one request at a time renew the saved sign-in of `connection`: BambooHR may hand out a new
/// refresh token each time and refuse the old one. A sync passes its lease: it renews only while it
/// still holds it. The claim names the connection, so work begun before a new connection was saved
/// can never renew, or store, another company's tokens.
pub(crate) fn renewal(db: &dyn Db, cfg: &HostConfig, connection: &str, sync_lease: Option<&str>, now: DateTime<Utc>) -> ApiResult<Renewal> {
    let same = "id = 1 AND auth = 'oauth' AND connection = ? AND (? IS NULL OR running_until = ?)";
    let current = db.one(&format!("SELECT * FROM people_sync WHERE {same}"), &params![connection, sync_lease, sync_lease])?;
    let Some(row) = current else { return Ok(Renewal::Changed) };
    let creds = Creds::of_row(cfg, &row)?;
    if !creds.needs_refresh(now) {
        return Ok(Renewal::UseCurrent(creds));
    }
    let lease = format!("{} {}", ts(now + Duration::seconds(REFRESH_LEASE_SECS)), crate::util::new_id());
    let claimed = db.execute(
        &format!("UPDATE people_sync SET refreshing_until = ? WHERE {same} AND (refreshing_until IS NULL OR refreshing_until <= ?)"),
        &params![lease.clone(), connection, sync_lease, sync_lease, ts(now)],
    )? > 0;
    Ok(match claimed {
        true => Renewal::Refresh(lease, creds),
        false if creds.expires_at.is_some_and(|e| e > now) => Renewal::UseCurrent(creds),
        false => Renewal::Wait,
    })
}

/// The request that renews `creds`, or why it can't be made.
pub(crate) fn renew_call(cfg: &HostConfig, subdomain: &str, base_url: &str, creds: &Creds) -> Result<HttpCall, String> {
    let app = app(cfg).ok_or("Sign in with BambooHR isn't set up on this server any more, so DumbSlab can't renew its sign-in.")?;
    let refresh = creds.cred.refresh_token.as_deref().ok_or(SIGNED_OUT)?;
    Ok(refresh_call(app, subdomain, &redirect_uri(cfg, base_url), refresh))
}

/// Takes the renewed tokens into `creds`, and stores them in the saved connection, keeping the rest
/// (a save may have stored a new webhook key meanwhile). Lets go of this request's lease either way.
///
/// The fence is the refresh token this renewal spent, not the lease: a renewal can outlive its
/// lease (a stalled host) while another takes over with the same refresh token and is refused. So:
/// - the same connection still holds the spent refresh token: the new tokens are its, and they're
///   stored, lease or not;
/// - another renewal advanced its tokens meanwhile: those are kept, and `creds` takes them;
/// - the connection was retired (a reconnect) or removed: `Err(CHANGED)`, and the new tokens go to
///   its cleanup record, which holds the spent refresh token (see [`super::cleanup::hand_over`]).
///
/// Other `Err`s say why BambooHR refused.
pub(crate) fn apply_refresh(
    db: &dyn Db,
    cfg: &HostConfig,
    creds: &mut Creds,
    connection: &str,
    lease: &str,
    reply: &HttpReply,
    now: DateTime<Utc>,
) -> ApiResult<Result<(), String>> {
    let tokens = match connect::standard_token("BambooHR", reply) {
        Ok(t) => t,
        Err(_) => {
            db.execute("UPDATE people_sync SET refreshing_until = NULL WHERE id = 1 AND refreshing_until = ?", &params![lease])?;
            let busy = reply.status == 0 || reply.status == 429 || reply.status >= 500;
            return Ok(Err(if busy { http_error("BambooHR", reply) } else { SIGNED_OUT.into() }));
        }
    };
    let spent = creds.cred.refresh_token.clone().unwrap_or_default();
    creds.take(tokens, now);
    let saved =
        db.one("SELECT secret, expires_at FROM people_sync WHERE id = 1 AND auth = 'oauth' AND connection = ?", &params![connection])?;
    let Some(row) = saved else {
        super::cleanup::hand_over(db, cfg, &spent, creds)?;
        return Ok(Err(CHANGED.into()));
    };
    let mut stored = crate::sync::open(cfg, OWNER, PROVIDER, &row.str("secret"))?;
    let release = "UPDATE people_sync SET refreshing_until = NULL WHERE id = 1 AND refreshing_until = ?";
    if spent.is_empty() || stored.refresh_token.as_deref() != Some(spent.as_str()) {
        // Another renewal advanced the tokens: keep its, and use them.
        db.execute(release, &params![lease])?;
        creds.cred.token = stored.token;
        creds.cred.refresh_token = stored.refresh_token;
        creds.expires_at = row.opt_str("expires_at").and_then(|s| parse_ts(&s));
        return Ok(Ok(()));
    }
    stored.token = creds.cred.token.clone();
    stored.refresh_token = creds.cred.refresh_token.clone();
    let secret = crate::sync::seal(cfg, OWNER, PROVIDER, &stored)?;
    db.execute(
        "UPDATE people_sync SET secret = ?, expires_at = ? WHERE id = 1 AND connection = ?",
        &params![secret, creds.expires_at.map(ts), connection],
    )?;
    db.execute(release, &params![lease])?;
    Ok(Ok(()))
}

/// Another request is renewing the saved sign-in now.
pub(crate) fn renewing(row: &Row, now: DateTime<Utc>) -> bool {
    row.opt_str("refreshing_until").and_then(|l| l.split(' ').next().and_then(parse_ts)).is_some_and(|until| until > now)
}

// ---------------------------------------------------------------------------
// Signing in

fn unavailable() -> ApiError {
    ApiError::new(
        503,
        "sign_in_off",
        "Sign in with BambooHR isn't set up on this server: it has no BambooHR app (docs/hosting/bamboohr-app.md).",
    )
}

/// Starts signing in with BambooHR for `subdomain`: records who asked, and returns BambooHR's
/// sign-in URL. On hosted DumbSlab the state starts with the workspace address, so the root domain
/// can send the admin back to their workspace.
pub(crate) fn start_sign_in(ctx: &Ctx, subdomain: &str) -> ApiResult<String> {
    let app = app(ctx.cfg).ok_or_else(unavailable)?;
    ctx.db.execute("DELETE FROM people_sync_sign_ins WHERE created_at < ?", &params![ts(ctx.now - Duration::minutes(SIGN_IN_MINUTES))])?;
    let random = crate::util::new_secret("");
    let state = match &ctx.cfg.workspace {
        Some(address) => format!("{address}.{random}"),
        None => random,
    };
    ctx.db.execute(
        "INSERT INTO people_sync_sign_ins (state_hash, user_id, session_hash, subdomain, created_at) VALUES (?, ?, ?, ?, ?)",
        &params![sha256_hex(&state), ctx.actor.user_id.clone(), ctx.actor.session_hash.clone(), subdomain, ctx.now_s()],
    )?;
    let scope = SCOPES.iter().map(|s| urlencoding::encode(s).into_owned()).collect::<Vec<_>>().join("+");
    let query = [
        ("request", "authorize".to_string()),
        ("response_type", "code".into()),
        ("client_id", app.client_id.clone()),
        ("redirect_uri", redirect_uri(ctx.cfg, &ctx.base_url)),
        ("state", state),
    ];
    let qs = query.iter().map(|(k, v)| format!("{k}={}", urlencoding::encode(v))).collect::<Vec<_>>().join("&");
    Ok(format!("https://{subdomain}.bamboohr.com/authorize.php?{qs}&scope={scope}"))
}

/// Settings › People sync, with how signing in went, and something to know (`old_webhook`: the
/// webhook DumbSlab had added before is still to be deleted). Only codes go in the link, never
/// text: anyone can make a link to Settings, and the page says what the code means.
pub(crate) fn settings_url(base_url: &str, outcome: Result<Option<&str>, &str>) -> String {
    match outcome {
        Ok(None) => format!("{base_url}/settings/people-sync?people_sync=connected"),
        Ok(Some(notice)) => format!("{base_url}/settings/people-sync?people_sync=connected&people_sync_notice={notice}"),
        Err(code) => format!("{base_url}/settings/people-sync?people_sync_error={code}"),
    }
}

fn query_of(raw: &str) -> BTreeMap<String, String> {
    let decode = |s: &str| urlencoding::decode(&s.replace('+', " ")).map(|c| c.into_owned()).unwrap_or_default();
    raw.split('&').filter_map(|p| p.split_once('=')).map(|(k, v)| (decode(k), decode(v))).collect()
}

/// `GET /sync/bamboohr/callback`: BambooHR sent an admin back after they signed in. The signed-in
/// admin (and browser session) must be the one who started. Answers with a job that exchanges the
/// code, checks access, adds BambooHR's webhook and saves, then sends them to Settings.
pub fn callback(db: &dyn Db, cfg: &HostConfig, req: &Request) -> Outcome {
    let base = crate::http::base_url(cfg, req);
    let redirect = |url: String| crate::http::done(Response::redirect(&url).with_header("cache-control", "no-store"));
    let back = |code: &str| redirect(settings_url(&base, Err(code)));
    let query = query_of(&req.query);
    let now = Utc::now();
    let run = || -> ApiResult<Outcome> {
        let state = query.get("state").cloned().unwrap_or_default();
        let hash = sha256_hex(&state);
        let Some(row) = db.one(
            "SELECT user_id, session_hash, subdomain, created_at FROM people_sync_sign_ins WHERE state_hash = ?",
            &params![hash.clone()],
        )?
        else {
            return Ok(back("expired_link"));
        };
        // Once only, however it ends.
        db.execute("DELETE FROM people_sync_sign_ins WHERE state_hash = ?", &params![hash])?;
        let actor = crate::auth::authenticate(db, cfg, req, now)?;
        let session_ok = |a: &crate::auth::Actor| row.opt_str("session_hash").is_none_or(|s| a.session_hash.as_deref() == Some(s.as_str()));
        let Some(actor) = actor.filter(|a| a.user_id == row.str("user_id") && session_ok(a)) else {
            return Ok(back("wrong_person"));
        };
        if actor.role != Role::Admin {
            return Ok(back("not_admin"));
        }
        let started = parse_ts(&row.str("created_at")).unwrap_or(now);
        if now - started > Duration::minutes(SIGN_IN_MINUTES) {
            return Ok(back("too_slow"));
        }
        if app(cfg).is_none() || connect::key(cfg).is_none() {
            return Ok(back("unavailable"));
        }
        let code = match (query.get("code"), query.get("error")) {
            (Some(c), _) if !c.is_empty() => c.clone(),
            (_, Some(_)) => return Ok(back("declined")),
            _ => return Ok(back("no_code")),
        };
        // A new sign-in retires the saved connection: not while a renewal of it is under way.
        let saved = db.one("SELECT refreshing_until FROM people_sync WHERE id = 1", &[])?;
        if saved.is_some_and(|r| renewing(&r, now)) {
            return Ok(back("busy"));
        }
        let Some(lease) = setup::claim_save(db, now)? else { return Ok(back("busy")) };
        let job = setup::sign_in_job(db, cfg, &base, &actor, row.str("subdomain"), code, lease)?;
        let mut out = back("failed");
        out.effects.push(crate::Effect::Connect(job));
        // Then, after the response, the webhooks still to delete, the one this replaced included.
        out.effects.push(crate::Effect::Background(super::cleanup::cleanup_job(&base, None)));
        Ok(out)
    };
    run().unwrap_or_else(|_| back("failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg_with(callback: Option<&str>) -> HostConfig {
        let mut cfg = HostConfig::default();
        cfg.connectors.callback_url = callback.map(str::to_string);
        cfg
    }

    #[test]
    fn the_redirect_uri_is_on_the_root_domain_when_hosted() {
        assert_eq!(redirect_uri(&cfg_with(None), "https://kb.test"), "https://kb.test/sync/bamboohr/callback");
        let hosted = cfg_with(Some("https://dumbslab.com/connect/callback"));
        assert_eq!(redirect_uri(&hosted, "https://acme.dumbslab.com"), "https://dumbslab.com/sync/bamboohr/callback");
        let dev = cfg_with(Some("http://localhost:8787/connect/callback"));
        assert_eq!(redirect_uri(&dev, "http://acme.localhost:8787"), "http://localhost:8787/sync/bamboohr/callback");
    }

    #[test]
    fn requests_authenticate_by_kind() {
        let key = Creds::api_key("k".into());
        assert!(key.call(HttpCall::get("https://x")).headers.contains(&("authorization".into(), "Basic azp4".into())));
        let signed_in = Creds { auth: Auth::OAuth, cred: Credential { token: "t".into(), ..Default::default() }, expires_at: None };
        assert!(signed_in.call(HttpCall::get("https://x")).headers.contains(&("authorization".into(), "Bearer t".into())));
    }

    #[test]
    fn tokens_are_renewed_shortly_before_they_expire() {
        let now = Utc::now();
        let mut c = Creds {
            auth: Auth::OAuth,
            cred: Credential { token: "t".into(), refresh_token: Some("r".into()), ..Default::default() },
            expires_at: Some(now + Duration::minutes(30)),
        };
        assert!(!c.needs_refresh(now));
        c.expires_at = Some(now + Duration::minutes(4));
        assert!(c.needs_refresh(now));
        c.cred.refresh_token = None;
        assert!(!c.needs_refresh(now), "nothing to renew with");
        assert!(!Creds::api_key("k".into()).needs_refresh(now));

        let mut c =
            Creds { auth: Auth::ApiKey, cred: Credential { refresh_token: Some("old".into()), ..Default::default() }, expires_at: None };
        c.take(TokenSet { access_token: "a".into(), refresh_token: None, expires_in: Some(3600), fields: BTreeMap::new() }, now);
        assert_eq!((c.auth, c.cred.token.as_str(), c.cred.refresh_token.as_deref()), (Auth::OAuth, "a", Some("old")));
        assert_eq!(c.expires_at, Some(now + Duration::seconds(3600)));
    }

    #[test]
    fn the_token_answer_names_the_company() {
        let reply = HttpReply {
            status: 200,
            body: json!({ "access_token": "a", "refresh_token": "r", "expires_in": 3600, "companyDomain": "Acme" }).to_string(),
        };
        let (tokens, company) = read_exchange(&reply).unwrap();
        assert_eq!((tokens.access_token.as_str(), company.as_deref()), ("a", Some("acme")));
        assert!(read_exchange(&HttpReply { status: 400, body: json!({ "error": "invalid_grant" }).to_string() }).is_err());
        let call = exchange_call(&OAuthApp { client_id: "id".into(), client_secret: "s".into() }, "acme", "https://r", "c0de");
        assert_eq!(call.url, "https://acme.bamboohr.com/token.php?request=token");
        let body = call.body.unwrap();
        for part in ["grant_type=authorization_code", "code=c0de", "redirect_uri=https%3A%2F%2Fr", "client_id=id", "client_secret=s"] {
            assert!(body.contains(part), "{body}");
        }
    }
}
