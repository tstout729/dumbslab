//! Single sign-on: admins set the workspace up to sign in with its identity provider, and people
//! link their accounts there. The flow itself lives in [`crate::sso`].

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{DONE, Done, NoInput, clean};
use crate::connect::{self, Deferred, Job};
use crate::db::DbExt;
use crate::error::{ApiError, ApiResult};
use crate::events::{Event, emit};
use crate::model::{UserRef, find_user, user_ref, user_refs};
use crate::registry::{Access, Ctx, Op, op};
use crate::sso::{self, Provider, SsoJob, SsoSettings};
use crate::{Effect, params};

pub fn ops() -> Vec<Op> {
    vec![
        op("sso", "get_sso", "GET", "/sso", Access::Admin, get_sso)
            .title("Single sign-on settings")
            .desc("How people sign in with the workspace's identity provider (Google Workspace, Microsoft Entra ID, Okta, OneLogin, Slack or any OpenID Connect provider), and the `redirect_uri` to register in the provider's app. The client secret is never shown.")
            .build(),
        op("sso", "update_sso", "PATCH", "/sso", Access::Admin, update_sso)
            .title("Set up single sign-on")
            .desc("Set up signing in with the workspace's identity provider. Register an OpenID Connect app (web, authorization code) with the provider, with the `redirect_uri` from get_sso, then give its `client_id` and `client_secret`. `provider` fills in the issuer for `google` and `slack`; `microsoft` takes the directory `tenant` ID; `okta`, `onelogin` and `oidc` take the `issuer` URL. A first sign-in joins an existing account only when the provider says the email is verified and its domain is in `allowed_domains`; `auto_provision` adds such people as members when nobody has their email yet. `require_sso` stops non-admins signing in with a password (admins keep theirs, in case the provider fails). Each save checks the provider's discovery document and answers with the result in `check`. Changing `provider` or `client_id` forgets the saved client secret.")
            .build(),
        op("sso", "list_sso_identities", "GET", "/sso/identities", Access::Read, list_identities)
            .title("Linked sign-in accounts")
            .desc("The accounts at the identity provider linked to people here, which they sign in with. Yours by default; admins can pass `user`, or `all`.")
            .build(),
        op("sso", "link_sso", "POST", "/me/sso", Access::Write, link_sso)
            .title("Link your sign-in account")
            .desc("Starts linking your account at the workspace's identity provider to yours here, so you can sign in with it even when the provider doesn't vouch for your email address. Answers with an `authorize_url` to open in the same browser; you come back to Settings › Profile. Only from a signed-in browser.")
            .build(),
        op("sso", "unlink_sso", "DELETE", "/sso/identities/{id}", Access::Write, unlink_sso)
            .title("Unlink a sign-in account")
            .desc("Unlink an account at the identity provider (yours; admins: anyone's). It can't sign in here until it's linked again, or matched by a verified email on its next sign-in.")
            .destructive()
            .build(),
    ]
}

fn get_sso(ctx: &mut Ctx, _: NoInput) -> ApiResult<SsoSettings> {
    sso::settings_view(ctx.db, ctx.cfg, &ctx.base_url, None)
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateSsoInput {
    /// `google`, `microsoft`, `okta`, `onelogin`, `slack` or `oidc` (any other OpenID Connect provider).
    pub provider: Option<Provider>,
    /// Okta, OneLogin and `oidc`: the issuer URL exactly as the provider's discovery document gives it, e.g. `https://acme.okta.com` or `https://acme.onelogin.com/oidc/2`.
    pub issuer: Option<String>,
    /// Microsoft: the directory (tenant) ID, a GUID from Microsoft Entra admin center › Overview.
    pub tenant: Option<String>,
    /// Slack, optional: only people in this Slack workspace (its team ID, `T…`) may sign in. Empty to allow any.
    pub team: Option<String>,
    /// The client (application) ID of the app registered with the provider.
    pub client_id: Option<String>,
    /// The app's client secret. Stored encrypted and never shown again. Empty to remove it.
    pub client_secret: Option<String>,
    /// Email domains, e.g. `["acme.com"]`. Verified addresses at these may sign in to existing accounts (and join, with `auto_provision`). Google: only accounts whose hosted domain is one of these may sign in at all.
    pub allowed_domains: Option<Vec<String>>,
    /// Add people the provider vouches for, from `allowed_domains`, as members when nobody here has their email. Off by default.
    pub auto_provision: Option<bool>,
    /// Only admins may sign in with a password; everyone else signs in with the provider. API tokens and MCP connections keep working.
    pub require_sso: Option<bool>,
    /// Show "Sign in with …" on the sign-in page. Needs the provider, client ID and secret set up.
    pub enabled: Option<bool>,
    /// `oidc`: the name on the button, e.g. `Acme SSO` for "Sign in with Acme SSO".
    pub label: Option<String>,
}

fn update_sso(ctx: &mut Ctx, input: UpdateSsoInput) -> ApiResult<Deferred<SsoSettings>> {
    let mut conf = sso::load(ctx.db)?;
    let mut secret_changed = false;
    if let Some(p) = input.provider
        && conf.provider != Some(p)
    {
        // Another provider means another app: nothing of the old one carries over.
        conf.provider = Some(p);
        conf.issuer = p.fixed_issuer().unwrap_or_default().to_string();
        conf.tenant.clear();
        conf.team.clear();
        conf.client_id.clear();
        secret_changed |= conf.client_secret.take().is_some();
    }
    let provider = conf.provider;
    let name = provider.map(Provider::name).unwrap_or("the provider");
    if let Some(issuer) = input.issuer {
        let issuer = issuer.trim().to_string();
        match provider {
            None => return Err(ApiError::bad_request("choose a `provider` first")),
            Some(Provider::Microsoft) => return Err(ApiError::bad_request("Microsoft's issuer comes from `tenant`; set that instead")),
            Some(p) if p.fixed_issuer().is_some() => {
                if issuer != conf.issuer {
                    return Err(ApiError::bad_request(format!("{name}'s issuer is always {}; leave out `issuer`", conf.issuer)));
                }
            }
            Some(_) => {
                if !sso::valid_issuer(&issuer) {
                    return Err(ApiError::bad_request("`issuer` must be an https URL without a query, e.g. https://acme.okta.com"));
                }
                conf.issuer = issuer;
            }
        }
    }
    if let Some(tenant) = input.tenant {
        if provider != Some(Provider::Microsoft) {
            return Err(ApiError::bad_request("`tenant` is for Microsoft Entra ID only"));
        }
        let tenant = sso::normalize_tenant(&tenant).ok_or_else(|| {
            ApiError::bad_request("`tenant` is the directory (tenant) ID, a GUID such as 72f988bf-86f1-41af-91ab-2d7cd011db47 (Microsoft Entra admin center › Overview). Shared endpoints like `common` and `organizations` aren't allowed.")
        })?;
        conf.issuer = sso::microsoft_issuer(&tenant);
        conf.tenant = tenant;
    }
    if let Some(team) = input.team {
        let team = team.trim().to_ascii_uppercase();
        if !team.is_empty() && provider != Some(Provider::Slack) {
            return Err(ApiError::bad_request("`team` is for Slack only"));
        }
        if !team.is_empty() && !(team.starts_with('T') && team.len() <= 30 && team.chars().all(|c| c.is_ascii_alphanumeric())) {
            return Err(ApiError::bad_request("`team` is a Slack workspace ID like T0123ABCD"));
        }
        conf.team = team;
    }
    if let Some(id) = input.client_id {
        let id = id.trim().to_string();
        if id.len() > 500 || id.contains(char::is_whitespace) {
            return Err(ApiError::bad_request("`client_id` is too long or has spaces"));
        }
        if id != conf.client_id {
            // A secret belongs to its app.
            secret_changed |= conf.client_secret.take().is_some();
        }
        conf.client_id = id;
    }
    if let Some(secret) = input.client_secret {
        let secret = secret.trim();
        if secret.is_empty() {
            conf.client_secret = None;
        } else {
            if secret.len() > 2000 {
                return Err(ApiError::bad_request("`client_secret` is too long"));
            }
            conf.client_secret = Some(sso::seal_secret(ctx.cfg, secret)?);
        }
        secret_changed = true;
    }
    if let Some(domains) = input.allowed_domains {
        if domains.len() > 50 {
            return Err(ApiError::bad_request("list at most 50 domains"));
        }
        let mut out: Vec<String> = vec![];
        for d in domains.iter().filter(|d| !d.trim().is_empty()) {
            let n =
                sso::normalize_domain(d).ok_or_else(|| ApiError::bad_request(format!("`{}` isn't a domain like acme.com", d.trim())))?;
            if !out.contains(&n) {
                out.push(n);
            }
        }
        conf.allowed_domains = out;
    }
    if let Some(label) = input.label {
        let label = label.trim().to_string();
        if label.chars().count() > 40 {
            return Err(ApiError::bad_request("`label` is longer than 40 characters"));
        }
        conf.label = label;
    }
    if let Some(b) = input.auto_provision {
        conf.auto_provision = b;
    }
    if let Some(b) = input.require_sso {
        conf.require_sso = b;
    }
    if let Some(b) = input.enabled {
        conf.enabled = b;
    }
    if conf.enabled {
        if !connect::enabled(ctx.cfg) {
            return Err(sso::off());
        }
        let mut missing = vec![];
        if provider.is_none() {
            missing.push("`provider`");
        }
        match provider {
            Some(Provider::Microsoft) if conf.tenant.is_empty() => missing.push("`tenant`"),
            Some(Provider::Okta | Provider::Onelogin | Provider::Oidc) if conf.issuer.is_empty() => missing.push("`issuer`"),
            Some(Provider::Google) if conf.allowed_domains.is_empty() => missing.push("`allowed_domains` (your Google Workspace domains)"),
            _ => {}
        }
        if conf.client_id.is_empty() {
            missing.push("`client_id`");
        }
        if conf.client_secret.is_none() {
            missing.push("`client_secret`");
        } else if sso::secret_unreadable(ctx.cfg, &conf) {
            missing.push("`client_secret` again (the saved one can't be read since the server's connector key changed)");
        }
        if !missing.is_empty() {
            return Err(ApiError::bad_request(format!("to turn single sign-on on, also set {}", missing.join(", "))));
        }
    }
    sso::save(ctx.db, &conf)?;
    let data = json!({
        "provider": conf.provider.map(Provider::as_str),
        "enabled": conf.enabled,
        "require_sso": conf.require_sso,
        "auto_provision": conf.auto_provision,
        "client_secret_changed": secret_changed,
    });
    emit(ctx, Event::new("sso.updated", "settings", "sso", "updated single sign-on").data(data).admin_only())?;
    // Check the provider's discovery document; the host fills in the result.
    if !conf.issuer.is_empty() {
        ctx.effects.push(Effect::Connect(Job::Sso(SsoJob::check(&ctx.base_url))));
        return Ok(Deferred::Pending);
    }
    Ok(Deferred::Ready(sso::settings_view(ctx.db, ctx.cfg, &ctx.base_url, None)?))
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct LinkStart {
    /// Open this in the same browser to sign in with the provider. Afterwards you land on Settings › Profile.
    pub authorize_url: String,
}

fn link_sso(ctx: &mut Ctx, _: NoInput) -> ApiResult<Deferred<LinkStart>> {
    // The provider sends the person back to their browser, which must still be signed in to this
    // same session to finish.
    let Some(session_hash) = ctx.actor.session_hash.clone() else {
        return Err(ApiError::forbidden("link your sign-in account in the web app, under Settings › Profile"));
    };
    if !sso::active(ctx.cfg, &sso::load(ctx.db)?) {
        return Err(ApiError::bad_request("single sign-on isn't set up for this workspace"));
    }
    ctx.effects.push(Effect::Connect(Job::Sso(SsoJob::link(&ctx.base_url, &ctx.actor.user_id, &session_hash))));
    Ok(Deferred::Pending)
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListIdentitiesInput {
    /// Admins only: another person (id, @handle or email), or `all`. Default: you.
    pub user: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SsoIdentity {
    pub id: String,
    pub user: UserRef,
    /// The provider's issuer.
    pub issuer: String,
    /// The address the provider gave when it was linked.
    pub email: String,
    /// At the issuer the workspace signs in with now.
    pub current: bool,
    pub linked_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SsoIdentityList {
    pub items: Vec<SsoIdentity>,
}

fn list_identities(ctx: &mut Ctx, input: ListIdentitiesInput) -> ApiResult<SsoIdentityList> {
    let rows = match clean(input.user).as_deref() {
        None | Some("me") => {
            ctx.db.query("SELECT * FROM sso_identities WHERE user_id = ? ORDER BY created_at", &params![ctx.actor.user_id.clone()])?
        }
        Some("all") => {
            ctx.actor.require_admin()?;
            ctx.db.query("SELECT * FROM sso_identities ORDER BY created_at", &[])?
        }
        Some(other) => {
            ctx.actor.require_admin()?;
            let id = find_user(ctx, other)?.str("id");
            ctx.db.query("SELECT * FROM sso_identities WHERE user_id = ? ORDER BY created_at", &params![id])?
        }
    };
    let issuer = sso::load(ctx.db)?.issuer;
    let users = user_refs(ctx.db, &rows.iter().map(|r| r.str("user_id")).collect::<Vec<_>>())?;
    Ok(SsoIdentityList {
        items: rows
            .iter()
            .map(|r| SsoIdentity {
                id: r.str("id"),
                user: user_ref(&users, &r.str("user_id")),
                current: r.str("issuer") == issuer,
                issuer: r.str("issuer"),
                email: r.str("email"),
                linked_at: r.str("created_at"),
                last_used_at: r.opt_str("last_used_at"),
            })
            .collect(),
    })
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityIdInput {
    pub id: String,
}

fn unlink_sso(ctx: &mut Ctx, input: IdentityIdInput) -> ApiResult<Done> {
    let row = ctx
        .db
        .one("SELECT user_id FROM sso_identities WHERE id = ?", &params![input.id.clone()])?
        .ok_or_else(|| ApiError::not_found("linked account"))?;
    let user_id = row.str("user_id");
    if user_id != ctx.actor.user_id {
        ctx.actor.require_admin()?;
    }
    ctx.db.execute("DELETE FROM sso_identities WHERE id = ?", &params![input.id.clone()])?;
    let who = user_refs(ctx.db, std::slice::from_ref(&user_id))?;
    let summary = format!("unlinked {}'s sign-in account", user_ref(&who, &user_id).name);
    emit(ctx, Event::new("sso.unlinked", "user", &user_id, summary).admin_only())?;
    Ok(DONE)
}
