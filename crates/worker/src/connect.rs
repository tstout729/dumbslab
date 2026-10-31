//! Connected apps on Cloudflare: settings from the environment, and the HTTP the core's jobs ask
//! for (see `dumbslab_core::connect`).

use std::time::Duration;

use dumbslab_core::connect::{self, Connectors, FETCH_TIMEOUT_SECS, HttpCall, HttpReply, MAX_REPLY_BYTES};
use dumbslab_core::slack::{self, SharedApp};
use dumbslab_core::sso::SharedApps;
use futures_util::StreamExt;
use futures_util::future::{Either, select};
use wasm_bindgen::JsValue;
use worker::*;

use crate::sql::var;

/// `CONNECTOR_KEY` (secret) encrypts people's credentials; `<APP>_CLIENT_ID` and the secret
/// `<APP>_CLIENT_SECRET` (e.g. `GITHUB_CLIENT_ID`, `GOOGLE_DRIVE_CLIENT_SECRET`) let people sign in
/// to that app, and `ATLASSIAN_CLIENT_ID` with `ATLASSIAN_CLIENT_SECRET` to Jira and Confluence
/// (see [`connect::oauth_apps`]). Hosted workspaces send sign-ins back through the root domain,
/// which forwards them.
pub fn connectors(env: &Env, origin: &str, hosted: bool) -> Connectors {
    let apps = connect::oauth_apps(|name| var(env, name));
    let callback_url = if hosted { root_callback(env, origin, "/connect/callback") } else { None };
    Connectors { key: var(env, "CONNECTOR_KEY"), apps, callback_url }
}

/// Add to Slack with DumbSlab's own Slack app: the secret `SLACK_SIGNING_SECRET`, with
/// `SLACK_CLIENT_ID` and the secret `SLACK_CLIENT_SECRET` (the `slack` connected app above). Hosted
/// workspaces send admins back through the root domain, which forwards them.
pub fn slack_app(env: &Env, origin: &str, hosted: bool) -> SharedApp {
    let callback_url = if hosted { root_callback(env, origin, slack::INSTALL_CALLBACK_PATH) } else { None };
    SharedApp { signing_secret: var(env, "SLACK_SIGNING_SECRET"), callback_url }
}

/// DumbSlab's own sign-in apps for single sign-on: the vars `SSO_GOOGLE_CLIENT_ID`,
/// `SSO_MICROSOFT_CLIENT_ID` and `SLACK_CLIENT_ID`, and the secrets `SSO_GOOGLE_CLIENT_SECRET`,
/// `SSO_MICROSOFT_CLIENT_SECRET` and `SLACK_CLIENT_SECRET` (see `dumbslab_core::sso::SharedApps`).
/// Hosted workspaces send sign-ins back through the root domain's `/sso/callback`, which forwards
/// them.
pub fn sso_apps(env: &Env, origin: &str, hosted: bool) -> SharedApps {
    let mut apps = SharedApps::from_vars(|name| var(env, name));
    apps.callback_url = if hosted { root_callback(env, origin, dumbslab_core::sso::CALLBACK_PATH) } else { None };
    apps
}

/// `https://dumbslab.com{path}` for a workspace at `https://acme.dumbslab.com`.
fn root_callback(env: &Env, origin: &str, path: &str) -> Option<String> {
    let root = var(env, "ROOT_DOMAIN")?;
    let (scheme, rest) = origin.split_once("://")?;
    let port = rest.rsplit_once(':').map(|(_, p)| format!(":{p}")).unwrap_or_default();
    Some(format!("{scheme}://{root}{port}{path}"))
}

/// Sends one request a workspace's job asked for. Calls to the directory (`slack::DIRECTORY`: Add
/// to Slack records, lets go of, asks about and gets the token of its Slack workspace) go to the
/// `Directory` object, for this workspace only: the home is this object's, whatever the call says.
/// Only those routes: the root domain's own (`/slack/row`, `/slack/lookup`) are never a
/// workspace's. Everything else is [`send`].
pub async fn send_for(env: &Env, home: Option<&str>, call: &HttpCall) -> HttpReply {
    let Some(path) = call.url.strip_prefix(slack::DIRECTORY) else { return send(call).await };
    let (Some(home), "/slack/install" | "/slack/release" | "/slack/token" | "/slack/status" | "/slack/forget") = (home, path) else {
        return HttpReply::default();
    };
    let mut body: serde_json::Value = call.body.as_deref().and_then(|b| serde_json::from_str(b).ok()).unwrap_or_default();
    if !body.is_object() {
        return HttpReply::default();
    }
    body["home"] = serde_json::Value::from(home);
    directory(env, path, &body).await
}

/// The root domain's own calls to the directory: an installation's token to check, and forgetting
/// a dead one (see `slack::UninstallCheck`). They name no workspace.
pub async fn send_for_root(env: &Env, call: &HttpCall) -> HttpReply {
    let Some(path) = call.url.strip_prefix(slack::DIRECTORY) else { return send(call).await };
    if !matches!(path, "/slack/row" | "/slack/forget") {
        return HttpReply::default();
    }
    let mut body: serde_json::Value = call.body.as_deref().and_then(|b| serde_json::from_str(b).ok()).unwrap_or_default();
    if let Some(fields) = body.as_object_mut() {
        fields.remove("home");
    }
    directory(env, path, &body).await
}

async fn directory(env: &Env, path: &str, body: &serde_json::Value) -> HttpReply {
    match crate::sql::call_object(env, "DIRECTORY", "directory", Method::Post, path, Some(body)).await {
        Ok((status, reply)) => HttpReply { status, body: reply.to_string() },
        Err(e) => {
            console_warn!("the directory didn't answer: {e}");
            HttpReply::default()
        }
    }
}

/// Sends one request a job asked for: https only, no redirects, at most
/// [`FETCH_TIMEOUT_SECS`] and [`MAX_REPLY_BYTES`]. Failures answer status 0.
pub async fn send(call: &HttpCall) -> HttpReply {
    if !call.url.starts_with("https://") {
        return HttpReply::default();
    }
    let attempt = async {
        let headers = Headers::new();
        for (k, v) in &call.headers {
            headers.set(k, v)?;
        }
        let mut init = RequestInit::new();
        init.with_method(Method::from(call.method.to_string())).with_headers(headers).with_redirect(RequestRedirect::Manual);
        if let Some(body) = &call.body {
            init.with_body(Some(JsValue::from_str(body)));
        }
        let mut resp = Fetch::Request(Request::new_with_init(&call.url, &init)?).send().await?;
        let status = resp.status_code();
        let mut body = Vec::new();
        // Read piece by piece and stop at the limit: an app (a self-managed GitLab, say) could send
        // far more than a Worker's memory holds.
        if let Ok(mut stream) = resp.stream() {
            while let Some(chunk) = stream.next().await {
                body.extend_from_slice(&chunk?);
                if body.len() > MAX_REPLY_BYTES {
                    body.truncate(MAX_REPLY_BYTES);
                    break;
                }
            }
        }
        Ok::<_, worker::Error>(HttpReply { status, body: String::from_utf8_lossy(&body).into_owned() })
    };
    let timeout = Delay::from(Duration::from_secs(FETCH_TIMEOUT_SECS));
    futures_util::pin_mut!(attempt, timeout);
    match select(attempt, timeout).await {
        Either::Left((Ok(reply), _)) => reply,
        Either::Left((Err(e), _)) => {
            console_warn!("request to a connected app failed: {e}");
            HttpReply::default()
        }
        Either::Right(_) => HttpReply::default(),
    }
}

/// `GET {path}` on the root domain (`/connect/callback`, `/sso/callback`, `/slack/install/callback`):
/// an app sent someone back after they signed in. The `state` starts with their workspace's
/// address; send them on to the same path at the workspace, which checks it.
pub fn root_callback_redirect(url: &Url, root: &str, path: &str) -> Result<Response> {
    let query = url.query().unwrap_or_default();
    let state = url.query_pairs().find(|(k, _)| k == "state").map(|(_, v)| v.into_owned()).unwrap_or_default();
    let address = state.split_once('.').map(|(a, _)| a).unwrap_or_default();
    if dumbslab_core::tenancy::validate_slug(address).is_err() {
        return crate::sql::error_response(
            400,
            "bad_request",
            "That sign-in link doesn't name a workspace. Start again from your workspace.",
        );
    }
    let port = url.port().map(|p| format!(":{p}")).unwrap_or_default();
    let target = Url::parse(&format!("{}://{address}.{root}{port}{path}?{query}", url.scheme()))?;
    // Built with all its headers: a `Response::redirect`'s headers can't be changed afterwards.
    let headers = Headers::new();
    headers.set("location", target.as_str())?;
    headers.set("cache-control", "no-store")?;
    headers.set("referrer-policy", "no-referrer")?;
    Ok(Response::empty()?.with_status(302).with_headers(headers))
}
