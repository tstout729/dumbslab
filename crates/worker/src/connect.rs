//! Connected apps on Cloudflare: settings from the environment, and the HTTP the core's jobs ask
//! for (see `dumbslab_core::connect`).

use std::collections::BTreeMap;
use std::time::Duration;

use dumbslab_core::connect::{self, Connectors, FETCH_TIMEOUT_SECS, HttpCall, HttpReply, MAX_REPLY_BYTES, OAuthApp};
use dumbslab_core::slack::{self, SharedApp};
use futures_util::StreamExt;
use futures_util::future::{Either, select};
use wasm_bindgen::JsValue;
use worker::*;

use crate::sql::var;

/// `CONNECTOR_KEY` (secret) encrypts people's credentials; `<APP>_CLIENT_ID` and the secret
/// `<APP>_CLIENT_SECRET` (e.g. `GITHUB_CLIENT_ID`, `GOOGLE_DRIVE_CLIENT_SECRET`) let people sign in
/// to that app. Hosted workspaces send sign-ins back through the root domain, which forwards them.
pub fn connectors(env: &Env, origin: &str, hosted: bool) -> Connectors {
    let mut apps = BTreeMap::new();
    for c in connect::providers::ALL {
        let id = c.info().id;
        let name = id.to_ascii_uppercase().replace('-', "_");
        if let (Some(client_id), Some(client_secret)) = (var(env, &format!("{name}_CLIENT_ID")), var(env, &format!("{name}_CLIENT_SECRET")))
        {
            apps.insert(id.to_string(), OAuthApp { client_id, client_secret });
        }
    }
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

/// `https://dumbslab.com{path}` for a workspace at `https://acme.dumbslab.com`.
fn root_callback(env: &Env, origin: &str, path: &str) -> Option<String> {
    let root = var(env, "ROOT_DOMAIN")?;
    let (scheme, rest) = origin.split_once("://")?;
    let port = rest.rsplit_once(':').map(|(_, p)| format!(":{p}")).unwrap_or_default();
    Some(format!("{scheme}://{root}{port}{path}"))
}

/// Sends one request a workspace's job asked for. Calls to the directory (`slack::DIRECTORY`: Add
/// to Slack claims and releases its Slack workspace) go to the `Directory` object, for this
/// workspace only: the home is this object's, whatever the call says. Everything else is [`send`].
pub async fn send_for(env: &Env, home: Option<&str>, call: &HttpCall) -> HttpReply {
    let Some(path) = call.url.strip_prefix(slack::DIRECTORY) else { return send(call).await };
    let (Some(home), "/slack/claim" | "/slack/release") = (home, path) else { return HttpReply::default() };
    let mut body: serde_json::Value = call.body.as_deref().and_then(|b| serde_json::from_str(b).ok()).unwrap_or_default();
    body["home"] = serde_json::Value::from(home);
    match crate::sql::call_object(env, "DIRECTORY", "directory", Method::Post, path, Some(&body)).await {
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

/// `GET {path}` on the root domain (`/connect/callback`, `/slack/install/callback`): an app sent
/// someone back after they signed in. The `state` starts with their workspace's address; send them
/// on to the same path at the workspace, which checks it.
pub fn root_callback_redirect(url: &Url, root: &str, path: &str) -> Result<Response> {
    let query = url.query().unwrap_or_default();
    let state = url.query_pairs().find(|(k, _)| k == "state").map(|(_, v)| v.into_owned()).unwrap_or_default();
    let address = state.split_once('.').map(|(a, _)| a).unwrap_or_default();
    if dumbslab_core::tenancy::validate_slug(address).is_err() {
        return crate::sql::error_response(
            400,
            "bad_request",
            "That sign-in link doesn't name a workspace. Start connecting again from your workspace.",
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
