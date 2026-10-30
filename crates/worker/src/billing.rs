//! Plans and Stripe on hosted DumbSlab. The rules live in `dumbslab_core::plan`; this file reads
//! the plan settings from the environment, calls Stripe's API, and handles Stripe's webhooks on
//! the root domain (`POST /api/stripe/webhook`).

use chrono::Utc;
use dumbslab_core::plan::{self, Allowance, Plans, STRIPE_API_VERSION, StripeCall, Subscription, WebhookAction};
use dumbslab_core::tenancy::FreeBudget;
use serde_json::{Value, json};
use wasm_bindgen::JsValue;
use worker::*;

use crate::sql::{api_error_response, call_object, error_response, json_response, read_body, var, var_i64};

const MB: u64 = 1024 * 1024;

fn positive(env: &Env, name: &str, default: i64) -> u64 {
    var_i64(env, name, default).max(1) as u64
}

/// The plans on offer. Pro is for sale once Stripe's key, webhook secret and price are all set.
pub fn plans(env: &Env) -> Plans {
    let stripe_ready = var(env, "STRIPE_SECRET_KEY").is_some() && var(env, "STRIPE_WEBHOOK_SECRET").is_some();
    // WORKSPACE_STORAGE_MB is the old name for the free plan's storage.
    let free_mb = var_i64(env, "FREE_STORAGE_MB", var_i64(env, "WORKSPACE_STORAGE_MB", 50)).max(1) as u64;
    Plans {
        free: Allowance { storage_bytes: free_mb * MB, writes_per_day: positive(env, "FREE_WRITES_PER_DAY", 50_000) },
        pro: Allowance {
            storage_bytes: positive(env, "PRO_STORAGE_MB", 5120) * MB,
            writes_per_day: positive(env, "PRO_WRITES_PER_DAY", 200_000),
        },
        stripe_price: var(env, "STRIPE_PRICE_ID").filter(|_| stripe_ready),
        price_label: var(env, "PRO_PRICE_LABEL").unwrap_or_else(|| "$8 a month".into()),
    }
}

/// What all free workspaces together may use.
pub fn free_budget(env: &Env) -> FreeBudget {
    FreeBudget {
        writes_per_day: positive(env, "FREE_TOTAL_WRITES_PER_DAY", 1_000_000),
        storage_bytes: positive(env, "FREE_TOTAL_STORAGE_MB", 4096) * MB,
    }
}

/// `GET /api/plans` on the root domain, for the sign-up page.
pub fn offer(env: &Env) -> Result<Response> {
    let p = plans(env);
    json_response(
        200,
        &json!({ "free": p.free, "pro": { "allowance": p.pro, "price": p.price_label, "available": p.stripe_price.is_some() } }),
    )
}

fn form_body(form: &[(String, String)]) -> String {
    form.iter().map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v))).collect::<Vec<_>>().join("&")
}

/// One Stripe API call. Returns (status, body).
async fn stripe(env: &Env, method: Method, path: &str, form: &[(String, String)]) -> Result<(u16, Value)> {
    let key = var(env, "STRIPE_SECRET_KEY").ok_or_else(|| Error::RustError("STRIPE_SECRET_KEY is not set".into()))?;
    let headers = Headers::new();
    headers.set("authorization", &format!("Bearer {key}"))?;
    headers.set("stripe-version", STRIPE_API_VERSION)?;
    let mut init = RequestInit::new();
    if method == Method::Post {
        headers.set("content-type", "application/x-www-form-urlencoded")?;
        headers.set("idempotency-key", &dumbslab_core::util::new_secret("ds_"))?;
        init.with_body(Some(JsValue::from_str(&form_body(form))));
    }
    init.with_method(method).with_headers(headers);
    let mut resp = Fetch::Request(Request::new_with_init(&format!("https://api.stripe.com/v1/{path}"), &init)?).send().await?;
    let status = resp.status_code();
    Ok((status, resp.json::<Value>().await.unwrap_or(Value::Null)))
}

/// Answers `upgrade_plan` and `manage_billing`: asks Stripe for the page and replies with its URL.
pub async fn page(env: &Env, call: &StripeCall) -> Result<Response> {
    let (status, body) = stripe(env, Method::Post, call.path, &call.form).await?;
    match body["url"].as_str() {
        Some(url) if status == 200 => json_response(200, &json!({ "url": url })),
        _ => {
            console_error!("stripe {} failed: {status} {}", call.path, body["error"]["message"]);
            error_response(502, "billing_unavailable", "Stripe couldn't open that page just now. Try again in a minute.")
        }
    }
}

async fn directory(env: &Env, path: &str, body: Value) -> Result<(u16, Value)> {
    call_object(env, "DIRECTORY", "directory", Method::Post, path, Some(&body)).await
}

/// `POST /api/stripe/webhook`. Answers 500 when something failed partway, so Stripe tries again;
/// every step can safely run twice.
pub async fn webhook(mut req: Request, env: &Env) -> Result<Response> {
    let Some(secret) = var(env, "STRIPE_WEBHOOK_SECRET") else {
        return error_response(404, "not_found", "not found");
    };
    let Some(body) = read_body(&mut req).await? else {
        return error_response(413, "too_large", "request body too large");
    };
    let header = req.headers().get("stripe-signature")?.unwrap_or_default();
    let event = match plan::verify_webhook(&secret, &header, &body, Utc::now().timestamp()) {
        Ok(e) => e,
        Err(e) => return api_error_response(&e),
    };
    match handle(env, &event).await {
        Ok(()) => json_response(200, &json!({ "received": true })),
        Err(e) => {
            console_error!("stripe event {} ({}) failed: {e}", event["id"], event["type"]);
            error_response(500, "failed", "not handled yet; Stripe will retry")
        }
    }
}

async fn handle(env: &Env, event: &Value) -> Result<()> {
    match plan::webhook_action(event) {
        WebhookAction::Link { home, customer, subscription } => {
            let (status, _) = directory(env, "/billing/link", json!({ "customer": customer, "home": home })).await?;
            if status != 200 {
                return Err(Error::RustError(format!("linking {customer} to {home}: directory answered {status}")));
            }
            sync(env, &subscription).await
        }
        WebhookAction::Sync { subscription } => sync(env, &subscription).await,
        WebhookAction::Risk { kind, customer, charge } => {
            let customer = match (customer, charge) {
                (Some(c), _) => Some(c),
                (None, Some(charge)) => {
                    let (status, body) = stripe(env, Method::Get, &format!("charges/{}", urlencoding::encode(&charge)), &[]).await?;
                    if status != 200 {
                        return Err(Error::RustError(format!("reading charge {charge}: Stripe answered {status}")));
                    }
                    body["customer"].as_str().map(str::to_string)
                }
                (None, None) => None,
            };
            if let Some(customer) = customer {
                console_warn!("stripe {kind} for customer {customer}");
                directory(env, "/billing/risk", json!({ "customer": customer, "kind": kind })).await?;
            }
            Ok(())
        }
        WebhookAction::Ignore => Ok(()),
    }
}

/// Reads a subscription from Stripe and records it on its workspace and in the directory.
async fn sync(env: &Env, id: &str) -> Result<()> {
    let (status, body) = stripe(env, Method::Get, &format!("subscriptions/{}", urlencoding::encode(id)), &[]).await?;
    if status != 200 {
        return Err(Error::RustError(format!("reading subscription {id}: Stripe answered {status}")));
    }
    let sub = Subscription::from_stripe(&body).ok_or_else(|| Error::RustError(format!("subscription {id} has no customer or status")))?;
    // The customer was linked to its workspace when Checkout finished. The subscription's own
    // metadata is the fallback, for an event that arrives before that one.
    let (_, found) = directory(env, "/billing/lookup", json!({ "customer": sub.customer })).await?;
    let home = match found["home"].as_str() {
        Some(h) => h.to_string(),
        None => match body["metadata"]["workspace"].as_str() {
            Some(h) => {
                directory(env, "/billing/link", json!({ "customer": sub.customer, "home": h })).await?;
                h.to_string()
            }
            None => {
                console_warn!("subscription {id} belongs to no workspace");
                return Ok(());
            }
        },
    };
    directory(env, "/billing/subscription", json!({ "customer": sub.customer, "subscription": sub.id, "status": sub.status })).await?;
    let (status, _) = call_object(
        env,
        "WORKSPACE",
        &format!("ws:{home}"),
        Method::Post,
        "/_internal/subscription",
        Some(&json!({ "home": home, "subscription": sub })),
    )
    .await?;
    match status {
        200 => Ok(()),
        // The workspace was deleted; the directory still knows who pays.
        404 => {
            console_warn!("subscription {id} is for {home}, which no longer exists");
            Ok(())
        }
        s => Err(Error::RustError(format!("recording subscription {id} on {home}: answered {s}"))),
    }
}
