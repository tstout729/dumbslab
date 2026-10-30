//! Plans for hosted workspaces, such as those on dumbslab.com. Every feature is on every plan; the
//! plans differ only in what costs money to run: how much a workspace stores, and how many
//! database rows it writes in 24 hours. A self-hosted server has no plan and no limits.
//!
//! - [`Plans`] holds the host's allowances. [`current`] reads a workspace's plan: Pro while its
//!   Stripe subscription is in good standing or the operator granted it, free otherwise.
//! - The write meter counts the rows each request wrote, per hour ([`record_writes`]), and sums
//!   the last 24 hours ([`writes_24h`]). Once a workspace has used its allowance, or the free plan
//!   is at capacity, operations that change things are refused ([`check_write`]); reading and
//!   signing in keep working. The host enforces the storage allowance itself, because only it
//!   can measure the database.
//! - Pro is bought through Stripe Checkout and managed in Stripe's customer portal. The plan
//!   operations hand the host a [`StripeCall`]; Stripe's webhooks come back through
//!   [`verify_webhook`] and [`webhook_action`], and [`apply_subscription`] records the result.

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::Hosting;
use crate::db::{Db, DbExt};
use crate::error::{ApiError, ApiResult};
use crate::ops::admin::{put_setting, setting};
use crate::params;
use crate::util::{hmac_sha256_hex, secure_eq, sha256_hex};

/// The Stripe API version of every call DumbSlab makes, and of its webhook endpoint.
pub const STRIPE_API_VERSION: &str = "2026-09-30.endive";
/// Tags DumbSlab's Checkout sessions in the Stripe Dashboard.
const INTEGRATION_ID: &str = "dumbslab_pro_qhxtmzkw";
/// How old a webhook signature may be.
const WEBHOOK_TOLERANCE_SECS: i64 = 300;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Plan {
    Free,
    Pro,
}

impl Plan {
    pub fn as_str(self) -> &'static str {
        match self {
            Plan::Free => "free",
            Plan::Pro => "pro",
        }
    }
}

/// What a plan includes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
pub struct Allowance {
    /// The most the workspace may store, uploaded files included, in bytes.
    pub storage_bytes: u64,
    /// Database rows the workspace may write in any 24 hours. An edit writes about 10, a new post about 20.
    pub writes_per_day: u64,
}

/// The plans a host offers.
#[derive(Clone, Debug)]
pub struct Plans {
    pub free: Allowance,
    pub pro: Allowance,
    /// The Stripe price for Pro. Without one, Pro can't be bought on this server.
    pub stripe_price: Option<String>,
    /// How Pro's price reads, e.g. `$8 a month`.
    pub price_label: String,
    /// The Stripe customer portal configuration to use (`bpc_…`); Stripe's default when unset.
    pub portal_configuration: Option<String>,
}

impl Plans {
    pub fn allowance(&self, plan: Plan) -> Allowance {
        match plan {
            Plan::Free => self.free,
            Plan::Pro => self.pro,
        }
    }

    fn for_sale(&self) -> bool {
        self.stripe_price.is_some()
    }
}

/// A workspace's Stripe subscription, as last reported by Stripe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub customer: String,
    /// Stripe's status: `active`, `trialing`, `past_due`, `unpaid`, `canceled`, `incomplete`,
    /// `incomplete_expired` or `paused`.
    pub status: String,
    /// When the current period ends (Unix seconds): the next renewal, or when a cancelled
    /// subscription stops.
    pub period_end: Option<i64>,
    /// The subscription stops at `period_end` instead of renewing.
    pub cancel_at_period_end: bool,
    /// The [`billing_id`] of the workspace whose Checkout created it (its `billing_id` metadata).
    #[serde(default)]
    pub billing_id: Option<String>,
}

impl Subscription {
    /// Reads a Stripe subscription object. Billing periods live on its items.
    pub fn from_stripe(v: &Value) -> Option<Subscription> {
        let item_end = v["items"]["data"].as_array().and_then(|items| items.iter().filter_map(|i| i["current_period_end"].as_i64()).max());
        let cancel_at = v["cancel_at"].as_i64();
        Some(Subscription {
            id: v["id"].as_str()?.to_string(),
            customer: object_id(&v["customer"])?,
            status: v["status"].as_str()?.to_string(),
            period_end: cancel_at.or(item_end).or_else(|| v["current_period_end"].as_i64()),
            cancel_at_period_end: v["cancel_at_period_end"].as_bool().unwrap_or(false) || cancel_at.is_some(),
            billing_id: v["metadata"]["billing_id"].as_str().map(str::to_string),
        })
    }

    /// Pro stays on while Stripe retries a failed renewal (`past_due`).
    pub fn in_good_standing(&self) -> bool {
        matches!(self.status.as_str(), "active" | "trialing" | "past_due")
    }
}

/// A Stripe field that is either an id or an expanded object.
fn object_id(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Object(o) => o.get("id").and_then(Value::as_str).map(str::to_string),
        _ => None,
    }
}

/// What decides a workspace's plan.
#[derive(Clone, Debug, Default)]
pub struct PlanState {
    /// The operator granted Pro, without a subscription.
    pub granted: bool,
    pub subscription: Option<Subscription>,
}

impl PlanState {
    pub fn plan(&self) -> Plan {
        if self.granted || self.subscription.as_ref().is_some_and(Subscription::in_good_standing) { Plan::Pro } else { Plan::Free }
    }
}

pub fn current(db: &dyn Db) -> ApiResult<PlanState> {
    Ok(PlanState {
        granted: setting(db, "plan_grant")?.as_deref() == Some("pro"),
        subscription: setting(db, "plan_subscription")?.and_then(|s| serde_json::from_str(&s).ok()),
    })
}

/// This workspace's identity for billing, made the first time it starts a Checkout. Its
/// subscriptions carry it, so one bought for a deleted workspace never applies to a new workspace
/// at the same address.
pub fn billing_id(db: &dyn Db) -> ApiResult<String> {
    if let Some(id) = setting(db, "billing_id")? {
        return Ok(id);
    }
    let id = crate::util::new_secret("");
    put_setting(db, "billing_id", &id)?;
    Ok(id)
}

/// Records what Stripe reported about a subscription. Returns `false` when it was ignored: it
/// belongs to another workspace (by [`billing_id`]), or it's news about an older subscription
/// that would undo a newer one in good standing.
pub fn apply_subscription(db: &dyn Db, sub: &Subscription) -> ApiResult<bool> {
    let ours = setting(db, "billing_id")?;
    if ours.is_none() || sub.billing_id != ours {
        return Ok(false);
    }
    if let Some(cur) = current(db)?.subscription
        && cur.id != sub.id
        && cur.in_good_standing()
        && !sub.in_good_standing()
    {
        return Ok(false);
    }
    put_setting(db, "plan_subscription", &serde_json::to_string(sub).map_err(|e| ApiError::internal(e.to_string()))?)?;
    Ok(true)
}

/// The operator grants Pro (or takes the grant back). A subscription is unaffected.
pub fn set_grant(db: &dyn Db, granted: bool) -> ApiResult<()> {
    if granted {
        put_setting(db, "plan_grant", "pro")
    } else {
        db.execute("DELETE FROM settings WHERE key = 'plan_grant'", &[])?;
        Ok(())
    }
}

fn hour_of(now: DateTime<Utc>) -> i64 {
    now.timestamp().div_euclid(3600)
}

/// Adds the rows a request wrote to the current hour, and forgets hours older than a day.
pub fn record_writes(db: &dyn Db, now: DateTime<Utc>, rows: u64) -> ApiResult<()> {
    let hour = hour_of(now);
    db.execute(
        "INSERT INTO usage_hours (hour, rows_written) VALUES (?, ?)
         ON CONFLICT(hour) DO UPDATE SET rows_written = rows_written + excluded.rows_written",
        &params![hour, rows as i64],
    )?;
    db.execute("DELETE FROM usage_hours WHERE hour <= ?", &params![hour - 24])?;
    Ok(())
}

/// Rows written in the current hour and the 23 before it.
pub fn writes_24h(db: &dyn Db, now: DateTime<Utc>) -> ApiResult<u64> {
    let n = db.scalar_i64("SELECT COALESCE(SUM(rows_written), 0) FROM usage_hours WHERE hour > ?", &params![hour_of(now) - 24])?;
    Ok(n.max(0) as u64)
}

/// Whether the free plan is at capacity across the whole service. The directory works it out
/// from what every workspace reports (see `tenancy::free_capacity`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capacity {
    /// Free workspaces wrote their shared daily budget: they can't change anything for now.
    pub writes_paused: bool,
    /// Free workspaces fill their shared storage budget: they can't grow for now.
    pub growth_paused: bool,
}

/// `12,345`.
pub fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// `50 MB`, `5 GB`.
pub fn size_label(bytes: u64) -> String {
    const MB: u64 = 1024 * 1024;
    if bytes >= 1024 * MB && bytes.is_multiple_of(1024 * MB) {
        format!("{} GB", bytes / (1024 * MB))
    } else {
        format!("{} MB", bytes.div_ceil(MB))
    }
}

/// How to get more room, for limit messages.
fn more_room(plans: &Plans, plan: Plan) -> &'static str {
    match plan {
        Plan::Free if plans.for_sale() => " Upgrade to Pro in Settings › Plan for more.",
        Plan::Free => " Or export the workspace and self-host DumbSlab, which has no limits.",
        Plan::Pro => "",
    }
}

/// Refuses an operation that changes things when the workspace has used its write allowance, or
/// a free workspace while the free plan is at capacity.
pub fn check_write(db: &dyn Db, hosting: &Hosting, now: DateTime<Utc>) -> ApiResult<()> {
    let plan = current(db)?.plan();
    let allowance = hosting.plans.allowance(plan);
    let used = writes_24h(db, now)?;
    if used >= allowance.writes_per_day {
        return Err(ApiError::new(
            429,
            "write_limit",
            format!(
                "This workspace has made its {} database writes for the last 24 hours on the {} plan, so changes are paused. The allowance refills hour by hour; reading and signing in keep working.{}",
                thousands(allowance.writes_per_day),
                plan.as_str(),
                more_room(&hosting.plans, plan)
            ),
        )
        .with_details(json!({ "plan": plan, "writes_24h": used, "writes_per_day": allowance.writes_per_day })));
    }
    if plan == Plan::Free && hosting.capacity.writes_paused {
        return Err(ApiError::new(
            503,
            "free_capacity",
            format!(
                "DumbSlab's free plan is at capacity today, so free workspaces can't save changes for a few hours. Reading and signing in keep working.{}",
                more_room(&hosting.plans, plan)
            ),
        ));
    }
    Ok(())
}

/// Whether reads may do their bookkeeping writes (such as view counts): not once the workspace
/// can't change things, or can't grow.
pub fn can_write(db: &dyn Db, hosting: Option<&Hosting>, now: DateTime<Utc>) -> ApiResult<bool> {
    let Some(h) = hosting else { return Ok(true) };
    let plan = current(db)?.plan();
    if h.storage_bytes >= h.plans.allowance(plan).storage_bytes || (plan == Plan::Free && h.capacity.growth_paused) {
        return Ok(false);
    }
    match check_write(db, h, now) {
        Ok(()) => Ok(true),
        Err(e) if matches!(e.code, "write_limit" | "free_capacity") => Ok(false),
        Err(e) => Err(e),
    }
}

/// The error for a change that would take a workspace past its storage allowance. `capacity`
/// means the free plan's shared storage is full rather than this workspace's own allowance.
pub fn storage_full(plans: &Plans, plan: Plan, capacity: bool) -> ApiError {
    let message = if capacity {
        format!(
            "DumbSlab's free plan is out of storage for now, so free workspaces can't grow. Deleting and editing within the space you use keep working.{}",
            more_room(plans, plan)
        )
    } else {
        format!(
            "This workspace has reached its {} storage limit on the {} plan. Delete old posts or uploaded files to make room.{}",
            size_label(plans.allowance(plan).storage_bytes),
            plan.as_str(),
            more_room(plans, plan)
        )
    };
    ApiError::new(507, "storage_full", message)
}

/// A Stripe API call whose page is the answer. The host POSTs `form` to
/// `https://api.stripe.com/v1/{path}` and puts the `url` Stripe returns in place of
/// [`STRIPE_URL_PENDING`] in the response, whatever the transport (REST or MCP).
#[derive(Clone, Debug)]
pub struct StripeCall {
    pub path: &'static str,
    pub form: Vec<(String, String)>,
    /// Stripe's `Idempotency-Key`: the same key returns the same object instead of a new one.
    pub idempotency_key: Option<String>,
}

/// Stands in for the Stripe page's URL until the host has it.
pub const STRIPE_URL_PENDING: &str = "dumbslab:stripe-url-pending";

/// Puts Stripe's page URL into a response body in place of [`STRIPE_URL_PENDING`]. The URL goes
/// in as is, so one that would need escaping in JSON (or JSON inside a JSON string, as in MCP's
/// text content) is refused.
pub fn fill_stripe_url(body: &[u8], url: &str) -> Option<Vec<u8>> {
    if !url.starts_with("https://") || url.bytes().any(|b| b == b'"' || b == b'\\' || !(0x21..0x7f).contains(&b)) {
        return None;
    }
    let text = std::str::from_utf8(body).ok()?;
    text.contains(STRIPE_URL_PENDING).then(|| text.replace(STRIPE_URL_PENDING, url).into_bytes())
}

fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
    items.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

/// A Checkout session for one Pro subscription. `client_reference_id` names the workspace (by its
/// first address), so the webhook can link the new customer to it, and the subscription carries
/// the workspace's [`billing_id`]. Asking again within the hour returns the same session, so a
/// double click or a second tab can't start a second subscription.
pub fn checkout_call(
    price: &str,
    home: &str,
    billing_id: &str,
    base_url: &str,
    customer: Option<&str>,
    email: &str,
    now: DateTime<Utc>,
) -> StripeCall {
    let return_url = format!("{base_url}/settings/plan");
    let success_url = format!("{return_url}?checkout=done");
    let mut form = pairs(&[
        ("mode", "subscription"),
        ("line_items[0][price]", price),
        ("line_items[0][quantity]", "1"),
        ("client_reference_id", home),
        ("success_url", &success_url),
        ("cancel_url", &return_url),
        ("subscription_data[metadata][workspace]", home),
        ("subscription_data[metadata][billing_id]", billing_id),
        ("allow_promotion_codes", "true"),
        ("integration_identifier", INTEGRATION_ID),
    ]);
    match customer {
        Some(c) => form.push(("customer".into(), c.into())),
        None if crate::util::is_valid_email(email) => form.push(("customer_email".into(), email.trim().into())),
        None => {}
    }
    let request: Vec<String> = form.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let key = sha256_hex(&format!("{billing_id}|{}|{}", hour_of(now), request.join("&")));
    StripeCall { path: "checkout/sessions", form, idempotency_key: Some(format!("dumbslab-checkout-{key}")) }
}

/// A customer portal session: change the card, see invoices, cancel.
pub fn portal_call(customer: &str, base_url: &str, configuration: Option<&str>) -> StripeCall {
    let return_url = format!("{base_url}/settings/plan");
    let mut form = pairs(&[("customer", customer), ("return_url", &return_url)]);
    if let Some(c) = configuration {
        form.push(("configuration".into(), c.into()));
    }
    StripeCall { path: "billing_portal/sessions", form, idempotency_key: None }
}

/// Checks a webhook's `Stripe-Signature` header against the endpoint's signing secret and returns
/// the event. Signatures older than five minutes are refused, so a captured request can't be replayed.
pub fn verify_webhook(secret: &str, header: &str, body: &[u8], now_unix: i64) -> ApiResult<Value> {
    let bad = || ApiError::new(400, "bad_signature", "the Stripe-Signature header doesn't match this endpoint's signing secret");
    let mut timestamp = None;
    let mut signatures = vec![];
    for part in header.split(',') {
        match part.trim().split_once('=') {
            Some(("t", v)) => timestamp = v.parse::<i64>().ok(),
            Some(("v1", v)) => signatures.push(v),
            _ => {}
        }
    }
    let t = timestamp.ok_or_else(bad)?;
    if (now_unix - t).abs() > WEBHOOK_TOLERANCE_SECS {
        return Err(ApiError::new(400, "bad_signature", "the webhook signature is too old"));
    }
    let payload = std::str::from_utf8(body).map_err(|_| bad())?;
    let expected = hmac_sha256_hex(secret, &format!("{t}.{payload}"));
    if !signatures.iter().any(|s| secure_eq(s, &expected)) {
        return Err(bad());
    }
    Ok(serde_json::from_str(payload)?)
}

/// What to do about a Stripe event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WebhookAction {
    /// Checkout finished: `customer` now pays for the workspace whose first address is `home`.
    /// Then sync `subscription`.
    Link {
        home: String,
        customer: String,
        subscription: String,
    },
    /// Read the subscription from Stripe and record it on its workspace.
    Sync {
        subscription: String,
    },
    /// A charge was refunded or disputed, or Stripe warned of fraud: note it for the operator.
    /// When the event doesn't name the customer, the host looks it up from `charge`.
    Risk {
        kind: String,
        customer: Option<String>,
        charge: Option<String>,
    },
    Ignore,
}

/// Maps an event to an action. Subscription state is always read fresh from Stripe, so events
/// that arrive late, twice or out of order change nothing.
pub fn webhook_action(event: &Value) -> WebhookAction {
    let kind = event["type"].as_str().unwrap_or_default();
    let obj = &event["data"]["object"];
    match kind {
        "checkout.session.completed" | "checkout.session.async_payment_succeeded" => {
            let home = obj["client_reference_id"].as_str().filter(|h| is_address(h));
            match (obj["mode"].as_str(), home, object_id(&obj["customer"]), object_id(&obj["subscription"])) {
                (Some("subscription"), Some(home), Some(customer), Some(subscription)) => {
                    WebhookAction::Link { home: home.to_string(), customer, subscription }
                }
                _ => WebhookAction::Ignore,
            }
        }
        "customer.subscription.created" | "customer.subscription.updated" | "customer.subscription.deleted" => {
            match object_id(&obj["id"]) {
                Some(subscription) => WebhookAction::Sync { subscription },
                None => WebhookAction::Ignore,
            }
        }
        "invoice.paid" | "invoice.payment_failed" => {
            match object_id(&obj["parent"]["subscription_details"]["subscription"]).or_else(|| object_id(&obj["subscription"])) {
                Some(subscription) => WebhookAction::Sync { subscription },
                None => WebhookAction::Ignore,
            }
        }
        "charge.refunded" => {
            WebhookAction::Risk { kind: kind.to_string(), customer: object_id(&obj["customer"]), charge: object_id(&obj["id"]) }
        }
        "charge.dispute.created" | "radar.early_fraud_warning.created" => {
            WebhookAction::Risk { kind: kind.to_string(), customer: None, charge: object_id(&obj["charge"]) }
        }
        _ => WebhookAction::Ignore,
    }
}

/// An address that was valid when it was claimed, though the reserved list may have grown since.
fn is_address(s: &str) -> bool {
    (3..=32).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(50_000), "50,000");
        assert_eq!(thousands(1_234_567), "1,234,567");
        assert_eq!(size_label(50 * 1024 * 1024), "50 MB");
        assert_eq!(size_label(5 * 1024 * 1024 * 1024), "5 GB");
    }

    #[test]
    fn subscriptions_from_stripe() {
        let v = json!({
            "id": "sub_1", "customer": "cus_1", "status": "active", "cancel_at_period_end": false, "cancel_at": null,
            "items": { "data": [{ "current_period_end": 1_796_056_472 }] }, "metadata": { "billing_id": "bid_1" }
        });
        let s = Subscription::from_stripe(&v).unwrap();
        assert_eq!(s.billing_id.as_deref(), Some("bid_1"));
        assert_eq!((s.id.as_str(), s.customer.as_str(), s.period_end), ("sub_1", "cus_1", Some(1_796_056_472)));
        assert!(s.in_good_standing() && !s.cancel_at_period_end);
        // The portal cancels by setting cancel_at; Pro lasts until then.
        let v = json!({ "id": "sub_1", "customer": { "id": "cus_1" }, "status": "active", "cancel_at": 1_800_000_000, "items": { "data": [] } });
        let s = Subscription::from_stripe(&v).unwrap();
        assert_eq!((s.customer.as_str(), s.period_end, s.cancel_at_period_end), ("cus_1", Some(1_800_000_000), true));
        for (status, pro) in [("trialing", true), ("past_due", true), ("unpaid", false), ("canceled", false), ("incomplete", false)] {
            let s = Subscription::from_stripe(&json!({ "id": "s", "customer": "c", "status": status })).unwrap();
            assert_eq!(s.in_good_standing(), pro, "{status}");
        }
        assert!(Subscription::from_stripe(&json!({ "id": "s", "status": "active" })).is_none());
    }

    #[test]
    fn webhook_signatures() {
        let body = br#"{"id":"evt_1","type":"invoice.paid"}"#;
        let sig =
            |secret: &str, t: i64| format!("t={t},v1={}", hmac_sha256_hex(secret, &format!("{t}.{}", std::str::from_utf8(body).unwrap())));
        let now = 1_800_000_000;
        assert_eq!(verify_webhook("whsec_x", &sig("whsec_x", now), body, now).unwrap()["id"], "evt_1");
        // Stripe sends several v1 signatures while a secret is being rolled.
        let rolled = format!("t={now},v1=deadbeef,{}", sig("whsec_x", now).split_once(',').unwrap().1);
        assert!(verify_webhook("whsec_x", &rolled, body, now).is_ok());
        assert!(verify_webhook("whsec_other", &sig("whsec_x", now), body, now).is_err(), "wrong secret");
        assert!(verify_webhook("whsec_x", &sig("whsec_x", now - 301), body, now).is_err(), "replayed later");
        assert!(verify_webhook("whsec_x", &sig("whsec_x", now), br#"{"id":"evt_2"}"#, now).is_err(), "tampered");
        assert!(verify_webhook("whsec_x", "v1=abc", body, now).is_err(), "no timestamp");
    }

    #[test]
    fn webhook_actions() {
        let ev = |kind: &str, obj: Value| json!({ "type": kind, "data": { "object": obj } });
        let done = ev(
            "checkout.session.completed",
            json!({ "mode": "subscription", "client_reference_id": "acme", "customer": "cus_1", "subscription": "sub_1", "payment_status": "paid" }),
        );
        assert_eq!(
            webhook_action(&done),
            WebhookAction::Link { home: "acme".into(), customer: "cus_1".into(), subscription: "sub_1".into() }
        );
        let payment = ev("checkout.session.completed", json!({ "mode": "payment", "client_reference_id": "acme", "customer": "cus_1" }));
        assert_eq!(webhook_action(&payment), WebhookAction::Ignore);
        let forged = ev(
            "checkout.session.completed",
            json!({ "mode": "subscription", "client_reference_id": "../x", "customer": "c", "subscription": "s" }),
        );
        assert_eq!(webhook_action(&forged), WebhookAction::Ignore);
        assert_eq!(
            webhook_action(&ev("customer.subscription.deleted", json!({ "id": "sub_1", "status": "canceled" }))),
            WebhookAction::Sync { subscription: "sub_1".into() }
        );
        let invoice = ev("invoice.payment_failed", json!({ "parent": { "subscription_details": { "subscription": "sub_2" } } }));
        assert_eq!(webhook_action(&invoice), WebhookAction::Sync { subscription: "sub_2".into() });
        assert_eq!(
            webhook_action(&ev("charge.dispute.created", json!({ "id": "dp_1", "charge": "ch_1" }))),
            WebhookAction::Risk { kind: "charge.dispute.created".into(), customer: None, charge: Some("ch_1".into()) }
        );
        assert_eq!(webhook_action(&ev("customer.created", json!({ "id": "cus_1" }))), WebhookAction::Ignore);
    }

    #[test]
    fn stripe_urls_fill_any_envelope() {
        let url = "https://checkout.stripe.com/c/pay/cs_test_a1#fid%2Fx";
        let rest = serde_json::to_vec(&json!({ "url": STRIPE_URL_PENDING })).unwrap();
        let filled: Value = serde_json::from_slice(&fill_stripe_url(&rest, url).unwrap()).unwrap();
        assert_eq!(filled["url"], url);
        // MCP carries the result twice: as structured content and as JSON text inside a string.
        let inner = serde_json::to_string(&json!({ "url": STRIPE_URL_PENDING })).unwrap();
        let mcp = serde_json::to_vec(
            &json!({ "result": { "structuredContent": { "url": STRIPE_URL_PENDING }, "content": [{ "type": "text", "text": inner }] } }),
        )
        .unwrap();
        let filled: Value = serde_json::from_slice(&fill_stripe_url(&mcp, url).unwrap()).unwrap();
        assert_eq!(filled["result"]["structuredContent"]["url"], url);
        let text: Value = serde_json::from_str(filled["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(text["url"], url);
        assert!(fill_stripe_url(&rest, "https://x.test/\"q").is_none(), "needs escaping");
        assert!(fill_stripe_url(&rest, "javascript:alert(1)").is_none());
        assert!(fill_stripe_url(b"{}", url).is_none(), "nothing to fill");
    }

    #[test]
    fn checkout_names_the_workspace() {
        let now = Utc::now();
        let call = checkout_call("price_1", "acme", "bid_1", "https://docs.dumbslab.com", None, "ada@acme.test", now);
        let get = |k: &str| call.form.iter().find(|(key, _)| key == k).map(|(_, v)| v.as_str());
        assert_eq!(call.path, "checkout/sessions");
        assert_eq!(get("client_reference_id"), Some("acme"));
        assert_eq!(get("success_url"), Some("https://docs.dumbslab.com/settings/plan?checkout=done"));
        assert_eq!(get("customer_email"), Some("ada@acme.test"));
        assert_eq!(get("customer"), None);
        assert!(get("payment_method_types").is_none());
        assert_eq!(get("subscription_data[metadata][billing_id]"), Some("bid_1"));
        let again = checkout_call("price_1", "acme", "bid_1", "https://acme.dumbslab.com", Some("cus_1"), "ada@acme.test", now);
        assert!(again.form.contains(&("customer".into(), "cus_1".into())));
        assert!(!again.form.iter().any(|(k, _)| k == "customer_email"), "an existing customer keeps its email");
        // The same request within the hour gets the same session; another workspace's doesn't.
        let same = checkout_call("price_1", "acme", "bid_1", "https://docs.dumbslab.com", None, "ada@acme.test", now);
        assert_eq!(same.idempotency_key, call.idempotency_key);
        let other = checkout_call("price_1", "acme", "bid_2", "https://docs.dumbslab.com", None, "ada@acme.test", now);
        assert_ne!(other.idempotency_key, call.idempotency_key);
        let portal = portal_call("cus_1", "https://acme.dumbslab.com", Some("bpc_1"));
        assert!(portal.form.contains(&("configuration".into(), "bpc_1".into())));
        assert!(!portal_call("cus_1", "https://acme.dumbslab.com", None).form.iter().any(|(k, _)| k == "configuration"));
    }
}
