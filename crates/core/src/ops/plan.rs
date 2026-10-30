//! A hosted workspace's plan: what it includes, how much is used, and buying or managing Pro.
//! The rules live in [`crate::plan`].

use schemars::JsonSchema;
use serde::Serialize;

use super::NoInput;
use crate::error::{ApiError, ApiResult};
use crate::plan::{self, Allowance, Plan};
use crate::registry::{Access, Ctx, Op, op};
use crate::{Effect, Hosting};

pub fn ops() -> Vec<Op> {
    vec![
        op("plan", "get_plan", "GET", "/plan", Access::Read, get_plan)
            .title("Plan and usage")
            .desc("The workspace's plan, what it includes and how much is used: storage, and database rows written in the last 24 hours. Every feature (MCP, the API, webhooks, uploads) is on every plan; Pro raises the storage and write allowances. When the write allowance is used up, changes are refused with `write_limit` until it refills hour by hour. Self-hosted servers have no plan or limits.")
            .build(),
        op("plan", "upgrade_plan", "POST", "/plan/upgrade", Access::Admin, upgrade_plan)
            .title("Upgrade to Pro")
            .desc("Hosted workspaces only: start buying Pro. Returns a Stripe Checkout `url` for a person to open and pay; the workspace switches to Pro as soon as the payment goes through. Admins only. Works even when the write allowance is used up.")
            .unmetered()
            .build(),
        op("plan", "manage_billing", "POST", "/plan/billing", Access::Admin, manage_billing)
            .title("Manage billing")
            .desc("Hosted workspaces that have bought Pro: returns a Stripe customer portal `url` where a person can change the card, download invoices or cancel. Cancelling keeps Pro until the paid period ends. Admins only.")
            .unmetered()
            .build(),
    ]
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Usage {
    /// The workspace database's size, uploaded files included, in bytes.
    pub storage_bytes: u64,
    /// Database rows written in the last 24 hours.
    pub writes_24h: u64,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ProOffer {
    pub allowance: Allowance,
    /// e.g. `$8 a month`.
    pub price: String,
    /// Whether Pro can be bought here now, with `upgrade_plan`.
    pub available: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SubscriptionInfo {
    /// Stripe's status: `active`, `trialing`, `past_due` (a renewal failed and Stripe is retrying; Pro stays on), `unpaid`, `canceled`, `incomplete`, `incomplete_expired` or `paused`.
    pub status: String,
    /// When the current period ends (Unix seconds): the next renewal, or the day Pro stops if it was cancelled.
    pub period_end: Option<i64>,
    /// Pro stops at `period_end` instead of renewing.
    pub cancel_at_period_end: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct PlanInfo {
    /// `false` on a self-hosted server, which has no plan and no limits.
    pub hosted: bool,
    /// `free` or `pro`. Absent when self-hosted.
    pub plan: Option<Plan>,
    /// What the current plan includes.
    pub allowance: Option<Allowance>,
    pub usage: Option<Usage>,
    /// What Pro includes and costs.
    pub pro: Option<ProOffer>,
    /// The Stripe subscription, if the workspace has had one.
    pub subscription: Option<SubscriptionInfo>,
    /// Pro was given to this workspace by DumbSlab's operator, with nothing to pay.
    pub granted: bool,
}

fn hosting<'a>(ctx: &Ctx<'a>) -> ApiResult<&'a Hosting> {
    ctx.cfg.hosting.as_ref().ok_or_else(|| {
        ApiError::bad_request("only hosted workspaces (like those on dumbslab.com) have a plan; a self-hosted server has no limits")
    })
}

fn get_plan(ctx: &mut Ctx, _: NoInput) -> ApiResult<PlanInfo> {
    let Some(h) = ctx.cfg.hosting.as_ref() else {
        return Ok(PlanInfo { hosted: false, plan: None, allowance: None, usage: None, pro: None, subscription: None, granted: false });
    };
    let state = plan::current(ctx.db)?;
    let current = state.plan();
    Ok(PlanInfo {
        hosted: true,
        plan: Some(current),
        allowance: Some(h.plans.allowance(current)),
        usage: Some(Usage { storage_bytes: h.storage_bytes, writes_24h: plan::writes_24h(ctx.db, ctx.now)? }),
        pro: Some(ProOffer { allowance: h.plans.pro, price: h.plans.price_label.clone(), available: h.plans.stripe_price.is_some() }),
        subscription: state.subscription.map(|s| SubscriptionInfo {
            status: s.status,
            period_end: s.period_end,
            cancel_at_period_end: s.cancel_at_period_end,
        }),
        granted: state.granted,
    })
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct BillingLink {
    /// Stripe's page. Open it in a browser right away; the link expires.
    pub url: String,
}

fn upgrade_plan(ctx: &mut Ctx, _: NoInput) -> ApiResult<BillingLink> {
    let h = hosting(ctx)?;
    let Some(price) = h.plans.stripe_price.as_deref() else {
        return Err(ApiError::new(503, "unavailable", "Pro isn't on sale yet. Every feature is already on the free plan."));
    };
    let state = plan::current(ctx.db)?;
    if state.granted {
        return Err(ApiError::conflict("this workspace already has Pro"));
    }
    if state.subscription.as_ref().is_some_and(plan::Subscription::in_good_standing) {
        return Err(ApiError::conflict("this workspace already has Pro; change or cancel it with manage_billing"));
    }
    let customer = state.subscription.map(|s| s.customer);
    let call = plan::checkout_call(price, &h.home, &ctx.base_url, customer.as_deref(), &ctx.actor.email);
    // The host asks Stripe for the page and puts its URL in place of the placeholder.
    ctx.effects.push(Effect::Stripe(call));
    Ok(BillingLink { url: plan::STRIPE_URL_PENDING.into() })
}

fn manage_billing(ctx: &mut Ctx, _: NoInput) -> ApiResult<BillingLink> {
    hosting(ctx)?;
    let Some(sub) = plan::current(ctx.db)?.subscription else {
        return Err(ApiError::conflict("this workspace hasn't bought Pro, so there's no billing to manage; upgrade with upgrade_plan"));
    };
    ctx.effects.push(Effect::Stripe(plan::portal_call(&sub.customer, &ctx.base_url)));
    Ok(BillingLink { url: plan::STRIPE_URL_PENDING.into() })
}
