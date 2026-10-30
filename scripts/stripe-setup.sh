#!/usr/bin/env bash
# Sets up DumbSlab Pro in the Stripe account that STRIPE_API_KEY belongs to: the product and its
# monthly price, the customer portal and the webhook endpoint. Safe to run again: it reuses what
# already exists.
#
#   STRIPE_API_KEY=rk_live_... scripts/stripe-setup.sh https://dumbslab.com [monthly price in cents]
#   STRIPE_API_KEY=sk_test_... scripts/stripe-setup.sh local    # no webhook endpoint; use `stripe listen`
#
# It prints the values to configure. The webhook signing secret is shown only when the endpoint is
# created; put it straight into `npx wrangler secret put STRIPE_WEBHOOK_SECRET`.
set -euo pipefail

BASE_URL="${1:?usage: STRIPE_API_KEY=... $0 https://your-domain [price-in-cents]}"
AMOUNT="${2:-800}"
API_VERSION="2026-09-30.endive"
LOOKUP_KEY="dumbslab_pro_monthly"
: "${STRIPE_API_KEY:?set STRIPE_API_KEY to a secret or restricted key}"

stripe_api() {
  local method="$1" path="$2"
  shift 2
  curl -sS -X "$method" "https://api.stripe.com/v1/$path" \
    -u "$STRIPE_API_KEY:" -H "Stripe-Version: $API_VERSION" "$@"
}

fail_on_error() {
  if jq -e '.error' >/dev/null <<<"$1"; then
    echo "Stripe error: $(jq -r '.error.message' <<<"$1")" >&2
    exit 1
  fi
}

# Product and price. The price's lookup key finds it on later runs.
prices=$(stripe_api GET "prices?active=true&lookup_keys[]=$LOOKUP_KEY")
fail_on_error "$prices"
price_id=$(jq -r '.data[0].id // empty' <<<"$prices")
if [[ -z "$price_id" ]]; then
  product=$(stripe_api POST products \
    -d name="DumbSlab Pro" \
    -d description="More storage and a higher daily write allowance for one DumbSlab workspace.")
  fail_on_error "$product"
  price=$(stripe_api POST prices \
    -d product="$(jq -r .id <<<"$product")" \
    -d currency=usd -d unit_amount="$AMOUNT" \
    -d "recurring[interval]=month" \
    -d lookup_key="$LOOKUP_KEY")
  fail_on_error "$price"
  price_id=$(jq -r .id <<<"$price")
fi

# Customer portal: update the card, see invoices, cancel at the end of the period.
configs=$(stripe_api GET "billing_portal/configurations?active=true&limit=100")
fail_on_error "$configs"
portal_id=$(jq -r '[.data[] | select(.metadata.app == "dumbslab")][0].id // empty' <<<"$configs")
if [[ -z "$portal_id" ]]; then
  portal=$(stripe_api POST billing_portal/configurations \
    -d "business_profile[headline]=Manage your DumbSlab Pro plan" \
    -d "features[payment_method_update][enabled]=true" \
    -d "features[invoice_history][enabled]=true" \
    -d "features[customer_update][enabled]=true" \
    -d "features[customer_update][allowed_updates][]=email" \
    -d "features[customer_update][allowed_updates][]=address" \
    -d "features[subscription_cancel][enabled]=true" \
    -d "features[subscription_cancel][mode]=at_period_end" \
    -d "metadata[app]=dumbslab")
  fail_on_error "$portal"
  portal_id=$(jq -r .id <<<"$portal")
fi

echo "STRIPE_PRICE_ID=$price_id"
echo "customer portal: $portal_id"
[[ "$BASE_URL" == local ]] && exit 0

# Webhook endpoint, subscribed only to the events DumbSlab acts on (crates/worker/src/billing.rs).
webhook_url="${BASE_URL%/}/api/stripe/webhook"
endpoints=$(stripe_api GET "webhook_endpoints?limit=100")
fail_on_error "$endpoints"
endpoint_id=$(jq -r --arg u "$webhook_url" '[.data[] | select(.url == $u)][0].id // empty' <<<"$endpoints")
webhook_secret=""
if [[ -z "$endpoint_id" ]]; then
  events=(
    checkout.session.completed
    checkout.session.async_payment_succeeded
    customer.subscription.created
    customer.subscription.updated
    customer.subscription.deleted
    invoice.paid
    invoice.payment_failed
    charge.refunded
    charge.dispute.created
    radar.early_fraud_warning.created
  )
  args=(-d url="$webhook_url" -d api_version="$API_VERSION" -d "description=DumbSlab plans")
  for e in "${events[@]}"; do args+=(-d "enabled_events[]=$e"); done
  endpoint=$(stripe_api POST webhook_endpoints "${args[@]}")
  fail_on_error "$endpoint"
  endpoint_id=$(jq -r .id <<<"$endpoint")
  webhook_secret=$(jq -r .secret <<<"$endpoint")
fi

echo "webhook endpoint: $endpoint_id ($webhook_url)"
if [[ -n "$webhook_secret" ]]; then
  echo "STRIPE_WEBHOOK_SECRET=$webhook_secret"
else
  echo "STRIPE_WEBHOOK_SECRET: the endpoint already existed; its secret is in the Stripe Dashboard (Developers › Webhooks)."
fi
