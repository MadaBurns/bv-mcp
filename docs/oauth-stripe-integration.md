# OAuth-Stripe Integration Guide

This document explains how Blackveil DNS (bv-mcp) integrates with Stripe-powered OAuth authentication from bv-web to enable paid tiers and rate-limited API access.

## Overview

Blackveil DNS offers two authentication paths:

1. **Free/Static API Key**: Anonymous (50 scans/day) or static `BV_API_KEY` (agent tier: 200 scans/day)
2. **Paid OAuth**: User purchases a plan on bv-web, authenticates via OAuth on bv-mcp, and receives developer/enterprise tier

This document focuses on **Paid OAuth** — the production flow used by customers with Stripe subscriptions.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Customer Journey                              │
├─────────────────────────────────────────────────────────────────┤
│  1. User visits bv-web                                           │
│  2. Chooses plan (MCP Developer $39/mo or MCP Enterprise $199/mo)│
│  3. Enters payment (Stripe Checkout)                             │
│  4. Stripe webhook updates bv-web subscription record            │
│  5. User clicks "Configure MCP" button                           │
│  6. Redirected to bv-mcp OAuth authorize endpoint                │
│  7. bv-mcp → bv-web service binding: validate entitlement        │
│  8. bv-web returns user tier + Stripe details                    │
│  9. bv-mcp issues OAuth JWT with tier claim                      │
│  10. User configures local MCP client with token                 │
│  11. Client calls /mcp → bv-mcp extracts tier from JWT           │
│  12. Rate limit enforced: developer (500/day) or enterprise (10k)│
└─────────────────────────────────────────────────────────────────┘
```

## Step-by-Step Flow

### 1. Stripe Subscription (bv-web)

**File**: `app/routes/api/billing/checkout.ts`

User purchases plan on bv-web. Stripe creates a subscription with:
- Product ID: `prod_MCP_Developer` or `prod_MCP_Enterprise`
- Price ID: Stored in env var `STRIPE_PRICE_MCP_DEVELOPER_MONTHLY_USD` or equivalent
- Customer ID: Stored in bv-web subscriptions table
- Subscription ID: Stored in bv-web subscriptions table
- Status: `active` or `trialing`

**Database Schema** (bv-web):

```sql
subscriptions (
  tenant_id,
  tier,                 -- 'mcp_developer' or 'mcp_enterprise'
  stripeCustomerId,     -- 'cus_...'
  stripeSubscriptionId, -- 'sub_...'
  stripePriceId,        -- 'price_...'
  status,               -- 'active', 'trialing', 'past_due', etc.
  currentPeriodEnd,     -- Unix timestamp
)
```

### 2. Stripe Webhook (bv-web)

**File**: `app/routes/api/webhooks/stripe.ts`

When subscription changes, Stripe POSTs to `https://bv-web.example.com/api/webhooks/stripe`:

```typescript
// Webhook handles events:
- 'customer.subscription.created'   → Insert subscription record
- 'customer.subscription.updated'   → Update subscription record (status, period_end)
- 'customer.subscription.deleted'   → Mark as cancelled
- 'invoice.payment_succeeded'       → Log payment
```

The webhook updates the subscriptions table so OAuth can query current status.

### 3. OAuth Authorize Redirect (bv-mcp)

**File**: `src/oauth/authorize.ts`

User clicks "Configure MCP" on bv-web dashboard. Browser redirected to:

```
GET https://dns-mcp.blackveilsecurity.com/oauth/authorize
  ?client_id=mcp-web
  &redirect_uri=https://bv-web.example.com/oauth/callback
  &response_type=code
  &code_challenge=...
  &state=...
```

bv-mcp OAuth handler validates:
- ✅ client_id registered
- ✅ redirect_uri matches registration
- ✅ code_challenge valid (PKCE S256)

Then:
1. User logs in via bv-web (if not already)
2. bv-web consent screen shows what OAuth is requesting
3. User approves
4. bv-web calls bv-mcp service binding to validate entitlement (next step)

### 4. Entitlement Lookup (bv-mcp → bv-web Service Binding)

**bv-mcp file**: `src/oauth/entitlements.ts` (lines 1-78)

**bv-web file**: `app/routes/api/internal/mcp-oauth-authorize.ts`

When bv-web consent succeeds, bv-web calls bv-mcp's service binding:

```typescript
const entitlement = await BV_WEB.fetch('https://internal/mcp/oauth/authorize', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    userId: 'user_123',
    tenantId: 'tenant_456',
    clientId: 'mcp-web',
    redirectUri: 'https://bv-web.example.com/oauth/callback',
    codeChallenge: '...',
  }),
});
```

bv-web responds with:

```typescript
{
  subject: 'user_123',
  emailHash: 'sha256(user@example.com)',
  tier: 'developer',                    // ← KEY: Resolved from Stripe subscription
  stripeCustomerId: 'cus_...',
  stripeSubscriptionId: 'sub_...',
  subscriptionStatus: 'active',
  scopes: ['mcp'],
  entitlementExpiresAt: 1735689600,     // currentPeriodEnd as Unix timestamp
}
```

### 5. Tier Resolution (bv-web)

**File**: `app/lib/services/mcp/oauth-entitlements.server.ts`

Function `resolveMcpTierForSubscription()` (lines 105–125) maps subscription details to OAuth tier:

```typescript
function resolveMcpTierForSubscription(params: {
  planId: string | null;                        // 'mcp_developer', 'mcp_enterprise'
  subscriptionStatus: string | null;            // 'active', 'trialing'
  stripePriceId: string | null;                 // Price ID from subscription
  env: StripeEnvLike;                           // Environment with price env vars
}): McpOAuthTier | null {
  // Must be active or trialing
  if (!ACTIVE_SUBSCRIPTION_STATUSES.has(params.subscriptionStatus)) {
    return null;
  }

  // Check stripePriceId against env vars (source of truth for Stripe)
  if (priceMatches(params.env, params.stripePriceId, DEVELOPER_PRICE_KEYS)) {
    return 'developer';
  }
  if (priceMatches(params.env, params.stripePriceId, ENTERPRISE_PRICE_KEYS)) {
    return 'enterprise';
  }

  // Fallback: check planId
  return PLAN_TO_MCP_TIER[params.planId] ?? null;
}
```

**Mapping Table** (lines 60–66):

```typescript
const PLAN_TO_MCP_TIER: Partial<Record<PlanId, McpOAuthTier>> = {
  [PLAN_ID.PRO]: 'developer',           // Standard pro plan → developer tier
  [PLAN_ID.BUSINESS]: 'developer',      // Business plan → developer tier
  [PLAN_ID.MCP_DEVELOPER]: 'developer', // MCP Developer plan → developer tier
  [PLAN_ID.ENTERPRISE]: 'enterprise',
  [PLAN_ID.MCP_ENTERPRISE]: 'enterprise',
};
```

**Tier Ranking** (lines 77–82):

```typescript
const MCP_TIER_RANK: Record<McpOAuthTier | 'free', number> = {
  free: 0,
  agent: 1,
  developer: 2,              // 500 scans/day in bv-mcp
  enterprise: 3,             // 10,000 scans/day in bv-mcp
};
```

If user has multiple subscriptions (via different tenants), the function takes the highest-rank tier.

### 6. OAuth Token Issuance (bv-mcp)

**File**: `src/oauth/token.ts`

Once entitlement is confirmed, bv-mcp mints an access token:

```typescript
const claims = {
  iss: 'https://dns-mcp.blackveilsecurity.com',
  sub: entitlement.subject,           // user_123
  aud: 'blackveil-dns',
  tier: entitlement.tier,              // 'developer' or 'enterprise'
  emailHash: entitlement.emailHash,
  stripeCustomerId: entitlement.stripeCustomerId,
  stripeSubscriptionId: entitlement.stripeSubscriptionId,
  subscriptionStatus: entitlement.subscriptionStatus,
  scopes: entitlement.scopes,
  exp: Math.floor(Date.now() / 1000) + 3600, // 1h expiry
  iat: Math.floor(Date.now() / 1000),
  jti: crypto.randomUUID(),            // For revocation tracking
};

const token = sign(claims, OAUTH_SIGNING_SECRET, 'HS256');
```

The client receives the token and stores it locally (e.g., in `~/.blackveil/config.json`).

### 7. MCP Client Uses Token

**File**: `src/lib/tier-auth.ts` (lines 71–86)

When MCP client makes a request with the OAuth token:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

bv-mcp extracts and validates the JWT:

```typescript
function resolveAuthFromRequest(req: Request): AuthContext {
  const authHeader = req.headers.get('Authorization');
  if (authHeader?.startsWith('Bearer ')) {
    const token = authHeader.slice(7);
    try {
      const claims = verifyJWT(token, OAUTH_SIGNING_SECRET);
      // Check tier is valid
      const tier = TierSchema.safeParse(claims.tier);
      if (tier.success) {
        return { tier: tier.data, source: 'oauth_jwt' };
      }
    } catch (e) {
      // Invalid token
    }
  }
  // Fall back to static key or unauthenticated
}
```

### 8. Rate Limit Enforcement (bv-mcp)

**File**: `src/lib/config.ts` (lines 95–102)

Rate limits by tier:

```typescript
export const TIER_LIMITS = {
  free: { scans: 50, concurrent: 3 },
  agent: { scans: 200, concurrent: 5 },           // Static API key only
  developer: { scans: 500, concurrent: 10 },      // OAuth MCP Developer
  enterprise: { scans: 10000, concurrent: 25 },   // OAuth MCP Enterprise
  partner: { scans: 50000, concurrent: 100 },
  owner: { scans: Infinity, concurrent: Infinity },
};
```

**File**: `src/lib/rate-limiter.ts`

Rate limit check on every `tools/call`:

```typescript
const used = await kv.get(`rate:${userId}:${today}`);
if (used >= TIER_LIMITS[tier].scans) {
  return error(-32029, 'Rate limit exceeded');  // JSON-RPC 200 OK with error code
}
await kv.put(`rate:${userId}:${today}`, used + 1, { expirationTtl: 86400 });
```

Concurrent tool check:

```typescript
const concurrent = await kv.get(`concurrent:${userId}`);
if (concurrent >= TIER_LIMITS[tier].concurrent) {
  return error(-32029, 'Max concurrent tools exceeded');
}
```

## Tier Comparison

### OAuth Tiers (from Stripe plans)

| Tier | Source | Scans/Day | Concurrent | Entitlement |
|---|---|---|---|---|
| developer | OAuth + MCP Developer/pro/business plan | 500 | 10 | Stripe active subscription |
| enterprise | OAuth + MCP Enterprise/enterprise plan | 10,000 | 25 | Stripe active subscription |

### Static API Key Tiers

| Tier | Source | Scans/Day | Concurrent | Entitlement |
|---|---|---|---|---|
| free | Unauthenticated | 50 | 3 | Per-IP rate limit |
| agent | Static `BV_API_KEY` env var | 200 | 5 | Bearer token matching |
| partner | Static key (internal) | 50,000 | 100 | Founder partnerships |
| owner | Static key (admin-only) | Unlimited | Unlimited | Admin-only via flag |

**Note**: OAuth never returns `agent`, `partner`, or `owner` tiers. Those are for internal/admin use only.

## Error Handling

### Subscription Not Found

bv-web entitlement endpoint returns `null`:

```typescript
// bv-mcp receives 404 or null from bv-web
// Falls back to unauthenticated rate limit (50/day)
```

**User action**: Ensure Stripe subscription is active on bv-web.

### Subscription Expired or Cancelled

bv-web returns tier `null` if subscription status is not `active` or `trialing`:

```typescript
// bv-web: subscription.status === 'cancelled'
// Returns: tier = null
// bv-mcp: User falls back to free tier (50/day)
```

**User action**: Renew subscription or purchase new plan.

### Token Expired

bv-mcp JWT has 1-hour expiry. After expiry, token is rejected:

```typescript
// bv-mcp receives expired JWT
// Returns error: 'JWT expired'
// Client action: Re-authenticate via OAuth
```

**User action**: Run MCP client with `--reauth` flag or delete cached token.

### Rate Limit Exceeded

When daily scan count exceeded:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32029,
    "message": "Rate limit exceeded: 500 scans/day"
  },
  "id": 1
}
```

HTTP 200 (not 429) per MCP spec.

**User action**: Wait until next day (UTC midnight) or upgrade plan.

## Configuration

### bv-mcp Environment Variables

```bash
# OAuth enable/disable
ENABLE_OAUTH=true                        # Enable OAuth discovery (set false by default, enable after hidden probes)

# bv-web service binding
BV_WEB=<service_binding>                 # Cloudflare service binding to bv-web Worker
BV_WEB_OAUTH_CONSENT_URL="https://bv-web.example.com/oauth/mcp-consent"

# OAuth signing
OAUTH_SIGNING_SECRET="<32+ byte secret>" # HS256 secret (generated once, stored in Cloudflare Secrets)
OAUTH_ISSUER="https://dns-mcp.blackveilsecurity.com"

# Rate limit quotas
TIER_DAILY_LIMITS_DEVELOPER=500          # Scans/day for developer tier
TIER_DAILY_LIMITS_ENTERPRISE=10000       # Scans/day for enterprise tier
```

### bv-web Environment Variables

```bash
# Stripe product/price IDs (from Stripe Dashboard)
STRIPE_PRICE_MCP_DEVELOPER_MONTHLY_USD="price_..."
STRIPE_PRICE_MCP_DEVELOPER_YEARLY_USD="price_..."
STRIPE_PRICE_MCP_ENTERPRISE_MONTHLY_USD="price_..."
STRIPE_PRICE_MCP_ENTERPRISE_YEARLY_USD="price_..."

# Webhook secret (from Stripe Dashboard)
STRIPE_WEBHOOK_SECRET="whsec_..."

# OAuth redirect (where bv-web directs after consent)
BV_MCP_OAUTH_TOKEN_ENDPOINT="https://dns-mcp.blackveilsecurity.com/oauth/token"
```

## Monitoring & Troubleshooting

### Check Subscription Status

```bash
# bv-web admin panel
# → Tenants → Select tenant → Billing → Subscriptions
# Verify: status = 'active', stripePriceId matches env var
```

### Verify Entitlement Lookup

```bash
# Manual test
curl -X POST https://internal-bv-web/mcp/oauth/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "user_123",
    "tenantId": "tenant_456",
    "clientId": "mcp-web",
    "redirectUri": "https://...",
    "codeChallenge": "..."
  }'

# Expected: 200 with { subject, tier: 'developer', ... }
# Error: 404 or null if no subscription
```

### Check JWT Claims

```bash
# Decode JWT (no verification, just see contents)
echo <your_token> | jq '.[1]' | base64 -d | jq .

# Should see:
# { "sub": "user_123", "tier": "developer", "exp": 1234567890, ... }
```

### Rate Limit Status

```bash
# bv-mcp analytics
# → MCP Tiers dashboard (if available)
# Verify: developer tier accounts show ~500 scans/day quota
# Verify: enterprise tier accounts show ~10,000 scans/day quota
```

### Webhook Delays

If subscription updates are delayed (1-5 min):

1. Check Stripe webhook delivery status in Stripe Dashboard
2. Verify webhook secret matches in bv-web environment
3. Check bv-web logs: `/api/webhooks/stripe`

## FAQ

**Q: Can I use both OAuth and static API key?**

A: Yes, but they're separate rate limits. If you have an OAuth token (developer tier = 500/day) and also use a static key (agent tier = 200/day), the rates don't stack — each auth method is tracked independently.

**Q: What happens if my Stripe subscription is paused?**

A: If subscription is paused (not cancelled), status is usually `past_due` or `unpaid`. bv-web entitlement returns `tier: null`, so you fall back to free tier (50/day).

**Q: How often is subscription status checked?**

A: Every OAuth authorize request fetches latest subscription status from bv-web. JWTs issued from that check remain valid for 1 hour.

**Q: Can I revoke an OAuth token?**

A: Not yet. Tokens are valid for 1 hour. To invalidate sooner, delete the token from your MCP config and re-authenticate.

**Q: Which tier should I buy?**

A: **Developer tier** (500 scans/day): Good for most teams. **Enterprise tier** (10,000 scans/day): For large organizations scanning hundreds of domains daily.

## Related Files

- **bv-mcp**: `src/oauth/entitlements.ts` (validation), `src/lib/tier-auth.ts` (rate limiting), `CLAUDE.md` (tier overview)
- **bv-web**: `app/lib/services/mcp/oauth-entitlements.server.ts` (tier resolution), `app/routes/api/webhooks/stripe.ts` (subscription sync), `CLAUDE.md` (platform overview)
- **Stripe**: [Webhook docs](https://stripe.com/docs/webhooks), [Product setup](https://stripe.com/docs/billing/prices-up-sell)
- **OAuth 2.0**: [RFC 6749](https://tools.ietf.org/html/rfc6749) (Authorization Code), [PKCE](https://tools.ietf.org/html/rfc7636) (S256)
