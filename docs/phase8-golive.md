# Phase 8: OAuth Full Enablement — Go-Live Package

**Status**: ✅ LIVE  
**Go-Live Date**: 2026-05-06  
**Configuration**: `ENABLE_OAUTH=true` (production)

---

## Executive Summary

Phase 8 OAuth Full Enablement is **COMPLETE and LIVE**. All OAuth endpoints are operational and integrated with the MCP DNS security scanner infrastructure.

### Key Metrics

| Metric | Value | Status |
|--------|-------|--------|
| OAuth Discovery | Responding | ✅ |
| Authorization Endpoint | HTTP 400 (expected) | ✅ |
| Token Endpoint | HTTP 415 (no body) | ✅ |
| Protected Resource Endpoint | Responding | ✅ |
| MCP Core Tools | 51 available | ✅ |
| Tier Mapping | developer/enterprise | ✅ |
| Rate Limiting | Enforced | ✅ |
| Stripe Integration | Active | ✅ |

---

## What's Live

### OAuth 2.1 Authorization Server

**Endpoints** (all responding):
- `GET /.well-known/oauth-authorization-server` — RFC 8414 discovery
- `GET /.well-known/oauth-protected-resource` — RFC 9728 protected resource discovery
- `GET /oauth/authorize?...` — Authorization endpoint (RFC 6234)
- `POST /oauth/token` — Token endpoint (RFC 6749)
- `POST /oauth/register` — Dynamic client registration (RFC 7591)

**Features**:
- PKCE support (RFC 7636)
- JWT bearer tokens (RS256)
- Stripe subscription validation
- Tier-based rate limiting
- Session management

### MCP Clients Can Now Authenticate Via OAuth

Clients can:
1. Register via `/oauth/register` to get client credentials
2. Initiate authorization via `/oauth/authorize`
3. Exchange code for access token via `/oauth/token`
4. Use token in `Authorization: Bearer <token>` header
5. Access MCP tools with subscription tier limits

### Tier System

**OAuth Tiers**:
- **Free** (default): 50 scans/day, 3 concurrent
- **Developer** ($39/mo): 500 scans/day, 10 concurrent
- **Enterprise** ($199/mo): 10,000 scans/day, 25 concurrent

**Validation Flow**:
1. Stripe subscription checked via bv-web service binding
2. Tier mapped: `MCP_DEVELOPER` → `developer` tier
3. JWT claim populated: `{ tier: 'developer' }`
4. Rate limiter enforces: 500 scans/day quota

---

## Production Configuration

### Current State

**File**: `.dev/wrangler.deploy.jsonc`  
**Setting**: `ENABLE_OAUTH = "true"`  
**Status**: Deployed to production ✅

```json
{
  "env": {
    "production": {
      "vars": {
        "ENABLE_OAUTH": "true",
        "OAUTH_ISSUER": "https://dns-mcp.blackveilsecurity.com"
      }
    }
  }
}
```

### Bindings Required

| Binding | Type | Purpose | Status |
|---------|------|---------|--------|
| `BV_API_KEY` | Secret | Owner-tier static auth | ✅ Set |
| `OAUTH_SIGNING_SECRET` | Secret | HS256 for OAuth tokens | ✅ Set |
| `OAUTH_ISSUER` | Var | Hardened against Host spoofing | ✅ Set |
| `SESSION_STORE` | KV | Cross-isolate sessions | ✅ Set |
| `RATE_LIMIT` | KV | Per-tier rate counters | ✅ Set |
| `SCAN_CACHE` | KV | 5-min result cache | ✅ Set |

All production bindings verified and operational.

---

## Monitoring Dashboard

### Key Metrics to Watch

**Real-time (dashboard.blackveilsecurity.com)**:
- OAuth registration rate (target: growing)
- Token issuance success % (target: >99%)
- Tier distribution (how many developer vs enterprise)
- Error rate (target: <1%)
- Auth success rate (target: >99%)

**Historical**:
- Daily unique OAuth users
- Average scans per tier
- Subscription plan adoption
- Support tickets (OAuth-related)

### Alert Thresholds

**Critical** (page on-call):
- OAuth token endpoint: <95% success
- Rate limiter accuracy: <99.5%
- Stripe webhook failures: >5 per hour

**Warning** (log + Slack):
- OAuth registration rate drops >50% YoY
- Error rate climbs above 0.5%
- Tier distribution skews to free tier >80%

---

## Customer Communication

### Announcement Template

**Subject**: Blackveil DNS Now Supports OAuth Authentication

Dear Blackveil DNS Customer,

We're excited to announce **OAuth 2.1 authentication** for the Blackveil DNS MCP server, enabling seamless integration with paid subscription tiers.

**What's New**:
- **OAuth Authentication**: Secure OAuth 2.1 flows with Stripe billing integration
- **Subscription Tiers**: MCP Developer ($39/mo, 500 scans/day) and MCP Enterprise ($199/mo, 10,000 scans/day)
- **MCP Client Support**: Works with all MCP clients (Claude Desktop, VS Code, Cursor, etc.)
- **Session Management**: Automatic token refresh, 2-hour session TTL

**How to Get Started**:
1. Visit blackveilsecurity.com to sign up for a paid plan
2. Register your MCP client via OAuth
3. Authenticate and start scanning with your subscription limits

**Documentation**:
- [OAuth Setup Guide](docs/oauth-stripe-integration.md)
- [Client Setup](docs/client-setup.md)
- [Pricing](https://blackveilsecurity.com/pricing)

**Support**:
- FAQ: [docs/faq.md](docs/faq.md)
- Issues: [support@blackveilsecurity.com](mailto:support@blackveilsecurity.com)

---

## Rollback Plan

### Emergency Rollback (If Critical Issues Arise)

**Step 1: Disable OAuth** (5 minutes)
```bash
# Deploy with ENABLE_OAUTH=false
wrangler deploy --env production --var ENABLE_OAUTH:false
```

**Step 2: Verify Static Keys Still Work**
```bash
curl -X POST https://dns-mcp.blackveilsecurity.com/mcp?api_key=xxx \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

**Step 3: Notify Customers**
- Post status update on status page
- Email OAuth users with rollback explanation
- Provide workaround (static API keys)

**Time to Rollback**: <5 minutes  
**Data Loss**: None (OAuth tokens simply stop being issued)  
**User Impact**: OAuth users revert to static key mode

---

## Support Runbooks

### Common Issues & Resolutions

#### 1. "OAuth endpoint not found (404)"

**Cause**: Old cached version or wrong URL  
**Resolution**:
- Verify URL: `https://dns-mcp.blackveilsecurity.com/oauth/...`
- Clear browser cache
- Check ENABLE_OAUTH=true in production config

#### 2. "Invalid client_id after registration"

**Cause**: Client ID not saved or session expired  
**Resolution**:
- Verify client registration response saved client_id
- Re-register if expired (TTL: 24 hours)
- Check bv-web integration (service binding)

#### 3. "Token validation failed (401)"

**Cause**: Signature mismatch or expired token  
**Resolution**:
- Verify OAUTH_SIGNING_SECRET unchanged
- Check token expiry (default: 1 hour)
- Refresh token via /oauth/token

#### 4. "Rate limit exceeded (429 → JSON-RPC -32029)"

**Cause**: Quota exhausted for tier  
**Resolution**:
- Check daily quota for tier (developer: 500/day)
- Upgrade to enterprise tier (10,000/day)
- Recommended: batch scans during off-peak hours

#### 5. "Subscription tier not recognized"

**Cause**: Stripe webhook delay or PLAN_ID mismatch  
**Resolution**:
- Verify plan purchased: MCP Developer or MCP Enterprise
- Check Stripe subscription status (active)
- Wait 60 seconds for webhook sync
- Contact support if persists

---

## Documentation Completeness

### Files Created/Updated

**New**:
- `docs/phase8-golive.md` (this file)
- `docs/oauth-stripe-integration.md` (Phase 6 deliverable)

**Updated**:
- `CLAUDE.md` — Added "Paid OAuth Tiers" section
- `docs/client-setup.md` — Added "Static API Key Tiers" section
- `README.md` — (Optional: add OAuth paragraph if needed)

### Links for Customers

- [OAuth Setup Guide](docs/oauth-stripe-integration.md)
- [Client Setup & Tiers](docs/client-setup.md)
- [Pricing](https://blackveilsecurity.com/pricing)
- [Support](https://support.blackveilsecurity.com)

---

## Post-Go-Live Monitoring (24-72 Hours)

### Checklist

- [ ] Monitor error rates (target <1%)
- [ ] Track auth success % (target >99%)
- [ ] Watch tier distribution adoption
- [ ] Check support ticket volume
- [ ] Validate billing sync (Stripe → tokens)
- [ ] Audit rate limiter accuracy
- [ ] Review user feedback

### Daily Report Template

**Day 1 (2026-05-07)**:
- OAuth registrations: ___ users
- Token issuance success: ___%
- Error rate: ___%
- Top issue: ___________
- Action items: ___________

**Day 2 (2026-05-08)**:
- OAuth registrations (cumulative): ___ users
- Tier distribution: Free _%, Developer _%, Enterprise _%
- Error rate: ___%
- Top issue: ___________
- Action items: ___________

**Day 3 (2026-05-09)**:
- Final go/no-go assessment
- Trends: ___________
- Recommendation: ___________

---

## Next Steps

1. **Announce** (immediate)
   - Send customer email
   - Update website (if planned)
   - Post to community forums

2. **Monitor** (continuous for 72 hours)
   - Check dashboard hourly
   - Review error logs daily
   - Track adoption metrics

3. **Support** (on-call)
   - OAuth questions → send to docs/oauth-stripe-integration.md
   - Registration issues → check client_id registration
   - Tier issues → verify Stripe subscription

4. **Retrospective** (after 72 hours)
   - Collect metrics
   - Identify gaps
   - Plan Phase 9+ improvements

---

**Phase 8 Status**: ✅ GO-LIVE COMPLETE  
**OAuth**: 🟢 LIVE AND OPERATIONAL  
**Next Phase**: Monitoring & Support (72 hours)

---

For questions or escalations, contact: engineering@blackveilsecurity.com
