# OAuth Production Smoke Probe Runbook

## What the Probe Does

| Mode | Purpose | Env Vars |
|------|---------|----------|
| `--mode=smoke` | POST junk payload to `/oauth/token`; expect 400 `invalid_grant`. Verifies routing and rate-limiting work. | `BV_MCP_BASE` (optional) |
| `--mode=redirect` | Dynamic registration followed by `GET /oauth/authorize`; expects a 302 to the bv-web customer consent URL with OAuth params preserved. Verifies customer login is configured. | `BV_MCP_BASE` (optional) |
| `--mode=e2e` | Legacy owner-key OAuth flow: register → authorize → token → `/mcp` with JWT. Use only when `ENABLE_OWNER_OAUTH=true`. | `BV_MCP_BASE` (optional), `BV_API_KEY` (required) |

**Default base URL**: `https://dns-mcp.blackveilsecurity.com`

### Quick Test

```bash
# Smoke test (no auth needed)
python3 scripts/oauth/prod-probe.py --mode=smoke

# Customer-consent redirect test (no owner key needed)
python3 scripts/oauth/prod-probe.py --mode=redirect

# Legacy owner-key end-to-end test (requires ENABLE_OWNER_OAUTH=true and owner API key)
BV_API_KEY=<key> python3 scripts/oauth/prod-probe.py --mode=e2e
```

---

## Required Production Configuration

Committed Worker vars in `wrangler.jsonc`:
- `ENABLE_OAUTH=true`
- `ENABLE_OWNER_OAUTH=false`
- `BV_WEB_OAUTH_CONSENT_URL=https://www.blackveilsecurity.com/oauth/mcp/consent`

Production Worker secrets:
- `OAUTH_SIGNING_SECRET` is required for OAuth token signing and route readiness.
- `BV_WEB_INTERNAL_KEY` is required for trusted bv-web to bv-mcp internal calls.
- `BV_API_KEY` is optional and only needed for legacy owner/admin probes such as `--mode=e2e`; it is not required for customer OAuth redirect verification.

The production deploy workflow runs both `--mode=smoke` and `--mode=redirect` after `/health` so a missing customer consent URL fails deploy verification instead of surfacing as `503 OAuth customer login is not configured` to users.

## Secret Rotation Procedure

Generate a new HS256 symmetric signing key, rotate it in production, and verify.

1. **Generate and upload new secret**:
   ```bash
   openssl rand -hex 32 | npx wrangler secret put OAUTH_SIGNING_SECRET --config .dev/wrangler.deploy.jsonc
   ```
   This creates a 32-byte random hex string and uploads it securely to Cloudflare.

2. **Trigger isolate reload**:
   ```bash
   curl -s -o /dev/null https://dns-mcp.blackveilsecurity.com/health
   ```
   Warm the worker; secret bindings propagate immediately on next request.

3. **Verify binding is active**:
   ```bash
   npx wrangler secret list --config .dev/wrangler.deploy.jsonc | grep OAUTH_SIGNING_SECRET
   ```
   Confirms the secret was uploaded and is listed.

4. **Smoke test**:
   ```bash
   python3 scripts/oauth/prod-probe.py --mode=smoke
   ```
   Should return `200 OK: got 400 with invalid_grant (expected)`.

5. **Customer-consent redirect test**:
   ```bash
   python3 scripts/oauth/prod-probe.py --mode=redirect
   ```
   Should confirm `/oauth/authorize` redirects to bv-web customer consent.

6. **Optional: Legacy owner-key e2e test**:
   ```bash
   BV_API_KEY=<your_owner_key> python3 scripts/oauth/prod-probe.py --mode=e2e
   ```
   Verifies the legacy owner-key OAuth flow (register → token → `/mcp`) works end-to-end when `ENABLE_OWNER_OAUTH=true`.

**Important**: Rotation **immediately invalidates every live JWT** signed with the old secret at the next JWT verify. Schedule rotations during low-traffic windows (e.g., 02:00 UTC). No user-visible outage on `/mcp`; `/oauth/token` endpoints unaffected by JWT verification.

---

## Rollback

### Option 1: Delete Secret (Safest)

```bash
npx wrangler secret delete OAUTH_SIGNING_SECRET --config .dev/wrangler.deploy.jsonc
```

Effect:
- `/oauth/token` reverts to HTTP 500 `server_error` (missing binding).
- Bearer-JWT path cascades to static fallback key in `tier-auth.ts`.
- No user-visible outage on `/mcp` endpoint; existing JWTs continue to work with fallback.

This is the safest rollback: OAuth registration/token exchange stops, but all existing JWT holders can still call `/mcp`.

### Option 2: Revert Worker Deploy

```bash
npx wrangler rollback --config .dev/wrangler.deploy.jsonc
```

Cloudflare Workers rollback reverts code but **secret bindings persist** across rollbacks. Use this if the rotation introduced a code bug (not a secret issue).

---

## Compromise Response

If the signing secret is suspected compromised, rotate immediately:

1. Generate a new secret (step 1 above).
2. Upload and verify (steps 2–3).

The rotation alone **invalidates every outstanding JWT** at the next verify. No additional revocation step is needed for symmetric HS256 — the old secret becomes useless.

**Propagation window**: <5 seconds for new isolates to receive the binding. Old JWTs fail verify during this window. If you need to pre-empt this (e.g., high-security scenario), use `revokeJti` by hand per user in the session store (manual intervention).

**Notes**:
- No user notification required; token failures trigger silent re-auth in clients.
- Smoke test after rotation confirms endpoint health.
- Keep old secret value in a secure backup for 24h in case of early rollback needs.
