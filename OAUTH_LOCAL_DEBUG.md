# OAuth Local Testing Setup

## Root Cause of 500 Error
The browser console shows: `POST /oauth/mcp/consent.data → 500`

This happens when:
1. `ENABLE_OWNER_OAUTH=false` (production setting)
2. `BV_WEB_OAUTH_CONSENT_URL` is empty or misconfigured
3. bv-mcp tries to redirect to bv-web consent page
4. bv-web endpoint tries to fetch consent.data and fails

## Solution: Enable Owner OAuth Locally

### 1. Use the new dev config
```bash
# The package.json dev script now uses .dev/wrangler.dev.jsonc which sets:
npm run dev
```

This config includes:
- `ENABLE_OWNER_OAUTH: "true"` — use local owner consent form (no bv-web needed)
- `BV_WEB_OAUTH_CONSENT_URL: ""` — disabled for local testing

### 2. Test the OAuth flow
```bash
# Start dev server
npm run dev

# In another terminal, test OAuth authorization endpoint
curl -v "http://localhost:8787/oauth/authorize?client_id=test-client&redirect_uri=http://localhost:3000/callback&response_type=code&state=xyz123&scope=mcp&code_challenge=abc&code_challenge_method=S256"

# Should return:
# - 200 with HTML consent form (if client exists in KV)
# - 400 if client_id is unknown or redirect_uri not registered
# - NOT 500 anymore
```

### 3. Generate OAuth test client
```bash
curl -X POST http://localhost:8787/oauth/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "LocalTestClient",
    "redirect_uris": ["http://localhost:3000/callback"],
    "grant_types": ["authorization_code"]
  }'

# Should return:
# {
#   "client_id": "...",
#   "client_secret": "...",
#   "expires_at": ...
# }
```

## Troubleshooting

### Still getting 503 "OAuth customer login is not configured"
- Verify `npm run dev` is using `.dev/wrangler.dev.jsonc`
- Check `wrangler dev` output: should show `env.ENABLE_OWNER_OAUTH ("true")`

### Still getting 500 errors
- Check the wrangler console output for error stack traces
- Verify `SESSION_STORE` KV is accessible (check wrangler output)
- Ensure no cached configs from previous run: restart `npm run dev`

### Need to test with bv-web integration
For testing customer OAuth with production bv-web:
1. Edit `wrangler.jsonc` (production config):
   ```jsonc
   "BV_WEB_OAUTH_CONSENT_URL": "https://blackveilsecurity.com/oauth/mcp/consent"
   ```
2. Deploy to production Cloudflare Worker
3. Do NOT use `npm run dev` with this config (it would bypass local bv-web entirely)

## OAuth Flow Architecture

```
Local Dev (ENABLE_OWNER_OAUTH=true):
  Client → bv-mcp /oauth/authorize → [Local HTML consent form]
       ↓ (user enters API key)
  bv-mcp /oauth/authorize (POST) → token generation → Client

Production (ENABLE_OWNER_OAUTH=false):
  Client → bv-mcp /oauth/authorize → [Redirect to bv-web]
       ↓ (bv-web consent flow)
  bv-web /oauth/mcp/consent → [User logs in with OAuth]
       ↓
  bv-web callback → bv-mcp /oauth/token → token generation → Client
```

## Related Files
- `src/oauth/authorize.ts` — main auth request handler
- `.dev/wrangler.dev.jsonc` — local development config (NEW)
- `package.json` — dev script points to .dev/wrangler.dev.jsonc
- `wrangler.jsonc` — production/deploy config (unchanged)
