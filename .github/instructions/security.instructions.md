---
description: Use when performing security audits, reviewing code for vulnerabilities, triaging findings, or assessing OWASP compliance in this repository.
name: Security Context
applyTo: src/**/*.ts
---
# Security Context & Threat Model

## Threat Model Boundaries

**Operator-controlled inputs (NOT attacker-controlled):**
- All environment variables (`BV_DOH_ENDPOINT`, `PROVIDER_SIGNATURES_URL`, `BV_API_KEY`, `ALLOWED_ORIGINS`, `SCORING_CONFIG`, etc.) are set by the deployer via wrangler.jsonc — they are NOT user/attacker input. Do not flag these as injection vectors.
- `PROVIDER_SIGNATURES_URL` is additionally validated at runtime via `validateRuntimeSourceUrl()` with allowlist and SHA-256 pinning.

**User-controlled inputs (require validation):**
- Domain names from tool arguments — validated by Zod schema then `validateDomain()` + `sanitizeDomain()`.
- All tool arguments — validated by centralized Zod schemas in `src/schemas/tool-args.ts` before dispatch.
- HTTP headers: `Origin`, `Authorization`, `Mcp-Session-Id`, `Content-Type`.
- Query parameters: `api_key`, `sessionId`, `format`.

## Existing Defense Layers

### Input Validation Pipeline
All tool arguments pass through a two-layer pipeline. Do not flag "unvalidated input" without checking both layers:
1. **Zod schemas** (`src/schemas/tool-args.ts` + `src/schemas/primitives.ts`): type, length, format, enum allowlists.
2. **Domain sanitization** (`src/lib/sanitize.ts`): SSRF blocklists, punycode normalization, TLD validation.

Key schemas that eliminate common findings:
- `RecordTypeSchema`: enum allowlist `['A','AAAA','MX','TXT','NS','CNAME','SOA','CAA']`
- `SafeLabelSchema` + `.regex(/^[a-z0-9._-]+$/i)`: validates `include_providers`, `mx_hosts` array elements
- `SessionIdSchema`: `/^[0-9a-f]{64}$/` — 256-bit hex, no injection surface
- `DkimSelectorSchema`: trimmed, lowercased, max 63 chars, DNS-label regex

### Authentication
- `isAuthorizedRequest()` uses SHA-256 hashing + constant-time XOR comparison. This is the industry-standard approach for eliminating both length oracles and timing side-channels. Do not flag as vulnerable.
- Token extracted from `Authorization: Bearer` header first, `?api_key=` query param as fallback.

### Rate Limiting Cascade
Rate limiting uses a three-tier cascade: Durable Object → KV → in-memory. In-memory is the **last resort fallback**, not the primary mechanism. Do not flag in-memory counters as "the only rate limiter" without checking the DO and KV layers.
- Per-IP: 50/min, 300/hr (tools), 60/min, 600/hr (control plane)
- Per-tool daily quotas: `FREE_TOOL_DAILY_LIMITS` in config.ts
- Global daily cap: 500k via `QuotaCoordinator` DO
- Session creation: dedicated 30/min rate limiter (applies to both creation and revival)

### Session Security
- Session IDs are 256-bit cryptographically random values (32 bytes → 64 hex chars). Brute-force is infeasible (2^256 keyspace).
- The session ID in the `Mcp-Session-Id` custom header serves as a CSRF token — custom headers cannot be set by cross-origin form submissions.
- **Tombstones**: Deleted sessions are tombstoned in both in-memory (10 min) and KV (600s = 10 min). These TTLs are intentionally synchronized.
- **Session revival**: By design for mcp-remote compatibility. Protected by: format validation, tombstone check (memory + KV), and session-create rate limit.
- **KV failure fallback**: Sessions degrade to in-memory on KV failure. This is intentional graceful degradation, not a vulnerability. Failures are logged via `logError()`.

### Origin Validation
- `checkOrigin()` compares full origins (scheme+host+port via `.origin` property).
- Desktop IDE schemes (`vscode-webview:`, `vscode-file:`) are Electron-only custom URI schemes. Standard browsers **cannot forge** these — they are not HTTP/HTTPS origins. Safe to allow without explicit allowlisting.
- `ALLOWED_ORIGINS` env var provides explicit allowlisting for additional origins.

### Internal Routes
- `/internal/*` routes are guarded by `cf-connecting-ip` header detection. Cloudflare sets this on ALL public internet requests. Service binding (Worker-to-Worker) calls never carry this header. This is a reliable infrastructure-level guard, not spoofable.
- Batch endpoint uses `ALLOWED_BATCH_ARGS` allowlist for argument keys and validates all domains through `validateDomain()` + `sanitizeDomain()`.

### SSRF Protection
- All outbound `fetch()` calls use `redirect: 'manual'` to prevent redirect-based SSRF.
- Domain blocklists in `src/lib/config.ts` block private IPs, link-local, loopback, and dangerous TLDs.
- `global_fetch_strictly_public` Cloudflare compat flag enforced.
- Provider signature loading uses URL validation, host allowlisting, and SHA-256 content pinning.

### Output Sanitization
- `createFinding()` auto-sanitizes `detail` via `sanitizeDnsData()` (strips HTML/markdown).
- SVG badges use XML-escape + hex regex for colors.
- Error messages are filtered through `sanitizeErrorMessage()` — only safe-prefixed messages reach clients.
- DoH responses are schema-validated before casting.

## Intentional Design Patterns (Not Vulnerabilities)

- **KV error swallowing with fallback**: Throughout session.ts, rate-limiter.ts, cache.ts — KV failures degrade gracefully to in-memory with `logError()` logging. This is the documented resilience pattern.
- **HSTS preload header**: Operational decision appropriate for an HTTPS-only Cloudflare Worker.
- **`initialize` exempt from control-plane rate limit**: Session creation has its own dedicated rate limiter (30/min). Double-limiting causes mcp-remote reconnection storms.
- **Passthrough Zod schemas (`.passthrough()`)**: Intentional — tools may receive extra properties from different MCP client versions. Unknown properties are ignored, not processed.
