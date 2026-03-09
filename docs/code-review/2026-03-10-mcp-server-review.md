# Code Review: MCP Server
**Date**: 2026-03-10
**Scope**: Cloudflare Worker MCP transport, auth/session boundaries, rate limiting, outbound fetch controls, tool output handling
**Review Plan**: Broken access control, SSRF/input validation, abuse controls and quotas, information disclosure and logging, OWASP LLM output-injection exposure
**Ready for Production**: No
**Critical Issues**: 0

## Priority 1 (Must Fix) ⛔

### High: KV-backed abuse controls can be bypassed with concurrent requests
- **Locations**: `src/lib/rate-limiter.ts:69`, `src/lib/rate-limiter.ts:156`, `src/lib/rate-limiter.ts:214`, `src/lib/session.ts:37`
- **Issue**: The worker enforces rate limits and session-creation quotas with KV `get` -> compare -> `put` sequences. That pattern is non-atomic across isolates, so concurrent requests can observe the same counter value and all succeed. The global daily cap is weaker still: `checkGlobalDailyLimitKV()` has no local serialization at all.
- **Impact**: An unauthenticated attacker can exceed the intended per-IP minute quotas, per-tool daily quotas, session-creation limits, and global daily cost ceiling with bursts of parallel requests. That directly weakens the service's main abuse-control boundary and can drive unexpected cost or availability impact.
- **Why this is real here**:
  - `checkScopedRateLimitKV()` and `checkToolDailyRateLimitKV()` only serialize within one isolate via `withIpKvLock()`, but still use non-atomic KV state.
  - `checkGlobalDailyLimitKV()` does not even use the local lock, so same-isolate concurrency can over-admit requests.
  - `checkSessionCreateRateLimit()` uses the same non-atomic `get`/`put` quota pattern for `initialize`.
- **Recommended fix**:
  - Move quota enforcement to an atomic store or coordinator such as a Durable Object, Cloudflare's native rate limiting product, or a transactional data store.
  - Treat KV only as a cache or reporting layer, not as the source of truth for security-sensitive counters.
  - Add concurrency tests that issue many parallel requests against the global cap and session-create quota, not just per-IP local locking.

## Priority 2 (Should Fix) ⚠️

### Medium: MCP tool responses reflect attacker-controlled DNS content into LLM-facing output
- **Locations**: `src/handlers/tool-formatters.ts:17`, `src/handlers/tool-formatters.ts:38`, `src/tools/check-dmarc.ts:331`, `src/tools/check-bimi.ts:129`, `src/tools/explain-finding.ts:171`
- **Issue**: Tool output is returned as plain MCP text and includes untrusted strings verbatim. `formatCheckResult()` emits `finding.detail` directly, while some findings embed raw DNS record fragments such as DMARC and BIMI TXT contents. `formatExplanation()` also reflects `details` without sanitization.
- **Impact**: In an MCP/LLM environment, a malicious domain owner can publish DNS text like "ignore previous instructions" or markdown links designed to influence the consuming model or operator. This is a classic tool-output prompt-injection path: the worker itself stays safe, but downstream LLM clients can be manipulated by hostile record content.
- **Why this is real here**:
  - `check-dmarc.ts` includes a substring of the raw DMARC record in a positive finding.
  - `check-bimi.ts` includes a substring of the raw BIMI record in a positive finding.
  - `formatCheckResult()` and `formatExplanation()` pass those strings through directly into the MCP response body.
- **Recommended fix**:
  - Stop embedding raw policy/record bodies in default MCP responses.
  - Sanitize untrusted text before emission: strip markdown control syntax, remove control characters, normalize whitespace, and cap length aggressively.
  - Prefer structured summaries such as "DMARC record present with reject policy" over echoing the record itself.
  - If raw artifacts are needed, put them behind an explicit diagnostic mode and clearly mark them as untrusted.

## Positive Controls Observed

- Domain validation and SSRF defenses are materially better than average for this class of worker. The code rejects IP literals, internal/reserved suffixes, and common rebinding domains in `src/lib/sanitize.ts`, while the deployment config enables `global_fetch_strictly_public` in `wrangler.jsonc`.
- Cross-origin browser access is explicitly constrained in `src/index.ts` with both CORS origin scoping and hard Origin rejection, which is the right pattern for MCP HTTP endpoints.
- Sensitive headers are redacted in structured logging and bearer-token comparison uses a fixed-length digest comparison instead of direct string equality.
- `npm audit` and `npm audit --omit=dev` both returned `found 0 vulnerabilities` during this review.

## Testing Gaps

- Existing tests cover local per-IP serialization for KV rate limiting, but I did not find coverage for same-window global-cap races or cross-isolate quota behavior.
- I did not find tests asserting that MCP text output strips or neutralizes attacker-controlled record contents before returning them to clients.

## Recommended Changes

1. Replace KV-backed security counters with an atomic coordinator for enforcement-critical quotas.
2. Remove raw DNS/policy reflection from default MCP responses and sanitize any untrusted text that still must be shown.
3. Add concurrency-focused abuse tests and LLM-output sanitization tests before calling the service production-ready.