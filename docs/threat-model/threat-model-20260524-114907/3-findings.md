# Security Findings

> **Remediation status (updated 2026-05-25).** All findings have been addressed and their STRIDE status + coverage table read `Mitigated`. The Tier-1/2/3 remediation findings were **merged to `main` via PR #208** (commit `ffe9f7e`). FIND-05 is a false positive (already mitigated on `main`). A few remediations carry deploy/cross-repo follow-ups (set `OAUTH_ISSUER`/`KV_ENVELOPE_KEY`, flip `REJECT_QUERY_API_KEY`; bv-web must send the internal bearer and call the revoke endpoint) — see PR #208. This model was generated at commit `7e23243`; see `../threat-model-20260524-184006-incremental/` for the before/after comparison.

---

## Tier 1 — Direct Exposure (No Prerequisites)

### FIND-01: API key accepted via `?api_key=` query parameter

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Moderate |
| CVSS 4.0 | 5.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N) |
| CWE | [CWE-598](https://cwe.mitre.org/data/definitions/598.html): Use of GET Request Method With Sensitive Query Strings |
| OWASP | A04:2025 – Cryptographic Failures |
| Exploitation Prerequisites | None |
| Exploitability Tier | Tier 1 — Direct Exposure (No Prerequisites) |
| Remediation Effort | Low |
| Mitigation Type | Standard Mitigation |
| Component | TierAuthResolver |
| Related Threats | [T11.I](2-stride-analysis.md#tierauthresolver) |

#### Description

The auth layer accepts the API key from a `?api_key=` query-string parameter as a fallback to the `Authorization: Bearer` header (a Smithery compatibility path). Tokens in query strings are recorded in CDN/edge access logs, browser history, and referer headers, widening the disclosure surface for a credential that maps to elevated tiers.

#### Evidence

**Prerequisite basis:** The `/mcp` endpoint is `External` with `Auth Required = No` in the Component Exposure Table (`0.1-architecture.md`); the query-string path is reachable unauthenticated, so the prerequisite floor is `None`.

Token extraction prefers the bearer header then falls back to `?api_key=` (`src/index.ts` auth gate); a `Sunset` header is already emitted to signal deprecation.

#### Remediation

Complete the planned deprecation: set a hard cutoff date for `?api_key=`, log/alert on its use, and reject it once clients have migrated. Until then, ensure the value is never echoed and is excluded from any request logging.

#### Verification

Send a request with `?api_key=` and confirm a deprecation response/header, and confirm the value does not appear in analytics, access logs, or error output.

### FIND-02: Free-tier abuse via distributed IPs against a shared global budget

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Moderate |
| CVSS 4.0 | 5.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N) |
| CWE | [CWE-770](https://cwe.mitre.org/data/definitions/770.html): Allocation of Resources Without Limits or Throttling |
| OWASP | A06:2025 – Insecure Design |
| Exploitation Prerequisites | None |
| Exploitability Tier | Tier 1 — Direct Exposure (No Prerequisites) |
| Remediation Effort | Medium |
| Mitigation Type | Standard Mitigation |
| Component | RateLimiter |
| Related Threats | [T07.A](2-stride-analysis.md#honoworker), [T46.E](2-stride-analysis.md#ratelimiter) |

#### Description

Per-IP limits (50/min, 300/hr) bound a single source, but an attacker spreading requests across many IPs can stay under per-IP thresholds while consuming the shared 500K/day global free budget, degrading availability for legitimate free-tier users. The global ceiling is the only cross-IP control.

#### Evidence

**Prerequisite basis:** `/mcp` is `External`, `Auth Required = No` — unauthenticated; prerequisite `None`.

Per-IP windows and the global daily ceiling are enforced in `src/lib/rate-limiter.ts` and `QuotaCoordinator`; there is no per-IP daily sub-limit beneath the global ceiling.

#### Remediation

Add a per-IP (or per-ASN) daily sub-limit for the free tier beneath the global ceiling, and consider a proof-of-work or progressive backoff once anomaly thresholds are crossed.

#### Verification

Simulate distributed traffic across many source IPs and confirm a per-IP daily cap engages before the global budget is exhausted.

### FIND-03: Scanner usable as a reconnaissance / amplification proxy

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Moderate |
| CVSS 4.0 | 5.1 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:L) |
| CWE | [CWE-406](https://cwe.mitre.org/data/definitions/406.html): Insufficient Control of Network Message Volume (Network Amplification) |
| OWASP | A06:2025 – Insecure Design |
| Exploitation Prerequisites | None |
| Exploitability Tier | Tier 1 — Direct Exposure (No Prerequisites) |
| Remediation Effort | Medium |
| Mitigation Type | Standard Mitigation |
| Component | ToolsHandler |
| Related Threats | [T32.A](2-stride-analysis.md#toolshandler), [T42.D](2-stride-analysis.md#dnsresolver), [T43.A](2-stride-analysis.md#dnsresolver) |

#### Description

An unauthenticated caller can direct scans/DNS lookups at arbitrary third-party domains, using the service as a recon proxy or a low-grade amplifier toward victim resolvers. Outbound requests originate from Cloudflare egress, masking the true source.

#### Evidence

**Prerequisite basis:** `scan_domain`/discovery tools are reachable on `External`, `Auth Required = No` `/mcp`; prerequisite `None`.

Per-IP rate limits and 20/day caps on `check_lookalikes`/`check_shadow_domains` exist (`src/lib/config.ts`), but general scanning of attacker-chosen targets is otherwise only bounded by the same per-IP limits.

#### Remediation

Apply stricter per-IP/global caps on outbound-heavy tools, add jittered backoff on repeated distinct-target scans, and document acceptable-use; consider requiring auth for high-fan-out discovery tools.

#### Verification

Confirm that repeated scans of many distinct third-party domains from one IP trip a tightened cap and that fuzzing alerts fire on enumeration patterns.

### FIND-04: OAuth issuer derived from a spoofable `Host` header

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Moderate |
| CVSS 4.0 | 4.8 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N) |
| CWE | [CWE-350](https://cwe.mitre.org/data/definitions/350.html): Reliance on Reverse DNS Resolution / Untrusted Host Header |
| OWASP | A02:2025 – Security Misconfiguration |
| Exploitation Prerequisites | None |
| Exploitability Tier | Tier 1 — Direct Exposure (No Prerequisites) |
| Remediation Effort | Low |
| Mitigation Type | Standard Mitigation |
| Component | HonoWorker |
| Related Threats | [T05.I](2-stride-analysis.md#honoworker) |

#### Description

When `OAUTH_ISSUER` is unset, the issuer value in OAuth discovery and token responses is derived from the request `Host`, which an attacker can spoof. While JWT `aud` validation limits direct impact, a spoofed issuer can mislead discovery clients and complicate token-audience reasoning.

#### Evidence

**Prerequisite basis:** `/oauth/*` and `/.well-known/oauth-*` are `External`, `Auth Required = No`; prerequisite `None`.

`OAUTH_ISSUER` is an optional override that falls back to Host (`src/oauth/discovery.ts`, `token.ts`); CLAUDE.md notes it should be set in production against Host spoofing.

#### Remediation

Set `OAUTH_ISSUER` explicitly in production deployment config and reject requests whose `Host` does not match the configured issuer host.

#### Verification

With `OAUTH_ISSUER` set, send a spoofed `Host` and confirm discovery/token responses still return the configured issuer.

### FIND-05: Open OAuth dynamic client registration

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Low |
| CVSS 4.0 | 4.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N) |
| CWE | [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html): Insecure Default Initialization of Resource |
| OWASP | A02:2025 – Security Misconfiguration |
| Exploitation Prerequisites | None |
| Exploitability Tier | Tier 1 — Direct Exposure (No Prerequisites) |
| Remediation Effort | Low |
| Mitigation Type | Existing Control |
| Component | OAuthIssuer |
| Related Threats | [T15.S](2-stride-analysis.md#oauthissuer) |

#### Description

> **Reclassified 2026-05-25 — FALSE POSITIVE (already mitigated).** Code verification found this control already present on `main`: `src/oauth/register.ts` enforces a per-IP registration limit (10/min + 30/hr → HTTP 429) and `src/oauth/storage.ts` writes client records with a TTL. No change was required; the original reconnaissance examined `token.ts` and missed `register.ts`. Retained here for traceability.

`POST /oauth/register` allows unauthenticated dynamic client registration (per the MCP OAuth profile). Without throttling or storage caps, an attacker can register many rogue clients, polluting client storage and enabling phishing-style consent flows.

#### Evidence

**Prerequisite basis:** `/oauth/register` is `External`, `Auth Required = No`; prerequisite `None`.

Registration is gated only by `ENABLE_OAUTH` (`src/oauth/register.ts`); PKCE and redirect_uri validation reduce downstream abuse but do not throttle registration volume.

#### Remediation

Rate-limit `/oauth/register` per IP, cap stored client records with TTL eviction, and require strict `redirect_uri` allowlisting per client.

#### Verification

Confirm a per-IP registration limit and that stale/unused client records are evicted.

### FIND-06: `force_refresh` enables cache-busting amplification

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Low |
| CVSS 4.0 | 3.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N) |
| CWE | [CWE-770](https://cwe.mitre.org/data/definitions/770.html): Allocation of Resources Without Limits or Throttling |
| OWASP | A06:2025 – Insecure Design |
| Exploitation Prerequisites | None |
| Exploitability Tier | Tier 1 — Direct Exposure (No Prerequisites) |
| Remediation Effort | Low |
| Mitigation Type | Standard Mitigation |
| Component | ToolsHandler |
| Related Threats | [T33.A](2-stride-analysis.md#toolshandler) |

#### Description

The `force_refresh` parameter bypasses the scan cache (`skipCache`), so repeated requests with `force_refresh` defeat the 5-minute TTL and force full backend work (DNS/fetch) each time, amplifying cost.

#### Evidence

**Prerequisite basis:** Reachable on `External`, `Auth Required = No` `/mcp`; prerequisite `None`.

`force_refresh → skipCache` in `runWithCache()` (`src/lib/cache.ts`); requests still count against per-tool quota but bypass the cheap cached path.

#### Remediation

Apply a stricter sub-limit specifically to `force_refresh` requests (e.g., a small fraction of the per-tool quota) and/or require authentication to use it.

#### Verification

Confirm a `force_refresh` sub-limit engages well before the standard per-tool quota.

### FIND-07: Domain validation hardening for homoglyph / IDN inputs

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Low |
| CVSS 4.0 | 3.1 (CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N) |
| CWE | [CWE-1007](https://cwe.mitre.org/data/definitions/1007.html): Insufficient Visual Distinction of Homoglyphs |
| OWASP | A03:2025 – Software Supply Chain Failures |
| Exploitation Prerequisites | None |
| Exploitability Tier | Tier 1 — Direct Exposure (No Prerequisites) |
| Remediation Effort | Medium |
| Mitigation Type | Custom Mitigation |
| Component | DomainSanitizer |
| Related Threats | [T34.T](2-stride-analysis.md#domainsanitizer) |

#### Description

Domain inputs accept internationalized names. Without explicit, well-tested punycode/homoglyph normalization, mixed-script or confusable inputs could produce misleading scan attribution. This is a hardening/verification item — no concrete bypass was confirmed, but the IDN handling path warrants explicit test coverage.

#### Evidence

**Prerequisite basis:** Domain input arrives on `External`, `Auth Required = No` `/mcp`; prerequisite `None`.

`sanitizeDomain`/`validateDomain` perform normalization and public-suffix checks (`src/lib/sanitize.ts`), but mixed-script confusable handling is not separately asserted in tests.

#### Remediation

Add explicit IDNA2008/UTS-46 normalization and mixed-script (confusable) detection, with unit tests covering homoglyph and bidi cases.

#### Verification

Add tests feeding homoglyph/mixed-script domains and assert canonicalized, unambiguous output.

### FIND-08: Authentication and token-integrity controls (existing control)

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Low |
| CVSS 4.0 | 2.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N) |
| CWE | [CWE-287](https://cwe.mitre.org/data/definitions/287.html): Improper Authentication |
| OWASP | A07:2025 – Authentication Failures |
| Exploitation Prerequisites | None |
| Exploitability Tier | Tier 1 — Direct Exposure (No Prerequisites) |
| Remediation Effort | Low |
| Mitigation Type | Existing Control |
| Component | TierAuthResolver |
| Related Threats | [T08.S](2-stride-analysis.md#tierauthresolver), [T09.S](2-stride-analysis.md#tierauthresolver), [T10.T](2-stride-analysis.md#tierauthresolver), [T12.E](2-stride-analysis.md#tierauthresolver), [T14.A](2-stride-analysis.md#tierauthresolver), [T16.T](2-stride-analysis.md#oauthissuer), [T17.I](2-stride-analysis.md#oauthissuer), [T21.S](2-stride-analysis.md#mcpexecutor) |

#### Description

This finding documents the existing authentication controls so they are tracked and regression-protected: constant-time key comparison, JWT algorithm pinning, server-derived tiering, the owner IP gate, PKCE, and random session IDs. No gap is asserted; the residual risk is implementation drift.

#### Evidence

**Prerequisite basis:** These controls sit on the `External`, `Auth Required = No` request path; prerequisite `None`.

Constant-time XOR over SHA-256 and `OWNER_ALLOW_IPS` gating (`src/lib/tier-auth.ts`); HS256 alg pinned with algorithm-checked-before-verify and `OAUTH_SIGNING_SECRET` ≥32 bytes (`src/oauth/jwt.ts`); single-use PKCE codes (`src/oauth/token.ts`); 64-hex session IDs (`src/lib/session.ts`).

#### Remediation

No change required. Maintain regression/contract tests asserting: constant-time compare, rejection of `alg=none`, tier never read from caller input, and minimum signing-secret length.

#### Verification

Run the auth contract/audit tests and confirm `alg=none`, tampered tiers, and short secrets are rejected.

### FIND-09: SSRF egress controls (existing control)

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Low |
| CVSS 4.0 | 2.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N) |
| CWE | [CWE-918](https://cwe.mitre.org/data/definitions/918.html): Server-Side Request Forgery |
| OWASP | A06:2025 – Insecure Design |
| Exploitation Prerequisites | None |
| Exploitability Tier | Tier 1 — Direct Exposure (No Prerequisites) |
| Remediation Effort | Low |
| Mitigation Type | Existing Control |
| Component | SafeFetch |
| Related Threats | [T35.I](2-stride-analysis.md#domainsanitizer), [T36.E](2-stride-analysis.md#domainsanitizer), [T37.T](2-stride-analysis.md#safefetch), [T38.I](2-stride-analysis.md#safefetch), [T39.D](2-stride-analysis.md#safefetch) |

#### Description

Documents the layered SSRF defenses for attacker-influenced URLs: input rejection of private/reserved/rebinding hosts, HTTPS-only egress with manual per-hop redirect re-validation, fetch timeouts, and the Cloudflare `global_fetch_strictly_public` runtime backstop. Residual risk is regression if a new tool uses raw `fetch()` on attacker-influenced URLs.

#### Evidence

**Prerequisite basis:** Egress is driven by `External`, `Auth Required = No` scan input; prerequisite `None`.

`safeFetch` HTTPS-only + `redirect:'manual'` (`src/lib/safe-fetch.ts`); blocklists in `src/lib/config.ts`; `validateDomain`/`validateOutboundUrl` (`src/lib/sanitize.ts`); `global_fetch_strictly_public` in `wrangler.jsonc`.

#### Remediation

No change required. Add a lint/contract test asserting that attacker-influenced URLs (BIMI `l=`/`a=`, redirect `Location:`) are only fetched via `safeFetch`, never raw `fetch()`.

#### Verification

Run the SSRF audit test; attempt fetches to `169.254.169.254` and RFC1918 hosts and confirm rejection.

### FIND-10: Rate limiting, quotas, and DoS budgets (existing control)

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Low |
| CVSS 4.0 | 2.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N) |
| CWE | [CWE-770](https://cwe.mitre.org/data/definitions/770.html): Allocation of Resources Without Limits or Throttling |
| OWASP | A06:2025 – Insecure Design |
| Exploitation Prerequisites | None |
| Exploitability Tier | Tier 1 — Direct Exposure (No Prerequisites) |
| Remediation Effort | Low |
| Mitigation Type | Existing Control |
| Component | RateLimiter |
| Related Threats | [T01.S](2-stride-analysis.md#honoworker), [T02.T](2-stride-analysis.md#honoworker), [T06.D](2-stride-analysis.md#honoworker), [T18.D](2-stride-analysis.md#oauthissuer), [T22.T](2-stride-analysis.md#mcpexecutor), [T25.D](2-stride-analysis.md#mcpexecutor), [T26.E](2-stride-analysis.md#mcpexecutor), [T27.A](2-stride-analysis.md#mcpexecutor), [T28.T](2-stride-analysis.md#toolshandler), [T30.D](2-stride-analysis.md#toolshandler), [T31.E](2-stride-analysis.md#toolshandler), [T44.T](2-stride-analysis.md#ratelimiter), [T45.D](2-stride-analysis.md#ratelimiter), [T47.A](2-stride-analysis.md#ratelimiter) |

#### Description

Documents the existing throttling, validation, and budget controls that bound resource consumption and input abuse: per-IP/per-tool/global limits, body-size caps, Zod argument validation, the tool allowlist, scan/batch time budgets, and fuzzing detection. Residual risk is the distributed-IP gap captured separately in FIND-02.

#### Evidence

**Prerequisite basis:** Controls operate on the `External`, `Auth Required = No` request path; prerequisite `None`.

`src/lib/rate-limiter.ts` (per-IP/global), `MAX_REQUEST_BODY_BYTES` (`src/lib/config.ts`), `validateToolArgs` + `TOOL_REGISTRY` (`src/handlers/tools.ts`), `batch_scan` budget/concurrency, `fuzzing-detector.ts`, DO fallback in `quota-coordinator.ts`.

#### Remediation

No change required beyond FIND-02. Maintain audit tests asserting limit thresholds, body caps, and fuzzing thresholds (`FUZZ_THRESHOLDS`).

#### Verification

Run the rate-limit and fuzzing audit tests; confirm 429-equivalent JSON-RPC `-32029` on threshold breach.

### FIND-11: Information-disclosure controls (existing control)

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Low |
| CVSS 4.0 | 2.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N) |
| CWE | [CWE-209](https://cwe.mitre.org/data/definitions/209.html): Generation of Error Message Containing Sensitive Information |
| OWASP | A09:2025 – Security Logging & Alerting Failures |
| Exploitation Prerequisites | None |
| Exploitability Tier | Tier 1 — Direct Exposure (No Prerequisites) |
| Remediation Effort | Low |
| Mitigation Type | Existing Control |
| Component | HonoWorker |
| Related Threats | [T03.R](2-stride-analysis.md#honoworker), [T04.I](2-stride-analysis.md#honoworker), [T23.R](2-stride-analysis.md#mcpexecutor), [T24.I](2-stride-analysis.md#mcpexecutor), [T29.I](2-stride-analysis.md#toolshandler), [T66.I](2-stride-analysis.md#intelligencedb), [T68.R](2-stride-analysis.md#intelligencedb) |

#### Description

Documents controls that limit information leakage and provide attribution without exposing PII: the error-message allowlist, suppression of `STRUCTURED_RESULT` for interactive clients, finding auto-sanitization, FNV-1a IP hashing in analytics, and AES-GCM-encrypted access-log IP evidence with bounded retention.

#### Evidence

**Prerequisite basis:** These controls act on `External`, `Auth Required = No` responses/telemetry; prerequisite `None`.

`sanitizeErrorMessage` allowlist (`src/lib/json-rpc.ts`); structured-result omission for LLM clients; `createFinding()` auto-sanitization; FNV-1a `ipHash` (`src/lib/analytics.ts`); AES-GCM access-log encryption (`src/mcp/execute.ts`, `INTELLIGENCE_DB`).

#### Remediation

No change required. Maintain tests asserting error-prefix allowlisting and that raw IPs never appear in analytics events.

#### Verification

Trigger a non-allowlisted error and confirm the generic fallback; inspect an analytics event and confirm only hashed IP is present.

---

## Tier 2 — Conditional Risk (Authenticated / Single Prerequisite)

### FIND-12: Internal routes default to no bearer authentication

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Moderate |
| CVSS 4.0 | 5.1 (CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N) |
| CWE | [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html): Insecure Default Initialization of Resource |
| OWASP | A02:2025 – Security Misconfiguration |
| Exploitation Prerequisites | Internal Network |
| Exploitability Tier | Tier 2 — Conditional Risk |
| Remediation Effort | Low |
| Mitigation Type | Standard Mitigation |
| Component | InternalRouter |
| Related Threats | [T52.A](2-stride-analysis.md#internalrouter) |

#### Description

`/internal/tools/*` and `/internal/analytics/*` use a lenient auth gate that requires a bearer only when `REQUIRE_INTERNAL_AUTH=true` (default off). Any in-account binding (or a misrouted internal caller) can therefore invoke tool execution and read analytics without a credential, relying solely on the `cf-connecting-ip` public-rejection guard.

#### Evidence

**Prerequisite basis:** `/internal/*` is `Internal Only` (public requests rejected by `isPublicInternetRequest`), so the prerequisite floor is `Internal Network` per the Component Exposure Table.

`internalLenientAuthGate` is opt-in via `REQUIRE_INTERNAL_AUTH` (`src/internal.ts`); credential-minting routes already use a strict gate, but tools/analytics do not by default.

#### Remediation

Set `REQUIRE_INTERNAL_AUTH=true` in production and provision `BV_WEB_INTERNAL_KEY`, making bearer auth mandatory for `/internal/tools/*` and `/internal/analytics/*`.

#### Verification

With the flag enabled, confirm `/internal/tools/call` without a valid bearer returns 401.

### FIND-13: JWT retains elevated tier after plan downgrade

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Moderate |
| CVSS 4.0 | 4.6 (CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N) |
| CWE | [CWE-613](https://cwe.mitre.org/data/definitions/613.html): Insufficient Session Expiration |
| OWASP | A07:2025 – Authentication Failures |
| Exploitation Prerequisites | Authenticated User |
| Exploitability Tier | Tier 2 — Conditional Risk |
| Remediation Effort | Medium |
| Mitigation Type | Standard Mitigation |
| Component | OAuthIssuer |
| Related Threats | [T20.A](2-stride-analysis.md#oauthissuer) |

#### Description

An issued JWT carries a tier claim and remains valid until `exp`. If a customer downgrades or cancels their plan, the previously issued token continues to grant the higher tier until it expires, unless explicitly revoked.

#### Evidence

**Prerequisite basis:** Requires a previously issued (authenticated) token; prerequisite `Authenticated User`.

Tier is embedded in the signed JWT (`src/oauth/jwt.ts`); JTI revocation exists in KV but is not automatically triggered on plan changes from bv-web.

#### Remediation

Keep access-token lifetime short and add a downgrade hook from bv-web that revokes outstanding JTIs (or bumps a per-subject token-version claim checked at validation).

#### Verification

Downgrade a test subscription and confirm previously issued tokens are rejected/limited within the token lifetime.

### FIND-14: Brand-audit discovery enables third-party enumeration

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Moderate |
| CVSS 4.0 | 4.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N) |
| CWE | [CWE-799](https://cwe.mitre.org/data/definitions/799.html): Improper Control of Interaction Frequency |
| OWASP | A06:2025 – Insecure Design |
| Exploitation Prerequisites | Authenticated User |
| Exploitability Tier | Tier 2 — Conditional Risk |
| Remediation Effort | Medium |
| Mitigation Type | Standard Mitigation |
| Component | BrandAuditPipeline |
| Related Threats | [T54.I](2-stride-analysis.md#brandauditpipeline), [T56.A](2-stride-analysis.md#brandauditpipeline) |

#### Description

Brand-audit tiered discovery enumerates candidate domains and infrastructure related to a watched brand via CT logs, WHOIS/RDAP, and intel bindings. A paid caller could point it at third-party brands to perform large-scale reconnaissance of infrastructure they do not own.

#### Evidence

**Prerequisite basis:** Brand audit requires a paid tier; the Component Exposure Table sets the floor at `Authenticated User`.

Watched-domain validation at register time exists (#201) and opt-out enforcement is present (`src/lib/brand-optout-enforcement.ts`), but cross-tenant third-party targeting is otherwise quota-bounded only.

#### Remediation

Require ownership verification (e.g., DNS TXT challenge) before deep discovery on a watched domain, and tighten per-tenant discovery quotas; honor the opt-out registry on all discovery paths.

#### Verification

Attempt a brand audit on an unverified third-party domain and confirm ownership verification is required before tiered discovery runs.

### FIND-15: Trial-key tier persists during resolution cache window

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Low |
| CVSS 4.0 | 3.5 (CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N) |
| CWE | [CWE-613](https://cwe.mitre.org/data/definitions/613.html): Insufficient Session Expiration |
| OWASP | A07:2025 – Authentication Failures |
| Exploitation Prerequisites | Authenticated User |
| Exploitability Tier | Tier 2 — Conditional Risk |
| Remediation Effort | Low |
| Mitigation Type | Standard Mitigation |
| Component | TierAuthResolver |
| Related Threats | [T13.E](2-stride-analysis.md#tierauthresolver) |

#### Description

Resolved trial keys are cached for ~60 seconds to reduce KV load. An expired or exhausted trial key therefore continues to grant its tier for up to the cache window before the next resolution downgrades it.

#### Evidence

**Prerequisite basis:** Requires possession of a (recently valid) trial key; prerequisite `Authenticated User`.

`TRIAL_KEY_CACHE_TTL` ~60 s in `src/lib/tier-auth.ts`; expiry/exhaustion is not reflected until the cache entry refreshes.

#### Remediation

Reduce the cache TTL for near-expiry keys, or check the key's expiry timestamp on each request even when serving a cached tier.

#### Verification

Expire a trial key and confirm tier downgrade occurs within an acceptable bound.

### FIND-16: Internal isolation and external-dependency hardening (existing control)

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Low |
| CVSS 4.0 | 2.5 (CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N) |
| CWE | [CWE-306](https://cwe.mitre.org/data/definitions/306.html): Missing Authentication for Critical Function |
| OWASP | A04:2025 – Cryptographic Failures |
| Exploitation Prerequisites | Internal Network |
| Exploitability Tier | Tier 2 — Conditional Risk |
| Remediation Effort | Low |
| Mitigation Type | Existing Control |
| Component | InternalRouter |
| Related Threats | [T19.E](2-stride-analysis.md#oauthissuer), [T40.S](2-stride-analysis.md#dnsresolver), [T41.T](2-stride-analysis.md#dnsresolver), [T48.S](2-stride-analysis.md#internalrouter), [T49.T](2-stride-analysis.md#internalrouter), [T50.D](2-stride-analysis.md#internalrouter), [T51.E](2-stride-analysis.md#internalrouter), [T53.T](2-stride-analysis.md#brandauditpipeline), [T55.D](2-stride-analysis.md#brandauditpipeline), [T58.D](2-stride-analysis.md#quotacoordinator), [T59.T](2-stride-analysis.md#profileaccumulator), [T60.A](2-stride-analysis.md#profileaccumulator), [T69.S](2-stride-analysis.md#bvweb), [T70.I](2-stride-analysis.md#bvweb), [T71.D](2-stride-analysis.md#bvweb), [T72.S](2-stride-analysis.md#publicdoh), [T73.T](2-stride-analysis.md#publicdoh), [T74.D](2-stride-analysis.md#publicdoh), [T75.T](2-stride-analysis.md#certtransparency), [T76.D](2-stride-analysis.md#certtransparency), [T77.I](2-stride-analysis.md#whoisrdap), [T78.D](2-stride-analysis.md#whoisrdap) |

#### Description

Documents the existing controls isolating the internal surface and hardening external dependencies: public-request rejection on `/internal/*`, strict bearer gates for credential-minting, batch input allowlists and budgets, TLS egress with multi-resolver/CT/WHOIS fallback chains, authenticated entitlement bindings with enum validation, and maturity-gated adaptive scoring with static fallback. Residual risk is captured by FIND-12 (default-off internal auth).

#### Evidence

**Prerequisite basis:** These controls govern `Internal Only` routes and `Internal Network`-reachable dependencies per the Component Exposure Table.

`isPublicInternetRequest` + strict gates (`src/internal.ts`); batch allowlist/limits; resolver fallback (`src/lib/dns-multi-resolver.ts`); enum-validated entitlements (`src/oauth/entitlements.ts`); maturity-gated blending (`src/lib/adaptive-weights.ts`, `profile-accumulator.ts`); output sanitization (`createFinding()`).

#### Remediation

No change required beyond FIND-12. Maintain the audit test asserting `/internal/*` rejects public requests and that credential-minting routes fail closed when the internal key is unset.

#### Verification

Run the internal-route audit tests; confirm public requests to `/internal/*` return 404 and credential routes return 503 when unconfigured.

---

## Tier 3 — Defense-in-Depth (Prior Compromise / Host Access)

### FIND-17: Sensitive KV records rely on platform isolation only

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Low |
| CVSS 4.0 | 4.2 (CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N) |
| CWE | [CWE-311](https://cwe.mitre.org/data/definitions/311.html): Missing Encryption of Sensitive Data |
| OWASP | A04:2025 – Cryptographic Failures |
| Exploitation Prerequisites | CloudflareWorker Compromise |
| Exploitability Tier | Tier 3 — Defense-in-Depth |
| Remediation Effort | Medium |
| Mitigation Type | Standard Mitigation |
| Component | RateLimitKV |
| Related Threats | [T62.I](2-stride-analysis.md#sessionstorekv), [T65.I](2-stride-analysis.md#ratelimitkv) |

#### Description

OAuth authorization codes/JTI markers (SessionStoreKV) and trial keys (RateLimitKV) are stored relying on Cloudflare's at-rest encryption and in-account binding isolation. Unlike the access-log IP evidence — which is AES-GCM-encrypted at the application layer — these secrets have no app-layer encryption, so a worker/account compromise exposes them directly.

#### Evidence

**Prerequisite basis:** KV namespaces have `No Listener` and are reachable only via in-account bindings; the floor is host/worker compromise (`Host/OS Access` / `CloudflareWorker Compromise`) per the Component Exposure Table.

Access-log IP evidence is app-encrypted (`src/mcp/execute.ts`), but trial keys (`src/lib/trial-keys.ts`) and OAuth codes (`src/oauth/storage.ts`) are stored without an equivalent app-layer envelope.

#### Remediation

Apply the same app-layer AES-GCM envelope (with a versioned key) to trial keys and OAuth codes, or store only hashed/opaque references, so platform isolation is not the sole protection.

#### Verification

Inspect KV contents and confirm trial keys / OAuth codes are stored encrypted or as non-reversible references.

---

## Threat Coverage Verification

| Threat ID | Finding ID | Status |
|-----------|------------|--------|
| T01.S | FIND-10 | ✅ Mitigated (FIND-10) |
| T02.T | FIND-10 | ✅ Mitigated (FIND-10) |
| T03.R | FIND-11 | ✅ Mitigated (FIND-11) |
| T04.I | FIND-11 | ✅ Mitigated (FIND-11) |
| T05.I | FIND-04 | ✅ Mitigated (FIND-04) |
| T06.D | FIND-10 | ✅ Mitigated (FIND-10) |
| T07.A | FIND-02 | ✅ Mitigated (FIND-02) |
| T08.S | FIND-08 | ✅ Mitigated (FIND-08) |
| T09.S | FIND-08 | ✅ Mitigated (FIND-08) |
| T10.T | FIND-08 | ✅ Mitigated (FIND-08) |
| T11.I | FIND-01 | ✅ Mitigated (FIND-01) |
| T12.E | FIND-08 | ✅ Mitigated (FIND-08) |
| T13.E | FIND-15 | ✅ Mitigated (FIND-15) |
| T14.A | FIND-08 | ✅ Mitigated (FIND-08) |
| T15.S | FIND-05 | ✅ Mitigated (FIND-05) |
| T16.T | FIND-08 | ✅ Mitigated (FIND-08) |
| T17.I | FIND-08 | ✅ Mitigated (FIND-08) |
| T18.D | FIND-10 | ✅ Mitigated (FIND-10) |
| T19.E | FIND-16 | ✅ Mitigated (FIND-16) |
| T20.A | FIND-13 | ✅ Mitigated (FIND-13) |
| T21.S | FIND-08 | ✅ Mitigated (FIND-08) |
| T22.T | FIND-10 | ✅ Mitigated (FIND-10) |
| T23.R | FIND-11 | ✅ Mitigated (FIND-11) |
| T24.I | FIND-11 | ✅ Mitigated (FIND-11) |
| T25.D | FIND-10 | ✅ Mitigated (FIND-10) |
| T26.E | FIND-10 | ✅ Mitigated (FIND-10) |
| T27.A | FIND-10 | ✅ Mitigated (FIND-10) |
| T28.T | FIND-10 | ✅ Mitigated (FIND-10) |
| T29.I | FIND-11 | ✅ Mitigated (FIND-11) |
| T30.D | FIND-10 | ✅ Mitigated (FIND-10) |
| T31.E | FIND-10 | ✅ Mitigated (FIND-10) |
| T32.A | FIND-03 | ✅ Mitigated (FIND-03) |
| T33.A | FIND-06 | ✅ Mitigated (FIND-06) |
| T34.T | FIND-07 | ✅ Mitigated (FIND-07) |
| T35.I | FIND-09 | ✅ Mitigated (FIND-09) |
| T36.E | FIND-09 | ✅ Mitigated (FIND-09) |
| T37.T | FIND-09 | ✅ Mitigated (FIND-09) |
| T38.I | FIND-09 | ✅ Mitigated (FIND-09) |
| T39.D | FIND-09 | ✅ Mitigated (FIND-09) |
| T40.S | FIND-16 | ✅ Mitigated (FIND-16) |
| T41.T | FIND-16 | ✅ Mitigated (FIND-16) |
| T42.D | FIND-03 | ✅ Mitigated (FIND-03) |
| T43.A | FIND-03 | ✅ Mitigated (FIND-03) |
| T44.T | FIND-10 | ✅ Mitigated (FIND-10) |
| T45.D | FIND-10 | ✅ Mitigated (FIND-10) |
| T46.E | FIND-02 | ✅ Mitigated (FIND-02) |
| T47.A | FIND-10 | ✅ Mitigated (FIND-10) |
| T48.S | FIND-16 | ✅ Mitigated (FIND-16) |
| T49.T | FIND-16 | ✅ Mitigated (FIND-16) |
| T50.D | FIND-16 | ✅ Mitigated (FIND-16) |
| T51.E | FIND-16 | ✅ Mitigated (FIND-16) |
| T52.A | FIND-12 | ✅ Mitigated (FIND-12) |
| T53.T | FIND-16 | ✅ Mitigated (FIND-16) |
| T54.I | FIND-14 | ✅ Mitigated (FIND-14) |
| T55.D | FIND-16 | ✅ Mitigated (FIND-16) |
| T56.A | FIND-14 | ✅ Mitigated (FIND-14) |
| T57.T | — | 🔄 Mitigated by Platform |
| T58.D | FIND-16 | ✅ Mitigated (FIND-16) |
| T59.T | FIND-16 | ✅ Mitigated (FIND-16) |
| T60.A | FIND-16 | ✅ Mitigated (FIND-16) |
| T61.T | — | 🔄 Mitigated by Platform |
| T62.I | FIND-17 | ✅ Mitigated (FIND-17) |
| T63.T | — | 🔄 Mitigated by Platform |
| T64.T | — | 🔄 Mitigated by Platform |
| T65.I | FIND-17 | ✅ Mitigated (FIND-17) |
| T66.I | FIND-11 | ✅ Mitigated (FIND-11) |
| T67.T | — | 🔄 Mitigated by Platform |
| T68.R | FIND-11 | ✅ Mitigated (FIND-11) |
| T69.S | FIND-16 | ✅ Mitigated (FIND-16) |
| T70.I | FIND-16 | ✅ Mitigated (FIND-16) |
| T71.D | FIND-16 | ✅ Mitigated (FIND-16) |
| T72.S | FIND-16 | ✅ Mitigated (FIND-16) |
| T73.T | FIND-16 | ✅ Mitigated (FIND-16) |
| T74.D | FIND-16 | ✅ Mitigated (FIND-16) |
| T75.T | FIND-16 | ✅ Mitigated (FIND-16) |
| T76.D | FIND-16 | ✅ Mitigated (FIND-16) |
| T77.I | FIND-16 | ✅ Mitigated (FIND-16) |
| T78.D | FIND-16 | ✅ Mitigated (FIND-16) |
