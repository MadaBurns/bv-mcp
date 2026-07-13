# STRIDE-A Threat Analysis

> This analysis uses the standard **STRIDE** methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) extended with **Abuse Cases** (business logic abuse, workflow manipulation, feature misuse). The "A" column in tables below represents Abuse — a supplementary category covering threats where legitimate features are misused for unintended purposes. This is distinct from Elevation of Privilege (E), which covers authorization bypass.
>
> **Incremental report.** Threat IDs T01–T78 are inherited from baseline `threat-model-20260524-114907`; T79–T93 are new in this window (f75ca7d → 7a1c6b3). Each threat row carries a `Change` column: `Existing` (still present in current code), `Fixed` (remediated — code change cited), `New`, or `Removed`.

## Exploitability Tiers

| Tier | Label | Prerequisites | Assignment Rule |
|------|-------|---------------|----------------|
| **Tier 1** | Direct Exposure | `None` | Exploitable by unauthenticated external attacker with NO prior access. The prerequisite field MUST say `None`. |
| **Tier 2** | Conditional Risk | Single prerequisite: `Authenticated User`, `Privileged User`, `Internal Network`, or single `{Boundary} Access` | Requires exactly ONE form of access. The prerequisite field has ONE item. |
| **Tier 3** | Defense-in-Depth | `Host/OS Access`, `Admin Credentials`, `{Component} Compromise`, `Physical Access`, or MULTIPLE prerequisites joined with `+` | Requires significant prior breach, infrastructure access, or multiple combined prerequisites. |

## Summary

| Component | Link | S | T | R | I | D | E | A | Total | T1 | T2 | T3 | Risk |
|-----------|------|---|---|---|---|---|---|---|-------|----|----|----|------|
| HonoWorker | [Link](#honoworker) | 1 | 1 | 1 | 2 | 1 | 0 | 1 | 7 | 7 | 0 | 0 | Low |
| TierAuthResolver | [Link](#tierauthresolver) | 2 | 1 | 0 | 1 | 0 | 3 | 1 | 8 | 6 | 1 | 1 | Low |
| OAuthIssuer | [Link](#oauthissuer) | 1 | 1 | 0 | 1 | 1 | 1 | 1 | 6 | 3 | 1 | 2 | Low |
| McpExecutor | [Link](#mcpexecutor) | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 7 | 7 | 0 | 0 | Low |
| ToolsHandler | [Link](#toolshandler) | 0 | 1 | 0 | 1 | 1 | 1 | 2 | 6 | 6 | 0 | 0 | Low |
| M365Proxy | [Link](#m365proxy) | 1 | 0 | 0 | 2 | 1 | 0 | 1 | 5 | 0 | 5 | 0 | Medium |
| DomainSanitizer | [Link](#domainsanitizer) | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 3 | 3 | 0 | 0 | Low |
| SafeFetch | [Link](#safefetch) | 0 | 1 | 0 | 1 | 1 | 0 | 0 | 3 | 3 | 0 | 0 | Low |
| DnsResolver | [Link](#dnsresolver) | 1 | 1 | 0 | 0 | 1 | 0 | 1 | 4 | 2 | 2 | 0 | Low |
| RateLimiter | [Link](#ratelimiter) | 0 | 1 | 0 | 0 | 1 | 1 | 1 | 4 | 3 | 0 | 1 | Low |
| InternalRouter | [Link](#internalrouter) | 1 | 1 | 0 | 0 | 1 | 1 | 2 | 6 | 0 | 6 | 0 | Low |
| BrandAuditPipeline | [Link](#brandauditpipeline) | 0 | 1 | 0 | 1 | 1 | 0 | 1 | 4 | 0 | 4 | 0 | Medium |
| QuotaCoordinator | [Link](#quotacoordinator) | 0 | 1 | 0 | 0 | 1 | 0 | 0 | 2 | 0 | 0 | 2 | Low |
| ProfileAccumulator | [Link](#profileaccumulator) | 0 | 1 | 0 | 0 | 0 | 0 | 1 | 2 | 0 | 0 | 2 | Low |
| SessionStoreKV | [Link](#sessionstorekv) | 0 | 1 | 0 | 1 | 0 | 0 | 0 | 2 | 0 | 0 | 2 | Low |
| ScanCacheKV | [Link](#scancachekv) | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 1 | Low |
| RateLimitKV | [Link](#ratelimitkv) | 0 | 1 | 0 | 1 | 0 | 0 | 0 | 2 | 0 | 0 | 2 | Low |
| IntelligenceDB | [Link](#intelligencedb) | 0 | 1 | 1 | 1 | 0 | 0 | 0 | 3 | 0 | 0 | 3 | Low |
| BvWeb | [Link](#bvweb) | 1 | 0 | 0 | 1 | 1 | 0 | 0 | 3 | 0 | 2 | 1 | Low |
| BvRecon | [Link](#bvrecon) | 1 | 1 | 0 | 1 | 1 | 0 | 1 | 5 | 0 | 4 | 1 | Medium |
| BvTlsProbe | [Link](#bvtlsprobe) | 0 | 1 | 0 | 1 | 1 | 0 | 0 | 3 | 0 | 2 | 1 | Low |
| PublicDoH | [Link](#publicdoh) | 1 | 1 | 0 | 0 | 1 | 0 | 0 | 3 | 0 | 3 | 0 | Low |
| CertTransparency | [Link](#certtransparency) | 0 | 1 | 0 | 0 | 1 | 0 | 0 | 2 | 0 | 2 | 0 | Low |
| WhoisRdap | [Link](#whoisrdap) | 0 | 0 | 0 | 1 | 1 | 0 | 0 | 2 | 0 | 2 | 0 | Low |
| **Totals** | | **11** | **21** | **3** | **18** | **17** | **9** | **14** | **93** | **40** | **34** | **19** | |

---

## HonoWorker

**Trust Boundary:** CloudflareWorker
**Role:** Edge HTTP router — CORS/Origin checks, body-size limits, route gating, error wrapping, binding threading
**Data Flows:** DF01, DF03, DF04, DF05
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T01.S | Spoofing | Forged `Origin` header to mount cross-site/CSRF requests against `/mcp` | None | DF01 | `checkOrigin` allowlist + MCP-compliant rejection of unauthorized browser origins (`src/index.ts`) | Mitigated | Existing |
| T02.T | Tampering | Oversized request body to exhaust isolate memory/CPU | None | DF01 | 10 KB body cap (`MAX_REQUEST_BODY_BYTES`) read before parse | Mitigated | Existing |
| T03.R | Repudiation | Client denies issuing abusive requests; weak attribution | None | DF01 | Encrypted access log (D1) + analytics `keyHash`/`ipHash`; JSON-RPC error codes now emitted to analytics | Mitigated | Existing |
| T04.I | Information Disclosure | Verbose/stack-trace errors leak internals to clients | None | DF01 | `sanitizeErrorMessage` allowlist; generic fallback (`src/lib/json-rpc.ts`) | Mitigated | Existing |
| T05.I | Information Disclosure | `Host` header spoofing poisons OAuth issuer URL in discovery responses | None | DF04 | `resolveIssuer` honors `OAUTH_ISSUER` override; `resolveIssuerStrict` host-pinning added (`src/oauth/discovery.ts:18-39`); Host fallback remains the default when unset (deploy-config-gated) | Open | Existing |
| T06.D | Denial of Service | Unauthenticated request flood against `/mcp` | None | DF01 | Per-IP 50/min + 300/hr limits, global 500K/day ceiling | Mitigated | Existing |
| T07.A | Abuse | Distributed free-tier abuse consuming the shared global daily budget | None | DF01 | Per-IP distinct-domain daily cap (12/day, `checkDistinctDomainDailyLimit`, `src/lib/rate-limiter.ts:555-593`) + global quota DO + per-IP limits | Mitigated | Fixed |

#### Tier 2 — Conditional Risk

*No Tier 2 threats identified.*

#### Tier 3 — Defense-in-Depth

*No Tier 3 threats identified.*

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Elevation of Privilege | The router makes no authorization decisions; tier resolution and gating happen in TierAuthResolver/McpExecutor. |

---

## TierAuthResolver

**Trust Boundary:** CloudflareWorker
**Role:** Caller tier resolution & authentication — static keys, OAuth JWT, trial keys, bv-web validate-key, LKG fallback
**Data Flows:** DF03, DF19
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T08.S | Spoofing | API-key brute force / timing side-channel against static keys | None | DF03 | Constant-time XOR over SHA-256 digests for both dev-key slots (`src/lib/tier-auth.ts:50-59,168-171`) | Mitigated | Existing |
| T09.S | Spoofing | Forged OAuth JWT via `alg=none`/algorithm confusion | None | DF03 | HS256 pinned; algorithm checked before signature verify (`src/oauth/jwt.ts`) | Mitigated | Existing |
| T10.T | Tampering | Tier-claim tampering to obtain a higher tier | None | DF03 | Signature verified before claims parsed; `JwtIssuableTierSchema` enum (owner/developer/enterprise) | Mitigated | Existing |
| T11.I | Information Disclosure | Owner key leaks via `?api_key=` query into CDN/edge logs | None | DF03 | Bearer preferred; `REJECT_QUERY_API_KEY` rejection gate merged (`src/index.ts:106`) but defaults to accepting query keys — activation is deploy-config | Open | Existing |
| T12.E | Elevation of Privilege | Spoofing client IP to satisfy `OWNER_ALLOW_IPS` and gain owner tier | None | DF03 | IP sourced only from `cf-connecting-ip`; `applyOwnerIpGate()` now applied on every owner-tier path including JWT (`src/lib/tier-auth.ts:61-68,136`) | Mitigated | Existing |
| T14.A | Abuse | Caller supplies a tier hint expecting the server to honor it | None | DF03 | Tier is always server-derived; never read from caller input | Mitigated | Existing |

#### Tier 2 — Conditional Risk

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T13.E | Elevation of Privilege | Expired/exhausted trial key retains its tier during the 60 s resolution cache window | Authenticated User | DF03 | Fixed: cache hits now re-check `trialExpiresAt` and evict stale entries (`src/lib/tier-auth.ts:190-193`) | Mitigated | Fixed |

#### Tier 3 — Defense-in-Depth

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T92.E | Elevation of Privilege | A key revoked while bv-web is unavailable keeps its last-known-good paid tier for up to 24 h (LKG cache consulted on 5xx/network errors) | Authenticated User + BvWeb Compromise | DF19 | LKG never consulted on definitive 4xx rejections — revocation correctness preserved; 24 h TTL bounds the window (`src/lib/tier-auth.ts:302-317`) | Mitigated | New |

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Repudiation | Authentication outcomes are attributed via keyHash in analytics and access logs; no repudiation surface beyond T03.R. |
| Denial of Service | The resolver is a bounded in-process step; flood scenarios are covered at HonoWorker (T06.D) and RateLimiter. |

---

## OAuthIssuer

**Trust Boundary:** CloudflareWorker
**Role:** OAuth 2.1 issuer — register, authorize, PKCE token exchange, HS256 JWT, entitlements, token-version revocation
**Data Flows:** DF04, DF13, DF20
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T15.S | Spoofing | Abuse of open dynamic client registration to register rogue clients | None | DF04 | PKCE required; redirect_uri validation; per-IP 10/min + 30/hr registration limits (`src/oauth/register.ts`); reclassified false positive in the interim overlay — controls verified intact at HEAD | Mitigated | Existing |
| T16.T | Tampering | Authorization-code injection / replay | None | DF04 | PKCE S256 verify; single-use codes with TTL in KV (`src/oauth/token.ts`) | Mitigated | Existing |
| T18.D | Denial of Service | Token-endpoint flooding | None | DF04 | 30/min per-IP limit on `/oauth/token` | Mitigated | Existing |

#### Tier 2 — Conditional Risk

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T20.A | Abuse | Issued JWT retains an elevated tier after the customer's plan is downgraded, until `exp` | Authenticated User | DF20 | Fixed: per-subject token-version (`ver`) revocation via `bumpTokenVersion()` (`src/oauth/storage.ts:139-144`, verified in `src/lib/tier-auth.ts:128-135`) + JWT TTL clamped to the entitlement window with expired entitlements rejected (`src/oauth/token.ts:167-181`) | Mitigated | Fixed |

#### Tier 3 — Defense-in-Depth

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T17.I | Information Disclosure | Weak/short `OAUTH_SIGNING_SECRET` enabling JWT forgery | Host/OS Access | DF04 | `OAUTH_SIGNING_SECRET_MIN_BYTES` (≥32) enforced; 503 until set | Mitigated | Existing |
| T19.E | Elevation of Privilege | Spoofed bv-web entitlement response grants an unauthorized tier | BvWeb Compromise | DF20 | Authenticated service binding; tier value validated against enum | Mitigated | Existing |

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Repudiation | Token issuance is logged with jti/subject; covered by platform/audit logging rather than a distinct issuer threat. |

---

## McpExecutor

**Trust Boundary:** CloudflareWorker
**Role:** MCP request pipeline — session validation, rate/quota application, paid/auth tool gates, method routing, keyHash threading
**Data Flows:** DF05, DF06, DF07, DF12, DF18
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T21.S | Spoofing | Session-ID guessing or fixation to hijack a session | None | DF12 | 64-hex IDs from 32 random bytes; schema-validated; KV-backed | Mitigated | Existing |
| T22.T | Tampering | Malformed JSON-RPC / parameter tampering | None | DF05 | JSON-RPC validation + Zod `validateToolArgs`; `isJsonRpcNotification()` now correctly treats `id: null` as requiring a response (`src/mcp/execute.ts:906`) | Mitigated | Existing |
| T23.R | Repudiation | Tool invocation cannot be attributed to a principal | None | DF18 | `tool_call` analytics + encrypted access log (D1); keyHash now threaded through dispatch to handlers (3.17.2 fix) | Mitigated | Existing |
| T24.I | Information Disclosure | Cross-session/tenant data leakage via predictable cache keys | None | DF12 | Domain-scoped, version-stamped cache keys; no per-user secrets cached | Mitigated | Existing |
| T25.D | Denial of Service | Amplification via expensive methods (e.g., `scan_domain`) | None | DF07 | Per-tool daily quotas; 15 s scan / 8 s per-check budgets (clamped, env-overridable) | Mitigated | Existing |
| T26.E | Elevation of Privilege | Invoking a non-allowlisted, scan-only, paid-only, or auth-required tool directly | None | DF07 | `TOOL_REGISTRY` allowlist; `GATED_PAID_ONLY_TOOLS` → 403/-32003 (`src/mcp/execute.ts:604-606`); `AUTH_REQUIRED_TOOLS` → 401/-32001 (`src/mcp/execute.ts:601-603`) | Mitigated | Existing |
| T27.A | Abuse | Session-creation flooding to exhaust KV / session maps | None | DF12 | Session creation rate-limited per IP; LRU-capped maps | Mitigated | Existing |

#### Tier 2 — Conditional Risk

*No Tier 2 threats identified.*

#### Tier 3 — Defense-in-Depth

*No Tier 3 threats identified.*

#### Categories Not Applicable

*None — all seven STRIDE-A categories produced concrete threats for this component.*

---

## ToolsHandler

**Trust Boundary:** CloudflareWorker
**Role:** Tool registry + execution (80 tools), request-dedup, versioned caching, binding dispatch
**Data Flows:** DF07, DF08, DF09, DF10, DF11, DF14, DF17, DF24, DF26, DF27
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T28.T | Tampering | Tool arguments injected to reach DNS/fetch with unvalidated values | None | DF08 | Zod `validateToolArgs` + `validateDomain`/`sanitizeDomain` after schema | Mitigated | Existing |
| T29.I | Information Disclosure | `STRUCTURED_RESULT` JSON leaks internal data to clients | None | DF07 | Omitted for interactive LLM clients; findings auto-sanitized via `createFinding()`; redundant comment stripped for structuredContent-capable clients (`src/mcp/dispatch.ts:188-200`) | Mitigated | Existing |
| T30.D | Denial of Service | `batch_scan` resource exhaustion | None | DF07 | `budgetMs` 25 s, concurrency 3, per-domain `Promise.race`; `batch_scan` now paid-only | Mitigated | Existing |
| T31.E | Elevation of Privilege | Domain-optional tool bypassing domain validation | None | DF08 | `DOMAIN_OPTIONAL_TOOLS` explicit allowlist; args still Zod-validated; domain-required SSOT audit | Mitigated | Existing |
| T32.A | Abuse | Using the scanner as a recon/attack proxy against arbitrary third-party domains | None | DF09 | Fixed: offensive/multi-domain tools gated to paid tiers via `GATED_PAID_ONLY_TOOLS` → HTTP 403/-32003 (`src/lib/config.ts:340-378`), pinned to 0 in free/agent quota maps | Mitigated | Fixed |
| T33.A | Abuse | Repeated `force_refresh` to bust cache and amplify backend load | None | DF14 | Fixed: `FORCE_REFRESH_DAILY_LIMIT = 5` free-tier daily cache-bypass cap (`src/lib/config.ts:338`) in addition to per-tool quotas | Mitigated | Fixed |

#### Tier 2 — Conditional Risk

*No Tier 2 threats identified.*

#### Tier 3 — Defense-in-Depth

*No Tier 3 threats identified.*

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Spoofing | The handler trusts the principal resolved upstream (TierAuthResolver); no identity decisions are made here. |
| Repudiation | Tool calls are attributed via `tool_call` analytics and access logs (covered at T23.R). |

---

## M365Proxy

**Trust Boundary:** CloudflareWorker
**Role:** Identity-secops tool family (query_signins, query_ual, get_ca_policies, assess_coverage) proxying to bv-web internal M365 endpoints
**Data Flows:** DF24, DF25
**Pod Co-location:** N/A

> **[New]** Component added in this window (identity_secops, v3.17.x; caller-principal hardening in 3.17.2/3.18.0).

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

*No Tier 1 threats identified.* (Component floor: `Authenticated User` — `AUTH_REQUIRED_TOOLS` rejects unauthenticated callers pre-dispatch.)

#### Tier 2 — Conditional Risk

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T79.S | Spoofing | Stolen/leaked API key of any paid tier used to invoke identity-secops tools as that principal | Authenticated User | DF24 | `AUTH_REQUIRED_TOOLS` 401 gate (`src/mcp/execute.ts:601-603`) + handler backstop rejecting dispatch when `keyHash` absent (`src/handlers/tools.ts:909-912`); key hygiene/revocation via `ver` mechanism | Mitigated | New |
| T80.I | Information Disclosure | Cross-tenant M365 log access: caller supplies an arbitrary `ms_tenant_id`; bv-mcp forwards it with the trusted internal bearer, relying on bv-web to enforce that the `keyHash` principal owns the tenant | Authenticated User | DF25 | `keyHash` forwarded in request body (`src/tools/m365/proxy.ts:38`); enforcement is delegated cross-service — bv-mcp cannot verify it locally | Open | New |
| T81.I | Information Disclosure | Tenant-ID enumeration via differentiable `m365_proxy_*` error codes (404 vs 403 vs 500) | Authenticated User | DF25 | Error codes map upstream statuses distinctly (`src/tools/m365/proxy.ts:41-49`); no bleaching to a generic error | Open | New |
| T82.D | Denial of Service | Unmetered M365 queries: tools are in `INTENTIONALLY_UNLIMITED_TOOLS` (no per-tool daily quota), so an authenticated caller can amplify load/cost on bv-web and Microsoft Graph | Authenticated User | DF25 | Global/per-IP caps only (`src/lib/config.ts:457-467`); per-principal metering not implemented | Open | New |
| T83.A | Abuse | Using identity-secops tools to surveil an organization's sign-in/audit activity beyond the caller's legitimate scope | Authenticated User | DF25 | Read-only tool set; bv-web tenant-scope authorization on `keyHash`; access logged | Mitigated | New |

#### Tier 3 — Defense-in-Depth

*No Tier 3 threats identified.*

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Tampering | The proxy is read-only — it mutates no state in bv-mcp or M365; request bodies are fixed-shape JSON to an internal binding. |
| Repudiation | Every call carries the `keyHash` principal and is recorded in `tool_call` analytics and access logs. |
| Elevation of Privilege | Authorization decisions are delegated to bv-web; the bypass scenario is captured as T80.I (information disclosure via missing scope check). |

---

## DomainSanitizer

**Trust Boundary:** CloudflareWorker
**Role:** Domain input validation / SSRF input guard
**Data Flows:** DF08
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T34.T | Tampering | Unicode/punycode homoglyph or encoding tricks bypassing domain validation | None | DF08 | Fixed: mixed-script (confusable) label rejection in `hasMixedScripts()`/`sanitizeDomain` (`src/lib/sanitize.ts`), verified present at HEAD; normalization + public-suffix checks | Mitigated | Fixed |
| T35.I | Information Disclosure | SSRF — domain input crafted to resolve to internal/metadata IPs | None | DF08 | Reject IP literals, localhost/.local/.onion, RFC1918, rebinding hosts (`src/lib/config.ts`) | Mitigated | Existing |
| T36.E | Elevation of Privilege | DNS-rebinding TOCTOU: validated hostname resolves to an internal IP at fetch time | None | DF08 | Cloudflare `global_fetch_strictly_public` blocks RFC1918 at runtime; SafeFetch re-validation | Mitigated | Existing |

#### Tier 2 — Conditional Risk

*No Tier 2 threats identified.*

#### Tier 3 — Defense-in-Depth

*No Tier 3 threats identified.*

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Spoofing | The sanitizer processes data, not identities. |
| Repudiation | Stateless validation library; no audit surface of its own. |
| Denial of Service | Validation is O(label count) string work; flood scenarios are covered upstream. |
| Abuse | Feature-misuse scenarios route through ToolsHandler (T32.A). |

---

## SafeFetch

**Trust Boundary:** CloudflareWorker
**Role:** Egress SSRF guard for attacker-influenced URLs
**Data Flows:** DF10
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T37.T | Tampering | Redirect-based SSRF — `Location:` header pointing at internal targets | None | DF10 | `redirect:'manual'` + per-hop re-validation through SafeFetch (`src/lib/safe-fetch.ts`) | Mitigated | Existing |
| T38.I | Information Disclosure | Attacker-influenced URL (BIMI `l=`/`a=`) fetched against internal services | None | DF10 | HTTPS-only, blocklist, userinfo rejection in SafeFetch; new outbound paths (lookalike web probe, brand CSC enrichment) verified to use safeFetch; RDAP enrichment restricted to a hardcoded registry-endpoint allowlist (`src/tools/check-lookalikes.ts:641-668`) | Mitigated | Existing |
| T39.D | Denial of Service | Slowloris/large-response from an attacker-controlled fetch target | None | DF10 | `AbortSignal.timeout` + total-budget caps (`check_http_security` 10 s) | Mitigated | Existing |

#### Tier 2 — Conditional Risk

*No Tier 2 threats identified.*

#### Tier 3 — Defense-in-Depth

*No Tier 3 threats identified.*

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Spoofing | Egress library; no identity surface. |
| Repudiation | Stateless; outbound requests attributed via the invoking tool's logs. |
| Elevation of Privilege | No authorization decisions made here. |
| Abuse | Abuse-of-fetch scenarios are captured at ToolsHandler (T32.A). |

---

## DnsResolver

**Trust Boundary:** CloudflareWorker
**Role:** DoH egress (multi-resolver chain)
**Data Flows:** DF09, DF21
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T42.D | Denial of Service | Using the scanner to flood a victim domain/resolver with DNS queries (reflection) | None | DF21 | Fixed: multi-domain/offensive tools paid-gated (`GATED_PAID_ONLY_TOOLS`) + 12 distinct domains/day per unauthenticated IP; queries target public DoH, not arbitrary victims | Mitigated | Fixed |
| T43.A | Abuse | Driving DNS queries for reconnaissance / resolver cache snooping | None | DF21 | Fixed: distinct-domain daily cap throttles enumeration breadth (`src/lib/rate-limiter.ts:555-593`); rate limits; bounded record types | Mitigated | Fixed |

#### Tier 2 — Conditional Risk

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T40.S | Spoofing | Malicious/MITM DoH resolver returns forged records | Internal Network | DF21 | TLS to resolvers; secondary resolver uses `X-BV-Token`; multi-resolver chain | Mitigated | Existing |
| T41.T | Tampering | DNS-response tampering that skews scan grades | Internal Network | DF21 | TLS transport; cross-resolver corroboration; DNSSEC checks where applicable | Mitigated | Existing |

#### Tier 3 — Defense-in-Depth

*No Tier 3 threats identified.*

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Repudiation | Resolver egress is attributed via tool-call logging; no distinct repudiation surface. |
| Information Disclosure | The resolver queries public DNS data only; SSRF-style disclosure is covered at DomainSanitizer/SafeFetch. |
| Elevation of Privilege | No authorization decisions made here. |

---

## RateLimiter

**Trust Boundary:** CloudflareWorker
**Role:** Rate limits, quotas, distinct-domain cap, fuzzing detection
**Data Flows:** DF06, DF15, DF16
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T44.T | Tampering | Forging client IP to evade per-IP counters | None | DF06 | IP sourced only from `cf-connecting-ip`; `x-forwarded-for` never trusted | Mitigated | Existing |
| T46.E | Elevation of Privilege | Distributed IPs (botnet) bypassing per-IP limits | None | DF06 | Fixed: per-IP distinct-domain daily cap (12) narrows per-IP value; global 500K/day ceiling enforced by QuotaCoordinator DO | Mitigated | Fixed |
| T47.A | Abuse | Low-and-slow fuzzing/enumeration kept under per-IP thresholds | None | DF15 | Fuzzing detector sliding-window scoring + webhook alerts; JSON-RPC error-code analytics added | Mitigated | Existing |

#### Tier 2 — Conditional Risk

*No Tier 2 threats identified.*

#### Tier 3 — Defense-in-Depth

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T45.D | Denial of Service | KV unavailability disabling rate-limit enforcement (fail-open) | RateLimitKV Compromise | DF15 | In-memory fallback + QuotaCoordinator DO with circuit breaker; distinct-domain cap is deliberately fail-open (best-effort) | Mitigated | Existing |

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Spoofing | Identity spoofing against limits is captured as T44.T (IP forging). |
| Repudiation | Counter state is operational, not an audit record. |
| Information Disclosure | Counters contain hashed principals only. |

---

## InternalRouter

**Trust Boundary:** CloudflareWorker
**Role:** Service-binding `/internal/*` surface — tools, analytics, tenants, credential-minting routes; agent-chat allowlist
**Data Flows:** DF02
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

*No Tier 1 threats identified.* (Component floor: `Internal Network` — reachable only via in-account service bindings.)

#### Tier 2 — Conditional Risk

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T48.S | Spoofing | Public attacker reaching `/internal/*` by manipulating proxy headers | Internal Network | DF02 | `isPublicInternetRequest` rejects any public proxy header → 404 (`src/internal.ts:123-125`) | Mitigated | Existing |
| T49.T | Tampering | Oversized/abusive internal batch payload | Internal Network | DF02 | 256 KB batch limit; tool names `^[a-z_]+$` ≤30 chars; arg-key allowlist | Mitigated | Existing |
| T50.D | Denial of Service | Batch endpoint resource exhaustion (up to 500 domains) | Internal Network | DF02 | Max 500 domains, concurrency cap, per-domain budget | Mitigated | Existing |
| T51.E | Elevation of Privilege | Reaching credential-minting routes (`/internal/oauth/grants`, `/internal/trial-keys/*`) without authorization | Internal Network | DF02 | Strict `BV_WEB_INTERNAL_KEY` bearer gate: 503 if unset, 401 on missing/wrong | Mitigated | Existing |
| T52.A | Abuse | Bearer auth on `/internal/tools/*` and `/internal/analytics/*` left opt-in, exposing them to any in-account binding | Internal Network | DF02 | Fixed: `internalLenientAuthGate` is secure-by-default — active unless `REQUIRE_INTERNAL_AUTH=false`, 503 when `BV_WEB_INTERNAL_KEY` unset, 401 on bad bearer (`src/internal.ts:165-182`) | Mitigated | Fixed |
| T93.A | Abuse | Internal caller omits or alters the `x-bv-caller: agent-chat` header to escape the 13-tool read-only allowlist | Internal Network | DF02 | Header rides the authenticated binding only; allowlist enforced at both `/internal/tools/call` and `/batch` (`src/internal.ts:217-223,419-422`) with tool-name normalization before the check; bv-web gateway enforces the same allowlist independently; exact-set audit test | Mitigated | New |

#### Tier 3 — Defense-in-Depth

*No Tier 3 threats identified.*

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Repudiation | Internal calls are attributed to the calling worker via binding identity and logs. |
| Information Disclosure | Internal responses go only to authenticated sibling workers; public exposure is captured as T48.S. |

---

## BrandAuditPipeline

**Trust Boundary:** CloudflareWorker
**Role:** Brand-audit orchestration + cron/queue — tiered discovery, registrar/CT/WHOIS enrichment
**Data Flows:** DF11, DF22, DF23
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

*No Tier 1 threats identified.* (Component floor: `Authenticated User` — brand-audit tools are paid-gated.)

#### Tier 2 — Conditional Risk

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T53.T | Tampering | Auditing a watched domain the caller does not own | Authenticated User | DF11 | Watched-domain validated at register time; ownership attestation remains caller-supplied (no DNS-TXT challenge yet) | Open | Existing |
| T54.I | Information Disclosure | Tiered discovery reveals competitor/third-party infrastructure | Authenticated User | DF22 | Opt-out enforcement; tier gating of discovery modes; brand tools now developer+ only — ownership attestation residual remains | Open | Existing |
| T55.D | Denial of Service | Expensive tiered discovery / brand-audit queue flooding | Authenticated User | DF11 | Per-tier quotas, processing budget, reaper for stale jobs; request-dedup absorbs client retries of `*_start` | Mitigated | Existing |
| T56.A | Abuse | Mass third-party domain enumeration via repeated brand audits | Authenticated User | DF22 | Per-tier daily quotas + opt-out registry; ownership attestation still caller-supplied (residual — see FIND-14) | Open | Existing |

#### Tier 3 — Defense-in-Depth

*No Tier 3 threats identified.*

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Spoofing | Caller identity is resolved upstream; watched-domain spoofing is captured as T53.T (tampering). |
| Repudiation | Audit rows record the owning principal (`owner_id`). |
| Elevation of Privilege | Tier gating decisions happen in McpExecutor. |

---

## QuotaCoordinator

**Trust Boundary:** DurableObjects
**Role:** Durable Object — cross-isolate quota coordination
**Data Flows:** DF16
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

*No Tier 1 threats identified.* (Component floor: `Host/OS Access` — no listener; in-account binding only.)

#### Tier 2 — Conditional Risk

*No Tier 2 threats identified.*

#### Tier 3 — Defense-in-Depth

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T57.T | Tampering | Manipulating DO state to reset/inflate quota counters | CloudflareWorker Compromise | DF16 | DO reachable only via in-account binding; no external listener | Platform | Existing |
| T58.D | Denial of Service | Single-instance DO bottleneck or unavailability disabling global quota | Host/OS Access | DF16 | Circuit-breaker fallback to KV/in-memory limiting | Mitigated | Existing |

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Spoofing | Reachable only via in-account binding; no caller identity surface. |
| Repudiation | Counter state is operational, not audit evidence. |
| Information Disclosure | Holds only aggregate counters keyed by hashed principals. |
| Elevation of Privilege | Makes no authorization decisions. |
| Abuse | No business workflow exposed. |

---

## ProfileAccumulator

**Trust Boundary:** DurableObjects
**Role:** Durable Object — adaptive-scoring EMA persistence
**Data Flows:** DF17
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

*No Tier 1 threats identified.* (Component floor: `Host/OS Access`.)

#### Tier 2 — Conditional Risk

*No Tier 2 threats identified.*

#### Tier 3 — Defense-in-Depth

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T59.T | Tampering | Poisoning adaptive weights via crafted telemetry | CloudflareWorker Compromise | DF17 | Maturity-gated blending (`MATURITY_THRESHOLD`); static fallback if DO unavailable | Mitigated | Existing |
| T60.A | Abuse | Sustained scans biasing the EMA to skew future scores | CloudflareWorker Compromise | DF17 | Maturity threshold before blending; bounded influence per profile | Mitigated | Existing |

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Spoofing | In-account binding only. |
| Repudiation | Aggregated statistics, not audit evidence. |
| Information Disclosure | Holds aggregate scoring statistics only. |
| Denial of Service | DO unavailability degrades to static weights (fail-soft). |
| Elevation of Privilege | Makes no authorization decisions. |

---

## SessionStoreKV

**Trust Boundary:** PlatformStorage
**Role:** KV — sessions, OAuth codes, JTI revocation, token-version counters
**Data Flows:** DF12, DF13
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

*No Tier 1 threats identified.* (Component floor: `Host/OS Access`.)

#### Tier 2 — Conditional Risk

*No Tier 2 threats identified.*

#### Tier 3 — Defense-in-Depth

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T61.T | Tampering | Tampering with session/auth-code records | CloudflareWorker Compromise | DF12 | KV reachable only via in-account binding; session schema validated on read | Platform | Existing |
| T62.I | Information Disclosure | Disclosure of OAuth codes / JTI if the KV namespace is exposed | Host/OS Access | DF13 | Fixed: AES-256-GCM KV envelope applied on the OAuth grants path (`src/lib/kv-envelope.ts`, wired at `src/internal.ts:299`); short single-use code TTL; platform encryption at rest | Mitigated | Fixed |

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Spoofing | No listener; in-account binding only. |
| Repudiation | Session records are operational state. |
| Denial of Service | KV outage degrades to in-isolate session map (fail-soft). |
| Elevation of Privilege | Storage layer makes no authorization decisions. |
| Abuse | No business workflow exposed. |

---

## ScanCacheKV

**Trust Boundary:** PlatformStorage
**Role:** KV — cached scan/check results under version-stamped keys
**Data Flows:** DF14
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

*No Tier 1 threats identified.* (Component floor: `Host/OS Access`.)

#### Tier 2 — Conditional Risk

*No Tier 2 threats identified.*

#### Tier 3 — Defense-in-Depth

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T63.T | Tampering | Cache poisoning — tampered cached results served to clients | CloudflareWorker Compromise | DF14 | KV in-account only; 5 min TTL; version-stamped keys (`buildScanCacheKey`) invalidate stale entries on server/dns-checks bumps | Platform | Existing |

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Spoofing | No listener; in-account binding only. |
| Repudiation | Cache is operational state. |
| Information Disclosure | Contains only public DNS scan results keyed by domain. |
| Denial of Service | Cache outage falls through to live checks. |
| Elevation of Privilege | No authorization decisions. |
| Abuse | Cache-busting abuse is captured at T33.A. |

---

## RateLimitKV

**Trust Boundary:** PlatformStorage
**Role:** KV — rate/fuzzing counters, trial keys, distinct-domain markers, request-dedup records
**Data Flows:** DF15
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

*No Tier 1 threats identified.* (Component floor: `Host/OS Access`.)

#### Tier 2 — Conditional Risk

*No Tier 2 threats identified.*

#### Tier 3 — Defense-in-Depth

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T64.T | Tampering | Tampering with counters or trial keys to evade limits/escalate tier | CloudflareWorker Compromise | DF15 | KV in-account only; DO fallback for quota | Platform | Existing |
| T65.I | Information Disclosure | Disclosure of trial keys / dedup records if the KV namespace is exposed | Host/OS Access | DF15 | Platform encryption at rest; trial keys bounded-lifetime; AES-256-GCM envelope helper exists (`src/lib/kv-envelope.ts`) but trial-key records are **not yet wrapped** (`src/lib/trial-keys.ts` unchanged in window) | Open | Existing |

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Spoofing | No listener; in-account binding only. |
| Repudiation | Counters are operational state. |
| Denial of Service | Fail-open design covered at T45.D. |
| Elevation of Privilege | No authorization decisions. |
| Abuse | No business workflow exposed. |

---

## IntelligenceDB

**Trust Boundary:** PlatformStorage
**Role:** D1 — MCP access logs with AES-GCM-encrypted IP evidence, 90-day retention
**Data Flows:** DF18
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

*No Tier 1 threats identified.* (Component floor: `Host/OS Access`.)

#### Tier 2 — Conditional Risk

*No Tier 2 threats identified.*

#### Tier 3 — Defense-in-Depth

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T66.I | Information Disclosure | Disclosure of client IP evidence from access logs | Host/OS Access | DF18 | AES-GCM encryption with versioned key; 90-day retention | Mitigated | Existing |
| T67.T | Tampering | Tampering with access logs to hide abuse activity | CloudflareWorker Compromise | DF18 | D1 in-account only; append-oriented write pattern | Platform | Existing |
| T68.R | Repudiation | Insufficient retention undermines forensic attribution | Host/OS Access | DF18 | Fixed: scheduled retention job deletes `mcp_access_log` rows older than 90 days via parameterized D1 query (`src/scheduled.ts:89-100`), making the retention window enforced rather than advisory | Mitigated | Fixed |

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Spoofing | No listener; in-account binding only. |
| Denial of Service | Log-write failure is fail-soft and does not block requests. |
| Elevation of Privilege | No authorization decisions. |
| Abuse | No business workflow exposed. |

---

## BvWeb

**Trust Boundary:** BlackVeilServices
**Role:** Sibling worker — validate-key, OAuth entitlements, internal M365 proxy endpoints
**Data Flows:** DF19, DF20, DF25
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

*No Tier 1 threats identified.* (Component floor: `Internal Network`.)

#### Tier 2 — Conditional Risk

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T70.I | Information Disclosure | Entitlement/plan data exposed in transit between workers | Internal Network | DF20 | In-account service binding (not public network); TLS within Cloudflare | Mitigated | Existing |
| T71.D | Denial of Service | bv-web unavailability blocking paid-tier authentication | Internal Network | DF19 | Static `BV_API_KEY` fallback; free tier unaffected; LKG tier cache now preserves paying customers through transient 5xx (`src/lib/tier-auth.ts:302-317`) | Mitigated | Existing |

#### Tier 3 — Defense-in-Depth

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T69.S | Spoofing | A compromised bv-web returns forged entitlements granting an elevated tier | BvWeb Compromise | DF20 | Authenticated binding (`BV_WEB_INTERNAL_KEY`); tier value validated against enum | Mitigated | Existing |

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Tampering | Covered by the spoofed-response scenario (T69.S); binding traffic is in-account. |
| Repudiation | Cross-worker calls logged on both sides. |
| Elevation of Privilege | Tier validation against enum captured under T69.S/T10.T. |
| Abuse | bv-web's own business logic is out of scope for this repo's model. |

---

## BvRecon

**Trust Boundary:** BlackVeilServices
**Role:** Operator-deploy-only bv-recon worker — OSINT investigations, bucket scans, realtime threat feed (start→poll), enrichment
**Data Flows:** DF26
**Pod Co-location:** N/A

> **[New]** Component added in this window (`BV_RECON` binding, fail-soft `unprovisioned` when absent).

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

*No Tier 1 threats identified.* (Component floor: recon tools are paid-gated — `Authenticated User`.)

#### Tier 2 — Conditional Risk

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T85.T | Tampering | Upstream recon payloads (bucket names, object keys, threat-feed entries) are attacker-controllable and flow into finding metadata / `structuredContent` consumed by LLMs (indirect prompt injection) | Authenticated User | DF26 | `sanitizeUpstreamObject/Value` strips C0/ANSI and clamps depth/length on all recon payloads (`src/lib/sanitize-upstream.ts:49-69`); injection-focused tests for the bucket/threat-feed spread pattern are incomplete | Open | New |
| T86.I | Information Disclosure | Cross-principal access to investigation/bucket-scan results by polling another caller's operation ID (`osint_investigation_status/report`, `scan_buckets_status/findings`) | Authenticated User | DF26 | IDs are opaque bv-recon UUIDs; bv-mcp forwards them with the shared bearer and no principal binding (`src/tools/osint-investigate.ts:115-145`, `src/lib/recon-binding.ts:141-212`) — ownership enforcement is assumed in bv-recon and unverified from this repo | Open | New |
| T87.D | Denial of Service | OSINT/bucket job flooding spawning expensive backend work on bv-recon | Authenticated User | DF26 | `*_start` tools are paid-only (403 for free/agent); request-dedup absorbs retries; per-tier daily scan quotas | Mitigated | New |
| T88.A | Abuse | People-OSINT (username/email investigations) used to investigate arbitrary third parties | Authenticated User | DF26 | People-OSINT restricted to owner/enterprise tiers; all recon tools paid-gated; investigations logged per principal | Mitigated | New |

#### Tier 3 — Defense-in-Depth

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T84.S | Spoofing | Compromised bv-recon returns forged intelligence that lands in customer reports | BvRecon Compromise | DF26 | Bearer-authenticated in-account binding; operator-controlled deployment; Zod response validation (lenient) | Mitigated | New |

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Repudiation | Investigation lifecycle is attributed via `tool_call` analytics and per-principal dedup records. |
| Elevation of Privilege | Tier gating for recon tools is enforced upstream in McpExecutor (T26.E). |

---

## BvTlsProbe

**Trust Boundary:** BlackVeilServices
**Role:** Operator-deploy-only bv-tls-probe worker — version-aware TLS handshakes enriching `check_ssl`
**Data Flows:** DF27
**Pod Co-location:** N/A

> **[New]** Component added in this window (`BV_TLS_PROBE` binding, fail-soft no-op when absent).

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

*No Tier 1 threats identified.* (Component floor: `Internal Network` — binding reachable only in-account.)

#### Tier 2 — Conditional Risk

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T89.I | Information Disclosure | Probe used as an internal-network reachability/timing oracle if bv-tls-probe does not validate target hosts | Internal Network | DF27 | Domain is pre-validated by `check_ssl`'s sanitizer before reaching the binding; host validation inside bv-tls-probe is assumed and unverified from this repo (`src/lib/tls-probe-binding.ts:63-83`) | Open | New |
| T91.D | Denial of Service | Slow/hanging probe targets consume the `check_ssl` latency budget | Internal Network | DF27 | 8 s probe timeout (`TLS_PROBE_TIMEOUT_MS`); fail-soft merge — absent/failed probe yields no finding | Mitigated | New |

#### Tier 3 — Defense-in-Depth

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T90.T | Tampering | Compromised bv-tls-probe returns forged TLS-version results skewing SSL scores | BvTlsProbe Compromise | DF27 | Bearer-authenticated in-account binding; operator-controlled; hardcoded literal matching in `isWeakTlsVersion()` (`src/lib/tls-probe-binding.ts:52-55`) | Mitigated | New |

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Spoofing | Bearer-authenticated binding with no caller-identity surface beyond the shared token (covered under T90.T). |
| Repudiation | Probe calls are attributed via the invoking tool's logging. |
| Elevation of Privilege | No authorization decisions. |
| Abuse | The probe exposes no business workflow; abuse-of-scanning is captured at ToolsHandler (T32.A). |

---

## PublicDoH

**Trust Boundary:** Internet
**Role:** Public DoH resolvers (Cloudflare/Google) for DNS queries
**Data Flows:** DF21
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

*No Tier 1 threats identified.* (Threats require on-path/network position relative to resolver egress.)

#### Tier 2 — Conditional Risk

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T72.S | Spoofing | Resolver spoofing/poisoning returning forged answers | Internal Network | DF21 | TLS to resolvers; multi-resolver chain; secondary `X-BV-Token` | Mitigated | Existing |
| T73.T | Tampering | DNS response tampering on the wire | Internal Network | DF21 | TLS transport (DoH) | Mitigated | Existing |
| T74.D | Denial of Service | Resolver outage degrading scan availability | Internal Network | DF21 | Fallback chain (empty → bv-dns → Google) | Mitigated | Existing |

#### Tier 3 — Defense-in-Depth

*No Tier 3 threats identified.*

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Repudiation | External resolver; no audit surface in this repo. |
| Information Disclosure | Queries carry only public domain names. |
| Elevation of Privilege | No authorization relationship. |
| Abuse | Abuse-of-DNS scenarios captured at DnsResolver (T43.A). |

---

## CertTransparency

**Trust Boundary:** Internet
**Role:** CT-log enumeration (certstream/crt.sh) for discovery
**Data Flows:** DF22
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

*No Tier 1 threats identified.*

#### Tier 2 — Conditional Risk

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T75.T | Tampering | Malicious CT data inflating brand-audit candidate sets | Internal Network | DF22 | crt.sh fallback + candidate validation; result counts capped and direct fallback bodies rejected above 5 MiB before parsing | Mitigated | Strengthened |
| T76.D | Denial of Service | CT source outage or oversized response degrading discovery | Internal Network | DF22 | Direct crt.sh fallback with timeout/jittered backoff plus a strict streaming byte ceiling | Mitigated | Strengthened |

#### Tier 3 — Defense-in-Depth

*No Tier 3 threats identified.*

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Spoofing | CT data authenticity is covered under T75.T (tampering). |
| Repudiation | External service; no audit surface here. |
| Information Disclosure | CT logs are public data. |
| Elevation of Privilege | No authorization relationship. |
| Abuse | Discovery abuse captured at BrandAuditPipeline (T56.A). |

---

## WhoisRdap

**Trust Boundary:** Internet
**Role:** WHOIS/RDAP registration lookups (+ hardcoded registry RDAP allowlist for lookalike enrichment)
**Data Flows:** DF23
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

*No Tier 1 threats identified.*

#### Tier 2 — Conditional Risk

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status | Change |
|----|----------|--------|---------------|---------------|------------|--------|--------|
| T77.I | Information Disclosure | Untrusted WHOIS/RDAP data injected into rendered reports (stored content) | Internal Network | DF23 | Output sanitization via `createFinding()` auto-sanitize; lookalike RDAP enrichment restricted to hardcoded registry endpoints | Mitigated | Existing |
| T78.D | Denial of Service | WHOIS/RDAP source outage degrading enrichment | Internal Network | DF23 | RDAP-only fallback; KV-cached IANA referrals; 2.5 s enrichment timeout, fail-soft (no downgrade suppression of real threats) | Mitigated | Existing |

#### Tier 3 — Defense-in-Depth

*No Tier 3 threats identified.*

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Spoofing | Registration-data authenticity is covered under T77.I. |
| Tampering | On-wire tampering is mitigated by TLS and covered by the same controls as T77.I. |
| Repudiation | External service; no audit surface here. |
| Elevation of Privilege | No authorization relationship. |
| Abuse | Enrichment abuse is bounded by paid gating and caps (T32.A). |
