# STRIDE + Abuse Cases — Threat Analysis

> This analysis uses the standard **STRIDE** methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) extended with **Abuse Cases** (business logic abuse, workflow manipulation, feature misuse). The "A" column in tables below represents Abuse — a supplementary category covering threats where legitimate features are misused for unintended purposes. This is distinct from Elevation of Privilege (E), which covers authorization bypass.

> **Scope note:** External actors (`McpClient`, `Operator`) are threat *sources*, not targets, and are excluded from STRIDE component sections per methodology. The 23 architecture elements therefore map to 21 analyzed components (23 minus the 2 external actors).

## Exploitability Tiers

Threats are classified into three exploitability tiers based on the prerequisites an attacker needs:

| Tier | Label | Prerequisites | Assignment Rule |
|------|-------|---------------|----------------|
| **Tier 1** | Direct Exposure | `None` | Exploitable by unauthenticated external attacker with NO prior access. The prerequisite field MUST say `None`. |
| **Tier 2** | Conditional Risk | Single prerequisite: `Authenticated User`, `Privileged User`, `Internal Network`, or single `{Boundary} Access` | Requires exactly ONE form of access. The prerequisite field has ONE item. |
| **Tier 3** | Defense-in-Depth | `Host/OS Access`, `Admin Credentials`, `{Component} Compromise`, `Physical Access`, or MULTIPLE prerequisites joined with `+` | Requires significant prior breach, infrastructure access, or multiple combined prerequisites. |

## Summary

| Component | Link | S | T | R | I | D | E | A | Total | T1 | T2 | T3 | Risk |
|-----------|------|---|---|---|---|---|---|---|-------|----|----|----|------|
| HonoWorker | [Link](#honoworker) | 1 | 1 | 1 | 2 | 1 | 0 | 1 | 7 | 7 | 0 | 0 | Medium |
| TierAuthResolver | [Link](#tierauthresolver) | 2 | 1 | 0 | 1 | 0 | 2 | 1 | 7 | 6 | 1 | 0 | High |
| OAuthIssuer | [Link](#oauthissuer) | 1 | 1 | 0 | 1 | 1 | 1 | 1 | 6 | 3 | 1 | 2 | High |
| McpExecutor | [Link](#mcpexecutor) | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 7 | 7 | 0 | 0 | Medium |
| ToolsHandler | [Link](#toolshandler) | 0 | 1 | 0 | 1 | 1 | 1 | 2 | 6 | 6 | 0 | 0 | High |
| DomainSanitizer | [Link](#domainsanitizer) | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 3 | 3 | 0 | 0 | High |
| SafeFetch | [Link](#safefetch) | 0 | 1 | 0 | 1 | 1 | 0 | 0 | 3 | 3 | 0 | 0 | High |
| DnsResolver | [Link](#dnsresolver) | 1 | 1 | 0 | 0 | 1 | 0 | 1 | 4 | 2 | 2 | 0 | Medium |
| RateLimiter | [Link](#ratelimiter) | 0 | 1 | 0 | 0 | 1 | 1 | 1 | 4 | 3 | 0 | 1 | Medium |
| InternalRouter | [Link](#internalrouter) | 1 | 1 | 0 | 0 | 1 | 1 | 1 | 5 | 0 | 5 | 0 | Medium |
| BrandAuditPipeline | [Link](#brandauditpipeline) | 0 | 1 | 0 | 1 | 1 | 0 | 1 | 4 | 0 | 4 | 0 | Medium |
| QuotaCoordinator | [Link](#quotacoordinator) | 0 | 1 | 0 | 0 | 1 | 0 | 0 | 2 | 0 | 0 | 2 | Low |
| ProfileAccumulator | [Link](#profileaccumulator) | 0 | 1 | 0 | 0 | 0 | 0 | 1 | 2 | 0 | 0 | 2 | Low |
| SessionStoreKV | [Link](#sessionstorekv) | 0 | 1 | 0 | 1 | 0 | 0 | 0 | 2 | 0 | 0 | 2 | Medium |
| ScanCacheKV | [Link](#scancachekv) | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 1 | Low |
| RateLimitKV | [Link](#ratelimitkv) | 0 | 1 | 0 | 1 | 0 | 0 | 0 | 2 | 0 | 0 | 2 | Low |
| IntelligenceDB | [Link](#intelligencedb) | 0 | 1 | 1 | 1 | 0 | 0 | 0 | 3 | 0 | 0 | 3 | Medium |
| BvWeb | [Link](#bvweb) | 1 | 0 | 0 | 1 | 1 | 0 | 0 | 3 | 0 | 2 | 1 | Medium |
| PublicDoH | [Link](#publicdoh) | 1 | 1 | 0 | 0 | 1 | 0 | 0 | 3 | 0 | 3 | 0 | Medium |
| CertTransparency | [Link](#certtransparency) | 0 | 1 | 0 | 0 | 1 | 0 | 0 | 2 | 0 | 2 | 0 | Low |
| WhoisRdap | [Link](#whoisrdap) | 0 | 0 | 0 | 1 | 1 | 0 | 0 | 2 | 0 | 2 | 0 | Low |
| **Totals** | | **9** | **19** | **3** | **14** | **14** | **8** | **11** | **78** | **40** | **22** | **16** | |

---

## HonoWorker

**Trust Boundary:** CloudflareWorker
**Role:** Edge HTTP router — CORS/Origin checks, body-size limits, route gating, error wrapping.
**Data Flows:** DF01, DF03, DF04, DF05
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status |
|----|----------|--------|---------------|---------------|------------|--------|
| T01.S | Spoofing | Forged `Origin` header to mount cross-site/CSRF requests against `/mcp` | None | DF01 | `checkOrigin` allowlist + MCP-compliant rejection of unauthorized browser origins (`src/index.ts`) | Mitigated |
| T02.T | Tampering | Oversized request body to exhaust isolate memory/CPU | None | DF01 | 10 KB body cap (`MAX_REQUEST_BODY_BYTES`) read before parse | Mitigated |
| T03.R | Repudiation | Client denies issuing abusive requests; weak attribution | None | DF01 | Encrypted access log (D1) + analytics `keyHash`/`ipHash` | Mitigated |
| T04.I | Information Disclosure | Verbose/stack-trace errors leak internals to clients | None | DF01 | `sanitizeErrorMessage` allowlist; generic fallback (`src/lib/json-rpc.ts`) | Mitigated |
| T05.I | Information Disclosure | `Host` header spoofing poisons OAuth issuer URL in discovery responses | None | DF04 | JWT `aud` validation; `OAUTH_ISSUER` override recommended in prod | Mitigated |
| T06.D | Denial of Service | Unauthenticated request flood against `/mcp` | None | DF01 | Per-IP 50/min + 300/hr limits, global 500K/day ceiling | Mitigated |
| T07.A | Abuse | Distributed free-tier abuse consuming the shared global daily budget | None | DF01 | Global quota DO + per-IP limits; residual budget contention | Mitigated |

#### Tier 2 — Conditional Risk

*No Tier 2 threats identified.*

#### Tier 3 — Defense-in-Depth

*No Tier 3 threats identified.*

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Elevation of Privilege | HonoWorker performs no authorization itself; tiering/authz is delegated to TierAuthResolver and McpExecutor. |

## TierAuthResolver

**Trust Boundary:** CloudflareWorker
**Role:** Resolves caller tier — constant-time `BV_API_KEY` compare, OAuth JWT verify, trial-key/bv-web lookup, `OWNER_ALLOW_IPS` gate.
**Data Flows:** DF03, DF19
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status |
|----|----------|--------|---------------|---------------|------------|--------|
| T08.S | Spoofing | API-key brute force / timing side-channel against `BV_API_KEY` | None | DF03 | Constant-time XOR over SHA-256 digests (`src/lib/tier-auth.ts`) | Mitigated |
| T09.S | Spoofing | Forged OAuth JWT via `alg=none`/algorithm confusion | None | DF03 | HS256 pinned; algorithm checked before signature verify (`src/oauth/jwt.ts`) | Mitigated |
| T10.T | Tampering | Tier-claim tampering to obtain a higher tier | None | DF03 | Signature verified before claims parsed; `JwtIssuableTierSchema` enum (owner/developer/enterprise) | Mitigated |
| T11.I | Information Disclosure | Owner key leaks via `?api_key=` query into CDN/edge logs | None | DF03 | Bearer preferred; `?api_key=` deprecated with `Sunset` header | Mitigated |
| T12.E | Elevation of Privilege | Spoofing client IP to satisfy `OWNER_ALLOW_IPS` and gain owner tier | None | DF03 | IP sourced only from `cf-connecting-ip`; owner→partner downgrade off-allowlist | Mitigated |
| T14.A | Abuse | Caller supplies a tier hint expecting the server to honor it | None | DF03 | Tier is always server-derived; never read from caller input | Mitigated |

#### Tier 2 — Conditional Risk

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status |
|----|----------|--------|---------------|---------------|------------|--------|
| T13.E | Elevation of Privilege | Expired/exhausted trial key retains its tier during the 60 s resolution cache window | Authenticated User | DF03 | Bounded 60 s TTL; tier downgrades on next resolution | Mitigated |

#### Tier 3 — Defense-in-Depth

*No Tier 3 threats identified.*

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Repudiation | Authentication outcomes are recorded by the fuzzing counter and analytics (`auth_fail`), addressed under HonoWorker/RateLimiter. |
| Denial of Service | Auth resolution is in-process and bounded; request-flooding DoS is covered by HonoWorker rate limiting. |

## OAuthIssuer

**Trust Boundary:** CloudflareWorker
**Role:** OAuth 2.1 issuer — dynamic registration, authorize, PKCE token exchange, HS256 JWT signing/validation, entitlements.
**Data Flows:** DF04, DF13, DF20
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status |
|----|----------|--------|---------------|---------------|------------|--------|
| T15.S | Spoofing | Abuse of open dynamic client registration to register rogue clients | None | DF04 | PKCE required; redirect_uri validation; registration gated by `ENABLE_OAUTH` | Mitigated |
| T16.T | Tampering | Authorization-code injection / replay | None | DF04 | PKCE S256 verify; single-use codes with TTL in KV (`src/oauth/token.ts`) | Mitigated |
| T18.D | Denial of Service | Token-endpoint flooding | None | DF04 | 30/min per-IP limit on `/oauth/token` | Mitigated |

#### Tier 2 — Conditional Risk

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status |
|----|----------|--------|---------------|---------------|------------|--------|
| T20.A | Abuse | Issued JWT retains an elevated tier after the customer's plan is downgraded, until `exp` | Authenticated User | DF20 | JTI revocation supported; short token lifetime recommended | Mitigated |

#### Tier 3 — Defense-in-Depth

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status |
|----|----------|--------|---------------|---------------|------------|--------|
| T17.I | Information Disclosure | Weak/short `OAUTH_SIGNING_SECRET` enabling JWT forgery | Host/OS Access | DF04 | `OAUTH_SIGNING_SECRET_MIN_BYTES` (≥32) enforced; 503 until set | Mitigated |
| T19.E | Elevation of Privilege | Spoofed bv-web entitlement response grants an unauthorized tier | BvWeb Compromise | DF20 | Authenticated service binding; tier value validated against enum | Mitigated |

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Repudiation | Token issuance and code exchange are recorded via analytics `session`/`tool_call` events. |

## McpExecutor

**Trust Boundary:** CloudflareWorker
**Role:** MCP request pipeline — session validation, per-tier rate/quota application, method routing.
**Data Flows:** DF05, DF06, DF07, DF12, DF18

**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status |
|----|----------|--------|---------------|---------------|------------|--------|
| T21.S | Spoofing | Session-ID guessing or fixation to hijack a session | None | DF12 | 64-hex IDs from 32 random bytes; schema-validated; KV-backed | Mitigated |
| T22.T | Tampering | Malformed JSON-RPC / parameter tampering | None | DF05 | JSON-RPC validation + Zod `validateToolArgs` | Mitigated |
| T23.R | Repudiation | Tool invocation cannot be attributed to a principal | None | DF18 | `tool_call` analytics + encrypted access log (D1) | Mitigated |
| T24.I | Information Disclosure | Cross-session/tenant data leakage via predictable cache keys | None | DF12 | Domain-scoped cache keys; no per-user secrets cached | Mitigated |
| T25.D | Denial of Service | Amplification via expensive methods (e.g., `scan_domain`) | None | DF07 | Per-tool daily quotas; 12 s scan / 8 s per-check budgets | Mitigated |
| T26.E | Elevation of Privilege | Invoking a non-allowlisted or scan-only tool (e.g., `check_subdomain_takeover`) directly | None | DF07 | `TOOL_REGISTRY` allowlist; `check_subdomain_takeover` runs only inside `scan_domain` | Mitigated |
| T27.A | Abuse | Session-creation flooding to exhaust KV / session maps | None | DF12 | Session creation limited 10/min per IP; LRU-capped maps | Mitigated |

#### Tier 2 — Conditional Risk

*No Tier 2 threats identified.*

#### Tier 3 — Defense-in-Depth

*No Tier 3 threats identified.*

#### Categories Not Applicable

*All STRIDE-A categories produced at least one threat for this component.*

## ToolsHandler

**Trust Boundary:** CloudflareWorker
**Role:** Tool registry + execution for ~80 `check_*`/scan tools.
**Data Flows:** DF07, DF08, DF09, DF10, DF11, DF14, DF17
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status |
|----|----------|--------|---------------|---------------|------------|--------|
| T28.T | Tampering | Tool arguments injected to reach DNS/fetch with unvalidated values | None | DF08 | Zod `validateToolArgs` + `validateDomain`/`sanitizeDomain` after schema | Mitigated |
| T29.I | Information Disclosure | `STRUCTURED_RESULT` JSON leaks internal data to clients | None | DF07 | Omitted for interactive LLM clients; findings auto-sanitized via `createFinding()` | Mitigated |
| T30.D | Denial of Service | `batch_scan` resource exhaustion | None | DF07 | `budgetMs` 25 s, concurrency 3, per-domain `Promise.race` | Mitigated |
| T31.E | Elevation of Privilege | Domain-optional tool bypassing domain validation | None | DF08 | `DOMAIN_OPTIONAL_TOOLS` explicit allowlist; args still Zod-validated | Mitigated |
| T32.A | Abuse | Using the scanner as a recon/attack proxy against arbitrary third-party domains | None | DF09 | Per-IP rate limits; `check_lookalikes`/`check_shadow_domains` 20/day per IP | Mitigated |
| T33.A | Abuse | Repeated `force_refresh` to bust cache and amplify backend load | None | DF14 | `force_refresh` counts against per-tool quota | Mitigated |

#### Tier 2 — Conditional Risk

*No Tier 2 threats identified.*

#### Tier 3 — Defense-in-Depth

*No Tier 3 threats identified.*

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Spoofing | ToolsHandler operates on already-authenticated, validated dispatch from McpExecutor; identity is established upstream. |
| Repudiation | Tool invocations are attributed via McpExecutor analytics and access logging. |

## DomainSanitizer

**Trust Boundary:** CloudflareWorker
**Role:** Domain input validation / SSRF input guard (`validateDomain`, `sanitizeDomain`, `validateOutboundUrl`).
**Data Flows:** DF08
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status |
|----|----------|--------|---------------|---------------|------------|--------|
| T34.T | Tampering | Unicode/punycode homoglyph or encoding tricks bypassing domain validation | None | DF08 | Normalization + public-suffix checks in `sanitizeDomain` (`src/lib/sanitize.ts`) | Mitigated |
| T35.I | Information Disclosure | SSRF — domain input crafted to resolve to internal/metadata IPs | None | DF08 | Reject IP literals, localhost/.local/.onion, RFC1918, rebinding hosts (`src/lib/config.ts`) | Mitigated |
| T36.E | Elevation of Privilege | DNS-rebinding TOCTOU: validated hostname resolves to an internal IP at fetch time | None | DF08 | Cloudflare `global_fetch_strictly_public` blocks RFC1918 at runtime; SafeFetch re-validation | Mitigated |

#### Tier 2 — Conditional Risk

*No Tier 2 threats identified.*

#### Tier 3 — Defense-in-Depth

*No Tier 3 threats identified.*

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Spoofing | DomainSanitizer authenticates no principals; it validates data, not identity. |
| Repudiation | Validation is a pure, stateless function with no auditable action of its own. |
| Denial of Service | Validation is bounded, synchronous, and inexpensive. |
| Abuse | No business workflow to misuse; it is a guard, not a feature. |

## SafeFetch

**Trust Boundary:** CloudflareWorker
**Role:** Egress SSRF guard for attacker-influenced URLs (BIMI `l=`, redirect targets).
**Data Flows:** DF10
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status |
|----|----------|--------|---------------|---------------|------------|--------|
| T37.T | Tampering | Redirect-based SSRF — `Location:` header pointing at internal targets | None | DF10 | `redirect:'manual'` + per-hop re-validation through SafeFetch (`src/lib/safe-fetch.ts`) | Mitigated |
| T38.I | Information Disclosure | Attacker-influenced URL (BIMI `l=`/`a=`) fetched against internal services | None | DF10 | HTTPS-only, blocklist, userinfo rejection in SafeFetch | Mitigated |
| T39.D | Denial of Service | Slowloris/large-response from an attacker-controlled fetch target | None | DF10 | `AbortSignal.timeout` + total-budget caps (`check_http_security` 10 s) | Mitigated |

#### Tier 2 — Conditional Risk

*No Tier 2 threats identified.*

#### Tier 3 — Defense-in-Depth

*No Tier 3 threats identified.*

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Spoofing | SafeFetch makes outbound requests and authenticates no inbound identity. |
| Repudiation | Egress requests are bounded library calls; auditing belongs to the calling tool. |
| Elevation of Privilege | SafeFetch holds no privileges to escalate; it restricts egress. |
| Abuse | No user-facing workflow; it is an egress control. |

## DnsResolver

**Trust Boundary:** CloudflareWorker
**Role:** DoH egress — Cloudflare primary, `BV_DOH_ENDPOINT` secondary, Google fallback.
**Data Flows:** DF09, DF21
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status |
|----|----------|--------|---------------|---------------|------------|--------|
| T42.D | Denial of Service | Using the scanner to flood a victim domain/resolver with DNS queries (reflection) | None | DF21 | Per-IP/per-tool rate limits; queries target public DoH, not arbitrary victims | Mitigated |
| T43.A | Abuse | Driving DNS queries for reconnaissance / resolver cache snooping | None | DF21 | Rate limits; bounded record types | Mitigated |

#### Tier 2 — Conditional Risk

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status |
|----|----------|--------|---------------|---------------|------------|--------|
| T40.S | Spoofing | Malicious/MITM DoH resolver returns forged records | Internal Network | DF21 | TLS to resolvers; secondary resolver uses `X-BV-Token`; multi-resolver chain | Mitigated |
| T41.T | Tampering | DNS-response tampering that skews scan grades | Internal Network | DF21 | TLS transport; cross-resolver corroboration; DNSSEC checks where applicable | Mitigated |

#### Tier 3 — Defense-in-Depth

*No Tier 3 threats identified.*

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Repudiation | DNS egress is recorded indirectly via tool-call analytics on the calling tool. |
| Information Disclosure | Queries concern public domains under scan; no secrets are transmitted. |
| Elevation of Privilege | The resolver holds no privilege boundary to cross. |

## RateLimiter

**Trust Boundary:** CloudflareWorker
**Role:** Rate limits, per-tier quotas, and fuzzing/abuse detection.
**Data Flows:** DF06, DF15, DF16
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status |
|----|----------|--------|---------------|---------------|------------|--------|
| T44.T | Tampering | Forging client IP to evade per-IP counters | None | DF06 | IP sourced only from `cf-connecting-ip`; `x-forwarded-for` never trusted | Mitigated |
| T46.E | Elevation of Privilege | Distributed IPs (botnet) bypassing per-IP limits | None | DF06 | Global 500K/day ceiling enforced by QuotaCoordinator DO | Mitigated |
| T47.A | Abuse | Low-and-slow fuzzing/enumeration kept under per-IP thresholds | None | DF15 | Fuzzing detector sliding-window scoring + webhook alerts | Mitigated |

#### Tier 2 — Conditional Risk

*No Tier 2 threats identified.*

#### Tier 3 — Defense-in-Depth

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status |
|----|----------|--------|---------------|---------------|------------|--------|
| T45.D | Denial of Service | KV unavailability disabling rate-limit enforcement (fail-open) | RateLimitKV Compromise | DF15 | In-memory fallback + QuotaCoordinator DO with circuit breaker | Mitigated |

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Spoofing | RateLimiter establishes no identity; it counts requests keyed by validated IP. |
| Repudiation | Limit decisions are emitted as `rate_limit` analytics events. |
| Information Disclosure | Counters hold no sensitive data beyond hashed principals. |

## InternalRouter

**Trust Boundary:** CloudflareWorker
**Role:** Service-binding `/internal/*` surface (tools, batch, OAuth grants, trial keys).
**Data Flows:** DF02
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

*No Tier 1 threats identified.*

#### Tier 2 — Conditional Risk

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status |
|----|----------|--------|---------------|---------------|------------|--------|
| T48.S | Spoofing | Public attacker reaching `/internal/*` by manipulating proxy headers | Internal Network | DF02 | `isPublicInternetRequest` rejects any public proxy header → 404 (`src/internal.ts`) | Mitigated |
| T49.T | Tampering | Oversized/abusive internal batch payload | Internal Network | DF02 | 256 KB batch limit; tool names `^[a-z_]+$` ≤30 chars; arg-key allowlist | Mitigated |
| T50.D | Denial of Service | Batch endpoint resource exhaustion (up to 500 domains) | Internal Network | DF02 | Max 500 domains, concurrency cap, per-domain budget | Mitigated |
| T51.E | Elevation of Privilege | Reaching credential-minting routes (`/internal/oauth/grants`, `/internal/trial-keys/*`) without authorization | Internal Network | DF02 | Strict `BV_WEB_INTERNAL_KEY` bearer gate: 503 if unset, 401 on missing/wrong | Mitigated |
| T52.A | Abuse | `REQUIRE_INTERNAL_AUTH` defaulting off leaves `/internal/tools/*` and `/internal/analytics/*` open to any in-account binding | Internal Network | DF02 | `cf-connecting-ip` guard; bearer auth available but opt-in | Mitigated |

#### Tier 3 — Defense-in-Depth

*No Tier 3 threats identified.*

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Repudiation | Internal calls are recorded via tool-call analytics with the calling principal. |
| Information Disclosure | Responses contain only the same scan data exposed publicly; no extra secrets returned. |

## BrandAuditPipeline

**Trust Boundary:** CloudflareWorker
**Role:** Brand-audit orchestration plus cron/queue (tiered discovery, registrar/CT/WHOIS enrichment).
**Data Flows:** DF11, DF22, DF23
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

*No Tier 1 threats identified.*

#### Tier 2 — Conditional Risk

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status |
|----|----------|--------|---------------|---------------|------------|--------|
| T53.T | Tampering | Auditing a watched domain the caller does not own | Authenticated User | DF11 | Watched-domain validated at register time (fix in #201) | Mitigated |
| T54.I | Information Disclosure | Tiered discovery reveals competitor/third-party infrastructure | Authenticated User | DF22 | Opt-out enforcement; tier gating of discovery modes | Mitigated |
| T55.D | Denial of Service | Expensive tiered discovery / brand-audit queue flooding | Authenticated User | DF11 | Per-tier quotas, processing budget, reaper for stale jobs | Mitigated |
| T56.A | Abuse | Mass third-party domain enumeration via repeated brand audits | Authenticated User | DF22 | Per-tier daily quotas + opt-out registry | Mitigated |

#### Tier 3 — Defense-in-Depth

*No Tier 3 threats identified.*

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Spoofing | Callers are authenticated upstream; the pipeline establishes no new identity. |
| Repudiation | Audit jobs are tracked in D1 with the requesting tenant/principal. |
| Elevation of Privilege | The pipeline runs with the same worker privileges as other tools; no boundary to escalate across. |

## QuotaCoordinator

**Trust Boundary:** DurableObjects
**Role:** Durable Object coordinating cross-isolate rate limits and the global daily quota.
**Data Flows:** DF16
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

*No Tier 1 threats identified.*

#### Tier 2 — Conditional Risk

*No Tier 2 threats identified.*

#### Tier 3 — Defense-in-Depth

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status |
|----|----------|--------|---------------|---------------|------------|--------|
| T57.T | Tampering | Manipulating DO state to reset/inflate quota counters | CloudflareWorker Compromise | DF16 | DO reachable only via in-account binding; no external listener | Platform |
| T58.D | Denial of Service | Single-instance DO bottleneck or unavailability disabling global quota | Host/OS Access | DF16 | Circuit-breaker fallback to KV/in-memory limiting | Mitigated |

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Spoofing | DO identity is bound by the Cloudflare platform; callers cannot impersonate it. |
| Repudiation | Quota operations are deterministic counter updates with no independent audit need. |
| Information Disclosure | Stores only aggregate counters, no sensitive data. |
| Elevation of Privilege | The DO grants no privileges to callers. |
| Abuse | No user-facing workflow exposed. |

## ProfileAccumulator

**Trust Boundary:** DurableObjects
**Role:** Durable Object persisting adaptive-scoring EMA per profile+provider.
**Data Flows:** DF17
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

*No Tier 1 threats identified.*

#### Tier 2 — Conditional Risk

*No Tier 2 threats identified.*

#### Tier 3 — Defense-in-Depth

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status |
|----|----------|--------|---------------|---------------|------------|--------|
| T59.T | Tampering | Poisoning adaptive weights via crafted telemetry | CloudflareWorker Compromise | DF17 | Maturity-gated blending (`MATURITY_THRESHOLD`); static fallback if DO unavailable | Mitigated |
| T60.A | Abuse | Sustained scans biasing the EMA to skew future scores | CloudflareWorker Compromise | DF17 | Maturity threshold before blending; bounded influence per profile | Mitigated |

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Spoofing | DO identity is platform-bound. |
| Repudiation | Weight updates are aggregate EMA operations with no per-call audit need. |
| Information Disclosure | Stores only derived weights, not user data. |
| Denial of Service | Falls back to static weights if unavailable; scoring continues. |
| Elevation of Privilege | Grants no privileges to callers. |

## SessionStoreKV

**Trust Boundary:** PlatformStorage
**Role:** KV holding session records, OAuth authorization codes, and JTI revocation markers.
**Data Flows:** DF12, DF13
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

*No Tier 1 threats identified.*

#### Tier 2 — Conditional Risk

*No Tier 2 threats identified.*

#### Tier 3 — Defense-in-Depth

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status |
|----|----------|--------|---------------|---------------|------------|--------|
| T61.T | Tampering | Tampering with session/auth-code records | CloudflareWorker Compromise | DF12 | KV reachable only via in-account binding; session schema validated on read | Platform |
| T62.I | Information Disclosure | Disclosure of OAuth codes / JTI if the KV namespace is exposed | Host/OS Access | DF13 | Short single-use code TTL; platform encryption at rest (app-layer encryption recommended) | Mitigated |

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Spoofing | KV is a passive store; it authenticates no callers. |
| Repudiation | KV writes are driven by audited services (McpExecutor, OAuthIssuer). |
| Denial of Service | KV capacity/availability is platform-managed. |
| Elevation of Privilege | The store grants no privileges. |
| Abuse | No workflow exposed by the store itself. |

## ScanCacheKV

**Trust Boundary:** PlatformStorage
**Role:** KV caching scan/check results keyed by domain.
**Data Flows:** DF14
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

*No Tier 1 threats identified.*

#### Tier 2 — Conditional Risk

*No Tier 2 threats identified.*

#### Tier 3 — Defense-in-Depth

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status |
|----|----------|--------|---------------|---------------|------------|--------|
| T63.T | Tampering | Cache poisoning — tampered cached results served to clients | CloudflareWorker Compromise | DF14 | KV in-account only; 5 min TTL; `force_refresh` bypass available | Platform |

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Spoofing | Passive store; no caller authentication. |
| Repudiation | Cache writes derive from audited tool execution. |
| Information Disclosure | Caches only public DNS/scan data, no secrets. |
| Denial of Service | Capacity/availability platform-managed; TTL bounds growth. |
| Elevation of Privilege | Grants no privileges. |
| Abuse | No exposed workflow. |

## RateLimitKV

**Trust Boundary:** PlatformStorage
**Role:** KV holding rate/fuzzing counters and trial keys.
**Data Flows:** DF15
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

*No Tier 1 threats identified.*

#### Tier 2 — Conditional Risk

*No Tier 2 threats identified.*

#### Tier 3 — Defense-in-Depth

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status |
|----|----------|--------|---------------|---------------|------------|--------|
| T64.T | Tampering | Tampering with counters or trial keys to evade limits/escalate tier | CloudflareWorker Compromise | DF15 | KV in-account only; DO fallback for quota | Platform |
| T65.I | Information Disclosure | Disclosure of trial keys if the KV namespace is exposed | Host/OS Access | DF15 | Platform encryption at rest; trial keys bounded-lifetime (app-layer encryption recommended) | Mitigated |

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Spoofing | Passive store; no caller authentication. |
| Repudiation | Writes derive from audited RateLimiter operations. |
| Denial of Service | Availability platform-managed; in-memory fallback exists. |
| Elevation of Privilege | Grants no privileges directly. |
| Abuse | No exposed workflow. |

## IntelligenceDB

**Trust Boundary:** PlatformStorage
**Role:** D1 storing MCP access logs with AES-GCM-encrypted IP evidence (~90-day retention).
**Data Flows:** DF18
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

*No Tier 1 threats identified.*

#### Tier 2 — Conditional Risk

*No Tier 2 threats identified.*

#### Tier 3 — Defense-in-Depth

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status |
|----|----------|--------|---------------|---------------|------------|--------|
| T66.I | Information Disclosure | Disclosure of client IP evidence from access logs | Host/OS Access | DF18 | AES-GCM encryption with versioned key; ~90-day retention | Mitigated |
| T67.T | Tampering | Tampering with access logs to hide abuse activity | CloudflareWorker Compromise | DF18 | D1 in-account only; append-oriented write pattern | Platform |
| T68.R | Repudiation | Insufficient retention undermines forensic attribution | Host/OS Access | DF18 | ~90-day retention window of encrypted evidence | Mitigated |

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Spoofing | Passive store; no caller authentication. |
| Denial of Service | D1 capacity/availability platform-managed. |
| Elevation of Privilege | Grants no privileges. |
| Abuse | No exposed workflow. |

## BvWeb

**Trust Boundary:** BlackVeilServices
**Role:** Sibling worker — validate-key and OAuth entitlement resolution (consumed over a service binding).
**Data Flows:** DF19, DF20
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

*No Tier 1 threats identified.*

#### Tier 2 — Conditional Risk

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status |
|----|----------|--------|---------------|---------------|------------|--------|
| T70.I | Information Disclosure | Entitlement/plan data exposed in transit between workers | Internal Network | DF20 | In-account service binding (not public network); TLS within Cloudflare | Mitigated |
| T71.D | Denial of Service | bv-web unavailability blocking paid-tier authentication | Internal Network | DF19 | Static `BV_API_KEY` fallback; free tier unaffected | Mitigated |

#### Tier 3 — Defense-in-Depth

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status |
|----|----------|--------|---------------|---------------|------------|--------|
| T69.S | Spoofing | A compromised bv-web returns forged entitlements granting an elevated tier | BvWeb Compromise | DF20 | Authenticated binding (`BV_WEB_INTERNAL_KEY`); tier value validated against enum | Mitigated |

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Tampering | Request/response integrity is provided by the in-account binding transport. |
| Repudiation | Entitlement lookups are recorded on both sides via analytics. |
| Elevation of Privilege | Covered under Spoofing (T69.S) — forged entitlement is the escalation path. |
| Abuse | No bv-mcp-exposed workflow; bv-web is a consumed dependency. |

## PublicDoH

**Trust Boundary:** Internet
**Role:** Public DoH resolvers (Cloudflare, Google) used for DNS queries.
**Data Flows:** DF21
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

*No Tier 1 threats identified.*

#### Tier 2 — Conditional Risk

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status |
|----|----------|--------|---------------|---------------|------------|--------|
| T72.S | Spoofing | Resolver spoofing/poisoning returning forged answers | Internal Network | DF21 | TLS to resolvers; multi-resolver chain; secondary `X-BV-Token` | Mitigated |
| T73.T | Tampering | DNS response tampering on the wire | Internal Network | DF21 | TLS transport (DoH) | Mitigated |
| T74.D | Denial of Service | Resolver outage degrading scan availability | Internal Network | DF21 | Fallback chain (empty → bv-dns → Google) | Mitigated |

#### Tier 3 — Defense-in-Depth

*No Tier 3 threats identified.*

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Repudiation | DoH queries are attributed to the calling tool, not the resolver. |
| Information Disclosure | Queries concern public domains; no secrets transmitted to the resolver. |
| Elevation of Privilege | The resolver grants bv-mcp no privileges. |
| Abuse | No bv-mcp workflow exposed via the resolver. |

## CertTransparency

**Trust Boundary:** Internet
**Role:** CT-log enumeration via `BV_CERTSTREAM` binding and crt.sh fallback.
**Data Flows:** DF22
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

*No Tier 1 threats identified.*

#### Tier 2 — Conditional Risk

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status |
|----|----------|--------|---------------|---------------|------------|--------|
| T75.T | Tampering | Malicious CT data inflating brand-audit candidate sets | Internal Network | DF22 | crt.sh fallback + candidate validation; bounded result sizes | Mitigated |
| T76.D | Denial of Service | CT source outage degrading discovery | Internal Network | DF22 | Direct crt.sh fallback with jittered backoff | Mitigated |

#### Tier 3 — Defense-in-Depth

*No Tier 3 threats identified.*

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Spoofing | CT source identity is established by TLS; no privileged trust granted. |
| Repudiation | CT queries are attributed to the brand-audit pipeline. |
| Information Disclosure | CT logs are public data; no secrets transmitted. |
| Elevation of Privilege | The source grants bv-mcp no privileges. |
| Abuse | No bv-mcp workflow exposed via the source. |

## WhoisRdap

**Trust Boundary:** Internet
**Role:** WHOIS/RDAP registration lookups via `BV_WHOIS` binding with RDAP fallback.
**Data Flows:** DF23
**Pod Co-location:** N/A

### STRIDE-A Analysis

#### Tier 1 — Direct Exposure (No Prerequisites)

*No Tier 1 threats identified.*

#### Tier 2 — Conditional Risk

| ID | Category | Threat | Prerequisites | Affected Flow | Mitigation | Status |
|----|----------|--------|---------------|---------------|------------|--------|
| T77.I | Information Disclosure | Untrusted WHOIS/RDAP data injected into rendered reports (stored content) | Internal Network | DF23 | Output sanitization via `createFinding()` auto-sanitize | Mitigated |
| T78.D | Denial of Service | WHOIS/RDAP source outage degrading enrichment | Internal Network | DF23 | RDAP-only fallback; KV-cached IANA referrals | Mitigated |

#### Tier 3 — Defense-in-Depth

*No Tier 3 threats identified.*

#### Categories Not Applicable

| Category | Justification |
|----------|---------------|
| Spoofing | Source identity established by TLS; no privileged trust granted. |
| Tampering | Response integrity provided by TLS; injected content handled under Information Disclosure (T77.I). |
| Repudiation | Lookups are attributed to the brand-audit pipeline. |
| Elevation of Privilege | The source grants bv-mcp no privileges. |
| Abuse | No bv-mcp workflow exposed via the source. |
