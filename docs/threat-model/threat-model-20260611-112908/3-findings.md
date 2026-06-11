# Security Findings

> **Incremental report.** Finding IDs FIND-01–17 are inherited from baseline `threat-model-20260524-114907` and re-verified against commit `7a1c6b3`; FIND-18–21 are new. Each finding body opens with a status tag: **[Existing]** (still present / existing control), **[Fixed]** (remediated — code cited), **[Partial]** (mechanism landed, residual remains), **[New]**. Because old IDs are preserved and findings are ordered by tier/severity, ID numbers are not strictly ascending in document order.

---

## Tier 1 — Direct Exposure (No Prerequisites)

### FIND-01: API key accepted via query parameter

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Moderate |
| CVSS 4.0 | 5.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N) |
| CWE | [CWE-598](https://cwe.mitre.org/data/definitions/598.html): Use of GET Request Method With Sensitive Query Strings |
| OWASP | A04:2025 – Cryptographic Failures |
| Exploitation Prerequisites | None |
| Exploitability Tier | Tier 1 — Direct Exposure |
| Remediation Effort | Low |
| Mitigation Type | Standard Mitigation |
| Component | TierAuthResolver |
| Related Threats | [T11.I](2-stride-analysis.md#tierauthresolver) |

#### Description

> **[Partial]**

The `/mcp` endpoint accepts an API key via the `?api_key=` query parameter (Smithery compatibility fallback). Query strings are routinely captured in CDN, proxy, and edge logs, so a high-privilege key passed this way can leak outside the application's control. A rejection gate (`REJECT_QUERY_API_KEY`) was merged in the remediation window, but it defaults to *accepting* query keys — the fix is code-complete and deploy-config-gated.

#### Evidence

**Prerequisite basis:** `/mcp` is externally reachable with no auth required (HonoWorker `Reachability = External`, `Min Prerequisite = None` per the Component Exposure Table).

`src/index.ts:106` — `const queryToken = c.env.REJECT_QUERY_API_KEY === 'true' ? null : bearerToken ? null : (c.req.query('api_key') ?? null);`. Unset/absent env → query keys accepted. Bearer is preferred when present.

#### Remediation

Set `REJECT_QUERY_API_KEY=true` in the production deploy overrides once Smithery-dependent clients are migrated; longer-term, flip the code default to reject and allowlist legacy clients explicitly.

#### Verification

With the gate set, `POST /mcp?api_key=<key>` must be treated as unauthenticated (free tier / 401 for auth-required tools); bearer-header auth must continue to work.

### FIND-02: Free-tier abuse via distributed IPs

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Moderate |
| CVSS 4.0 | 5.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N) |
| CWE | [CWE-770](https://cwe.mitre.org/data/definitions/770.html): Allocation of Resources Without Limits or Throttling |
| OWASP | A06:2025 – Insecure Design |
| Exploitation Prerequisites | None |
| Exploitability Tier | Tier 1 — Direct Exposure |
| Remediation Effort | Medium |
| Mitigation Type | Custom Mitigation |
| Component | RateLimiter |
| Related Threats | [T07.A](2-stride-analysis.md#honoworker), [T46.E](2-stride-analysis.md#ratelimiter) |

#### Description

> **[Fixed]**

An attacker rotating through many source IPs could keep each IP under the per-IP minute/hour limits while collectively consuming large scan volume from the shared free-tier budget. The remediation adds a per-IP distinct-domains-per-day cap, sharply reducing the per-IP value of a botnet for breadth enumeration, on top of the pre-existing global daily ceiling.

#### Evidence

**Prerequisite basis:** Public `/mcp`, no auth required (Exposure Table: `None`).

Fixed by `checkDistinctDomainDailyLimit()` (`src/lib/rate-limiter.ts:555-593`), `FREE_DISTINCT_DOMAIN_DAILY_LIMIT = 12` (`src/lib/config.ts:433`), enforced pre-dispatch for unauthenticated `tools/call` (`src/mcp/execute.ts:715-756`, HTTP 429 + `x-quota-*` headers). Slot recorded before validation so invalid calls also consume budget. Global 500K/day ceiling via QuotaCoordinator unchanged.

#### Remediation

Tune the provisional cap (12) against production telemetry; consider extending distinct-domain budgets to authenticated free-adjacent tiers if abuse shifts.

#### Verification

From a single IP, scans of 12 distinct domains succeed; the 13th distinct domain returns HTTP 429 with `distinct domains per day` messaging; repeats of already-scanned domains are not blocked.

### FIND-03: Scanner usable as recon/amplification proxy

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Moderate |
| CVSS 4.0 | 5.1 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:L) |
| CWE | [CWE-406](https://cwe.mitre.org/data/definitions/406.html): Insufficient Control of Network Message Volume (Network Amplification) |
| OWASP | A06:2025 – Insecure Design |
| Exploitation Prerequisites | None |
| Exploitability Tier | Tier 1 — Direct Exposure |
| Remediation Effort | Medium |
| Mitigation Type | Custom Mitigation |
| Component | ToolsHandler |
| Related Threats | [T32.A](2-stride-analysis.md#toolshandler), [T42.D](2-stride-analysis.md#dnsresolver), [T43.A](2-stride-analysis.md#dnsresolver), [T87.D](2-stride-analysis.md#bvrecon), [T88.A](2-stride-analysis.md#bvrecon) |

#### Description

> **[Fixed]**

Anonymous callers could use offensive and multi-domain tools (lookalike/shadow-domain discovery, subdomain enumeration, batch scans) to reconnoiter or amplify traffic against third-party domains. The remediation gates the entire offensive/multi-domain tool set to paid tiers (developer+), returning HTTP 403 with JSON-RPC `-32003` (`UPGRADE_REQUIRED`) for free, agent, and unauthenticated callers, while keeping result-pollers free.

#### Evidence

**Prerequisite basis:** Public `/mcp`, no auth required (Exposure Table: `None`).

Fixed by `GATED_PAID_ONLY_TOOLS` (`src/lib/config.ts:340-378`) enforced at `src/mcp/execute.ts:604-606` (unauthenticated) and `769-771` (authenticated free/agent); tools also pinned to 0 in `FREE_TOOL_DAILY_LIMITS` and `TIER_TOOL_DAILY_LIMITS.free/.agent`. SSOT audited by `test/audits/gated-tools-ssot.audit.test.ts` and the commercial-tier contract audit.

#### Remediation

Maintain the gated set as new offensive tools are added (the SSOT audit trips on drift); keep the distinct-domain cap (FIND-02) as the residual brake on single-domain recon breadth.

#### Verification

Unauthenticated `tools/call check_lookalikes` returns HTTP 403/-32003 "requires a paid plan"; a developer-tier key succeeds; `osint_investigation_status` (poller) remains callable without a paid plan.

### FIND-04: OAuth issuer from spoofable Host header

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Moderate |
| CVSS 4.0 | 4.8 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N) |
| CWE | [CWE-350](https://cwe.mitre.org/data/definitions/350.html): Reliance on Reverse DNS Resolution / Host-Derived Trust |
| OWASP | A02:2025 – Security Misconfiguration |
| Exploitation Prerequisites | None |
| Exploitability Tier | Tier 1 — Direct Exposure |
| Remediation Effort | Low |
| Mitigation Type | Standard Mitigation |
| Component | HonoWorker |
| Related Threats | [T05.I](2-stride-analysis.md#honoworker) |

#### Description

> **[Partial]**

When `OAUTH_ISSUER` is unset, OAuth discovery derives the issuer URL from the request `Host` header, which an attacker can influence in some fronting configurations to poison discovery metadata. The override mechanism and a strict host-pinning variant are implemented; the secure behavior activates only when the env var is set in the production deploy config.

#### Evidence

**Prerequisite basis:** `/oauth/*` discovery endpoints are externally reachable without auth (Exposure Table: `None`).

`src/oauth/discovery.ts:18-22` — `resolveIssuer()` uses `OAUTH_ISSUER` when set (trailing-slash stripped), else falls back to `${url.protocol}//${url.host}`. `resolveIssuerStrict` (lines 29-39) errors when the Host doesn't match the configured issuer.

#### Remediation

Set `OAUTH_ISSUER` in production deploy overrides (already recommended in `wrangler` docs); route discovery through `resolveIssuerStrict` once set.

#### Verification

`GET /.well-known/oauth-authorization-server` with a forged `Host` header must return the configured issuer, not the forged host.

### FIND-05: Open OAuth dynamic client registration

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Low |
| CVSS 4.0 | 4.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N) |
| CWE | [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html): Insecure Default Initialization of Resource |
| OWASP | A02:2025 – Security Misconfiguration |
| Exploitation Prerequisites | None |
| Exploitability Tier | Tier 1 — Direct Exposure |
| Remediation Effort | Low |
| Mitigation Type | Existing Control |
| Component | OAuthIssuer |
| Related Threats | [T15.S](2-stride-analysis.md#oauthissuer) |

#### Description

> **[Existing]**

Reclassified as a false positive in the interim overlay: the controls flagged as missing were already present at the baseline commit. Re-verified at HEAD — dynamic client registration is rate-limited per IP and constrained, so open registration is not exploitable for resource exhaustion or rogue-client abuse at meaningful scale.

#### Evidence

**Prerequisite basis:** `/oauth/register` is externally reachable without auth (Exposure Table: `None`).

`src/oauth/register.ts` — per-IP 10/min + 30/hr limits (lines 11-78), 4 KB body cap, strict `application/json` check, redirect-URI validation before any write, UUIDv4 client IDs; `client_id_issued_at` stamped per RFC 7591.

#### Remediation

None required beyond keeping the limits regression-tested; consider client-record TTL/cleanup if registration volume grows.

#### Verification

Eleven registrations in one minute from one IP → the 11th is rate-limited; registered clients require valid redirect URIs.

### FIND-06: force_refresh cache-busting amplification

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Low |
| CVSS 4.0 | 3.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N) |
| CWE | [CWE-770](https://cwe.mitre.org/data/definitions/770.html): Allocation of Resources Without Limits or Throttling |
| OWASP | A06:2025 – Insecure Design |
| Exploitation Prerequisites | None |
| Exploitability Tier | Tier 1 — Direct Exposure |
| Remediation Effort | Low |
| Mitigation Type | Standard Mitigation |
| Component | ToolsHandler |
| Related Threats | [T33.A](2-stride-analysis.md#toolshandler) |

#### Description

> **[Fixed]**

Repeated `force_refresh=true` calls bypassed the 5-minute scan cache and amplified backend DoH/fetch load. A dedicated free-tier daily cap on cache bypasses now bounds this independently of per-tool quotas.

#### Evidence

**Prerequisite basis:** Public `/mcp`, no auth required (Exposure Table: `None`).

`FORCE_REFRESH_DAILY_LIMIT = 5` (`src/lib/config.ts:338`) — free-tier daily cache-bypass cap, enforced in the quota path alongside per-tool daily limits.

#### Remediation

Monitor cache-status analytics (`cacheStatus` blob) for bypass-pattern drift; raise/lower the cap from telemetry.

#### Verification

Six `force_refresh` scans in a day from a free caller → the 6th is rejected or served from cache.

### FIND-07: Domain validation hardening for homoglyph/IDN

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Low |
| CVSS 4.0 | 3.1 (CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N) |
| CWE | [CWE-1007](https://cwe.mitre.org/data/definitions/1007.html): Insufficient Visual Distinction of Homoglyphs Presented to User |
| OWASP | A03:2025 – Software Supply Chain Failures |
| Exploitation Prerequisites | None |
| Exploitability Tier | Tier 1 — Direct Exposure |
| Remediation Effort | Medium |
| Mitigation Type | Standard Mitigation |
| Component | DomainSanitizer |
| Related Threats | [T34.T](2-stride-analysis.md#domainsanitizer) |

#### Description

> **[Fixed]**

Mixed-script (e.g., Latin+Cyrillic) confusable labels could slip through domain validation and skew scan/brand-audit results. Mixed-script detection now rejects labels combining characters from multiple Unicode scripts at the validation gate.

#### Evidence

**Prerequisite basis:** Domain inputs arrive via public `/mcp` tools (Exposure Table: `None`).

`hasMixedScripts()` and its enforcement in `sanitizeDomain()` (`src/lib/sanitize.ts`) — present at HEAD (landed in the PR #208 remediation window; verified unchanged-in-behavior through the current diff window despite surrounding additions).

#### Remediation

Keep the confusable tables current with Unicode updates; extend to whole-script confusables if abuse appears.

#### Verification

`scan_domain` of a label mixing Cyrillic `а` with Latin characters is rejected with a `Domain `-prefixed validation error.

### FIND-08: Authentication & token-integrity controls (existing control)

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Low |
| CVSS 4.0 | 2.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N) |
| CWE | [CWE-287](https://cwe.mitre.org/data/definitions/287.html): Improper Authentication |
| OWASP | A07:2025 – Authentication Failures |
| Exploitation Prerequisites | None |
| Exploitability Tier | Tier 1 — Direct Exposure |
| Remediation Effort | Low |
| Mitigation Type | Existing Control |
| Component | TierAuthResolver |
| Related Threats | [T08.S](2-stride-analysis.md#tierauthresolver), [T09.S](2-stride-analysis.md#tierauthresolver), [T10.T](2-stride-analysis.md#tierauthresolver), [T12.E](2-stride-analysis.md#tierauthresolver), [T14.A](2-stride-analysis.md#tierauthresolver), [T16.T](2-stride-analysis.md#oauthissuer), [T17.I](2-stride-analysis.md#oauthissuer), [T21.S](2-stride-analysis.md#mcpexecutor), [T92.E](2-stride-analysis.md#tierauthresolver) |

#### Description

> **[Existing]**

Documents the authentication and token-integrity control set so regressions are caught: constant-time static-key comparison, pinned-algorithm JWT verification with signature-before-claims ordering, enum-validated issuable tiers, PKCE S256, session-ID entropy. Strengthened this window: a second independent dev-key slot (also constant-time compared), `OWNER_ALLOW_IPS` applied on every owner path including JWT, and a last-known-good (LKG) tier cache that preserves paying customers through bv-web 5xx without honoring definitive rejections.

#### Evidence

**Prerequisite basis:** The resolver guards the public, unauthenticated `/mcp` surface (Exposure Table: `None`).

`src/lib/tier-auth.ts:50-59` (`matchesStaticDevKey` constant-time XOR), `:61-68,136` (`applyOwnerIpGate` on JWT path), `:128-135` (token-version check), `:302-317` (LKG on 5xx only, 24 h TTL, never on 4xx); `src/oauth/jwt.ts:104-113` (signature before claims); `JwtIssuableTierSchema` (owner/developer/enterprise only).

#### Remediation

Residual to watch: a key revoked *during* a bv-web outage can retain its LKG tier up to 24 h (T92.E) — acceptable trade-off; consider purging the LKG entry from the revoke path if revocation-during-outage becomes a real scenario.

#### Verification

Timing-difference tests on static-key comparison stay flat; `alg=none` and tampered-tier JWTs are rejected; LKG is not consulted after a 401/403 from bv-web.

### FIND-09: SSRF egress controls (existing control)

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Low |
| CVSS 4.0 | 2.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N) |
| CWE | [CWE-918](https://cwe.mitre.org/data/definitions/918.html): Server-Side Request Forgery (SSRF) |
| OWASP | A06:2025 – Insecure Design |
| Exploitation Prerequisites | None |
| Exploitability Tier | Tier 1 — Direct Exposure |
| Remediation Effort | Low |
| Mitigation Type | Existing Control |
| Component | SafeFetch |
| Related Threats | [T35.I](2-stride-analysis.md#domainsanitizer), [T36.E](2-stride-analysis.md#domainsanitizer), [T37.T](2-stride-analysis.md#safefetch), [T38.I](2-stride-analysis.md#safefetch), [T39.D](2-stride-analysis.md#safefetch), [T89.I](2-stride-analysis.md#bvtlsprobe) |

#### Description

> **[Existing]**

Documents the SSRF control chain: input-side domain blocklists (IP literals, localhost, rebinding hosts), egress-side `safeFetch` (HTTPS-only, manual redirects, per-hop re-validation), and the platform `global_fetch_strictly_public` flag. All outbound paths added this window were audited: lookalike web probes and brand CSC enrichment use `safeFetch`; RDAP enrichment hits a hardcoded registry-endpoint allowlist; recon/M365/TLS-probe traffic goes to fixed in-account service bindings. One open assumption: the bv-tls-probe worker's own target-host validation is not verifiable from this repo (T89.I).

#### Evidence

**Prerequisite basis:** Attacker-influenced URLs originate from public `/mcp` tool inputs (Exposure Table: `None`).

`src/lib/safe-fetch.ts` (unchanged, intact); `src/tools/check-lookalikes.ts:697` (safeFetch web probe), `:641-668` (RDAP via `FALLBACK_RDAP_SERVERS` allowlist — domain appears only in the URL path); `src/lib/brand-audit-csc-enrichment.ts:70,97` (hardcoded Google DoH + safeFetch); `src/lib/tls-probe-binding.ts:63-83` (host forwarded to operator-controlled probe — validation assumed there).

#### Remediation

Confirm bv-tls-probe validates/blocklists target hosts (internal-network oracle, T89.I); keep the new-outbound-path review as part of tool-addition checklists.

#### Verification

BIMI `l=` URLs pointing at RFC1918/metadata addresses are rejected; redirects to internal targets are dropped at each hop; `check_ssl` of an internal hostname yields no probe result.

### FIND-10: Rate limiting, quotas & DoS budgets (existing control)

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Low |
| CVSS 4.0 | 2.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N) |
| CWE | [CWE-770](https://cwe.mitre.org/data/definitions/770.html): Allocation of Resources Without Limits or Throttling |
| OWASP | A06:2025 – Insecure Design |
| Exploitation Prerequisites | None |
| Exploitability Tier | Tier 1 — Direct Exposure |
| Remediation Effort | Low |
| Mitigation Type | Existing Control |
| Component | RateLimiter |
| Related Threats | [T01.S](2-stride-analysis.md#honoworker), [T02.T](2-stride-analysis.md#honoworker), [T06.D](2-stride-analysis.md#honoworker), [T18.D](2-stride-analysis.md#oauthissuer), [T22.T](2-stride-analysis.md#mcpexecutor), [T25.D](2-stride-analysis.md#mcpexecutor), [T26.E](2-stride-analysis.md#mcpexecutor), [T27.A](2-stride-analysis.md#mcpexecutor), [T28.T](2-stride-analysis.md#toolshandler), [T30.D](2-stride-analysis.md#toolshandler), [T31.E](2-stride-analysis.md#toolshandler), [T44.T](2-stride-analysis.md#ratelimiter), [T45.D](2-stride-analysis.md#ratelimiter), [T47.A](2-stride-analysis.md#ratelimiter), [T53.T](2-stride-analysis.md#brandauditpipeline), [T55.D](2-stride-analysis.md#brandauditpipeline), [T58.D](2-stride-analysis.md#quotacoordinator), [T91.D](2-stride-analysis.md#bvtlsprobe) |

#### Description

> **[Existing]**

Documents the layered DoS/abuse budget controls: per-IP minute/hour limits, per-tool daily quotas, per-tier daily quotas, the global 500K/day DO-coordinated ceiling, body-size caps, scan/check/tool time budgets, and fuzzing detection. Extended this window with the distinct-domain cap (FIND-02), force-refresh cap (FIND-06), request-dedup for mutating tools, and runtime-clamped scan/check timeouts.

#### Evidence

**Prerequisite basis:** Public `/mcp`, no auth required (Exposure Table: `None`).

`src/lib/rate-limiter.ts` + `src/lib/quota-coordinator.ts` (per-IP/per-tool/global); `src/lib/config.ts` (`FREE_IP_DAILY_LIMIT = 1000`, `GLOBAL_DAILY_TOOL_LIMIT = 500000`, per-tool maps); `src/lib/request-dedup.ts` (90 s KV window, store-on-success, keyHash-only principal); scan 15 s / per-check 8 s budgets clamped `[5s,30s]`/`[2s,15s]`.

#### Remediation

Keep quota maps SSOT-audited as tools are added (`tool-quota-coverage` audit); see FIND-20 for the intentionally-unlimited M365 family.

#### Verification

51 requests/minute from one IP → 429 with `retry-after`; full-suite quota audits green in CI.

### FIND-11: Information-disclosure controls (existing control)

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Low |
| CVSS 4.0 | 2.3 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N) |
| CWE | [CWE-209](https://cwe.mitre.org/data/definitions/209.html): Generation of Error Message Containing Sensitive Information |
| OWASP | A09:2025 – Security Logging & Alerting Failures |
| Exploitation Prerequisites | None |
| Exploitability Tier | Tier 1 — Direct Exposure |
| Remediation Effort | Low |
| Mitigation Type | Existing Control |
| Component | HonoWorker |
| Related Threats | [T03.R](2-stride-analysis.md#honoworker), [T04.I](2-stride-analysis.md#honoworker), [T23.R](2-stride-analysis.md#mcpexecutor), [T24.I](2-stride-analysis.md#mcpexecutor), [T29.I](2-stride-analysis.md#toolshandler), [T66.I](2-stride-analysis.md#intelligencedb), [T68.R](2-stride-analysis.md#intelligencedb), [T77.I](2-stride-analysis.md#whoisrdap) |

#### Description

> **[Existing]**

Documents the information-disclosure control set: the client-visible error-message allowlist, finding auto-sanitization (`createFinding()`), privacy-preserving analytics (FNV-1a IP hash, truncated key hash), AES-GCM-encrypted access-log IP evidence, and structured-output gating per client type. Strengthened this window: the 90-day access-log retention is now enforced by a scheduled delete (T68.R fixed), and JSON-RPC error codes are emitted to analytics for attribution without leaking detail to clients.

#### Evidence

**Prerequisite basis:** Public `/mcp` error and output surfaces (Exposure Table: `None`).

`src/lib/json-rpc.ts` `SAFE_ERROR_PREFIXES` (`Missing required`, `Invalid`, `Domain `, `Resource not found`, `Rate limit exceeded`) — unchanged, intact; `src/scheduled.ts:89-100` parameterized `mcp_access_log` retention delete; `src/mcp/dispatch.ts:188-200` structured-comment stripping gated by client allowlists.

#### Remediation

Any new client-visible error must start with an allowlisted prefix (enforced by convention + review); nothing further required.

#### Verification

Forced internal errors return the generic fallback; access-log rows older than 90 days are absent after the cron runs.

---

## Tier 2 — Conditional Risk (Authenticated / Single Prerequisite)

### FIND-19: M365 tenant authorization is delegated cross-service on a forwarded keyHash

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Moderate |
| CVSS 4.0 | 5.5 (CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N) |
| CWE | [CWE-862](https://cwe.mitre.org/data/definitions/862.html): Missing Authorization |
| OWASP | A01:2025 – Broken Access Control |
| Exploitation Prerequisites | Authenticated User |
| Exploitability Tier | Tier 2 — Conditional Risk |
| Remediation Effort | Medium |
| Mitigation Type | Custom Mitigation |
| Component | M365Proxy |
| Related Threats | [T79.S](2-stride-analysis.md#m365proxy), [T80.I](2-stride-analysis.md#m365proxy), [T81.I](2-stride-analysis.md#m365proxy), [T83.A](2-stride-analysis.md#m365proxy) |

#### Description

> **[New]**

The identity-secops tools (`query_signins`, `query_ual`, `get_ca_policies`, `assess_coverage`) let an authenticated caller name an arbitrary `ms_tenant_id`. bv-mcp forwards the request to bv-web's internal M365 proxy carrying the *trusted* internal bearer plus the caller's `keyHash`; whether the caller is entitled to that tenant is decided entirely in bv-web. bv-mcp's own guards (401 pre-dispatch, keyHash backstop) ensure a real principal is always forwarded, but a bv-web-side scope-check failure would be a cross-tenant read of highly sensitive sign-in/audit data. The distinguishable `m365_proxy_*` error codes also allow modest tenant-ID enumeration.

#### Evidence

**Prerequisite basis:** `AUTH_REQUIRED_TOOLS` rejects unauthenticated callers with HTTP 401 pre-dispatch (`src/mcp/execute.ts:601-603`) — matches the M365Proxy exposure row (`Authenticated User`).

`src/tools/m365/proxy.ts:32-40` — internal bearer + `keyHash: opts?.keyHash` forwarded; `src/handlers/tools.ts:909-912` — backstop rejects dispatch when `m365Proxy` is bound and `keyHash` absent (the 3.17.2 P0 fix made this path correct for authenticated callers); `src/tools/m365/proxy.ts:41-49` — upstream statuses map to distinct error codes.

#### Remediation

Treat bv-web's tenant-membership check on `keyHash` as a tested cross-repo contract (bv-web-prod#97 lineage): add a contract test or runbook check that `keyHash: undefined` and out-of-scope `keyHash` are rejected upstream. Bleach `m365_proxy_*` errors to a generic "unavailable" for non-owner callers to blunt enumeration.

#### Verification

With a valid developer key entitled to tenant A, `query_signins` for tenant B returns an authorization error (not data); responses for nonexistent vs unauthorized tenants are indistinguishable.

### FIND-12: Internal routes default to no bearer auth

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

> **[Fixed]**

`/internal/tools/*` and `/internal/analytics/*` previously relied on the network-origin guard alone unless bearer auth was explicitly enabled. The gate is now secure-by-default: bearer auth is ACTIVE unless `REQUIRE_INTERNAL_AUTH=false` is explicitly set, fails closed (503) when the key is unconfigured, and 401s wrong/missing bearers. The agent-chat caller principal added in #391 further constrains the highest-volume internal caller to a 13-tool read-only allowlist.

#### Evidence

**Prerequisite basis:** `/internal/*` reachable only via in-account service bindings; public requests 404 via `isPublicInternetRequest` (Exposure Table: `Internal Network`).

`src/internal.ts:165-182` — `internalLenientAuthGate`: opt-out only via explicit `REQUIRE_INTERNAL_AUTH === 'false'`; 503 when `BV_WEB_INTERNAL_KEY` unset; 401 on bad bearer. Covers `/tools/*`, `/analytics/*`, `/tenants/*`. Agent-chat allowlist at `src/internal.ts:217-223,419-422`.

#### Remediation

None — keep bv-web sending the bearer (deploy sequencing already validated in production since 3.17.x).

#### Verification

Binding call without bearer → 401; with correct bearer → 200; with `REQUIRE_INTERNAL_AUTH=false` → network guard only (documented escape hatch).

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
| Mitigation Type | Custom Mitigation |
| Component | OAuthIssuer |
| Related Threats | [T20.A](2-stride-analysis.md#oauthissuer) |

#### Description

> **[Fixed]**

A customer who downgraded (or cancelled) could keep using a previously-issued long-lived JWT at the old tier until `exp`. Two independent mechanisms now close this: per-subject token-version (`ver`) revocation — bumping the stored version invalidates all earlier tokens — and, new this window, JWT lifetime clamped to the remaining Stripe entitlement window at issuance, with expired entitlements rejected outright at token exchange.

#### Evidence

**Prerequisite basis:** Requires a previously-issued valid paid-tier JWT (`Authenticated User`).

`src/oauth/jwt.ts:32` (`ver` claim, default 1); `src/oauth/storage.ts:139-144` (`bumpTokenVersion()`); `src/lib/tier-auth.ts:128-135` (reject `tokenVer < storedVer`); `src/oauth/token.ts:167-181` (TTL clamp to `entitlementExpiresAt`; `invalid_grant` 400 when already lapsed).

#### Remediation

Residual cross-repo step: confirm bv-web calls the revoke endpoint on plan downgrade (pre-existing tokens with `ver=1` stay valid until first bump or `exp` — the TTL clamp bounds this to the entitlement window).

#### Verification

After `bumpTokenVersion(subject)`, a previously-valid JWT is rejected; a token minted 1 day before entitlement end carries ≤1 day TTL.

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
| Mitigation Type | Custom Mitigation |
| Component | BrandAuditPipeline |
| Related Threats | [T53.T](2-stride-analysis.md#brandauditpipeline), [T54.I](2-stride-analysis.md#brandauditpipeline), [T56.A](2-stride-analysis.md#brandauditpipeline) |

#### Description

> **[Partial]**

A paid caller can run brand audits against domains they do not own, harvesting competitor/third-party infrastructure intelligence at scale. Quotas, tier gating (now developer+ via the paid gate), and the opt-out registry bound the volume, and ownership attestation exists — but it remains **caller-supplied**; the planned DNS-TXT challenge that would make ownership cryptographically verifiable has not landed in this window.

#### Evidence

**Prerequisite basis:** Brand tools are paid-gated (`GATED_PAID_ONLY_TOOLS`) — `Authenticated User` per the exposure table.

`src/lib/db/brand-audit-schema.ts` — no `ownership_verified` enforcement field; `owner_id` records the caller's principal only; no DNS-TXT challenge logic in `src/lib/brand-audit-pipeline.ts` / `src/tenants/discovery/` at HEAD.

#### Remediation

Implement the DNS-TXT ownership challenge for third-party watched domains before relying on attestation for any access decision; keep per-tier quotas as the volume bound.

#### Verification

Registering a watch for a domain without the expected TXT record should require (or flag) unverified ownership once the challenge ships.

### FIND-18: Recon operation IDs are not bound to the requesting principal on poll

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Low |
| CVSS 4.0 | 4.1 (CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N) |
| CWE | [CWE-639](https://cwe.mitre.org/data/definitions/639.html): Authorization Bypass Through User-Controlled Key |
| OWASP | A01:2025 – Broken Access Control |
| Exploitation Prerequisites | Authenticated User |
| Exploitability Tier | Tier 2 — Conditional Risk |
| Remediation Effort | Medium |
| Mitigation Type | Custom Mitigation |
| Component | BvRecon |
| Related Threats | [T84.S](2-stride-analysis.md#bvrecon), [T86.I](2-stride-analysis.md#bvrecon) |

#### Description

> **[New]**

The OSINT/bucket start→poll pattern returns an opaque operation ID; the pollers (`osint_investigation_status/_report`, `scan_buckets_status/_findings`) forward any caller-supplied ID to bv-recon with the shared service bearer and no principal association. A caller who learns another principal's ID (logs, shared transcripts, support snippets) could retrieve their investigation results. IDs are unguessable UUIDs and the pollers stay free-tier, so practical risk hinges on ID leakage plus whether bv-recon enforces ownership — which this repo cannot verify.

#### Evidence

**Prerequisite basis:** Recon `*_start` tools are paid-gated; pollers require knowledge of a live operation ID (`Authenticated User` floor for the component).

`src/tools/osint-investigate.ts:115-145` — status/report take only `id`; `src/lib/recon-binding.ts:141-212` — ID forwarded in URL with shared `BV_RECON_KEY` bearer; `src/tools/scan-buckets.ts:40-50` — same pattern for bucket scans. Request-dedup is principal-scoped, but that protects creation, not polling.

#### Remediation

Bind operation IDs to the creating `keyHash` (KV map `opId → keyHash` at start, checked on poll), or verify and contract-test that bv-recon enforces per-caller ownership of investigation/scan IDs.

#### Verification

Polling a valid operation ID created by principal A using principal B's key returns not-found/forbidden.

### FIND-15: Trial-key tier persists during cache window

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

> **[Fixed]**

An expired or exhausted trial key could retain its tier for up to 60 seconds via the resolution cache. Cache hits now re-check the stored `trialExpiresAt` and evict stale entries, falling through to a fresh lookup.

#### Evidence

**Prerequisite basis:** Requires possession of a (recently expired) trial key (`Authenticated User`).

`src/lib/tier-auth.ts:190-193` — on cache hit, expired `trialExpiresAt` → evict + re-resolve.

#### Remediation

None — covered; keep the cache TTL at 60 s.

#### Verification

A trial key one second past expiry resolves to free/unauthenticated on the next call even within the cache window.

### FIND-20: M365 identity tools are intentionally unmetered per-tool

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Low |
| CVSS 4.0 | 3.5 (CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N) |
| CWE | [CWE-770](https://cwe.mitre.org/data/definitions/770.html): Allocation of Resources Without Limits or Throttling |
| OWASP | A06:2025 – Insecure Design |
| Exploitation Prerequisites | Authenticated User |
| Exploitability Tier | Tier 2 — Conditional Risk |
| Remediation Effort | Low |
| Mitigation Type | Custom Mitigation |
| Component | M365Proxy |
| Related Threats | [T82.D](2-stride-analysis.md#m365proxy) |

#### Description

> **[New]**

The four identity-secops tools sit in `INTENTIONALLY_UNLIMITED_TOOLS` (no per-tool daily quota) on the rationale that they are never reachable by free/anonymous callers. An authenticated customer (or a stolen key) can therefore drive unbounded M365 query volume through bv-web to Microsoft Graph, bounded only by global/per-IP caps — a cost-amplification and upstream-throttling risk rather than an outage risk.

#### Evidence

**Prerequisite basis:** `AUTH_REQUIRED_TOOLS` gate — `Authenticated User` floor.

`src/lib/config.ts:457-467` — M365 tools listed in `INTENTIONALLY_UNLIMITED_TOOLS` with the never-free rationale; no per-principal metering in `src/handlers/tools.ts` M365 dispatch paths.

#### Remediation

Add a per-principal daily quota for the identity_secops group (modest, e.g. matching the tier's scans/day), or meter on the bv-web side where Graph costs accrue.

#### Verification

A single developer key issuing sustained `query_signins` volume hits a per-principal limit before exhausting bv-web/Graph budgets.

### FIND-21: Recon upstream payloads lack injection-focused test coverage

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Low |
| CVSS 4.0 | 3.0 (CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N) |
| CWE | [CWE-1427](https://cwe.mitre.org/data/definitions/1427.html): Improper Neutralization of Input Used for LLM Prompting |
| OWASP | A05:2025 – Injection |
| Exploitation Prerequisites | Authenticated User |
| Exploitability Tier | Tier 2 — Conditional Risk |
| Remediation Effort | Low |
| Mitigation Type | Standard Mitigation |
| Component | BvRecon |
| Related Threats | [T85.T](2-stride-analysis.md#bvrecon) |

#### Description

> **[New]**

Bucket-scan and threat-feed results contain attacker-controllable strings (bucket names, object keys, feed entries) that are spread into finding `metadata` and reach LLM clients via `structuredContent` — an indirect prompt-injection channel. The shared sanitizer (`sanitize-upstream`) strips control bytes/ANSI and clamps depth/length on these payloads, but the bucket/threat-feed spread pattern lacks dedicated injection tests, so regressions in the sanitization path would ship silently.

#### Evidence

**Prerequisite basis:** Recon tools are paid-gated (`Authenticated User`); the injected content targets downstream LLM consumers.

`src/tools/scan-buckets.ts:31,45,57` and `src/tools/check-realtime-threat-feed.ts:69` — `sanitizeUpstreamObject(...)` spread into metadata; `src/lib/sanitize-upstream.ts:49-69` — `sanitizeDnsData` per string, `MAX_META_DEPTH=6`, `MAX_META_STRING=8000`; OSINT status/report paths apply the same helper with test coverage, bucket/feed paths do not.

#### Remediation

Add injection-shaped fixtures (ANSI, C0, prompt-injection phrases, oversized strings) to the bucket-scan and threat-feed specs asserting post-sanitization metadata; consider an allowlist of expected upstream fields instead of opaque spread.

#### Verification

New specs fail if `sanitizeUpstreamObject` is removed from either spread site.

### FIND-16: Internal isolation & dependency hardening (existing control)

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
| Related Threats | [T19.E](2-stride-analysis.md#oauthissuer), [T40.S](2-stride-analysis.md#dnsresolver), [T41.T](2-stride-analysis.md#dnsresolver), [T48.S](2-stride-analysis.md#internalrouter), [T49.T](2-stride-analysis.md#internalrouter), [T50.D](2-stride-analysis.md#internalrouter), [T51.E](2-stride-analysis.md#internalrouter), [T59.T](2-stride-analysis.md#profileaccumulator), [T60.A](2-stride-analysis.md#profileaccumulator), [T69.S](2-stride-analysis.md#bvweb), [T70.I](2-stride-analysis.md#bvweb), [T71.D](2-stride-analysis.md#bvweb), [T72.S](2-stride-analysis.md#publicdoh), [T73.T](2-stride-analysis.md#publicdoh), [T74.D](2-stride-analysis.md#publicdoh), [T75.T](2-stride-analysis.md#certtransparency), [T76.D](2-stride-analysis.md#certtransparency), [T78.D](2-stride-analysis.md#whoisrdap), [T90.T](2-stride-analysis.md#bvtlsprobe), [T93.A](2-stride-analysis.md#internalrouter) |

#### Description

> **[Existing]**

Documents the internal-surface and dependency hardening controls: the public-request guard, strict bearer gate on credential-minting routes, batch input constraints, authenticated sibling-worker bindings, multi-resolver DoH with fallbacks, and bounded external-data ingestion. Strengthened this window by the secure-by-default lenient gate (FIND-12), the agent-chat 13-tool read-only allowlist with exact-set audit, tenant-scope intersection enforcement (`X-Tenant-Scope` ∩ `TENANT_KEY_SCOPE` with `denyIfOutOfScope` coverage audit), the tenant-resolver active-flag recheck, and a proper domain-suffix MX-platform matcher replacing an unanchored substring regex.

#### Evidence

**Prerequisite basis:** All listed surfaces require in-account binding or on-path network position (`Internal Network`).

`src/internal.ts:123-125` (`isPublicInternetRequest`), `:203-205` + config body caps, `:217-223,419-422` (agent-chat allowlist); `src/tenants/routes.ts:107-180` (`assertTenantScope` intersection + `denyIfOutOfScope`); `src/tenants/tenant-resolver.ts:115-149` (active-flag recheck, fail-open on transient read errors only); `src/tenants/discovery/mx-platform-detector.ts:27-41` (suffix matcher).

#### Remediation

None — keep the exact-set and coverage audits green; extend the allowlist pattern to future internal caller principals.

#### Verification

Public request to `/internal/tools/call` → 404; agent-chat caller invoking a non-allowlisted tool → 403 `agent_tool_not_allowed`; out-of-scope tenant access → denied.

---

## Tier 3 — Defense-in-Depth (Prior Compromise / Host Access)

### FIND-17: Sensitive KV records rely on platform isolation only

| Attribute | Value |
|-----------|-------|
| SDL Bugbar Severity | Low |
| CVSS 4.0 | 4.2 (CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N) |
| CWE | [CWE-311](https://cwe.mitre.org/data/definitions/311.html): Missing Encryption of Sensitive Data |
| OWASP | A04:2025 – Cryptographic Failures |
| Exploitation Prerequisites | Host/OS Access |
| Exploitability Tier | Tier 3 — Defense-in-Depth |
| Remediation Effort | Medium |
| Mitigation Type | Custom Mitigation |
| Component | RateLimitKV |
| Related Threats | [T62.I](2-stride-analysis.md#sessionstorekv), [T65.I](2-stride-analysis.md#ratelimitkv) |

#### Description

> **[Partial]**

Sensitive KV records (trial keys, OAuth artifacts) historically relied on Cloudflare's at-rest encryption and account isolation alone. An AES-256-GCM application-layer envelope (`kv-envelope.ts`, versioned wire format, no-op when `KV_ENVELOPE_KEY` unset) shipped and is wired on the OAuth grants path — but trial-key records are **not yet wrapped** (`src/lib/trial-keys.ts` unchanged in this window), and the envelope is inert anywhere the secret is unset. This contradicts the interim overlay's "fixed" status; the disagreement is logged in Needs Verification.

#### Evidence

**Prerequisite basis:** KV namespaces have no listeners; reading them requires Cloudflare account/host access (Exposure Table: `Host/OS Access`).

`src/lib/kv-envelope.ts` — `sealKv`/`openKv`/`isSealed`/`parseEnvelopeKey` (AES-256-GCM, `v{n}:iv:ct`); `src/internal.ts:299` — envelope parsed on the OAuth path; `src/lib/trial-keys.ts` — no envelope usage (no diff f75ca7d→HEAD). Compensating controls: trial keys are bounded-lifetime (14-day default) and quota-limited.

#### Remediation

Wrap trial-key writes/reads in `sealKv`/`openKv` (with `isSealed` migration handling); confirm `KV_ENVELOPE_KEY` is set in production overrides and plan key-version rotation.

#### Verification

New trial-key KV values start with the `v1:` envelope prefix; reads of legacy plaintext records still succeed during migration.

---

## Threat Coverage Verification

| Threat ID | Finding ID | Status |
|-----------|------------|--------|
| T01.S | FIND-10 | ✅ Mitigated (FIND-10) |
| T02.T | FIND-10 | ✅ Mitigated (FIND-10) |
| T03.R | FIND-11 | ✅ Mitigated (FIND-11) |
| T04.I | FIND-11 | ✅ Mitigated (FIND-11) |
| T05.I | FIND-04 | ✅ Covered (FIND-04) |
| T06.D | FIND-10 | ✅ Mitigated (FIND-10) |
| T07.A | FIND-02 | ✅ Mitigated (FIND-02) |
| T08.S | FIND-08 | ✅ Mitigated (FIND-08) |
| T09.S | FIND-08 | ✅ Mitigated (FIND-08) |
| T10.T | FIND-08 | ✅ Mitigated (FIND-08) |
| T11.I | FIND-01 | ✅ Covered (FIND-01) |
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
| T53.T | FIND-14 | ✅ Covered (FIND-14) |
| T54.I | FIND-14 | ✅ Covered (FIND-14) |
| T55.D | FIND-10 | ✅ Mitigated (FIND-10) |
| T56.A | FIND-14 | ✅ Covered (FIND-14) |
| T57.T | — | 🔄 Mitigated by Platform |
| T58.D | FIND-10 | ✅ Mitigated (FIND-10) |
| T59.T | FIND-16 | ✅ Mitigated (FIND-16) |
| T60.A | FIND-16 | ✅ Mitigated (FIND-16) |
| T61.T | — | 🔄 Mitigated by Platform |
| T62.I | FIND-17 | ✅ Mitigated (FIND-17) |
| T63.T | — | 🔄 Mitigated by Platform |
| T64.T | — | 🔄 Mitigated by Platform |
| T65.I | FIND-17 | ✅ Covered (FIND-17) |
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
| T77.I | FIND-11 | ✅ Mitigated (FIND-11) |
| T78.D | FIND-16 | ✅ Mitigated (FIND-16) |
| T79.S | FIND-19 | ✅ Mitigated (FIND-19) |
| T80.I | FIND-19 | ✅ Covered (FIND-19) |
| T81.I | FIND-19 | ✅ Covered (FIND-19) |
| T82.D | FIND-20 | ✅ Covered (FIND-20) |
| T83.A | FIND-19 | ✅ Mitigated (FIND-19) |
| T84.S | FIND-18 | ✅ Mitigated (FIND-18) |
| T85.T | FIND-21 | ✅ Covered (FIND-21) |
| T86.I | FIND-18 | ✅ Covered (FIND-18) |
| T87.D | FIND-03 | ✅ Mitigated (FIND-03) |
| T88.A | FIND-03 | ✅ Mitigated (FIND-03) |
| T89.I | FIND-09 | ✅ Covered (FIND-09) |
| T90.T | FIND-16 | ✅ Mitigated (FIND-16) |
| T91.D | FIND-10 | ✅ Mitigated (FIND-10) |
| T92.E | FIND-08 | ✅ Mitigated (FIND-08) |
| T93.A | FIND-16 | ✅ Mitigated (FIND-16) |
