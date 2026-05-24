# Security Assessment

> **Remediation status (updated 2026-05-25).** All findings have been addressed; STRIDE statuses and the coverage table read `Mitigated`. Remediation was **merged to `main` via PR #208** (commit `ffe9f7e`); this report merged via #209. The risk rating below reflects the analyzed commit `7e23243` (pre-remediation), not the post-fix state — see the incremental comparison in `../threat-model-20260524-184006-incremental/` for the before/after. FIND-05 was a false positive (already mitigated on `main`). Deploy/cross-repo follow-ups remain (see PR #208).

---

## Report Files

| File | Description |
|------|-------------|
| [0-assessment.md](0-assessment.md) | This document — executive summary, risk rating, action plan, metadata |
| [0.1-architecture.md](0.1-architecture.md) | Architecture overview, components, scenarios, tech stack |
| [1-threatmodel.md](1-threatmodel.md) | Threat model DFD diagram with element, flow, and boundary tables |
| [1.1-threatmodel.mmd](1.1-threatmodel.mmd) | Pure Mermaid DFD source file |
| [2-stride-analysis.md](2-stride-analysis.md) | Full STRIDE-A analysis for all components |
| [3-findings.md](3-findings.md) | Prioritized security findings with remediation |
| [1.2-threatmodel-summary.mmd](1.2-threatmodel-summary.mmd) | Summary DFD for large systems |

---

## Executive Summary

Blackveil DNS (`bv-mcp`) is a publicly-exposed Cloudflare Worker that exposes ~80 DNS/email-security tools via an MCP server (JSON-RPC over Streamable HTTP), an OAuth 2.1 issuer for paid tiers, a multi-tenant subsystem, and internal service-binding routes. Because it is internet-facing and accepts unauthenticated free-tier traffic, its primary attack surface is the public `/mcp` and `/oauth/*` request path, with secondary surfaces in the service-binding `/internal/*` routes and Cloudflare-managed state (KV, D1, Durable Objects).

The codebase demonstrates a mature security posture. Authentication uses constant-time key comparison and algorithm-pinned HS256 JWTs; outbound requests to attacker-influenced URLs pass through a dedicated SSRF guard (`safeFetch`) layered on a domain sanitizer and Cloudflare's `global_fetch_strictly_public` runtime control; abuse is bounded by multi-layer rate limiting, per-tool quotas, a global daily ceiling, and a fuzzing detector; and privacy-sensitive data (client IPs in access logs) is encrypted at the application layer. The majority of enumerated threats are already mitigated by these existing controls or by the Cloudflare platform.

The analysis covers 23 system elements across 5 trust boundaries.

### Risk Rating: Moderate

The system has no identified critical or directly-exploitable authentication-bypass, injection, or remote-code-execution issues. The directly-exploitable (Tier 1) findings are abuse-resistance and hardening gaps — query-string credential exposure, distributed free-tier abuse, scanner-as-proxy misuse, and a spoofable OAuth issuer — none of which compromise confidentiality or integrity of other users' data on their own. The most material gap is operational: internal tool/analytics routes default to no bearer authentication (`REQUIRE_INTERNAL_AUTH` off by default), which must be enabled in production. Overall residual risk is Moderate, driven by abuse-resistance and configuration hardening rather than core vulnerabilities.

> **Note on threat counts:** This analysis identified 78 threats across 21 components. This count reflects comprehensive STRIDE-A coverage, not systemic insecurity. Of these, **40 are directly exploitable** without prerequisites (Tier 1). The remaining 38 represent conditional risks and defense-in-depth considerations.

---

## Action Summary

| Tier | Description | Threats | Findings | Priority |
|------|-------------|---------|----------|----------|
| [Tier 1](3-findings.md#tier-1--direct-exposure-no-prerequisites) | Directly exploitable | 40 | 11 | 🔴 Critical Risk |
| [Tier 2](3-findings.md#tier-2--conditional-risk-authenticated--single-prerequisite) | Requires authenticated access | 22 | 5 | 🟠 Elevated Risk |
| [Tier 3](3-findings.md#tier-3--defense-in-depth-prior-compromise--host-access) | Requires prior compromise | 16 | 1 | 🟡 Moderate Risk |
| **Total** | | **78** | **17** | |

### Priority by Tier and CVSS Score (Top 10)

| Finding | Tier | CVSS Score | SDL Severity | Title |
|---------|------|------------|-------------|-------|
| [FIND-01](3-findings.md#find-01-api-key-accepted-via-api_key-query-parameter) | T1 | 5.3 | Moderate | API key accepted via `?api_key=` query parameter |
| [FIND-02](3-findings.md#find-02-free-tier-abuse-via-distributed-ips-against-a-shared-global-budget) | T1 | 5.3 | Moderate | Free-tier abuse via distributed IPs against a shared global budget |
| [FIND-03](3-findings.md#find-03-scanner-usable-as-a-reconnaissance--amplification-proxy) | T1 | 5.1 | Moderate | Scanner usable as a reconnaissance / amplification proxy |
| [FIND-04](3-findings.md#find-04-oauth-issuer-derived-from-a-spoofable-host-header) | T1 | 4.8 | Moderate | OAuth issuer derived from a spoofable `Host` header |
| [FIND-05](3-findings.md#find-05-open-oauth-dynamic-client-registration) | T1 | 4.3 | Low | Open OAuth dynamic client registration |
| [FIND-06](3-findings.md#find-06-force_refresh-enables-cache-busting-amplification) | T1 | 3.7 | Low | `force_refresh` enables cache-busting amplification |
| [FIND-07](3-findings.md#find-07-domain-validation-hardening-for-homoglyph--idn-inputs) | T1 | 3.1 | Low | Domain validation hardening for homoglyph / IDN inputs |
| [FIND-08](3-findings.md#find-08-authentication-and-token-integrity-controls-existing-control) | T1 | 2.3 | Low | Authentication and token-integrity controls (existing control) |
| [FIND-09](3-findings.md#find-09-ssrf-egress-controls-existing-control) | T1 | 2.3 | Low | SSRF egress controls (existing control) |
| [FIND-10](3-findings.md#find-10-rate-limiting-quotas-and-dos-budgets-existing-control) | T1 | 2.3 | Low | Rate limiting, quotas, and DoS budgets (existing control) |

### Quick Wins

| Finding | Title | Why Quick |
|---------|-------|-----------|
| [FIND-01](3-findings.md#find-01-api-key-accepted-via-api_key-query-parameter) | API key accepted via `?api_key=` query parameter | Deprecation path already exists; set a cutoff and reject the query param. |
| [FIND-04](3-findings.md#find-04-oauth-issuer-derived-from-a-spoofable-host-header) | OAuth issuer derived from a spoofable `Host` header | Single config value — set `OAUTH_ISSUER` in production. |
| [FIND-05](3-findings.md#find-05-open-oauth-dynamic-client-registration) | Open OAuth dynamic client registration | Add a per-IP registration rate limit and storage TTL. |
| [FIND-06](3-findings.md#find-06-force_refresh-enables-cache-busting-amplification) | `force_refresh` enables cache-busting amplification | Add a small sub-limit for `force_refresh` requests. |

---

## Analysis Context & Assumptions

### Analysis Scope
| Constraint | Description |
|------------|-------------|
| Scope | Source-level STRIDE-A threat model of the `bv-mcp` Cloudflare Worker, OAuth issuer, internal routes, scheduled/queue handlers, Durable Objects, and the `@blackveil/dns-checks` core. |
| Excluded | Cloudflare platform internals; sibling-worker source (bv-web, certstream, whois, intel/enterprise bindings) treated as external trust targets; operator-only private bindings (`BV_INFRA_GRAPH`, `BV_INTEL_GATEWAY`, `BV_ENTERPRISE`) not in the public distribution. |
| Focus Areas | Public request path (auth, SSRF, rate limiting, OAuth), internal-route isolation, secret handling, multi-tenant/brand-audit abuse surface. |

### Infrastructure Context
| Category | Discovered from Codebase | Findings Affected |
|----------|--------------------------|-------------------|
| Deployment | Public Cloudflare Worker; bindings in [wrangler.jsonc](../../../wrangler.jsonc); `global_fetch_strictly_public` enabled | FIND-04, FIND-09 |
| Authentication | Static key + OAuth JWT in [src/lib/tier-auth.ts](../../../src/lib/tier-auth.ts), [src/oauth/](../../../src/oauth/) | FIND-01, FIND-08, FIND-13, FIND-15 |
| SSRF controls | [src/lib/safe-fetch.ts](../../../src/lib/safe-fetch.ts), [src/lib/sanitize.ts](../../../src/lib/sanitize.ts), [src/lib/config.ts](../../../src/lib/config.ts) | FIND-07, FIND-09 |
| Rate limiting / quotas | [src/lib/rate-limiter.ts](../../../src/lib/rate-limiter.ts), [src/lib/quota-coordinator.ts](../../../src/lib/quota-coordinator.ts) | FIND-02, FIND-03, FIND-06, FIND-10 |
| Internal routes | [src/internal.ts](../../../src/internal.ts) (`isPublicInternetRequest`, `REQUIRE_INTERNAL_AUTH`) | FIND-12, FIND-16 |
| State storage | KV/D1/DO; access-log encryption in [src/mcp/execute.ts](../../../src/mcp/execute.ts) | FIND-11, FIND-17 |

### Needs Verification
| Item | Question | What to Check | Why Uncertain |
|------|----------|---------------|---------------|
| `REQUIRE_INTERNAL_AUTH` | Is internal bearer auth enabled in production? | Production `wrangler` vars / `.dev/wrangler.deploy.jsonc` | Default is off in code; production value is not in the public repo. |
| `OAUTH_ISSUER` | Is the issuer override set in production? | Production environment vars | Falls back to Host header when unset; prod value not in repo. |
| IDN/homoglyph handling | Does `sanitizeDomain` fully normalize confusable domains? | Add unit tests for mixed-script/punycode inputs | No explicit confusable-detection tests observed. |
| Trial-key / OAuth-code storage | Are these encrypted at the application layer? | [src/lib/trial-keys.ts](../../../src/lib/trial-keys.ts), [src/oauth/storage.ts](../../../src/oauth/storage.ts) | Only access-log IPs are app-encrypted; KV secrets rely on platform at-rest encryption. |

### Finding Overrides
| Finding ID | Original Severity | Override | Justification | New Status |
|------------|-------------------|----------|---------------|------------|
| — | — | — | No overrides applied. Update this section after review. | — |

### Additional Notes

The finding count (17) is moderate relative to the threat count (78) because most threats are already addressed by existing controls or the Cloudflare platform; four of the seventeen findings (FIND-08–11, FIND-16) are "existing control" entries that document strong controls for regression protection rather than gaps. Platform-mitigated threats account for ~6% of the total, below the 20% suspicion threshold. The `tenants/` subsystem and operator-only tiered-discovery bindings were treated as in-scope behaviorally but their private sibling workers were modeled as external trust targets.

---

## References Consulted

### Security Standards
| Standard | URL | How Used |
|----------|-----|----------|
| Microsoft SDL Bug Bar | https://www.microsoft.com/en-us/msrc/sdlbugbar | Severity classification |
| OWASP Top 10:2025 | https://owasp.org/Top10/2025/ | Threat categorization |
| CVSS 4.0 | https://www.first.org/cvss/v4.0/specification-document | Risk scoring |
| CWE | https://cwe.mitre.org/ | Weakness classification |
| STRIDE | https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats | Threat enumeration |
| OWASP Agentic Security Initiative | https://genai.owasp.org/initiatives/#agenticsecurity | Tool-execution/agentic abuse review lens |

### Component Documentation
| Component | Documentation URL | Relevant Section |
|-----------|------------------|------------------|
| Cloudflare Workers | https://developers.cloudflare.com/workers/ | Runtime, bindings, `global_fetch_strictly_public` |
| Model Context Protocol | https://modelcontextprotocol.io/specification | Streamable HTTP transport, JSON-RPC, OAuth profile |
| Hono | https://hono.dev/ | Routing, CORS middleware |
| DNS over HTTPS (RFC 8484) | https://www.rfc-editor.org/rfc/rfc8484 | DoH transport security |
| OAuth 2.1 / PKCE (RFC 7636) | https://www.rfc-editor.org/rfc/rfc7636 | Authorization-code + PKCE flow |

---

## Report Metadata

| Field | Value |
|-------|-------|
| Source Location | `/Applications/Github/bv-mcp` |
| Git Repository | `https://github.com/MadaBurns/bv-mcp.git` |
| Git Branch | `main` |
| Git Commit | `7e23243` (`2026-05-24 23:32:40 +1200`) |
| Model | `claude-opus-4-7[1m]` |
| Machine Name | `Adams-MacBook-Pro.local` |
| Analysis Started | `2026-05-24 11:49:07 UTC` |
| Analysis Completed | `2026-05-24 12:13:43 UTC` |
| Duration | `~25 minutes` |
| Output Folder | `docs/threat-model/threat-model-20260524-114907` |
| Prompt | `run the threat-model-analyst on bv-mcp` |

---

## Classification Reference

| Classification | Values |
|---------------|--------|
| **Exploitability Tiers** | **T1** Direct Exposure (no prerequisites) · **T2** Conditional Risk (single prerequisite) · **T3** Defense-in-Depth (multiple prerequisites or infrastructure access) |
| **STRIDE + Abuse** | **S** Spoofing · **T** Tampering · **R** Repudiation · **I** Information Disclosure · **D** Denial of Service · **E** Elevation of Privilege · **A** Abuse (feature misuse) |
| **SDL Severity** | `Critical` · `Important` · `Moderate` · `Low` |
| **Remediation Effort** | `Low` · `Medium` · `High` |
| **Mitigation Type** | `Redesign` · `Standard Mitigation` · `Custom Mitigation` · `Existing Control` · `Accept Risk` · `Transfer Risk` |
| **Threat Status** | `Open` · `Mitigated` · `Platform` |
| **Incremental Tags** | `[Existing]` · `[Fixed]` · `[Partial]` · `[New]` · `[Removed]` (incremental reports only) |
| **CVSS** | CVSS 4.0 vector with `CVSS:4.0/` prefix |
| **CWE** | Hyperlinked CWE ID (e.g., [CWE-306](https://cwe.mitre.org/data/definitions/306.html)) |
| **OWASP** | OWASP Top 10:2025 mapping (e.g., A01:2025 – Broken Access Control) |
