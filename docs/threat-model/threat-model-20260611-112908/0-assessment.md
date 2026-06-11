# Security Assessment

---

## Report Files

| File | Description |
|------|-------------|
| [0-assessment.md](0-assessment.md) | This document — executive summary, risk rating, action plan, metadata |
| [0.1-architecture.md](0.1-architecture.md) | Architecture overview, components, scenarios, tech stack |
| [1-threatmodel.md](1-threatmodel.md) | Threat model DFD diagram with element, flow, and boundary tables |
| [1.1-threatmodel.mmd](1.1-threatmodel.mmd) | Pure Mermaid DFD source file |
| [1.2-threatmodel-summary.mmd](1.2-threatmodel-summary.mmd) | Summary DFD for large systems |
| [2-stride-analysis.md](2-stride-analysis.md) | Full STRIDE-A analysis for all components |
| [3-findings.md](3-findings.md) | Prioritized security findings with remediation |
| [incremental-comparison.html](incremental-comparison.html) | Visual comparison report |

---

## Executive Summary

Blackveil DNS (`bv-mcp`) is a publicly-exposed Cloudflare Worker exposing 75 DNS/email-security tools via an MCP server (JSON-RPC over Streamable HTTP), an OAuth 2.1 issuer for paid tiers, a multi-tenant subsystem, and internal service-binding routes. This is an **incremental** threat model: it inherits the component inventory of baseline `threat-model-20260524-114907` (commit `7e23243`) and the interim remediation overlay at `f75ca7d`, and verifies the full posture against commit `7a1c6b3` (v3.18.0) — a window of 230 commits / ~159 PRs.

The window is strongly net-defensive. Twelve baseline threats are now code-verified **fixed** — among them the distributed free-tier abuse vector (per-IP distinct-domain cap), the scanner-as-recon-proxy vector (paid-only gating with HTTP 403), the insecure-by-default internal bearer gate (now secure-by-default), JWT tier persistence after downgrade (token-version revocation + entitlement TTL clamp), and access-log retention (now enforced by cron). Three new attack surfaces arrived with new features: the **M365Proxy** identity-secops tool family (highly sensitive sign-in/audit data, tenant authorization delegated to bv-web), the **BvRecon** OSINT/bucket-scan binding (cross-principal poll-ID and LLM prompt-injection considerations), and the **BvTlsProbe** enrichment binding. These produce 15 new threats and 4 new findings, all Tier 2 — none are exploitable without a valid credential.

The analysis covers 26 system elements across 5 trust boundaries.

### Risk Rating: Low

All Tier 1 threats except two deploy-config activations are mitigated in code; the four remaining [Partial] items are deploy-config activations (`REJECT_QUERY_API_KEY`, `OAUTH_ISSUER`), a pending DNS-TXT ownership challenge, and trial-key envelope adoption. The new exposure is concentrated in authenticated, paid-tier surfaces whose residual risk depends on cross-service contracts (bv-web tenant scoping, bv-recon ID ownership) — verifiable, bounded, and listed in Needs Verification.

> **Note on threat counts:** This analysis identified 93 threats across 24 analyzed components. This count reflects comprehensive STRIDE-A coverage, not systemic insecurity. Of these, **40 are directly exploitable** without prerequisites (Tier 1) — 38 are mitigated by existing controls and 2 (query-key acceptance, Host-derived issuer) await deploy-config activation of already-merged mechanisms. The remaining 53 represent conditional risks and defense-in-depth considerations.

---

## Action Summary

| Tier | Description | Threats | Findings | Priority |
|------|-------------|---------|----------|----------|
| [Tier 1](3-findings.md#tier-1--direct-exposure-no-prerequisites) | Directly exploitable | 40 | 11 | 🔴 Critical Risk |
| [Tier 2](3-findings.md#tier-2--conditional-risk-authenticated--single-prerequisite) | Requires authenticated access | 34 | 9 | 🟠 Elevated Risk |
| [Tier 3](3-findings.md#tier-3--defense-in-depth-prior-compromise--host-access) | Requires prior compromise | 19 | 1 | 🟡 Moderate Risk |
| **Total** | | **93** | **21** | |

### Priority by Tier and CVSS Score (Top 10)

| Finding | Tier | CVSS Score | SDL Severity | Title |
|---------|------|------------|-------------|-------|
| [FIND-01](3-findings.md#find-01-api-key-accepted-via-query-parameter) | T1 | 5.3 | Moderate | API key accepted via query parameter |
| [FIND-02](3-findings.md#find-02-free-tier-abuse-via-distributed-ips) | T1 | 5.3 | Moderate | Free-tier abuse via distributed IPs |
| [FIND-03](3-findings.md#find-03-scanner-usable-as-reconamplification-proxy) | T1 | 5.1 | Moderate | Scanner usable as recon/amplification proxy |
| [FIND-04](3-findings.md#find-04-oauth-issuer-from-spoofable-host-header) | T1 | 4.8 | Moderate | OAuth issuer from spoofable Host header |
| [FIND-05](3-findings.md#find-05-open-oauth-dynamic-client-registration) | T1 | 4.3 | Low | Open OAuth dynamic client registration |
| [FIND-06](3-findings.md#find-06-force_refresh-cache-busting-amplification) | T1 | 3.7 | Low | force_refresh cache-busting amplification |
| [FIND-07](3-findings.md#find-07-domain-validation-hardening-for-homoglyphidn) | T1 | 3.1 | Low | Domain validation hardening for homoglyph/IDN |
| [FIND-08](3-findings.md#find-08-authentication--token-integrity-controls-existing-control) | T1 | 2.3 | Low | Authentication & token-integrity controls (existing control) |
| [FIND-09](3-findings.md#find-09-ssrf-egress-controls-existing-control) | T1 | 2.3 | Low | SSRF egress controls (existing control) |
| [FIND-10](3-findings.md#find-10-rate-limiting-quotas--dos-budgets-existing-control) | T1 | 2.3 | Low | Rate limiting, quotas & DoS budgets (existing control) |

### Quick Wins

| Finding | Title | Why Quick |
|---------|-------|-----------|
| [FIND-01](3-findings.md#find-01-api-key-accepted-via-query-parameter) | API key accepted via query parameter | Code is merged — set `REJECT_QUERY_API_KEY=true` in the private deploy overrides once Smithery clients are migrated |
| [FIND-04](3-findings.md#find-04-oauth-issuer-from-spoofable-host-header) | OAuth issuer from spoofable Host header | Code is merged — set `OAUTH_ISSUER` in the private deploy overrides and route discovery through the strict resolver |

---

## Change Summary

### Component Changes

| Status | Count | Components |
|--------|-------|------------|
| Unchanged | 11 | BrandAuditPipeline, CertTransparency, DnsResolver, McpClient, Operator, ProfileAccumulator, PublicDoH, QuotaCoordinator, SafeFetch, SessionStoreKV, WhoisRdap |
| Modified | 12 | BvWeb, DomainSanitizer, HonoWorker, IntelligenceDB, InternalRouter, McpExecutor, OAuthIssuer, RateLimitKV, RateLimiter, ScanCacheKV, TierAuthResolver, ToolsHandler |
| New | 3 | BvRecon, BvTlsProbe, M365Proxy |
| Removed | 0 | — |

### Threat Status

| Status | Count |
|--------|-------|
| Existing | 66 |
| Fixed | 12 |
| New | 15 |
| Removed | 0 |

### Finding Status

| Status | Count |
|--------|-------|
| Existing | 6 |
| Fixed | 7 |
| Partial | 4 |
| New | 4 |
| Removed | 0 |

### Risk Direction

Improving — every Tier 1 finding from the baseline is fixed or control-locked, and the window added gating/quota/authorization controls faster than it added attack surface; the 4 new findings are all Tier 2, credential-gated, and dominated by cross-service verification work rather than code defects.

---

## Previously Unidentified Issues

No previously unidentified issues found. All four new findings (FIND-18–21) arise from code added after the baseline (`new_code`), not from gaps in the prior analysis. The baseline's one over-report (FIND-05) was already corrected in the interim overlay and re-verified here.

| Finding | Title | Component | Evidence |
|---------|-------|-----------|----------|
| — | — | — | — |

---

## Analysis Context & Assumptions

### Analysis Scope

| Constraint | Description |
|------------|-------------|
| Scope | Incremental source-level STRIDE-A re-verification of the `bv-mcp` Cloudflare Worker (commit `7a1c6b3`) against the 2026-05-24 baseline: all baseline components re-checked, diff window f75ca7d→7a1c6b3 analyzed, new components fully modeled. |
| Excluded | Sibling-worker internals (bv-web, bv-recon, bv-tls-probe, bv-dns) — modeled as external trust targets; `threat-model-*` folders, `node_modules`, `dist`. |
| Focus Areas | New service-binding surfaces (M365/recon/TLS-probe), free-tier gating + distinct-domain cap, internal-route auth defaults + agent-chat allowlist, OAuth revocation/TTL, baseline finding status re-verification. |

### Infrastructure Context

| Category | Discovered from Codebase | Findings Affected |
|----------|--------------------------|-------------------|
| Edge platform | Cloudflare Worker, public `/mcp` + `/oauth/*`; `global_fetch_strictly_public` flag ([wrangler.jsonc](../../../wrangler.jsonc)) | FIND-09 |
| Service bindings | bv-web (validate-key/entitlements/M365), BV_RECON, BV_TLS_PROBE, BV_CERTSTREAM, BV_WHOIS — operator-deploy-only bindings absent on BSL self-hosts ([src/index.ts](../../../src/index.ts)) | FIND-18, FIND-19, FIND-20 |
| State | KV (RATE_LIMIT/SCAN_CACHE/SESSION_STORE), D1 (INTELLIGENCE_DB/BRAND_AUDIT_DB), 2 Durable Objects | FIND-17 |
| CI guardrails | Exact-set audits: gated-tools SSOT, agent-tool allowlist, tenant-scope coverage, tool-quota coverage ([test/audits/](../../../test/audits/)) | FIND-03, FIND-16 |

### Needs Verification

| Item | Question | What to Check | Why Uncertain |
|------|----------|---------------|---------------|
| bv-web M365 tenant scoping (FIND-19) | Does bv-web reject `keyHash` values not entitled to the requested `ms_tenant_id` (and `keyHash: undefined`)? | bv-web-prod `/api/internal/m365/*` handlers; add a cross-repo contract test | Enforcement lives in a different repo; bv-mcp only forwards the principal |
| bv-recon poll-ID ownership (FIND-18) | Does bv-recon bind investigation/bucket-scan IDs to the creating caller? | bv-recon route handlers for `/osint/*` status/report and `/buckets/api/*` | bv-mcp forwards IDs with a shared bearer; ownership check not visible here |
| bv-tls-probe host validation (T89.I) | Does the probe refuse internal/reserved targets? | bv-tls-probe worker source (local-only repo) | Probe is operator-controlled but its validation is outside this repo |
| Deploy gates (FIND-01, FIND-04) | Are `REJECT_QUERY_API_KEY=true` and `OAUTH_ISSUER` set in production overrides? | `.dev/wrangler.deploy.jsonc` / private overlay + live discovery response | Code defaults remain permissive; fixes are config-activated |
| KV envelope adoption (FIND-17) | Is `KV_ENVELOPE_KEY` set in prod, and when will trial-key records be wrapped? | Private deploy overrides; `src/lib/trial-keys.ts` | **Disagreement with interim overlay:** it marked FIND-17 fixed; this analysis found trial keys still unwrapped (envelope live on the OAuth path only) — downgraded to [Partial] per code evidence |
| bv-web revoke call (FIND-13 residual) | Does bv-web call `POST /internal/oauth/revoke-subject` on plan downgrade? | bv-web-prod billing/downgrade flow | TTL clamp bounds the exposure, but the revoke call completes the design |
| M365 per-principal metering (FIND-20) | Should identity_secops gain a per-principal daily quota? | Product decision + bv-web Graph cost telemetry | Current unlimited status is intentional but cost exposure is unbounded per key |

### Finding Overrides

| Finding ID | Original Severity | Override | Justification | New Status |
|------------|-------------------|----------|---------------|------------|
| — | — | — | No overrides applied. Update this section after review. | — |

### Additional Notes

Threat IDs T01–T78 and finding IDs FIND-01–17 are stable against the baseline for cross-report tracing; the interim overlay's per-finding statuses were re-derived from code rather than carried forward (one downgrade: FIND-17). The `tenants/`, `queue/`, and `workers/infra-probe` code remains folded into existing components per the baseline's modeling judgment (tenant routes under InternalRouter, queue consumers under BrandAuditPipeline).

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
| OWASP LLM Top 10 | https://owasp.org/www-project-top-10-for-large-language-model-applications/ | Prompt-injection surface (FIND-21) |
| NIST SP 800-81r3 | https://csrc.nist.gov/pubs/sp/800/81/r3/final | DNS security control context |

### Component Documentation

| Component | Documentation URL | Relevant Section |
|-----------|------------------|------------------|
| Cloudflare Workers | https://developers.cloudflare.com/workers/ | Service bindings, `global_fetch_strictly_public`, KV/D1/DO isolation |
| Model Context Protocol | https://modelcontextprotocol.io/specification/2025-06-18 | Streamable HTTP transport, protocol-version header, structuredContent |
| OAuth 2.1 / PKCE | https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1 | Authorization-code flow, dynamic client registration |
| Microsoft Graph (sign-in/audit logs) | https://learn.microsoft.com/en-us/graph/api/resources/signin | Data sensitivity of identity_secops surface |

---

## Report Metadata

| Field | Value |
|-------|-------|
| Source Location | `/Applications/Github/bv-mcp` |
| Git Repository | `https://github.com/MadaBurns/bv-mcp.git` |
| Git Branch | `main` |
| Git Commit | `7a1c6b3` (`2026-06-11 00:41:51 +1200`) |
| Model | `claude-fable-5` |
| Machine Name | `Adams-MacBook-Pro.local` |
| Analysis Started | `2026-06-11 11:29:08 UTC` |
| Analysis Completed | `2026-06-11 12:34:00 UTC` |
| Duration | `~65 minutes` |
| Output Folder | `docs/threat-model/threat-model-20260611-112908` |
| Prompt | `/threat-model-analyst` (incremental mode selected against the 2026-05-24 baseline) |
| Baseline Report | `docs/threat-model/threat-model-20260524-114907` |
| Baseline Commit | `7e23243` (`2026-05-24`) |
| Target Commit | `7a1c6b3` (`2026-06-11`) |
| Baseline Worktree | `.worktrees/baseline-f75ca7d` (diff base `f75ca7d`, `2026-05-25`) |
| Analysis Mode | `Incremental` |

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
| **OWASP** | OWASP Top 10:2025 mapping (e.g., A01:2025 – Broken Access Control) |
| **CWE** | Hyperlinked CWE ID (e.g., [CWE-306](https://cwe.mitre.org/data/definitions/306.html)) |
