# Security Assessment — Incremental Update

> **Scope of this incremental pass.** This is a focused change-tracked comparison of the baseline threat model (`../threat-model-20260524-114907/`, commit `7e23243`) against the current `main` (commit `f75ca7d`, after the remediation in PR #208 and this model's own merge in #209). Because the architecture, DFD, trust boundaries, and per-component/finding detail are **structurally unchanged** from the baseline (no new or removed deployment components), this update does not re-emit those 8 files — it records what *changed*: component/threat/finding status deltas, the risk direction, and items needing verification. See `incremental-comparison.html` for the visual before/after, and the baseline folder for full per-component detail.

## Report Files

| File | Description |
|------|-------------|
| [0-assessment.md](0-assessment.md) | This incremental assessment — change summary, risk direction, verification items |
| [incremental-comparison.html](incremental-comparison.html) | Visual baseline→target comparison (status cards, component grid, STRIDE heatmap) |
| [threat-inventory.json](threat-inventory.json) | Incremental inventory (`schema_version: 1.1`) with `change_status` per component/finding + status summary |
| `../threat-model-20260524-114907/` | **Baseline** — full architecture, DFD, STRIDE-A, findings (statuses now read `Mitigated`) |

## Executive Summary

The remediation branch (PR #208) addressed every finding from the baseline threat model. Of the baseline's 17 findings, **9 are fully fixed in code**, **2 are partially mitigated** (mechanism landed; cross-repo/crypto follow-up pending), **1 was a false positive** (already mitigated on `main`), and **5 are existing controls** now locked with regression tests. No new findings and no new or removed deployment components were introduced; the remediation added controls, not attack surface.

The analysis covers 23 system elements across 5 trust boundaries — unchanged from baseline. 10 components were modified (security-relevant), 13 unchanged.

> **Note on threat counts:** The baseline identified 78 STRIDE-A threats. In this update **13 are fixed**, **3 partially mitigated**, **1 reclassified** (false positive), and **61 still present** (already-mitigated existing controls + platform-handled, carried forward). **0 new threats.**

### Risk Rating: Low (was Moderate)

### Risk Direction: Improving

The directly-exploitable (Tier 1) abuse and information-disclosure findings — query-string credential exposure, distributed free-tier abuse, scanner-as-proxy, `force_refresh` amplification, homoglyph inputs, and the spoofable OAuth issuer — are now mitigated in code. Residual risk is concentrated in **deploy-config activation** (`OAUTH_ISSUER`, `KV_ENVELOPE_KEY`, flipping `REJECT_QUERY_API_KEY`) and **cross-repo coordination** (bv-web must send the internal bearer and call the new revoke endpoint), which fully close FIND-12/13/14. With those follow-ups complete, residual risk is Low.

## Change Summary

### Component Changes

| Status | Count | Components |
|--------|-------|------------|
| Unchanged | 13 | SafeFetch, DnsResolver, BrandAuditPipeline, QuotaCoordinator, ProfileAccumulator, ScanCacheKV, IntelligenceDB, BvWeb, PublicDoH, CertTransparency, WhoisRdap, McpClient, Operator |
| Modified | 10 | HonoWorker, TierAuthResolver, OAuthIssuer, McpExecutor, ToolsHandler, DomainSanitizer, RateLimiter, InternalRouter, SessionStoreKV, RateLimitKV |
| New | 0 | — |
| Removed | 0 | — |

> `kv-envelope.ts` was added but is a crypto **helper** consumed by the storage components (SessionStoreKV, RateLimitKV, OAuthIssuer) — not a standalone deployment component.

### Threat Status

| Status | Count |
|--------|-------|
| Still Present (carried-forward mitigated/platform) | 61 |
| Fixed | 13 |
| Partially Mitigated | 3 |
| Reclassified (false positive) | 1 |
| New | 0 |
| Removed with Component | 0 |

### Finding Status

| Status | Count | Findings |
|--------|-------|----------|
| Fixed | 9 | FIND-01, 02, 03, 04, 06, 07, 12, 15, 17 |
| Partially Mitigated | 2 | FIND-13 (token-version mechanism; needs bv-web revoke call), FIND-14 (ownership attestation; DNS-TXT challenge pending) |
| Reclassified — false positive | 1 | FIND-05 (registration rate-limit + client TTL already on `main`) |
| Still Present (existing control, now test-locked) | 5 | FIND-08, 09, 10, 11, 16 |
| New | 0 | — |

## Previously Unidentified Issues

No vulnerabilities were missed in the baseline that the current analysis newly identifies. One baseline **over-report** was corrected: **FIND-05** ("Open OAuth dynamic client registration") was already mitigated at the baseline commit (`src/oauth/register.ts` per-IP 10/min + 30/hr limit; `src/oauth/storage.ts` client TTL) — the original recon examined `token.ts` and missed `register.ts`.

## Analysis Context & Assumptions

### Needs Verification

| Item | Question | What to Check |
|------|----------|---------------|
| Token-version revocation (FIND-13) | Does bv-web call the new endpoint on plan downgrade? | bv-web service client → `POST /internal/oauth/revoke-subject`; note `ver` defaults to 1, so pre-existing tokens stay valid until first revoke or `exp` |
| Brand-audit ownership (FIND-14) | Is the `ownership_verified` attestation enforced cryptographically? | It is currently **caller-supplied**; a DNS-TXT challenge is the intended follow-up before relying on it for third-party domains |
| `KV_ENVELOPE_KEY` (FIND-17) | Is the secret set in prod, with rotation planned? | Envelope is a **no-op when unset**; set the 32-byte secret in deploy overrides; plan key-version rotation |
| `REQUIRE_INTERNAL_AUTH` flip (FIND-12) | Does bv-web send the internal bearer before prod relies on it? | If bv-web doesn't send `Authorization: Bearer ${BV_WEB_INTERNAL_KEY}`, `/internal/*` now 401s by default; sequence the bv-web deploy first |
| Deploy-gated fixes (FIND-01, 04) | Are `REJECT_QUERY_API_KEY` / `OAUTH_ISSUER` set in prod? | Code mechanisms are merged; the gate/override values must be set in the private deploy config to be active |

### Finding Overrides

| Finding ID | Original | Override | Justification | New Status |
|------------|----------|----------|---------------|------------|
| FIND-05 | Tier 1 / Open | False positive | Control already present on `main` at baseline commit | Reclassified |

## Report Metadata

| Field | Value |
|-------|-------|
| Git Repository | `https://github.com/MadaBurns/bv-mcp.git` |
| Model | `claude-opus-4-7[1m]` |
| Baseline Report | `../threat-model-20260524-114907/` |
| Baseline Commit | `7e23243` (`2026-05-24`) |
| Target Commit | `f75ca7d` (`2026-05-25`) |
| Code Changes | 2 commits (PR #208 remediation + #209 doc-merge) — 20 source files, +714/−72 |
| Analysis Mode | `Incremental` |
| Analysis Date | `2026-05-25` |

## Classification Reference

| Classification | Values |
|---------------|--------|
| **Change Status** | `Unchanged` · `Modified` · `New` · `Removed` (components) · `Still Present` · `Fixed` · `Partially Mitigated` · `Reclassified` · `New` (threats/findings) |
| **Exploitability Tiers** | **T1** Direct Exposure · **T2** Conditional Risk · **T3** Defense-in-Depth |
| **Risk Direction** | `Improving` · `Worsening` · `Stable` |
