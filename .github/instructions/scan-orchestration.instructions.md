---
description: Use when modifying scan_domain orchestration, maturity staging, post-processing adjustments, partial timeout handling, or scan report formatting in this repository.
name: Scan Orchestration
applyTo: src/tools/scan-domain.ts
---
# Scan Orchestration

## Parallel execution

`scan_domain` runs the 19 scan categories in parallel via `Promise.allSettled`. The single source is the `CHECK_DISPATCH` registry in `src/tools/scan-domain.ts`:
spf, dmarc, dkim, dnssec, ssl, mta_sts, ns, caa, bimi, tlsrpt, subdomain_takeover, mx, http_security, dane, dane_https, svcb_https, subdomailing, ptr, dnskey_strength. `SCAN_CATEGORIES` and the retry switch derive from it.

When `profile: 'authoritative_dns_infra'` is selected, scan orchestration runs only `checkAuthoritativeDnsInfra` and `checkRootServerSet`, then merges them into the `authoritative_dns_infra` category.

All checks are **static imports** — no dynamic imports in scan context (unlike `check_mx` in `handlers/tools.ts`).

## Timeouts and partial results

- Per-check timeout: `PER_CHECK_TIMEOUT_MS = 8_000` (8s)
- Total scan timeout: `SCAN_TIMEOUT_MS = 15_000` (15s; the env override is clamped to 5-30s)
- Completed checks are preserved on timeout; missing checks get timeout findings
- Scan context skips secondary DNS confirmation for speed

## Post-processing adjustments

`applyScanPostProcessing()` in `src/tools/scan/post-processing.ts` applies adjustments after all checks complete, including:

1. **Non-apex hosts** (e.g. `www.example.com`): absent host-label mail records are not reported as security failures
2. **Non-mail domains** (no inbound mail): downgrades email-auth findings to `info` only when the parent's DMARC `sp=`/`p=` is `quarantine`/`reject`
3. **No-send signal** (SPF `noSendPolicy` metadata): downgrades DKIM/MTA-STS/BIMI missing-record findings to `info`
4. **BIMI**: wording rewritten for non-mail domains (text only)
5. **Impersonation escalation**: a mail-sending domain with weak/absent DMARC and active lookalike/shadow domains is escalated

## Maturity staging

`computeMaturityStage()` in `src/tools/scan/maturity-staging.ts` classifies domains into stages 0-4:
- Stage 0: Unprotected
- Stage 1-2: Basic/Monitoring
- Stage 3: Enforcing (SPF + DMARC quarantine/reject; does not require DKIM or DNSSEC)
- Stage 4: Hardened (Stage 3 + at least 2 of {MTA-STS, DNSSEC, BIMI, DANE, CAA, DKIM-discovered}, at least one being DNSSEC, MTA-STS or DANE)

`web_only`/`non_mail` domains use a second ladder (Transport-Hardened, Defensive, Comprehensive).

`capMaturityStage()` caps by the displayed 6-band NIST grade: F (<60) → max Stage 2, D (60-69) → max Stage 3.

## Caching

- Keys are versioned, `cache:v<serverVersion>-dc<dnsChecksVersion>:<domain>[:check:<name>|:profile:<profile>]`, built by `buildCheckCacheKey` / `buildScanCacheKey` (`src/lib/cache.ts`)
- Per-check entries: 5 min default, `cacheTtlSeconds` override
- `force_refresh` propagates via `skipCache` in `runWithCache()`

## Output structure

- `formatScanReport()` in `src/tools/scan/format-report.ts` → human-readable text
- `buildToolContent()` wraps text + structured JSON for `format=full` clients
- `StructuredScanResult` interface defined in `src/tools/scan/format-report.ts`

## Reference docs

- Scoring model: [docs/scoring.md](../../docs/scoring.md)
- Request flow: `src/index.ts` (Hono app) → `src/mcp/dispatch.ts` (JSON-RPC routing) → `src/handlers/tools.ts` (TOOL_REGISTRY) → individual checks under `src/tools/`. Trace the imports directly; the standalone architecture-diagram doc was removed in 2026-05-08 to keep this source-available repo focused on customer-facing material.
