---
description: Use when modifying scan_domain orchestration, maturity staging, post-processing adjustments, partial timeout handling, or scan report formatting in this repository.
name: Scan Orchestration
applyTo: src/tools/scan-domain.ts
---
# Scan Orchestration

## Parallel execution

`scan_domain` runs **16 checks** in parallel via `Promise.allSettled`:
`checkSpf`, `checkDmarc`, `checkDkim`, `checkDnssec`, `checkSsl`, `checkMtaSts`, `checkNs`, `checkCaa`, `checkBimi`, `checkTlsrpt`, `checkSubdomainTakeover`, `checkMx`, `checkHttpSecurity`, `checkDane`, `checkDaneHttps`, `checkSvcbHttps`, `checkSubdomailing`

All checks are **static imports** — no dynamic imports in scan context (unlike `check_mx` in `handlers/tools.ts`).

## Timeouts and partial results

- Per-check timeout: `PER_CHECK_TIMEOUT_MS = 8_000` (8s)
- Total scan timeout: `SCAN_TIMEOUT_MS = 12_000` (12s)
- Completed checks are preserved on timeout; missing checks get timeout findings
- Scan context skips secondary DNS confirmation for speed

## Post-processing adjustments

`applyScanPostProcessing()` in `src/tools/scan/post-processing.ts` applies three adjustments after all checks complete:

1. **Non-mail domains** (no MX): queries parent DMARC `sp=`/`p=` → downgrades email-auth findings to `info`
2. **No-send signal** (SPF `noSendPolicy` metadata): downgrades DKIM/MTA-STS/BIMI missing-record findings to `info`
3. **BIMI**: rewritten for non-mail domains

## Maturity staging

`computeMaturityStage()` in `src/tools/scan/maturity-staging.ts` classifies domains into stages 0-4:
- Stage 0: Unprotected
- Stage 1-2: Basic/Configured
- Stage 3: Enforcing (does not require DKIM)
- Stage 4: Hardened (requires CAA + DKIM-discovered + BIMI + DANE + MTA-STS strict)

`capMaturityStage()` applies score-based caps: F (<50) → max Stage 2, D/D+ (<63) → max Stage 3.

## Caching

- Each check cached at `cache:<domain>:check:<name>` (5 min default, `cacheTtlSeconds` override)
- Top-level scan cached at `cache:<domain>`
- Profile-specific: `cache:<domain>:profile:<profile>`
- `force_refresh` propagates via `skipCache` in `runWithCache()`

## Output structure

- `formatScanReport()` in `src/tools/scan/format-report.ts` → human-readable text
- `buildToolContent()` wraps text + structured JSON for `format=full` clients
- `StructuredScanResult` interface defined in `src/tools/scan/format-report.ts`

## Reference docs

- Scoring model: [docs/scoring.md](../../docs/scoring.md)
- Architecture diagrams: [docs/architecture.md](../../docs/architecture.md)
