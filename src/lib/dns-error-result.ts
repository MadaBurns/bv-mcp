// SPDX-License-Identifier: BUSL-1.1

/**
 * Shared helper for the DNS-failure-resilience convention (see CLAUDE.md):
 * a tool called directly (not just via scan_domain's safeCheck) should convert
 * a top-level DNS failure into a structured CheckResult instead of throwing, so
 * a direct tools/call returns an actionable finding rather than a generic
 * transport error.
 *
 * The returned shape is byte-for-byte equivalent to what scan-domain's
 * safeCheck() produces when a check throws — `checkStatus: 'error'` + score 0 +
 * a high-severity finding. This matters for the scan path: scan_domain's
 * transient-zero retry (shouldRetry) keys off `checkStatus === 'error'`, and the
 * scoring engine EXCLUDES `checkStatus`-tagged categories as transient failures
 * (renormalised, shown n/a) rather than zeroing them. Using `missingControl`
 * here instead would silently disable the retry and change the display, so do
 * not switch shapes without re-running test/scan-domain.spec.ts retry cases.
 *
 * `partial: true` keeps the transient error OUT of the cache on the direct
 * registry path (handlers/tools.ts uses `(r) => !r.partial` as its shouldCache
 * predicate), so a one-off DNS hiccup on a direct check_* call self-heals on the
 * next call instead of sticking for the 5-minute TTL. (The scan path caches
 * regardless — unchanged from the prior throw→safeCheck behaviour.)
 *
 * `passed: false` is set explicitly: buildCheckResult would otherwise derive
 * `passed: true` from the single-high-finding score (~75) even though we zero the
 * score, leaving a misleading `passed: true` + `score: 0` for direct callers and
 * the aggregators that branch on `.passed` (assess-spoofability, validate-fix,
 * generate-records). An errored check did not pass.
 */

import { buildCheckResult, createFinding, type CheckCategory, type CheckResult } from './scoring';

// Mirrors safeCheck()'s allowlist so the surfaced detail stays bounded/safe.
const SAFE_PREFIXES = ['DNS query', 'Check timed out', 'Check failed', 'Connection', 'timeout'];

/**
 * Build a transient-failure CheckResult for a caught DNS error. `label` is the
 * human-readable control name used in the finding text (e.g. 'DMARC', 'TLS-RPT').
 */
export function buildDnsErrorResult(category: CheckCategory, label: string, err: unknown): CheckResult {
	const rawMessage = err instanceof Error ? err.message : 'Check failed';
	const safeMessage = SAFE_PREFIXES.some((p) => rawMessage.startsWith(p)) ? rawMessage : 'Check failed';
	const findings = [createFinding(category, `${label} check error`, 'high', `Check failed: ${safeMessage}`, { errorKind: 'dns_error' })];
	return { ...buildCheckResult(category, findings), score: 0, passed: false, checkStatus: 'error' as const, partial: true };
}
