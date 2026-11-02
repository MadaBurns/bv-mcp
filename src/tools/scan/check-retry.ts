// SPDX-License-Identifier: BUSL-1.1

/**
 * Per-check execution helpers for scan_domain: the single-retry policy, the
 * authoritative_dns_infra profile merge, the in-isolate dedup wrapper and the
 * timeout/error-safe check runner. Split out of scan-domain.ts (SQ-537) with no
 * behaviour change.
 */

import { type CheckCategory, type CheckResult, buildCheckResult, createFinding } from '../../lib/scoring';
import { buildCheckCacheKey, runWithCache } from '../../lib/cache';
import type { QueryDnsOptions } from '../../lib/dns-types';
import { CHECK_DISPATCH } from './check-dispatch';
import type { ScanRuntimeOptions } from './post-processing';

/**
 * Decide whether a check result qualifies for a single retry.
 * Retries fire only for transient failures: checks that threw and were
 * caught by safeCheck(), producing checkStatus='error' and score=0.
 * Timeouts (checkStatus='timeout') are excluded because the scan budget
 * is already exhausted in that case.
 */
export function shouldRetry(result: CheckResult): boolean {
	return result.checkStatus === 'error' && result.score === 0;
}

function mergeMetadataArray(results: CheckResult[], key: string): unknown[] {
	const values: unknown[] = [];
	for (const result of results) {
		const value = result.metadata?.[key];
		if (Array.isArray(value)) values.push(...value);
	}
	return [...new Set(values)];
}

function mergeCapabilitySummary(results: CheckResult[]): Record<string, string[]> {
	const passed = new Set<string>();
	const failed = new Set<string>();
	const inconclusive = new Set<string>();
	for (const result of results) {
		const summary = result.metadata?.capabilitySummary as { passed?: string[]; failed?: string[]; inconclusive?: string[] } | undefined;
		for (const capability of summary?.passed ?? []) passed.add(capability);
		for (const capability of summary?.failed ?? []) failed.add(capability);
		for (const capability of summary?.inconclusive ?? []) inconclusive.add(capability);
	}
	return {
		passed: [...passed],
		failed: [...failed],
		inconclusive: [...inconclusive],
	};
}

export function mergeAuthoritativeDnsInfraResults(results: CheckResult[]): CheckResult {
	const findings = results.flatMap((result) => result.findings);
	const merged = buildCheckResult('authoritative_dns_infra', findings);
	const evidenceModes = new Set(results.map((result) => result.metadata?.evidenceMode));
	const checkStatus = results.find((result) => result.checkStatus)?.checkStatus;
	return {
		...merged,
		...(results.some((result) => result.partial) ? { partial: true } : {}),
		...(checkStatus ? { checkStatus } : {}),
		metadata: {
			evidenceMode: evidenceModes.size === 1 ? [...evidenceModes][0] : 'mixed',
			rootServers: mergeMetadataArray(results, 'rootServers'),
			capabilitySummary: mergeCapabilitySummary(results),
		},
	};
}

/**
 * Dispatch a single check retry for the given category with fresh DNS options.
 * Uses a tighter timeout than the initial scan check to protect the budget.
 */
export async function runCheckRetry(
	category: CheckCategory,
	domain: string,
	scanDns: QueryDnsOptions,
	retryTimeoutMs: number,
	runtimeOptions?: ScanRuntimeOptions,
): Promise<CheckResult> {
	const retryDns: QueryDnsOptions = { ...scanDns, queryCache: new Map() };
	const timeoutPromise = new Promise<never>((_, reject) => setTimeout(() => reject(new Error('Retry timed out')), retryTimeoutMs));

	const checkPromise = CHECK_DISPATCH[category]?.(domain, retryDns, runtimeOptions);
	if (!checkPromise) {
		// Unsupported category (e.g. profile-only authoritative_dns_infra) — synthetic error result.
		return { ...buildCheckResult(category, []), score: 0, passed: false, checkStatus: 'error' as const, partial: true };
	}

	return Promise.race([checkPromise, timeoutPromise]);
}

/**
 * Run one scored check with in-isolate dedup, writing NOTHING to KV or memory.
 *
 * SQ-498: a cold scan used to write one `...:check:<category>` entry per category (19 scored + 6
 * web posture) alongside the single scan-level entry: ~27 SCAN_CACHE puts for one scan. Measured
 * over 7 days of production tool_call events, only ~1.3k direct check_* calls hit such an entry
 * (against ~800 cold scans' worth of writes), 95% of them from owner-tier sweeps rather than
 * customers, and a repeat scan is answered by the scan-level entry, not these. So the scan keeps
 * the scan-level entry (the 5-min scan cache) and no longer persists its per-check results.
 *
 * What stays: `runWithCache` still shares the in-flight promise for the same key, so two
 * concurrent scans of one domain in an isolate run each check once, and it reads the in-memory
 * cache. `shouldCache` is false so nothing is written there either (a memory write per category
 * would churn the 1000-entry fallback cache that short-TTL poller results rely on). Direct
 * check_* calls keep their own KV-backed per-check cache under the same key.
 */
export function runDedupedCheck(
	domain: string,
	category: CheckCategory,
	run: () => Promise<CheckResult>,
	skipCache?: boolean,
): Promise<CheckResult> {
	return runWithCache(buildCheckCacheKey(domain, category), run, undefined, undefined, skipCache, () => false, true);
}

/**
 * Run a single check with error handling and a per-check timeout.
 * If a check fails or exceeds the timeout, returns a failed CheckResult
 * with an error/timeout finding instead of throwing, so other checks
 * can still complete.
 */
export async function safeCheck(
	category: CheckCategory,
	fn: () => Promise<CheckResult>,
	perCheckTimeoutMs: number,
	onTimeout?: () => void,
	queueClock?: () => number,
): Promise<CheckResult> {
	let timer: ReturnType<typeof setTimeout> | undefined;
	try {
		const result = await Promise.race([
			fn(),
			new Promise<never>((_, reject) => {
				// #952: the budget is for the check's own work, not for waiting on the
				// shared DoH pool. batch_scan runs its scans through ONE 5-slot pool, and
				// measured at 150ms DoH latency checks expired while their queries sat
				// QUEUED — excluding categories a single scan of the same domain measured
				// fine. Widening the pool cannot buy real parallelism (the Workers runtime
				// caps an invocation at 6 connections waiting for headers), so instead each
				// time the timer fires it is extended by the pool-saturated time accrued
				// since it was last armed. Still bounded by the scan race and batch budget.
				let saturatedAtArm = queueClock?.() ?? 0;
				const arm = (ms: number) => {
					timer = setTimeout(() => {
						const queued = (queueClock?.() ?? 0) - saturatedAtArm;
						if (queued > 0) {
							saturatedAtArm += queued;
							arm(queued);
							return;
						}
						// R7: fire the per-check abort BEFORE rejecting so the orphaned
						// raw-fetch subrequests of THIS check are cancelled the moment the
						// per-check budget is exceeded. Fail-soft: an onTimeout throw must
						// not mask the timeout rejection.
						try {
							onTimeout?.();
						} catch {
							/* best-effort abort — never let it swallow the timeout */
						}
						reject(new Error('Check timed out'));
					}, ms);
				};
				arm(perCheckTimeoutMs);
			}),
		]);
		return result;
	} catch (err) {
		const rawMessage = err instanceof Error ? err.message : 'Check failed';
		const isTimeout = rawMessage === 'Check timed out';
		const SAFE_PREFIXES = ['DNS query', 'Check timed out', 'Check failed', 'Connection', 'timeout'];
		const safeMessage = SAFE_PREFIXES.some((p) => rawMessage.startsWith(p)) ? rawMessage : 'Check failed';

		// Timeouts are infrastructure issues, not security findings — use 'low' severity
		// and 'timeout' status consistent with scan-level timeout handling.
		// Actual errors (DNS failures, connection errors) remain 'high' severity.
		const severity = isTimeout ? 'low' : ('high' as const);
		const title = isTimeout ? `${category.toUpperCase()} check timed out` : `${category.toUpperCase()} check error`;
		const detail = isTimeout
			? `Check did not complete within the ${perCheckTimeoutMs / 1000}s per-check time limit. Try running this check individually.`
			: `Check failed: ${safeMessage}`;
		const checkStatus = isTimeout ? ('timeout' as const) : ('error' as const);

		const findings = [createFinding(category, title, severity, detail)];
		const result = buildCheckResult(category, findings);
		// `partial: true` keeps the one-off transient error OUT of the 5-min per-check
		// cache that direct check_* calls use (their shouldCache predicate is `!partial`),
		// so it self-heals and is not served to them.
		// `passed: false` explicitly: buildCheckResult derived `passed: true` from the
		// single high/low finding's score (75/95), which survived the `score: 0` spread —
		// the post-processing re-apply masked it in scan output, but the intermediate
		// result must carry the same not-assessed contract as buildDnsErrorResult.
		return { ...result, score: 0, passed: false, checkStatus, partial: true };
	} finally {
		if (timer !== undefined) clearTimeout(timer);
	}
}
