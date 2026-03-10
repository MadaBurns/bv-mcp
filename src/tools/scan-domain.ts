// SPDX-License-Identifier: MIT

/**
 * scan-domain orchestrator tool.
 * Runs all DNS security checks in parallel via Promise.all
 * and computes an overall security score.
 *
 * Uses KV-backed cache with 5-minute TTL for scan results when available,
 * with in-memory fallback when KV is not configured.
 * Compatible with Cloudflare Workers runtime (no Node.js APIs).
 */

import { type CheckCategory, type CheckResult, type ScanScore, buildCheckResult, computeScanScore, createFinding } from '../lib/scoring';
import { cacheGet, cacheSet, runWithCache } from '../lib/cache';
import { checkSpf } from './check-spf';
import { checkDmarc } from './check-dmarc';
import { checkDkim } from './check-dkim';
import { checkDnssec } from './check-dnssec';
import { checkSsl } from './check-ssl';
import { checkMtaSts } from './check-mta-sts';
import { checkNs } from './check-ns';
import { checkCaa } from './check-caa';
import { checkBimi } from './check-bimi';
import { checkTlsrpt } from './check-tlsrpt';
import { checkSubdomainTakeover } from './check-subdomain-takeover';
import { checkMx } from './check-mx';
import { applyScanPostProcessing } from './scan/post-processing';
import type { ScanRuntimeOptions } from './scan/post-processing';
import { computeMaturityStage } from './scan/maturity-staging';
import type { MaturityStage } from './scan/maturity-staging';
export { formatScanReport } from './scan/format-report';
export type { MaturityStage } from './scan/maturity-staging';
export type { ScanRuntimeOptions } from './scan/post-processing';

/** Cache key prefix for scan and per-check results */
const CACHE_PREFIX = 'cache:';

/** Maximum wall-clock time for a single check within scan_domain (ms). */
const PER_CHECK_TIMEOUT_MS = 15_000;

/** Maximum wall-clock time for the entire scan_domain orchestration (ms). */
const SCAN_TIMEOUT_MS = 25_000;

export interface ScanDomainResult {
	domain: string;
	score: ScanScore;
	checks: CheckResult[];
	maturity: MaturityStage;
	cached: boolean;
	timestamp: string;
}

/**
 * Run a full DNS security scan on a domain.
 * Executes all checks in parallel and computes an overall score.
 *
 * @param domain - The domain to scan (must already be validated and sanitized by the caller)
 * @param kv - Optional KV namespace for persistent scan result caching
 * @returns Full scan result with score, individual check results, and metadata
 */
export async function scanDomain(domain: string, kv?: KVNamespace, runtimeOptions?: ScanRuntimeOptions): Promise<ScanDomainResult> {
	const cacheKey = `${CACHE_PREFIX}${domain}`;

	// Check cache first
	const cached = await cacheGet<ScanDomainResult>(cacheKey, kv);
	if (cached) {
		return { ...cached, cached: true };
	}

	// Run all checks in parallel with per-check timeouts, wrapped in an
	// overall scan timeout to guarantee a timely response.
	const runAllChecks = async (): Promise<ScanDomainResult> => {
		let checkResults: CheckResult[] = await Promise.all([
			runCachedCheck(domain, 'spf', () => safeCheck('spf', () => checkSpf(domain)), kv),
			runCachedCheck(domain, 'dmarc', () => safeCheck('dmarc', () => checkDmarc(domain)), kv),
			runCachedCheck(domain, 'dkim', () => safeCheck('dkim', () => checkDkim(domain)), kv),
			runCachedCheck(domain, 'dnssec', () => safeCheck('dnssec', () => checkDnssec(domain)), kv),
			runCachedCheck(domain, 'ssl', () => safeCheck('ssl', () => checkSsl(domain)), kv),
			runCachedCheck(domain, 'mta_sts', () => safeCheck('mta_sts', () => checkMtaSts(domain)), kv),
			runCachedCheck(domain, 'ns', () => safeCheck('ns', () => checkNs(domain)), kv),
			runCachedCheck(domain, 'caa', () => safeCheck('caa', () => checkCaa(domain)), kv),
			runCachedCheck(domain, 'bimi', () => safeCheck('bimi', () => checkBimi(domain)), kv),
			runCachedCheck(domain, 'tlsrpt', () => safeCheck('tlsrpt', () => checkTlsrpt(domain)), kv),
			runCachedCheck(domain, 'subdomain_takeover', () => safeCheck('subdomain_takeover', () => checkSubdomainTakeover(domain)), kv),
			runCachedCheck(
				domain,
				'mx',
				() =>
					safeCheck(
						'mx',
						() =>
							checkMx(domain, {
								providerSignaturesUrl: runtimeOptions?.providerSignaturesUrl,
								providerSignaturesAllowedHosts: runtimeOptions?.providerSignaturesAllowedHosts,
								providerSignaturesSha256: runtimeOptions?.providerSignaturesSha256,
							}),
					),
				kv,
			),
		]);

		checkResults = await applyScanPostProcessing(domain, checkResults, runtimeOptions);

		const score = computeScanScore(checkResults);
		const maturity = computeMaturityStage(checkResults);

		return {
			domain,
			score,
			checks: checkResults,
			maturity,
			cached: false,
			timestamp: new Date().toISOString(),
		};
	};

	let result: ScanDomainResult;
	try {
		result = await Promise.race([
			runAllChecks(),
			new Promise<never>((_, reject) => setTimeout(() => reject(new Error('__scan_timeout__')), SCAN_TIMEOUT_MS)),
		]);
	} catch (err) {
		if (err instanceof Error && err.message === '__scan_timeout__') {
			// Overall scan timed out — return a degraded result so the client
			// still gets useful feedback instead of an opaque error.
			const timeoutFinding = createFinding(
				'ns',
				'Scan timed out',
				'low',
				`Full scan of ${domain} exceeded the ${SCAN_TIMEOUT_MS / 1000}s time limit. Some checks may be incomplete. Try running individual checks or retry — results are cached progressively.`,
			);
			const fallbackResults = [buildCheckResult('ns', [timeoutFinding])];
			const score = computeScanScore(fallbackResults);
			const maturity = computeMaturityStage(fallbackResults);
			return {
				domain,
				score,
				checks: fallbackResults,
				maturity,
				cached: false,
				timestamp: new Date().toISOString(),
			};
		}
		throw err;
	}

	// Cache the result
	await cacheSet(cacheKey, result, kv);

	return result;
}

async function runCachedCheck(
	domain: string,
	category: CheckCategory,
	run: () => Promise<CheckResult>,
	kv?: KVNamespace,
): Promise<CheckResult> {
	return runWithCache(`${CACHE_PREFIX}${domain}:check:${category}`, run, kv);
}

/**
 * Run a single check with error handling and a per-check timeout.
 * If a check fails or exceeds the timeout, returns a failed CheckResult
 * with an error/timeout finding instead of throwing, so other checks
 * can still complete.
 */
async function safeCheck(category: CheckCategory, fn: () => Promise<CheckResult>): Promise<CheckResult> {
	try {
		const result = await Promise.race([
			fn(),
			new Promise<never>((_, reject) => setTimeout(() => reject(new Error('Check timed out')), PER_CHECK_TIMEOUT_MS)),
		]);
		return result;
	} catch (err) {
		const message = err instanceof Error ? err.message : 'Check failed';
		const severity = message === 'Check timed out' ? 'low' : 'high';
		const findings = [createFinding(category, `${category.toUpperCase()} check error`, severity, `Check failed: ${message}`)];
		return buildCheckResult(category, findings);
	}
}

