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
export { formatScanReport, buildStructuredScanResult } from './scan/format-report';
export type { StructuredScanResult } from './scan/format-report';
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
	// Uses Promise.allSettled so that completed checks are preserved on timeout.
	const ALL_CHECK_CATEGORIES: CheckCategory[] = [
		'spf', 'dmarc', 'dkim', 'dnssec', 'ssl', 'mta_sts', 'ns', 'caa', 'bimi', 'tlsrpt', 'subdomain_takeover', 'mx',
	];

	const checkPromises = [
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
	];

	let timedOut = false;
	const settled = await Promise.race([
		Promise.allSettled(checkPromises),
		new Promise<PromiseSettledResult<CheckResult>[]>((resolve) =>
			setTimeout(() => {
				timedOut = true;
				// Snapshot whatever has settled so far by racing each promise with an immediate rejection
				resolve(
					Promise.allSettled(
						checkPromises.map((p) => Promise.race([p, new Promise<never>((_, reject) => reject(new Error('__check_pending__')))])),
					),
				);
			}, SCAN_TIMEOUT_MS),
		),
	]);

	let checkResults = settled
		.filter((r): r is PromiseFulfilledResult<CheckResult> => r.status === 'fulfilled')
		.map((r) => r.value);

	// For any checks that didn't complete, add a timeout finding
	if (timedOut) {
		const completedCategories = new Set(checkResults.map((r) => r.category));
		for (const category of ALL_CHECK_CATEGORIES) {
			if (!completedCategories.has(category)) {
				checkResults.push(
					buildCheckResult(category, [
						createFinding(
							category,
							`${category.toUpperCase()} check timed out`,
							'low',
							`Check did not complete within the ${SCAN_TIMEOUT_MS / 1000}s scan time limit. Try running this check individually.`,
						),
					]),
				);
			}
		}
	}

	let result: ScanDomainResult;
	try {
		checkResults = await applyScanPostProcessing(domain, checkResults, runtimeOptions);

		const score = computeScanScore(checkResults);
		const maturity = computeMaturityStage(checkResults);

		result = {
			domain,
			score,
			checks: checkResults,
			maturity,
			cached: false,
			timestamp: new Date().toISOString(),
		};
	} catch {
		// Post-processing or scoring failed — return whatever we have
		const score = computeScanScore(checkResults);
		const maturity = computeMaturityStage(checkResults);
		result = {
			domain,
			score,
			checks: checkResults,
			maturity,
			cached: false,
			timestamp: new Date().toISOString(),
		};
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

