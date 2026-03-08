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
import { checkSubdomainTakeover } from './check-subdomain-takeover';
import { checkMx } from './check-mx';
import { applyScanPostProcessing } from './scan/post-processing';
import type { ScanRuntimeOptions } from './scan/post-processing';
export { formatScanReport } from './scan/format-report';

/** Cache key prefix for scan and per-check results */
const CACHE_PREFIX = 'cache:';

export interface ScanDomainResult {
	domain: string;
	score: ScanScore;
	checks: CheckResult[];
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

	// Run all checks in parallel with individual-check caching
	let checkResults: CheckResult[] = await Promise.all([
		runCachedCheck(domain, 'spf', () => safeCheck('spf', () => checkSpf(domain)), kv),
		runCachedCheck(domain, 'dmarc', () => safeCheck('dmarc', () => checkDmarc(domain)), kv),
		runCachedCheck(domain, 'dkim', () => safeCheck('dkim', () => checkDkim(domain)), kv),
		runCachedCheck(domain, 'dnssec', () => safeCheck('dnssec', () => checkDnssec(domain)), kv),
		runCachedCheck(domain, 'ssl', () => safeCheck('ssl', () => checkSsl(domain)), kv),
		runCachedCheck(domain, 'mta_sts', () => safeCheck('mta_sts', () => checkMtaSts(domain)), kv),
		runCachedCheck(domain, 'ns', () => safeCheck('ns', () => checkNs(domain)), kv),
		runCachedCheck(domain, 'caa', () => safeCheck('caa', () => checkCaa(domain)), kv),
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

	// Compute overall score from all check results
	const score = computeScanScore(checkResults);

	const result: ScanDomainResult = {
		domain: domain,
		score,
		checks: checkResults,
		cached: false,
		timestamp: new Date().toISOString(),
	};

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
 * Run a single check with error handling.
 * If a check fails, returns a failed CheckResult with an error finding
 * instead of throwing, so other checks can still complete.
 */
async function safeCheck(category: CheckCategory, fn: () => Promise<CheckResult>): Promise<CheckResult> {
	try {
		return await fn();
	} catch (err) {
		const message = err instanceof Error ? err.message : 'Check failed';
		const findings = [createFinding(category, `${category.toUpperCase()} check error`, 'high', `Check failed: ${message}`)];
		return buildCheckResult(category, findings);
	}
}

