// SPDX-License-Identifier: BUSL-1.1

/**
 * scan-domain orchestrator tool.
 * Runs all DNS security checks in parallel via Promise.all
 * and computes an overall security score.
 *
 * Uses KV-backed cache with 5-minute TTL for scan results when available,
 * with in-memory fallback when KV is not configured.
 * Compatible with Cloudflare Workers runtime (no Node.js APIs).
 */

import {
	type CheckCategory,
	type CheckResult,
	type DomainContext,
	type DomainProfile,
	type ScanScore,
	buildCheckResult,
	computeScanScore,
	createFinding,
	detectDomainContext,
	getProfileWeights,
} from '../lib/scoring';
import {
	adaptiveWeightsToContext,
	generateScoringNote,
	type AdaptiveWeightsResponse,
	type ScanTelemetry,
} from '../lib/adaptive-weights';
import { cacheGet, cacheSet, runWithCache } from '../lib/cache';
import type { QueryDnsOptions } from '../lib/dns-types';
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
import { checkHttpSecurity } from './check-http-security';
import { checkDane } from './check-dane';
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
const PER_CHECK_TIMEOUT_MS = 8_000;

/** Maximum wall-clock time for the entire scan_domain orchestration (ms). */
const SCAN_TIMEOUT_MS = 12_000;

/** In-memory cache for adaptive weight responses from the ProfileAccumulator DO. */
const adaptiveWeightCache = new Map<string, { weights: AdaptiveWeightsResponse; expires: number }>();

/** TTL for the in-memory adaptive weight cache (ms). */
const ADAPTIVE_CACHE_TTL_MS = 60_000;

/** Maximum entries in the adaptive weight cache before eviction. */
const ADAPTIVE_CACHE_MAX_ENTRIES = 100;

/** Timeout for fetching adaptive weights from the DO (ms). */
const ADAPTIVE_FETCH_TIMEOUT_MS = 50;

export interface ScanDomainResult {
	domain: string;
	score: ScanScore;
	checks: CheckResult[];
	maturity: MaturityStage;
	context: DomainContext;
	cached: boolean;
	timestamp: string;
	scoringNote: string | null;
	adaptiveWeightDeltas: Record<string, number> | null;
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
	const explicitProfile = runtimeOptions?.profile;
	const isExplicit = explicitProfile && explicitProfile !== 'auto';
	const cacheKey = isExplicit
		? `${CACHE_PREFIX}${domain}:profile:${explicitProfile}`
		: `${CACHE_PREFIX}${domain}`;

	// Check cache first
	const cached = await cacheGet<ScanDomainResult>(cacheKey, kv);
	if (cached) {
		return { ...cached, cached: true };
	}

	// Run all checks in parallel with per-check timeouts, wrapped in an
	// overall scan timeout to guarantee a timely response.
	// Uses Promise.allSettled so that completed checks are preserved on timeout.
	const ALL_CHECK_CATEGORIES: CheckCategory[] = [
		'spf', 'dmarc', 'dkim', 'dnssec', 'ssl', 'mta_sts', 'ns', 'caa', 'bimi', 'tlsrpt', 'subdomain_takeover', 'http_security', 'dane', 'mx',
	];

	// Skip secondary DNS confirmation in scan context for speed — individual checks
	// still use secondary confirmation when called directly by users.
	const scanDns: QueryDnsOptions = { skipSecondaryConfirmation: true };

	const checkPromises = [
		runCachedCheck(domain, 'spf', () => safeCheck('spf', () => checkSpf(domain, scanDns)), kv),
		runCachedCheck(domain, 'dmarc', () => safeCheck('dmarc', () => checkDmarc(domain, scanDns)), kv),
		runCachedCheck(domain, 'dkim', () => safeCheck('dkim', () => checkDkim(domain, undefined, scanDns)), kv),
		runCachedCheck(domain, 'dnssec', () => safeCheck('dnssec', () => checkDnssec(domain, scanDns)), kv),
		runCachedCheck(domain, 'ssl', () => safeCheck('ssl', () => checkSsl(domain)), kv),
		runCachedCheck(domain, 'mta_sts', () => safeCheck('mta_sts', () => checkMtaSts(domain, scanDns)), kv),
		runCachedCheck(domain, 'ns', () => safeCheck('ns', () => checkNs(domain, scanDns)), kv),
		runCachedCheck(domain, 'caa', () => safeCheck('caa', () => checkCaa(domain, scanDns)), kv),
		runCachedCheck(domain, 'bimi', () => safeCheck('bimi', () => checkBimi(domain, scanDns)), kv),
		runCachedCheck(domain, 'tlsrpt', () => safeCheck('tlsrpt', () => checkTlsrpt(domain, scanDns)), kv),
		runCachedCheck(domain, 'subdomain_takeover', () => safeCheck('subdomain_takeover', () => checkSubdomainTakeover(domain, scanDns)), kv),
		runCachedCheck(domain, 'http_security', () => safeCheck('http_security', () => checkHttpSecurity(domain)), kv),
		runCachedCheck(domain, 'dane', () => safeCheck('dane', () => checkDane(domain, scanDns)), kv),
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
						}, scanDns),
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

		// Detect domain context from check results
		let domainContext = detectDomainContext(checkResults);

		// If an explicit profile was requested, override detection
		if (isExplicit) {
			domainContext = {
				profile: explicitProfile as DomainProfile,
				signals: [...domainContext.signals, `explicit profile override: ${explicitProfile}`],
				weights: getProfileWeights(explicitProfile as DomainProfile, runtimeOptions?.scoringConfig),
				detectedProvider: domainContext.detectedProvider,
			};
		}

		// Phase 1: only pass context to scoring when an explicit profile is set.
		// For 'auto' (or unset), detection runs and is reported but scoring
		// uses the default weights (identical to pre-profile behavior).
		const scoringContext = isExplicit ? domainContext : undefined;

		// Attempt to fetch adaptive weights from the ProfileAccumulator DO
		let adaptiveResponse: AdaptiveWeightsResponse | null = null;
		if (runtimeOptions?.profileAccumulator) {
			adaptiveResponse = await fetchAdaptiveWeights(
				runtimeOptions.profileAccumulator,
				domainContext.profile,
				domainContext.detectedProvider,
			);
		}

		// Add bound hits to signals if present
		if (adaptiveResponse?.boundHits.length) {
			domainContext.signals.push(`adaptive bound hits: ${adaptiveResponse.boundHits.join(', ')}`);
		}

		let score: ScanScore;
		let scoringNote: string | null = null;
		let adaptiveWeightDeltas: Record<string, number> | null = null;

		if (adaptiveResponse && adaptiveResponse.sampleCount > 0) {
			const adaptiveWeights = adaptiveWeightsToContext(adaptiveResponse.weights, domainContext.profile);
			if (adaptiveWeights) {
				// Compute adaptive score
				const adaptiveContext: DomainContext = { ...domainContext, weights: adaptiveWeights };
				const adaptiveScore = computeScanScore(checkResults, adaptiveContext, runtimeOptions?.scoringConfig);

				// Compute static score for comparison
				const staticContext: DomainContext = {
					...domainContext,
					weights: getProfileWeights(domainContext.profile, runtimeOptions?.scoringConfig),
				};
				const staticScore = computeScanScore(checkResults, scoringContext ?? staticContext, runtimeOptions?.scoringConfig);

				// Compute per-category weight deltas
				const staticWeights = getProfileWeights(domainContext.profile, runtimeOptions?.scoringConfig);
				const deltas: Record<string, number> = {};
				for (const cat of Object.keys(staticWeights) as CheckCategory[]) {
					deltas[cat] = adaptiveWeights[cat].importance - staticWeights[cat].importance;
				}

				const scoreDelta = adaptiveScore.overall - staticScore.overall;
				scoringNote = generateScoringNote(deltas, scoreDelta, domainContext.detectedProvider);
				adaptiveWeightDeltas = deltas;
				score = adaptiveScore;
			} else {
				score = computeScanScore(checkResults, scoringContext, runtimeOptions?.scoringConfig);
			}
		} else {
			score = computeScanScore(checkResults, scoringContext, runtimeOptions?.scoringConfig);
		}

		const maturity = computeMaturityStage(checkResults);

		result = {
			domain,
			score,
			checks: checkResults,
			maturity,
			context: domainContext,
			cached: false,
			timestamp: new Date().toISOString(),
			scoringNote,
			adaptiveWeightDeltas,
		};

		// POST telemetry to DO (best-effort, non-blocking)
		if (runtimeOptions?.profileAccumulator) {
			const telemetry: ScanTelemetry = {
				profile: domainContext.profile,
				provider: domainContext.detectedProvider,
				categoryFindings: checkResults.map((r) => ({ category: r.category, score: r.score, passed: r.passed })),
				timestamp: Date.now(),
			};
			const telemetryPromise = (async () => {
				try {
					const stub = runtimeOptions.profileAccumulator!.get(
						runtimeOptions.profileAccumulator!.idFromName('global'),
					);
					await stub.fetch(
						new Request('https://do/ingest', {
							method: 'POST',
							headers: { 'Content-Type': 'application/json' },
							body: JSON.stringify(telemetry),
						}),
					);
				} catch {
					/* best-effort */
				}
			})();
			if (runtimeOptions.waitUntil) runtimeOptions.waitUntil(telemetryPromise);
		}
	} catch {
		// Post-processing or scoring failed — return whatever we have
		let fallbackContext = detectDomainContext(checkResults);
		if (isExplicit) {
			fallbackContext = {
				profile: explicitProfile as DomainProfile,
				signals: [...fallbackContext.signals, `explicit profile override: ${explicitProfile}`],
				weights: getProfileWeights(explicitProfile as DomainProfile, runtimeOptions?.scoringConfig),
				detectedProvider: fallbackContext.detectedProvider,
			};
		}
		const fallbackScoringContext = isExplicit ? fallbackContext : undefined;
		const score = computeScanScore(checkResults, fallbackScoringContext, runtimeOptions?.scoringConfig);
		const maturity = computeMaturityStage(checkResults);
		result = {
			domain,
			score,
			checks: checkResults,
			maturity,
			context: fallbackContext,
			cached: false,
			timestamp: new Date().toISOString(),
			scoringNote: null,
			adaptiveWeightDeltas: null,
		};
	}

	// Cache the result
	await cacheSet(cacheKey, result, kv);

	return result;
}

/**
 * Fetch adaptive weights from the ProfileAccumulator DO with in-memory caching.
 * Returns null on failure or timeout (silently falls back to static weights).
 */
async function fetchAdaptiveWeights(
	accumulator: DurableObjectNamespace,
	profile: string,
	provider: string | null,
): Promise<AdaptiveWeightsResponse | null> {
	const cacheKey = `${profile}:${provider ?? ''}`;
	const now = Date.now();

	// Check in-memory cache first
	const cached = adaptiveWeightCache.get(cacheKey);
	if (cached && cached.expires > now) {
		return cached.weights;
	}

	try {
		const stub = accumulator.get(accumulator.idFromName('global'));
		const url = new URL('https://do/weights');
		url.searchParams.set('profile', profile);
		if (provider) url.searchParams.set('provider', provider);

		const response = await Promise.race([
			stub.fetch(new Request(url.toString())),
			new Promise<never>((_, reject) => setTimeout(() => reject(new Error('adaptive weight fetch timeout')), ADAPTIVE_FETCH_TIMEOUT_MS)),
		]);

		if (!response.ok) return null;

		const data = (await response.json()) as AdaptiveWeightsResponse;
		if (adaptiveWeightCache.size >= ADAPTIVE_CACHE_MAX_ENTRIES) adaptiveWeightCache.clear();
		adaptiveWeightCache.set(cacheKey, { weights: data, expires: now + ADAPTIVE_CACHE_TTL_MS });
		return data;
	} catch {
		return null;
	}
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
	} catch {
		const message = 'Check failed';
		const findings = [createFinding(category, `${category.toUpperCase()} check error`, 'high', `Check failed: ${message}`)];
		return buildCheckResult(category, findings);
	}
}

