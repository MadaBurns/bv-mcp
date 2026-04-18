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
	MATURITY_THRESHOLD,
	type AdaptiveWeightsResponse,
	type ScanTelemetry,
} from '../lib/adaptive-weights';
import { applyInteractionPenalties, type InteractionEffect } from '../lib/category-interactions';
import { cacheGet, cacheSet, runWithCache } from '../lib/cache';
import type { QueryDnsOptions } from '../lib/dns-types';
import { checkSpf } from './check-spf';
import { checkDmarc } from './check-dmarc';
import { checkDkim, applyProviderDkimContext } from './check-dkim';
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
import { checkDaneHttps } from './check-dane-https';
import { checkSvcbHttps } from './check-svcb-https';
import { checkSubdomailing } from './check-subdomailing';
import { applyScanPostProcessing } from './scan/post-processing';
import type { ScanRuntimeOptions } from './scan/post-processing';
import { logError } from '../lib/log';
import { getAdaptiveWeights, publishAdaptiveWeightSummary } from '../lib/profile-accumulator';
import { capMaturityStage, computeMaturityStage } from './scan/maturity-staging';
import type { MaturityStage } from './scan/maturity-staging';
export { formatScanReport, buildStructuredScanResult } from './scan/format-report';
export type { StructuredScanResult, ScanResultEnrichment } from './scan/format-report';
export type { MaturityStage } from './scan/maturity-staging';
export type { ScanRuntimeOptions } from './scan/post-processing';

/** Cache key prefix for scan and per-check results */
const CACHE_PREFIX = 'cache:';

/** Maximum wall-clock time for a single check within scan_domain (ms). */
const PER_CHECK_TIMEOUT_MS = 8_000;

/** Maximum wall-clock time for the entire scan_domain orchestration (ms). */
const SCAN_TIMEOUT_MS = 12_000;

/** Budget (ms) reserved for retry attempts of transiently-failed checks. */
const RETRY_BUDGET_MS = 3_000;

/** Maximum number of checks retried per scan to protect the overall budget. */
const MAX_RETRIES_PER_SCAN = 3;

/** Per-retry timeout (ms) — tighter than the initial 8s per-check timeout. */
const RETRY_TIMEOUT_MS = 2_500;

/** In-memory cache for adaptive weight responses from the ProfileAccumulator DO. */
const adaptiveWeightCache = new Map<string, { weights: AdaptiveWeightsResponse; expires: number }>();

/** TTL for the in-memory adaptive weight cache (ms). */
const ADAPTIVE_CACHE_TTL_MS = 60_000;

/** Maximum entries in the adaptive weight cache before eviction. */
const ADAPTIVE_CACHE_MAX_ENTRIES = 100;

/** Timeout for fetching adaptive weights from the DO (ms). */
const ADAPTIVE_FETCH_TIMEOUT_MS = 200;

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
	/** Category interaction effects applied as post-scoring adjustments. Empty when no interactions triggered. */
	interactionEffects: InteractionEffect[];
}

/**
 * Decide whether a check result qualifies for a single retry.
 * Retries fire only for transient failures: checks that threw and were
 * caught by safeCheck(), producing checkStatus='error' and score=0.
 * Timeouts (checkStatus='timeout') are excluded because the scan budget
 * is already exhausted in that case.
 */
function shouldRetry(result: CheckResult): boolean {
	return result.checkStatus === 'error' && result.score === 0;
}

/**
 * Dispatch a single check retry for the given category with fresh DNS options.
 * Uses a tighter timeout than the initial scan check to protect the budget.
 */
async function runCheckRetry(
	category: CheckCategory,
	domain: string,
	scanDns: QueryDnsOptions,
	runtimeOptions?: ScanRuntimeOptions,
): Promise<CheckResult> {
	const retryDns: QueryDnsOptions = { ...scanDns, queryCache: new Map() };
	const timeoutPromise = new Promise<never>((_, reject) =>
		setTimeout(() => reject(new Error('Retry timed out')), RETRY_TIMEOUT_MS),
	);

	let checkPromise: Promise<CheckResult>;
	switch (category) {
		case 'spf': checkPromise = checkSpf(domain, retryDns); break;
		case 'dmarc': checkPromise = checkDmarc(domain, retryDns); break;
		case 'dkim': checkPromise = checkDkim(domain, undefined, retryDns); break;
		case 'dnssec': checkPromise = checkDnssec(domain, retryDns); break;
		case 'ssl': checkPromise = checkSsl(domain); break;
		case 'mta_sts': checkPromise = checkMtaSts(domain, retryDns); break;
		case 'ns': checkPromise = checkNs(domain, retryDns); break;
		case 'caa': checkPromise = checkCaa(domain, retryDns); break;
		case 'bimi': checkPromise = checkBimi(domain, retryDns); break;
		case 'tlsrpt': checkPromise = checkTlsrpt(domain, retryDns); break;
		case 'subdomain_takeover': checkPromise = checkSubdomainTakeover(domain, retryDns); break;
		case 'http_security': checkPromise = checkHttpSecurity(domain); break;
		case 'dane': checkPromise = checkDane(domain, retryDns); break;
		case 'dane_https': checkPromise = checkDaneHttps(domain, retryDns); break;
		case 'svcb_https': checkPromise = checkSvcbHttps(domain, retryDns); break;
		case 'subdomailing': checkPromise = checkSubdomailing(domain, retryDns); break;
		case 'mx':
			checkPromise = checkMx(domain, {
				providerSignaturesUrl: runtimeOptions?.providerSignaturesUrl,
				providerSignaturesAllowedHosts: runtimeOptions?.providerSignaturesAllowedHosts,
				providerSignaturesSha256: runtimeOptions?.providerSignaturesSha256,
			}, retryDns);
			break;
		default:
			// Unsupported category — return a synthetic error result
			return { ...buildCheckResult(category, []), score: 0, passed: false, checkStatus: 'error' as const };
	}

	return Promise.race([checkPromise, timeoutPromise]);
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
	// scanId: generated once per scan for threading to analytics degradation events.
	// Currently unused here — callers will pass it when emitDegradationEvent sites migrate.
	const _scanId = crypto.randomUUID();
	const scanStartTime = Date.now();
	const explicitProfile = runtimeOptions?.profile;
	const isExplicit = explicitProfile && explicitProfile !== 'auto';
	const cacheKey = isExplicit
		? `${CACHE_PREFIX}${domain}:profile:${explicitProfile}`
		: `${CACHE_PREFIX}${domain}`;

	// Check cache first (skip when force_refresh is requested)
	if (!runtimeOptions?.forceRefresh) {
		const cached = await cacheGet<ScanDomainResult>(cacheKey, kv);
		if (cached) {
			return { ...cached, cached: true };
		}
	}

	// Run all checks in parallel with per-check timeouts, wrapped in an
	// overall scan timeout to guarantee a timely response.
	// Uses Promise.allSettled so that completed checks are preserved on timeout.
	const ALL_CHECK_CATEGORIES: CheckCategory[] = [
		'spf', 'dmarc', 'dkim', 'dnssec', 'ssl', 'mta_sts', 'ns', 'caa', 'bimi', 'tlsrpt', 'subdomain_takeover', 'http_security', 'dane', 'mx', 'dane_https', 'svcb_https', 'subdomailing',
	];

	// Skip secondary DNS confirmation in scan context for speed — individual checks
	// still use secondary confirmation when called directly by users.
	const scanDns: QueryDnsOptions = {
		skipSecondaryConfirmation: true,
		queryCache: new Map(),
		secondaryDoh: runtimeOptions?.secondaryDoh,
	};

	const forceRefresh = runtimeOptions?.forceRefresh;
	const cacheTtl = runtimeOptions?.cacheTtlSeconds;

	const checkPromises = [
		runCachedCheck(domain, 'spf', () => safeCheck('spf', () => checkSpf(domain, scanDns)), kv, cacheTtl, forceRefresh),
		runCachedCheck(domain, 'dmarc', () => safeCheck('dmarc', () => checkDmarc(domain, scanDns)), kv, cacheTtl, forceRefresh),
		runCachedCheck(domain, 'dkim', () => safeCheck('dkim', () => checkDkim(domain, undefined, scanDns)), kv, cacheTtl, forceRefresh),
		runCachedCheck(domain, 'dnssec', () => safeCheck('dnssec', () => checkDnssec(domain, scanDns)), kv, cacheTtl, forceRefresh),
		runCachedCheck(domain, 'ssl', () => safeCheck('ssl', () => checkSsl(domain)), kv, cacheTtl, forceRefresh),
		runCachedCheck(domain, 'mta_sts', () => safeCheck('mta_sts', () => checkMtaSts(domain, scanDns)), kv, cacheTtl, forceRefresh),
		runCachedCheck(domain, 'ns', () => safeCheck('ns', () => checkNs(domain, scanDns)), kv, cacheTtl, forceRefresh),
		runCachedCheck(domain, 'caa', () => safeCheck('caa', () => checkCaa(domain, scanDns)), kv, cacheTtl, forceRefresh),
		runCachedCheck(domain, 'bimi', () => safeCheck('bimi', () => checkBimi(domain, scanDns)), kv, cacheTtl, forceRefresh),
		runCachedCheck(domain, 'tlsrpt', () => safeCheck('tlsrpt', () => checkTlsrpt(domain, scanDns)), kv, cacheTtl, forceRefresh),
		runCachedCheck(domain, 'subdomain_takeover', () => safeCheck('subdomain_takeover', () => checkSubdomainTakeover(domain, scanDns)), kv, cacheTtl, forceRefresh),
		runCachedCheck(domain, 'http_security', () => safeCheck('http_security', () => checkHttpSecurity(domain)), kv, cacheTtl, forceRefresh),
		runCachedCheck(domain, 'dane', () => safeCheck('dane', () => checkDane(domain, scanDns)), kv, cacheTtl, forceRefresh),
		runCachedCheck(domain, 'dane_https', () => safeCheck('dane_https', () => checkDaneHttps(domain, scanDns)), kv, cacheTtl, forceRefresh),
		runCachedCheck(domain, 'svcb_https', () => safeCheck('svcb_https', () => checkSvcbHttps(domain, scanDns)), kv, cacheTtl, forceRefresh),
		runCachedCheck(domain, 'subdomailing', () => safeCheck('subdomailing', () => checkSubdomailing(domain, scanDns)), kv, cacheTtl, forceRefresh),
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
			cacheTtl,
			forceRefresh,
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

	// Track categories with degraded status before post-processing strips checkStatus.
	// Post-processing calls buildCheckResult() which creates new objects without checkStatus,
	// so we must record these statuses separately and re-apply them after post-processing.
	const degradedStatuses = new Map<CheckCategory, 'error' | 'timeout'>();
	for (const r of checkResults) {
		if (r.checkStatus === 'error' || r.checkStatus === 'timeout') {
			degradedStatuses.set(r.category, r.checkStatus);
		}
	}

	// Retry transient zero-score failures when we have budget remaining.
	// Only fires for errored checks (checkStatus='error', score=0) caught
	// by safeCheck() — thrown exceptions from DNS/HTTPS failures. Timeouts
	// are skipped because they mean the scan budget is already exhausted.
	if (!timedOut && (Date.now() - scanStartTime) < (SCAN_TIMEOUT_MS - RETRY_BUDGET_MS)) {
		const retryable = checkResults
			.map((r, idx) => ({ r, idx }))
			.filter(({ r }) => shouldRetry(r))
			.slice(0, MAX_RETRIES_PER_SCAN);

		if (retryable.length > 0) {
			const retrySettled = await Promise.allSettled(
				retryable.map(({ r }) => runCheckRetry(r.category, domain, scanDns, runtimeOptions)),
			);
			for (let i = 0; i < retryable.length; i++) {
				const s = retrySettled[i];
				if (s.status === 'fulfilled' && s.value.checkStatus !== 'error' && s.value.score > 0) {
					checkResults[retryable[i].idx] = s.value;
					// Clear the degraded status since the retry succeeded
					degradedStatuses.delete(retryable[i].r.category);
				}
			}
		}
	}

	// For any checks that didn't complete, add a timeout finding
	if (timedOut) {
		const completedCategories = new Set(checkResults.map((r) => r.category));
		for (const category of ALL_CHECK_CATEGORIES) {
			if (!completedCategories.has(category)) {
				const findings = [
					createFinding(
						category,
						`${category.toUpperCase()} check timed out`,
						'low',
						`Check did not complete within the ${SCAN_TIMEOUT_MS / 1000}s scan time limit. Try running this check individually.`,
					),
				];
				const result = buildCheckResult(category, findings);
				checkResults.push({ ...result, score: 0, passed: false, checkStatus: 'timeout' as const });
				degradedStatuses.set(category, 'timeout');
			}
		}
	}

	let result: ScanDomainResult;
	try {
		checkResults = await applyScanPostProcessing(domain, checkResults, runtimeOptions);

		// Re-apply score=0 and checkStatus for checks that errored or timed out.
		// Post-processing calls buildCheckResult() which creates new objects that lose checkStatus,
		// so we re-enforce the zero score, failed status, and passed=false using the degradedStatuses map.
		if (degradedStatuses.size > 0) {
			checkResults = checkResults.map((r) => {
				const status = degradedStatuses.get(r.category);
				return status ? { ...r, score: 0, passed: false, checkStatus: status } : r;
			});
		}

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

		// Apply provider-informed DKIM adjustment: when a known DKIM-signing
		// provider is detected via MX, downgrade the "not found" finding since
		// the provider likely signs by default with a custom selector.
		if (domainContext.detectedProvider) {
			const dkimIdx = checkResults.findIndex((r) => r.category === 'dkim');
			if (dkimIdx !== -1) {
				checkResults[dkimIdx] = applyProviderDkimContext(checkResults[dkimIdx], domainContext.detectedProvider);
			}
		}

		// Phase 1: only pass context to scoring when an explicit profile is set.
		// For 'auto' (or unset), detection runs and is reported but scoring
		// uses the default weights (identical to pre-profile behavior).
		const scoringContext = isExplicit ? domainContext : undefined;

		// Attempt to fetch adaptive weights — KV first for cross-isolate convergence,
		// then fall through to the ProfileAccumulator DO on miss.
		let adaptiveResponse: AdaptiveWeightsResponse | null = null;
		const adaptiveProvider = domainContext.detectedProvider ?? '';

		if (kv && adaptiveProvider) {
			const kvWeights = await getAdaptiveWeights(domainContext.profile, adaptiveProvider, kv);
			if (kvWeights) {
				// Synthesise a minimal AdaptiveWeightsResponse from KV data so the
				// downstream code path is unchanged.
				adaptiveResponse = {
					profile: domainContext.profile,
					provider: adaptiveProvider,
					sampleCount: MATURITY_THRESHOLD,
					blendFactor: 1,
					weights: kvWeights,
					boundHits: [],
				};
			}
		}

		if (!adaptiveResponse && runtimeOptions?.profileAccumulator) {
			adaptiveResponse = await fetchAdaptiveWeights(
				runtimeOptions.profileAccumulator,
				domainContext.profile,
				domainContext.detectedProvider,
			);
			// Publish to KV so other isolates can converge within the TTL window.
			if (adaptiveResponse && adaptiveProvider && kv && runtimeOptions.waitUntil) {
				runtimeOptions.waitUntil(
					publishAdaptiveWeightSummary(domainContext.profile, adaptiveProvider, adaptiveResponse.weights, kv),
				);
			}
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
				// Use the SAME scoring call as the non-adaptive path for determinism.
				// Both paths must produce identical results regardless of whether the
				// ProfileAccumulatorDO responds. The adaptive delta is reported in
				// scoringNote for analytics consumers.
				score = computeScanScore(checkResults, scoringContext, runtimeOptions?.scoringConfig);
			} else {
				score = computeScanScore(checkResults, scoringContext, runtimeOptions?.scoringConfig);
			}
		} else {
			score = computeScanScore(checkResults, scoringContext, runtimeOptions?.scoringConfig);
		}

		// Apply category interaction penalties (post-scoring adjustment)
		const { adjustedScore, effects: interactionEffects } = applyInteractionPenalties(score, runtimeOptions?.scoringConfig);
		score = adjustedScore;

		const rawMaturity = computeMaturityStage(checkResults);
		const maturity = capMaturityStage(rawMaturity, score.overall);

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
			interactionEffects,
		};

		// POST telemetry to DO (best-effort, non-blocking)
		if (runtimeOptions?.profileAccumulator) {
			const telemetry: ScanTelemetry = {
				profile: domainContext.profile,
				provider: domainContext.detectedProvider,
				categoryFindings: checkResults.map((r) => ({ category: r.category, score: r.score, passed: r.passed })),
				timestamp: Date.now(),
				overallScore: score.overall,
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
	} catch (postProcessError) {
		// Post-processing or scoring failed — return whatever we have with degradation note.
		logError(postProcessError instanceof Error ? postProcessError : String(postProcessError), {
			category: 'scan-domain',
			domain,
			details: { phase: 'post-processing', checksCompleted: checkResults.length },
		});
		// Re-apply degraded status overrides in case post-processing ran partially.
		if (degradedStatuses.size > 0) {
			checkResults = checkResults.map((r) => {
				const status = degradedStatuses.get(r.category);
				return status ? { ...r, score: 0, checkStatus: status } : r;
			});
		}
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
		const rawMaturity = computeMaturityStage(checkResults);
		const maturity = capMaturityStage(rawMaturity, score.overall);
		result = {
			domain,
			score,
			checks: checkResults,
			maturity,
			context: fallbackContext,
			cached: false,
			timestamp: new Date().toISOString(),
			scoringNote: 'Post-processing encountered an error; results may be approximate',
			adaptiveWeightDeltas: null,
			interactionEffects: [],
		};
	}

	// Cache the result (use configurable TTL if provided)
	// Defer the write via waitUntil when available to avoid blocking the response.
	const cachePromise = cacheSet(cacheKey, result, kv, runtimeOptions?.cacheTtlSeconds);
	if (runtimeOptions?.waitUntil) {
		runtimeOptions.waitUntil(cachePromise);
	} else {
		await cachePromise;
	}

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
		if (adaptiveWeightCache.size >= ADAPTIVE_CACHE_MAX_ENTRIES) {
			evictAdaptiveWeightCache();
		}
		adaptiveWeightCache.set(cacheKey, { weights: data, expires: now + ADAPTIVE_CACHE_TTL_MS });
		return data;
	} catch {
		return null;
	}
}

/**
 * Evict entries from the adaptive weight cache.
 * Removes expired entries first, then if still at capacity, evicts the entry with the oldest expiry time.
 */
export function evictAdaptiveWeightCache(): void {
	const now = Date.now();

	// First pass: remove all expired entries
	for (const [key, entry] of adaptiveWeightCache) {
		if (entry.expires <= now) {
			adaptiveWeightCache.delete(key);
		}
	}

	// If still at capacity after removing expired entries, evict the oldest by expiry
	if (adaptiveWeightCache.size >= ADAPTIVE_CACHE_MAX_ENTRIES) {
		let oldestKey: string | null = null;
		let oldestExpiry = Infinity;
		for (const [key, entry] of adaptiveWeightCache) {
			if (entry.expires < oldestExpiry) {
				oldestExpiry = entry.expires;
				oldestKey = key;
			}
		}
		if (oldestKey !== null) {
			adaptiveWeightCache.delete(oldestKey);
		}
	}
}

/** Exposed for testing only — do not use in production code. */
export const _adaptiveWeightCacheForTest = adaptiveWeightCache;

async function runCachedCheck(
	domain: string,
	category: CheckCategory,
	run: () => Promise<CheckResult>,
	kv?: KVNamespace,
	ttlSeconds?: number,
	skipCache?: boolean,
): Promise<CheckResult> {
	return runWithCache(`${CACHE_PREFIX}${domain}:check:${category}`, run, kv, ttlSeconds, skipCache);
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
			? `Check did not complete within the ${PER_CHECK_TIMEOUT_MS / 1000}s per-check time limit. Try running this check individually.`
			: `Check failed: ${safeMessage}`;
		const checkStatus = isTimeout ? ('timeout' as const) : ('error' as const);

		const findings = [createFinding(category, title, severity, detail)];
		const result = buildCheckResult(category, findings);
		return { ...result, score: 0, checkStatus };
	}
}

