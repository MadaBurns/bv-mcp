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
	computeProfileAwareScanScore,
	computeScanScore,
	createFinding,
	detectDomainContext,
	getProfileWeights,
} from '../lib/scoring';
import { resolveZoneApex } from '../lib/zone-apex';
import {
	adaptiveWeightsToContext,
	generateScoringNote,
	MATURITY_THRESHOLD,
	type AdaptiveWeightsResponse,
	type ScanTelemetry,
} from '../lib/adaptive-weights';
import { applyInteractionPenalties } from '../lib/category-interactions';
import { computeScoringConfigHash } from '../lib/scoring-version';
import { buildScanCacheKey, cacheGet, cacheSet } from '../lib/cache';
import type { DohPrimaryFailureTally, QueryDnsOptions } from '../lib/dns-types';
import { queryDns } from '../lib/dns';
import { probeApexRcode } from '../lib/apex-resolution';
import { Semaphore } from '../lib/semaphore';
import { SCAN_DNS_CONCURRENCY, parseScanDnsConcurrency } from '../lib/config';
import { applyProviderDkimContext } from './check-dkim';
import { checkAuthoritativeDnsInfra } from './check-authoritative-dns-infra';
import { checkRootServerSet } from './check-root-server-set';
import { applyScanPostProcessing, mxDeclaresNoInboundMail } from './scan/post-processing';
import { resolveScanTimeoutBudget } from './scan/timeouts';
import { applyWebPostureSwitch, attachWebPosture, canReplayCachedScan, startScanWebPosture } from './scan/web-posture';
import type { ScanRuntimeOptions } from './scan/post-processing';
import { logError } from '../lib/log';
import { createRobotsFetchMemo } from '../lib/robots-memo';
import { fetchBudgetFor } from '../lib/fetch-budget';
import { isSatisfiedControl } from '../lib/control-presence';
import { isCompletedCheck } from '../lib/ungraded-display';
import {
	getAdaptiveWeights,
	publishAdaptiveWeightSummary,
	resolveAccumulatorShardName,
	maybeEmitShardWarmupDegradation,
} from '../lib/profile-accumulator';
import { capMaturityStage, computeMaturityStage } from './scan/maturity-staging';
import { CHECK_DISPATCH, SCAN_CATEGORIES, CHECKS_WITHOUT_DNS_POOL } from './scan/check-dispatch';
import type { ScanDomainResult, ScanDomainOptions } from './scan/scan-types';
import { buildUnscoredResult, buildNonResolvingResult, buildDnsBrokenResult } from './scan/early-results';
import { shouldRetry, mergeAuthoritativeDnsInfraResults, runCheckRetry, runDedupedCheck, safeCheck } from './scan/check-retry';
import { fetchAdaptiveWeights } from './scan/adaptive-weights';
export { formatScanReport, buildStructuredScanResult } from './scan/format-report';
export type { StructuredScanResult, ScanResultEnrichment } from './scan/format-report';
export type { MaturityStage } from './scan/maturity-staging';
export type { ScanRuntimeOptions } from './scan/post-processing';
// SQ-537: the helpers below moved to src/tools/scan/*; every name this module exported before is still exported here.
export { CHECK_DISPATCH, SCAN_CATEGORIES, CHECKS_WITHOUT_DNS_POOL } from './scan/check-dispatch';
export type { ScanDomainResult, ScanDomainOptions } from './scan/scan-types';
export { runCheckRetry } from './scan/check-retry';
export { evictAdaptiveWeightCache, _adaptiveWeightCacheForTest } from './scan/adaptive-weights';

// SQ-214: per-isolate memory of ungraded scans refused by the cache admission predicate,
// keyed by scan cache key, so a repeat within 5 min can be flagged in analytics.
// Measurement only; bounded; never read on any scoring or caching path.
const UNGRADED_REPEAT_WINDOW_MS = 5 * 60 * 1000;
const UNGRADED_REPEAT_MAX_ENTRIES = 500;
const recentUngradedRefusals = new Map<string, number>();

/**
 * Same active-probe tier gate as `src/handlers/tools.ts`'s `activeProbesAllowed` (US-4
 * frozen decision 5): `/mcp` is zero-auth, so an unauthenticated request's `authTier` is
 * `'anon'`; a caller entitled through bv-web but resolving to no MCP tier reads `'free'`.
 * Every OTHER tier has presented a credential — active probes (and the AXFR/CHAOS evidence
 * they produce) are enabled ONLY for those.
 */
function activeProbesAllowedForScan(runtimeOptions?: ScanRuntimeOptions): boolean {
	const tier = runtimeOptions?.authTier;
	return tier !== undefined && tier !== 'anon' && tier !== 'free';
}

/**
 * Run a full DNS security scan on a domain.
 * Executes all checks in parallel and computes an overall score.
 *
 * @param domain - The domain to scan (must already be validated and sanitized by the caller)
 * @param kv - Optional KV namespace for persistent scan result caching
 * @returns Full scan result with score, individual check results, and metadata
 */
export async function scanDomain(domain: string, kv?: KVNamespace, runtimeOptions?: ScanDomainOptions): Promise<ScanDomainResult> {
	if (runtimeOptions?.signal?.aborted) throw runtimeOptions.signal.reason ?? new Error('scan_aborted');
	const scanStartTime = Date.now();
	const timeoutBudget = resolveScanTimeoutBudget(runtimeOptions);
	const explicitProfile = runtimeOptions?.profile;
	const isExplicit = explicitProfile && explicitProfile !== 'auto';
	// The authoritative_dns_infra profile's ENTIRE result is the active-probe gate's evidence
	// (US-4 contract addendum): partition its cache key on the gate
	// so an authenticated scan's AXFR/CHAOS-bearing result is never served to an anonymous
	// caller within the TTL, and the reverse never hides measured capabilities from a paying
	// caller. Every other profile is unaffected.
	const infraProfileCacheKeySuffix =
		isExplicit && explicitProfile === 'authoritative_dns_infra' && activeProbesAllowedForScan(runtimeOptions) ? ':active' : '';
	// Versioned (cache:v<version>:...) so a deploy auto-invalidates — see buildScanCacheKey.
	const cacheKey = isExplicit ? buildScanCacheKey(domain, `${explicitProfile}${infraProfileCacheKeySuffix}`) : buildScanCacheKey(domain);

	// Fingerprint of the EFFECTIVE scoring config this scan runs under. Stamped onto
	// every result this function returns so downstream formatting reports the config
	// that actually produced the numbers instead of the `'default'` marker.
	const scoringConfigHash = computeScoringConfigHash(runtimeOptions?.scoringConfig);

	// Check cache first (skip when force_refresh is requested)
	if (!runtimeOptions?.forceRefresh) {
		const cached = await cacheGet<ScanDomainResult>(cacheKey, kv);
		if (runtimeOptions?.signal?.aborted) throw runtimeOptions.signal.reason ?? new Error('scan_aborted');
		// A scan_domain call does not replay an entry another tool cached without the web posture
		// section; it rescans (re-running the checks) and re-caches with the section.
		if (cached && canReplayCachedScan(cached, runtimeOptions)) {
			// Deliberately NOT re-stamped with the current hash: a cached result's score
			// was computed under the config in force when it was written, so it must keep
			// carrying THAT fingerprint. `?? scoringConfigHash` only covers cache entries
			// written before this field existed (bounded by the 5-min TTL and the
			// deploy-versioned cache key).
			return applyWebPostureSwitch(
				{ ...cached, cached: true, scoringConfigHash: cached.scoringConfigHash ?? scoringConfigHash },
				runtimeOptions,
			);
		}
	}

	// Run all checks in parallel with per-check timeouts, wrapped in an
	// overall scan timeout to guarantee a timely response.
	// Uses Promise.allSettled so that completed checks are preserved on timeout.
	const isAuthoritativeInfraProfile = explicitProfile === 'authoritative_dns_infra';
	const ALL_CHECK_CATEGORIES: CheckCategory[] = isAuthoritativeInfraProfile ? ['authoritative_dns_infra'] : SCAN_CATEGORIES;

	// Bound the ~19-way DoH fan-out with a per-scan outbound-concurrency
	// semaphore. This only caps how many DoH connections are open at once
	// (smoothing tail-latency + Workers subrequest pressure); every query still
	// runs and returns the same answer, so scan results/score are unchanged.
	// Sized by runtimeOptions.dnsConcurrency (env-overridable upstream via
	// SCAN_DNS_CONCURRENCY) else the static default; clamped to [1, 50].
	const dnsConcurrency =
		runtimeOptions?.dnsConcurrency !== undefined ? parseScanDnsConcurrency(String(runtimeOptions.dnsConcurrency)) : SCAN_DNS_CONCURRENCY;
	const dnsSemaphore = runtimeOptions?.dnsSemaphore ?? new Semaphore(dnsConcurrency);

	// R7 — abort (not just abandon) in-flight subrequests on timeout. The
	// scan-level controller is aborted by the scan-timeout snapshot below; each
	// check additionally gets its OWN controller (linked to this one via
	// AbortSignal.any) so a single check's per-check timeout cancels ONLY that
	// check's fetches, never a sibling's still-needed work. The composed
	// per-check signal reaches ONLY the raw-`fetch` checks (ssl, http_security,
	// dane_https) as the 4th dispatch argument. DoH checks deliberately do NOT
	// get it: they share one `queryCache`, so a per-check abort would cancel an
	// in-flight query a SIBLING had deduplicated onto — see the CheckRunner
	// JSDoc above, which is the authoritative account of this split.
	// Consequence (#941, measured + accepted): a DoH query still QUEUED on the
	// shared semaphore when a check's per-check race expires is not withdrawn —
	// it dispatches later and returns a result nobody reads, bounded only by the
	// 15s scan abort. Magnitude is ~0-8 orphaned subrequests per healthy scan
	// (more under batch_scan's narrower pool) against the 10,000/invocation
	// ceiling at a ~500 baseline, so the waste is real but not worth buying with
	// a correctness change to the cached DoH hot path. Do NOT "fix" this by
	// giving the semaphore a maxWaitMs — see the note in lib/semaphore.ts.
	// The apex-state probe below shares `scanDns` (and thus the scan signal) but
	// runs BEFORE any timeout can fire.
	const scanAbort = new AbortController();
	const parentSignal = runtimeOptions?.signal;
	const scanSignal = parentSignal ? AbortSignal.any([scanAbort.signal, parentSignal]) : scanAbort.signal;

	// Skip secondary DNS confirmation in scan context for speed — individual checks
	// still use secondary confirmation when called directly by users.
	// SQ-209: scan-scoped tally of PRIMARY DoH failures, summarised in ONE
	// analytics row once the checks settle. Instrumentation only.
	const primaryFailureTally: DohPrimaryFailureTally = { attempts: 0, http5xx: 0, network: 0, timeout: 0 };
	const scanDns: QueryDnsOptions = {
		skipSecondaryConfirmation: true,
		primaryFailureTally,
		queryCache: new Map(),
		secondaryDoh: runtimeOptions?.secondaryDoh,
		dnsSemaphore,
		signal: scanSignal,
	};

	// Apex-state short-circuit: probe the apex NS before fanning out, to separate
	// "can't resolve the zone" from "resolves but insecure".
	//
	// - NXDOMAIN (RCODE 3): the domain does not exist — scoring it would fabricate a
	//   posture for an unregistered name, so we return a dedicated non-resolving result.
	//
	// - SERVFAIL (RCODE 2): the zone is delegated but the validating query failed.
	//   This is EITHER a DNSSEC-bogus zone OR a broken/lame delegation. We disambiguate
	//   with a SECOND apex query that disables DNSSEC checking (cd=1), using a FRESH
	//   queryCache so it can't return the already-cached SERVFAIL (the cache key now
	//   also distinguishes cd=1, but a fresh map is the belt-and-suspenders guard, as
	//   in runCheckRetry). Transient-vs-persistent rule: we only short-circuit on a
	//   CONFIRMING signal, never on a single hiccup. A clean SERVFAIL on the validating
	//   query PLUS a successful cd=1 retry ⇒ dnssec_bogus (confirmed: resolves only with
	//   validation off). SERVFAIL on BOTH (or the retry errors) ⇒ unresolvable (confirmed
	//   persistent). If the retry instead returns NOERROR because the original SERVFAIL
	//   was a transient hiccup, it lands in the dnssec_bogus branch — acceptable, since
	//   the only way the retry succeeds is the zone genuinely answering with validation
	//   off; a flaky-then-clear validating result would more naturally re-SERVFAIL here
	//   too. Crucially, if the FIRST query throws/times out (not a clean RCODE 2), we keep
	//   the fail-open behavior and fall through to the matrix — a transport hiccup must
	//   never be mistaken for "does not exist" or "broken".
	//
	// Fail-open by design otherwise: NOERROR falls through to the normal matrix.
	// The NS lookup populates scanDns.queryCache, so the `ns` check reuses it (no double query).
	if (!isAuthoritativeInfraProfile) {
		try {
			// Shared with the individual check_* tools' NXDOMAIN gate (#1128) — one predicate.
			const apexClass = await probeApexRcode(domain, scanDns);
			if (apexClass === 'nxdomain') {
				return { ...buildNonResolvingResult(domain), scoringConfigHash };
			}
			if (apexClass === 'servfail') {
				// CD-disabled retry on a fresh cache (no cd=0/default collision).
				try {
					const cdDisabled = await queryDns(domain, 'NS', false, {
						...scanDns,
						checkingDisabled: true,
						queryCache: new Map(),
					});
					// Resolves only with validation off ⇒ DNSSEC-bogus; still SERVFAIL/other ⇒ unresolvable.
					return { ...buildDnsBrokenResult(domain, cdDisabled.Status === 0 ? 'dnssec_bogus' : 'unresolvable'), scoringConfigHash };
				} catch {
					// The confirming retry itself failed transport-wise — treat the
					// confirmed validating-SERVFAIL as a persistent unresolvable delegation.
					return { ...buildDnsBrokenResult(domain, 'unresolvable'), scoringConfigHash };
				}
			}
		} catch {
			// Transient probe failure on the FIRST query — fall through and let the full matrix run.
		}
	}

	// Resolve the governing zone apex ONCE per scan (shared across ns/caa/dnssec/mta_sts).
	// Reuses scanDns.queryCache, so the apex NS query above is not repeated. Fail-soft:
	// resolveZoneApex never throws (returns delegationStatus:'unknown' on resolver error).
	const zone = isAuthoritativeInfraProfile ? undefined : await resolveZoneApex(domain, scanDns);

	// Issue #641: ONE robots.txt fetch memo per scan, shared by the checks that probe
	// the SAME host over raw HTTPS (`ssl` and `http_security` both hit
	// `https://<domain>/robots.txt`). Before this, `check-ssl.ts` built a private
	// `withRobotsGate` closure per call, so the two checks each paid their own
	// blocking robots.txt fetch of up to ROBOTS_FETCH_TIMEOUT_MS (3s) inside an 8s
	// per-check budget — a measured contributor to `ssl` timing out on 12 of 21 cold
	// first-touch scans and silently dropping 3–4 points off the grade.
	//
	// Lifetime and blast radius are both bounded HERE, by construction:
	//   • declared as a local `const` inside scanDomain(), so it dies with this scan.
	//     There is deliberately NO module-level memo — a Worker isolate is long-lived
	//     and `/internal/tools/batch` fans one tool across up to 500 domains in a
	//     single invocation, so isolate-scoped state would outlive its evidence.
	//   • keyed on the absolute robots.txt URL (see lib/robots-memo.ts), so domain A's
	//     robots.txt can never be served for domain B — the origin IS the key.
	//   • `mta_sts` deliberately does NOT take the memo: its robots.txt fetch targets
	//     `mta-sts.<domain>` (a DIFFERENT host — see the package's check-mta-sts.ts
	//     policy URL), so it shares nothing with ssl/http_security and would only
	//     lose its module-scope isolate-lifetime cache in exchange for zero dedup.
	const robotsMemo = createRobotsFetchMemo();

	const forceRefresh = runtimeOptions?.forceRefresh;

	const checkPromises: Promise<CheckResult>[] = isAuthoritativeInfraProfile
		? [
				Promise.all([
					safeCheck(
						'authoritative_dns_infra',
						() =>
							checkAuthoritativeDnsInfra(domain, {
								infraProbe: runtimeOptions?.infraProbe,
								activeProbes: activeProbesAllowedForScan(runtimeOptions),
							}),
						timeoutBudget.perCheckTimeoutMs,
					),
					safeCheck(
						'authoritative_dns_infra',
						() => checkRootServerSet({ infraProbe: runtimeOptions?.infraProbe }),
						timeoutBudget.perCheckTimeoutMs,
					),
				]).then(mergeAuthoritativeDnsInfraResults),
			]
		: SCAN_CATEGORIES.map((cat) => {
				// R7: per-check controller, composed with the scan-level signal. Aborting it
				// on this check's per-check timeout cancels ONLY this check's raw fetches; the
				// scan-level abort cascades into it. Composition (AbortSignal.any) keeps the
				// per-check signal alive until either source fires.
				const perCheckAbort = new AbortController();
				const perCheckSignal = AbortSignal.any([perCheckAbort.signal, scanSignal]);
				return runDedupedCheck(
					domain,
					cat,
					() =>
						safeCheck(
							cat,
							() =>
								CHECK_DISPATCH[cat](
									domain,
									scanDns,
									runtimeOptions,
									perCheckSignal,
									zone,
									robotsMemo,
									fetchBudgetFor(timeoutBudget.perCheckTimeoutMs),
								),
							timeoutBudget.perCheckTimeoutMs,
							() => perCheckAbort.abort(),
							// #952/SQ-15: withhold the queue-clock extension from checks that
							// never wait on the DNS pool — see CHECKS_WITHOUT_DNS_POOL above.
							CHECKS_WITHOUT_DNS_POOL.has(cat) ? undefined : () => dnsSemaphore.saturatedMs(),
						),
					forceRefresh,
				);
			});

	// US-16 T10: the six NON-SCORING web posture checks, only when the caller opted in (the
	// scan_domain tool). SQ-487: they start only now, after the scored fan-out has been dispatched,
	// and hold at most 2 connections, so they cannot queue scored requests behind a hung web host.
	// They are deliberately NOT in CHECK_DISPATCH and never join `checkResults`; the section is
	// attached beside the scored result just before caching. See src/tools/scan/web-posture.ts.
	const webPostureRun = startScanWebPosture(domain, runtimeOptions, {
		scanDns,
		robotsMemo,
		signal: scanSignal,
		perCheckTimeoutMs: timeoutBudget.perCheckTimeoutMs,
	});

	let timedOut = false;
	let scanTimeoutId: ReturnType<typeof setTimeout> | undefined;
	const settled = await Promise.race([
		Promise.allSettled(checkPromises),
		new Promise<PromiseSettledResult<CheckResult>[]>(
			(resolve) =>
				(scanTimeoutId = setTimeout(() => {
					timedOut = true;
					// R7: abort the scan-level controller so EVERY still-in-flight subrequest
					// (DoH via scanDns.signal + the raw HTTPS fetches via each composed
					// per-check signal) is cancelled, not merely abandoned — the scan is over,
					// so freeing the Workers subrequest budget is unambiguously correct here.
					scanAbort.abort();
					// Snapshot whatever has settled so far by racing each promise with an immediate rejection
					resolve(
						Promise.allSettled(
							checkPromises.map((p) => Promise.race([p, new Promise<never>((_, reject) => reject(new Error('__check_pending__')))])),
						),
					);
				}, timeoutBudget.scanTimeoutMs)),
		),
	]);
	if (scanTimeoutId !== undefined) clearTimeout(scanTimeoutId);
	if (parentSignal?.aborted) {
		scanAbort.abort(parentSignal.reason);
		await Promise.allSettled(checkPromises);
		throw parentSignal.reason ?? new Error('scan_aborted');
	}

	// SQ-209: one per-scan primary-DoH failure summary (counts are 0 on a clean scan).
	runtimeOptions?.analytics?.emitDohPrimarySummary?.({ ...primaryFailureTally, domain });

	let checkResults = settled.filter((r): r is PromiseFulfilledResult<CheckResult> => r.status === 'fulfilled').map((r) => r.value);

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
	if (!timedOut && Date.now() - scanStartTime < timeoutBudget.scanTimeoutMs - timeoutBudget.retryBudgetMs) {
		const retryable = checkResults
			.map((r, idx) => ({ r, idx }))
			.filter(({ r }) => shouldRetry(r))
			.slice(0, timeoutBudget.maxRetriesPerScan);

		if (retryable.length > 0) {
			const retrySettled = await Promise.allSettled(
				retryable.map(({ r }) => runCheckRetry(r.category, domain, scanDns, timeoutBudget.retryTimeoutMs, runtimeOptions)),
			);
			for (let i = 0; i < retryable.length; i++) {
				const s = retrySettled[i];
				// `checkStatus !== 'error'` alone gates acceptance — NOT `score > 0`. A
				// completed retry that correctly measures a genuine absence (e.g. a
				// `missingControl` finding, score 0) is the better measurement and must
				// replace the earlier transient-error result, not be discarded in the
				// domain's favour. `runCheckRetry` only returns `checkStatus: 'error'`
				// itself for an unsupported category's synthetic result; any other
				// fulfilled retry is a real completed measurement, whatever score it lands on.
				if (s.status === 'fulfilled' && s.value.checkStatus !== 'error') {
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
						`Check did not complete within the ${timeoutBudget.scanTimeoutMs / 1000}s scan time limit. Try running this check individually.`,
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
		const isNonApexNonMailHost = zone?.isApex === false && mxDeclaresNoInboundMail(checkResults.find((result) => result.category === 'mx'));
		checkResults = await applyScanPostProcessing(domain, checkResults, {
			...runtimeOptions,
			nonApexHost: isNonApexNonMailHost,
		});

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

		// A non-delegated host with no MX is a web target, not a mail domain. Its
		// host-specific TLS/HTTP/takeover checks remain deliberate scan evidence;
		// mail controls are not scored against a label that does not receive mail.
		if (isNonApexNonMailHost) {
			domainContext = {
				profile: 'web_only',
				signals: [...domainContext.signals, 'non-apex host has no MX; mail controls not applicable'],
				weights: getProfileWeights('web_only', runtimeOptions?.scoringConfig),
				detectedProvider: domainContext.detectedProvider,
			};
		} else if (isExplicit) {
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

		// Reuse the context already detected above instead of re-running
		// detectDomainContext via computeProfileAwareScanScore. The detection is
		// invariant to the provider-informed DKIM adjustment (applyProviderDkimContext
		// preserves controlPresent, which is all detectDomainContext reads), so the
		// pre-adjustment domainContext is identical to what a re-detection would yield.
		// The explicit branch above already set config-aware weights; for the
		// auto/detected case, apply them now to match computeProfileAwareScanScore's
		// non-explicit context construction exactly (config weights, not the static table).
		if (!isExplicit) {
			domainContext = {
				...domainContext,
				weights: getProfileWeights(domainContext.profile, runtimeOptions?.scoringConfig),
			};
		}

		// Canonical score, computed ONCE on the DKIM-adjusted checkResults with the
		// canonical context. The non-adaptive and adaptive paths both report this same
		// score for determinism — the adaptive delta is surfaced via scoringNote only.
		const canonicalScore = computeScanScore(checkResults, domainContext, runtimeOptions?.scoringConfig);

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
				// Route the /weights read to the SAME shard the /ingest write targets
				// for this profile (R10 PROPOSAL, default-off → 'global').
				resolveAccumulatorShardName(domainContext.profile, runtimeOptions.profileAccumulatorShardMode),
			);
			// Publish to KV so other isolates can converge within the TTL window.
			if (adaptiveResponse && adaptiveProvider && kv && runtimeOptions.waitUntil) {
				runtimeOptions.waitUntil(publishAdaptiveWeightSummary(domainContext.profile, adaptiveProvider, adaptiveResponse.weights, kv));
			}
			// Observable-by-default warm-up signal (Adam non-negotiable #6): when
			// sharding is ON and this profile's shard is still below the benchmark
			// floor, emit a degradation event so an operator can watch the warm-up
			// drain after a flip. No-op in default 'global' mode.
			maybeEmitShardWarmupDegradation({
				mode: runtimeOptions.profileAccumulatorShardMode,
				profile: domainContext.profile,
				sampleCount: adaptiveResponse?.sampleCount ?? 0,
				emit: runtimeOptions.analytics?.emitDegradationEvent
					? (event) =>
							runtimeOptions.analytics!.emitDegradationEvent({
								...event,
								domain,
							})
					: undefined,
			});
		}

		// Add bound hits to signals if present
		if (adaptiveResponse?.boundHits.length) {
			domainContext.signals.push(`adaptive bound hits: ${adaptiveResponse.boundHits.join(', ')}`);
		}

		// The reported score is always the canonical score (computed once above) for
		// determinism — both the adaptive and non-adaptive paths must produce identical
		// results regardless of whether the ProfileAccumulatorDO responds. The adaptive
		// delta is surfaced via scoringNote/adaptiveWeightDeltas only.
		let score: ScanScore = canonicalScore;
		let scoringNote: string | null = null;
		let adaptiveWeightDeltas: Record<string, number> | null = null;

		if (adaptiveResponse && adaptiveResponse.sampleCount > 0) {
			// Same effective config as the `getProfileWeights(...)` static side below — the two
			// operands of `deltas` must share a base, else an override manufactures phantom
			// deltas for every category the accumulator returned no data for.
			const adaptiveWeights = adaptiveWeightsToContext(adaptiveResponse.weights, domainContext.profile, runtimeOptions?.scoringConfig);
			if (adaptiveWeights) {
				// Compute adaptive score (for the reported delta only)
				const adaptiveContext: DomainContext = { ...domainContext, weights: adaptiveWeights };
				const adaptiveScore = computeScanScore(checkResults, adaptiveContext, runtimeOptions?.scoringConfig);

				// The static-comparison score is the canonical score: domainContext already
				// carries the canonical (config-aware) static weights, so a re-scoring would
				// be identical. Reuse it instead of recomputing.
				const staticScore = canonicalScore;

				// Compute per-category weight deltas
				const staticWeights = getProfileWeights(domainContext.profile, runtimeOptions?.scoringConfig);
				const deltas: Record<string, number> = {};
				for (const cat of Object.keys(staticWeights) as CheckCategory[]) {
					deltas[cat] = adaptiveWeights[cat].importance - staticWeights[cat].importance;
				}

				const scoreDelta = adaptiveScore.overall !== null && staticScore.overall !== null ? adaptiveScore.overall - staticScore.overall : 0;
				scoringNote = generateScoringNote(deltas, scoreDelta, domainContext.detectedProvider);
				adaptiveWeightDeltas = deltas;
			}
		}

		// Apply category interaction penalties (post-scoring adjustment)
		const { adjustedScore, effects: interactionEffects } = applyInteractionPenalties(score, runtimeOptions?.scoringConfig);
		score = adjustedScore;

		const rawMaturity = computeMaturityStage(checkResults, domainContext?.profile);
		// An ungraded scan has no score to cap the stage with — leave the raw stage alone
		// rather than coercing `null` to 0 (which would silently cap every ungraded scan).
		const maturity = score.overall === null ? rawMaturity : capMaturityStage(rawMaturity, score.overall, domainContext?.profile);

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

		// POST telemetry to DO (best-effort, non-blocking).
		// An ungraded scan (`score.overall === null`) carries no measurement, so it must NOT
		// train the adaptive-weight EMA — feeding it in would pull every profile's weights
		// toward a domain that was never actually measured.
		if (runtimeOptions?.profileAccumulator && score.overall !== null) {
			const telemetry: ScanTelemetry = {
				profile: domainContext.profile,
				provider: domainContext.detectedProvider,
				// `isSatisfiedControl`, not raw `passed` — `passed` records whether the
				// category was PENALIZED, not whether the control exists (#705/#706/#725).
				// Absent DNSSEC (60), CAA (85) and MTA-STS (85) all carry `passed: true`
				// and would otherwise be invisible to this telemetry's own cohort-failure
				// statistics (`topFailingCategories` in profile-accumulator.ts) — the exact
				// surface this feeds and the exact class of gap it exists to report. This
				// does NOT reactivate the adaptive-weights scoring path: the published score
				// above is always `canonicalScore` (never the adaptive one), so this only
				// changes what the reporting/statistics layer records, not what any domain
				// is scored or graded.
				//
				// Timed-out / errored checks are left OUT: `safeCheck` stamps them
				// `score: 0, passed: false`, which is a measurement gap, not a measurement.
				// `computeScanScore` already excludes them from the reported score; recording
				// them here as failed controls skewed the adaptive-weight deltas and
				// `topFailingCategories` toward whichever category happened to time out.
				categoryFindings: checkResults
					.filter((r) => isCompletedCheck(r))
					.map((r) => ({ category: r.category, score: r.score, passed: isSatisfiedControl(r) })),
				timestamp: Date.now(),
				overallScore: score.overall,
			};
			// R10 PROPOSAL (default-off): route the /ingest write to the per-profile
			// shard so write traffic spreads across ~6 DO input gates instead of one
			// global gate. The matching /weights read (fetchAdaptiveWeights below)
			// resolves the SAME shard name from the SAME profile, so reads and writes
			// co-locate. `'global'` mode reproduces the legacy single-instance routing.
			const ingestShardName = resolveAccumulatorShardName(domainContext.profile, runtimeOptions.profileAccumulatorShardMode);
			const telemetryPromise = (async () => {
				try {
					const stub = runtimeOptions.profileAccumulator!.get(runtimeOptions.profileAccumulator!.idFromName(ingestShardName));
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
				return status ? { ...r, score: 0, passed: false, checkStatus: status } : r;
			});
		}
		// Defense-in-depth: the fallback re-runs the SAME scoring call, so if the
		// scoring path itself is what failed (e.g. the prod "m5 is not defined"
		// ReferenceError from a stale bundle), this would throw again and — with no
		// outer try/catch — crash the whole scan into a generic handler error for
		// every domain. Guard it so a scoring failure degrades to an unscored
		// result (findings preserved) instead of taking down the entire tool.
		try {
			const fallbackScoring = computeProfileAwareScanScore(checkResults, {
				profile: isExplicit ? (explicitProfile as DomainProfile) : 'auto',
				config: runtimeOptions?.scoringConfig,
			});
			const fallbackContext = fallbackScoring.context;
			const score = fallbackScoring.score;
			const rawMaturity = computeMaturityStage(checkResults, fallbackContext?.profile);
			const maturity = score.overall === null ? rawMaturity : capMaturityStage(rawMaturity, score.overall, fallbackContext?.profile);
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
		} catch (scoringError) {
			logError(scoringError instanceof Error ? scoringError : String(scoringError), {
				category: 'scan-domain',
				domain,
				details: { phase: 'scoring-fallback', checksCompleted: checkResults.length },
			});
			result = buildUnscoredResult(
				domain,
				checkResults,
				'Scoring unavailable — the security checks completed but the overall score could not be computed.',
			);
		}
	}

	// Stamp the effective-config fingerprint BEFORE caching, so a cache hit replays the
	// hash the result was actually scored under (see the cache-read branch above). The
	// non-scoring web posture section is attached here too, so it is cached with the result.
	// SQ-487: the scored result is ready now and waits at most WEB_POSTURE_GRACE_MS for it; a check
	// still running reads as not assessed ("deadline") and finishes under waitUntil.
	result = await attachWebPosture({ ...result, scoringConfigHash }, webPostureRun, runtimeOptions?.waitUntil);

	// Cache the result (use configurable TTL if provided) — but ONLY when it is a real,
	// gradeable measurement. An ungraded result (score.overall === null, arising from
	// score.evidenceInsufficient — the evidence gate withholding a grade when most checks
	// never ran, e.g. a total DoH outage — or from a scoring-path failure in
	// buildUnscoredResult) describes the SCAN's own failure to measure, not the domain's
	// posture. Caching it would serve that "couldn't measure" verdict with `cached: true`
	// to every caller for the full TTL, turning one transient resolver blip into a
	// 5-minute grade blackout. Deliberately keyed on score.overall ALONE: a graded scan
	// whose maturity ladder abstained (maturity.indeterminate — TLS not measured behind an
	// edge/WAF block, or spf/dmarc inconclusive) still carries a real grade and real
	// findings and MUST keep caching; gating on that field would re-scan exactly the
	// hosts that are most expensive to probe on every call
	// (test/characterization/scan-result-contract.spec.ts caught this on the first cut).
	// A single errored category on an otherwise graded scan is ordinary partial
	// degradation and keeps caching exactly as before — no new heuristic.
	const isCacheableResult = result.score.overall !== null;
	if (isCacheableResult) {
		// Defer the write via waitUntil when available to avoid blocking the response.
		if (parentSignal?.aborted) throw parentSignal.reason ?? new Error('scan_aborted');
		const cachePromise = cacheSet(cacheKey, result, kv, runtimeOptions?.cacheTtlSeconds);
		if (runtimeOptions?.waitUntil) {
			runtimeOptions.waitUntil(cachePromise);
		} else {
			await cachePromise;
		}
	} else if (runtimeOptions?.analytics) {
		const now = Date.now();
		const last = recentUngradedRefusals.get(cacheKey);
		const repeat = last !== undefined && now - last < UNGRADED_REPEAT_WINDOW_MS;
		if (recentUngradedRefusals.size >= UNGRADED_REPEAT_MAX_ENTRIES && !recentUngradedRefusals.has(cacheKey)) {
			for (const [k, t] of recentUngradedRefusals) {
				if (now - t >= UNGRADED_REPEAT_WINDOW_MS) recentUngradedRefusals.delete(k);
			}
			if (recentUngradedRefusals.size >= UNGRADED_REPEAT_MAX_ENTRIES) {
				recentUngradedRefusals.delete(recentUngradedRefusals.keys().next().value as string);
			}
		}
		recentUngradedRefusals.set(cacheKey, now);
		runtimeOptions.analytics.emitUngradedNotCachedEvent({ domain, repeat });
	}

	return result;
}
