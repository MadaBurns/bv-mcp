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
	type Finding,
	type ScanScore,
	buildCheckResult,
	computeProfileAwareScanScore,
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
import { buildCheckCacheKey, buildScanCacheKey, cacheGet, cacheSet, runWithCache } from '../lib/cache';
import type { QueryDnsOptions } from '../lib/dns-types';
import { queryDns } from '../lib/dns';
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
import { checkPtr } from './check-ptr';
import { checkHttpSecurity } from './check-http-security';
import { checkDane } from './check-dane';
import { checkDnskeyStrength } from './check-dnskey-strength';
import { checkDaneHttps } from './check-dane-https';
import { checkSvcbHttps } from './check-svcb-https';
import { checkSubdomailing } from './check-subdomailing';
import { checkAuthoritativeDnsInfra } from './check-authoritative-dns-infra';
import { checkRootServerSet } from './check-root-server-set';
import { applyScanPostProcessing } from './scan/post-processing';
import { resolveScanTimeoutBudget } from './scan/timeouts';
import type { ScanRuntimeOptions } from './scan/post-processing';
import { logError } from '../lib/log';
import { getAdaptiveWeights, publishAdaptiveWeightSummary } from '../lib/profile-accumulator';
import { capMaturityStage, computeMaturityStage } from './scan/maturity-staging';
import type { MaturityStage } from './scan/maturity-staging';
export { formatScanReport, buildStructuredScanResult } from './scan/format-report';
export type { StructuredScanResult, ScanResultEnrichment } from './scan/format-report';
export type { MaturityStage } from './scan/maturity-staging';
export type { ScanRuntimeOptions } from './scan/post-processing';

/**
 * TLS probe (Browser Rendering) is a paid-tier enrichment — skip it for
 * free/agent/anonymous scans, which are ~98% of volume and the cost driver.
 */
const PROBE_ELIGIBLE_TIERS = new Set(['developer', 'enterprise', 'partner', 'owner']);

/**
 * Resolve the TLS-probe binding for the ssl check, gated on tier eligibility.
 * Paid-tier only — free/agent/anonymous scans skip Browser Rendering.
 */
function resolveSslOptions(rt?: ScanRuntimeOptions): { tlsProbeBinding?: { fetch: typeof fetch }; tlsProbeAuthToken?: string } {
	return {
		tlsProbeBinding: PROBE_ELIGIBLE_TIERS.has(rt?.authTier ?? '') ? rt?.tlsProbeBinding : undefined,
		tlsProbeAuthToken: rt?.tlsProbeAuthToken,
	};
}

/** Shape the provider-signature options object shared by the mx and ptr checks. */
function resolveProviderSignatureOptions(rt?: ScanRuntimeOptions): {
	providerSignaturesUrl?: string;
	providerSignaturesAllowedHosts?: string[];
	providerSignaturesSha256?: string;
} {
	return {
		providerSignaturesUrl: rt?.providerSignaturesUrl,
		providerSignaturesAllowedHosts: rt?.providerSignaturesAllowedHosts,
		providerSignaturesSha256: rt?.providerSignaturesSha256,
	};
}

/**
 * A per-category check runner. Captures the bespoke argument shaping for each
 * scanned category in one place (the single source of dispatch truth used by
 * BOTH the initial-run fan-out and {@link runCheckRetry}). `ssl` and
 * `http_security` ignore the `dnsOptions` parameter by design.
 */
type CheckRunner = (domain: string, dnsOptions: QueryDnsOptions, rt?: ScanRuntimeOptions) => Promise<CheckResult>;

/**
 * The single dispatch table for all NORMAL-PROFILE scanned categories.
 *
 * Key insertion order is load-bearing: it defines {@link SCAN_CATEGORIES} (and
 * thus the scan fan-out order). It MUST match the historical normal-profile
 * `ALL_CHECK_CATEGORIES` order. The `authoritative_dns_infra`/`root_server_set`
 * profile-only checks are deliberately NOT here — that profile takes its own
 * branch (Promise.all + mergeAuthoritativeDnsInfraResults).
 */
const CHECK_DISPATCH: Record<string, CheckRunner> = {
	spf: (d, dns) => checkSpf(d, dns),
	dmarc: (d, dns) => checkDmarc(d, dns),
	dkim: (d, dns) => checkDkim(d, undefined, dns),
	dnssec: (d, dns) => checkDnssec(d, dns),
	ssl: (d, _dns, rt) => checkSsl(d, resolveSslOptions(rt)),
	mta_sts: (d, dns) => checkMtaSts(d, dns),
	ns: (d, dns) => checkNs(d, dns),
	caa: (d, dns) => checkCaa(d, dns),
	bimi: (d, dns) => checkBimi(d, dns),
	tlsrpt: (d, dns) => checkTlsrpt(d, dns),
	subdomain_takeover: (d, dns) => checkSubdomainTakeover(d, dns),
	http_security: (d) => checkHttpSecurity(d),
	dane: (d, dns) => checkDane(d, dns),
	mx: (d, dns, rt) => checkMx(d, resolveProviderSignatureOptions(rt), dns),
	dane_https: (d, dns) => checkDaneHttps(d, dns),
	svcb_https: (d, dns) => checkSvcbHttps(d, dns),
	subdomailing: (d, dns) => checkSubdomailing(d, dns),
	dnskey_strength: (d, dns) => checkDnskeyStrength(d, dns),
	ptr: (d, dns, rt) => checkPtr(d, resolveProviderSignatureOptions(rt), dns),
};

/**
 * The runtime scan category set — the keys of {@link CHECK_DISPATCH}, in order.
 * Frozen export contract: `test/audits/scan-domain-wiring.audit.test.ts` pins
 * this against the `scanIncluded` SSOT in TOOL_DEFS.
 */
export const SCAN_CATEGORIES: CheckCategory[] = Object.keys(CHECK_DISPATCH) as CheckCategory[];

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
	/**
	 * Tri-state resolution signal:
	 * - absent/`true` — domain resolves and was scored normally.
	 * - `false` — apex returned NXDOMAIN; the domain does not exist in DNS and was
	 *   not scored (no posture to assess).
	 * - `'broken'` — apex returned SERVFAIL; the zone exists but cannot be resolved
	 *   (DNSSEC-bogus or lame/broken delegation). Not scored — see
	 *   {@link buildDnsBrokenResult}.
	 * Aggregators should exclude `resolves === false` and `resolves === 'broken'`
	 * results rather than averaging their grade N/A into a population score.
	 */
	resolves?: boolean | 'broken';
}

/**
 * Build a degraded scan result when the scoring path itself fails — e.g. a
 * runtime/bundle error such as the production "m5 is not defined" ReferenceError
 * thrown from a stale bundle.
 *
 * The checks already ran successfully, so we preserve their findings and
 * per-category scores and surface them to the operator; only the weighted
 * overall score and grade are marked unavailable. This converts a total scan
 * failure (a generic "unexpected error" for every domain) into a graceful
 * degradation. Deliberately calls NO scoring-package function, since the
 * scoring package is exactly what failed.
 */
function buildUnscoredResult(domain: string, checkResults: CheckResult[], reason: string): ScanDomainResult {
	const categoryScores = {} as Record<CheckCategory, number>;
	const findings: Finding[] = [];
	for (const check of checkResults) {
		categoryScores[check.category] = check.score;
		findings.push(...check.findings);
	}
	return {
		domain,
		score: {
			overall: 0,
			grade: 'N/A',
			categoryScores,
			findings,
			summary: reason,
		},
		checks: checkResults,
		maturity: {
			stage: 0,
			label: 'Unscored',
			description: reason,
			nextStep: 'Re-run the scan. If the score stays unavailable, the scoring service is degraded — check the deployment.',
		},
		context: {
			profile: 'mail_enabled',
			signals: ['scoring unavailable — degraded result'],
			weights: {} as DomainContext['weights'],
			detectedProvider: null,
		},
		cached: false,
		timestamp: new Date().toISOString(),
		scoringNote: reason,
		adaptiveWeightDeltas: null,
		interactionEffects: [],
	};
}

/**
 * Build a result for a domain that does not exist in DNS (apex NXDOMAIN).
 *
 * Unlike {@link buildUnscoredResult} (checks ran, scoring failed), here the
 * checks never run: a non-existent domain has no security posture to assess, and
 * running the matrix would only fabricate "absence = missing control" findings —
 * producing a misleading D+/F for a domain that simply isn't registered. We emit
 * NO findings and NO per-category scores; grade is `N/A` and `resolves` is false
 * so aggregators exclude it rather than averaging it in.
 */
function buildNonResolvingResult(domain: string): ScanDomainResult {
	const reason = `${domain} does not resolve (NXDOMAIN) — the domain does not exist in DNS, so there is no security posture to assess.`;
	return {
		domain,
		score: {
			overall: 0,
			grade: 'N/A',
			categoryScores: {} as Record<CheckCategory, number>,
			findings: [],
			summary: reason,
		},
		checks: [],
		maturity: {
			stage: 0,
			label: 'Does not resolve',
			description: reason,
			nextStep: 'Confirm the domain is registered and has authoritative nameservers. If it was recently registered, DNS may not have propagated yet.',
		},
		context: {
			profile: 'mail_enabled',
			signals: ['domain does not resolve (NXDOMAIN)'],
			weights: {} as DomainContext['weights'],
			detectedProvider: null,
		},
		cached: false,
		timestamp: new Date().toISOString(),
		scoringNote: reason,
		adaptiveWeightDeltas: null,
		interactionEffects: [],
		resolves: false,
	};
}

/** Kinds of broken DNS resolution distinguished by the SERVFAIL apex probe. */
type DnsBrokenKind = 'dnssec_bogus' | 'unresolvable';

/**
 * Build a result for a domain whose apex SERVFAILs — the zone is delegated but
 * cannot be resolved. Distinct from {@link buildNonResolvingResult} (NXDOMAIN,
 * the name does not exist) and from a normal scored result.
 *
 * Two sub-states, both confirmed (never inferred from a single transient query):
 * - `dnssec_bogus`: the validating apex query SERVFAILs but a checking-disabled
 *   (`cd=1`) retry succeeds — the zone resolves only with DNSSEC validation off,
 *   so its signatures are bogus/expired.
 * - `unresolvable`: BOTH the validating query and the `cd=1` retry SERVFAIL — a
 *   persistent broken/lame delegation, not a DNSSEC issue.
 *
 * Like the non-resolving case, we emit NO findings and NO per-category scores:
 * a zone we cannot resolve has no measurable posture, and running the matrix
 * would only fabricate "absence = missing control" findings. Grade is `N/A`
 * and `resolves` is `'broken'` so aggregators exclude it.
 */
function buildDnsBrokenResult(domain: string, kind: DnsBrokenKind): ScanDomainResult {
	const reason =
		kind === 'dnssec_bogus'
			? `${domain} DNS resolution is broken: the zone fails DNSSEC validation (resolves only with validation disabled). Until the DNSSEC chain is fixed, validating resolvers return SERVFAIL and the domain is effectively unreachable — so there is no measurable security posture to assess.`
			: `${domain} DNS resolution is broken: the apex returns SERVFAIL and the zone is unresolvable (broken or lame delegation). With no resolvable records there is no security posture to assess.`;
	const nextStep =
		kind === 'dnssec_bogus'
			? 'Fix the DNSSEC chain (re-sign the zone / update DS at the parent) or, if DNSSEC is not intended, remove the DS records so the zone resolves cleanly. Then re-run the scan.'
			: 'Confirm the delegation is healthy: the parent NS records point at authoritative nameservers that answer for the zone. Once the zone resolves, re-run the scan.';
	const signal = kind === 'dnssec_bogus' ? 'DNS resolution broken (DNSSEC validation failure)' : 'DNS resolution broken (unresolvable delegation)';
	return {
		domain,
		score: {
			overall: 0,
			grade: 'N/A',
			categoryScores: {} as Record<CheckCategory, number>,
			findings: [],
			summary: reason,
		},
		checks: [],
		maturity: {
			stage: 0,
			label: 'DNS resolution broken',
			description: reason,
			nextStep,
		},
		context: {
			profile: 'mail_enabled',
			signals: [signal],
			weights: {} as DomainContext['weights'],
			detectedProvider: null,
		},
		cached: false,
		timestamp: new Date().toISOString(),
		scoringNote: reason,
		adaptiveWeightDeltas: null,
		interactionEffects: [],
		resolves: 'broken',
	};
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
		const summary = result.metadata?.capabilitySummary as
			| { passed?: string[]; failed?: string[]; inconclusive?: string[] }
			| undefined;
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

function mergeAuthoritativeDnsInfraResults(results: CheckResult[]): CheckResult {
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
	const timeoutPromise = new Promise<never>((_, reject) =>
		setTimeout(() => reject(new Error('Retry timed out')), retryTimeoutMs),
	);

	const checkPromise = CHECK_DISPATCH[category]?.(domain, retryDns, runtimeOptions);
	if (!checkPromise) {
		// Unsupported category (e.g. profile-only authoritative_dns_infra) — synthetic error result.
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
	const scanStartTime = Date.now();
	const timeoutBudget = resolveScanTimeoutBudget(runtimeOptions);
	const explicitProfile = runtimeOptions?.profile;
	const isExplicit = explicitProfile && explicitProfile !== 'auto';
	// Versioned (cache:v<version>:...) so a deploy auto-invalidates — see buildScanCacheKey.
	const cacheKey = isExplicit ? buildScanCacheKey(domain, explicitProfile) : buildScanCacheKey(domain);

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
	const isAuthoritativeInfraProfile = explicitProfile === 'authoritative_dns_infra';
	const ALL_CHECK_CATEGORIES: CheckCategory[] = isAuthoritativeInfraProfile ? ['authoritative_dns_infra'] : SCAN_CATEGORIES;

	// Skip secondary DNS confirmation in scan context for speed — individual checks
	// still use secondary confirmation when called directly by users.
	const scanDns: QueryDnsOptions = {
		skipSecondaryConfirmation: true,
		queryCache: new Map(),
		secondaryDoh: runtimeOptions?.secondaryDoh,
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
			const apex = await queryDns(domain, 'NS', false, scanDns);
			if (apex.Status === 3) {
				return buildNonResolvingResult(domain);
			}
			if (apex.Status === 2) {
				// CD-disabled retry on a fresh cache (no cd=0/default collision).
				try {
					const cdDisabled = await queryDns(domain, 'NS', false, {
						...scanDns,
						checkingDisabled: true,
						queryCache: new Map(),
					});
					// Resolves only with validation off ⇒ DNSSEC-bogus; still SERVFAIL/other ⇒ unresolvable.
					return buildDnsBrokenResult(domain, cdDisabled.Status === 0 ? 'dnssec_bogus' : 'unresolvable');
				} catch {
					// The confirming retry itself failed transport-wise — treat the
					// confirmed validating-SERVFAIL as a persistent unresolvable delegation.
					return buildDnsBrokenResult(domain, 'unresolvable');
				}
			}
		} catch {
			// Transient probe failure on the FIRST query — fall through and let the full matrix run.
		}
	}

	const forceRefresh = runtimeOptions?.forceRefresh;
	const cacheTtl = runtimeOptions?.cacheTtlSeconds;

	const checkPromises: Promise<CheckResult>[] = isAuthoritativeInfraProfile ? [
		Promise.all([
			safeCheck(
				'authoritative_dns_infra',
				() => checkAuthoritativeDnsInfra(domain, { infraProbe: runtimeOptions?.infraProbe }),
				timeoutBudget.perCheckTimeoutMs,
			),
			safeCheck(
				'authoritative_dns_infra',
				() => checkRootServerSet({ infraProbe: runtimeOptions?.infraProbe }),
				timeoutBudget.perCheckTimeoutMs,
			),
		]).then(mergeAuthoritativeDnsInfraResults),
	] : SCAN_CATEGORIES.map((cat) =>
		runCachedCheck(
			domain,
			cat,
			() => safeCheck(cat, () => CHECK_DISPATCH[cat](domain, scanDns, runtimeOptions), timeoutBudget.perCheckTimeoutMs),
			kv,
			cacheTtl,
			forceRefresh,
		),
	);

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
			}, timeoutBudget.scanTimeoutMs),
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
	if (!timedOut && (Date.now() - scanStartTime) < (timeoutBudget.scanTimeoutMs - timeoutBudget.retryBudgetMs)) {
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

		const canonicalScoring = computeProfileAwareScanScore(checkResults, {
			profile: isExplicit ? (explicitProfile as DomainProfile) : 'auto',
			config: runtimeOptions?.scoringConfig,
		});
		domainContext = canonicalScoring.context;
		const scoringContext = domainContext;

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

		const rawMaturity = computeMaturityStage(checkResults, domainContext?.profile);
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
	// skipSentinel: per-check scan caches are ~98% unique-domain / low-contention;
	// the cross-isolate sentinel's KV writes+deletes cost more than the rare stampede
	// they'd prevent (INFLIGHT still dedups in-isolate).
	return runWithCache(buildCheckCacheKey(domain, category), run, kv, ttlSeconds, skipCache, (r: CheckResult) => !r.partial, true);
}

/**
 * Run a single check with error handling and a per-check timeout.
 * If a check fails or exceeds the timeout, returns a failed CheckResult
 * with an error/timeout finding instead of throwing, so other checks
 * can still complete.
 */
async function safeCheck(category: CheckCategory, fn: () => Promise<CheckResult>, perCheckTimeoutMs: number): Promise<CheckResult> {
	try {
		const result = await Promise.race([
			fn(),
			new Promise<never>((_, reject) => setTimeout(() => reject(new Error('Check timed out')), perCheckTimeoutMs)),
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
		// `partial: true` keeps the one-off transient error OUT of the 5-min
		// per-check cache (see runCachedCheck's shouldCache predicate) so it
		// self-heals and isn't served to direct check_* calls.
		return { ...result, score: 0, checkStatus, partial: true };
	}
}
