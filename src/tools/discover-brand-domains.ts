// SPDX-License-Identifier: BUSL-1.1

/**
 * Brand-domain discovery orchestrator (Phase-4 unified tool).
 *
 * Aggregates the four phase-4 discovery signals (SAN co-ownership via crt.sh,
 * NS-record correlation, DMARC RUA mining, DKIM key reuse) into a single
 * candidate list with multi-signal corroborated confidence scoring.
 *
 * The four signal modules already live under `src/tenants/discovery/*` and each
 * exposes its own typed result. This wrapper:
 *   1. Runs the requested signals in parallel via `Promise.allSettled`,
 *      so one failing signal doesn't kill the whole tool call.
 *   2. Aggregates per-candidate signals — when the same domain shows up under
 *      multiple signals, its confidence is corroborated, not averaged.
 *   3. Combines confidences via the design doc §2.4 formula:
 *        combined = 1 - prod(1 - signal_confidence)
 *      i.e. independent-events probability that *any* signal is correct.
 *   4. Filters by `min_confidence`, sorts descending, and returns a CheckResult
 *      with one finding per surviving candidate plus a summary finding.
 *
 * Severity policy on the candidate findings:
 *   - `low` for combined_confidence ≥ 0.85 (auto-include / strong signal)
 *   - `info` for everything else (review queue)
 *
 * DNS-failure resilience: if EVERY requested signal throws (or all return
 * empty without any successes), we surface a `missingControl: true` finding
 * mirroring the `check-spf.ts` reference pattern. Partial failures are noted
 * in metadata but don't degrade the rest of the result.
 */

import {
	correlateSans as defaultCorrelateSans,
	correlateSansRecursive as defaultCorrelateSansRecursive,
	correlateNs as defaultCorrelateNs,
	mineDmarcRua as defaultMineDmarcRua,
	detectDkimKeyReuse as defaultDetectDkimKeyReuse,
	detectHttpRedirect as defaultDetectHttpRedirect,
	detectMxOverlap as defaultDetectMxOverlap,
	detectSharedMxPlatform as defaultDetectSharedMxPlatform,
	detectSharedTxtVerifications as defaultDetectSharedTxtVerifications,
	detectSpfInclude as defaultDetectSpfInclude,
	extractSeedSpfIncludes as defaultExtractSeedSpfIncludes,
	detectCnameAlignment as defaultDetectCnameAlignment,
	type SanCorrelationResult,
	type SanRecursiveResult,
	type NsCorrelationResult,
	type DmarcRuaResult,
	type DkimKeyReuseResult,
	type HttpRedirectResult,
	type MxOverlapResult,
	type MxPlatformResult,
	type SpfIncludeResult,
	type SeedSpfWalkResult,
	type TxtVerificationResult,
	type CnameAlignmentResult,
} from '../tenants/discovery';
import { createDiscoveryDnsContext, type DiscoveryDnsContext } from '../tenants/discovery/dns-context';
import type { OutputFormat } from '../handlers/tool-args';
import { buildCheckResult, createFinding, type CheckResult, type Finding, type Severity } from '../lib/scoring';
import { sanitizeOutputText } from '../lib/output-sanitize';
import { isSubdomainOf } from '../lib/sanitize';
import { generateMarkovLookalikes } from './markov-generator';
import { buildBrandCandidateUniverse, type BrandAuditDepth, type CandidateSeedSource } from '../lib/brand-candidate-universe';
import { planBrandDiscoverySignals, type BrandDiscoverySignalPlan } from '../lib/brand-discovery-planner';
import { domainLabelSimilarity as defaultDomainLabelSimilarity } from '../lib/domain-similarity';
import { checkLookalikes as defaultCheckLookalikes } from './check-lookalikes';
import { clearsOwnershipGate, type BrandEvidenceObservation } from '../lib/brand-evidence';
import { detectAppLinks } from '../tenants/discovery/app-links-detector';
import { detectBountyScope, type BountyPlatform } from '../tenants/discovery/bounty-scope-detector';
import type { Tier0Result } from '../lib/brand-tier0-enterprise';
import type { Tier1Result } from '../lib/brand-tier1-graph';
import type { Tier2Result } from '../lib/brand-tier2-evidence';
import { applyOptoutFilter, type OptoutFetcher } from '../lib/brand-optout-enforcement';

/**
 * Discovery mode flag.
 *
 * - `classic` — default. Runs the legacy signal-sweep pipeline byte-identically.
 *   The only mode supported under BSL — public clones never flip the default.
 * - `tiered`  — runs Tier 0 (tenant portfolio), Tier 1 (infrastructure-graph),
 *   Tier 2 (declared evidence) lookups in front of the legacy sweep. Falls
 *   back to Tier 3 (= legacy sweep) only on a stale fingerprint / cache miss /
 *   uncovered caller candidates. Requires private BlackVeil service bindings.
 */
export type DiscoveryMode = 'classic' | 'tiered';

/** Closed enum of drop reasons emitted by the discovery aggregator. */
export type DiscoveryDropReason =
	| 'cap'
	| 'seedOrSubdomain'
	| 'infrastructureProvider'
	| 'corroborationGate'
	| 'belowConfidence'
	| 'optOutRedacted';

export const DISCOVERY_DROP_REASONS: readonly DiscoveryDropReason[] = [
	'cap',
	'seedOrSubdomain',
	'infrastructureProvider',
	'corroborationGate',
	'belowConfidence',
	'optOutRedacted',
] as const;

/**
 * Built-in bug-bounty program handles for the Phase-5 demo brands. Replace
 * with a D1-backed tenant config table once the UI lands. Brands not in the
 * map simply skip the bounty-scope detector; no harm done.
 */
const PHASE5_BOUNTY_HANDLES: Record<string, Partial<Record<BountyPlatform, string>>> = {
	'brand-alpha.com': { hackerone: 'walmart' },
	'brand-zeta.com': { hackerone: 'disney' },
	'brand-kappa.com': { hackerone: 'marriott' },
	'brand-eta.com': { hackerone: 'bankofamerica' },
	'brand-theta.com': { hackerone: 'mastercard' },
	'paypal.com': { hackerone: 'paypal' },
	'github.com': { hackerone: 'github' },
	'shopify.com': { hackerone: 'shopify' },
	'brand-lambda.com': { hackerone: 'uber' },
};

/** All supported signal kinds. */
export type DiscoverSignal =
	| 'san'
	| 'san_recursive'
	| 'ns'
	| 'dmarc_rua'
	| 'dkim_key_reuse'
	| 'http_redirect'
	| 'mx_overlap'
	| 'txt_verification'
	| 'mx_platform'
	| 'spf_include'
	| 'spf_include_seed'
	| 'cname_alignment'
	| 'markov_gen'
	| 'active_lookalike'
	// Ground-truth signals (Phase-5): brand-declared scope from
	// `/.well-known/apple-app-site-association`, `assetlinks.json`, and public
	// bug-bounty platforms. These bypass the downstream signal sweep — they
	// don't need NS/SAN/MX corroboration because the brand has authored them.
	| 'app_links'
	| 'bounty_scope';

/** Default signal set used when the caller omits `signals`. */
const ALL_SIGNALS: DiscoverSignal[] = [
	'san',
	'san_recursive',
	'ns',
	'dmarc_rua',
	'dkim_key_reuse',
	'http_redirect',
	'mx_overlap',
	'txt_verification',
	'mx_platform',
	'spf_include',
	'spf_include_seed',
	'cname_alignment',
];

const CANDIDATE_BACKED_SIGNALS = new Set<DiscoverSignal>([
	'ns',
	'dkim_key_reuse',
	'mx_overlap',
	'txt_verification',
	'mx_platform',
	'spf_include',
	'cname_alignment',
]);

/** Default cutoff: a candidate must reach this combined-confidence to surface. */
const DEFAULT_MIN_CONFIDENCE = 0.5;

/** Default per-signal confidence used when the underlying module doesn't supply one. */
const DEFAULT_SIGNAL_CONFIDENCE: Record<DiscoverSignal, number> = {
	san: 0.1, // SAN co-ownership — speculative; multi-tenant CDN risk
	san_recursive: 0.85, // Second-order SAN: candidate's own crt.sh listing also names the seed — near-deterministic mutual cross-cert inclusion
	ns: 0.9, // NS overlap — very strong organization signal (module always overrides with shared/seedNs ratio)
	dmarc_rua: 0.6, // DMARC RUA `related` — module always supplies; matches dmarc-rua-miner emission
	dkim_key_reuse: 0.95, // DKIM key reuse — near-deterministic (module always overrides)
	http_redirect: 0.95, // HTTP redirect terminating at seed apex — near-deterministic operational ownership
	mx_overlap: 0.7, // MX hostname overlap — module supplies per-overlap-kind confidence
	txt_verification: 0.9, // Shared site/domain verification token — strong account-control evidence
	mx_platform: 0.55, // Shared mail platform is weak alone but useful when caller/provenance corroborates
	spf_include: 0.85, // Candidate SPF `include:` of seed-rooted policy — near-deterministic
	spf_include_seed: 0.85, // Forward-discovery: seed's own SPF chain delegates to a different registrable apex — authoritative mail-policy delegation, near-deterministic
	cname_alignment: 0.9, // CNAME chain terminating at seed apex/edge — near-deterministic
	markov_gen: 0.01, // speculative generation — purely a candidate seed, provides no weight on its own
	active_lookalike: 0.4, // DNS-active lookalike seed, not ownership evidence
	app_links: 1.0, // brand-authored /.well-known files — Apple/Google verify before publication
	bounty_scope: 1.0, // brand-declared bug-bounty scope — strongest possible ownership signal
};

/** Threshold above which a candidate is considered auto-include rather than review. */
const AUTO_INCLUDE_THRESHOLD = 0.85;

/** Per-candidate aggregation state during collection. */
interface CandidateAggregator {
	domain: string;
	/** Per-signal confidences observed. Multiple values from the same signal kind are reduced to max(). */
	perSignalConfidence: Map<DiscoverSignal, number>;
	/** Free-form per-signal source notes — surfaced on the finding's metadata for downstream review. */
	sources: Record<string, unknown>;
	candidateSeedSources: CandidateSeedSource[];
	candidateSeedReasons: string[];
	sharedTxtVerifications: string[];
	sharedMxPlatform: string | null;
	lookalikeScore: number;
}

/**
 * Injectable signal-module dependencies. Tests pass stubs; production omits
 * `deps` and the module-level imports are used.
 */
export interface DiscoverBrandDomainsDeps {
	correlateSans: typeof defaultCorrelateSans;
	correlateSansRecursive: typeof defaultCorrelateSansRecursive;
	correlateNs: typeof defaultCorrelateNs;
	mineDmarcRua: typeof defaultMineDmarcRua;
	detectDkimKeyReuse: typeof defaultDetectDkimKeyReuse;
	detectHttpRedirect: typeof defaultDetectHttpRedirect;
	detectMxOverlap: typeof defaultDetectMxOverlap;
	detectSharedTxtVerifications: typeof defaultDetectSharedTxtVerifications;
	detectSharedMxPlatform: typeof defaultDetectSharedMxPlatform;
	detectSpfInclude: typeof defaultDetectSpfInclude;
	extractSeedSpfIncludes: typeof defaultExtractSeedSpfIncludes;
	detectCnameAlignment: typeof defaultDetectCnameAlignment;
	generateMarkovLookalikes: typeof generateMarkovLookalikes;
	checkLookalikes: typeof defaultCheckLookalikes;
	domainLabelSimilarity: typeof defaultDomainLabelSimilarity;
	createDnsContext?: typeof createDiscoveryDnsContext;
	/** Tier 0 lookup (tenant-declared portfolio via bv-enterprise). Tiered mode only. */
	tier0Lookup?: (domain: string) => Promise<Tier0Result>;
	/** Tier 1 lookup (bv-infrastructure-graph). Tiered mode only. */
	tier1Lookup?: (domain: string) => Promise<Tier1Result>;
	/** Tier 2 lookup (bv-intel-gateway). Tiered mode only. */
	tier2Lookup?: (domain: string) => Promise<Tier2Result>;
	/** Opt-out fetcher used by the consumer-side filter. Tiered mode only. */
	fetchOptouts?: OptoutFetcher;
}

/** Tool args shape — the Zod schema lives in `src/schemas/tool-args.ts`. */
export interface DiscoverBrandDomainsOptions {
	signals?: DiscoverSignal[];
	candidate_domains?: string[];
	brand_aliases?: string[];
	dkim_selectors?: string[];
	min_confidence?: number;
	depth?: BrandAuditDepth;
	planner_mode?: 'off' | 'observe' | 'enforce';
	planner_caps?: Partial<Record<DiscoverSignal, number>>;
	/**
	 * Discovery mode. `'classic'` (default) runs the legacy public pipeline
	 * byte-identically. `'tiered'` layers Tier 0/1/2 lookups in front and
	 * conditionally falls back to Tier 3 (= the legacy sweep). BSL boundary:
	 * the default never flips.
	 */
	discovery_mode?: DiscoveryMode;
	/** Internal clock override for deterministic telemetry tests. */
	now?: () => number;
	/** Epoch-ms deadline for returning partial discovery before the caller's queue/runtime budget expires. */
	deadlineMs?: number;
	/** Internal progress sink used by the async brand-audit pipeline to persist partial discovery telemetry. */
	onProgress?: (event: BrandDiscoveryProgressEvent) => void | Promise<void>;
	/**
	 * Optional bv-certstream-worker service binding. Threaded into the SAN
	 * correlator's primary path — sidesteps crt.sh per-IP throttling and
	 * benefits from the worker's cache when available. Falls back to direct
	 * crt.sh (with retry) if the binding fails.
	 */
	certstream?: { fetch: typeof fetch };
	/**
	 * Abort signal — checked at major phase boundaries (post-allSettled, before
	 * recursive SAN expansion) so that a budget-exceeded consumer can interrupt
	 * the orchestrator before it launches the next expensive step. In-flight
	 * fetches are not cancelled (DNS transport doesn't accept a signal yet), but
	 * no NEW work starts after the signal fires.
	 */
	signal?: AbortSignal;
}

export interface BrandDiscoveryProgressEvent {
	name: string;
	status: string;
	startedAtMs: number;
	finishedAtMs?: number;
	elapsedMs?: number;
	detail?: Record<string, unknown>;
}

interface BrandDiscoveryTiers {
	tier0Count: number;
	tier1Count: number;
	tier2Count: number;
	tier3Count: number;
	tier4Count: number;
	tier0Status: string;
	tier1Status: string;
	tier2Status: string;
	tier3FallbackTriggered: number;
	tier1Freshness: Record<string, unknown> | null;
	optOutsFiltered: number;
}

interface BrandDiscoveryPerformance {
	elapsedMs: number;
	phases: BrandDiscoveryProgressEvent[];
	efficiency: {
		candidateSignalProbes: number;
		baselineCandidateSignalProbes: number;
		surfacedCandidates: number;
		probesPerSurfacedCandidate: number;
		probeReductionRatio: number;
		plannerMode: 'off' | 'observe' | 'enforce';
	};
	planner: {
		mode: 'off' | 'observe' | 'enforce';
		wouldProbeBySignal: Record<string, number>;
		wouldDropBySignal: Record<string, number>;
	};
	/**
	 * Per-tier metadata. Present iff `discovery_mode === 'tiered'`. Strict
	 * invariance in classic mode: the key is omitted entirely (not `{}`).
	 */
	tiers?: BrandDiscoveryTiers;
}

/** Combine independent-event confidences: P(any signal correct). */
export function combineConfidences(values: number[]): number {
	if (values.length === 0) return 0;
	let product = 1;
	for (const v of values) {
		const clamped = Math.max(0, Math.min(1, v));
		product *= 1 - clamped;
	}
	return 1 - product;
}

/** Round to 4 decimals for stable test/log output. */
export function round4(n: number): number {
	return Math.round(n * 10_000) / 10_000;
}

/** Per-signal default confidences (exported for regression-lock tests). */
export { DEFAULT_SIGNAL_CONFIDENCE };

/** Default deps wiring used when the caller doesn't inject. */
function defaultDeps(): DiscoverBrandDomainsDeps {
	return {
		correlateSans: defaultCorrelateSans,
		correlateSansRecursive: defaultCorrelateSansRecursive,
		correlateNs: defaultCorrelateNs,
		mineDmarcRua: defaultMineDmarcRua,
		detectDkimKeyReuse: defaultDetectDkimKeyReuse,
		detectHttpRedirect: defaultDetectHttpRedirect,
		detectMxOverlap: defaultDetectMxOverlap,
		detectSharedTxtVerifications: defaultDetectSharedTxtVerifications,
		detectSharedMxPlatform: defaultDetectSharedMxPlatform,
		detectSpfInclude: defaultDetectSpfInclude,
		extractSeedSpfIncludes: defaultExtractSeedSpfIncludes,
		detectCnameAlignment: defaultDetectCnameAlignment,
		generateMarkovLookalikes: generateMarkovLookalikes,
		checkLookalikes: defaultCheckLookalikes,
		domainLabelSimilarity: defaultDomainLabelSimilarity,
	};
}

/** Add a per-signal candidate observation to the aggregator. */
function addObservation(
	agg: Map<string, CandidateAggregator>,
	domain: string,
	signal: DiscoverSignal,
	confidence: number,
	sourceNote: unknown,
): void {
	const lower = domain.trim().toLowerCase().replace(/\.$/, '');
	if (!lower) return;
	let entry = agg.get(lower);
	if (!entry) {
		entry = {
			domain: lower,
			perSignalConfidence: new Map(),
			sources: {},
			candidateSeedSources: [],
			candidateSeedReasons: [],
			sharedTxtVerifications: [],
			sharedMxPlatform: null,
			lookalikeScore: 0,
		};
		agg.set(lower, entry);
	}
	const existing = entry.perSignalConfidence.get(signal);
	if (existing === undefined || confidence > existing) {
		entry.perSignalConfidence.set(signal, confidence);
	}
	entry.sources[signal] = sourceNote;
}

function ensureCandidate(agg: Map<string, CandidateAggregator>, domain: string): CandidateAggregator | null {
	const lower = domain.trim().toLowerCase().replace(/\.$/, '');
	if (!lower) return null;
	let entry = agg.get(lower);
	if (!entry) {
		entry = {
			domain: lower,
			perSignalConfidence: new Map(),
			sources: {},
			candidateSeedSources: [],
			candidateSeedReasons: [],
			sharedTxtVerifications: [],
			sharedMxPlatform: null,
			lookalikeScore: 0,
		};
		agg.set(lower, entry);
	}
	return entry;
}

function addCandidateSeed(
	agg: Map<string, CandidateAggregator>,
	domain: string,
	sources: CandidateSeedSource[],
	reasons: string[],
): void {
	const entry = ensureCandidate(agg, domain);
	if (!entry) return;
	for (const source of sources) {
		if (!entry.candidateSeedSources.includes(source)) entry.candidateSeedSources.push(source);
	}
	entry.candidateSeedReasons.push(...reasons);
	if (sources.some((source) => source !== 'caller_candidate')) {
		if (sources.includes('active_lookalike')) {
			addObservation(agg, domain, 'active_lookalike', DEFAULT_SIGNAL_CONFIDENCE.active_lookalike, {
				strategy: 'dns_active_lookalike',
				sources,
			});
		} else {
			addObservation(agg, domain, 'markov_gen', DEFAULT_SIGNAL_CONFIDENCE.markov_gen, {
				strategy: 'candidate_seed',
				sources,
			});
		}
	}
}

/** Run a single signal handler, swallowing errors into a typed status report. */
type SignalOutcome<R> = { ok: true; value: R } | { ok: false; error: string };

async function runSignal<R>(fn: () => Promise<R>): Promise<SignalOutcome<R>> {
	try {
		const value = await fn();
		return { ok: true, value };
	} catch (err) {
		return { ok: false, error: err instanceof Error ? err.message : String(err) };
	}
}

function signalCouldNotComplete(status: string | undefined): boolean {
	return status === 'failed' || status === 'error' || status === 'timeout' || status === 'rate_limited';
}

function isGeneratedSeedSignal(signal: DiscoverSignal): boolean {
	return signal === 'markov_gen' || signal === 'active_lookalike';
}

// Infrastructure-provider allowlist + match helpers live in a shared module so
// the dmarc-rua miner can consume the same source of truth. Re-exported here
// so existing test imports (test/audits/infrastructure-providers.audit.test.ts)
// keep working.
export {
	INFRASTRUCTURE_PROVIDERS,
	registeredApex,
	isInfrastructureProvider,
} from '../tenants/discovery/infrastructure-providers';
import { isInfrastructureProvider } from '../tenants/discovery/infrastructure-providers';

function extractActiveLookalikeDomains(result: CheckResult): string[] {
	const out = new Set<string>();
	for (const finding of result.findings) {
		const domain = finding.metadata?.lookalikeDomain;
		if (typeof domain === 'string' && domain.length > 0) out.add(domain);
	}
	return Array.from(out).sort();
}

/**
 * Orchestrate brand-domain discovery across the four phase-4 signals.
 *
 * Programmer-error throws (invalid seed domain) propagate from the underlying
 * modules. All other failure modes are surfaced via `missingControl: true`
 * findings or per-signal status metadata, never thrown.
 */
export async function discoverBrandDomains(
	seedDomain: string,
	options: DiscoverBrandDomainsOptions = {},
	deps?: DiscoverBrandDomainsDeps,
): Promise<CheckResult> {
	const d: DiscoverBrandDomainsDeps = { ...defaultDeps(), ...(deps ?? {}) };
	const now = options.now ?? Date.now;
	const discoveryStartedAtMs = now();
	const RECURSIVE_SAN_MIN_DEADLINE_HEADROOM_MS = 70_000;
	const deadlineRemainingMs = (): number | null => {
		if (typeof options.deadlineMs !== 'number' || !Number.isFinite(options.deadlineMs)) return null;
		return Math.max(0, options.deadlineMs - now());
	};
	const phaseTimings: BrandDiscoveryProgressEvent[] = [];
	const emitProgress = async (event: BrandDiscoveryProgressEvent): Promise<void> => {
		try {
			await options.onProgress?.(event);
		} catch {
			// Discovery telemetry is diagnostic only; never fail the audit because
			// a progress sink is unavailable or the step cache is missing.
		}
	};
	const startPhase = async (name: string, detail?: Record<string, unknown>): Promise<number> => {
		const startedAtMs = now();
		await emitProgress({
			name,
			status: 'started',
			startedAtMs,
			...(detail ? { detail } : {}),
		});
		return startedAtMs;
	};
	const finishPhase = async (
		name: string,
		status: string,
		startedAtMs: number,
		detail?: Record<string, unknown>,
	): Promise<BrandDiscoveryProgressEvent> => {
		const finishedAtMs = now();
		const event: BrandDiscoveryProgressEvent = {
			name,
			status,
			startedAtMs,
			finishedAtMs,
			elapsedMs: Math.max(0, finishedAtMs - startedAtMs),
			...(detail ? { detail } : {}),
		};
		phaseTimings.push(event);
		await emitProgress(event);
		return event;
	};
	const recordInstantPhase = async (
		name: string,
		status: string,
		detail?: Record<string, unknown>,
	): Promise<void> => {
		const atMs = now();
		await finishPhase(name, status, atMs, detail);
	};
	const candidateBackedSignalProbes: Record<string, number> = {};
	let candidateBackedSignalBaselineProbes: Record<string, number> = {};
	let signalPlan: BrandDiscoverySignalPlan = { candidatesBySignal: {}, droppedBySignal: {}, priorityByDomain: {}, guardedByDomain: {} };

	// Tiered discovery state. Populated only when `discovery_mode === 'tiered'`.
	// In classic mode the entire tiered block is skipped and `tieredState` stays
	// null, so `discoveryPerformance.tiers` is omitted (strict BSL invariance).
	const discoveryMode: DiscoveryMode = options.discovery_mode ?? 'classic';
	interface TieredState {
		tier0Count: number;
		tier1Count: number;
		tier2Count: number;
		tier4Count: number;
		tier3Count: number;
		tier0Status: string;
		tier1Status: string;
		tier2Status: string;
		tier3FallbackTriggered: 0 | 1;
		tier1Freshness: Record<string, unknown> | null;
		optOutsFiltered: number;
	}
	let tieredState: TieredState | null = null;
	// Default flipped from 'observe' to 'enforce' after the planner cap-tuning
	// was validated against production (walmart/bankofamerica/marriott: 44.8%
	// probe reduction, zero surfaced/bucket regressions) and against a chaos
	// suite covering low-yield-signal failure, high-yield-signal failure, and
	// guarded caller-asserted candidates under aggressive caps. Callers can
	// still opt out per-request with `planner_mode: 'observe'` or `'off'`.
	const plannerMode = options.planner_mode ?? 'enforce';
	const recordCandidateSignalProbes = (signal: DiscoverSignal, candidates: string[]): string[] => {
		candidateBackedSignalProbes[signal] = candidates.length;
		return candidates;
	};
	const countPlannedCandidates = (candidatesBySignal: BrandDiscoverySignalPlan['candidatesBySignal']): Record<string, number> =>
		Object.fromEntries(Object.entries(candidatesBySignal).map(([signal, candidates]) => [signal, candidates.length]));
	const countDroppedCandidates = (droppedBySignal: BrandDiscoverySignalPlan['droppedBySignal']): Record<string, number> =>
		Object.fromEntries(Object.entries(droppedBySignal).map(([signal, dropped]) => [signal, dropped.length]));
	const buildDiscoveryPerformance = (): BrandDiscoveryPerformance => {
		const candidateSignalProbes = Object.values(candidateBackedSignalProbes).reduce((sum, count) => sum + count, 0);
		const baselineCandidateSignalProbes = Object.values(candidateBackedSignalBaselineProbes).reduce((sum, count) => sum + count, 0);
		const surfaced = phaseTimings.find((phase) => phase.name === 'aggregation')?.detail?.surfaced;
		const surfacedCandidates = typeof surfaced === 'number' ? surfaced : 0;
		const out: BrandDiscoveryPerformance = {
			elapsedMs: Math.max(0, now() - discoveryStartedAtMs),
			phases: phaseTimings.slice(),
			efficiency: {
				candidateSignalProbes,
				baselineCandidateSignalProbes,
				surfacedCandidates,
				probesPerSurfacedCandidate: candidateSignalProbes / Math.max(1, surfacedCandidates),
				probeReductionRatio:
					baselineCandidateSignalProbes > 0
						? 1 - candidateSignalProbes / baselineCandidateSignalProbes
						: 0,
				plannerMode,
			},
			planner: {
				mode: plannerMode,
				wouldProbeBySignal: countPlannedCandidates(signalPlan.candidatesBySignal),
				wouldDropBySignal: countDroppedCandidates(signalPlan.droppedBySignal),
			},
		};
		// BSL invariance: attach `tiers` ONLY when tiered mode populated state.
		// Classic mode leaves the key absent from the object entirely.
		if (tieredState) {
			out.tiers = {
				tier0Count: tieredState.tier0Count,
				tier1Count: tieredState.tier1Count,
				tier2Count: tieredState.tier2Count,
				tier3Count: tieredState.tier3Count,
				tier4Count: tieredState.tier4Count,
				tier0Status: tieredState.tier0Status,
				tier1Status: tieredState.tier1Status,
				tier2Status: tieredState.tier2Status,
				tier3FallbackTriggered: tieredState.tier3FallbackTriggered,
				tier1Freshness: tieredState.tier1Freshness,
				optOutsFiltered: tieredState.optOutsFiltered,
			};
		}
		return out;
	};
	const runTrackedSignal = async <R>(
		name: DiscoverSignal,
		fn: () => Promise<R>,
		statusForValue: (value: R) => string,
		detailForValue?: (value: R) => Record<string, unknown>,
	): Promise<SignalOutcome<R>> => {
		const startedAtMs = now();
		const out = await runSignal(fn);
		if (out.ok) {
			await finishPhase(name, statusForValue(out.value), startedAtMs, detailForValue?.(out.value));
		} else {
			await finishPhase(name, 'failed', startedAtMs, { error: out.error });
		}
		return out;
	};
	// Thread the caller's signal into the dnsContext factory: every probe that
	// uses `dnsContext.query(...)` then inherits cancellation through Phase 2's
	// signal-forwarding contract. This is the choke-point that makes most of
	// the discovery fan-out abortable without per-probe code changes.
	const createDnsContext = d.createDnsContext ?? createDiscoveryDnsContext;
	const dnsContext: DiscoveryDnsContext = createDnsContext({ signal: options.signal });
	let dkimDnsContext: DiscoveryDnsContext | null = null;
	const getDkimDnsContext = (): DiscoveryDnsContext => {
		if (!dkimDnsContext) {
			dkimDnsContext = createDnsContext({ signal: options.signal, maxConcurrent: 4 });
		}
		return dkimDnsContext;
	};
	const signals = (options.signals && options.signals.length > 0 ? options.signals : ALL_SIGNALS).slice();
	const candidateDomains = options.candidate_domains ?? [];
	// Caller-asserted ownership: bypass the corroboration gate for these.
	// One signal hit is enough when the caller has already named the domain
	// — see the gate below. Unsolicited single-signal discoveries still get
	// dropped per LR-1/LR-2.
	const callerAssertedDomains = new Set(
		candidateDomains.map((dom) => dom.trim().toLowerCase().replace(/\.$/, '')),
	);
	const dkimSelectors = options.dkim_selectors;
	const minConfidence = typeof options.min_confidence === 'number'
		? Math.max(0, Math.min(1, options.min_confidence))
		: DEFAULT_MIN_CONFIDENCE;

	const depth = options.depth ?? 'standard';
	const candidateUniverseStartedAtMs = await startPhase('candidate_universe', { depth });
	const markovCandidates = d.generateMarkovLookalikes(seedDomain, depth === 'deep' ? 60 : 20);
	let activeLookalikes: string[] = [];
	const preSignalStatus: Record<string, { status: string; error?: string }> = {};
	if (depth === 'deep') {
		const activeStartedAtMs = await startPhase('active_lookalike');
		const activeOut = await runSignal<CheckResult>(() => d.checkLookalikes(seedDomain));
		if (activeOut.ok) {
			activeLookalikes = extractActiveLookalikeDomains(activeOut.value);
			preSignalStatus.active_lookalike = { status: activeOut.value.partial ? 'partial' : 'ok' };
			await finishPhase('active_lookalike', preSignalStatus.active_lookalike.status, activeStartedAtMs, {
				discovered: activeLookalikes.length,
			});
		} else {
			preSignalStatus.active_lookalike = { status: 'failed', error: activeOut.error };
			await finishPhase('active_lookalike', 'failed', activeStartedAtMs, { error: activeOut.error });
		}
	}
	const universe = buildBrandCandidateUniverse({
		seedDomain,
		candidateDomains,
		markovCandidates,
		activeLookalikes,
		brandAliases: options.brand_aliases,
		depth,
	});
	await finishPhase('candidate_universe', 'completed', candidateUniverseStartedAtMs, {
		seeded: universe.stats.seeded,
		dropped: universe.stats.dropped,
		sources: universe.stats.sources,
	});

	// Pre-validate seed via the SAN correlator's strict guard. correlateSans
	// throws on invalid input (programmer error) — we let that escape.
	// We don't want to call it just for validation when 'san' isn't requested,
	// so reuse `validateDomain` directly.
	const { validateDomain } = await import('../lib/sanitize');
	const v = validateDomain(seedDomain);
	if (!v.valid) {
		throw new Error(`Domain validation failed: ${v.error ?? 'invalid domain'}`);
	}

	interface Job {
		name: DiscoverSignal;
		run: () => Promise<void>;
	}
	const aggregator = new Map<string, CandidateAggregator>();

	for (const candidate of universe.candidates) {
		addCandidateSeed(aggregator, candidate.domain, candidate.sources, candidate.reasons);
	}

	// ---------------------------------------------------------------------
	// Tiered discovery (T7) — Tier 0/1/2 run BEFORE the legacy sweep (Tier 3).
	// Tier 3 only fires conditionally: very_stale freshness, Tier 1 returned
	// no candidates AND freshness != fresh, or caller_candidates not covered.
	// Classic mode skips the entire block (strict BSL invariance — public
	// default never flips).
	// ---------------------------------------------------------------------
	const seedNormForTiered = seedDomain.trim().toLowerCase().replace(/\.$/, '');
	const tieredObservations: Array<{
		candidate: string;
		tier: 0 | 1 | 2 | 4;
		source: string;
		confidence: number;
		metadata: Record<string, unknown>;
	}> = [];
	let runTier3 = true;
	if (discoveryMode === 'tiered') {
		tieredState = {
			tier0Count: 0,
			tier1Count: 0,
			tier2Count: 0,
			tier4Count: 0,
			tier3Count: 0,
			tier0Status: 'skipped',
			tier1Status: 'skipped',
			tier2Status: 'skipped',
			tier3FallbackTriggered: 0,
			tier1Freshness: null,
			optOutsFiltered: 0,
		};
		const tieredStartedAtMs = await startPhase('tiered_lookup');
		const tier0Started = now();
		const tier1Started = now();
		const tier2Started = now();
		const [tier0Settled, tier1Settled, tier2Settled] = await Promise.allSettled([
			d.tier0Lookup
				? d.tier0Lookup(seedDomain)
				: Promise.resolve<Tier0Result>({ observations: [], status: 'skipped', optedOut: false }),
			d.tier1Lookup
				? d.tier1Lookup(seedDomain)
				: Promise.resolve<Tier1Result>({ observations: [], status: 'skipped', triggerTier3Fallback: false }),
			d.tier2Lookup
				? d.tier2Lookup(seedDomain)
				: Promise.resolve<Tier2Result>({ observations: [], status: 'skipped' }),
		]);

		if (tier0Settled.status === 'fulfilled') {
			const r = tier0Settled.value;
			tieredState.tier0Status = r.status;
			for (const obs of r.observations) {
				tieredObservations.push({
					candidate: obs.candidate,
					tier: 0,
					source: obs.source,
					confidence: obs.confidence,
					metadata: { tier: 0, source: obs.source, tenantId: obs.tenantId, registeredAt: obs.registeredAt },
				});
			}
			await finishPhase('tier0_tenant', r.status, tier0Started, {
				observations: r.observations.length,
				optedOut: r.optedOut,
			});
		} else {
			tieredState.tier0Status = 'degraded';
			await finishPhase('tier0_tenant', 'failed', tier0Started, { error: String(tier0Settled.reason) });
		}

		if (tier1Settled.status === 'fulfilled') {
			const r = tier1Settled.value;
			tieredState.tier1Status = r.status;
			tieredState.tier1Freshness = (r.freshness as unknown as Record<string, unknown>) ?? null;
			for (const obs of r.observations) {
				tieredObservations.push({
					candidate: obs.candidate,
					tier: 1,
					source: obs.source,
					confidence: obs.confidence,
					metadata: {
						tier: 1,
						source: obs.source,
						specificityScore: obs.specificityScore,
						signalType: obs.signalType,
						signalValue: obs.signalValue,
						numSharedSignals: obs.numSharedSignals,
						maxSpecificity: obs.maxSpecificity,
						signalTypes: obs.signalTypes,
					},
				});
			}
			await finishPhase('tier1_graph', r.status, tier1Started, {
				observations: r.observations.length,
				triggerTier3Fallback: r.triggerTier3Fallback,
			});
		} else {
			tieredState.tier1Status = 'degraded';
			await finishPhase('tier1_graph', 'failed', tier1Started, { error: String(tier1Settled.reason) });
		}

		if (tier2Settled.status === 'fulfilled') {
			const r = tier2Settled.value;
			tieredState.tier2Status = r.status;
			for (const obs of r.observations) {
				if (obs.tier === 2) {
					tieredObservations.push({
						candidate: obs.candidate,
						tier: 2,
						source: obs.source,
						confidence: obs.confidence,
						metadata: { tier: 2, source: obs.source, threatLevel: obs.threatLevel, capturedAt: obs.capturedAt },
					});
				} else {
					tieredObservations.push({
						candidate: obs.candidate,
						tier: 4,
						source: obs.source,
						confidence: obs.confidence,
						metadata: { tier: 4, source: obs.source, alertType: obs.alertType, transition: obs.transition },
					});
				}
			}
			await finishPhase('tier2_evidence', r.status, tier2Started, { observations: r.observations.length });
		} else {
			tieredState.tier2Status = 'degraded';
			await finishPhase('tier2_evidence', 'failed', tier2Started, { error: String(tier2Settled.reason) });
		}

		// Apply consumer-side opt-out filter to ALL surfaced tiered candidates.
		// 3rd defensive layer: even if both producer-side filters miss an
		// opted-out apex, bv-mcp redacts it here.
		if (d.fetchOptouts && tieredObservations.length > 0) {
			try {
				const candidatesToCheck = Array.from(new Set(tieredObservations.map((o) => o.candidate)));
				const optoutResult = await applyOptoutFilter(candidatesToCheck, d.fetchOptouts);
				const survivors = new Set(optoutResult.filtered.map((c) => c.trim().toLowerCase().replace(/\.$/, '')));
				const beforeLen = tieredObservations.length;
				let writeIdx = 0;
				for (let i = 0; i < tieredObservations.length; i++) {
					const norm = tieredObservations[i].candidate.trim().toLowerCase().replace(/\.$/, '');
					if (survivors.has(norm)) {
						tieredObservations[writeIdx++] = tieredObservations[i];
					}
				}
				tieredObservations.length = writeIdx;
				tieredState.optOutsFiltered = Math.max(beforeLen - writeIdx, optoutResult.redactedCount);
			} catch {
				// Fail-soft: filter unavailable → no redaction, no abort.
			}
		}

		// Land tiered observations in the aggregator BEFORE the Tier 3 decision,
		// so the signal sweep (if it runs) corroborates rather than duplicates.
		// Tiered candidates are treated as caller-asserted: they came from a
		// declared/tenant/graph source and bypass the multi-signal corroboration
		// gate (intended for unsolicited single-signal discoveries).
		for (const obs of tieredObservations) {
			callerAssertedDomains.add(obs.candidate.trim().toLowerCase().replace(/\.$/, ''));
			// Tier observations live on the `markov_gen` signal key (zero
			// contribution to combined-confidence — the caller-asserted bypass
			// is what surfaces these). The metadata blob carries the real tier
			// + source for the T8 classifier to read.
			addObservation(aggregator, obs.candidate, 'markov_gen', obs.confidence, {
				tier: obs.tier,
				source: obs.source,
				...obs.metadata,
			});
		}

		// Tier counts (post-opt-out).
		for (const obs of tieredObservations) {
			if (obs.tier === 0) tieredState.tier0Count++;
			else if (obs.tier === 1) tieredState.tier1Count++;
			else if (obs.tier === 2) tieredState.tier2Count++;
			else if (obs.tier === 4) tieredState.tier4Count++;
		}

		// ---- Tier 3 decision ----
		// Per the source-of-truth plan §521-524 (and reconciled with the task
		// description test at "fresh → no Tier 3 fallback"):
		//   - tier1Freshness === 'very_stale', OR
		//   - Tier 1 returned no candidates AND tier1Freshness !== 'fresh', OR
		//   - caller_candidates present and not covered by Tier 0/1/2.
		const tier1FreshnessStaleness =
			tieredState.tier1Freshness && typeof tieredState.tier1Freshness.overallStaleness === 'string'
				? (tieredState.tier1Freshness.overallStaleness as string)
				: undefined;
		const tier1Fresh = tier1FreshnessStaleness === 'fresh';
		const tier1VeryStale = tier1FreshnessStaleness === 'very_stale';
		const tier1HadCandidates = tieredState.tier1Count > 0;
		const coveredByTiers = new Set(
			tieredObservations.map((o) => o.candidate.trim().toLowerCase().replace(/\.$/, '')),
		);
		coveredByTiers.add(seedNormForTiered);
		const callerNorm = candidateDomains
			.map((dom) => dom.trim().toLowerCase().replace(/\.$/, ''))
			.filter((dom) => dom.length > 0);
		const uncoveredCaller = callerNorm.some((dom) => !coveredByTiers.has(dom));
		const shouldRunTier3 = tier1VeryStale || (!tier1HadCandidates && !tier1Fresh) || uncoveredCaller;
		runTier3 = shouldRunTier3;
		tieredState.tier3FallbackTriggered = shouldRunTier3 ? 1 : 0;

		await finishPhase('tiered_lookup', 'completed', tieredStartedAtMs, {
			tier0Count: tieredState.tier0Count,
			tier1Count: tieredState.tier1Count,
			tier2Count: tieredState.tier2Count,
			tier4Count: tieredState.tier4Count,
			tier3FallbackTriggered: tieredState.tier3FallbackTriggered,
			optOutsFiltered: tieredState.optOutsFiltered,
		});
	}

	const signalStatus: Record<string, { status: string; error?: string }> = { ...preSignalStatus };

	// Phase-5 ground-truth signals (app-links + bounty-scope). Their domains
	// land directly in the aggregator as confidence-1.0 observations and join
	// `callerAssertedDomains` so the corroboration gate bypasses them. They are
	// then *excluded* from `mergedCandidates` — the downstream signal sweep
	// skips probing them entirely, since brand-authored declarations need no
	// further proof. Previous attempt (commit 8df859a, reverted) added them via
	// `candidateDomains` instead, blowing the consumer's 300s cap on fan-out.
	const seedNorm = seedDomain.trim().toLowerCase().replace(/\.$/, '');
	const groundTruthBypass = new Set<string>();

	const appLinksStartedAtMs = await startPhase('app_links');
	const appLinksOut = await runSignal(() => detectAppLinks(seedDomain));
	if (appLinksOut.ok) {
		signalStatus.app_links = { status: appLinksOut.value.queryStatus };
		for (const c of appLinksOut.value.coOwnedDomains) {
			if (!c.domain || c.domain === seedNorm) continue;
			addObservation(aggregator, c.domain, 'app_links', DEFAULT_SIGNAL_CONFIDENCE.app_links, c.evidence);
			callerAssertedDomains.add(c.domain);
			groundTruthBypass.add(c.domain);
		}
		await finishPhase('app_links', appLinksOut.value.queryStatus, appLinksStartedAtMs, {
			discovered: appLinksOut.value.coOwnedDomains.length,
		});
	} else {
		signalStatus.app_links = { status: 'failed', error: appLinksOut.error };
		await finishPhase('app_links', 'failed', appLinksStartedAtMs, { error: appLinksOut.error });
	}

	const bountyHandles = PHASE5_BOUNTY_HANDLES[seedNorm] ?? {};
	if (Object.keys(bountyHandles).length > 0) {
		const bountyStartedAtMs = await startPhase('bounty_scope', { handles: Object.keys(bountyHandles) });
		const bountyOut = await runSignal(() => detectBountyScope(seedDomain, { handles: bountyHandles }));
		if (bountyOut.ok) {
			const failedPlatforms = bountyOut.value.failedPlatforms;
			signalStatus.bounty_scope = {
				status: bountyOut.value.queryStatus,
				...(failedPlatforms.length > 0 ? { error: `failedPlatforms=${failedPlatforms.join(',')}` } : {}),
			};
			for (const c of bountyOut.value.coOwnedDomains) {
				if (!c.domain || c.domain === seedNorm) continue;
				addObservation(aggregator, c.domain, 'bounty_scope', DEFAULT_SIGNAL_CONFIDENCE.bounty_scope, c.evidence);
				callerAssertedDomains.add(c.domain);
				groundTruthBypass.add(c.domain);
			}
			await finishPhase('bounty_scope', bountyOut.value.queryStatus, bountyStartedAtMs, {
				discovered: bountyOut.value.coOwnedDomains.length,
				fetchedPlatforms: bountyOut.value.fetchedPlatforms,
				failedPlatforms,
				wildcardScopes: bountyOut.value.wildcardScopes.length,
				outOfScopeDomains: bountyOut.value.outOfScopeDomains.length,
			});
		} else {
			signalStatus.bounty_scope = { status: 'failed', error: bountyOut.error };
			await finishPhase('bounty_scope', 'failed', bountyStartedAtMs, { error: bountyOut.error });
		}
	} else {
		await recordInstantPhase('bounty_scope', 'skipped_no_handles');
	}

	// Universe candidates feed the signal sweep, MINUS the ground-truth
	// bypass set. Bypassed domains stay in the aggregator (already added
	// above) but are never sent to the existing 12 signal probes.
	const mergedCandidates = universe.candidates
		.map((candidate) => candidate.domain)
		.filter((d) => !groundTruthBypass.has(d));
	candidateBackedSignalBaselineProbes = Object.fromEntries(
		signals
			.filter((signal) => CANDIDATE_BACKED_SIGNALS.has(signal))
			.map((signal) => [signal, mergedCandidates.length]),
	);
	if (plannerMode !== 'off') {
		signalPlan = planBrandDiscoverySignals({
			depth,
			candidates: universe.candidates.filter((candidate) => !groundTruthBypass.has(candidate.domain)),
			signals,
			caps: options.planner_caps,
		});
	}
	const candidatesForSignal = (signal: DiscoverSignal): string[] => {
		if (plannerMode !== 'enforce') return mergedCandidates;
		return signalPlan.candidatesBySignal[signal] ?? mergedCandidates;
	};

	const jobs: Job[] = [];

	// Captured first-order SAN hits — fed into the second-order recursive pass below.
	let firstOrderSanCandidates: string[] = [];

	if (signals.includes('san')) {
		jobs.push({
			name: 'san',
			run: async () => {
			const out = await runTrackedSignal<SanCorrelationResult>('san', () =>
				d.correlateSans(seedDomain, {
					...(options.certstream ? { certstream: options.certstream } : {}),
					signal: options.signal,
				}),
				(value) => value.queryStatus,
				(value) => ({ discovered: value.coOwnedDomains.length, certIds: value.certIds.length }),
			);
			if (!out.ok) {
				signalStatus.san = { status: 'failed', error: out.error };
				return;
			}
			signalStatus.san = { status: out.value.queryStatus };
			firstOrderSanCandidates = out.value.coOwnedDomains.slice();
			for (const dom of out.value.coOwnedDomains) {
				addObservation(aggregator, dom, 'san', DEFAULT_SIGNAL_CONFIDENCE.san, {
					seed: out.value.seedDomain,
					certIds: out.value.certIds.slice(0, 5),
				});
			}
			},
		});
	}

	if (signals.includes('ns')) {
		jobs.push({
			name: 'ns',
			run: async () => {
			const nsCandidates = recordCandidateSignalProbes('ns', candidatesForSignal('ns'));
			const out = await runTrackedSignal<NsCorrelationResult>('ns', () =>
				d.correlateNs(seedDomain, { candidateDomains: nsCandidates, dnsContext }),
				(value) => value.queryStatus,
				(value) => ({ discovered: value.coOwnedDomains.length, probedCandidates: nsCandidates.length }),
			);
			if (!out.ok) {
				signalStatus.ns = { status: 'failed', error: out.error };
				return;
			}
			signalStatus.ns = { status: out.value.queryStatus };
			for (const c of out.value.coOwnedDomains) {
				addObservation(aggregator, c.domain, 'ns', c.confidence, {
					sharedNs: c.sharedNs,
					nsConfidence: c.confidence,
				});
			}
			},
		});
	}

	if (signals.includes('dmarc_rua')) {
		jobs.push({
			name: 'dmarc_rua',
			run: async () => {
			const out = await runTrackedSignal<DmarcRuaResult>('dmarc_rua', () => d.mineDmarcRua(seedDomain, { dnsContext }),
				(value) => value.queryStatus,
				(value) => ({ ruaDomains: value.ruaDomains.length }),
			);
			if (!out.ok) {
				signalStatus.dmarc_rua = { status: 'failed', error: out.error };
				return;
			}
			signalStatus.dmarc_rua = { status: out.value.queryStatus };
			for (const r of out.value.ruaDomains) {
				if (r.classification !== 'related') continue;
				addObservation(aggregator, r.domain, 'dmarc_rua', r.confidence, {
					classification: r.classification,
					externalAuthorization: r.externalAuthorization,
				});
			}
			},
		});
	}

	if (signals.includes('dkim_key_reuse')) {
		jobs.push({
			name: 'dkim_key_reuse',
			run: async () => {
			const dkimCandidates = recordCandidateSignalProbes('dkim_key_reuse', candidatesForSignal('dkim_key_reuse'));
			const out = await runTrackedSignal<DkimKeyReuseResult>('dkim_key_reuse', () =>
				d.detectDkimKeyReuse(seedDomain, dkimCandidates, {
					...(dkimSelectors ? { selectors: dkimSelectors } : {}),
					dnsContext: getDkimDnsContext(),
					maxCandidates: depth === 'deep' ? 40 : 30,
					candidateConcurrency: 4,
					totalBudgetMs: 25_000,
					signal: options.signal,
				}),
				(value) => value.queryStatus,
				(value) => ({
					discovered: value.coOwnedDomains.length,
					probedCandidates: value.probedCandidates ?? dkimCandidates.length,
					skippedCandidates: value.skippedCandidates ?? 0,
					budgetExceeded: value.budgetExceeded === true,
				}),
			);
			if (!out.ok) {
				signalStatus.dkim_key_reuse = { status: 'failed', error: out.error };
				return;
			}
			signalStatus.dkim_key_reuse = { status: out.value.queryStatus };
			for (const c of out.value.coOwnedDomains) {
				addObservation(aggregator, c.domain, 'dkim_key_reuse', c.confidence, {
					sharedSelectors: c.sharedSelectors,
					sharedKeys: c.sharedKeys,
				});
			}
			},
		});
	}

	if (signals.includes('http_redirect')) {
		jobs.push({
			name: 'http_redirect',
			run: async () => {
			const out = await runTrackedSignal<HttpRedirectResult>('http_redirect', () =>
				d.detectHttpRedirect(seedDomain, { candidateDomains: mergedCandidates }),
				(value) => value.queryStatus,
				(value) => ({ discovered: value.coOwnedDomains.length, probedCandidates: mergedCandidates.length }),
			);
			if (!out.ok) {
				signalStatus.http_redirect = { status: 'failed', error: out.error };
				return;
			}
			signalStatus.http_redirect = { status: out.value.queryStatus };
			for (const c of out.value.coOwnedDomains) {
				addObservation(aggregator, c.domain, 'http_redirect', c.confidence, c.evidence);
			}
			},
		});
	}

	if (signals.includes('mx_overlap')) {
		jobs.push({
			name: 'mx_overlap',
			run: async () => {
			const mxOverlapCandidates = recordCandidateSignalProbes('mx_overlap', candidatesForSignal('mx_overlap'));
			const out = await runTrackedSignal<MxOverlapResult>('mx_overlap', () =>
				d.detectMxOverlap(seedDomain, { candidateDomains: mxOverlapCandidates, dnsContext }),
				(value) => value.queryStatus,
				(value) => ({ discovered: value.coOwnedDomains.length, probedCandidates: mxOverlapCandidates.length }),
			);
			if (!out.ok) {
				signalStatus.mx_overlap = { status: 'failed', error: out.error };
				return;
			}
			signalStatus.mx_overlap = { status: out.value.queryStatus };
			for (const c of out.value.coOwnedDomains) {
				addObservation(aggregator, c.domain, 'mx_overlap', c.confidence, c.evidence);
			}
			},
		});
	}

	if (signals.includes('txt_verification')) {
		jobs.push({
			name: 'txt_verification',
			run: async () => {
			const txtVerificationCandidates = recordCandidateSignalProbes('txt_verification', candidatesForSignal('txt_verification'));
			const out = await runTrackedSignal<TxtVerificationResult>('txt_verification', () =>
				d.detectSharedTxtVerifications(seedDomain, { candidateDomains: txtVerificationCandidates, dnsContext }),
				(value) => value.queryStatus,
				(value) => ({ discovered: value.coOwnedDomains.length, probedCandidates: txtVerificationCandidates.length }),
			);
			if (!out.ok) {
				signalStatus.txt_verification = { status: 'failed', error: out.error };
				return;
			}
			signalStatus.txt_verification = { status: out.value.queryStatus };
			for (const c of out.value.coOwnedDomains) {
				addObservation(aggregator, c.domain, 'txt_verification', c.confidence, {
					sharedTxtVerifications: c.sharedTxtVerifications,
				});
				const entry = aggregator.get(c.domain.trim().toLowerCase().replace(/\.$/, ''));
				if (entry) {
					entry.sharedTxtVerifications = Array.from(
						new Set([...entry.sharedTxtVerifications, ...c.sharedTxtVerifications]),
					).sort();
				}
			}
			},
		});
	}

	if (signals.includes('mx_platform')) {
		jobs.push({
			name: 'mx_platform',
			run: async () => {
			const mxPlatformCandidates = recordCandidateSignalProbes('mx_platform', candidatesForSignal('mx_platform'));
			const out = await runTrackedSignal<MxPlatformResult>('mx_platform', () =>
				d.detectSharedMxPlatform(seedDomain, { candidateDomains: mxPlatformCandidates, dnsContext }),
				(value) => value.queryStatus,
				(value) => ({ discovered: value.coOwnedDomains.length, probedCandidates: mxPlatformCandidates.length }),
			);
			if (!out.ok) {
				signalStatus.mx_platform = { status: 'failed', error: out.error };
				return;
			}
			signalStatus.mx_platform = { status: out.value.queryStatus };
			for (const c of out.value.coOwnedDomains) {
				addObservation(aggregator, c.domain, 'mx_platform', c.confidence, {
					sharedMxPlatform: c.sharedMxPlatform,
				});
				const entry = aggregator.get(c.domain.trim().toLowerCase().replace(/\.$/, ''));
				if (entry) entry.sharedMxPlatform = c.sharedMxPlatform;
			}
			},
		});
	}

	if (signals.includes('spf_include')) {
		jobs.push({
			name: 'spf_include',
			run: async () => {
			const spfIncludeCandidates = recordCandidateSignalProbes('spf_include', candidatesForSignal('spf_include'));
			const out = await runTrackedSignal<SpfIncludeResult>('spf_include', () =>
				d.detectSpfInclude(seedDomain, { candidateDomains: spfIncludeCandidates, dnsContext }),
				(value) => value.queryStatus,
				(value) => ({ discovered: value.coOwnedDomains.length, probedCandidates: spfIncludeCandidates.length }),
			);
			if (!out.ok) {
				signalStatus.spf_include = { status: 'failed', error: out.error };
				return;
			}
			signalStatus.spf_include = { status: out.value.queryStatus };
			for (const c of out.value.coOwnedDomains) {
				addObservation(aggregator, c.domain, 'spf_include', c.confidence, c.evidence);
			}
			},
		});
	}

	// Forward-discovery: walk the SEED's own SPF chain and surface every
	// different-apex include/redirect target as a same-organization candidate.
	// Unlike `spf_include` (corroboration-only — needs a candidate to probe),
	// this signal MINTS candidates straight from the seed's authoritative
	// mail policy — the path that unlocks Nike-style brand families whose
	// regional ccTLD apexes appear only in the seed's `include:` chain.
	if (signals.includes('spf_include_seed')) {
		jobs.push({
			name: 'spf_include_seed',
			run: async () => {
			const out = await runTrackedSignal<SeedSpfWalkResult>('spf_include_seed', () => d.extractSeedSpfIncludes(seedDomain, { dnsContext }),
				(value) => value.queryStatus,
				(value) => ({ candidates: value.candidates.length }),
			);
			if (!out.ok) {
				signalStatus.spf_include_seed = { status: 'failed', error: out.error };
				return;
			}
			signalStatus.spf_include_seed = { status: out.value.queryStatus };
			for (const c of out.value.candidates) {
				addObservation(aggregator, c.apex, 'spf_include_seed', c.confidence, {
					via: c.via,
					depth: c.depth,
				});
			}
			},
		});
	}

	if (signals.includes('cname_alignment')) {
		jobs.push({
			name: 'cname_alignment',
			run: async () => {
			const cnameAlignmentCandidates = recordCandidateSignalProbes('cname_alignment', candidatesForSignal('cname_alignment'));
			const out = await runTrackedSignal<CnameAlignmentResult>('cname_alignment', () =>
				d.detectCnameAlignment(seedDomain, { candidateDomains: cnameAlignmentCandidates, dnsContext }),
				(value) => value.queryStatus,
				(value) => ({ discovered: value.coOwnedDomains.length, probedCandidates: cnameAlignmentCandidates.length }),
			);
			if (!out.ok) {
				signalStatus.cname_alignment = { status: 'failed', error: out.error };
				return;
			}
			signalStatus.cname_alignment = { status: out.value.queryStatus };
			for (const c of out.value.coOwnedDomains) {
				addObservation(aggregator, c.domain, 'cname_alignment', c.confidence, c.evidence);
			}
			},
		});
	}

	if (!runTier3) {
		// Tiered mode decided Tier 3 (= the legacy sweep) isn't needed. Mark
		// every requested signal as `skipped_tiered` so the allFailed gate
		// below sees a known-good non-failure outcome, then skip the sweep.
		for (const s of signals) {
			signalStatus[s] ??= { status: 'skipped_tiered' };
		}
		await recordInstantPhase('signal_sweep', 'skipped_tiered', { reason: 'tier1_fresh_no_uncovered_caller' });
	} else {
		const signalSweepStartedAtMs = await startPhase('signal_sweep', {
			signals: jobs.map((job) => job.name),
			probedCandidates: mergedCandidates.length,
		});
		await Promise.allSettled(jobs.map((j) => j.run()));
		await finishPhase(
			'signal_sweep',
			options.signal?.aborted ? 'partial' : 'completed',
			signalSweepStartedAtMs,
			{
				completedSignals: phaseTimings
					.filter((phase) => jobs.some((job) => job.name === phase.name))
					.map((phase) => phase.name),
			},
		);
	}

	// Budget gate: if the consumer's AbortController has fired while jobs were
	// in flight, skip the recursive SAN expansion (the most expensive single
	// step, ~30s) and head straight to the aggregator pass with whatever we
	// already have. The consumer will flip the row to `failed` once we return.
	if (!runTier3) {
		// Tiered mode skipped the sweep entirely → nothing to do for san_recursive.
		signalStatus.san_recursive ??= { status: 'skipped_tiered' };
	} else if (options.signal?.aborted) {
		signalStatus.san_recursive ??= { status: 'skipped_no_first_order' };
		await recordInstantPhase('san_recursive', 'skipped_aborted');
	} else if (signals.includes('san_recursive') && firstOrderSanCandidates.length > 0) {
		const remainingMs = deadlineRemainingMs();
		if (remainingMs !== null && remainingMs < RECURSIVE_SAN_MIN_DEADLINE_HEADROOM_MS) {
			signalStatus.san_recursive = { status: 'skipped_deadline' };
			await recordInstantPhase('san_recursive', 'skipped_deadline', {
				remainingMs,
				requiredHeadroomMs: RECURSIVE_SAN_MIN_DEADLINE_HEADROOM_MS,
				firstOrderCandidates: firstOrderSanCandidates.length,
			});
		} else {
			const recursiveOut = await runTrackedSignal<SanRecursiveResult>('san_recursive', () =>
				d.correlateSansRecursive(seedDomain, firstOrderSanCandidates, {
					certstream: options.certstream,
					// Caps tightened (2026-05-19) to fit Cloudflare Worker CPU budget.
					// Each candidate triggers a fresh crt.sh fetch (~200KB-2MB JSON parse
					// for tier-1 brands), so 20 candidates × 8 concurrency was the single
					// largest CPU sink in the walmart wedge. 10/4/15s keeps headroom for
					// the remaining 11 signal probes + RDAP enrichment.
					maxCandidates: 10,
					concurrency: 4,
					totalBudgetMs: 15_000,
					signal: options.signal,
				}),
				(value) => (value.queryStatus === 'budget_exceeded' ? 'partial' : value.queryStatus),
				(value) => ({
					probed: value.probed.length,
					crossConfirmed: value.crossConfirmed.length,
				}),
			);
			if (!recursiveOut.ok) {
				signalStatus.san_recursive = { status: 'failed', error: recursiveOut.error };
			} else {
				signalStatus.san_recursive =
					recursiveOut.value.queryStatus === 'budget_exceeded'
						? { status: 'partial', error: 'budget_exceeded' }
						: { status: recursiveOut.value.queryStatus };
				for (const cc of recursiveOut.value.crossConfirmed) {
					addObservation(aggregator, cc.candidate, 'san_recursive', DEFAULT_SIGNAL_CONFIDENCE.san_recursive, {
						seed: recursiveOut.value.seedDomain,
						certIds: cc.certIds,
						probedCount: recursiveOut.value.probed.length,
					});
				}
			}
		}
	} else if (signals.includes('san_recursive')) {
		// Requested but no first-order candidates to probe. If first-order SAN
		// itself failed, propagate failure (its preconditions blew up); else
		// record an empty-input skip for telemetry. The propagation keeps the
		// all-failed gate honest when every signal — including san — broke.
		if (signalStatus.san?.status === 'failed') {
			signalStatus.san_recursive = { status: 'failed', error: 'first_order_san_failed' };
			await recordInstantPhase('san_recursive', 'failed', { error: 'first_order_san_failed' });
		} else {
			signalStatus.san_recursive = { status: 'skipped_no_first_order' };
			await recordInstantPhase('san_recursive', 'skipped_no_first_order');
		}
	}

	// Did every requested signal blow up? If yes, surface a missingControl finding.
	const allFailed = signals.length > 0 && signals.every((s) => signalCouldNotComplete(signalStatus[s]?.status));
	if (allFailed) {
		return buildCheckResult('brand_discovery', [
			createFinding(
				'brand_discovery',
				'Brand-domain discovery could not complete',
				'high',
				`All ${signals.length} requested signal(s) failed; see signalStatus metadata for details.`,
				{
					missingControl: true,
					confidence: 'heuristic',
					errorKind: 'dns_error',
					signalStatus,
					discoveryPerformance: buildDiscoveryPerformance(),
				},
			),
		]);
	}

	// Build candidate findings.
	const aggregationStartedAtMs = await startPhase('aggregation', { aggregatedTotal: aggregator.size });
	const candidateFindings: Finding[] = [];
	const dropCounts = {
		cap: universe.stats.dropped.cap,
		seedOrSubdomain: 0,
		infrastructureProvider: 0,
		corroborationGate: 0,
		belowConfidence: 0,
	};
	const surviving: Array<{
		domain: string;
		combined: number;
		signals: DiscoverSignal[];
		sources: Record<string, unknown>;
		candidateSeedSources: CandidateSeedSource[];
		candidateSeedReasons: string[];
		sharedTxtVerifications: string[];
		sharedMxPlatform: string | null;
		lookalikeScore: number;
		evidenceObservations: BrandEvidenceObservation[];
	}> = [];

	for (const entry of aggregator.values()) {
		// Drop the seed or its subdomains if they accidentally appear (e.g. self-referenced rua=).
		if (isSubdomainOf(entry.domain, seedDomain)) {
			dropCounts.seedOrSubdomain++;
			continue;
		}

		const perSignal = Array.from(entry.perSignalConfidence.entries());

		const signalKinds = perSignal.map(([k]) => k).sort() as DiscoverSignal[];
		const evidenceObservations = perSignal.map(([signal, confidence]) => ({
			signal,
			confidence,
			metadata: typeof entry.sources[signal] === 'object' && entry.sources[signal] !== null && !Array.isArray(entry.sources[signal])
				? (entry.sources[signal] as Record<string, unknown>)
				: undefined,
		})) satisfies BrandEvidenceObservation[];
		const lookalikeScore = round4(d.domainLabelSimilarity(seedDomain, entry.domain));
		entry.lookalikeScore = lookalikeScore;

		// Only suppress infrastructure providers when the *sole* signal is dmarc_rua
		// (RUA mailboxes are processors, not siblings). Other signals (san, ns,
		// dkim_key_reuse, http_redirect, ...) legitimately surface brand-owned
		// infra like outlook.com / azure.com / amazonaws.com.
		if (isInfrastructureProvider(entry.domain) && signalKinds.every((s) => s === 'dmarc_rua')) {
			dropCounts.infrastructureProvider++;
			continue;
		}

		// Corroboration Requirement: delegated to the shared evidence policy so
		// discovery and classification use the same ownership threshold.
		if (!clearsOwnershipGate(evidenceObservations, { callerAsserted: callerAssertedDomains.has(entry.domain) })) {
			dropCounts.corroborationGate++;
			continue;
		}

		const scoredSignals = perSignal.filter(([signal]) => !isGeneratedSeedSignal(signal));
		const combined = round4(combineConfidences(scoredSignals.map(([, c]) => c)));
		if (combined < minConfidence) {
			dropCounts.belowConfidence++;
			continue;
		}

		surviving.push({
			domain: entry.domain,
			combined,
			signals: signalKinds,
			sources: entry.sources,
			candidateSeedSources: entry.candidateSeedSources.slice(),
			candidateSeedReasons: Array.from(new Set(entry.candidateSeedReasons)),
			sharedTxtVerifications: entry.sharedTxtVerifications.slice(),
			sharedMxPlatform: entry.sharedMxPlatform,
			lookalikeScore,
			evidenceObservations,
		});
	}

	surviving.sort((a, b) => b.combined - a.combined || a.domain.localeCompare(b.domain));

	for (const cand of surviving) {
		const severity: Severity = cand.combined >= AUTO_INCLUDE_THRESHOLD ? 'low' : 'info';
		candidateFindings.push(
			createFinding(
				'brand_discovery',
				`Discovered candidate: ${cand.domain}`,
				severity,
				`Found via ${cand.signals.length} signal(s): ${cand.signals.join(', ')}; combined confidence ${cand.combined.toFixed(2)}.`,
				{
					candidate: cand.domain,
					signals: cand.signals,
					combinedConfidence: cand.combined,
					sources: cand.sources,
					candidateSeedSources: cand.candidateSeedSources,
					candidateSeedReasons: cand.candidateSeedReasons,
					sharedTxtVerifications: cand.sharedTxtVerifications,
					sharedMxPlatform: cand.sharedMxPlatform,
					lookalikeScore: cand.lookalikeScore,
					evidenceObservations: cand.evidenceObservations,
				},
			),
		);
	}
	await finishPhase('aggregation', 'completed', aggregationStartedAtMs, {
		surfaced: candidateFindings.length,
		dropped: dropCounts,
	});

	// Tier 3 count: in tiered mode, count surviving candidates that were NOT
	// surfaced by Tier 0/1/2. Identified by domain set membership.
	if (tieredState) {
		const tieredApex = new Set(
			tieredObservations.map((o) => o.candidate.trim().toLowerCase().replace(/\.$/, '')),
		);
		let tier3Count = 0;
		for (const cand of surviving) {
			if (!tieredApex.has(cand.domain)) tier3Count++;
		}
		tieredState.tier3Count = tier3Count;
	}

	// Always emit a summary finding so the formatter has something to print.
	const summary = createFinding(
		'brand_discovery',
		`Brand-domain discovery: ${candidateFindings.length} candidate(s) at confidence ≥ ${minConfidence}`,
		'info',
		`Seed=${seedDomain.trim().toLowerCase()} signals=[${signals.join(', ')}] aggregated_total=${aggregator.size} surfaced=${candidateFindings.length}`,
		{
			summary: true,
			signals,
			signalStatus,
			minConfidence,
			totalAggregated: aggregator.size,
			surfaced: candidateFindings.length,
			discoveryPerformance: buildDiscoveryPerformance(),
			candidateUniverse: {
				seeded: universe.stats.seeded,
				probed: mergedCandidates.length,
				surfaced: candidateFindings.length,
				dropped: dropCounts,
				sources: universe.stats.sources,
			},
		},
	);

	return buildCheckResult('brand_discovery', [summary, ...candidateFindings]);
}

/** Format a discoverBrandDomains CheckResult as human-readable text. */
export function formatDiscoverBrandDomains(result: CheckResult, format: OutputFormat = 'full'): string {
	const summary = result.findings.find((f) => f.metadata?.summary === true);
	const candidates = result.findings.filter((f) => f.metadata?.candidate);

	if (format === 'compact') {
		const lines: string[] = [];
		lines.push(`Brand discovery — ${candidates.length} candidate(s)`);
		if (summary) {
			lines.push(`  ${sanitizeOutputText(summary.detail, 240)}`);
		}
		for (const c of candidates) {
			const conf = c.metadata?.combinedConfidence as number | undefined;
			const signals = (c.metadata?.signals as string[] | undefined)?.join(',') ?? '';
			lines.push(
				`  - ${sanitizeOutputText(c.metadata?.candidate as string, 80)} (conf=${conf?.toFixed(2) ?? '?'}, signals=${signals})`,
			);
		}
		return lines.join('\n');
	}

	const lines: string[] = [];
	lines.push('# Brand-Domain Discovery');
	if (summary) {
		lines.push(sanitizeOutputText(summary.detail, 400));
	}
	lines.push('');
	if (candidates.length === 0) {
		lines.push('No candidate domains surfaced above the confidence threshold.');
	} else {
		lines.push('## Candidates');
		for (const c of candidates) {
			const icon = c.severity === 'low' ? '🟡' : '🔵';
			const conf = c.metadata?.combinedConfidence as number | undefined;
			const signals = (c.metadata?.signals as string[] | undefined)?.join(', ') ?? '';
			lines.push(`${icon} **${sanitizeOutputText(c.metadata?.candidate as string, 80)}** — confidence ${conf?.toFixed(2) ?? '?'}`);
			lines.push(`  signals: ${signals}`);
		}
	}
	const missing = result.findings.find((f) => f.metadata?.missingControl);
	if (missing) {
		lines.push('');
		lines.push(`🔴 ${sanitizeOutputText(missing.title, 200)}: ${sanitizeOutputText(missing.detail, 400)}`);
	}
	return lines.join('\n');
}
