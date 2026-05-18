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
import type { OutputFormat } from '../handlers/tool-args';
import { buildCheckResult, createFinding, type CheckResult, type Finding, type Severity } from '../lib/scoring';
import { sanitizeOutputText } from '../lib/output-sanitize';
import { isSubdomainOf } from '../lib/sanitize';
import { generateMarkovLookalikes } from './markov-generator';
import { buildBrandCandidateUniverse, type BrandAuditDepth, type CandidateSeedSource } from '../lib/brand-candidate-universe';
import { domainLabelSimilarity as defaultDomainLabelSimilarity } from '../lib/domain-similarity';

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
	| 'active_lookalike';

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
};

/** Threshold above which a candidate is considered auto-include rather than review. */
const AUTO_INCLUDE_THRESHOLD = 0.85;

/**
 * Signals strong enough to surface a candidate by themselves. Every other
 * signal must be corroborated by ≥1 distinct signal to clear the gate.
 *
 * Why only dkim_key_reuse: shared DKIM private keys are near-deterministic
 * ownership evidence — a third party cannot publish a matching `_domainkey`
 * TXT without operator access. SAN co-tenancy is multi-tenant CDN noise,
 * DMARC RUA can name unknown third-party aggregators, NS overlap collapses
 * on commodity DNS/parking hosts. Those all need corroboration.
 */
const NEAR_DETERMINISTIC_SIGNALS: ReadonlySet<DiscoverSignal> = new Set([
	'dkim_key_reuse',
	'http_redirect',
	'txt_verification',
	'spf_include',
	'spf_include_seed',
	'cname_alignment',
	'san_recursive',
]);

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
	domainLabelSimilarity: typeof defaultDomainLabelSimilarity;
}

/** Tool args shape — the Zod schema lives in `src/schemas/tool-args.ts`. */
export interface DiscoverBrandDomainsOptions {
	signals?: DiscoverSignal[];
	candidate_domains?: string[];
	brand_aliases?: string[];
	dkim_selectors?: string[];
	min_confidence?: number;
	depth?: BrandAuditDepth;
	/**
	 * Optional bv-certstream-worker service binding. Threaded into the SAN
	 * correlator's primary path — sidesteps crt.sh per-IP throttling and
	 * benefits from the worker's cache when available. Falls back to direct
	 * crt.sh (with retry) if the binding fails.
	 */
	certstream?: { fetch: typeof fetch };
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
		addObservation(agg, domain, 'markov_gen', DEFAULT_SIGNAL_CONFIDENCE.markov_gen, {
			strategy: 'candidate_seed',
			sources,
		});
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
	const markovCandidates = d.generateMarkovLookalikes(seedDomain, depth === 'deep' ? 60 : 20);
	const universe = buildBrandCandidateUniverse({
		seedDomain,
		candidateDomains,
		markovCandidates,
		brandAliases: options.brand_aliases,
		depth,
	});
	const mergedCandidates = universe.candidates.map((candidate) => candidate.domain);

	// Pre-validate seed via the SAN correlator's strict guard. correlateSans
	// throws on invalid input (programmer error) — we let that escape.
	// We don't want to call it just for validation when 'san' isn't requested,
	// so reuse `validateDomain` directly.
	const { validateDomain } = await import('../lib/sanitize');
	const v = validateDomain(seedDomain);
	if (!v.valid) {
		throw new Error(`Domain validation failed: ${v.error ?? 'invalid domain'}`);
	}

	type Job = () => Promise<void>;
	const aggregator = new Map<string, CandidateAggregator>();

	for (const candidate of universe.candidates) {
		addCandidateSeed(aggregator, candidate.domain, candidate.sources, candidate.reasons);
	}

	const signalStatus: Record<string, { status: string; error?: string }> = {};
	const jobs: Job[] = [];

	// Captured first-order SAN hits — fed into the second-order recursive pass below.
	let firstOrderSanCandidates: string[] = [];

	if (signals.includes('san')) {
		jobs.push(async () => {
			const out = await runSignal<SanCorrelationResult>(() =>
				d.correlateSans(seedDomain, options.certstream ? { certstream: options.certstream } : {}),
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
		});
	}

	if (signals.includes('ns')) {
		jobs.push(async () => {
			const out = await runSignal<NsCorrelationResult>(() => d.correlateNs(seedDomain, { candidateDomains: mergedCandidates }));
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
		});
	}

	if (signals.includes('dmarc_rua')) {
		jobs.push(async () => {
			const out = await runSignal<DmarcRuaResult>(() => d.mineDmarcRua(seedDomain));
			if (!out.ok) {
				signalStatus.dmarc_rua = { status: 'failed', error: out.error };
				return;
			}
			signalStatus.dmarc_rua = { status: out.value.queryStatus };
			for (const r of out.value.ruaDomains) {
				if (r.classification !== 'related') continue;
				addObservation(aggregator, r.domain, 'dmarc_rua', r.confidence, {
					classification: r.classification,
				});
			}
		});
	}

	if (signals.includes('dkim_key_reuse')) {
		jobs.push(async () => {
			const out = await runSignal<DkimKeyReuseResult>(() =>
				d.detectDkimKeyReuse(seedDomain, mergedCandidates, dkimSelectors ? { selectors: dkimSelectors } : {}),
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
		});
	}

	if (signals.includes('http_redirect')) {
		jobs.push(async () => {
			const out = await runSignal<HttpRedirectResult>(() =>
				d.detectHttpRedirect(seedDomain, { candidateDomains: mergedCandidates }),
			);
			if (!out.ok) {
				signalStatus.http_redirect = { status: 'failed', error: out.error };
				return;
			}
			signalStatus.http_redirect = { status: out.value.queryStatus };
			for (const c of out.value.coOwnedDomains) {
				addObservation(aggregator, c.domain, 'http_redirect', c.confidence, c.evidence);
			}
		});
	}

	if (signals.includes('mx_overlap')) {
		jobs.push(async () => {
			const out = await runSignal<MxOverlapResult>(() =>
				d.detectMxOverlap(seedDomain, { candidateDomains: mergedCandidates }),
			);
			if (!out.ok) {
				signalStatus.mx_overlap = { status: 'failed', error: out.error };
				return;
			}
			signalStatus.mx_overlap = { status: out.value.queryStatus };
			for (const c of out.value.coOwnedDomains) {
				addObservation(aggregator, c.domain, 'mx_overlap', c.confidence, c.evidence);
			}
		});
	}

	if (signals.includes('txt_verification')) {
		jobs.push(async () => {
			const out = await runSignal<TxtVerificationResult>(() =>
				d.detectSharedTxtVerifications(seedDomain, { candidateDomains: mergedCandidates }),
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
		});
	}

	if (signals.includes('mx_platform')) {
		jobs.push(async () => {
			const out = await runSignal<MxPlatformResult>(() =>
				d.detectSharedMxPlatform(seedDomain, { candidateDomains: mergedCandidates }),
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
		});
	}

	if (signals.includes('spf_include')) {
		jobs.push(async () => {
			const out = await runSignal<SpfIncludeResult>(() =>
				d.detectSpfInclude(seedDomain, { candidateDomains: mergedCandidates }),
			);
			if (!out.ok) {
				signalStatus.spf_include = { status: 'failed', error: out.error };
				return;
			}
			signalStatus.spf_include = { status: out.value.queryStatus };
			for (const c of out.value.coOwnedDomains) {
				addObservation(aggregator, c.domain, 'spf_include', c.confidence, c.evidence);
			}
		});
	}

	// Forward-discovery: walk the SEED's own SPF chain and surface every
	// different-apex include/redirect target as a same-organization candidate.
	// Unlike `spf_include` (corroboration-only — needs a candidate to probe),
	// this signal MINTS candidates straight from the seed's authoritative
	// mail policy — the path that unlocks Nike-style brand families whose
	// regional ccTLD apexes appear only in the seed's `include:` chain.
	if (signals.includes('spf_include_seed')) {
		jobs.push(async () => {
			const out = await runSignal<SeedSpfWalkResult>(() => d.extractSeedSpfIncludes(seedDomain));
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
		});
	}

	if (signals.includes('cname_alignment')) {
		jobs.push(async () => {
			const out = await runSignal<CnameAlignmentResult>(() =>
				d.detectCnameAlignment(seedDomain, { candidateDomains: mergedCandidates }),
			);
			if (!out.ok) {
				signalStatus.cname_alignment = { status: 'failed', error: out.error };
				return;
			}
			signalStatus.cname_alignment = { status: out.value.queryStatus };
			for (const c of out.value.coOwnedDomains) {
				addObservation(aggregator, c.domain, 'cname_alignment', c.confidence, c.evidence);
			}
		});
	}

	await Promise.allSettled(jobs.map((j) => j()));

	// Second-order SAN expansion: for each first-order sibling, re-query crt.sh
	// and check whether the original seed appears in the candidate's own SAN
	// listing. Mutual cross-cert inclusion is near-deterministic — single hit
	// clears the corroboration gate (see NEAR_DETERMINISTIC_SIGNALS).
	// Skipped when 'san_recursive' isn't requested or first-order yielded no
	// candidates (nothing to probe).
	if (signals.includes('san_recursive') && firstOrderSanCandidates.length > 0) {
		const recursiveOut = await runSignal<SanRecursiveResult>(() =>
			d.correlateSansRecursive(seedDomain, firstOrderSanCandidates, {
				certstream: options.certstream,
				maxCandidates: 20,
				concurrency: 8,
				totalBudgetMs: 30_000,
			}),
		);
		if (!recursiveOut.ok) {
			signalStatus.san_recursive = { status: 'failed', error: recursiveOut.error };
		} else {
			signalStatus.san_recursive = { status: recursiveOut.value.queryStatus };
			for (const cc of recursiveOut.value.crossConfirmed) {
				addObservation(aggregator, cc.candidate, 'san_recursive', DEFAULT_SIGNAL_CONFIDENCE.san_recursive, {
					seed: recursiveOut.value.seedDomain,
					certIds: cc.certIds,
					probedCount: recursiveOut.value.probed.length,
				});
			}
		}
	} else if (signals.includes('san_recursive')) {
		// Requested but no first-order candidates to probe. If first-order SAN
		// itself failed, propagate failure (its preconditions blew up); else
		// record an empty-input skip for telemetry. The propagation keeps the
		// all-failed gate honest when every signal — including san — broke.
		if (signalStatus.san?.status === 'failed') {
			signalStatus.san_recursive = { status: 'failed', error: 'first_order_san_failed' };
		} else {
			signalStatus.san_recursive = { status: 'skipped_no_first_order' };
		}
	}

	// Did every requested signal blow up? If yes, surface a missingControl finding.
	const allFailed = signals.length > 0 && signals.every((s) => signalStatus[s]?.status === 'failed');
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
				},
			),
		]);
	}

	// Build candidate findings.
	const candidateFindings: Finding[] = [];
	const dropCounts = {
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
	}> = [];

	for (const entry of aggregator.values()) {
		// Drop the seed or its subdomains if they accidentally appear (e.g. self-referenced rua=).
		if (isSubdomainOf(entry.domain, seedDomain)) {
			dropCounts.seedOrSubdomain++;
			continue;
		}

		const perSignal = Array.from(entry.perSignalConfidence.entries());

		const signalKinds = perSignal.map(([k]) => k).sort() as DiscoverSignal[];
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

		// Corroboration Requirement: a candidate must be corroborated by ≥2 distinct
		// signals OR be a single near-deterministic signal. Filters single-signal
		// markov_gen, san, dmarc_rua, and ns (LR-1, LR-2 in the v2.14.0 audit) —
		// only single-signal dkim_key_reuse is permitted through this gate.
		// Exception: caller-asserted domains (passed via `candidate_domains`)
		// bypass the gate when at least one signal corroborates them — the
		// caller's explicit listing IS the second corroboration.
		if (
			!callerAssertedDomains.has(entry.domain) &&
			signalKinds.length === 1 &&
			!NEAR_DETERMINISTIC_SIGNALS.has(signalKinds[0])
		) {
			dropCounts.corroborationGate++;
			continue;
		}

		const combined = round4(combineConfidences(perSignal.map(([, c]) => c)));
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
				},
			),
		);
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
