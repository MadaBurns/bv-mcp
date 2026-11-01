// SPDX-License-Identifier: BUSL-1.1

/**
 * Tier 1 service-binding wrapper for `bv-infrastructure-graph`.
 *
 * Calls `GET /domain/:domain/related` via the `BV_INFRA_GRAPH` Fetcher binding
 * and converts the producer's shared-signal payload into one Tier 1
 * observation **per candidate domain**, with confidence computed via the
 * three-term formula documented in
 *   docs/superpowers/plans/2026-05-20-brand-discovery-first-principles.md
 * (search "Tier 1 confidence formula").
 *
 * Cross-worker contract: bv-mcp consumer side, producer schema lives in
 * bv-web. See:
 *   docs/superpowers/plans/2026-05-20-brand-discovery-cross-worker-contract.md § 1.1
 *   docs/superpowers/plans/2026-05-20-brand-discovery-first-principles-tdd.md   Task 3
 *
 * Invariants enforced here:
 *   1. Never construct an `Authorization` header without `BV_WEB_INTERNAL_KEY`.
 *      Missing key → short-circuit with degraded status; the binding is never called.
 *   2. Never throw. Every failure mode (binding error, non-2xx, malformed JSON,
 *      schema mismatch) collapses into `{ observations: [], status: 'degraded',
 *      triggerTier3Fallback: true }` (`status: 'timeout'` when the deadline
 *      aborted the call), carrying a `degradedReason` token so a dead seam is
 *      diagnosable from the audit result instead of reading as a bare "degraded".
 *   3. Clamp `specificityScore` to [0, 1] on the consumer side as defense vs
 *      producer drift — the schema requires it but we don't depend on validation.
 *   4. No PII logging. The wrapper does not log domain values or auth tokens.
 *   5. Emit ALL co-occurring domains, weighted by the formula. Do not pre-filter
 *      low-specificity entries — downstream gating (T6/T8) decides.
 *   6. Aggregate per candidate: one observation per candidate even when multiple
 *      shared signals contribute. This matches the design doc and prevents the
 *      downstream classifier from double-counting evidence.
 */

import {
	DomainRelatedResponseSchema,
	type DomainRelatedResponse,
	type SharedSignal,
} from '../schemas/cross-worker-domain-related';
import {
	shouldTriggerLiveFallback,
	type FreshnessResponse,
} from './brand-fingerprint-freshness';
import { readJsonResponseCapped } from './response-body';

const TIER1_GRAPH_MAX_BODY_BYTES = 1024 * 1024;
const TIER1_GRAPH_TIMEOUT_MS = 5_000;
/** Cap for reading the producer's JSON error envelope on a non-2xx reply. */
const TIER1_GRAPH_MAX_ERROR_BODY_BYTES = 4 * 1024;
/**
 * Producer error codes are fixed snake_case tokens (`optout_service_unavailable`,
 * `signal_db_unavailable`, `auth_not_configured`, ...). Anything else is dropped
 * so producer-controlled text, and any domain value, never reaches the result.
 */
const UPSTREAM_ERROR_CODE = /^[a-z0-9_]{1,64}$/;

/** Single aggregated observation per co-occurring candidate domain. */
export interface Tier1Observation {
	candidate: string;
	source: 'infra_graph_signal';
	tier: 1;
	confidence: number;
	/** Specificity of the strongest contributing signal (== `maxSpecificity`). */
	specificityScore: number;
	/** Signal type of the strongest contributing signal (max specificity). */
	signalType: string;
	/** Signal value of the strongest contributing signal (max specificity). */
	signalValue: string;
	/** Count of distinct shared signals contributing to this candidate. */
	numSharedSignals: number;
	/** Maximum specificity across all contributing signals. */
	maxSpecificity: number;
	/** All signal types contributing to this candidate (deduped, input order). */
	signalTypes: string[];
}

export type Tier1Status = 'ok' | 'degraded' | 'partial' | 'timeout' | 'skipped';

export interface Tier1Result {
	observations: Tier1Observation[];
	status: Tier1Status;
	triggerTier3Fallback: boolean;
	freshness?: FreshnessResponse;
	/**
	 * Why the lookup did not return `ok`; present on every degraded/timeout
	 * result. One of `no_internal_key`, `timeout`, `fetch_failed`,
	 * `body_unreadable`, `schema_mismatch`, or `http_<status>` optionally
	 * suffixed with the producer's error code (`http_503:optout_service_unavailable`).
	 */
	degradedReason?: string;
}

/** Env shape minimally required by this wrapper. */
export interface Tier1Env {
	BV_WEB_INTERNAL_KEY?: string;
}

/** Cross-worker contract version pinned in the request header. */
const CONTRACT_VERSION = '1';

/** Build the absolute URL passed to the service-binding fetch. */
function buildUrl(domain: string): string {
	return `https://bv-infrastructure-graph/domain/${encodeURIComponent(domain)}/related`;
}

/** Clamp a numeric specificity to the contract range [0, 1]. */
function clamp01(n: number): number {
	if (Number.isNaN(n)) return 0;
	if (n < 0) return 0;
	if (n > 1) return 1;
	return n;
}

/**
 * Tier 1 confidence formula — pure helper, exported for unit tests.
 *
 * confidence = clamp(0, 1,
 *   0.15 * num_shared_signals
 * + 0.50 * max_specificity
 * + 0.10 * signal_type_weight_bonus)
 *
 * `signal_type_weight_bonus` is currently always 0 — see the activation TODO
 * at the call site in `flattenSharedSignals`.
 *
 * Source: docs/superpowers/plans/2026-05-20-brand-discovery-first-principles.md
 */
export function computeTier1Confidence(args: {
	numSharedSignals: number;
	maxSpecificity: number;
	// TODO(brand-discovery): activate signal_type_weight_bonus once bv-web amends
	// cross-Worker contract to include domainCount on SharedSignal. Bonus weights
	// are documented in 2026-05-20-brand-discovery-first-principles.md (search
	// "signal_type_weight_bonus"). Until then, conglomerate brands (PepsiCo-style
	// multi-brand portfolios) will underweight on low-specificity soa_admin
	// signals.
	signalTypeWeightBonus: number;
}): number {
	const raw =
		0.15 * args.numSharedSignals +
		0.5 * args.maxSpecificity +
		0.1 * args.signalTypeWeightBonus;
	if (Number.isNaN(raw)) return 0;
	if (raw < 0) return 0;
	if (raw > 1) return 1;
	return raw;
}

/**
 * Map a parsed producer response into Tier 1 observations.
 *
 * Aggregates per candidate: each candidate appears once even if multiple
 * shared signals contribute. The strongest-specificity contributor wins for
 * the singular `signalType`/`signalValue`/`specificityScore` fields, with
 * input order as a deterministic tie-break.
 */
function flattenSharedSignals(signals: readonly SharedSignal[]): Tier1Observation[] {
	interface Accumulator {
		topSignal: SharedSignal;
		topSpecificity: number;
		signalTypes: string[]; // dedup, input order
		seenTypes: Set<string>;
		count: number;
	}

	const byCandidate = new Map<string, Accumulator>();

	for (const signal of signals) {
		const specificity = clamp01(signal.specificityScore);
		for (const candidate of signal.coOccurringDomains) {
			const existing = byCandidate.get(candidate);
			if (!existing) {
				byCandidate.set(candidate, {
					topSignal: signal,
					topSpecificity: specificity,
					signalTypes: [signal.signalType],
					seenTypes: new Set([signal.signalType]),
					count: 1,
				});
				continue;
			}
			existing.count += 1;
			if (!existing.seenTypes.has(signal.signalType)) {
				existing.seenTypes.add(signal.signalType);
				existing.signalTypes.push(signal.signalType);
			}
			// Strict `>` keeps input-order tie-break — first encountered wins on ties.
			if (specificity > existing.topSpecificity) {
				existing.topSignal = signal;
				existing.topSpecificity = specificity;
			}
		}
	}

	const observations: Tier1Observation[] = [];
	for (const [candidate, acc] of byCandidate) {
		// TODO(brand-discovery): once SharedSignal.domainCount lands in the
		// producer contract, compute the bonus here from the strongest
		// contributing signal's (signalType, domainCount). Until then we
		// pass 0 — see computeTier1Confidence for the bonus rubric.
		const signalTypeWeightBonus = 0;
		const confidence = computeTier1Confidence({
			numSharedSignals: acc.count,
			maxSpecificity: acc.topSpecificity,
			signalTypeWeightBonus,
		});
		observations.push({
			candidate,
			source: 'infra_graph_signal',
			tier: 1,
			confidence,
			specificityScore: acc.topSpecificity,
			signalType: acc.topSignal.signalType,
			signalValue: acc.topSignal.signalValue,
			numSharedSignals: acc.count,
			maxSpecificity: acc.topSpecificity,
			signalTypes: acc.signalTypes,
		});
	}
	return observations;
}

/** The single failure shape for every error path — keeps semantics uniform. */
function degraded(degradedReason: string, status: 'degraded' | 'timeout' = 'degraded'): Tier1Result {
	return { observations: [], status, triggerTier3Fallback: true, degradedReason };
}

/** `http_<status>`, suffixed with the producer's error code when it sent a valid one. */
async function upstreamHttpReason(response: Response): Promise<string> {
	const reason = `http_${response.status}`;
	const body = await readJsonResponseCapped<unknown>(response, TIER1_GRAPH_MAX_ERROR_BODY_BYTES);
	const code = body && typeof body === 'object' ? (body as { error?: unknown }).error : undefined;
	return typeof code === 'string' && UPSTREAM_ERROR_CODE.test(code) ? `${reason}:${code}` : reason;
}

/**
 * Tier 1 candidate lookup against `bv-infrastructure-graph`.
 *
 * Returns observations + status; never throws.
 */
export async function tier1GraphLookup(
	domain: string,
	binding: Fetcher,
	env: Tier1Env,
	timeoutMs = TIER1_GRAPH_TIMEOUT_MS,
): Promise<Tier1Result> {
	// Invariant 1: no auth key → never construct an Authorization header.
	if (!env.BV_WEB_INTERNAL_KEY) {
		return degraded('no_internal_key');
	}

	const controller = new AbortController();
	const timeoutId = setTimeout(
		() => controller.abort(new DOMException('Tier 1 graph lookup timed out', 'TimeoutError')),
		timeoutMs,
	);
	try {
		const req = new Request(buildUrl(domain), {
			method: 'GET',
			headers: {
				Authorization: `Bearer ${env.BV_WEB_INTERNAL_KEY}`,
				'X-Contract-Version': CONTRACT_VERSION,
				Accept: 'application/json',
			},
			signal: controller.signal,
			redirect: 'manual',
		});
		const response = await binding.fetch(req);

		if (!response.ok) {
			return degraded(await upstreamHttpReason(response));
		}

		const rawBody = await readJsonResponseCapped<unknown>(response, TIER1_GRAPH_MAX_BODY_BYTES);
		if (rawBody === null) return degraded('body_unreadable');

		const parsed = DomainRelatedResponseSchema.safeParse(rawBody);
		if (!parsed.success) {
			return degraded('schema_mismatch');
		}

		const data: DomainRelatedResponse = parsed.data;
		const observations = flattenSharedSignals(data.sharedSignals);
		const triggerTier3Fallback = shouldTriggerLiveFallback(data.freshness);

		return {
			observations,
			status: 'ok',
			triggerTier3Fallback,
			freshness: data.freshness,
		};
	} catch {
		return controller.signal.aborted ? degraded('timeout', 'timeout') : degraded('fetch_failed');
	} finally {
		clearTimeout(timeoutId);
	}
}
