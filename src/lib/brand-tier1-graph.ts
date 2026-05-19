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
 *      triggerTier3Fallback: true }`.
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

/** The single failure mode for every error path — keeps semantics uniform. */
function degraded(): Tier1Result {
	return { observations: [], status: 'degraded', triggerTier3Fallback: true };
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
): Promise<Tier1Result> {
	// Invariant 1: no auth key → never construct an Authorization header.
	if (!env.BV_WEB_INTERNAL_KEY) {
		return degraded();
	}

	let response: Response;
	try {
		const req = new Request(buildUrl(domain), {
			method: 'GET',
			headers: {
				Authorization: `Bearer ${env.BV_WEB_INTERNAL_KEY}`,
				'X-Contract-Version': CONTRACT_VERSION,
				Accept: 'application/json',
			},
		});
		response = await binding.fetch(req);
	} catch {
		return degraded();
	}

	if (!response.ok) {
		return degraded();
	}

	let rawBody: unknown;
	try {
		rawBody = await response.json();
	} catch {
		return degraded();
	}

	const parsed = DomainRelatedResponseSchema.safeParse(rawBody);
	if (!parsed.success) {
		return degraded();
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
}
