// SPDX-License-Identifier: BUSL-1.1

/**
 * Tier 1 service-binding wrapper for `bv-infrastructure-graph`.
 *
 * Calls `GET /domain/:domain/related` via the `BV_INFRA_GRAPH` Fetcher binding
 * and converts each shared-signal co-occurrence into a Tier 1 observation
 * weighted by `specificityScore`.
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
 *   5. Emit ALL co-occurring domains, weighted by specificity. Do not pre-filter
 *      low-specificity entries — downstream gating (T6) decides.
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

/** Single observation emitted per co-occurring domain. */
export interface Tier1Observation {
	candidate: string;
	source: 'infra_graph_signal';
	tier: 1;
	confidence: number;
	specificityScore: number;
	signalType: string;
	signalValue: string;
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

/** Map a parsed producer response into Tier 1 observations. */
function flattenSharedSignals(signals: readonly SharedSignal[]): Tier1Observation[] {
	const observations: Tier1Observation[] = [];
	for (const signal of signals) {
		const confidence = clamp01(signal.specificityScore);
		for (const candidate of signal.coOccurringDomains) {
			observations.push({
				candidate,
				source: 'infra_graph_signal',
				tier: 1,
				confidence,
				specificityScore: confidence,
				signalType: signal.signalType,
				signalValue: signal.signalValue,
			});
		}
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
