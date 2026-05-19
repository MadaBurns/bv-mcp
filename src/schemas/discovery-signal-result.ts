// SPDX-License-Identifier: BUSL-1.1

/**
 * Shared contract for brand-discovery signal detectors.
 *
 * Every detector under `src/tenants/discovery/` returns a result that conforms
 * to {@link DiscoverySignalResultSchema}. Adding a new signal? Make the result
 * type conform here, then add the detector to
 * `test/contracts/discovery-signals.contract.test.ts`.
 *
 * Per testing-methodology.md principle 3: Zod schemas ARE the inter-service
 * contract. Tightening this schema (e.g. dropping legacy queryStatus values)
 * is the convergence pressure.
 */

import { z } from 'zod';

/**
 * Canonical 3-state outcome for new detectors. Audit test
 * `discovery-detector-conventions` enforces this for newly-added detectors.
 * Legacy values below are accepted today but should converge.
 */
export const CANONICAL_QUERY_STATUS_VALUES = ['ok', 'partial', 'failed'] as const;

export const QueryStatusSchema = z.enum([
	...CANONICAL_QUERY_STATUS_VALUES,
	// Legacy aliases preserved for backward-compat. Each marked detector should
	// migrate to a canonical value with telemetry preserving the original
	// reason via a sibling field (e.g. `errorKind`).
	'error',
	'rate_limited',
	'timeout',
	'no_spf',
	'budget_exceeded',
]);
export type QueryStatus = z.infer<typeof QueryStatusSchema>;

/**
 * Common candidate shape. Detectors that return bare domain strings (e.g.
 * `SanCorrelationResult.coOwnedDomains: string[]`) satisfy the union via the
 * `z.string()` branch. New detectors should always return the object form so
 * confidence + evidence can travel alongside the domain.
 */
export const CoOwnedCandidateSchema = z.union([
	z.string().min(1),
	z
		.object({
			/** Lowercase ASCII domain. */
			domain: z.string().min(1),
			/** 0.0–1.0 ownership confidence, optional for legacy detectors. */
			confidence: z.number().min(0).max(1).optional(),
			/** Detector-specific corroborating evidence (free-form). */
			evidence: z.unknown().optional(),
		})
		.passthrough(),
]);
export type CoOwnedCandidate = z.infer<typeof CoOwnedCandidateSchema>;

/**
 * Minimum contract every discovery detector must satisfy. Concrete detectors
 * may extend with additional fields (seed metadata, query counts, etc.) — the
 * passthrough on this schema preserves them.
 */
export const DiscoverySignalResultSchema = z
	.object({
		/** Lowercase ASCII seed. Optional for detectors that operate without a single seed. */
		seedDomain: z.string().min(1).optional(),
		coOwnedDomains: z.array(CoOwnedCandidateSchema),
		queryStatus: QueryStatusSchema,
	})
	.passthrough();
export type DiscoverySignalResult = z.infer<typeof DiscoverySignalResultSchema>;

/**
 * Strict variant for NEW detectors built against the convergence target.
 * Forbids bare-string candidates and legacy status values. Use this when
 * authoring a new detector; do NOT relax it for legacy compatibility.
 */
export const StrictCoOwnedCandidateSchema = z
	.object({
		domain: z.string().min(1),
		confidence: z.number().min(0).max(1),
		evidence: z.unknown().optional(),
	})
	.passthrough();

export const StrictDiscoverySignalResultSchema = z
	.object({
		seedDomain: z.string().min(1),
		coOwnedDomains: z.array(StrictCoOwnedCandidateSchema),
		queryStatus: z.enum(CANONICAL_QUERY_STATUS_VALUES),
	})
	.passthrough();
export type StrictDiscoverySignalResult = z.infer<typeof StrictDiscoverySignalResultSchema>;
