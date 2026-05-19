// SPDX-License-Identifier: BUSL-1.1
import { z } from 'zod';

/**
 * Consumer-side Zod schema for the cross-worker contract surface
 *   `bv-infrastructure-graph` → `GET /domain/:domain/related`
 *
 * Producer-side schema lives in bv-web under proprietary license at
 *   cloudflare/infrastructure-graph/src/schemas/domain-related.ts
 * Both copies must accept the same payloads. Schema drift is caught by
 * `test/contracts/bv-infra-graph-domain-related.contract.test.ts` running
 * against a captured-from-live fixture.
 *
 * No source imports cross the license boundary — this file is duplicated
 * intentionally under BSL-1.1.
 *
 * See: docs/superpowers/plans/2026-05-20-brand-discovery-cross-worker-contract.md § 1.1
 */

/** A single shared signal correlating the seed to one or more co-occurring domains. */
export const SharedSignalSchema = z
	.object({
		// signalType remains an open string — the contract enumerates
		// "ns" | "mx" | "spf_include" | "cert_issuer" | "cert_fingerprint" | "soa_admin" | "txt" | ...
		// with a trailing "..." reserving room for producer additions. Tightening to an enum
		// would break the consumer on the next added signal type.
		signalType: z.string(),
		signalValue: z.string(),
		specificityScore: z.number().min(0).max(1),
		coOccurringDomains: z.array(z.string()),
		// Forward-compat: producer may emit the size of the cohort sharing
		// this signal. Used by the Tier 1 confidence formula's
		// `signal_type_weight_bonus` term (deferred until the producer ships
		// this field — see brand-tier1-graph.ts).
		domainCount: z.number().int().min(0).optional(),
	})
	.passthrough();

/** Per-signal-type freshness — captured timestamp + computed age in hours. */
export const PerSignalFreshnessSchema = z.object({
	capturedAt: z.number(),
	ageHours: z.number(),
});

/**
 * Freshness contract:
 *   fresh       — every signal type has a capture < 24h old
 *   partial     — some signals fresh, some 24h–7d
 *   stale       — all signals 7d–30d old
 *   very_stale  — any signal > 30d old (triggers fallback to live sweep)
 */
export const FreshnessSchema = z.object({
	perSignalType: z.record(z.string(), PerSignalFreshnessSchema),
	overallStaleness: z.enum(['fresh', 'partial', 'stale', 'very_stale']),
});

export const DomainRelatedClusterSchema = z
	.object({
		id: z.string(),
		name: z.string().nullable(),
		type: z.string(),
		riskLevel: z.string(),
		domainCount: z.number(),
		matchScore: z.number(),
	})
	.passthrough();

export const DomainRelatedResponseSchema = z
	.object({
		domain: z.string(),
		totalRelated: z.number(),
		clusters: z.array(DomainRelatedClusterSchema),
		sharedSignals: z.array(SharedSignalSchema),
		freshness: FreshnessSchema,
	})
	.passthrough();

export type SharedSignal = z.infer<typeof SharedSignalSchema>;
export type PerSignalFreshness = z.infer<typeof PerSignalFreshnessSchema>;
export type Freshness = z.infer<typeof FreshnessSchema>;
export type DomainRelatedCluster = z.infer<typeof DomainRelatedClusterSchema>;
export type DomainRelatedResponse = z.infer<typeof DomainRelatedResponseSchema>;
