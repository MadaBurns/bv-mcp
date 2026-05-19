// SPDX-License-Identifier: BUSL-1.1

/**
 * Wire-format schema for the `bv-intel-gateway` `getDomainEvidence` RPC.
 *
 * Authoritative source: cross-Worker contract document § 1.2 in
 * `docs/superpowers/plans/2026-05-20-brand-discovery-cross-worker-contract.md`.
 *
 * The bv-intel-gateway Worker exposes `getDomainEvidence` on its
 * `WorkerEntrypoint` and returns this exact shape. bv-mcp consumes it via the
 * `BV_INTEL_GATEWAY` service binding and parses the response with this Zod
 * schema before mapping to brand-discovery tier observations.
 *
 * Any wire-format change MUST be coordinated between the two repos and
 * surfaced through the contract test (`test/contracts/bv-intel-gateway-evidence.contract.test.ts`).
 */

import { z } from 'zod';

/** Geographic region the seed was classified into, or `null` if uncategorised. */
export const DomainEvidenceRegionSchema = z.enum(['APAC', 'EMEA', 'AMER', 'ME', 'global']).nullable();

/** Coarse threat banding used by bv-intelligence score buckets. */
export const DomainEvidenceThreatLevelSchema = z.enum(['secure', 'low', 'medium', 'high', 'critical']);

/** Class of `score_alerts` row produced by bv-intelligence drift detection. */
export const DomainEvidenceAlertTypeSchema = z.enum(['degradation', 'critical_drop', 'threshold_cross', 'improvement']);

/** A single scan capture row (`regional_latest_scans` or historical snapshot). */
export const DomainEvidenceScanSchema = z.object({
	capturedAt: z.number(),
	score: z.number().optional(),
	threatLevel: DomainEvidenceThreatLevelSchema.optional(),
});

/** A single `score_alerts` row from the apex `bv-intelligence` DB. */
export const DomainEvidenceScoreAlertSchema = z.object({
	createdAt: z.number(),
	alertType: DomainEvidenceAlertTypeSchema,
	previousThreatLevel: DomainEvidenceThreatLevelSchema,
	newThreatLevel: DomainEvidenceThreatLevelSchema,
	scoreDelta: z.number(),
});

/**
 * Discriminated union: producer returns `ok: false` for the in-corpus-miss
 * (`error: 'not_in_corpus'`) and the opt-out hit (`error: 'opted_out'`).
 * Both are expected, non-exceptional outcomes for many seeds.
 */
export const DomainEvidenceResponseSchema = z.discriminatedUnion('ok', [
	z.object({
		ok: z.literal(true),
		domain: z.string(),
		region: DomainEvidenceRegionSchema,
		latestScan: DomainEvidenceScanSchema.nullable(),
		scanHistory: z.array(DomainEvidenceScanSchema),
		scoreAlerts: z.array(DomainEvidenceScoreAlertSchema),
	}),
	z.object({
		ok: z.literal(false),
		error: z.string(),
	}),
]);

export type DomainEvidenceRegion = z.infer<typeof DomainEvidenceRegionSchema>;
export type DomainEvidenceThreatLevel = z.infer<typeof DomainEvidenceThreatLevelSchema>;
export type DomainEvidenceAlertType = z.infer<typeof DomainEvidenceAlertTypeSchema>;
export type DomainEvidenceScan = z.infer<typeof DomainEvidenceScanSchema>;
export type DomainEvidenceScoreAlert = z.infer<typeof DomainEvidenceScoreAlertSchema>;
export type DomainEvidenceResponse = z.infer<typeof DomainEvidenceResponseSchema>;
