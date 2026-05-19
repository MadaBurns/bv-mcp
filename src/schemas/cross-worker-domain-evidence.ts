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

/**
 * A single scan capture row (`regional_latest_scans` or historical snapshot).
 *
 * Per cross-Worker contract § 1.2, `threatLevel` is declared as raw `string`
 * (NOT the closed `DomainEvidenceThreatLevelSchema` enum). The bv-intel-gateway
 * producer emits open string (defaulting to `''` when the DB row's value is
 * null) — tightening to the enum here would fail-parse the whole discriminated
 * union on any legacy/empty value and cause the Tier 2 wrapper to silently
 * drop ALL evidence. Wrapper `Set.has()` lookups tolerate unknown strings, so
 * non-matching values simply skip the Tier 4 emit, which is correct behaviour.
 *
 * This schema is shared by `latestScan` and `scanHistory[]`, so the loosening
 * covers both.
 */
export const DomainEvidenceScanSchema = z.object({
	capturedAt: z.number(),
	score: z.number().optional(),
	// Open string per § 1.2 — see comment above. Producer emits '' for null DB rows.
	threatLevel: z.string().optional(),
});

/**
 * A single `score_alerts` row from the apex `bv-intelligence` DB.
 *
 * Per cross-Worker contract § 1.2, ALL string-typed fields here
 * (`alertType`, `previousThreatLevel`, `newThreatLevel`) are declared as raw
 * `string`, NOT the closed `DomainEvidenceAlertTypeSchema` / threat-level enums.
 * bv-intelligence's `score_alerts` table may emit historical legacy values
 * (e.g. `'unknown'`) or future bandings/alertTypes not yet in either enum.
 * Tightening here would fail-parse the whole discriminated union on any such
 * row and cause the Tier 2 wrapper to silently drop ALL evidence.
 *
 * The wrapper's becoming-critical detection (`BECOMING_CRITICAL_FROM` /
 * `BECOMING_CRITICAL_TO`) does set-membership matching against
 * previous/newThreatLevel, which is robust against unknown strings — non-
 * matching values simply don't trigger the Tier 4 emit, which is the correct
 * behavior. `alertType` is forwarded as-is to the observation.
 */
export const DomainEvidenceScoreAlertSchema = z.object({
	createdAt: z.number(),
	// Open string per § 1.2 — see comment above. Producer emits open string.
	alertType: z.string(),
	previousThreatLevel: z.string(),
	newThreatLevel: z.string(),
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
