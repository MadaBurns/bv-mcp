// SPDX-License-Identifier: BUSL-1.1

import { z } from 'zod';

/** Weight map: category name → numeric weight. */
const WeightsMapSchema = z.record(z.string(), z.number().min(0));

/** Tier split: core/protective/hardening percentages. */
const TierSplitSchema = z.object({
	core: z.number(),
	protective: z.number(),
	hardening: z.number(),
});

/** Thresholds object. */
const ThresholdsSchema = z.object({
	emailBonusImportance: z.number().optional(),
	emailBonusFull: z.number().optional(),
	emailBonusMid: z.number().optional(),
	emailBonusPartial: z.number().optional(),
	spfStrongThreshold: z.number().optional(),
	criticalOverallPenalty: z.number().optional(),
	criticalGapCeiling: z.number().optional(),
}).passthrough();

/** Grade boundaries. */
const GradesSchema = z.object({
	aPlus: z.number().optional(),
	a: z.number().optional(),
	bPlus: z.number().optional(),
	b: z.number().optional(),
	cPlus: z.number().optional(),
	c: z.number().optional(),
	dPlus: z.number().optional(),
	d: z.number().optional(),
}).passthrough();

/**
 * Schema for raw SCORING_CONFIG env var JSON input.
 * All fields optional — parseScoringConfig() merges with defaults.
 */
export const ScoringConfigInputSchema = z.object({
	weights: WeightsMapSchema.optional(),
	profileWeights: z.record(z.string(), WeightsMapSchema).optional(),
	tierSplit: TierSplitSchema.optional(),
	coreWeights: WeightsMapSchema.optional(),
	protectiveWeights: WeightsMapSchema.optional(),
	providerDkimConfidence: z.record(z.string(), z.number().min(0).max(1)).optional(),
	thresholds: ThresholdsSchema.optional(),
	grades: GradesSchema.optional(),
	baselineFailureRates: WeightsMapSchema.optional(),
}).passthrough();
