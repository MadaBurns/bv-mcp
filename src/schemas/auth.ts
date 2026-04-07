// SPDX-License-Identifier: BUSL-1.1

import { z } from 'zod';
import { TierSchema } from './primitives';

/** Tier cache entry stored in KV. */
export const TierCacheEntrySchema = z.object({
	tier: TierSchema,
	revokedAt: z.number().nullable().optional(),
});

/** Response from bv-web service binding validate-key endpoint. */
export const ValidateKeyResponseSchema = z.object({
	tier: TierSchema,
});

/** Trial API key record stored in KV at `trial:{hash}`. */
export const TrialKeyRecordSchema = z.object({
	tier: TierSchema,
	expiresAt: z.number(),
	maxUses: z.number().int().nonnegative(),
	currentUses: z.number().int().nonnegative(),
	label: z.string().max(200),
	createdAt: z.number(),
});

export type TrialKeyRecord = z.infer<typeof TrialKeyRecordSchema>;
