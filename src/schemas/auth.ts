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
