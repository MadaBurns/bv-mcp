// SPDX-License-Identifier: BUSL-1.1

import { z } from 'zod';
import { TierSchema, ToolNameSchema } from './primitives';

/** POST /internal/tools/call request body. */
export const InternalToolCallSchema = z.object({
	name: ToolNameSchema,
	arguments: z.record(z.string(), z.unknown()).optional(),
});

/** POST /internal/tools/batch request body. */
export const BatchRequestSchema = z.object({
	tool: ToolNameSchema.optional().default('scan_domain'),
	domains: z.array(z.string()).min(1).max(500),
	arguments: z.record(z.string(), z.unknown()).optional(),
	concurrency: z.number().int().min(1).max(50).optional(),
});

/** POST /internal/trial-keys request body. */
export const CreateTrialKeyRequestSchema = z.object({
	label: z.string().min(1).max(200),
	tier: TierSchema.optional(),
	expiresInDays: z.number().int().min(1).max(365).optional(),
	maxUses: z.number().int().min(1).max(1_000_000).optional(),
});
