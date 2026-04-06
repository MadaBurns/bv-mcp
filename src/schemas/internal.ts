// SPDX-License-Identifier: BUSL-1.1

import { z } from 'zod';
import { ToolNameSchema } from './primitives';

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
