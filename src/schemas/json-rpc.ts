// SPDX-License-Identifier: BUSL-1.1

import { z } from 'zod';

/** JSON-RPC 2.0 request id: string, number, or null. */
export const JsonRpcIdSchema = z.union([z.string(), z.number(), z.null()]);

/** Single JSON-RPC 2.0 request. Uses passthrough to preserve extra fields. */
export const JsonRpcRequestSchema = z.object({
	jsonrpc: z.literal('2.0'),
	method: z.string().min(1),
	id: JsonRpcIdSchema.optional(),
	params: z.record(z.string(), z.unknown()).optional(),
}).passthrough();

/** Batch: non-empty array of JSON-RPC requests. */
export const JsonRpcBatchSchema = z.array(JsonRpcRequestSchema).min(1);

/** Body: single request or batch. */
export const JsonRpcBodySchema = z.union([JsonRpcRequestSchema, JsonRpcBatchSchema]);
