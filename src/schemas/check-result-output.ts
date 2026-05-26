// SPDX-License-Identifier: BUSL-1.1

/**
 * Lenient MCP `outputSchema` for tools whose `structuredContent` is a `CheckResult`.
 *
 * v3.3.0 added `structuredContent` to tool-call results; for the registry-driven
 * `check_*`/recon tools that source it from a `CheckResult`, this schema is what
 * strict MCP clients validate the result against.
 *
 * **Contract requirement:** ANY real `CheckResult` MUST validate. `CheckResult`
 * carries optional/wrapper-added fields (`checkStatus`, `partial`, `metadata`,
 * extra finding metadata, and a `category` string that may sit outside the
 * package enum), so this schema is deliberately additive: it pins only the four
 * always-present keys (`category`, `score`, `passed`, `findings`) by type and
 * permits any extra properties via `.loose()`. We do NOT reuse the package
 * `CheckResultSchema` — that one is a strict object keyed to the `CheckCategory`
 * enum and would reject extra keys / new categories, failing strict clients.
 */

import { z } from 'zod';

/**
 * Lenient Zod schema for a `CheckResult`-shaped `structuredContent` payload.
 * `.loose()` (Zod v4 passthrough) lets wrapper-added fields ride through.
 */
export const CheckResultOutputSchema = z
	.object({
		category: z.string(),
		score: z.number(),
		passed: z.boolean(),
		findings: z.array(z.object({}).loose()),
	})
	.loose();

/**
 * The lenient CheckResult output schema as a JSON Schema object, derived via the
 * same `z.toJSONSchema()` path used for tool `inputSchema` (with `$schema` stripped).
 * Built once and shared across all CheckResult tools.
 */
export function buildCheckResultOutputJsonSchema(): {
	type: string;
	properties: Record<string, unknown>;
	required?: string[];
	[key: string]: unknown;
} {
	const jsonSchema = z.toJSONSchema(CheckResultOutputSchema) as Record<string, unknown>;
	delete jsonSchema.$schema;
	return jsonSchema as ReturnType<typeof buildCheckResultOutputJsonSchema>;
}
