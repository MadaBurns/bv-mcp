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
		// Advertised as OPTIONAL, so every existing CheckResult still validates. They are
		// named rather than left to `.loose()` because they are how a strict client learns
		// that `score`/`passed` may be withheld: a check whose `checkStatus` is 'timeout' or
		// 'error' did not complete, and its verdict must not be read as a measurement (#695).
		// A field a client cannot see in the schema is a field it will not look for.
		// `z.string()`, NOT `z.enum([...])`. Naming the field is the point — a strict client
		// cannot look for what the schema never mentions. Pinning its VALUES would re-introduce
		// the brittleness this whole module exists to avoid (see the header): a future
		// CheckStatus member would be rejected by every already-deployed client validating
		// against the older schema, turning an additive package change into a breaking one.
		checkStatus: z.string().optional(),
		partial: z.boolean().optional(),
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
