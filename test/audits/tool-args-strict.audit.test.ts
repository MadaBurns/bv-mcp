// SPDX-License-Identifier: BUSL-1.1

/**
 * Strict tool-argument audit (operator decision 2026-10-25): EVERY tool rejects
 * unknown argument keys, and its published inputSchema says so. A future
 * `.passthrough()` (or a bare strip-mode `z.object`) on any TOOL_SCHEMA_MAP entry
 * — including a `.extend()` derivative or a shared base like BaseDomainArgs —
 * fails here instead of silently re-opening the surface.
 */
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { TOOL_SCHEMA_MAP } from '../../src/schemas/tool-args';
import { TOOLS } from '../../src/schemas/tool-definitions';

const PROBE_KEY = '__strict_args_audit_probe__';
const entries = Object.entries(TOOL_SCHEMA_MAP);

describe('strict tool-argument audit', () => {
	it('covers every published tool (the map and TOOLS name the same set)', () => {
		expect(entries.length).toBeGreaterThan(0);
		expect(new Set(entries.map(([name]) => name))).toEqual(new Set(TOOLS.map((tool) => tool.name)));
	});

	it.each(entries)('%s is a ZodObject that rejects an unknown top-level key at parse', (_name, schema) => {
		expect(schema).toBeInstanceOf(z.ZodObject);
		const result = schema.safeParse({ [PROBE_KEY]: true });
		expect(result.success).toBe(false);
		const unknownKeyIssues = (result.error?.issues ?? []).filter((issue) => issue.code === 'unrecognized_keys');
		expect(unknownKeyIssues).toHaveLength(1);
		expect(unknownKeyIssues[0]).toMatchObject({ path: [], keys: [PROBE_KEY] });
	});

	it.each(TOOLS.map((tool) => [tool.name, tool] as const))('%s publishes additionalProperties:false', (_name, tool) => {
		expect((tool.inputSchema as Record<string, unknown>).additionalProperties).toBe(false);
	});
});
