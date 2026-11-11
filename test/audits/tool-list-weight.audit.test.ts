// SPDX-License-Identifier: BUSL-1.1

/**
 * Tool-list weight ratchet.
 *
 * A client that loads the full `tools/list` response pays for every character of
 * it in every conversation, before the user types anything. This audit measures
 * the PUBLIC wire shape (`handleToolsList()`, i.e. what an unauthenticated
 * `tools/list` returns) and fails when it grows past the pinned budgets.
 *
 * The budgets are ceilings, not targets: lower `MAX_TOOL_LIST_CHARS` whenever a
 * trim lands, and raise it only on purpose (a new tool, a new parameter), in the
 * same change that adds the weight.
 *
 * Out of scope on purpose: `outputSchema` (the CLI's `check` command and strict
 * clients depend on it), `annotations` and `_meta` (pinned by their own audits).
 */
import { describe, expect, it } from 'vitest';
import { handleToolsList } from '../../src/handlers/tools';

/** Compact-JSON size of the whole public tool list. Roughly four characters per token. */
const MAX_TOOL_LIST_CHARS = 109_500;
/** Per-tool description ceiling, measured on the wire (includes the scan_domain suffix). */
const MAX_TOOL_DESCRIPTION_CHARS = 400;
/** Per-parameter description ceiling, at any depth of a tool's inputSchema. */
const MAX_PARAM_DESCRIPTION_CHARS = 100;

const tools = handleToolsList().tools;

/** Every `description` string inside a JSON Schema, with a dotted path for the failure message. */
function schemaDescriptions(node: unknown, path: string): Array<{ path: string; text: string }> {
	if (Array.isArray(node)) return node.flatMap((child, index) => schemaDescriptions(child, `${path}[${index}]`));
	if (node === null || typeof node !== 'object') return [];
	return Object.entries(node).flatMap(([key, value]) =>
		key === 'description' && typeof value === 'string' ? [{ path, text: value }] : schemaDescriptions(value, path ? `${path}.${key}` : key),
	);
}

describe('tool list weight: total budget', () => {
	it('the public tools/list response stays under the pinned size', () => {
		expect(tools.length).toBeGreaterThan(0);
		const chars = JSON.stringify(tools).length;
		expect(chars, `tools/list is ${chars} chars; budget is ${MAX_TOOL_LIST_CHARS}`).toBeLessThanOrEqual(MAX_TOOL_LIST_CHARS);
	});
});

describe('tool list weight: tool descriptions', () => {
	it(`no tool description exceeds ${MAX_TOOL_DESCRIPTION_CHARS} characters`, () => {
		const over = tools
			.filter((tool) => tool.description.length > MAX_TOOL_DESCRIPTION_CHARS)
			.map((tool) => `${tool.name} (${tool.description.length})`);
		expect(over).toEqual([]);
	});
});

describe('tool list weight: parameter descriptions', () => {
	it(`no parameter description exceeds ${MAX_PARAM_DESCRIPTION_CHARS} characters`, () => {
		const over = tools.flatMap((tool) =>
			schemaDescriptions(tool.inputSchema, '')
				.filter((entry) => entry.text.length > MAX_PARAM_DESCRIPTION_CHARS)
				.map((entry) => `${tool.name}: ${entry.path} (${entry.text.length})`),
		);
		expect(over).toEqual([]);
	});
});
