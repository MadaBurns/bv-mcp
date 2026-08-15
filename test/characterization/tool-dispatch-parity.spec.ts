// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { DIRECT_DISPATCH_TOOLS, TOOL_REGISTRY, handleToolsList } from '../../src/handlers/tools';
import { isInternalOnlyTool } from '../../src/lib/config';
import { TOOLS } from '../../src/schemas/tool-definitions';

describe('tool dispatch characterization', () => {
	it('exposes every non-internal definition exactly once on the public tools/list surface', () => {
		const listed = handleToolsList().tools.map((tool) => tool.name);
		const expected = TOOLS.filter((tool) => !isInternalOnlyTool(tool.name)).map((tool) => tool.name);

		expect(listed).toEqual(expected);
		expect(new Set(listed).size).toBe(listed.length);
	});

	it('gives every declared tool a registry or explicit-dispatch resolution path', () => {
		const unresolved = TOOLS.map((tool) => tool.name).filter((name) => !(name in TOOL_REGISTRY) && !DIRECT_DISPATCH_TOOLS.has(name));
		expect(unresolved).toEqual([]);
	});

	it('keeps internal-only tools out of public tools/list while retaining a dispatch path', () => {
		const publicNames = new Set(handleToolsList().tools.map((tool) => tool.name));
		for (const tool of TOOLS.filter((definition) => isInternalOnlyTool(definition.name))) {
			expect(publicNames.has(tool.name)).toBe(false);
			expect(tool.name in TOOL_REGISTRY || DIRECT_DISPATCH_TOOLS.has(tool.name)).toBe(true);
		}
	});
});
