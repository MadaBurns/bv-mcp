// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import serverJsonText from '../../server.json?raw';
import { TOOLS } from '../../src/schemas/tool-definitions';

describe('server.json tool count', () => {
	it('keeps the MCP Registry description tool count in sync with TOOLS.length', () => {
		const serverJson = JSON.parse(serverJsonText) as { description: string };
		const match = serverJson.description.match(/(\d+) MCP tools/);

		expect(match, 'server.json description must contain "N MCP tools"').not.toBeNull();
		expect(Number(match![1])).toBe(TOOLS.length);
	});
});
