// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import readme from '../../README.md?raw';
import { TOOLS } from '../../src/schemas/tool-definitions';

describe('README tool surface', () => {
	it('keeps published tool counts and authoritative DNS infra tools current', () => {
		const toolCount = TOOLS.length;

		expect(toolCount).toBe(59);
		expect(readme).toContain(`MCP%20tools-${toolCount}`);
		expect(readme).toContain(`current ${toolCount}-tool surface`);
		expect(readme).toContain(`${toolCount} MCP tools`);
		expect(readme).toContain('18 scoring categories');
		expect(readme).toContain('check_authoritative_dns_infra');
		expect(readme).toContain('check_root_server_set');
	});
});
