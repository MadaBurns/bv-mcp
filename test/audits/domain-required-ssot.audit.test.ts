// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import handlersSource from '../../src/handlers/tools.ts?raw';
import { toolRequiresDomain } from '../../src/handlers/tools';
import { TOOLS } from '../../src/schemas/tool-definitions';

function schemaRequiresDomain(tool: (typeof TOOLS)[number]): boolean {
	const required = tool.inputSchema.required;
	return Array.isArray(required) && required.includes('domain');
}

describe('domain-required SSOT audit', () => {
	it('derives domain-required behavior from tool schemas', () => {
		expect(handlersSource).not.toContain('DOMAIN_OPTIONAL_TOOLS');

		for (const tool of TOOLS) {
			expect(toolRequiresDomain(tool.name)).toBe(schemaRequiresDomain(tool));
		}
	});

	it('treats register_brand_audit_watch as domain-required because its schema requires domain', () => {
		expect(toolRequiresDomain('register_brand_audit_watch')).toBe(true);
	});
});
