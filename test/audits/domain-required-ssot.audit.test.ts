// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { toolRequiresDomain } from '../../src/handlers/tools';
import { TOOLS } from '../../src/schemas/tool-definitions';

// The domain-required derivation lives in tool-sets.ts; tools.ts re-exports it and
// tool-registry.ts holds the registry. A legacy hand-maintained list must be absent
// from every module of the split, not just the original file.
const HANDLER_MODULES = ['../../src/handlers/tools.ts', '../../src/handlers/tool-sets.ts', '../../src/handlers/tool-registry.ts'];
const handlerSources = import.meta.glob(
	['../../src/handlers/tools.ts', '../../src/handlers/tool-sets.ts', '../../src/handlers/tool-registry.ts'],
	{ query: '?raw', import: 'default', eager: true },
) as Record<string, string>;

function schemaRequiresDomain(tool: (typeof TOOLS)[number]): boolean {
	const required = tool.inputSchema.required;
	return Array.isArray(required) && required.includes('domain');
}

describe('domain-required SSOT audit', () => {
	it('census: the glob sees every handler module, so the absence check below is not vacuous', () => {
		expect(Object.keys(handlerSources).sort()).toEqual([...HANDLER_MODULES].sort());
		for (const [path, source] of Object.entries(handlerSources)) {
			expect(source.length, `${path} resolved to an empty source`).toBeGreaterThan(0);
		}
		expect(handlerSources['../../src/handlers/tool-sets.ts']).toContain('DOMAIN_REQUIRED_TOOLS');
	});

	it('derives domain-required behavior from tool schemas', () => {
		for (const [path, source] of Object.entries(handlerSources)) {
			expect(source, `${path} must not reintroduce a hand-maintained DOMAIN_OPTIONAL_TOOLS list`).not.toContain('DOMAIN_OPTIONAL_TOOLS');
		}

		for (const tool of TOOLS) {
			expect(toolRequiresDomain(tool.name)).toBe(schemaRequiresDomain(tool));
		}
	});

	it('treats register_brand_audit_watch as domain-required because its schema requires domain', () => {
		expect(toolRequiresDomain('register_brand_audit_watch')).toBe(true);
	});
});
