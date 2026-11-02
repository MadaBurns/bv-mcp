// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';

// Each module is imported on its own inside a fresh module graph so a top-level
// `const` read across an import cycle (TDZ ReferenceError at Worker start-up)
// fails here instead of in production. Typecheck cannot see that class of bug.
describe('handlers/tools split modules load', () => {
	it('tool-types loads (types only)', async () => {
		vi.resetModules();
		const mod = await import('../src/handlers/tool-types');
		expect(mod).toBeDefined();
	});

	it('tool-sets loads on its own and exposes toolRequiresDomain', async () => {
		vi.resetModules();
		const mod = await import('../src/handlers/tool-sets');
		expect(mod.toolRequiresDomain).toBeDefined();
	});

	it('tool-registry loads on its own and exposes TOOL_REGISTRY', async () => {
		vi.resetModules();
		const mod = await import('../src/handlers/tool-registry');
		expect(mod.TOOL_REGISTRY).toBeDefined();
	});

	it('direct-dispatch loads on its own and exposes dispatchDirectTool', async () => {
		vi.resetModules();
		const mod = await import('../src/handlers/direct-dispatch');
		expect(mod.dispatchDirectTool).toBeDefined();
	});

	it('tools loads on its own and exposes handleToolsCall', async () => {
		vi.resetModules();
		const mod = await import('../src/handlers/tools');
		expect(mod.handleToolsCall).toBeDefined();
	});

	it('tools re-exports the same bindings as the leaf modules', async () => {
		vi.resetModules();
		const tools = await import('../src/handlers/tools');
		const registry = await import('../src/handlers/tool-registry');
		const sets = await import('../src/handlers/tool-sets');
		expect(tools.TOOL_REGISTRY).toBe(registry.TOOL_REGISTRY);
		expect(tools.INTERNAL_BATCH_SAFE_TOOLS).toBe(sets.INTERNAL_BATCH_SAFE_TOOLS);
		expect(tools.MUTATING_DEDUP_TOOLS).toBe(sets.MUTATING_DEDUP_TOOLS);
		expect(tools.DIRECT_DISPATCH_TOOLS).toBe(sets.DIRECT_DISPATCH_TOOLS);
		expect(tools.NXDOMAIN_GATED_TOOLS).toBe(sets.NXDOMAIN_GATED_TOOLS);
		expect(tools.toolRequiresDomain).toBe(sets.toolRequiresDomain);
	});
});
