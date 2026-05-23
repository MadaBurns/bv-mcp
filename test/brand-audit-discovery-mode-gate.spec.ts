// SPDX-License-Identifier: BUSL-1.1

/**
 * Tier gate for `discovery_mode='tiered'` on the brand-discovery surface.
 *
 * Background: `tiered` discovery activates Tier-0/1/2 lookups against the
 * private BV_INFRA_GRAPH, BV_INTEL_GATEWAY, and BV_ENTERPRISE service
 * bindings (operator-deploy only). Premium data sources behind a public
 * tool surface — pay-walling them mirrors the `view='csc_complement'` gate
 * at handlers/tools.ts and brings discover_brand_domains, brand_audit_single,
 * and brand_audit_batch_start into parity. On BSL self-hosts, the bindings
 * aren't provisioned and the pipeline degrades to classic; the gate is a
 * no-op there because the underlying capability never existed.
 *
 * Mocks underlying tools so the "accepts" tests don't hit real DNS/RDAP.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';

const TOOLS_ACCEPTING_DISCOVERY_MODE = ['discover_brand_domains', 'brand_audit_single', 'brand_audit_batch_start'] as const;

type ToolName = (typeof TOOLS_ACCEPTING_DISCOVERY_MODE)[number];

function makeArgs(tool: ToolName, discovery_mode?: 'tiered' | 'classic') {
	const base = tool === 'brand_audit_batch_start' ? { domains: ['example.com'] } : { domain: 'example.com' };
	return discovery_mode === undefined ? base : { ...base, discovery_mode };
}

const okResult = {
	category: 'brand_discovery',
	passed: true,
	score: 100,
	findings: [],
};

function mockUnderlyingTools() {
	vi.doMock('../src/tools/discover-brand-domains', () => ({
		discoverBrandDomains: vi.fn().mockResolvedValue(okResult),
	}));
	vi.doMock('../src/tools/brand-audit-single', () => ({
		brandAuditSingle: vi.fn().mockResolvedValue(okResult),
	}));
	vi.doMock('../src/tools/brand-audit-batch-start', () => ({
		brandAuditBatchStart: vi.fn().mockResolvedValue(okResult),
	}));
}

describe('discovery_mode=tiered tier gate', () => {
	afterEach(() => {
		vi.resetModules();
		vi.doUnmock('../src/tools/discover-brand-domains');
		vi.doUnmock('../src/tools/brand-audit-single');
		vi.doUnmock('../src/tools/brand-audit-batch-start');
	});

	for (const tool of TOOLS_ACCEPTING_DISCOVERY_MODE) {
		const args = makeArgs(tool, 'tiered');

		it(`rejects ${tool} discovery_mode='tiered' when authTier is free`, async () => {
			mockUnderlyingTools();
			const { handleToolsCall } = await import('../src/handlers/tools');
			const result = await handleToolsCall({ name: tool, arguments: args }, undefined, { authTier: 'free' } as never);
			expect(result.isError, `${tool}@free with discovery_mode=tiered must error`).toBe(true);
			const textContent = result.content[0];
			const text = textContent && 'text' in textContent ? textContent.text : '';
			expect(text).toMatch(/^Error: Invalid discovery_mode: 'tiered' requires developer tier or higher/);
		});

		it(`rejects ${tool} discovery_mode='tiered' when authTier is agent`, async () => {
			mockUnderlyingTools();
			const { handleToolsCall } = await import('../src/handlers/tools');
			const result = await handleToolsCall({ name: tool, arguments: args }, undefined, { authTier: 'agent' } as never);
			expect(result.isError, `${tool}@agent with discovery_mode=tiered must error`).toBe(true);
			const textContent = result.content[0];
			const text = textContent && 'text' in textContent ? textContent.text : '';
			expect(text).toMatch(/^Error: Invalid discovery_mode: 'tiered' requires developer tier or higher/);
		});

		it(`accepts ${tool} discovery_mode='tiered' when authTier is developer`, async () => {
			mockUnderlyingTools();
			const { handleToolsCall } = await import('../src/handlers/tools');
			const result = await handleToolsCall({ name: tool, arguments: args }, undefined, { authTier: 'developer' } as never);
			if (result.isError) {
				const textContent = result.content[0];
				const text = textContent && 'text' in textContent ? textContent.text : '';
				expect(text).not.toMatch(/^Error: Invalid discovery_mode: 'tiered'/);
			}
		});

		it(`accepts ${tool} discovery_mode='tiered' when authTier is enterprise`, async () => {
			mockUnderlyingTools();
			const { handleToolsCall } = await import('../src/handlers/tools');
			const result = await handleToolsCall({ name: tool, arguments: args }, undefined, { authTier: 'enterprise' } as never);
			if (result.isError) {
				const textContent = result.content[0];
				const text = textContent && 'text' in textContent ? textContent.text : '';
				expect(text).not.toMatch(/^Error: Invalid discovery_mode: 'tiered'/);
			}
		});
	}

	it('omitting discovery_mode does not trigger the gate (free tier allowed)', async () => {
		mockUnderlyingTools();
		const { handleToolsCall } = await import('../src/handlers/tools');
		const result = await handleToolsCall({ name: 'discover_brand_domains', arguments: makeArgs('discover_brand_domains') }, undefined, {
			authTier: 'free',
		} as never);
		if (result.isError) {
			const textContent = result.content[0];
			const text = textContent && 'text' in textContent ? textContent.text : '';
			expect(text).not.toMatch(/^Error: Invalid discovery_mode/);
		}
	});

	it("discovery_mode='classic' is never gated, regardless of tier", async () => {
		mockUnderlyingTools();
		const { handleToolsCall } = await import('../src/handlers/tools');
		const result = await handleToolsCall(
			{ name: 'discover_brand_domains', arguments: makeArgs('discover_brand_domains', 'classic') },
			undefined,
			{ authTier: 'free' } as never,
		);
		if (result.isError) {
			const textContent = result.content[0];
			const text = textContent && 'text' in textContent ? textContent.text : '';
			expect(text).not.toMatch(/^Error: Invalid discovery_mode/);
		}
	});
});
