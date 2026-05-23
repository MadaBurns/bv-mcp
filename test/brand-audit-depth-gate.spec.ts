// SPDX-License-Identifier: BUSL-1.1

/**
 * Tier gate for `depth='deep'` on the brand-discovery surface.
 *
 * Background: `deep` discovery expands candidate seeding and enrichment fanout,
 * roughly 3× the per-call compute and outbound-fetch cost of `standard`. The
 * surface accepts it on three tools — `discover_brand_domains`,
 * `brand_audit_single`, and `brand_audit_batch_start`. Pre-gate, a free caller
 * could request `deep` at the per-tool quota limit (1/day for
 * `discover_brand_domains`; brand_audit_* are already 0 for free/agent so the
 * gate is redundant-but-defensive for those two).
 *
 * Pay-walled at developer tier or higher — same threshold as the
 * `discovery_mode='tiered'` gate landed in PR #188.
 *
 * Mocks underlying tools so "accepts" tests don't hit real DNS/RDAP.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';

const TOOLS_ACCEPTING_DEPTH = ['discover_brand_domains', 'brand_audit_single', 'brand_audit_batch_start'] as const;
type ToolName = (typeof TOOLS_ACCEPTING_DEPTH)[number];

function makeArgs(tool: ToolName, depth?: 'deep' | 'standard') {
	const base = tool === 'brand_audit_batch_start' ? { domains: ['example.com'] } : { domain: 'example.com' };
	return depth === undefined ? base : { ...base, depth };
}

const okResult = { category: 'brand_discovery', passed: true, score: 100, findings: [] };

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

describe('depth=deep tier gate', () => {
	afterEach(() => {
		vi.resetModules();
		vi.doUnmock('../src/tools/discover-brand-domains');
		vi.doUnmock('../src/tools/brand-audit-single');
		vi.doUnmock('../src/tools/brand-audit-batch-start');
	});

	for (const tool of TOOLS_ACCEPTING_DEPTH) {
		const args = makeArgs(tool, 'deep');

		it(`rejects ${tool} depth='deep' when authTier is free`, async () => {
			mockUnderlyingTools();
			const { handleToolsCall } = await import('../src/handlers/tools');
			const result = await handleToolsCall({ name: tool, arguments: args }, undefined, { authTier: 'free' } as never);
			expect(result.isError, `${tool}@free with depth=deep must error`).toBe(true);
			const textContent = result.content[0];
			const text = textContent && 'text' in textContent ? textContent.text : '';
			expect(text).toMatch(/^Error: Invalid depth: 'deep' requires developer tier or higher/);
		});

		it(`rejects ${tool} depth='deep' when authTier is agent`, async () => {
			mockUnderlyingTools();
			const { handleToolsCall } = await import('../src/handlers/tools');
			const result = await handleToolsCall({ name: tool, arguments: args }, undefined, { authTier: 'agent' } as never);
			expect(result.isError, `${tool}@agent with depth=deep must error`).toBe(true);
			const textContent = result.content[0];
			const text = textContent && 'text' in textContent ? textContent.text : '';
			expect(text).toMatch(/^Error: Invalid depth: 'deep' requires developer tier or higher/);
		});

		it(`accepts ${tool} depth='deep' when authTier is developer`, async () => {
			mockUnderlyingTools();
			const { handleToolsCall } = await import('../src/handlers/tools');
			const result = await handleToolsCall({ name: tool, arguments: args }, undefined, { authTier: 'developer' } as never);
			if (result.isError) {
				const textContent = result.content[0];
				const text = textContent && 'text' in textContent ? textContent.text : '';
				expect(text).not.toMatch(/^Error: Invalid depth: 'deep'/);
			}
		});

		it(`accepts ${tool} depth='deep' when authTier is enterprise`, async () => {
			mockUnderlyingTools();
			const { handleToolsCall } = await import('../src/handlers/tools');
			const result = await handleToolsCall({ name: tool, arguments: args }, undefined, { authTier: 'enterprise' } as never);
			if (result.isError) {
				const textContent = result.content[0];
				const text = textContent && 'text' in textContent ? textContent.text : '';
				expect(text).not.toMatch(/^Error: Invalid depth: 'deep'/);
			}
		});
	}

	it('omitting depth does not trigger the gate (free tier allowed)', async () => {
		mockUnderlyingTools();
		const { handleToolsCall } = await import('../src/handlers/tools');
		const result = await handleToolsCall({ name: 'discover_brand_domains', arguments: makeArgs('discover_brand_domains') }, undefined, {
			authTier: 'free',
		} as never);
		if (result.isError) {
			const textContent = result.content[0];
			const text = textContent && 'text' in textContent ? textContent.text : '';
			expect(text).not.toMatch(/^Error: Invalid depth/);
		}
	});

	it("depth='standard' is never gated, regardless of tier", async () => {
		mockUnderlyingTools();
		const { handleToolsCall } = await import('../src/handlers/tools');
		const result = await handleToolsCall(
			{ name: 'discover_brand_domains', arguments: makeArgs('discover_brand_domains', 'standard') },
			undefined,
			{ authTier: 'free' } as never,
		);
		if (result.isError) {
			const textContent = result.content[0];
			const text = textContent && 'text' in textContent ? textContent.text : '';
			expect(text).not.toMatch(/^Error: Invalid depth/);
		}
	});
});
