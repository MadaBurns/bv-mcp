// SPDX-License-Identifier: BUSL-1.1

/**
 * FIND-14 — Domain-ownership verification before tiered brand-audit discovery.
 *
 * A developer-tier caller can run brand-audit "tiered" discovery against
 * third-party domains they don't own, enabling mass reconnaissance. The guard
 * requires `ownership_verified: true` on the tool call when `discovery_mode`
 * is `'tiered'` and the caller is not an enterprise/owner/partner principal
 * (those tiers audit their own portfolios and are exempt from the attestation).
 *
 * Insertion point: `src/handlers/tools.ts`, inline with the existing
 * `discovery_mode='tiered'` tier gate.
 *
 * Mirrors the test structure in `test/brand-audit-discovery-mode-gate.spec.ts`.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';

const TOOLS_ACCEPTING_DISCOVERY_MODE = ['discover_brand_domains', 'brand_audit_single', 'brand_audit_batch_start'] as const;

type ToolName = (typeof TOOLS_ACCEPTING_DISCOVERY_MODE)[number];

function makeArgs(tool: ToolName, extra: Record<string, unknown> = {}) {
	const base = tool === 'brand_audit_batch_start' ? { domains: ['example.com'] } : { domain: 'example.com' };
	return { ...base, discovery_mode: 'tiered', ...extra };
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

describe('FIND-14: ownership_verified gate for tiered discovery', () => {
	afterEach(() => {
		vi.resetModules();
		vi.doUnmock('../src/tools/discover-brand-domains');
		vi.doUnmock('../src/tools/brand-audit-single');
		vi.doUnmock('../src/tools/brand-audit-batch-start');
	});

	for (const tool of TOOLS_ACCEPTING_DISCOVERY_MODE) {
		it(`rejects ${tool} with discovery_mode='tiered' when developer tier omits ownership_verified`, async () => {
			mockUnderlyingTools();
			const { handleToolsCall } = await import('../src/handlers/tools');
			const result = await handleToolsCall(
				{ name: tool, arguments: makeArgs(tool) },
				undefined,
				{ authTier: 'developer' } as never,
			);
			expect(result.isError, `${tool}@developer with tiered and no ownership_verified must error`).toBe(true);
			const textContent = result.content[0];
			const text = textContent && 'text' in textContent ? textContent.text : '';
			expect(text).toMatch(/ownership_unverified/);
		});

		it(`rejects ${tool} with discovery_mode='tiered' when developer tier sends ownership_verified=false`, async () => {
			mockUnderlyingTools();
			const { handleToolsCall } = await import('../src/handlers/tools');
			const result = await handleToolsCall(
				{ name: tool, arguments: makeArgs(tool, { ownership_verified: false }) },
				undefined,
				{ authTier: 'developer' } as never,
			);
			expect(result.isError, `${tool}@developer with tiered and ownership_verified=false must error`).toBe(true);
			const textContent = result.content[0];
			const text = textContent && 'text' in textContent ? textContent.text : '';
			expect(text).toMatch(/ownership_unverified/);
		});

		it(`allows ${tool} with discovery_mode='tiered' when developer tier sends ownership_verified=true`, async () => {
			mockUnderlyingTools();
			const { handleToolsCall } = await import('../src/handlers/tools');
			const result = await handleToolsCall(
				{ name: tool, arguments: makeArgs(tool, { ownership_verified: true }) },
				undefined,
				{ authTier: 'developer' } as never,
			);
			// Must not be the ownership_unverified error
			if (result.isError) {
				const textContent = result.content[0];
				const text = textContent && 'text' in textContent ? textContent.text : '';
				expect(text).not.toMatch(/ownership_unverified/);
			}
		});

		it(`allows ${tool} with discovery_mode='tiered' when enterprise tier omits ownership_verified (exempt)`, async () => {
			mockUnderlyingTools();
			const { handleToolsCall } = await import('../src/handlers/tools');
			const result = await handleToolsCall(
				{ name: tool, arguments: makeArgs(tool) },
				undefined,
				{ authTier: 'enterprise' } as never,
			);
			// Enterprise is exempt — must not be the ownership_unverified error
			if (result.isError) {
				const textContent = result.content[0];
				const text = textContent && 'text' in textContent ? textContent.text : '';
				expect(text).not.toMatch(/ownership_unverified/);
			}
		});

		it(`allows ${tool} with discovery_mode='tiered' when owner tier omits ownership_verified (exempt)`, async () => {
			mockUnderlyingTools();
			const { handleToolsCall } = await import('../src/handlers/tools');
			const result = await handleToolsCall(
				{ name: tool, arguments: makeArgs(tool) },
				undefined,
				{ authTier: 'owner' } as never,
			);
			if (result.isError) {
				const textContent = result.content[0];
				const text = textContent && 'text' in textContent ? textContent.text : '';
				expect(text).not.toMatch(/ownership_unverified/);
			}
		});

		it(`allows ${tool} with discovery_mode='tiered' when partner tier omits ownership_verified (exempt — operator-internal)`, async () => {
			mockUnderlyingTools();
			const { handleToolsCall } = await import('../src/handlers/tools');
			const result = await handleToolsCall(
				{ name: tool, arguments: makeArgs(tool) },
				undefined,
				{ authTier: 'partner' } as never,
			);
			if (result.isError) {
				const textContent = result.content[0];
				const text = textContent && 'text' in textContent ? textContent.text : '';
				expect(text).not.toMatch(/ownership_unverified/);
			}
		});
	}

	it("classic discovery_mode does not trigger the ownership gate (developer tier, no ownership_verified)", async () => {
		mockUnderlyingTools();
		const { handleToolsCall } = await import('../src/handlers/tools');
		const result = await handleToolsCall(
			{ name: 'discover_brand_domains', arguments: { domain: 'example.com', discovery_mode: 'classic' } },
			undefined,
			{ authTier: 'developer' } as never,
		);
		if (result.isError) {
			const textContent = result.content[0];
			const text = textContent && 'text' in textContent ? textContent.text : '';
			expect(text).not.toMatch(/ownership_unverified/);
		}
	});

	it("omitting discovery_mode does not trigger the ownership gate (developer tier)", async () => {
		mockUnderlyingTools();
		const { handleToolsCall } = await import('../src/handlers/tools');
		const result = await handleToolsCall(
			{ name: 'discover_brand_domains', arguments: { domain: 'example.com' } },
			undefined,
			{ authTier: 'developer' } as never,
		);
		if (result.isError) {
			const textContent = result.content[0];
			const text = textContent && 'text' in textContent ? textContent.text : '';
			expect(text).not.toMatch(/ownership_unverified/);
		}
	});
});
