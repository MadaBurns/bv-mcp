// SPDX-License-Identifier: BUSL-1.1

/**
 * Post-FIND-14 ownership gate tests.
 *
 * The self-asserted `ownership_verified` attestation path has been removed.
 * Developer-tier callers no longer qualify for `discovery_mode='tiered'`
 * (they hit the tier gate in src/handlers/tools.ts before any ownership
 * logic fires), so the FIND-14 gate block is gone.
 *
 * Enterprise, owner, and partner callers were already exempt from the
 * ownership attestation under the old model. Under the new model they
 * remain exempt — and are now the only tiers that can request tiered
 * discovery at all.
 *
 * This file:
 *  - Confirms developer-tier is rejected by the TIER gate (not ownership gate).
 *  - Confirms enterprise / owner / partner are accepted by the tier gate.
 *  - Confirms classic discovery is never gated for any tier.
 *  - Confirms omitting discovery_mode is never gated for any tier.
 *
 * The `ownership_verified` field remains accepted by the Zod schema (no
 * source change needed) but is ignored — enterprise/partner/owner callers
 * may pass it without error; developer callers never reach the point where
 * it would be read.
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

describe('Tiered-discovery tier gate — post ownership-attestation removal', () => {
	afterEach(() => {
		vi.resetModules();
		vi.doUnmock('../src/tools/discover-brand-domains');
		vi.doUnmock('../src/tools/brand-audit-single');
		vi.doUnmock('../src/tools/brand-audit-batch-start');
	});

	for (const tool of TOOLS_ACCEPTING_DISCOVERY_MODE) {
		// --- Developer is now rejected by the TIER gate ---

		it(`rejects ${tool} with discovery_mode='tiered' for developer tier (tier gate, not ownership gate)`, async () => {
			mockUnderlyingTools();
			const { handleToolsCall } = await import('../src/handlers/tools');
			const result = await handleToolsCall(
				{ name: tool, arguments: makeArgs(tool) },
				undefined,
				{ authTier: 'developer' } as never,
			);
			expect(result.isError, `${tool}@developer with tiered must be rejected by tier gate`).toBe(true);
			const textContent = result.content[0];
			const text = textContent && 'text' in textContent ? textContent.text : '';
			// Must hit the TIER gate — not the (removed) ownership gate.
			expect(text).toMatch(/^Error: Invalid discovery_mode: 'tiered' requires enterprise tier or higher/);
			expect(text).not.toMatch(/ownership_unverified/);
		});

		it(`rejects ${tool} with discovery_mode='tiered' for developer even when ownership_verified=true (tier gate wins)`, async () => {
			mockUnderlyingTools();
			const { handleToolsCall } = await import('../src/handlers/tools');
			const result = await handleToolsCall(
				{ name: tool, arguments: makeArgs(tool, { ownership_verified: true }) },
				undefined,
				{ authTier: 'developer' } as never,
			);
			// Ownership attestation no longer unlocks tiered discovery for developer.
			expect(result.isError, `${tool}@developer with tiered+ownership_verified=true must still be rejected`).toBe(true);
			const textContent = result.content[0];
			const text = textContent && 'text' in textContent ? textContent.text : '';
			expect(text).toMatch(/^Error: Invalid discovery_mode: 'tiered' requires enterprise tier or higher/);
		});

		// --- Enterprise / partner / owner pass the tier gate ---

		it(`allows ${tool} with discovery_mode='tiered' when enterprise tier (no ownership_verified needed)`, async () => {
			mockUnderlyingTools();
			const { handleToolsCall } = await import('../src/handlers/tools');
			const result = await handleToolsCall(
				{ name: tool, arguments: makeArgs(tool) },
				undefined,
				{ authTier: 'enterprise' } as never,
			);
			if (result.isError) {
				const textContent = result.content[0];
				const text = textContent && 'text' in textContent ? textContent.text : '';
				expect(text).not.toMatch(/^Error: Invalid discovery_mode: 'tiered'/);
				expect(text).not.toMatch(/ownership_unverified/);
			}
		});

		it(`allows ${tool} with discovery_mode='tiered' when owner tier (no ownership_verified needed)`, async () => {
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
				expect(text).not.toMatch(/^Error: Invalid discovery_mode: 'tiered'/);
				expect(text).not.toMatch(/ownership_unverified/);
			}
		});

		it(`allows ${tool} with discovery_mode='tiered' when partner tier (operator-internal, no ownership_verified needed)`, async () => {
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
				expect(text).not.toMatch(/^Error: Invalid discovery_mode: 'tiered'/);
				expect(text).not.toMatch(/ownership_unverified/);
			}
		});
	}

	it("classic discovery_mode is never gated (developer tier, no ownership_verified)", async () => {
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
			expect(text).not.toMatch(/^Error: Invalid discovery_mode/);
			expect(text).not.toMatch(/ownership_unverified/);
		}
	});

	it("omitting discovery_mode is never gated (developer tier)", async () => {
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
			expect(text).not.toMatch(/^Error: Invalid discovery_mode/);
			expect(text).not.toMatch(/ownership_unverified/);
		}
	});
});
