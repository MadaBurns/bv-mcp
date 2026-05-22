// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { setupFetchMock } from './helpers/dns-mock';

describe('view=csc_complement tier gate', () => {
	let mockCtx: { restore: () => void };

	beforeEach(() => {
		mockCtx = setupFetchMock();
	});

	afterEach(() => {
		mockCtx.restore();
		vi.resetModules();
	});

	it('rejects view=csc_complement when authTier is below enterprise', async () => {
		const { handleToolsCall } = await import('../src/handlers/tools');

		const result = await handleToolsCall(
			{ name: 'brand_audit_single', arguments: { domain: 'example.com', view: 'csc_complement' } },
			undefined,
			{ authTier: 'agent' } as never,
		);

		expect(result.isError).toBe(true);
		const textContent = result.content[0];
		const text = textContent && 'text' in textContent ? textContent.text : '';
		expect(text).toMatch(/^Error: Invalid view: 'csc_complement' requires enterprise tier/);
	});

	it('does not reject view=csc_complement at the gate when authTier is enterprise', async () => {
		// Mock brandAuditSingle at the module level before importing handleToolsCall.
		// This short-circuits the tool after the gate passes, avoiding hangs from real discovery.
		// Lift the mock function so we can assert it was called with view forwarded.
		let brandAuditSingleMock: ReturnType<typeof vi.fn>;
		vi.doMock('../src/tools/brand-audit-single', () => {
			brandAuditSingleMock = vi.fn().mockResolvedValue({
				category: 'brand_discovery',
				score: 100,
				findings: [
					{
						category: 'brand_discovery',
						title: 'Mocked brand audit',
						severity: 'info',
						detail: 'Tool mocked for gate test',
					},
				],
			});
			return { brandAuditSingle: brandAuditSingleMock };
		});

		const { handleToolsCall } = await import('../src/handlers/tools');
		const result = await handleToolsCall(
			{ name: 'brand_audit_single', arguments: { domain: 'example.com', view: 'csc_complement' } },
			undefined,
			{ authTier: 'enterprise' } as never,
		);

		// The call may error deeper down (network, missing bindings, etc.) — but if it errors, the
		// message must NOT be the gate's rejection. The gate must let enterprise through.
		if (result.isError) {
			const textContent = result.content[0];
			const text = textContent && 'text' in textContent ? textContent.text : '';
			expect(text).not.toMatch(/^Error: Invalid view:.*requires enterprise tier/);
		}

		// Forwarding assertion: brandAuditSingle must have been called with view in its options.
		// This catches the regression where the gate passes but view is dropped before the pipeline.
		expect(brandAuditSingleMock!).toHaveBeenCalledWith(
			expect.anything(),
			expect.objectContaining({ view: 'csc_complement' }),
			expect.anything(),
		);
	});

	it('omits view → schema accepts and view is undefined', async () => {
		// Asserts the Zod schema accepts a missing `view`; gate logic only fires when view is explicitly csc_complement.
		const { BrandAuditSingleArgs } = await import('../src/schemas/tool-args');
		const parsed = BrandAuditSingleArgs.parse({ domain: 'example.com' });
		expect(parsed.view).toBeUndefined();
	});
});
