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

	it('accepts view=csc_complement when authTier is enterprise (schema accepts arg)', async () => {
		// Smoke test only — asserts the Zod schema accepts the arg without error.
		// Pipeline correctness is covered by Task 6 integration tests.
		const { BrandAuditSingleArgs } = await import('../src/schemas/tool-args');
		const args = BrandAuditSingleArgs.parse({ domain: 'example.com', view: 'csc_complement' });
		expect(args.view).toBe('csc_complement');
	});

	it('omits view → schema accepts and view is undefined', async () => {
		// Asserts the Zod schema accepts a missing `view`; gate logic only fires when view is explicitly csc_complement.
		const { BrandAuditSingleArgs } = await import('../src/schemas/tool-args');
		const parsed = BrandAuditSingleArgs.parse({ domain: 'example.com' });
		expect(parsed.view).toBeUndefined();
	});
});
