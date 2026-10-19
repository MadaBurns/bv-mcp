// SPDX-License-Identifier: BUSL-1.1

/**
 * `runBrandAuditPipeline` honours its AbortSignal at phase boundaries: a signal that is already
 * aborted stops the pipeline before discovery runs, and the thrown value depends on the abort
 * reason (an Error is rethrown as-is, a string becomes the message, anything else is 'aborted').
 */

import { describe, expect, it, vi } from 'vitest';
import { runBrandAuditPipeline } from '../src/lib/brand-audit-pipeline';

function abortedSignal(reason: unknown): AbortSignal {
	const controller = new AbortController();
	controller.abort(reason);
	return controller.signal;
}

describe('runBrandAuditPipeline abort handling', () => {
	it('rethrows an Error abort reason unchanged and never starts discovery', async () => {
		const discoverBrandDomains = vi.fn();
		const checkRdapLookup = vi.fn();
		const reason = new Error('queue deadline exceeded');

		await expect(
			runBrandAuditPipeline('example.com', { signal: abortedSignal(reason) }, { discoverBrandDomains: discoverBrandDomains as never, checkRdapLookup }),
		).rejects.toBe(reason);
		expect(discoverBrandDomains).not.toHaveBeenCalled();
		expect(checkRdapLookup).not.toHaveBeenCalled();
	});

	it('wraps a string abort reason in an Error carrying that message', async () => {
		const discoverBrandDomains = vi.fn();
		await expect(
			runBrandAuditPipeline('example.com', { signal: abortedSignal('wall-clock timeout') }, { discoverBrandDomains: discoverBrandDomains as never }),
		).rejects.toThrow('wall-clock timeout');
		expect(discoverBrandDomains).not.toHaveBeenCalled();
	});

	it('falls back to a generic "aborted" Error for a non-Error, non-string reason', async () => {
		const discoverBrandDomains = vi.fn();
		await expect(
			runBrandAuditPipeline('example.com', { signal: abortedSignal(42) }, { discoverBrandDomains: discoverBrandDomains as never }),
		).rejects.toThrow(/^aborted$/);
		expect(discoverBrandDomains).not.toHaveBeenCalled();
	});
});
