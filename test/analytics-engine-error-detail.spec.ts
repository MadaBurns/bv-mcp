// SPDX-License-Identifier: BUSL-1.1

/**
 * The AE SQL API explains 4xx rejections in the RESPONSE BODY, never in the status
 * line. `queryAnalyticsEngine` used to throw the status alone, so a permanently
 * broken alerting pipeline paged an operator with "analytics check could not run"
 * and nothing else — the reason ("unknown function call: GREATEST") was sitting in a
 * body the client had already discarded. Diagnosing it took an out-of-band probe
 * against the live API.
 *
 * These tests lock the body into the thrown error so the next failure is readable
 * from the alert itself.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';
import { queryAnalyticsEngine } from '../src/lib/analytics-engine';

const originalFetch = globalThis.fetch;
afterEach(() => {
	globalThis.fetch = originalFetch;
	vi.restoreAllMocks();
});

function mockResponse(status: number, body: string): void {
	globalThis.fetch = vi.fn(async () => new Response(body, { status })) as typeof fetch;
}

describe('queryAnalyticsEngine error detail', () => {
	it('includes the AE rejection reason from the response body, not just the status', async () => {
		mockResponse(422, "Input was invalid: unknown function call: GREATEST");
		await expect(queryAnalyticsEngine('acct', 'tok', 'SELECT 1')).rejects.toThrow(/unknown function call: GREATEST/);
	});

	it('still reports the status code', async () => {
		mockResponse(422, 'Input was invalid: unsupported expression type: CASE WHEN');
		await expect(queryAnalyticsEngine('acct', 'tok', 'SELECT 1')).rejects.toThrow(/422/);
	});

	it('collapses whitespace and bounds the body so a huge error cannot blow up an alert payload', async () => {
		mockResponse(400, 'line one\n\n  line two\t\tline three' + 'x'.repeat(2000));
		await expect(queryAnalyticsEngine('acct', 'tok', 'SELECT 1')).rejects.toThrow(
			// single-spaced, and the whole message stays well under the 2KB body
			/line one line two line three/,
		);
		try {
			await queryAnalyticsEngine('acct', 'tok', 'SELECT 1');
			expect.unreachable('should have thrown');
		} catch (err) {
			expect((err as Error).message.length).toBeLessThan(400);
		}
	});

	it('degrades to the bare status when the body is empty or unreadable', async () => {
		mockResponse(500, '');
		await expect(queryAnalyticsEngine('acct', 'tok', 'SELECT 1')).rejects.toThrow(/Analytics Engine query failed: 500/);
	});

	it('does not throw on a 200', async () => {
		globalThis.fetch = vi.fn(async () => Response.json({ data: [{ n: 1 }] })) as typeof fetch;
		await expect(queryAnalyticsEngine('acct', 'tok', 'SELECT 1')).resolves.toEqual([{ n: 1 }]);
	});
});
