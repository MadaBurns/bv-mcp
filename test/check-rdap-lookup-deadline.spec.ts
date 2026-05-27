// SPDX-License-Identifier: BUSL-1.1
//
// Regression for the `rdap_lookup` ~28s server-cap timeout: the RDAP fetch
// loop honoured server-controlled `Retry-After` values up to 15s + ran up to
// 2 attempts × 10s each, plus a follow-on WHOIS fallback. A slow / rate-
// limited TLD RDAP server could chain past 28s without anything short-
// circuiting, losing the Promise.race against TOOL_CALL_TIMEOUT_MS. With
// deadlineMs threaded in, `parseRetryAfterMs` must clamp the sleep against
// remaining budget and the retry must short-circuit when budget is gone.

import { describe, it, expect, vi, afterEach } from 'vitest';

afterEach(() => {
	vi.restoreAllMocks();
});

describe('checkRdapLookup — deadline propagation', () => {
	it('does NOT sleep through a server-supplied 60s Retry-After when the deadline is tight', async () => {
		// Mock fetch:
		// - IANA bootstrap returns a real-shaped RDAP service map for .com.
		// - The actual RDAP query returns 503 with Retry-After: 60 — without
		//   the clamp this would sleep 60s; with it, the sleep is clamped to
		//   remaining budget (< 2s here) and the retry is skipped entirely.
		const fetchSpy = vi
			.spyOn(globalThis, 'fetch')
			.mockImplementation((input: RequestInfo | URL) => {
				const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
				if (url.includes('data.iana.org/rdap/dns.json')) {
					return Promise.resolve(
						new Response(
							JSON.stringify({
								services: [[['com'], ['https://rdap.verisign.com/com/v1/']]],
							}),
							{ status: 200 },
						),
					);
				}
				if (url.includes('rdap.verisign.com')) {
					return Promise.resolve(
						new Response('Too Many Requests', {
							status: 503,
							headers: { 'Retry-After': '60' },
						}),
					);
				}
				return Promise.resolve(new Response('Not Found', { status: 404 }));
			});

		const { checkRdapLookup } = await import('../src/tools/check-rdap-lookup');
		const start = Date.now();
		const result = await checkRdapLookup('example.com', {
			signal: AbortSignal.timeout(1_500),
			deadlineMs: Date.now() + 1_500,
		});
		const elapsed = Date.now() - start;

		// Pipeline returned well within the 1.5s budget — NOT after a 60s sleep.
		expect(elapsed).toBeLessThan(5_000);
		// Result is well-formed (the category itself is invariant; error path
		// surfaces through `findings`).
		expect(result.category).toBe('rdap');
		// Sanity: fetch was actually invoked (so the test exercised the code).
		expect(fetchSpy).toHaveBeenCalled();
	}, 10_000);
});
