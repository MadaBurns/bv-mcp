// SPDX-License-Identifier: BUSL-1.1
//
// Regression for the `compare_domains` ~28s server-cap timeout: the sequential
// scanDomain loop could hang the whole tool call (each scan caps at 15s; 2+
// uncached domains can exceed 28s), losing the Promise.race against
// TOOL_CALL_TIMEOUT_MS and discarding EVERY completed scan. With deadlineMs
// threaded in from the handler, the orchestrator must short-circuit BEFORE
// the next scan rather than past the cap, mark the result `partial: true`,
// preserve already-completed scans, and tag the un-scanned domains in
// `errors` with `budget_exceeded`.

import { describe, it, expect, vi } from 'vitest';
import { compareDomains } from '../src/tools/compare-domains';
import type { StructuredScanResult } from '../src/tools/scan/format-report';

describe('compareDomains — deadline propagation', () => {
	it('short-circuits when deadlineMs is exceeded mid-loop and marks the result partial', async () => {
		// Fast scan: resolves immediately with a real-shape stub.
		// Slow scan: hangs until its abort fires (mirrors a hung downstream).
		// We don't even need the slow scan to fire — the per-iteration deadline
		// check trips BEFORE we call scan() for the 2nd domain, since the 1st
		// scan's resolver runs synchronously enough that Date.now() advances
		// past `deadlineMs: Date.now() - 1` (already in the past).
		const fastResult: StructuredScanResult = {
			domain: 'fast.com',
			score: 95,
			grade: 'A',
			passed: true,
			checks: [],
			summary: { criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, passCount: 0 },
		} as unknown as StructuredScanResult;

		const scanFn = vi
			.fn()
			.mockResolvedValueOnce(fastResult)
			.mockImplementation(
				() =>
					new Promise<StructuredScanResult>(() => {
						/* would hang — but the deadline guard should prevent us reaching here */
					}),
			);

		const start = Date.now();
		const result = await compareDomains(['fast.com', 'hang.com'], {
			scanFn: scanFn as unknown as typeof import('../src/tools/scan-domain').scanDomain,
			deadlineMs: Date.now() - 1, // already in the past — trips on iteration 1
		});
		const elapsed = Date.now() - start;

		// Pipeline returned quickly rather than waiting on the hung scan.
		expect(elapsed).toBeLessThan(5_000);
		// Marked partial because not all domains were scanned.
		expect(result.partial).toBe(true);
		// The hung scan was NEVER invoked — deadline tripped before its iteration.
		// (scanFn may have been invoked 0 times if the deadline trips on iter 0,
		// or 1 time if it trips on iter 1. We assert "≤ 1", not "=== 1".)
		expect(scanFn.mock.calls.length).toBeLessThanOrEqual(1);
		// At minimum, the un-scanned domain shows budget_exceeded in errors.
		expect(result.errors?.['hang.com']).toBe('budget_exceeded');
	});
});
