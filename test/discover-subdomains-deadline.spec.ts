// SPDX-License-Identifier: BUSL-1.1
//
// Regression for the `discover_subdomains` ~28s server-cap timeout: the
// cold-cache fallback path could chain three 10-second stages (certstream
// `enumerate` → certstream `sans` → crt.sh fallback) for a total of ~30s,
// hitting TOOL_CALL_TIMEOUT_MS and discarding any partial result that the
// earlier stages may have already gathered. With deadlineMs threaded in from
// the handler, the orchestrator must short-circuit BEFORE the next stage
// when the deadline trips, return whatever data is available, and mark the
// result `partial: true` if the deadline was the reason for stopping.

import { describe, it, expect } from 'vitest';
import { discoverSubdomains } from '../src/tools/discover-subdomains';

describe('discoverSubdomains — deadline propagation', () => {
	it('returns immediately when deadlineMs is already in the past', async () => {
		// `discoverSubdomains` has a deadline guard at the very top (line ~215)
		// that returns emptyResult(domain, sourceUnavailable=true, partial=true)
		// before issuing ANY network call. With deadlineMs already past, we
		// must return synchronously without making a single fetch.
		const start = Date.now();
		const result = await discoverSubdomains('example.com', undefined, undefined, {
			deadlineMs: Date.now() - 1,
		});
		const elapsed = Date.now() - start;

		// Returned essentially immediately — no fetches issued.
		expect(elapsed).toBeLessThan(1_000);
		// Marked partial so consumers know this is a budget-trip, not a true
		// "no subdomains found" answer.
		expect(result.partial).toBe(true);
		// And the result is well-formed.
		expect(result.domain).toBe('example.com');
		expect(result.subdomains).toEqual([]);
	});
});
