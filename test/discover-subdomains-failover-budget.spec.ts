// SPDX-License-Identifier: BUSL-1.1

// #738 item 3 — the Certspotter fallback was STRUCTURALLY UNREACHABLE.
//
// `queryDirectSources` refuses to start a source it cannot finish inside the
// caller's deadline (`hasBudgetFor(options, source.timeoutMs)`), an all-or-
// nothing gate. With crt.sh at a hardcoded 10s out of the 24s handler budget,
// the remainder was 24_000 - 10_000 = 14_000 = exactly `CERTSPOTTER_TIMEOUT_MS`,
// so ANY elapsed time at all (cache read, fast-path check, JSON parse) made the
// gate false and Certspotter was never asked. Measured live on v3.58.0:
// `crtsh=timeout, certspotter=not-consulted` for meta.com AND anthropic.com,
// while Certspotter answered anthropic.com directly in HTTP 200 / 43 KB.
//
// These are assertions against the real constants, not comments: any future
// bump of one timeout that re-closes the failover window fails here.

import { describe, expect, it, vi, afterEach } from 'vitest';
import {
	CERTSPOTTER_TIMEOUT_MS,
	CT_FAILOVER_HEADROOM_MS,
	CT_SOURCE_TIMEOUT_MS,
	DISCOVER_SUBDOMAINS_SYNC_BUDGET_MS,
	discoverSubdomains,
} from '../src/tools/discover-subdomains';

describe('CT failover budget invariant (#738)', () => {
	it('leaves a FULL Certspotter attempt inside the handler budget after crt.sh burns its whole timeout', () => {
		expect(CT_SOURCE_TIMEOUT_MS + CERTSPOTTER_TIMEOUT_MS).toBeLessThanOrEqual(DISCOVER_SUBDOMAINS_SYNC_BUDGET_MS);
		// Strictly less: equality is the pre-fix state, where the gate fails on any
		// non-zero elapsed time.
		expect(DISCOVER_SUBDOMAINS_SYNC_BUDGET_MS - CT_SOURCE_TIMEOUT_MS - CERTSPOTTER_TIMEOUT_MS).toBeGreaterThanOrEqual(
			CT_FAILOVER_HEADROOM_MS,
		);
	});

	it('keeps crt.sh a useful primary rather than trimming it to nothing', () => {
		expect(CT_SOURCE_TIMEOUT_MS).toBeGreaterThanOrEqual(5_000);
	});

	it('still consults Certspotter after crt.sh consumes its entire timeout', async () => {
		const consulted: string[] = [];
		vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = String(input instanceof Request ? input.url : input);
			if (url.includes('crt.sh')) {
				consulted.push('crtsh');
				// crt.sh hangs until its per-source abort signal fires — the exact
				// production shape that used to consume the whole budget.
				return await new Promise<Response>((_resolve, reject) => {
					init?.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true });
				});
			}
			if (url.includes('certspotter.com')) {
				consulted.push('certspotter');
				return Response.json([{ id: '1', dns_names: ['api.example.com'], not_before: '', not_after: '' }], { status: 200 });
			}
			return Response.json({}, { status: 404 });
		});

		// The real handler deadline. Elapsed time is non-zero by the time crt.sh
		// aborts, which is precisely what the pre-fix arithmetic could not absorb.
		const result = await discoverSubdomains('example.com', undefined, undefined, {
			deadlineMs: Date.now() + DISCOVER_SUBDOMAINS_SYNC_BUDGET_MS,
		});

		expect(consulted).toEqual(['crtsh', 'certspotter']);
		expect(result.coverage?.notConsulted ?? []).not.toContain('certspotter');
		expect(result.totalSubdomains).toBe(1);
	}, 30_000);

	afterEach(() => {
		vi.unstubAllGlobals();
	});
});
