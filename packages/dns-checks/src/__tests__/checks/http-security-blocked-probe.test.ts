// SPDX-License-Identifier: BUSL-1.1

/**
 * Issue #972, http_security half (repair of the SQ-4 candidate, which fixed only check_ssl —
 * see SQ-17's review and the oracle verdict rejecting that candidate as incomplete).
 *
 * A non-Cloudflare/Akamai origin can answer the scanner's probe with an unfingerprinted 202
 * "Accepted" interstitial instead of an interactive page. `response.ok` is true for any 2xx
 * status, so before this guard a 202 fell straight into `analyzeSecurityHeaders()` — same defect
 * family as #806's 204/205 no-content case, just via the `ok` branch instead of missing it
 * entirely. `waf-detection.ts`'s `detectWafEvent` cannot rescue this: it requires a
 * Cloudflare/Akamai header or body signature, and this origin carries none.
 *
 * The pinned contract, same shape as the existing 204/205 and 401/403/"other 4xx" unmeasured
 * lanes:
 *   - NO missing-header findings, and NEVER `missingControl`;
 *   - one `inconclusive: true` finding;
 *   - score 0 / passed false, `checkStatus: 'error'` (scoring engine excludes the category);
 *   - treated as origin-PERSISTENT like the 401/403 lanes, not transient like 204/205 — no
 *     `partial: true`, so it stays cacheable.
 *
 * Imports the SOURCE module, not the built `@blackveil/dns-checks` — meaningful without a dist
 * rebuild.
 */

import { describe, it, expect } from 'vitest';
import { checkHTTPSecurity } from '../../checks/check-http-security';
import type { FetchFunction } from '../../types';

function expectUnmeasuredBlockedProbe(result: Awaited<ReturnType<typeof checkHTTPSecurity>>) {
	expect(result.findings.some((f) => f.title.startsWith('No '))).toBe(false);
	expect(result.findings.some((f) => f.metadata?.missingControl === true)).toBe(false);
	const marker = result.findings.find((f) => f.metadata?.inconclusive === true);
	expect(marker).toBeDefined();
	expect(result.score).toBe(0);
	expect(result.passed).toBe(false);
	expect(result.checkStatus).toBe('error');
	// Origin-persistent, not a transient anomaly — must stay cacheable (issue #972, unlike #806).
	expect(result.partial).toBeUndefined();
}

describe('checkHTTPSecurity — an unfingerprinted 2xx-shaped block is unmeasured, not a missing-header slate (issue #972)', () => {
	it('a uniform 202 on the direct HEAD path (both dual-fetch HEAD probes accepted, no vendor signal)', async () => {
		const fetchFn: FetchFunction = async () => new Response(null, { status: 202 });
		expectUnmeasuredBlockedProbe(await checkHTTPSecurity('example.com', fetchFn));
	});

	it('202 reached via a redirect chain (301 → 202)', async () => {
		let calls = 0;
		const fetchFn: FetchFunction = async () => {
			calls++;
			if (calls === 1) {
				return new Response(null, { status: 301, headers: { location: 'https://www.example.com/' } });
			}
			return new Response(null, { status: 202 });
		};
		expectUnmeasuredBlockedProbe(await checkHTTPSecurity('example.com', fetchFn));
	});

	it("HEAD → 403, GET fallback → 202 (issue #972's exact reported shape)", async () => {
		const fetchFn: FetchFunction = async (_url, init) => {
			if (init?.method === 'GET') return new Response(null, { status: 202 });
			return new Response(null, { status: 403 });
		};
		expectUnmeasuredBlockedProbe(await checkHTTPSecurity('example.com', fetchFn));
	});

	it('a real headerless 200 is UNCHANGED — still analyzed as a measured page', async () => {
		const fetchFn: FetchFunction = async () => new Response('<html></html>', { status: 200 });
		const result = await checkHTTPSecurity('example.com', fetchFn);
		expect(result.checkStatus).toBeUndefined();
		expect(result.findings.some((f) => f.title === 'No Content-Security-Policy')).toBe(true);
	});
});
