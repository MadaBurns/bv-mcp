// SPDX-License-Identifier: BUSL-1.1

/**
 * Issue #806, package half.
 *
 * A terminal 204/205 (no-content 2xx) satisfies `response.ok`, so before the guard it
 * flowed straight into `analyzeSecurityHeaders()` and produced the ENTIRE confident
 * missing-header slate — fully scored, no `inconclusive`, no `checkStatus` — from a
 * response that by definition carried no page (observed live: google.com scored
 * "No X-Frame-Options" off an anomalous 204 that google never serves).
 *
 * The pinned contract: a no-content terminal response is UNMEASURED, routed to the same
 * shape as the WAF-blocked/never-completed-probe branches (issue #638 lineage):
 *   - NO missing-header findings, and NEVER `missingControl` (that flag asserts
 *     "we measured and it's absent" — a 204 measured nothing);
 *   - one `inconclusive: true` finding with `errorKind`/`confidence` markers;
 *   - score 0 / passed false, with `checkStatus: 'error'` so the scoring engine
 *     EXCLUDES the category (transient-failure renormalization) rather than scoring it.
 *
 * Imports the SOURCE module, not the built `@blackveil/dns-checks` — meaningful without
 * a dist rebuild.
 */

import { describe, it, expect } from 'vitest';
import { checkHTTPSecurity } from '../../checks/check-http-security';
import type { FetchFunction } from '../../types';

function expectUnmeasuredNoContent(result: Awaited<ReturnType<typeof checkHTTPSecurity>>) {
	// No confident missing-header slate may be derived from a bodyless response…
	expect(result.findings.some((f) => f.title.startsWith('No '))).toBe(false);
	// …and absolutely no claim of absence.
	expect(result.findings.some((f) => f.metadata?.missingControl === true)).toBe(false);
	// One honest unmeasured finding with the transient-exclusion markers.
	const marker = result.findings.find((f) => f.metadata?.inconclusive === true);
	expect(marker).toBeDefined();
	expect(marker!.metadata?.errorKind).toBe('no_content');
	expect(marker!.metadata?.confidence).toBe('heuristic');
	// Unmeasured must never read as a PASS, and the category is EXCLUDED, not zeroed.
	expect(result.score).toBe(0);
	expect(result.passed).toBe(false);
	expect(result.checkStatus).toBe('error');
}

describe('checkHTTPSecurity — a no-content 2xx is unmeasured, not a missing-header slate (issue #806)', () => {
	it('terminal 204 on the direct HEAD path', async () => {
		const fetchFn: FetchFunction = async () => new Response(null, { status: 204 });
		expectUnmeasuredNoContent(await checkHTTPSecurity('example.com', fetchFn));
	});

	it('terminal 205 on the direct HEAD path', async () => {
		const fetchFn: FetchFunction = async () => new Response(null, { status: 205 });
		expectUnmeasuredNoContent(await checkHTTPSecurity('example.com', fetchFn));
	});

	it('204 reached via a redirect chain (301 → 204)', async () => {
		let calls = 0;
		const fetchFn: FetchFunction = async () => {
			calls++;
			if (calls === 1) {
				return new Response(null, { status: 301, headers: { location: 'https://www.example.com/' } });
			}
			return new Response(null, { status: 204 });
		};
		expectUnmeasuredNoContent(await checkHTTPSecurity('example.com', fetchFn));
	});

	it('204 returned by the GET fallback after a 405 HEAD', async () => {
		const fetchFn: FetchFunction = async (_url, init) => {
			if (init?.method === 'GET') return new Response(null, { status: 204 });
			return new Response(null, { status: 405 });
		};
		expectUnmeasuredNoContent(await checkHTTPSecurity('example.com', fetchFn));
	});

	it('a real headerless 200 is UNCHANGED — still analyzed as a measured page', async () => {
		// The guard is scoped to 204/205: a 200 with no security headers is a genuine
		// measurement of a served page, and its missing-header findings stay confident.
		const fetchFn: FetchFunction = async () => new Response('<html></html>', { status: 200 });
		const result = await checkHTTPSecurity('example.com', fetchFn);
		expect(result.checkStatus).toBeUndefined();
		expect(result.findings.some((f) => f.title === 'No Content-Security-Policy')).toBe(true);
	});
});
