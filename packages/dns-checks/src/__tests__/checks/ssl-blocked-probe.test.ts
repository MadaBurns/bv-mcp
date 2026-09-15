// SPDX-License-Identifier: BUSL-1.1

/**
 * Issue #972 — an unfingerprinted UA/TLS-based block (non-Cloudflare nginx, no vendor body
 * signature) completed `ssl` normally and published a confident "No HSTS header" plus a false
 * "No HTTP to HTTPS redirect (status 202)", even though a normal client sees the headers and a
 * real 301. `check-http-security.ts` already treats every 4xx as unmeasured (issue #638); this
 * package's `check-ssl.ts` and `ssl-analysis.ts` did not — a 401/403/429/202 on either the
 * https:// or http:// leg fell through to the "real page" branch and was read as the site's own
 * answer.
 *
 * The fix is status-shaped, not body/vendor-shaped (`src/lib/waf-detection.ts`'s Cloudflare/Akamai
 * fingerprints would miss this origin, per the issue's own analysis), so it lives in
 * `isBlockedProbeStatus()` — reused by both the https-leg HSTS analysis and the http-leg redirect
 * analysis instead of two parallel detectors.
 *
 * Imports the SOURCE modules, not the built `@blackveil/dns-checks`.
 */

import { describe, it, expect } from 'vitest';
import { checkSSL } from '../../checks/check-ssl';
import { getHttpRedirectFindings, isBlockedProbeStatus } from '../../checks/ssl-analysis';
import type { FetchFunction } from '../../types';

describe('isBlockedProbeStatus', () => {
	it.each([[401], [403], [429], [202], [500], [503], [0]])('%d is a blocked/unmeasurable probe status', (status) => {
		expect(isBlockedProbeStatus(status)).toBe(true);
	});

	it.each([[200], [301], [404], [418]])('%d is a real, measurable status', (status) => {
		expect(isBlockedProbeStatus(status)).toBe(false);
	});
});

describe('getHttpRedirectFindings — a block/challenge response on the HTTP probe is unmeasured (issue #972)', () => {
	it.each([[401], [403], [429], [202], [503]])('status %d emits NO redirect finding', (status) => {
		expect(getHttpRedirectFindings('example.com', status, null)).toEqual([]);
	});

	// Control (issue #806/#819, unchanged by this fix): a genuine non-block status still emits it.
	it.each([[200], [404], [418]])('a real non-redirect status %d still emits the finding (control)', (status) => {
		const findings = getHttpRedirectFindings('example.com', status, null);
		expect(findings).toHaveLength(1);
		expect(findings[0].title).toBe('No HTTP to HTTPS redirect');
	});
});

describe('checkSSL — a blocked https:// probe is inconclusive, not a missing-HSTS slate (issue #972)', () => {
	it.each([[401], [403], [429], [202]])('https HEAD %d with no headers: no HSTS finding, excluded, no missingControl', async (status) => {
		const fetchFn: FetchFunction = async (url) => {
			if (url.startsWith('http://')) {
				return new Response(null, { status: 301, headers: { location: 'https://example.com/' } });
			}
			// The block page carries none of the site's real security headers.
			return new Response(null, { status });
		};
		const result = await checkSSL('example.com', fetchFn);
		expect(result.findings.some((f) => f.title === 'No HSTS header')).toBe(false);
		expect(result.findings.some((f) => f.metadata?.missingControl === true)).toBe(false);
		expect(result.checkStatus).toBe('error');
		expect(result.score).toBe(0);
		expect(result.passed).toBe(false);
	});

	it('a real 200 with a genuine missing HSTS header is UNCHANGED (control)', async () => {
		const fetchFn: FetchFunction = async (url) =>
			url.startsWith('http://')
				? new Response(null, { status: 301, headers: { location: 'https://example.com/' } })
				: new Response(null, { status: 200 });
		const result = await checkSSL('example.com', fetchFn);
		expect(result.findings.some((f) => f.title === 'No HSTS header')).toBe(true);
		expect(result.checkStatus).toBeUndefined();
	});

	it('headers that ARE present on a 403 must not be reported missing (positive control)', async () => {
		// A 403 with the site's real HSTS header attached would be an odd shape in practice, but the
		// contract is: a blocked status abstains outright — it never reads ANY header off that
		// response, present or absent, as the site's own answer.
		const fetchFn: FetchFunction = async (url) =>
			url.startsWith('http://')
				? new Response(null, { status: 301, headers: { location: 'https://example.com/' } })
				: new Response(null, { status: 403, headers: { 'strict-transport-security': 'max-age=31536000; includeSubDomains' } });
		const result = await checkSSL('example.com', fetchFn);
		expect(result.findings.some((f) => f.title === 'No HSTS header')).toBe(false);
		expect(result.checkStatus).toBe('error');
	});

	it('an https 200 paired with a blocked http:// probe (status 202) is not scored a missing redirect (issue #972 exact shape)', async () => {
		const fetchFn: FetchFunction = async (url) =>
			url.startsWith('http://')
				? new Response(null, { status: 202 })
				: new Response(null, { status: 200, headers: { 'strict-transport-security': 'max-age=31536000; includeSubDomains' } });
		const result = await checkSSL('example.com', fetchFn);
		expect(result.findings.some((f) => f.title === 'No HTTP to HTTPS redirect')).toBe(false);
		expect(result.checkStatus).toBeUndefined();
	});
});
