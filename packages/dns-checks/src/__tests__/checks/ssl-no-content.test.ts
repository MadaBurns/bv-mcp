// SPDX-License-Identifier: BUSL-1.1

/**
 * Issue #806, ssl half.
 *
 * `getHttpRedirectFindings` has a catch-all "No HTTP to HTTPS redirect (status N)"
 * finding for any non-3xx status. A 204/205 from the plain-HTTP probe is a no-content
 * response that measured nothing about redirect posture (observed live: google.com's
 * real http:// answer is a 301, yet a scan emitted "status 204") — so the sub-probe is
 * SKIPPED (no finding), matching the check's existing silent-skip posture for a failed
 * HTTP probe. Real statuses (200, 4xx, 3xx→http) keep their current behavior.
 *
 * Imports the SOURCE module, not the built `@blackveil/dns-checks`.
 */

import { describe, it, expect } from 'vitest';
import { getHttpRedirectFindings } from '../../checks/ssl-analysis';
import { checkSSL } from '../../checks/check-ssl';
import type { FetchFunction } from '../../types';

describe('getHttpRedirectFindings — no-content HTTP probe responses are unmeasured (issue #806)', () => {
	it.each([[204], [205]])('status %d emits NO redirect finding', (status) => {
		expect(getHttpRedirectFindings('example.com', status, null)).toEqual([]);
	});

	it.each([[200], [404], [418]])('a real non-redirect status %d still emits the finding', (status) => {
		const findings = getHttpRedirectFindings('example.com', status, null);
		expect(findings).toHaveLength(1);
		expect(findings[0].title).toBe('No HTTP to HTTPS redirect');
		expect(findings[0].severity).toBe('medium');
	});

	it('an http:// downgrade redirect still emits its finding', () => {
		const findings = getHttpRedirectFindings('example.com', 301, 'http://example.com/');
		expect(findings).toHaveLength(1);
		expect(findings[0].title).toBe('HTTP does not redirect to HTTPS');
	});

	it('an https:// redirect stays clean', () => {
		expect(getHttpRedirectFindings('example.com', 301, 'https://example.com/')).toEqual([]);
	});
});

describe('checkSSL — a no-content 2xx on the https:// probe is unmeasured, not a missing-HSTS slate (issue #806 follow-up)', () => {
	it.each([[204], [205]])('https HEAD %d: no HSTS finding, inconclusive/excluded shape, redirect leg skipped', async (status) => {
		// A terminal 204/205 on the https:// leg is not a redirect, so before the guard it
		// flowed into getHttpsFindings() with its empty header set and produced a confident
		// scored "No HSTS header" medium finding from a response that delivered no page —
		// the exact defect family #819 fixed on the http:// leg.
		const httpCalls: string[] = [];
		const fetchFn: FetchFunction = async (url) => {
			if (url.startsWith('http://')) {
				httpCalls.push(url);
				return new Response(null, { status: 301, headers: { location: 'https://example.com/' } });
			}
			return new Response(null, { status });
		};
		const result = await checkSSL('example.com', fetchFn);
		// No confident HSTS verdict may be derived from a bodyless response…
		expect(result.findings.some((f) => f.title === 'No HSTS header')).toBe(false);
		// …and absolutely no claim of absence (issue #638 law).
		expect(result.findings.some((f) => f.metadata?.missingControl === true)).toBe(false);
		// One honest unmeasured finding with the transient-exclusion markers.
		const marker = result.findings.find((f) => f.metadata?.inconclusive === true);
		expect(marker).toBeDefined();
		expect(marker!.metadata?.errorKind).toBe('no_content');
		// The category is EXCLUDED from scoring (transient-failure renormalization).
		expect(result.checkStatus).toBe('error');
		// Nothing reliable to compare the redirect leg against — it must be skipped.
		expect(httpCalls).toEqual([]);
	});

	it('a real headerless 200 is UNCHANGED — still a confident "No HSTS header" finding', async () => {
		const fetchFn: FetchFunction = async (url) =>
			url.startsWith('http://')
				? new Response(null, { status: 301, headers: { location: 'https://example.com/' } })
				: new Response('<html></html>', { status: 200 });
		const result = await checkSSL('example.com', fetchFn);
		expect(result.findings.some((f) => f.title === 'No HSTS header')).toBe(true);
		expect(result.checkStatus).toBeUndefined();
	});
});
