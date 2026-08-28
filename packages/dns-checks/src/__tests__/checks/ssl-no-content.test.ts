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
