// SPDX-License-Identifier: BUSL-1.1

/**
 * Nameserver provider diversity must group by registrable domain, not by the last two
 * labels: `ns1.alpha.co.nz` and `ns1.beta.co.nz` are two different providers, both
 * under the `co.nz` public suffix.
 */

import { describe, it, expect } from 'vitest';
import { getNameserverDiversityFinding } from '../../checks/ns-analysis';

describe('getNameserverDiversityFinding under multi-label public suffixes', () => {
	it('does not flag two unrelated providers under co.nz', () => {
		expect(getNameserverDiversityFinding(['ns1.alpha.co.nz', 'ns1.beta.co.nz'])).toBeNull();
	});

	it('does not flag two unrelated providers under co.uk', () => {
		expect(getNameserverDiversityFinding(['ns1.alpha.co.uk', 'ns1.beta.co.uk'])).toBeNull();
	});

	it('does not flag unrelated providers under com.au / org.uk / govt.nz', () => {
		expect(getNameserverDiversityFinding(['ns1.alpha.com.au', 'ns1.beta.com.au'])).toBeNull();
		expect(getNameserverDiversityFinding(['ns1.alpha.org.uk', 'ns1.beta.org.uk'])).toBeNull();
		expect(getNameserverDiversityFinding(['ns1.alpha.govt.nz', 'ns1.beta.govt.nz'])).toBeNull();
	});

	it('still flags a single provider under a multi-label suffix and names its registrable domain', () => {
		const finding = getNameserverDiversityFinding(['ns1.alpha.co.nz', 'ns2.alpha.co.nz']);
		expect(finding?.title).toBe('Low nameserver diversity');
		expect(finding?.detail).toContain('All nameservers are under alpha.co.nz.');
	});

	it('still flags a single provider under a single-label suffix', () => {
		const finding = getNameserverDiversityFinding(['ns1.cloudflare.com', 'ns2.cloudflare.com']);
		expect(finding?.detail).toContain('All nameservers are under cloudflare.com.');
	});

	it('does not flag providers on different single-label registrable domains', () => {
		expect(getNameserverDiversityFinding(['ns1.cloudflare.com', 'ns1.awsdns-01.org'])).toBeNull();
	});
});
