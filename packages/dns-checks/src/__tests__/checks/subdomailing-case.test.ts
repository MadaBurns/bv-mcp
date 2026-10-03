// SPDX-License-Identifier: BUSL-1.1

/**
 * RFC 7208 section 4.5: the SPF version string `v=spf1` is matched case-insensitively.
 * A `V=SPF1 ...` record is a valid SPF record, so an include pointing at it is NOT a void
 * include, and the SPF chain walk must recognise it as the record to follow.
 */

import { describe, it, expect, vi } from 'vitest';
import { extractSpfIncludeChain, probeIncludeDomain } from '../../checks/subdomailing-analysis';
import type { DNSQueryFunction } from '../../types';

function createMockDNS(rules: Record<string, string[]>): DNSQueryFunction {
	return vi.fn(async (domain: string, recordType: string) => rules[`${domain}:${recordType}`] ?? []);
}

describe('subdomailing SPF version string is case-insensitive (RFC 7208 section 4.5)', () => {
	it('does not report an include publishing "V=SPF1" as a void include', async () => {
		const queryDNS = createMockDNS({ 'vendor.example.net:TXT': ['V=SPF1 ip4:192.0.2.1 -all'] });
		const result = await probeIncludeDomain('vendor.example.net', 'include:vendor.example.net', queryDNS);
		expect(result.riskType).toBeNull();
	});

	it('still reports an include with no SPF record at all as a void include', async () => {
		const queryDNS = createMockDNS({ 'vendor.example.net:TXT': ['google-site-verification=abc'] });
		const result = await probeIncludeDomain('vendor.example.net', 'include:vendor.example.net', queryDNS);
		expect(result.riskType).toBe('void_include');
	});

	it('follows a "V=SPF1" record when walking the include chain', async () => {
		const queryDNS = createMockDNS({
			'example.com:TXT': ['V=SPF1 include:vendor.example.net -all'],
			'vendor.example.net:TXT': ['v=spf1 ip4:192.0.2.1 -all'],
		});
		const { domains, spfRecord } = await extractSpfIncludeChain('example.com', queryDNS);
		expect(spfRecord).toBe('V=SPF1 include:vendor.example.net -all');
		expect(domains.has('vendor.example.net')).toBe(true);
	});
});
