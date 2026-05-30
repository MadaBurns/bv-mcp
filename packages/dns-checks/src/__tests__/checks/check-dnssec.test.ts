// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, vi } from 'vitest';
import { checkDNSSEC } from '../../checks/check-dnssec';
import type { DNSQueryFunction, RawDNSQueryFunction } from '../../types';

function createMockDNS(records: Record<string, string[]>): DNSQueryFunction {
	return vi.fn(async (domain: string, _type: string) => {
		return records[domain] ?? [];
	});
}

describe('checkDNSSEC', () => {
	it('reports DNSSEC not enabled when no records found', async () => {
		const queryDNS = createMockDNS({});
		const rawQueryDNS: RawDNSQueryFunction = vi.fn(async () => ({ AD: false }));
		const result = await checkDNSSEC('example.com', queryDNS, { rawQueryDNS });
		expect(result.category).toBe('dnssec');
		expect(result.findings.some((f) => f.title === 'DNSSEC not enabled')).toBe(true);
		// NIST-aligned (SP 800-81r3): DNSSEC absence is a high-severity integrity gap,
		// NOT a missing-control zero. Category takes the high penalty (100-25=75) and
		// passes, rather than zeroing — DNSSEC stays a weighted Core control.
		expect(result.passed).toBe(true);
		expect(result.score).toBe(75);
		expect(result.findings.find((f) => f.title === 'DNSSEC not enabled')?.metadata?.missingControl).toBeUndefined();
	});

	it('reports chain of trust incomplete when DNSKEY present but no DS', async () => {
		// Return DNSKEY from first call, empty from second (DS)
		const mockDNS: DNSQueryFunction = vi.fn(async (_domain: string, type: string) => {
			if (type === 'DNSKEY') return ['257 3 13 base64key...'];
			return [];
		});
		const rawQueryDNS: RawDNSQueryFunction = vi.fn(async () => ({ AD: false }));
		const result = await checkDNSSEC('example.com', mockDNS, { rawQueryDNS });
		expect(result.findings.some((f) => f.title === 'DNSSEC chain of trust incomplete')).toBe(true);
	});

	it('reports DNSSEC enabled and validated when all checks pass', async () => {
		const mockDNS: DNSQueryFunction = vi.fn(async (_domain: string, type: string) => {
			if (type === 'DNSKEY') return ['257 3 13 base64key...'];
			if (type === 'DS') return ['12345 13 2 abcdef...'];
			return [];
		});
		const rawQueryDNS: RawDNSQueryFunction = vi.fn(async () => ({ AD: true }));
		const result = await checkDNSSEC('example.com', mockDNS, { rawQueryDNS });
		expect(result.findings.some((f) => f.title.includes('Modern DNSSEC algorithm') || f.title === 'DNSSEC enabled and validated')).toBe(true);
	});

	it('flags deprecated algorithm', async () => {
		const mockDNS: DNSQueryFunction = vi.fn(async (_domain: string, type: string) => {
			if (type === 'DNSKEY') return ['257 3 5 base64key...'];
			if (type === 'DS') return ['12345 5 2 abcdef...'];
			return [];
		});
		const rawQueryDNS: RawDNSQueryFunction = vi.fn(async () => ({ AD: true }));
		const result = await checkDNSSEC('example.com', mockDNS, { rawQueryDNS });
		expect(result.findings.some((f) => f.title.includes('Deprecated DNSKEY algorithm'))).toBe(true);
	});
});
