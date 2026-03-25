// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, vi } from 'vitest';
import { checkDMARC } from '../../checks/check-dmarc';
import type { DNSQueryFunction } from '../../types';

function createMockDNS(records: Record<string, string[]>): DNSQueryFunction {
	return vi.fn(async (domain: string, _type: string) => {
		return records[domain] ?? [];
	});
}

describe('checkDMARC', () => {
	it('returns critical when no DMARC record found', async () => {
		const queryDNS = createMockDNS({ '_dmarc.example.com': [] });
		const result = await checkDMARC('example.com', queryDNS);
		expect(result.category).toBe('dmarc');
		expect(result.findings[0].severity).toBe('critical');
		expect(result.findings[0].title).toBe('No DMARC record found');
	});

	it('flags p=none as high', async () => {
		const queryDNS = createMockDNS({
			'_dmarc.example.com': ['v=DMARC1; p=none; rua=mailto:dmarc@example.com'],
		});
		const result = await checkDMARC('example.com', queryDNS);
		expect(result.findings.some((f) => f.title === 'DMARC policy set to none')).toBe(true);
	});

	it('flags p=quarantine as low', async () => {
		const queryDNS = createMockDNS({
			'_dmarc.example.com': ['v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com'],
		});
		const result = await checkDMARC('example.com', queryDNS);
		expect(result.findings.some((f) => f.title === 'DMARC policy set to quarantine')).toBe(true);
	});

	it('reports properly configured for p=reject with strict alignment', async () => {
		const queryDNS = createMockDNS({
			'_dmarc.example.com': ['v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@example.com; ruf=mailto:ruf@example.com; adkim=s; aspf=s'],
		});
		const result = await checkDMARC('example.com', queryDNS);
		expect(result.findings.some((f) => f.title === 'DMARC properly configured')).toBe(true);
		expect(result.passed).toBe(true);
	});

	it('flags missing rua', async () => {
		const queryDNS = createMockDNS({
			'_dmarc.example.com': ['v=DMARC1; p=reject'],
		});
		const result = await checkDMARC('example.com', queryDNS);
		expect(result.findings.some((f) => f.title === 'No aggregate reporting')).toBe(true);
	});

	it('flags subdomain policy weaker than parent', async () => {
		const queryDNS = createMockDNS({
			'_dmarc.example.com': ['v=DMARC1; p=reject; sp=none; rua=mailto:dmarc@example.com'],
		});
		const result = await checkDMARC('example.com', queryDNS);
		expect(result.findings.some((f) => f.title === 'Subdomain policy weaker than parent policy' && f.severity === 'high')).toBe(true);
	});

	it('flags invalid pct value', async () => {
		const queryDNS = createMockDNS({
			'_dmarc.example.com': ['v=DMARC1; p=reject; pct=abc'],
		});
		const result = await checkDMARC('example.com', queryDNS);
		expect(result.findings.some((f) => f.title === 'Invalid DMARC percentage value')).toBe(true);
	});
});
