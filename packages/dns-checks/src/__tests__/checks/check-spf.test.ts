// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, vi } from 'vitest';
import { checkSPF } from '../../checks/check-spf';
import type { DNSQueryFunction } from '../../types';

function createMockDNS(records: Record<string, string[]>): DNSQueryFunction {
	return vi.fn(async (domain: string, _type: string) => {
		return records[domain] ?? [];
	});
}

describe('checkSPF', () => {
	it('returns critical when no SPF record found', async () => {
		const queryDNS = createMockDNS({ 'example.com': [] });
		const result = await checkSPF('example.com', queryDNS);
		expect(result.category).toBe('spf');
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('critical');
		expect(result.findings[0].title).toBe('No SPF record found');
	});

	it('returns high when multiple SPF records found', async () => {
		const queryDNS = createMockDNS({
			'example.com': ['v=spf1 -all', 'v=spf1 ~all'],
			'_dmarc.example.com': [],
		});
		const result = await checkSPF('example.com', queryDNS);
		expect(result.findings.some((f) => f.title === 'Multiple SPF records')).toBe(true);
	});

	it('flags +all as critical', async () => {
		const queryDNS = createMockDNS({
			'example.com': ['v=spf1 +all'],
			'_dmarc.example.com': [],
		});
		const result = await checkSPF('example.com', queryDNS);
		expect(result.findings.some((f) => f.title.includes('Permissive SPF'))).toBe(true);
		expect(result.findings.find((f) => f.title.includes('Permissive SPF'))?.severity).toBe('critical');
	});

	it('flags ~all as low when DMARC is not enforcing', async () => {
		const queryDNS = createMockDNS({
			'example.com': ['v=spf1 include:_spf.google.com ~all'],
			'_dmarc.example.com': ['v=DMARC1; p=none'],
		});
		const result = await checkSPF('example.com', queryDNS);
		expect(result.findings.some((f) => f.title === 'SPF soft fail (~all)' && f.severity === 'low')).toBe(true);
	});

	it('downgrades ~all to info when DMARC p=reject is active', async () => {
		const queryDNS = createMockDNS({
			'example.com': ['v=spf1 include:_spf.google.com ~all'],
			'_dmarc.example.com': ['v=DMARC1; p=reject; aspf=s; adkim=s'],
		});
		const result = await checkSPF('example.com', queryDNS);
		expect(result.findings.some((f) => f.title === 'SPF soft fail (~all) with DMARC enforcement' && f.severity === 'info')).toBe(true);
	});

	it('downgrades ~all to info when DMARC p=quarantine is active', async () => {
		const queryDNS = createMockDNS({
			'example.com': ['v=spf1 include:_spf.google.com ~all'],
			'_dmarc.example.com': ['v=DMARC1; p=quarantine'],
		});
		const result = await checkSPF('example.com', queryDNS);
		expect(result.findings.some((f) => f.title === 'SPF soft fail (~all) with DMARC enforcement' && f.severity === 'info')).toBe(true);
	});

	it('downgrades ~all to info when DMARC p=reject with pct parameter', async () => {
		const queryDNS = createMockDNS({
			'example.com': ['v=spf1 include:_spf.google.com ~all'],
			'_dmarc.example.com': ['v=DMARC1; p=reject; pct=50'],
		});
		const result = await checkSPF('example.com', queryDNS);
		expect(result.findings.some((f) => f.title === 'SPF soft fail (~all) with DMARC enforcement' && f.severity === 'info')).toBe(true);
	});

	it('flags ~all as low when DMARC record is completely absent', async () => {
		const queryDNS = createMockDNS({
			'example.com': ['v=spf1 include:_spf.google.com ~all'],
			'_dmarc.example.com': [],
		});
		const result = await checkSPF('example.com', queryDNS);
		expect(result.findings.some((f) => f.title === 'SPF soft fail (~all)' && f.severity === 'low')).toBe(true);
	});

	it('returns info for properly configured SPF with -all', async () => {
		const queryDNS = createMockDNS({
			'example.com': ['v=spf1 -all'],
			'_dmarc.example.com': ['v=DMARC1; p=reject; aspf=s; adkim=s'],
		});
		const result = await checkSPF('example.com', queryDNS);
		expect(result.findings.some((f) => f.title === 'SPF record configured' && f.severity === 'info')).toBe(true);
		expect(result.passed).toBe(true);
	});

	it('flags deprecated ptr mechanism', async () => {
		const queryDNS = createMockDNS({
			'example.com': ['v=spf1 ptr -all'],
			'_dmarc.example.com': [],
		});
		const result = await checkSPF('example.com', queryDNS);
		expect(result.findings.some((f) => f.title === 'Deprecated ptr mechanism')).toBe(true);
	});

	it('flags overly broad IP ranges', async () => {
		const queryDNS = createMockDNS({
			'example.com': ['v=spf1 ip4:10.0.0.0/4 -all'],
			'_dmarc.example.com': [],
		});
		const result = await checkSPF('example.com', queryDNS);
		expect(result.findings.some((f) => f.title === 'Overly broad IP range')).toBe(true);
	});
});
