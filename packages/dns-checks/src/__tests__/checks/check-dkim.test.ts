// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, vi } from 'vitest';
import { checkDKIM } from '../../checks/check-dkim';
import type { DNSQueryFunction } from '../../types';

function createMockDNS(records: Record<string, string[]>): DNSQueryFunction {
	return vi.fn(async (domain: string, _type: string) => {
		return records[domain] ?? [];
	});
}

describe('checkDKIM', () => {
	it('returns high when no DKIM records found among selectors', async () => {
		const queryDNS = createMockDNS({});
		const result = await checkDKIM('example.com', queryDNS);
		expect(result.category).toBe('dkim');
		expect(result.findings.some((f) => f.title === 'No DKIM records found among tested selectors')).toBe(true);
		expect(result.findings[0].severity).toBe('high');
	});

	it('detects DKIM record with specific selector', async () => {
		const queryDNS = createMockDNS({
			'myselector._domainkey.example.com': ['v=DKIM1; k=rsa; p=' + 'A'.repeat(600)],
		});
		const result = await checkDKIM('example.com', queryDNS, { selector: 'myselector' });
		expect(result.findings.some((f) => f.title === 'DKIM configured')).toBe(true);
	});

	it('flags revoked DKIM key', async () => {
		const queryDNS = createMockDNS({
			'default._domainkey.example.com': ['v=DKIM1; p=;'],
		});
		const result = await checkDKIM('example.com', queryDNS);
		// Single revoked key = medium finding
		expect(result.findings.some((f) => f.title.includes('Revoked DKIM key'))).toBe(true);
	});

	it('detects ed25519 key type', async () => {
		const queryDNS = createMockDNS({
			'default._domainkey.example.com': ['v=DKIM1; k=ed25519; p=AAAA'],
		});
		const result = await checkDKIM('example.com', queryDNS);
		expect(result.findings.some((f) => f.title.includes('Ed25519'))).toBe(true);
	});

	it('flags testing mode', async () => {
		const queryDNS = createMockDNS({
			'default._domainkey.example.com': ['v=DKIM1; k=rsa; t=y; p=' + 'A'.repeat(400)],
		});
		const result = await checkDKIM('example.com', queryDNS);
		expect(result.findings.some((f) => f.title.includes('testing mode'))).toBe(true);
	});
});
