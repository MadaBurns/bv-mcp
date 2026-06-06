// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, vi } from 'vitest';
import { checkSPF } from '../../checks/check-spf';
import { analyzeSpfLookupBudget, checkBroadIpRanges, estimateTxtRrsetBytes, extractLookupDomains, extractSpfSignalDomains } from '../../checks/spf-analysis';
import type { DNSQueryFunction } from '../../types';

/** Build a TXT string of an exact byte length (ASCII, so 1 char === 1 byte). */
function txtOfLength(length: number): string {
	return 'a'.repeat(length);
}

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

	it('returns critical when the record does not begin with v=spf1 (paste-prefix)', async () => {
		// RFC 7208 §4.5: a TXT record is only an SPF record if it BEGINS with "v=spf1".
		// "Value: v=spf1 ..." (a copy-paste artefact) is ignored by receivers → no SPF.
		const queryDNS = createMockDNS({
			'example.com': ['Value: v=spf1 include:spf.protection.outlook.com ~all'],
			'_dmarc.example.com': [],
		});
		const result = await checkSPF('example.com', queryDNS);
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].title).toBe('No SPF record found');
		expect(result.findings[0].severity).toBe('critical');
	});

	it('returns critical when v=spf1 is not followed by a space (run-together mechanisms)', async () => {
		// RFC 7208 §4.5 ABNF: the version token must be followed by SP or end-of-record.
		// "v=spf1include:..." is malformed → receivers treat the domain as having no SPF.
		const queryDNS = createMockDNS({
			'example.com': ['v=spf1include:spf.protection.outlook.com~all'],
			'_dmarc.example.com': [],
		});
		const result = await checkSPF('example.com', queryDNS);
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].title).toBe('No SPF record found');
		expect(result.findings[0].severity).toBe('critical');
	});

	it('does not treat an unrelated TXT record containing v=spf1 as an SPF record', async () => {
		// A record that merely embeds the substring mid-string must not be picked up.
		const queryDNS = createMockDNS({
			'example.com': ['contains v=spf1 mid-string but is not an SPF record'],
			'_dmarc.example.com': [],
		});
		const result = await checkSPF('example.com', queryDNS);
		expect(result.findings).toHaveLength(1);
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

	it('does not flag truncation when the TXT RRset is well under 512 bytes', async () => {
		const queryDNS = createMockDNS({
			'example.com': ['v=spf1 include:_spf.example.net -all'],
			'_dmarc.example.com': ['v=DMARC1; p=reject; aspf=s; adkim=s'],
		});
		const result = await checkSPF('example.com', queryDNS);
		expect(result.findings.some((f) => f.title.toLowerCase().includes('udp'))).toBe(false);
		expect(result.findings.some((f) => f.metadata?.findingCode === 'SPF_RRSET_LARGE')).toBe(false);
	});

	it('emits a low SPF_RRSET_LARGE finding when the TXT RRset is 450-512 bytes', async () => {
		// Two TXT records summing into the 450-512 byte estimate window.
		const queryDNS = createMockDNS({
			'example.com': ['v=spf1 ' + txtOfLength(240) + ' -all', txtOfLength(190)],
			'_dmarc.example.com': ['v=DMARC1; p=reject; aspf=s; adkim=s'],
		});
		const result = await checkSPF('example.com', queryDNS);
		const finding = result.findings.find((f) => f.metadata?.findingCode === 'SPF_RRSET_LARGE');
		expect(finding).toBeDefined();
		expect(finding?.severity).toBe('low');
		expect(finding?.detail).toMatch(/512-byte UDP/i);
	});

	it('emits a medium finding mentioning TCP fallback and RFC 7208 when the TXT RRset exceeds 512 bytes', async () => {
		const queryDNS = createMockDNS({
			'example.com': [
				'v=spf1 ' + txtOfLength(250) + ' -all',
				txtOfLength(250),
				txtOfLength(100),
			],
			'_dmarc.example.com': ['v=DMARC1; p=reject; aspf=s; adkim=s'],
		});
		const result = await checkSPF('example.com', queryDNS);
		const finding = result.findings.find(
			(f) => f.severity === 'medium' && /512-byte UDP/i.test(f.detail),
		);
		expect(finding).toBeDefined();
		expect(finding?.detail).toMatch(/TCP fallback/i);
		expect(finding?.detail).toMatch(/RFC 7208/i);
	});
});

describe('estimateTxtRrsetBytes', () => {
	it('returns 0 for an empty RRset', () => {
		expect(estimateTxtRrsetBytes([])).toBe(0);
	});

	it('accounts for per-record overhead and the single length octet for a short string', () => {
		// 1 record, 10-byte string: 12 (RR overhead) + 10 (string) + 1 (length octet) = 23
		expect(estimateTxtRrsetBytes([txtOfLength(10)])).toBe(23);
	});

	it('sums multiple records', () => {
		// two 10-byte strings: 2 * 23 = 46
		expect(estimateTxtRrsetBytes([txtOfLength(10), txtOfLength(10)])).toBe(46);
	});

	it('adds an extra length octet for each 255-byte character-string chunk', () => {
		// 300-byte string spans 2 character-strings → 2 length octets.
		// 12 (RR overhead) + 300 (string) + 2 (length octets) = 314
		expect(estimateTxtRrsetBytes([txtOfLength(300)])).toBe(314);
	});

	it('counts an empty TXT string as one (empty) character-string', () => {
		// 12 (RR overhead) + 0 (string) + 1 (length octet) = 13
		expect(estimateTxtRrsetBytes([''])).toBe(13);
	});
});

describe('analyzeSpfLookupBudget — redirect= counts toward the §4.6.4 budget', () => {
	it('counts a bare redirect= modifier as one DNS lookup', () => {
		// RFC 7208 §4.6.4: the redirect modifier is a lookup-consuming term.
		const analysis = analyzeSpfLookupBudget('v=spf1 redirect=_spf.example.com');
		expect(analysis.count).toBe(1);
		expect(analysis.mechanisms).toContain('redirect');
	});

	it('counts redirect= alongside mechanisms so 10 mechanisms + redirect = 11 (crosses the limit)', () => {
		const tenMechs = Array.from({ length: 10 }, (_, i) => `include:spf${i}.example.com`).join(' ');
		const analysis = analyzeSpfLookupBudget(`v=spf1 ${tenMechs} redirect=_spf.example.com -all`);
		expect(analysis.count).toBe(11);
		expect(analysis.count).toBeGreaterThan(10);
	});
});

// Relocated from the removed Worker-side test/spf-analysis.spec.ts, which exercised
// a dead src/tools/spf-analysis.ts fork. These now run against the live dns-checks copy.
// (The fork's analyzeSpfLookupBudget case is covered by the redirect-budget block above.)
describe('spf-analysis signal/IP helpers', () => {
	it('extracts include and redirect domains for downstream signal use', () => {
		expect(extractSpfSignalDomains('v=spf1 include:_spf.google.com include:mail.example.com redirect=_spf.example.net')).toEqual({
			includeDomains: ['_spf.google.com', 'mail.example.com'],
			redirectDomain: '_spf.example.net',
		});
		expect(extractLookupDomains('v=spf1 include:a.com include:b.com redirect=c.com -all')).toEqual({
			includes: ['a.com', 'b.com'],
			redirect: 'c.com',
		});
	});

	it('flags overly broad IPv4 and IPv6 ranges', () => {
		const findings = checkBroadIpRanges('v=spf1 ip4:10.0.0.0/8 ip6:2001::/16 -all', { signalType: 'spf' });
		expect(findings).toHaveLength(2);
		expect(findings[0].title).toContain('Overly broad IP range');
		expect(findings[1].title).toContain('Overly broad IPv6 range');
	});
});
