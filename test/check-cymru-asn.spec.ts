// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a DoH A-record response. */
function aResponse(name: string, ips: string[]) {
	return createDohResponse(
		[{ name, type: 1 }],
		ips.map((ip) => ({ name, type: 1, TTL: 300, data: ip })),
	);
}

/** Build a DoH TXT-record response (data values are double-quoted per DNS wire format). */
function txtResponse(name: string, values: string[]) {
	return createDohResponse(
		[{ name, type: 16 }],
		values.map((v) => ({ name, type: 16, TTL: 300, data: `"${v}"` })),
	);
}

/** Build an empty DoH response (NXDOMAIN / no answers). */
function emptyResponse(name: string) {
	return createDohResponse([{ name, type: 1 }], []);
}

/**
 * Build a fetch mock that routes A-record and Cymru TXT queries.
 *
 * @param domainAIps - A records returned for the domain
 * @param originTxt - Map of IP to origin TXT response (e.g. "15169 | 93.184.216.0/24 | US | arin | 2007-03-19")
 * @param orgTxt - Map of ASN to org TXT response (e.g. "15169 | US | arin | 2007-03-19 | GOOGLE - Google LLC, US")
 * @param originErrors - Set of IPs whose origin queries should fail
 * @param orgErrors - Set of ASNs whose org queries should fail
 */
function buildFetchMock(opts: {
	domain?: string;
	domainAIps?: string[];
	originTxt?: Record<string, string>;
	orgTxt?: Record<string, string>;
	originErrors?: Set<string>;
	orgErrors?: Set<string>;
}) {
	const domain = opts.domain ?? 'example.com';
	const domainAIps = opts.domainAIps ?? [];
	const originTxt = opts.originTxt ?? {};
	const orgTxt = opts.orgTxt ?? {};
	const originErrors = opts.originErrors ?? new Set();
	const orgErrors = opts.orgErrors ?? new Set();

	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

		// A record query for domain
		if (url.includes(`name=${domain}`) && url.includes('type=A')) {
			return Promise.resolve(aResponse(domain, domainAIps));
		}
		if (url.includes(`name=${encodeURIComponent(domain)}`) && url.includes('type=A')) {
			return Promise.resolve(aResponse(domain, domainAIps));
		}

		// Origin TXT queries (must check before general asn.cymru.com)
		if (url.includes('origin.asn.cymru.com') && url.includes('type=TXT')) {
			// Check for error IPs
			for (const ip of originErrors) {
				const parts = ip.split('.').reverse().join('.');
				if (url.includes(parts)) {
					return Promise.reject(new Error('DNS timeout'));
				}
			}

			// Check for matching origin records
			for (const [ip, txt] of Object.entries(originTxt)) {
				const reversed = ip.split('.').reverse().join('.');
				if (url.includes(reversed)) {
					const queryName = `${reversed}.origin.asn.cymru.com`;
					return Promise.resolve(txtResponse(queryName, [txt]));
				}
			}

			return Promise.resolve(emptyResponse('origin-query'));
		}

		// Org name TXT queries (AS{asn}.asn.cymru.com)
		if (url.includes('asn.cymru.com') && url.includes('type=TXT')) {
			// Check for error ASNs
			for (const asn of orgErrors) {
				if (url.includes(`AS${asn}.asn.cymru.com`) || url.includes(`AS${asn}.asn.cymru.com`)) {
					return Promise.reject(new Error('DNS timeout'));
				}
			}

			// Check for matching org records
			for (const [asn, txt] of Object.entries(orgTxt)) {
				if (url.includes(`AS${asn}.asn.cymru.com`)) {
					const queryName = `AS${asn}.asn.cymru.com`;
					return Promise.resolve(txtResponse(queryName, [txt]));
				}
			}

			return Promise.resolve(emptyResponse('org-query'));
		}

		// Default empty response
		return Promise.resolve(emptyResponse('unknown'));
	});
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('checkCymruAsn', () => {
	async function run(domain = 'example.com') {
		const { checkCymruAsn } = await import('../src/tools/check-cymru-asn');
		return checkCymruAsn(domain);
	}

	it('should parse standard IPv4 ASN lookup with org name', async () => {
		buildFetchMock({
			domainAIps: ['93.184.216.34'],
			originTxt: {
				'93.184.216.34': '15169 | 93.184.216.0/24 | US | arin | 2007-03-19',
			},
			orgTxt: {
				'15169': '15169 | US | arin | 2007-03-19 | GOOGLE - Google LLC, US',
			},
		});

		const result = await run();
		expect(result.category).toBe('asn');
		expect(result.findings.length).toBeGreaterThanOrEqual(1);

		const infoFinding = result.findings.find((f) => f.severity === 'info' && f.detail.includes('15169'));
		expect(infoFinding).toBeDefined();
		expect(infoFinding!.detail).toContain('93.184.216.0/24');
		expect(infoFinding!.detail).toContain('GOOGLE');
	});

	it('should flag high-risk ASN with medium severity', async () => {
		buildFetchMock({
			domainAIps: ['104.236.128.1'],
			originTxt: {
				'104.236.128.1': '14061 | 104.236.0.0/16 | US | arin | 2012-01-01',
			},
			orgTxt: {
				'14061': '14061 | US | arin | 2012-01-01 | DIGITALOCEAN-ASN - DigitalOcean LLC, US',
			},
		});

		const result = await run();
		expect(result.category).toBe('asn');

		const mediumFinding = result.findings.find((f) => f.severity === 'medium');
		expect(mediumFinding).toBeDefined();
		expect(mediumFinding!.detail).toMatch(/high-risk/i);
		expect(mediumFinding!.detail).toContain('14061');
	});

	it('should report info when no origin record found (no ASN data)', async () => {
		buildFetchMock({
			domainAIps: ['198.51.100.1'],
			// No originTxt — Cymru returns empty
		});

		const result = await run();
		expect(result.category).toBe('asn');

		const infoFinding = result.findings.find((f) => f.severity === 'info' && (f.detail.includes('no ASN') || f.detail.includes('No ASN')));
		expect(infoFinding).toBeDefined();
	});

	it('should still report ASN when org name lookup fails', async () => {
		buildFetchMock({
			domainAIps: ['93.184.216.34'],
			originTxt: {
				'93.184.216.34': '15169 | 93.184.216.0/24 | US | arin | 2007-03-19',
			},
			orgErrors: new Set(['15169']),
		});

		const result = await run();
		expect(result.category).toBe('asn');

		// Should still have the ASN finding even without org name
		const asnFinding = result.findings.find((f) => f.detail.includes('15169'));
		expect(asnFinding).toBeDefined();
		expect(asnFinding!.detail).toContain('93.184.216.0/24');
	});

	it('should handle multiple A record IPs with different ASNs', async () => {
		buildFetchMock({
			domainAIps: ['93.184.216.34', '104.236.128.1'],
			originTxt: {
				'93.184.216.34': '15169 | 93.184.216.0/24 | US | arin | 2007-03-19',
				'104.236.128.1': '14061 | 104.236.0.0/16 | US | arin | 2012-01-01',
			},
			orgTxt: {
				'15169': '15169 | US | arin | 2007-03-19 | GOOGLE - Google LLC, US',
				'14061': '14061 | US | arin | 2012-01-01 | DIGITALOCEAN-ASN - DigitalOcean LLC, US',
			},
		});

		const result = await run();
		expect(result.category).toBe('asn');

		// Should have findings for both IPs
		const googleFinding = result.findings.find((f) => f.detail.includes('15169'));
		const doFinding = result.findings.find((f) => f.detail.includes('14061'));
		expect(googleFinding).toBeDefined();
		expect(doFinding).toBeDefined();

		// DigitalOcean is high-risk
		const mediumFinding = result.findings.find((f) => f.severity === 'medium');
		expect(mediumFinding).toBeDefined();
		expect(mediumFinding!.detail).toContain('14061');
	});

	it('should report info when domain has no A records', async () => {
		buildFetchMock({
			domainAIps: [], // No A records
		});

		const result = await run();
		expect(result.category).toBe('asn');

		const infoFinding = result.findings.find((f) => f.severity === 'info');
		expect(infoFinding).toBeDefined();
		expect(infoFinding!.detail).toMatch(/no.*A record|no.*IP|Could not resolve/i);
	});
});
