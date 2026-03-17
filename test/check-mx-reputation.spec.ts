// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse, ptrResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

/** Build a DoH response containing MX records for a domain. */
function mxResponse(domain: string, records: Array<{ priority: number; exchange: string }>) {
	return createDohResponse(
		[{ name: domain, type: 15 }],
		records.map((r) => ({ name: domain, type: 15, TTL: 300, data: `${r.priority} ${r.exchange}.` })),
	);
}

/** Build a DoH response containing A records for a hostname. */
function aResponse(name: string, ips: string[]) {
	return createDohResponse(
		[{ name, type: 1 }],
		ips.map((ip) => ({ name, type: 1, TTL: 300, data: ip })),
	);
}

/** Build an empty DoH response (no answers). */
function emptyResponse(name: string, type: number) {
	return createDohResponse([{ name, type }], []);
}

describe('checkMxReputation', () => {
	async function run(domain = 'example.com') {
		const { checkMxReputation } = await import('../src/tools/check-mx-reputation');
		return checkMxReputation(domain);
	}

	it('should return info findings for domain with clean MX reputation', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			// MX records
			if (url.includes('type=MX') || url.includes('type=15')) {
				return Promise.resolve(mxResponse('example.com', [{ priority: 10, exchange: 'mail.example.com' }]));
			}
			// A record for MX host
			if (url.includes('name=mail.example.com') && (url.includes('type=A') || url.includes('type=1'))) {
				return Promise.resolve(aResponse('mail.example.com', ['198.51.100.1']));
			}
			// PTR record for IP
			if (url.includes('1.100.51.198.in-addr.arpa') && (url.includes('type=PTR') || url.includes('type=12'))) {
				return Promise.resolve(ptrResponse('198.51.100.1', ['mail.example.com']));
			}
			// Forward A lookup for PTR hostname (FCrDNS verification)
			if (url.includes('name=mail.example.com') && (url.includes('type=A') || url.includes('type=1'))) {
				return Promise.resolve(aResponse('mail.example.com', ['198.51.100.1']));
			}
			// DNSBL lookups — all clean (empty responses)
			if (url.includes('spamhaus') || url.includes('spamcop') || url.includes('barracuda')) {
				return Promise.resolve(emptyResponse('1.100.51.198.zen.spamhaus.org', 1));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('mx_reputation');
		expect(result.passed).toBe(true);
		// Should have info findings (valid PTR + clean DNSBL)
		const infoFindings = result.findings.filter((f) => f.severity === 'info');
		expect(infoFindings.length).toBeGreaterThanOrEqual(2);
	});

	it('should return high finding when MX IP is listed on DNSBL', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=MX') || url.includes('type=15')) {
				return Promise.resolve(mxResponse('example.com', [{ priority: 10, exchange: 'mail.example.com' }]));
			}
			if (url.includes('name=mail.example.com') && (url.includes('type=A') || url.includes('type=1'))) {
				return Promise.resolve(aResponse('mail.example.com', ['198.51.100.1']));
			}
			if (url.includes('1.100.51.198.in-addr.arpa') && (url.includes('type=PTR') || url.includes('type=12'))) {
				return Promise.resolve(ptrResponse('198.51.100.1', ['mail.example.com']));
			}
			// DNSBL: listed on Spamhaus
			if (url.includes('spamhaus')) {
				return Promise.resolve(aResponse('1.100.51.198.zen.spamhaus.org', ['127.0.0.2']));
			}
			// Other DNSBLs clean
			if (url.includes('spamcop') || url.includes('barracuda')) {
				return Promise.resolve(emptyResponse('lookup', 1));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('mx_reputation');
		const highFinding = result.findings.find((f) => f.severity === 'high');
		expect(highFinding).toBeDefined();
		expect(highFinding!.title).toContain('listed on');
		expect(highFinding!.title).toContain('spamhaus');
	});

	it('should return medium finding when MX IP has no PTR record', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=MX') || url.includes('type=15')) {
				return Promise.resolve(mxResponse('example.com', [{ priority: 10, exchange: 'mail.example.com' }]));
			}
			if (url.includes('name=mail.example.com') && (url.includes('type=A') || url.includes('type=1'))) {
				return Promise.resolve(aResponse('mail.example.com', ['198.51.100.1']));
			}
			// No PTR record
			if (url.includes('in-addr.arpa') && (url.includes('type=PTR') || url.includes('type=12'))) {
				return Promise.resolve(emptyResponse('1.100.51.198.in-addr.arpa', 12));
			}
			// DNSBL clean
			if (url.includes('spamhaus') || url.includes('spamcop') || url.includes('barracuda')) {
				return Promise.resolve(emptyResponse('lookup', 1));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('mx_reputation');
		const mediumFinding = result.findings.find((f) => f.severity === 'medium');
		expect(mediumFinding).toBeDefined();
		expect(mediumFinding!.title).toContain('No PTR record');
	});

	it('should return info finding when domain has no MX records', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=MX') || url.includes('type=15')) {
				return Promise.resolve(emptyResponse('example.com', 15));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('mx_reputation');
		expect(result.passed).toBe(true);
		const infoFinding = result.findings.find((f) => f.title.includes('No MX records'));
		expect(infoFinding).toBeDefined();
		expect(infoFinding!.severity).toBe('info');
	});

	it('should handle MX DNS query failure gracefully', async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error('DNS failure'));

		const result = await run();
		expect(result.category).toBe('mx_reputation');
		const finding = result.findings.find((f) => f.title === 'MX lookup failed');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
	});

	it('should return medium finding for FCrDNS mismatch', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=MX') || url.includes('type=15')) {
				return Promise.resolve(mxResponse('example.com', [{ priority: 10, exchange: 'mail.example.com' }]));
			}
			// A record for MX host
			if (url.includes('name=mail.example.com') && (url.includes('type=A') || url.includes('type=1'))) {
				return Promise.resolve(aResponse('mail.example.com', ['198.51.100.1']));
			}
			// PTR points to a different hostname
			if (url.includes('in-addr.arpa') && (url.includes('type=PTR') || url.includes('type=12'))) {
				return Promise.resolve(ptrResponse('198.51.100.1', ['other.example.net']));
			}
			// Forward lookup of PTR hostname resolves to a different IP
			if (url.includes('name=other.example.net') && (url.includes('type=A') || url.includes('type=1'))) {
				return Promise.resolve(aResponse('other.example.net', ['198.51.100.99']));
			}
			// DNSBL clean
			if (url.includes('spamhaus') || url.includes('spamcop') || url.includes('barracuda')) {
				return Promise.resolve(emptyResponse('lookup', 1));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('mx_reputation');
		const mismatchFinding = result.findings.find((f) => f.title.includes('PTR does not match'));
		expect(mismatchFinding).toBeDefined();
		expect(mismatchFinding!.severity).toBe('medium');
	});

	it('should handle MX host with no A record', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=MX') || url.includes('type=15')) {
				return Promise.resolve(mxResponse('example.com', [{ priority: 10, exchange: 'mail.example.com' }]));
			}
			// No A record for MX host
			if (url.includes('name=mail.example.com') && (url.includes('type=A') || url.includes('type=1'))) {
				return Promise.resolve(emptyResponse('mail.example.com', 1));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('mx_reputation');
		const finding = result.findings.find((f) => f.title.includes('No A record'));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
	});

	it('should limit checks to first 3 MX hosts', async () => {
		const mxHosts = [
			{ priority: 10, exchange: 'mx1.example.com' },
			{ priority: 20, exchange: 'mx2.example.com' },
			{ priority: 30, exchange: 'mx3.example.com' },
			{ priority: 40, exchange: 'mx4.example.com' },
		];

		const queriedHosts = new Set<string>();

		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=MX') || url.includes('type=15')) {
				return Promise.resolve(mxResponse('example.com', mxHosts));
			}
			// Track which MX hosts are queried for A records
			for (const mx of mxHosts) {
				if (url.includes(`name=${mx.exchange}`) && (url.includes('type=A') || url.includes('type=1'))) {
					queriedHosts.add(mx.exchange);
					return Promise.resolve(aResponse(mx.exchange, ['198.51.100.1']));
				}
			}
			// PTR
			if (url.includes('in-addr.arpa')) {
				return Promise.resolve(ptrResponse('198.51.100.1', ['mail.example.com']));
			}
			// DNSBL clean
			if (url.includes('spamhaus') || url.includes('spamcop') || url.includes('barracuda')) {
				return Promise.resolve(emptyResponse('lookup', 1));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		await run();
		// Should only query A records for first 3 MX hosts
		expect(queriedHosts.has('mx4.example.com')).toBe(false);
		expect(queriedHosts.size).toBeLessThanOrEqual(3);
	});

	it('should skip null MX exchanges', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=MX') || url.includes('type=15')) {
				return Promise.resolve(
					createDohResponse(
						[{ name: 'example.com', type: 15 }],
						[{ name: 'example.com', type: 15, TTL: 300, data: '0 .' }],
					),
				);
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('mx_reputation');
		// Should get the "no valid MX hosts" info finding
		expect(result.findings.length).toBeGreaterThan(0);
		expect(result.passed).toBe(true);
	});
});
