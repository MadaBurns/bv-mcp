// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

/** Build a DoH A-record response for a given query name. */
function aResponse(name: string, ips: string[]) {
	return createDohResponse(
		[{ name, type: 1 }],
		ips.map((ip) => ({ name, type: 1, TTL: 300, data: ip })),
	);
}

/** Build an empty DoH response (NXDOMAIN / no answers). */
function emptyResponse(name: string) {
	return createDohResponse([{ name, type: 1 }], []);
}

describe('checkDbl', () => {
	async function run(domain = 'example.com') {
		const { checkDbl } = await import('../src/tools/check-dbl');
		return checkDbl(domain);
	}

	it('should report high finding when listed on Spamhaus DBL', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			// Spamhaus DBL: listed as spam domain (127.0.1.2)
			if (url.includes('dbl.spamhaus.org')) {
				return Promise.resolve(aResponse('example.com.dbl.spamhaus.org', ['127.0.1.2']));
			}
			// URIBL and SURBL: clean
			if (url.includes('multi.uribl.com')) {
				return Promise.resolve(emptyResponse('example.com.multi.uribl.com'));
			}
			if (url.includes('multi.surbl.org')) {
				return Promise.resolve(emptyResponse('example.com.multi.surbl.org'));
			}
			return Promise.resolve(emptyResponse('example.com'));
		});

		const result = await run();
		expect(result.category).toBe('dbl');
		const highFinding = result.findings.find((f) => f.severity === 'high');
		expect(highFinding).toBeDefined();
		expect(highFinding!.title).toMatch(/Spamhaus DBL/i);
		expect(highFinding!.detail).toContain('Spam');
	});

	it('should decode URIBL bitmask (127.0.0.2 = Grey)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('dbl.spamhaus.org')) {
				return Promise.resolve(emptyResponse('example.com.dbl.spamhaus.org'));
			}
			// URIBL: listed as Grey (bitmask 0x02 → 127.0.0.2)
			if (url.includes('multi.uribl.com')) {
				return Promise.resolve(aResponse('example.com.multi.uribl.com', ['127.0.0.2']));
			}
			if (url.includes('multi.surbl.org')) {
				return Promise.resolve(emptyResponse('example.com.multi.surbl.org'));
			}
			return Promise.resolve(emptyResponse('example.com'));
		});

		const result = await run();
		expect(result.category).toBe('dbl');
		const mediumFinding = result.findings.find((f) => f.severity === 'medium');
		expect(mediumFinding).toBeDefined();
		expect(mediumFinding!.title).toMatch(/URIBL/i);
		expect(mediumFinding!.detail).toContain('Grey');
	});

	it('should decode SURBL bitmask (127.0.0.16 = Phishing)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('dbl.spamhaus.org')) {
				return Promise.resolve(emptyResponse('example.com.dbl.spamhaus.org'));
			}
			if (url.includes('multi.uribl.com')) {
				return Promise.resolve(emptyResponse('example.com.multi.uribl.com'));
			}
			// SURBL: listed as Phishing (bitmask 0x10 → 127.0.0.16)
			if (url.includes('multi.surbl.org')) {
				return Promise.resolve(aResponse('example.com.multi.surbl.org', ['127.0.0.16']));
			}
			return Promise.resolve(emptyResponse('example.com'));
		});

		const result = await run();
		expect(result.category).toBe('dbl');
		const mediumFinding = result.findings.find((f) => f.severity === 'medium');
		expect(mediumFinding).toBeDefined();
		expect(mediumFinding!.title).toMatch(/SURBL/i);
		expect(mediumFinding!.detail).toContain('Phishing');
	});

	it('should report info finding when clean on all zones (NXDOMAIN)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('dbl.spamhaus.org')) {
				return Promise.resolve(emptyResponse('example.com.dbl.spamhaus.org'));
			}
			if (url.includes('multi.uribl.com')) {
				return Promise.resolve(emptyResponse('example.com.multi.uribl.com'));
			}
			if (url.includes('multi.surbl.org')) {
				return Promise.resolve(emptyResponse('example.com.multi.surbl.org'));
			}
			return Promise.resolve(emptyResponse('example.com'));
		});

		const result = await run();
		expect(result.category).toBe('dbl');
		expect(result.passed).toBe(true);
		const infoFinding = result.findings.find((f) => f.severity === 'info');
		expect(infoFinding).toBeDefined();
		expect(infoFinding!.title).toMatch(/not listed/i);
	});

	it('should treat Spamhaus 127.255.255.x as quota error, not a listing', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			// Spamhaus returns quota/error response
			if (url.includes('dbl.spamhaus.org')) {
				return Promise.resolve(aResponse('example.com.dbl.spamhaus.org', ['127.255.255.254']));
			}
			if (url.includes('multi.uribl.com')) {
				return Promise.resolve(emptyResponse('example.com.multi.uribl.com'));
			}
			if (url.includes('multi.surbl.org')) {
				return Promise.resolve(emptyResponse('example.com.multi.surbl.org'));
			}
			return Promise.resolve(emptyResponse('example.com'));
		});

		const result = await run();
		expect(result.category).toBe('dbl');
		// Should NOT have a high finding — quota error is not a listing
		const highFinding = result.findings.find((f) => f.severity === 'high');
		expect(highFinding).toBeUndefined();
		// Should have a low/info finding about the quota error
		const quotaFinding = result.findings.find((f) => f.detail.includes('quota') || f.detail.includes('rate'));
		expect(quotaFinding).toBeDefined();
	});

	it('should return partial results when one zone has DNS error', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			// Spamhaus: DNS error
			if (url.includes('dbl.spamhaus.org')) {
				return Promise.reject(new Error('DNS timeout'));
			}
			// URIBL: listed
			if (url.includes('multi.uribl.com')) {
				return Promise.resolve(aResponse('example.com.multi.uribl.com', ['127.0.0.2']));
			}
			// SURBL: clean
			if (url.includes('multi.surbl.org')) {
				return Promise.resolve(emptyResponse('example.com.multi.surbl.org'));
			}
			return Promise.resolve(emptyResponse('example.com'));
		});

		const result = await run();
		expect(result.category).toBe('dbl');
		// Should have findings from URIBL (medium) even though Spamhaus failed
		const mediumFinding = result.findings.find((f) => f.severity === 'medium');
		expect(mediumFinding).toBeDefined();
		expect(mediumFinding!.title).toMatch(/URIBL/i);
		// Should also have an error finding for the failed zone
		const errorFinding = result.findings.find((f) => f.title.includes('Spamhaus') && f.detail.includes('error'));
		expect(errorFinding).toBeDefined();
	});

	it('should use domain as-is without stripping subdomains', async () => {
		const queriedNames = new Set<string>();

		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			queriedNames.add(url);

			if (url.includes('dbl.spamhaus.org')) {
				return Promise.resolve(emptyResponse('sub.example.com.dbl.spamhaus.org'));
			}
			if (url.includes('multi.uribl.com')) {
				return Promise.resolve(emptyResponse('sub.example.com.multi.uribl.com'));
			}
			if (url.includes('multi.surbl.org')) {
				return Promise.resolve(emptyResponse('sub.example.com.multi.surbl.org'));
			}
			return Promise.resolve(emptyResponse('sub.example.com'));
		});

		const result = await run('sub.example.com');
		expect(result.category).toBe('dbl');

		// Verify the full subdomain was queried, not just example.com
		const urls = Array.from(queriedNames);
		const dblQueries = urls.filter((u) => u.includes('dbl.spamhaus.org'));
		expect(dblQueries.length).toBeGreaterThan(0);
		expect(dblQueries[0]).toContain('sub.example.com.dbl.spamhaus.org');
	});
});
