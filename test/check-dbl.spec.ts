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

	it('should decode URIBL bitmask (127.0.0.2 = Black)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('dbl.spamhaus.org')) {
				return Promise.resolve(emptyResponse('example.com.dbl.spamhaus.org'));
			}
			// URIBL: listed as Black (bitmask 0x02 → 127.0.0.2)
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
		expect(mediumFinding!.detail).toContain('Black');
	});

	it('should decode SURBL bitmask (127.0.0.8 = PH Phishing)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('dbl.spamhaus.org')) {
				return Promise.resolve(emptyResponse('example.com.dbl.spamhaus.org'));
			}
			if (url.includes('multi.uribl.com')) {
				return Promise.resolve(emptyResponse('example.com.multi.uribl.com'));
			}
			// SURBL: listed as Phishing (bitmask 0x08 → 127.0.0.8)
			if (url.includes('multi.surbl.org')) {
				return Promise.resolve(aResponse('example.com.multi.surbl.org', ['127.0.0.8']));
			}
			return Promise.resolve(emptyResponse('example.com'));
		});

		const result = await run();
		expect(result.category).toBe('dbl');
		const mediumFinding = result.findings.find((f) => f.severity === 'medium');
		expect(mediumFinding).toBeDefined();
		expect(mediumFinding!.title).toMatch(/SURBL/i);
		expect(mediumFinding!.detail).toContain('PH (Phishing)');
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

	it('abstains when every blocklist zone errors instead of claiming the domain is not listed', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('dbl.spamhaus.org') || url.includes('multi.uribl.com') || url.includes('multi.surbl.org')) {
				return Promise.reject(new Error('DNS timeout'));
			}
			return Promise.resolve(emptyResponse('example.com'));
		});

		const result = await run();
		expect(result.category).toBe('dbl');
		// #900: zero zones answered, so the old tail still asserted "Domain not listed on any
		// blocklist" with zonesChecked: 0 — a non-answer that scored 85, `passed: true`, and was
		// cached for the tool's full 3600 s TTL.
		expect(result).toMatchObject({ score: 0, passed: false, checkStatus: 'error', partial: true });
		expect(result.findings.map((f) => f.metadata?.errorKind)).toEqual(['dns_error']);
		expect(result.findings.some((f) => /not listed/i.test(f.title))).toBe(false);
	});

	it('bounds the no-listings claim when only some blocklist zones answered', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('multi.surbl.org')) {
				return Promise.reject(new Error('DNS timeout'));
			}
			if (url.includes('dbl.spamhaus.org')) {
				return Promise.resolve(emptyResponse('example.com.dbl.spamhaus.org'));
			}
			if (url.includes('multi.uribl.com')) {
				return Promise.resolve(emptyResponse('example.com.multi.uribl.com'));
			}
			return Promise.resolve(emptyResponse('example.com'));
		});

		const result = await run();
		expect(result.category).toBe('dbl');
		// Two zones answered and one errored: a real measurement, but not an unqualified clean.
		expect(result.findings.some((f) => f.title === 'Domain not listed on any blocklist')).toBe(false);
		const bounded = result.findings.find((f) => f.title === 'No listings on the zones that answered');
		expect(bounded).toBeDefined();
		expect(bounded!.metadata).toMatchObject({ zonesChecked: 2, unansweredZones: 1, quotaLimited: 0 });
	});

	it('excludes a quota-stubbed zone from the count the no-listings claim cites', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			// 127.255.255.x is a Spamhaus quota/rate-limit stub, not a verdict.
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
		const quotaFinding = result.findings.find((f) => f.metadata?.quotaError === true);
		expect(quotaFinding).toBeDefined();
		// Three zones answered, only two gave a usable verdict — the claim must not cite three.
		expect(result.findings.some((f) => f.title === 'Domain not listed on any blocklist')).toBe(false);
		const bounded = result.findings.find((f) => f.title === 'No listings on the zones that answered');
		expect(bounded).toBeDefined();
		expect(bounded!.metadata).toMatchObject({ zonesChecked: 2, unansweredZones: 0, quotaLimited: 1 });
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
