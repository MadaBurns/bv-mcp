// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse, dnssecResponse, tlsaResponse } from './helpers/dns-mock';
import { DOH_TRANSPORT_FAILURES, expectDnsAbstention } from './helpers/dns-transport-failure';

const { restore } = setupFetchMock();

afterEach(() => restore());

/** Build an empty DoH response (no answers). */
function emptyResponse(name: string, type: number) {
	return createDohResponse([{ name, type }], []);
}

describe('checkDaneHttps', () => {
	async function run(domain = 'example.com') {
		const { checkDaneHttps } = await import('../src/tools/check-dane-https');
		return checkDaneHttps(domain);
	}

	it('should return an unverified-pin finding when HTTPS TLSA is present with DNSSEC', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			// DNSSEC check: A record with AD=true
			if ((url.includes('type=A') || url.includes('type=1')) && !url.includes('_tcp')) {
				return Promise.resolve(dnssecResponse('example.com', true));
			}
			// TLSA for HTTPS
			if (url.includes('_443._tcp.example.com') && (url.includes('type=TLSA') || url.includes('type=52'))) {
				return Promise.resolve(
					tlsaResponse('_443._tcp.example.com', [
						{ usage: 3, selector: 1, matchingType: 1, certData: 'aabbccddee' },
					]),
				);
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('dane_https');
		expect(result.passed).toBe(true);
		const unverified = result.findings.find((f) => f.title.includes('DANE TLSA configured'));
		expect(unverified).toBeDefined();
		expect(unverified?.severity).toBe('low');
		expect(result.score).toBe(95);
	});

	it('should return high finding when TLSA present but no DNSSEC', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			// DNSSEC: AD=false
			if ((url.includes('type=A') || url.includes('type=1')) && !url.includes('_tcp')) {
				return Promise.resolve(dnssecResponse('example.com', false));
			}
			// TLSA for HTTPS with DANE-EE usage (requires DNSSEC)
			if (url.includes('_443._tcp.example.com') && (url.includes('type=TLSA') || url.includes('type=52'))) {
				return Promise.resolve(
					tlsaResponse('_443._tcp.example.com', [
						{ usage: 3, selector: 1, matchingType: 1, certData: 'aabbccddee' },
					]),
				);
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('dane_https');
		const highFinding = result.findings.find((f) => f.severity === 'high');
		expect(highFinding).toBeDefined();
		expect(highFinding!.title).toBe('DANE without DNSSEC');
	});

	it('should return low finding when no HTTPS TLSA record found', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			// DNSSEC check
			if ((url.includes('type=A') || url.includes('type=1')) && !url.includes('_tcp')) {
				return Promise.resolve(dnssecResponse('example.com', true));
			}
			// No TLSA for HTTPS
			if (url.includes('_443._tcp') && (url.includes('type=TLSA') || url.includes('type=52'))) {
				return Promise.resolve(emptyResponse('_443._tcp.example.com', 52));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('dane_https');
		const lowFinding = result.findings.find((f) => f.severity === 'low');
		expect(lowFinding).toBeDefined();
		expect(lowFinding!.title).toContain('No DANE TLSA for HTTPS');
	});

	it('should flag malformed TLSA record', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if ((url.includes('type=A') || url.includes('type=1')) && !url.includes('_tcp')) {
				return Promise.resolve(dnssecResponse('example.com', true));
			}
			// Malformed TLSA data
			if (url.includes('_443._tcp.example.com') && (url.includes('type=TLSA') || url.includes('type=52'))) {
				return Promise.resolve(
					createDohResponse(
						[{ name: '_443._tcp.example.com', type: 52 }],
						[{ name: '_443._tcp.example.com', type: 52, TTL: 300, data: 'invalid-tlsa-data' }],
					),
				);
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('dane_https');
		const mediumFinding = result.findings.find((f) => f.severity === 'medium');
		expect(mediumFinding).toBeDefined();
		expect(mediumFinding!.title).toBe('Malformed TLSA record');
	});

	// SQ-201: a TLSA lookup that never got an answer used to return a COMPLETED `low`
	// "DANE HTTPS query failed" finding scored 95 — measured evidence from a cut probe.
	it.each(DOH_TRANSPORT_FAILURES)('abstains (checkStatus error, no scored finding) when $label', async ({ install }) => {
		install();

		const result = await run();
		expectDnsAbstention(result, 'dane_https');
		expect(result.findings.map((f) => f.title)).toEqual(['DANE HTTPS not assessed — TLSA query failed']);
	});

	it('an answered NXDOMAIN for _443._tcp is still a measured absence, not an abstention', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('_443._tcp.example.com') && (url.includes('type=TLSA') || url.includes('type=52'))) {
				return Promise.resolve(createDohResponse([{ name: '_443._tcp.example.com', type: 52 }], [], { status: 3 }));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.checkStatus).toBeUndefined();
		expect(result.recordPresent).toBe(false);
		expect(result.findings.map((f) => f.title)).toEqual(['No DANE TLSA for HTTPS']);
		expect(result.score).toBe(95);
	});

	// SQ-207: the DNSSEC (AD) lookup is a separate probe from the TLSA lookup. When ONLY the AD
	// lookup is cut, "DNSSEC unknown" must not be scored as "unsigned" ("DANE without DNSSEC",
	// high) — the TLSA facet still reports from its answer and the DNSSEC facet abstains.
	describe('DNSSEC (AD) lookup transport failure with a TLSA answer (SQ-207)', () => {
		function cutAdLookupOnly(fail: () => Promise<Response>, usage: number) {
			globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
				const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
				if ((url.includes('type=A') || url.includes('type=1')) && !url.includes('_tcp')) return fail();
				if (url.includes('_443._tcp.example.com') && (url.includes('type=TLSA') || url.includes('type=52'))) {
					return Promise.resolve(
						tlsaResponse('_443._tcp.example.com', [{ usage, selector: 1, matchingType: 1, certData: 'aabbccddee' }]),
					);
				}
				return Promise.resolve(emptyResponse('example.com', 1));
			});
		}

		it.each(DOH_TRANSPORT_FAILURES)('does not score "DANE without DNSSEC" when $label for the AD lookup only', async ({ fail }) => {
			cutAdLookupOnly(fail, 3);

			const result = await run();
			expect(result.category).toBe('dane_https');
			// The cut probe is not an unsigned verdict: no high finding, no missingControl.
			expect(result.findings.some((f) => f.title === 'DANE without DNSSEC')).toBe(false);
			expect(result.findings.some((f) => f.severity === 'high')).toBe(false);
			for (const finding of result.findings) expect(finding.metadata?.missingControl, finding.title).not.toBe(true);
			// The DNSSEC facet abstains with an info dns_error finding...
			const facet = result.findings.find((f) => f.title === 'DNSSEC status not determined');
			expect(facet).toBeDefined();
			expect(facet?.severity).toBe('info');
			expect(facet?.metadata?.errorKind).toBe('dns_error');
			// ...while the TLSA facet is still reported from its successful answer.
			expect(result.recordPresent).toBe(true);
			expect(result.findings.some((f) => f.title.includes('DANE TLSA configured'))).toBe(true);
			expect(result.checkStatus).toBeUndefined();
			expect(result.score).toBe(95);
			// A half-measured result is not cached.
			expect(result.partial).toBe(true);
		});

		it('keeps an answered AD=false as a measured "DANE without DNSSEC" (high)', async () => {
			globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
				const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
				if ((url.includes('type=A') || url.includes('type=1')) && !url.includes('_tcp')) {
					return Promise.resolve(dnssecResponse('example.com', false));
				}
				if (url.includes('_443._tcp.example.com') && (url.includes('type=TLSA') || url.includes('type=52'))) {
					return Promise.resolve(
						tlsaResponse('_443._tcp.example.com', [{ usage: 3, selector: 1, matchingType: 1, certData: 'aabbccddee' }]),
					);
				}
				return Promise.resolve(emptyResponse('example.com', 1));
			});

			const result = await run();
			expect(result.findings.find((f) => f.severity === 'high')?.title).toBe('DANE without DNSSEC');
			expect(result.findings.some((f) => f.title === 'DNSSEC status not determined')).toBe(false);
			expect(result.partial).toBeUndefined();
		});
	});

	it('should handle DNSSEC check failure gracefully', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			// DNSSEC check fails
			if ((url.includes('type=A') || url.includes('type=1')) && !url.includes('_tcp')) {
				return Promise.reject(new Error('DNSSEC query failed'));
			}
			// TLSA present
			if (url.includes('_443._tcp.example.com') && (url.includes('type=TLSA') || url.includes('type=52'))) {
				return Promise.resolve(
					tlsaResponse('_443._tcp.example.com', [
						{ usage: 1, selector: 1, matchingType: 1, certData: 'aabbccddee' },
					]),
				);
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('dane_https');
		// Should still return some findings even if DNSSEC check failed
		expect(result.findings.length).toBeGreaterThan(0);
	});

	it('should not query MX records (HTTPS-only check)', async () => {
		const fetchMock = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if ((url.includes('type=A') || url.includes('type=1')) && !url.includes('_tcp')) {
				return Promise.resolve(dnssecResponse('example.com', true));
			}
			if (url.includes('_443._tcp') && (url.includes('type=TLSA') || url.includes('type=52'))) {
				return Promise.resolve(emptyResponse('_443._tcp.example.com', 52));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});
		globalThis.fetch = fetchMock;

		await run();

		// Verify no MX queries were made
		const calls = fetchMock.mock.calls.map((c) => {
			const input = c[0];
			return typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		});
		const mxQuery = calls.find((url: string) => url.includes('type=MX') || url.includes('type=15'));
		expect(mxQuery).toBeUndefined();
	});

	it('should return all findings with dane_https category', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if ((url.includes('type=A') || url.includes('type=1')) && !url.includes('_tcp')) {
				return Promise.resolve(dnssecResponse('example.com', true));
			}
			if (url.includes('_443._tcp.example.com') && (url.includes('type=TLSA') || url.includes('type=52'))) {
				return Promise.resolve(
					tlsaResponse('_443._tcp.example.com', [
						{ usage: 3, selector: 1, matchingType: 1, certData: 'aabbccddee' },
					]),
				);
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('dane_https');
		for (const finding of result.findings) {
			expect(finding.category).toBe('dane_https');
		}
	});
});
