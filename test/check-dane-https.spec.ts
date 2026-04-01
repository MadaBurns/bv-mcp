// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse, dnssecResponse, tlsaResponse } from './helpers/dns-mock';

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

	it('should return info finding when HTTPS TLSA record is present with DNSSEC', async () => {
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
		const infoFindings = result.findings.filter((f) => f.severity === 'info');
		expect(infoFindings.length).toBeGreaterThanOrEqual(1);
		expect(infoFindings[0].title).toContain('DANE TLSA configured');
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

	it('should handle DNS query failure gracefully', async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error('DNS failure'));

		const result = await run();
		expect(result.category).toBe('dane_https');
		expect(result.findings.length).toBeGreaterThan(0);
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
