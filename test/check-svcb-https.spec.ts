// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

/** Build an empty DoH response (no answers). */
function emptyResponse(name: string, type: number) {
	return createDohResponse([{ name, type }], []);
}

/** Build a DoH response containing HTTPS records. */
function httpsRecordResponse(domain: string, records: string[]) {
	return createDohResponse(
		[{ name: domain, type: 65 }],
		records.map((data) => ({ name: domain, type: 65, TTL: 300, data })),
	);
}

describe('checkSvcbHttps', () => {
	async function run(domain = 'example.com') {
		const { checkSvcbHttps } = await import('../src/tools/check-svcb-https');
		return checkSvcbHttps(domain);
	}

	it('should return low finding when no HTTPS records found', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('type=HTTPS') || url.includes('type=65')) {
				return Promise.resolve(emptyResponse('example.com', 65));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('svcb_https');
		expect(result.passed).toBe(false); // missingControl: true forces passed=false
		expect(result.score).toBe(0);
		const lowFinding = result.findings.find((f) => f.severity === 'low');
		expect(lowFinding).toBeDefined();
		expect(lowFinding!.title).toBe('No HTTPS record found');
	});

	it('should return info finding for HTTPS record with h2 and h3 ALPN', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('type=HTTPS') || url.includes('type=65')) {
				return Promise.resolve(
					httpsRecordResponse('example.com', ['1 . alpn="h2,h3"']),
				);
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('svcb_https');
		const infoFindings = result.findings.filter((f) => f.severity === 'info');
		expect(infoFindings.length).toBeGreaterThanOrEqual(1);
		const configuredFinding = infoFindings.find((f) => f.title === 'HTTPS record configured');
		expect(configuredFinding).toBeDefined();
	});

	it('should return info finding for HTTP/3 when h3 ALPN present', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('type=HTTPS') || url.includes('type=65')) {
				return Promise.resolve(
					httpsRecordResponse('example.com', ['1 . alpn="h2,h3"']),
				);
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('svcb_https');
		const h3Finding = result.findings.find((f) => f.title === 'HTTP/3 (QUIC) advertised via HTTPS record');
		expect(h3Finding).toBeDefined();
		expect(h3Finding!.severity).toBe('info');
	});

	it('should return info finding when ECH is present', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('type=HTTPS') || url.includes('type=65')) {
				return Promise.resolve(
					httpsRecordResponse('example.com', ['1 . alpn="h2,h3" ech=AEX...']),
				);
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('svcb_https');
		const echFinding = result.findings.find((f) => f.title === 'Encrypted Client Hello (ECH) advertised');
		expect(echFinding).toBeDefined();
		expect(echFinding!.severity).toBe('info');
	});

	it('should return info finding for alias mode record (priority 0)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('type=HTTPS') || url.includes('type=65')) {
				return Promise.resolve(
					httpsRecordResponse('example.com', ['0 example.com.']),
				);
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('svcb_https');
		const aliasFinding = result.findings.find((f) => f.title === 'HTTPS record in alias mode');
		expect(aliasFinding).toBeDefined();
		expect(aliasFinding!.severity).toBe('info');
	});

	it('should flag missing ALPN in service mode record', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('type=HTTPS') || url.includes('type=65')) {
				return Promise.resolve(
					httpsRecordResponse('example.com', ['1 .']),
				);
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('svcb_https');
		const missingAlpn = result.findings.find((f) => f.title === 'HTTPS record missing ALPN parameter');
		expect(missingAlpn).toBeDefined();
		expect(missingAlpn!.severity).toBe('low');
	});

	it('should flag missing HTTP/2 when record only has h3', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('type=HTTPS') || url.includes('type=65')) {
				return Promise.resolve(
					httpsRecordResponse('example.com', ['1 . alpn="h3"']),
				);
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('svcb_https');
		const noH2Finding = result.findings.find((f) => f.title === 'HTTPS record does not advertise HTTP/2');
		expect(noH2Finding).toBeDefined();
		expect(noH2Finding!.severity).toBe('low');
	});

	it('should handle DNS query failure gracefully', async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error('DNS failure'));

		const result = await run();
		expect(result.category).toBe('svcb_https');
		expect(result.findings.length).toBeGreaterThan(0);
		const failFinding = result.findings.find((f) => f.title === 'HTTPS record query failed');
		expect(failFinding).toBeDefined();
	});

	it('should return all findings with svcb_https category', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('type=HTTPS') || url.includes('type=65')) {
				return Promise.resolve(
					httpsRecordResponse('example.com', ['1 . alpn="h2,h3"']),
				);
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('svcb_https');
		for (const finding of result.findings) {
			expect(finding.category).toBe('svcb_https');
		}
	});
});
