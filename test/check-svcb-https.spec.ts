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

	// RFC 3597 wire-format fixture: real Cloudflare DoH response for blackveilsecurity.com.
	// Decodes to: priority=1, target=., alpn=["h3","h2"], ipv4hint=[104.18.8.92, 104.18.9.92], ipv6hint=[2 IPv6 addrs]
	// Cloudflare DoH returns HTTPS records in this format (RFC 3597 §5) instead of presentation form.
	const cloudflareWireFormatH2H3 =
		'\\# 61 00 01 00 00 01 00 06 02 68 33 02 68 32 00 04 00 08 68 12 08 5c 68 12 09 5c 00 06 00 20 26 06 47 00 00 00 00 00 00 00 00 00 68 12 08 5c 26 06 47 00 00 00 00 00 00 00 00 00 68 12 09 5c';

	it('parses ALPN from RFC 3597 wire-format DoH response (Cloudflare)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('type=HTTPS') || url.includes('type=65')) {
				return Promise.resolve(httpsRecordResponse('example.com', [cloudflareWireFormatH2H3]));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		const titles = result.findings.map((f) => f.title);
		expect(titles).toContain('HTTP/3 (QUIC) advertised via HTTPS record');
		expect(titles).not.toContain('HTTPS record missing ALPN parameter');
		expect(titles).not.toContain('HTTPS record does not advertise HTTP/2');
	});

	it('parses ALPN from wire-format record with multi-label TargetName', async () => {
		// priority=1, target="www.example.com.", alpn=["h2"]
		// 00 01 | 03 "www" 07 "example" 03 "com" 00 | 00 01 00 03 02 "h2"  → 26 bytes
		const wire =
			'\\# 26 00 01 03 77 77 77 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 03 02 68 32';

		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('type=HTTPS') || url.includes('type=65')) {
				return Promise.resolve(httpsRecordResponse('example.com', [wire]));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		const titles = result.findings.map((f) => f.title);
		expect(titles).toContain('HTTPS record configured');
		expect(titles).not.toContain('HTTPS record missing ALPN parameter');
		const configured = result.findings.find((f) => f.title === 'HTTPS record configured');
		expect(configured?.metadata).toMatchObject({ alpn: ['h2'], priority: 1 });
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
