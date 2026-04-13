// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

/** Build a DoH A-record response for a domain with given IPs and TTL. */
function aResponse(domain: string, ips: string[], ttl = 300) {
	return createDohResponse(
		[{ name: domain, type: 1 }],
		ips.map((ip) => ({ name: domain, type: 1, TTL: ttl, data: ip })),
	);
}

/** Build a DoH AAAA-record response for a domain with given IPs and TTL. */
function aaaaResponse(domain: string, ips: string[], ttl = 300) {
	return createDohResponse(
		[{ name: domain, type: 28 }],
		ips.map((ip) => ({ name: domain, type: 28, TTL: ttl, data: ip })),
	);
}

/** Build an empty DoH response (no answers). */
function emptyResponse(domain: string, type = 1) {
	return createDohResponse([{ name: domain, type }], []);
}

/** Extract the primary (non-limitation) finding from results. */
function primaryFinding(findings: Array<{ title: string; metadata?: Record<string, unknown> }>) {
	return findings.find((f) => !f.title.includes('limitations'));
}

describe('checkFastFlux', () => {
	async function run(domain = 'example.com', rounds = 3) {
		const { checkFastFlux } = await import('../src/tools/check-fast-flux');
		return checkFastFlux(domain, rounds, undefined, 0);
	}

	it('should report info for stable domain (same IPs every round, high TTL)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=AAAA')) {
				return Promise.resolve(aaaaResponse('example.com', ['2606:2800:220:1:248:1893:25c8:1946'], 3600));
			}
			if (url.includes('type=A')) {
				return Promise.resolve(aResponse('example.com', ['93.184.216.34'], 3600));
			}
			return Promise.resolve(emptyResponse('example.com'));
		});

		const result = await run();
		expect(result.category).toBe('fast_flux');
		expect(result.passed).toBe(true);
		const infoFinding = result.findings.find((f) => f.severity === 'info' && f.title.includes('Stable'));
		expect(infoFinding).toBeDefined();
		expect(infoFinding!.title).toMatch(/stable/i);
		// Check finding metadata for flux_detected
		const primary = primaryFinding(result.findings);
		expect(primary?.metadata?.flux_detected).toBe(false);
	});

	it('should report high finding for rotating IPs with low TTL', async () => {
		let aCallCount = 0;
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=AAAA')) {
				return Promise.resolve(emptyResponse('flux.example.com', 28));
			}
			if (url.includes('type=A')) {
				aCallCount++;
				// Each round returns different IPs
				const roundIps = [
					['1.2.3.4', '5.6.7.8'],
					['9.10.11.12', '13.14.15.16'],
					['17.18.19.20', '21.22.23.24'],
				];
				const idx = Math.min(aCallCount - 1, roundIps.length - 1);
				return Promise.resolve(aResponse('flux.example.com', roundIps[idx], 60));
			}
			return Promise.resolve(emptyResponse('flux.example.com'));
		});

		const result = await run('flux.example.com');
		expect(result.category).toBe('fast_flux');
		const highFinding = result.findings.find((f) => f.severity === 'high');
		expect(highFinding).toBeDefined();
		expect(highFinding!.title).toMatch(/fast.flux/i);
		expect(highFinding!.metadata?.flux_detected).toBe(true);
	});

	it('should NOT flag low TTL with stable IPs (TTL alone is not flux)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=AAAA')) {
				return Promise.resolve(emptyResponse('example.com', 28));
			}
			if (url.includes('type=A')) {
				return Promise.resolve(aResponse('example.com', ['1.2.3.4'], 30));
			}
			return Promise.resolve(emptyResponse('example.com'));
		});

		const result = await run();
		const primary = primaryFinding(result.findings);
		expect(primary?.metadata?.flux_detected).toBe(false);
		expect(result.findings.find((f) => f.severity === 'high')).toBeUndefined();
	});

	it('should NOT flag changing IPs with high TTL (CDN behavior)', async () => {
		let aCallCount = 0;
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=AAAA')) {
				return Promise.resolve(emptyResponse('cdn.example.com', 28));
			}
			if (url.includes('type=A')) {
				aCallCount++;
				const roundIps = [
					['1.2.3.4'],
					['5.6.7.8'],
					['9.10.11.12'],
				];
				const idx = Math.min(aCallCount - 1, roundIps.length - 1);
				return Promise.resolve(aResponse('cdn.example.com', roundIps[idx], 3600));
			}
			return Promise.resolve(emptyResponse('cdn.example.com'));
		});

		const result = await run('cdn.example.com');
		const primary = primaryFinding(result.findings);
		expect(primary?.metadata?.flux_detected).toBe(false);
		expect(result.findings.find((f) => f.severity === 'high')).toBeUndefined();
	});

	it('should handle DNS errors gracefully', async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error('DNS timeout'));

		const result = await run('error.example.com');
		expect(result.category).toBe('fast_flux');
		// Should have findings but not crash
		expect(result.findings.length).toBeGreaterThan(0);
	});

	it('should respect the rounds parameter (verify correct number of query rounds)', async () => {
		let aQueryCount = 0;
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=AAAA')) {
				return Promise.resolve(emptyResponse('example.com', 28));
			}
			if (url.includes('type=A')) {
				aQueryCount++;
				return Promise.resolve(aResponse('example.com', ['1.2.3.4'], 300));
			}
			return Promise.resolve(emptyResponse('example.com'));
		});

		await run('example.com', 5);
		// 5 rounds, each round queries A once (AAAA checked first to avoid substring match)
		expect(aQueryCount).toBe(5);
	});

	it('should include AAAA records in detection (IPv6 IPs tracked)', async () => {
		let aaaaCallCount = 0;
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=AAAA')) {
				aaaaCallCount++;
				// Rotating AAAA records
				const roundIps = [
					['2001:db8::1'],
					['2001:db8::2'],
					['2001:db8::3'],
				];
				const idx = Math.min(aaaaCallCount - 1, roundIps.length - 1);
				return Promise.resolve(aaaaResponse('v6flux.example.com', roundIps[idx], 60));
			}
			if (url.includes('type=A')) {
				// Same A records every round
				return Promise.resolve(aResponse('v6flux.example.com', ['1.2.3.4'], 60));
			}
			return Promise.resolve(emptyResponse('v6flux.example.com'));
		});

		const result = await run('v6flux.example.com');
		const highFinding = result.findings.find((f) => f.severity === 'high');
		expect(highFinding).toBeDefined();
		expect(highFinding!.metadata?.flux_detected).toBe(true);
		// Verify IPv6 IPs are included in the unique IP set
		expect((highFinding!.metadata?.unique_ips as number)).toBeGreaterThan(1);
	});
});
