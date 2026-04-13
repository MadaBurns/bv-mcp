// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach, vi } from 'vitest';

afterEach(() => {
	vi.restoreAllMocks();
});

/** Build a minimal IANA RDAP bootstrap JSON response. */
function makeBootstrap(services: [string[], string[]][] = [[['com'], ['https://rdap.verisign.com/com/v1/']]]) {
	return {
		version: '1.0',
		publication: '2024-01-01T00:00:00Z',
		services,
	};
}

/** Build a minimal RDAP domain response. */
function makeRdapResponse(overrides: Record<string, unknown> = {}) {
	return {
		objectClassName: 'domain',
		ldhName: 'example.com',
		handle: 'D12345-COM',
		status: ['clientTransferProhibited', 'serverDeleteProhibited'],
		events: [
			{ eventAction: 'registration', eventDate: '2020-01-15T00:00:00Z' },
			{ eventAction: 'expiration', eventDate: '2027-06-15T00:00:00Z' },
			{ eventAction: 'last changed', eventDate: '2024-03-01T12:00:00Z' },
		],
		entities: [
			{
				objectClassName: 'entity',
				roles: ['registrar'],
				vcardArray: ['vcard', [
					['version', {}, 'text', '4.0'],
					['fn', {}, 'text', 'Example Registrar Inc.'],
				]],
			},
			{
				objectClassName: 'entity',
				roles: ['registrant'],
				vcardArray: ['vcard', [
					['version', {}, 'text', '4.0'],
					['fn', {}, 'text', 'ACME Corporation'],
					['adr', {}, 'text', ['', '', '123 Main St', 'Springfield', 'IL', '62704', 'US']],
				]],
			},
		],
		...overrides,
	};
}

/** Route fetch calls by URL pattern. */
function mockFetchRouter(routes: Record<string, () => unknown>) {
	return vi.fn().mockImplementation((input: string | URL | Request, _init?: RequestInit) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		for (const [pattern, handler] of Object.entries(routes)) {
			if (url.includes(pattern)) {
				return Promise.resolve(new Response(JSON.stringify(handler()), {
					status: 200,
					headers: { 'Content-Type': 'application/rdap+json' },
				}));
			}
		}
		return Promise.resolve(new Response('Not Found', { status: 404 }));
	});
}

describe('checkRdapLookup', () => {
	async function run(domain = 'example.com') {
		const mod = await import('../src/tools/check-rdap-lookup');
		mod._resetBootstrapCache();
		return mod.checkRdapLookup(domain);
	}

	it('should parse registrar and creation date from standard .com domain', async () => {
		globalThis.fetch = mockFetchRouter({
			'data.iana.org/rdap/dns.json': () => makeBootstrap(),
			'rdap.verisign.com': () => makeRdapResponse(),
		});

		const result = await run();
		expect(result.category).toBe('rdap');
		expect(result.findings.length).toBeGreaterThanOrEqual(1);

		const infoFinding = result.findings.find((f) => f.severity === 'info' && f.title.toLowerCase().includes('registration'));
		expect(infoFinding).toBeDefined();
		expect(infoFinding!.detail).toContain('Example Registrar Inc.');
		expect(infoFinding!.detail).toContain('2020-01-15');
	});

	it('should handle privacy-redacted registrant', async () => {
		const redactedResponse = makeRdapResponse({
			entities: [
				{
					objectClassName: 'entity',
					roles: ['registrar'],
					vcardArray: ['vcard', [
						['version', {}, 'text', '4.0'],
						['fn', {}, 'text', 'Namecheap Inc.'],
					]],
				},
				{
					objectClassName: 'entity',
					roles: ['registrant'],
					vcardArray: ['vcard', [
						['version', {}, 'text', '4.0'],
						['fn', {}, 'text', 'REDACTED FOR PRIVACY'],
						['adr', {}, 'text', ['', '', 'REDACTED FOR PRIVACY', '', '', '', 'REDACTED FOR PRIVACY']],
					]],
				},
			],
		});

		globalThis.fetch = mockFetchRouter({
			'data.iana.org/rdap/dns.json': () => makeBootstrap(),
			'rdap.verisign.com': () => redactedResponse,
		});

		const result = await run();
		const infoFinding = result.findings.find((f) => f.severity === 'info' && f.title.toLowerCase().includes('registration'));
		expect(infoFinding).toBeDefined();
		expect(infoFinding!.detail).toContain('REDACTED');
	});

	it('should flag newly registered domain (< 30 days) as medium severity', async () => {
		const now = new Date();
		const recentDate = new Date(now.getTime() - 10 * 24 * 60 * 60 * 1000); // 10 days ago

		const newDomainResponse = makeRdapResponse({
			events: [
				{ eventAction: 'registration', eventDate: recentDate.toISOString() },
				{ eventAction: 'expiration', eventDate: '2027-06-15T00:00:00Z' },
			],
		});

		globalThis.fetch = mockFetchRouter({
			'data.iana.org/rdap/dns.json': () => makeBootstrap(),
			'rdap.verisign.com': () => newDomainResponse,
		});

		const result = await run();
		const mediumFinding = result.findings.find((f) => f.severity === 'medium');
		expect(mediumFinding).toBeDefined();
		expect(mediumFinding!.title).toMatch(/newly registered/i);
		// domainAgeDays lives in finding metadata
		const infoFinding = result.findings.find((f) => f.severity === 'info' || f.severity === 'medium');
		expect(infoFinding?.metadata?.domainAgeDays).toBeLessThanOrEqual(15);
	});

	it('should handle RDAP server timeout gracefully', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('data.iana.org/rdap/dns.json')) {
				return Promise.resolve(new Response(JSON.stringify(makeBootstrap()), {
					status: 200,
					headers: { 'Content-Type': 'application/json' },
				}));
			}
			// Simulate timeout on RDAP domain lookup
			return Promise.reject(new DOMException('The operation was aborted', 'AbortError'));
		});

		const result = await run();
		expect(result.category).toBe('rdap');
		const errorFinding = result.findings.find((f) => f.severity === 'info' && f.title.toLowerCase().includes('failed'));
		expect(errorFinding).toBeDefined();
	});

	it('should use redirect: manual for all fetch calls', async () => {
		const fetchSpy = vi.fn().mockImplementation((input: string | URL | Request, _init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('data.iana.org/rdap/dns.json')) {
				return Promise.resolve(new Response(JSON.stringify(makeBootstrap()), {
					status: 200,
					headers: { 'Content-Type': 'application/json' },
				}));
			}
			if (url.includes('rdap.verisign.com')) {
				return Promise.resolve(new Response(JSON.stringify(makeRdapResponse()), {
					status: 200,
					headers: { 'Content-Type': 'application/rdap+json' },
				}));
			}
			return Promise.resolve(new Response('Not Found', { status: 404 }));
		});
		globalThis.fetch = fetchSpy;

		await run();

		// Verify every fetch call used redirect: 'manual'
		for (const call of fetchSpy.mock.calls) {
			const init = call[1] as RequestInit | undefined;
			expect(init?.redirect, `Fetch to ${call[0]} missing redirect:manual`).toBe('manual');
		}
	});

	it('should calculate domain age correctly in metadata', async () => {
		const creationDate = new Date('2023-06-01T00:00:00Z');
		const expectedAgeDays = Math.floor((Date.now() - creationDate.getTime()) / (1000 * 60 * 60 * 24));

		const response = makeRdapResponse({
			events: [
				{ eventAction: 'registration', eventDate: '2023-06-01T00:00:00Z' },
				{ eventAction: 'expiration', eventDate: '2030-06-01T00:00:00Z' },
			],
		});

		globalThis.fetch = mockFetchRouter({
			'data.iana.org/rdap/dns.json': () => makeBootstrap(),
			'rdap.verisign.com': () => response,
		});

		const result = await run();
		// domainAgeDays lives in finding metadata
		const infoFinding = result.findings.find((f) => f.severity === 'info' && f.title.toLowerCase().includes('registration'));
		expect(infoFinding?.metadata?.domainAgeDays).toBeDefined();
		// Allow 1 day tolerance for test timing
		expect(Math.abs((infoFinding!.metadata!.domainAgeDays as number) - expectedAgeDays)).toBeLessThanOrEqual(1);
	});

	it('should use hardcoded fallback when bootstrap has no matching TLD', async () => {
		// Bootstrap returns empty services → should fall back to hardcoded map
		globalThis.fetch = mockFetchRouter({
			'data.iana.org/rdap/dns.json': () => makeBootstrap([]),
			'rdap.verisign.com': () => makeRdapResponse(),
		});

		const result = await run('example.com');
		expect(result.category).toBe('rdap');
		// Should still get results via hardcoded fallback for .com
		const infoFinding = result.findings.find((f) => f.severity === 'info' && f.title.toLowerCase().includes('registration'));
		expect(infoFinding).toBeDefined();
	});
});
