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
				vcardArray: [
					'vcard',
					[
						['version', {}, 'text', '4.0'],
						['fn', {}, 'text', 'Example Registrar Inc.'],
					],
				],
			},
			{
				objectClassName: 'entity',
				roles: ['registrant'],
				vcardArray: [
					'vcard',
					[
						['version', {}, 'text', '4.0'],
						['fn', {}, 'text', 'ACME Corporation'],
						['adr', {}, 'text', ['', '', '123 Main St', 'Springfield', 'IL', '62704', 'US']],
					],
				],
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
				return Promise.resolve(
					new Response(JSON.stringify(handler()), {
						status: 200,
						headers: { 'Content-Type': 'application/rdap+json' },
					}),
				);
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

	it('retries a transient RDAP 429 before falling back to WHOIS', async () => {
		let rdapAttempts = 0;
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('data.iana.org/rdap/dns.json')) {
				return Promise.resolve(
					new Response(JSON.stringify(makeBootstrap([[['global'], ['https://rdap.identitydigital.services/rdap/']]])), {
						status: 200,
						headers: { 'Content-Type': 'application/json' },
					}),
				);
			}
			if (url.includes('rdap.identitydigital.services')) {
				rdapAttempts++;
				if (rdapAttempts === 1) {
					return Promise.resolve(new Response('Too Many Requests', { status: 429, headers: { 'Retry-After': '0' } }));
				}
				return Promise.resolve(
					new Response(
						JSON.stringify(
							makeRdapResponse({
								ldhName: 'stripe.global',
								entities: [
									{
										objectClassName: 'entity',
										roles: ['registrar'],
										vcardArray: [
											'vcard',
											[
												['version', {}, 'text', '4.0'],
												['fn', {}, 'text', 'SafeNames Ltd.'],
											],
										],
									},
								],
							}),
						),
						{
							status: 200,
							headers: { 'Content-Type': 'application/rdap+json' },
						},
					),
				);
			}
			return Promise.resolve(new Response('Not Found', { status: 404 }));
		});

		const result = await run('stripe.global');

		expect(rdapAttempts).toBe(2);
		const infoFinding = result.findings.find((f) => f.severity === 'info' && f.title.toLowerCase().includes('registration'));
		expect(infoFinding?.metadata?.registrar).toBe('SafeNames Ltd.');
		expect(infoFinding?.metadata?.registrarSource).toBe('rdap');
		expect(result.findings.some((f) => f.metadata?.registrarSource === 'lookup_failed')).toBe(false);
	});

	it('should handle privacy-redacted registrant', async () => {
		const redactedResponse = makeRdapResponse({
			entities: [
				{
					objectClassName: 'entity',
					roles: ['registrar'],
					vcardArray: [
						'vcard',
						[
							['version', {}, 'text', '4.0'],
							['fn', {}, 'text', 'Namecheap Inc.'],
						],
					],
				},
				{
					objectClassName: 'entity',
					roles: ['registrant'],
					vcardArray: [
						'vcard',
						[
							['version', {}, 'text', '4.0'],
							['fn', {}, 'text', 'REDACTED FOR PRIVACY'],
							['adr', {}, 'text', ['', '', 'REDACTED FOR PRIVACY', '', '', '', 'REDACTED FOR PRIVACY']],
						],
					],
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
				return Promise.resolve(
					new Response(JSON.stringify(makeBootstrap()), {
						status: 200,
						headers: { 'Content-Type': 'application/json' },
					}),
				);
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
				return Promise.resolve(
					new Response(JSON.stringify(makeBootstrap()), {
						status: 200,
						headers: { 'Content-Type': 'application/json' },
					}),
				);
			}
			if (url.includes('rdap.verisign.com')) {
				return Promise.resolve(
					new Response(JSON.stringify(makeRdapResponse()), {
						status: 200,
						headers: { 'Content-Type': 'application/rdap+json' },
					}),
				);
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

	it('extracts registrar organization from RDAP vcard org when fn is absent', async () => {
		globalThis.fetch = mockFetchRouter({
			'data.iana.org/rdap/dns.json': () => makeBootstrap(),
			'rdap.verisign.com': () =>
				makeRdapResponse({
					entities: [
						{
							objectClassName: 'entity',
							roles: ['registrar'],
							vcardArray: [
								'vcard',
								[
									['version', {}, 'text', '4.0'],
									['org', {}, 'text', 'Synthetic Registrar Org LLC'],
								],
							],
						},
					],
				}),
		});

		const result = await run();
		const infoFinding = result.findings.find((f) => f.metadata?.registrarSource === 'rdap');
		expect(infoFinding?.metadata?.registrar).toBe('Synthetic Registrar Org LLC');
	});

	it('extracts registrar IANA ID from RDAP registrar entity publicIds', async () => {
		globalThis.fetch = mockFetchRouter({
			'data.iana.org/rdap/dns.json': () => makeBootstrap(),
			'rdap.verisign.com': () =>
				makeRdapResponse({
					entities: [
						{
							objectClassName: 'entity',
							roles: ['registrar'],
							publicIds: [{ type: 'IANA Registrar ID', identifier: '299' }],
							vcardArray: [
								'vcard',
								[
									['version', {}, 'text', '4.0'],
									['fn', {}, 'text', 'Corporation Service Company'],
								],
							],
						},
					],
				}),
		});

		const result = await run();
		const infoFinding = result.findings.find((f) => f.metadata?.registrarSource === 'rdap');
		expect(infoFinding?.metadata?.registrar).toBe('Corporation Service Company');
		expect(infoFinding?.metadata?.registrarIanaId).toBe('299');
	});

	it('extracts registrar from RDAP entity publicIds even without registrar role', async () => {
		globalThis.fetch = mockFetchRouter({
			'data.iana.org/rdap/dns.json': () => makeBootstrap(),
			'rdap.verisign.com': () =>
				makeRdapResponse({
					entities: [
						{
							objectClassName: 'entity',
							roles: ['technical'],
							publicIds: [{ type: 'IANA Registrar ID', identifier: '9999' }],
							vcardArray: [
								'vcard',
								[
									['version', {}, 'text', '4.0'],
									['fn', {}, 'text', 'Synthetic PublicId Registrar LLC'],
								],
							],
						},
					],
				}),
		});

		const result = await run();
		const infoFinding = result.findings.find((f) => f.metadata?.registrarSource === 'rdap');
		expect(infoFinding?.metadata?.registrar).toBe('Synthetic PublicId Registrar LLC');
		expect(infoFinding?.metadata?.registrarIanaId).toBe('9999');
	});

	it('falls back to WHOIS when RDAP succeeds but registrar attribution is unknown', async () => {
		globalThis.fetch = mockFetchRouter({
			'data.iana.org/rdap/dns.json': () => makeBootstrap(),
			'rdap.verisign.com': () => makeRdapResponse({ entities: [] }),
		});
		const whoisBinding = {
			fetch: vi.fn(
				async () =>
					new Response(JSON.stringify({ registrar: 'WHOIS Fallback Registrar Inc.', source: 'whois' }), {
						status: 200,
						headers: { 'Content-Type': 'application/json' },
					}),
			),
		};

		const mod = await import('../src/tools/check-rdap-lookup');
		mod._resetBootstrapCache();
		const result = await mod.checkRdapLookup('example.com', { whoisBinding });

		const infoFinding = result.findings.find((f) => f.metadata?.registrarSource === 'whois');
		expect(infoFinding?.metadata?.registrar).toBe('WHOIS Fallback Registrar Inc.');
		expect(whoisBinding.fetch).toHaveBeenCalledOnce();
	});

	it.each([
		['Registrar', 'Synthetic Registrar LLC'],
		['Registrar Name', 'Synthetic Registrar Name LLC'],
		['Sponsoring Registrar', 'Synthetic Sponsoring Registrar LLC'],
		['Registrar Organization', 'Synthetic Registrar Organization LLC'],
	])('falls back to plain WHOIS %s labels when RDAP has no registrar attribution', async (label, registrar) => {
		globalThis.fetch = mockFetchRouter({
			'data.iana.org/rdap/dns.json': () => makeBootstrap(),
			'rdap.verisign.com': () => makeRdapResponse({ entities: [] }),
		});
		const whoisBinding = {
			fetch: vi.fn(
				async () =>
					new Response(`Domain Name: EXAMPLE.COM\n${label}: ${registrar}\nUpdated Date: 2026-01-01T00:00:00Z\n`, {
						status: 200,
						headers: { 'Content-Type': 'text/plain' },
					}),
			),
		};

		const mod = await import('../src/tools/check-rdap-lookup');
		mod._resetBootstrapCache();
		const result = await mod.checkRdapLookup('example.com', { whoisBinding });

		const infoFinding = result.findings.find((f) => f.metadata?.registrarSource === 'whois');
		expect(infoFinding?.metadata?.registrar).toBe(registrar);
		expect(whoisBinding.fetch).toHaveBeenCalledOnce();
	});

	it('does not treat Registrar URL as a registrar name', async () => {
		globalThis.fetch = mockFetchRouter({
			'data.iana.org/rdap/dns.json': () => makeBootstrap(),
			'rdap.verisign.com': () => makeRdapResponse({ entities: [] }),
		});
		const whoisBinding = {
			fetch: vi.fn(
				async () =>
					new Response('Domain Name: EXAMPLE.COM\nRegistrar URL: https://registrar.example.test\n', {
						status: 200,
						headers: { 'Content-Type': 'text/plain' },
					}),
			),
		};

		const mod = await import('../src/tools/check-rdap-lookup');
		mod._resetBootstrapCache();
		const result = await mod.checkRdapLookup('example.com', { whoisBinding });

		const urlRegistrar = result.findings.find((f) => f.metadata?.registrar === 'https://registrar.example.test');
		expect(urlRegistrar).toBeUndefined();
		const fallbackFinding = result.findings.find((f) => f.metadata?.registrarSource === 'redacted');
		expect(fallbackFinding?.metadata?.registrarFailureReason).toBeUndefined();
		expect(whoisBinding.fetch).toHaveBeenCalledOnce();
	});

	describe('SSRF: bootstrap-derived RDAP server host', () => {
		it('does NOT fetch an RDAP server whose host (from network-sourced bootstrap) is a blocked RFC1918 destination', async () => {
			// The IANA bootstrap is network-sourced, so its server hostnames are NOT
			// statically trusted. A MITM (or poisoned mirror) could point a TLD at an
			// internal address. The fetch must be re-validated by the SSRF gate and
			// blocked — even though the blocked host here returns a VALID RDAP body,
			// the response must never be consumed.
			const blockedHost = '192.168.1.1';
			const fetchSpy = vi.fn().mockImplementation((input: string | URL | Request) => {
				const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
				if (url.includes('data.iana.org/rdap/dns.json')) {
					return Promise.resolve(
						new Response(JSON.stringify(makeBootstrap([[['evilcorp'], [`https://${blockedHost}/rdap/`]]])), {
							status: 200,
							headers: { 'Content-Type': 'application/json' },
						}),
					);
				}
				// A would-be-successful RDAP response from the blocked host. If the SSRF
				// gate is bypassed (raw fetch), this is consumed → registrarSource 'rdap'.
				return Promise.resolve(
					new Response(JSON.stringify(makeRdapResponse({ ldhName: 'acme.evilcorp' })), {
						status: 200,
						headers: { 'Content-Type': 'application/rdap+json' },
					}),
				);
			});
			globalThis.fetch = fetchSpy;

			const result = await run('acme.evilcorp');

			// Discriminator: the blocked host's valid response must NOT have been parsed.
			const rdapSourced = result.findings.find((f) => f.metadata?.registrarSource === 'rdap');
			expect(rdapSourced, 'blocked RDAP response must not be consumed').toBeUndefined();

			// The fetch to the blocked host must never have been performed.
			const calledBlockedHost = fetchSpy.mock.calls.some((call) => {
				const u = typeof call[0] === 'string' ? call[0] : call[0] instanceof URL ? call[0].href : (call[0] as Request).url;
				return u.includes(blockedHost);
			});
			expect(calledBlockedHost, `fetch must not be performed against ${blockedHost}`).toBe(false);

			// The lookup surfaces as a transient lookup_failure (SSRF block → TypeError → catch).
			const failed = result.findings.find((f) => f.metadata?.registrarSource === 'lookup_failed');
			expect(failed?.metadata?.registrarFailureReason).toBe('rdap_fetch_error');
		});

		it('still fetches a normal public RDAP host (no regression)', async () => {
			const fetchSpy = mockFetchRouter({
				'data.iana.org/rdap/dns.json': () => makeBootstrap(),
				'rdap.verisign.com': () => makeRdapResponse(),
			});
			globalThis.fetch = fetchSpy;

			const result = await run('example.com');
			const infoFinding = result.findings.find((f) => f.metadata?.registrarSource === 'rdap');
			expect(infoFinding?.metadata?.registrar).toBe('Example Registrar Inc.');
			const calledPublicHost = fetchSpy.mock.calls.some((call) => {
				const u = typeof call[0] === 'string' ? call[0] : call[0] instanceof URL ? call[0].href : (call[0] as Request).url;
				return u.includes('rdap.verisign.com');
			});
			expect(calledPublicHost, 'public RDAP host should be fetched').toBe(true);
		});
	});

	describe('FALLBACK_RDAP_SERVERS', () => {
		it('.app and .dev point at pubapi.registry.google (not the dead www.registry.google host)', async () => {
			const { FALLBACK_RDAP_SERVERS } = await import('../src/tools/check-rdap-lookup');
			expect(FALLBACK_RDAP_SERVERS.app).toBe('https://pubapi.registry.google/rdap/');
			expect(FALLBACK_RDAP_SERVERS.dev).toBe('https://pubapi.registry.google/rdap/');
			expect(FALLBACK_RDAP_SERVERS.app).not.toContain('www.registry.google');
		});

		it('covers the ccTLDs the brand-audit hits most often without bootstrap (.uk, .nl, .de via WHOIS, .ca, .sg, .fr, .jp via WHOIS, .in, .au)', async () => {
			const { FALLBACK_RDAP_SERVERS } = await import('../src/tools/check-rdap-lookup');
			// Covered by IANA bootstrap → also pinned in our hardcoded fallback.
			for (const tld of ['uk', 'nl', 'ca', 'sg', 'fr', 'in', 'au', 'pl', 'no', 'cz']) {
				expect(FALLBACK_RDAP_SERVERS[tld], `missing fallback for .${tld}`).toMatch(/^https:\/\//);
			}
		});

		it('every fallback URL is HTTPS and ends with /', async () => {
			const { FALLBACK_RDAP_SERVERS } = await import('../src/tools/check-rdap-lookup');
			for (const [tld, url] of Object.entries(FALLBACK_RDAP_SERVERS)) {
				expect(url.startsWith('https://'), `.${tld} → ${url} not https`).toBe(true);
				expect(url.endsWith('/'), `.${tld} → ${url} missing trailing slash`).toBe(true);
			}
		});
	});

	describe('bootstrap in-flight dedup', () => {
		it('concurrent RDAP calls share a single IANA bootstrap fetch (not N concurrent fetches)', async () => {
			let bootstrapFetchCount = 0;
			let resolveBootstrap: (v: Response) => void = () => {};
			const bootstrapPromise = new Promise<Response>((r) => {
				resolveBootstrap = r;
			});

			globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
				const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
				if (url.includes('data.iana.org/rdap/dns.json')) {
					bootstrapFetchCount++;
					return bootstrapPromise;
				}
				return Promise.resolve(
					new Response(JSON.stringify(makeRdapResponse()), {
						status: 200,
						headers: { 'Content-Type': 'application/rdap+json' },
					}),
				);
			});

			const mod = await import('../src/tools/check-rdap-lookup');
			mod._resetBootstrapCache();

			// Fire three concurrent lookups before bootstrap resolves
			const p1 = mod.checkRdapLookup('a.com');
			const p2 = mod.checkRdapLookup('b.com');
			const p3 = mod.checkRdapLookup('c.com');

			// Let microtasks flush so all three calls reach fetchBootstrap()
			await Promise.resolve();
			await Promise.resolve();

			expect(bootstrapFetchCount).toBe(1);

			resolveBootstrap(
				new Response(JSON.stringify(makeBootstrap()), {
					status: 200,
					headers: { 'Content-Type': 'application/json' },
				}),
			);

			await Promise.all([p1, p2, p3]);
			expect(bootstrapFetchCount).toBe(1);
		});
	});
});

describe('deriveLockPosture', () => {
	async function derive(status: string[]) {
		const { deriveLockPosture } = await import('../src/tools/check-rdap-lookup');
		return deriveLockPosture(status);
	}

	it('empty status → unknown, all booleans false', async () => {
		expect(await derive([])).toEqual({
			level: 'unknown',
			transferLocked: false,
			deleteLocked: false,
			updateLocked: false,
			registryLevel: false,
			registrarLevel: false,
		});
	});

	it('client transfer prohibited (RDAP spaced form) → registrar-lock', async () => {
		const p = await derive(['client transfer prohibited']);
		expect(p.level).toBe('registrar-lock');
		expect(p.registrarLevel).toBe(true);
		expect(p.registryLevel).toBe(false);
		expect(p.transferLocked).toBe(true);
	});

	it('serverTransferProhibited (EPP camelCase) → registry-lock', async () => {
		const p = await derive(['serverTransferProhibited']);
		expect(p.level).toBe('registry-lock');
		expect(p.registryLevel).toBe(true);
	});

	it('full server lock set → registry-lock with all booleans true', async () => {
		const p = await derive(['server transfer prohibited', 'server delete prohibited', 'server update prohibited']);
		expect(p.level).toBe('registry-lock');
		expect(p.transferLocked).toBe(true);
		expect(p.deleteLocked).toBe(true);
		expect(p.updateLocked).toBe(true);
		expect(p.registryLevel).toBe(true);
	});

	it('clientUpdateProhibited only (no transfer lock) → unlocked', async () => {
		const p = await derive(['clientUpdateProhibited']);
		expect(p.level).toBe('unlocked');
		expect(p.updateLocked).toBe(true);
		expect(p.transferLocked).toBe(false);
	});

	it('active / ok (no prohibitions) → unlocked', async () => {
		expect((await derive(['active'])).level).toBe('unlocked');
		expect((await derive(['ok'])).level).toBe('unlocked');
	});

	it('mixed case + extra whitespace → still registry-lock (normalization)', async () => {
		const p = await derive(['  Server Transfer Prohibited ']);
		expect(p.level).toBe('registry-lock');
		expect(p.registryLevel).toBe(true);
	});

	it('both client + server transfer present → registry-lock (server precedence)', async () => {
		const p = await derive(['clientTransferProhibited', 'serverTransferProhibited']);
		expect(p.level).toBe('registry-lock');
		expect(p.registrarLevel).toBe(true);
		expect(p.registryLevel).toBe(true);
	});
});
