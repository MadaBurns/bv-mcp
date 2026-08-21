import { describe, it, expect, afterEach } from 'vitest';
import { vi } from 'vitest';
import { setupFetchMock } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

/** Mock crt.sh API response entries. */
const mockCtResponse = [
	{
		name_value: 'api.example.com',
		issuer_name: "CN=R3, O=Let's Encrypt",
		not_before: '2026-01-01',
		not_after: '2026-04-01',
	},
	{
		name_value: '*.example.com',
		issuer_name: 'CN=DigiCert',
		not_before: '2026-01-01',
		not_after: '2026-12-31',
	},
	{
		name_value: 'old.example.com',
		issuer_name: 'CN=R3',
		not_before: '2023-01-01',
		not_after: '2023-04-01',
	},
	{
		name_value: 'api.example.com\nwww.example.com',
		issuer_name: 'CN=R3',
		not_before: '2026-02-01',
		not_after: '2026-05-01',
	},
];

/** Set up the fetch mock to intercept crt.sh requests. */
function mockCrtSh(response: unknown, ok = true) {
	globalThis.fetch = vi.fn().mockImplementation(async (url: string | URL | Request) => {
		const urlStr = typeof url === 'string' ? url : url instanceof URL ? url.toString() : url.url;
		if (urlStr.includes('crt.sh')) {
			return Response.json(response, { status: ok ? 200 : 500 });
		}
		// Fallback for any other requests
		return { ok: true, status: 200, json: () => Promise.resolve({ Status: 0, Answer: [] }) };
	});
}

describe('discoverSubdomains', () => {
	async function run(domain = 'example.com') {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		return discoverSubdomains(domain);
	}

	it('uses the certstream service binding with bearer auth when a token is provided', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const certstreamFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
			expect(url).toBe('https://certstream/enumerate?domain=example.com');
			expect(init?.headers).toMatchObject({ Authorization: 'Bearer shared-internal-key' });
			return new Response(
				JSON.stringify({
					domain: 'example.com',
					subdomains: ['api.example.com', 'www.example.com'],
					certificateCount: 2,
					timedOut: false,
					cached: false,
					source: 'certspotter',
				}),
				{ status: 200, headers: { 'Content-Type': 'application/json' } },
			);
		});
		globalThis.fetch = vi.fn(async () => {
			throw new Error('crt.sh fallback should not be used');
		});

		const result = await discoverSubdomains('example.com', { fetch: certstreamFetch as unknown as typeof fetch }, 'shared-internal-key');

		expect(result.totalSubdomains).toBe(2);
		expect(result.totalCertificates).toBe(2);
		expect(result.subdomains.map((s) => s.subdomain)).toEqual(['api.example.com', 'www.example.com']);
		expect(result.sourceUnavailable).toBeUndefined();
	});

	it('falls back to certstream /sans when /enumerate is transiently unavailable', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const certstreamFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
			expect(init?.headers).toMatchObject({ Authorization: 'Bearer shared-internal-key' });
			if (url === 'https://certstream/enumerate?domain=example.com') {
				return new Response(JSON.stringify({ error: 'upstream transient' }), {
					status: 502,
					headers: { 'Content-Type': 'application/json' },
				});
			}
			if (url === 'https://certstream/sans?domain=example.com') {
				return new Response(
					JSON.stringify({
						domain: 'example.com',
						names: ['www.example.com', '*.example.com', '*.attacker.invalid', 'example.com', 'api.example.com.'],
						certificateCount: 5,
						timedOut: false,
						truncated: false,
						cached: false,
					}),
					{ status: 200, headers: { 'Content-Type': 'application/json' } },
				);
			}
			throw new Error(`unexpected certstream URL: ${url}`);
		});
		globalThis.fetch = vi.fn(async () => {
			throw new Error('crt.sh fallback should not be used');
		});

		const result = await discoverSubdomains('example.com', { fetch: certstreamFetch as unknown as typeof fetch }, 'shared-internal-key');

		expect(certstreamFetch).toHaveBeenCalledTimes(2);
		expect(result.totalSubdomains).toBe(3);
		expect(result.totalCertificates).toBe(5);
		expect(result.subdomains.map((s) => s.subdomain)).toEqual(['www.example.com', '*.example.com', 'api.example.com']);
		expect(result.sourceUnavailable).toBeUndefined();
	});

	it('cancels unread certstream /enumerate body before falling back to /sans', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const enumerateResponse = new Response(JSON.stringify({ error: 'upstream transient' }), {
			status: 502,
			headers: { 'Content-Type': 'application/json' },
		});
		const enumerateCancel = vi.spyOn(enumerateResponse.body!, 'cancel');
		const certstreamFetch = vi.fn(async (input: RequestInfo | URL) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
			if (url === 'https://certstream/enumerate?domain=example.com') return enumerateResponse;
			if (url === 'https://certstream/sans?domain=example.com') {
				return Response.json({
					domain: 'example.com',
					names: ['api.example.com', 'www.example.com'],
					certificateCount: 2,
					timedOut: false,
					truncated: false,
					cached: false,
				});
			}
			throw new Error(`unexpected certstream URL: ${url}`);
		});
		globalThis.fetch = vi.fn(async () => {
			throw new Error('crt.sh fallback should not be used');
		});

		const result = await discoverSubdomains('example.com', { fetch: certstreamFetch as unknown as typeof fetch }, 'shared-internal-key');

		expect(result.totalSubdomains).toBe(2);
		expect(enumerateCancel).toHaveBeenCalledTimes(1);
	});

	it('should parse crt.sh response and extract subdomains', async () => {
		mockCrtSh(mockCtResponse);
		const result = await run();

		expect(result.domain).toBe('example.com');
		expect(result.totalSubdomains).toBeGreaterThan(0);
		expect(result.totalCertificates).toBe(4);

		const subdomainNames = result.subdomains.map((s) => s.subdomain);
		expect(subdomainNames).toContain('api.example.com');
		expect(subdomainNames).toContain('www.example.com');
		expect(subdomainNames).toContain('*.example.com');
		expect(subdomainNames).toContain('old.example.com');
	});

	it('should deduplicate subdomains correctly', async () => {
		mockCrtSh(mockCtResponse);
		const result = await run();

		// api.example.com appears in two entries — should be deduplicated
		const apiEntries = result.subdomains.filter((s) => s.subdomain === 'api.example.com');
		expect(apiEntries).toHaveLength(1);
		expect(apiEntries[0].certCount).toBe(2);
	});

	it('should detect wildcard certificates', async () => {
		mockCrtSh(mockCtResponse);
		const result = await run();

		expect(result.wildcardCerts).toBeGreaterThan(0);
		const wildcard = result.subdomains.find((s) => s.subdomain === '*.example.com');
		expect(wildcard).toBeDefined();
		expect(wildcard!.isWildcard).toBe(true);

		// Should have a wildcard_exposure issue
		const wildcardIssue = result.issues.find((i) => i.type === 'wildcard_exposure');
		expect(wildcardIssue).toBeDefined();
		expect(wildcardIssue!.severity).toBe('info');
	});

	it('should detect expired certificates', async () => {
		mockCrtSh(mockCtResponse);
		const result = await run();

		expect(result.expiredCerts).toBeGreaterThan(0);
		const oldSub = result.subdomains.find((s) => s.subdomain === 'old.example.com');
		expect(oldSub).toBeDefined();
		expect(oldSub!.isExpired).toBe(true);

		// Should have an expired_subdomain issue
		const expiredIssue = result.issues.find((i) => i.type === 'expired_subdomain' && i.detail.includes('old.example.com'));
		expect(expiredIssue).toBeDefined();
		expect(expiredIssue!.severity).toBe('medium');
	});

	it('should handle crt.sh being unavailable (fetch throws)', async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error('Network error'));
		const result = await run();

		expect(result.totalSubdomains).toBe(0);
		expect(result.subdomains).toHaveLength(0);
		expect(result.totalCertificates).toBe(0);
		// Distinguish "source unavailable" from "queried, none found".
		expect(result.sourceUnavailable).toBe(true);
	});

	it('should handle crt.sh returning an error status', async () => {
		mockCrtSh(null, false);
		const result = await run();

		expect(result.totalSubdomains).toBe(0);
		expect(result.subdomains).toHaveLength(0);
		expect(result.sourceUnavailable).toBe(true);
	});

	it('rejects an oversized crt.sh response before parsing it', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(
			new Response('[]', {
				status: 200,
				headers: {
					'Content-Type': 'application/json',
					'Content-Length': String(6 * 1024 * 1024),
				},
			}),
		);

		const result = await run();
		expect(result.totalSubdomains).toBe(0);
		expect(result.sourceUnavailable).toBe(true);
	});

	it('marks a successful-but-empty crt.sh query as available (none found, not unavailable)', async () => {
		mockCrtSh([]);
		const result = await run();

		expect(result.totalSubdomains).toBe(0);
		expect(result.sourceUnavailable).toBeFalsy();
	});

	it('should filter out the bare domain (only returns subdomains)', async () => {
		const entriesWithBareDomain = [
			...mockCtResponse,
			{
				name_value: 'example.com',
				issuer_name: 'CN=R3',
				not_before: '2026-01-01',
				not_after: '2026-04-01',
			},
		];
		mockCrtSh(entriesWithBareDomain);
		const result = await run();

		const subdomainNames = result.subdomains.map((s) => s.subdomain);
		expect(subdomainNames).not.toContain('example.com');
	});

	// The structural return cap is 500 (raised from 100 in #573 — a 100-name cap
	// silently dropped the majority of a real bank's estate). The ~100-name cap
	// that remains is a TEXT-rendering cap, asserted in the truncation suite.
	it('returns the full set structurally when it fits under the 500 cap', async () => {
		// Generate 150 unique subdomains
		const manyEntries = Array.from({ length: 150 }, (_, i) => ({
			name_value: `sub${i}.example.com`,
			issuer_name: 'CN=R3',
			not_before: '2026-01-01',
			not_after: '2026-04-01',
		}));
		mockCrtSh(manyEntries);
		const result = await run();

		expect(result.subdomains).toHaveLength(150);
		expect(result.totalSubdomains).toBe(150);
		expect(result.truncated).toBeFalsy();
	});

	it('should limit structured output to 500 subdomains', async () => {
		const manyEntries = Array.from({ length: 640 }, (_, i) => ({
			name_value: `sub${i}.example.com`,
			issuer_name: 'CN=R3',
			not_before: '2026-01-01',
			not_after: '2026-04-01',
		}));
		mockCrtSh(manyEntries);
		const result = await run();

		expect(result.subdomains).toHaveLength(500);
		expect(result.totalSubdomains).toBe(640);
		expect(result.returned).toBe(500);
		expect(result.truncated).toBe(true);
	});

	it('should sort subdomains by lastSeen descending', async () => {
		const entries = [
			{
				name_value: 'oldest.example.com',
				issuer_name: 'CN=R3',
				not_before: '2024-01-01',
				not_after: '2025-01-01',
			},
			{
				name_value: 'newest.example.com',
				issuer_name: 'CN=R3',
				not_before: '2026-03-01',
				not_after: '2026-06-01',
			},
			{
				name_value: 'middle.example.com',
				issuer_name: 'CN=R3',
				not_before: '2025-06-01',
				not_after: '2025-12-01',
			},
		];
		mockCrtSh(entries);
		const result = await run();

		expect(result.subdomains[0].subdomain).toBe('newest.example.com');
		expect(result.subdomains[1].subdomain).toBe('middle.example.com');
		expect(result.subdomains[2].subdomain).toBe('oldest.example.com');
	});

	it('should extract issuer CN correctly', async () => {
		mockCrtSh(mockCtResponse);
		const result = await run();

		const apiSub = result.subdomains.find((s) => s.subdomain === 'api.example.com');
		expect(apiSub).toBeDefined();
		// The latest cert for api.example.com is from 2026-02-01 with issuer CN=R3
		expect(apiSub!.issuer).toBe('R3');
	});

	it('should track first and last seen dates across multiple certs', async () => {
		mockCrtSh(mockCtResponse);
		const result = await run();

		const apiSub = result.subdomains.find((s) => s.subdomain === 'api.example.com');
		expect(apiSub).toBeDefined();
		// First cert: 2026-01-01, second cert: 2026-02-01
		expect(apiSub!.firstSeen).toBe('2026-01-01');
		expect(apiSub!.lastSeen).toBe('2026-02-01');
	});

	it('should detect many_issuers when more than 3 CAs are present', async () => {
		const multiIssuerEntries = [
			{ name_value: 'a.example.com', issuer_name: 'CN=R3', not_before: '2026-01-01', not_after: '2026-04-01' },
			{ name_value: 'b.example.com', issuer_name: 'CN=DigiCert', not_before: '2026-01-01', not_after: '2026-04-01' },
			{ name_value: 'c.example.com', issuer_name: 'CN=Amazon', not_before: '2026-01-01', not_after: '2026-04-01' },
			{ name_value: 'd.example.com', issuer_name: 'CN=Sectigo', not_before: '2026-01-01', not_after: '2026-04-01' },
		];
		mockCrtSh(multiIssuerEntries);
		const result = await run();

		expect(result.uniqueIssuers).toHaveLength(4);
		const manyIssuersIssue = result.issues.find((i) => i.type === 'many_issuers');
		expect(manyIssuersIssue).toBeDefined();
		expect(manyIssuersIssue!.severity).toBe('low');
	});

	it('should handle empty crt.sh response', async () => {
		mockCrtSh([]);
		const result = await run();

		expect(result.totalSubdomains).toBe(0);
		expect(result.subdomains).toHaveLength(0);
	});

	it('should filter out domains that are not subdomains of the target', async () => {
		const entries = [
			{ name_value: 'api.example.com', issuer_name: 'CN=R3', not_before: '2026-01-01', not_after: '2026-04-01' },
			{ name_value: 'evil.otherdomain.com', issuer_name: 'CN=R3', not_before: '2026-01-01', not_after: '2026-04-01' },
			{ name_value: 'notexample.com', issuer_name: 'CN=R3', not_before: '2026-01-01', not_after: '2026-04-01' },
		];
		mockCrtSh(entries);
		const result = await run();

		const names = result.subdomains.map((s) => s.subdomain);
		expect(names).toContain('api.example.com');
		expect(names).not.toContain('evil.otherdomain.com');
		expect(names).not.toContain('notexample.com');
	});
});

describe('discoverSubdomains — honest zero (D5 residual gaps: R1/R2/R3)', () => {
	async function run(domain = 'example.com') {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		return discoverSubdomains(domain);
	}

	// R1: emptyResult() must never surface a bare `issues: []` — structured
	// consumers read `issues[]` directly and drop `isError` (a handler-layer
	// concern), so an empty issues array on a zero-subdomain result is a
	// success-shaped zero indistinguishable from a genuinely verified absence.
	it('R1: a corroborated-empty direct-source result still carries a high-severity unconfirmed_zero issue', async () => {
		mockCrtSh([]); // crt.sh: outcome 'empty'. Certspotter falls to mockCrtSh's
		// generic non-Response fallback, which throws inside fetchCertspotterEntries
		// and is caught as outcome 'error' — so this exercises "one source spoke
		// (empty), the other never confirmed" exactly as R3 requires.
		const result = await run();

		expect(result.totalSubdomains).toBe(0);
		expect(result.sourceUnavailable).toBeFalsy();
		const issue = result.issues.find((i) => i.type === 'unconfirmed_zero');
		expect(issue).toBeDefined();
		expect(issue?.severity).toBe('high');
	});

	it('R1: a total-outage emptyResult also carries the unconfirmed_zero issue (belt-and-braces with isError)', async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error('Network error'));
		const result = await run();

		expect(result.sourceUnavailable).toBe(true);
		const issue = result.issues.find((i) => i.type === 'unconfirmed_zero');
		expect(issue).toBeDefined();
		expect(issue?.severity).toBe('high');
	});

	// R2: CertstreamEnumerateResponse.timedOut / CertstreamSansResponse.timedOut
	// are declared but were never read — a `{subdomains: [], timedOut: true}`
	// response was accepted as a confident zero.
	it('R2: a timed-out /enumerate response with an EMPTY list is not accepted as a confident zero — falls through to /sans', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const certstreamFetch = vi.fn(async (input: RequestInfo | URL) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
			if (url === 'https://certstream/enumerate?domain=example.com') {
				return Response.json({ domain: 'example.com', subdomains: [], certificateCount: 0, timedOut: true, cached: false });
			}
			if (url === 'https://certstream/sans?domain=example.com') {
				return Response.json({
					domain: 'example.com',
					names: ['api.example.com'],
					certificateCount: 1,
					timedOut: false,
					truncated: false,
					cached: false,
				});
			}
			throw new Error(`unexpected certstream URL: ${url}`);
		});
		globalThis.fetch = vi.fn(async () => {
			throw new Error('crt.sh fallback should not be used');
		});

		const result = await discoverSubdomains('example.com', { fetch: certstreamFetch as unknown as typeof fetch }, 'shared-internal-key');

		// The enumerate timeout must not have been treated as a final answer —
		// /sans had to be consulted.
		expect(certstreamFetch).toHaveBeenCalledTimes(2);
		expect(result.totalSubdomains).toBe(1);
		expect(result.subdomains.map((s) => s.subdomain)).toEqual(['api.example.com']);
		expect(result.sourceUnavailable).toBeFalsy();
	});

	it('R2: a timed-out /enumerate response WITH data is kept and marked partial, not suppressed', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const certstreamFetch = vi.fn(async (input: RequestInfo | URL) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
			if (url === 'https://certstream/enumerate?domain=example.com') {
				return Response.json({
					domain: 'example.com',
					subdomains: ['api.example.com'],
					certificateCount: 1,
					timedOut: true,
					cached: false,
				});
			}
			throw new Error(`unexpected certstream URL: ${url} (should not reach /sans — enumerate already had data)`);
		});
		globalThis.fetch = vi.fn(async () => {
			throw new Error('crt.sh fallback should not be used');
		});

		const result = await discoverSubdomains('example.com', { fetch: certstreamFetch as unknown as typeof fetch }, 'shared-internal-key');

		expect(certstreamFetch).toHaveBeenCalledTimes(1);
		expect(result.totalSubdomains).toBe(1);
		expect(result.subdomains.map((s) => s.subdomain)).toEqual(['api.example.com']);
		expect(result.partial).toBe(true);
		expect(result.sourceUnavailable).toBeFalsy();
	});

	it('R2: a timed-out /sans response with an empty list falls through to the direct public sources', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const certstreamFetch = vi.fn(async (input: RequestInfo | URL) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
			if (url === 'https://certstream/enumerate?domain=example.com') {
				return new Response(JSON.stringify({ error: 'upstream transient' }), {
					status: 502,
					headers: { 'Content-Type': 'application/json' },
				});
			}
			if (url === 'https://certstream/sans?domain=example.com') {
				return Response.json({ domain: 'example.com', names: [], certificateCount: 0, timedOut: true, truncated: false, cached: false });
			}
			throw new Error(`unexpected certstream URL: ${url}`);
		});
		mockCrtSh([{ name_value: 'fromcrtsh.example.com', issuer_name: 'CN=R3', not_before: '2026-01-01', not_after: '2026-04-01' }]);

		const result = await discoverSubdomains('example.com', { fetch: certstreamFetch as unknown as typeof fetch }, 'shared-internal-key');

		expect(result.subdomains.map((s) => s.subdomain)).toContain('fromcrtsh.example.com');
		expect(result.sourceUnavailable).toBeFalsy();
	});

	// R3: a first-source (crt.sh) HTTP-200 `[]` was treated as available:true
	// and short-circuited before Certspotter (the #562 cross-check) ever ran.
	it('R3: a first-source empty does not short-circuit — falls through to corroborate with the second source', async () => {
		let certspotterCalled = false;
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh')) return Response.json([], { status: 200 }); // empty
			if (s.includes('certspotter.com')) {
				certspotterCalled = true;
				return Response.json(
					[
						{
							dns_names: ['found.example.com'],
							issuer: { name: "C=US, O=Let's Encrypt, CN=R3" },
							not_before: '2026-01-01',
							not_after: '2026-04-01',
						},
					],
					{ status: 200 },
				);
			}
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});

		const result = await run();

		expect(certspotterCalled).toBe(true);
		expect(result.subdomains.map((s) => s.subdomain)).toContain('found.example.com');
		expect(result.sourceUnavailable).toBeFalsy();
	});

	it('R3: an empty confirmed by BOTH direct sources is still reported unconfirmed (issues[] carries the caution), not a clean 0', async () => {
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh')) return Response.json([], { status: 200 });
			if (s.includes('certspotter.com')) return Response.json([], { status: 200 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});

		const result = await run();

		expect(result.totalSubdomains).toBe(0);
		expect(result.sourceUnavailable).toBeFalsy();
		expect(result.issues.some((i) => i.type === 'unconfirmed_zero')).toBe(true);
	});
});

describe('formatSubdomainDiscovery', () => {
	async function getFormatter() {
		const { formatSubdomainDiscovery } = await import('../src/tools/discover-subdomains');
		return formatSubdomainDiscovery;
	}

	it('reports CT source unavailable distinctly from "none found"', async () => {
		const formatSubdomainDiscovery = await getFormatter();
		const result = {
			domain: 'github.com',
			totalSubdomains: 0,
			totalCertificates: 0,
			subdomains: [],
			wildcardCerts: 0,
			expiredCerts: 0,
			uniqueIssuers: [],
			issues: [],
			sourceUnavailable: true,
		};
		const output = formatSubdomainDiscovery(result, 'full');
		expect(output).toMatch(/unavailable|could not/i);
		expect(output).not.toMatch(/no subdomains found/i);
	});

	it('should format compact output correctly', async () => {
		const formatSubdomainDiscovery = await getFormatter();

		const result = {
			domain: 'example.com',
			totalSubdomains: 2,
			totalCertificates: 5,
			subdomains: [
				{
					subdomain: 'api.example.com',
					firstSeen: '2026-01-01',
					lastSeen: '2026-03-15',
					issuer: 'R3',
					certCount: 3,
					isWildcard: false,
					isExpired: false,
				},
				{
					subdomain: '*.example.com',
					firstSeen: '2026-01-01',
					lastSeen: '2026-03-20',
					issuer: 'DigiCert',
					certCount: 2,
					isWildcard: true,
					isExpired: false,
				},
			],
			wildcardCerts: 1,
			expiredCerts: 0,
			uniqueIssuers: ['R3', 'DigiCert'],
			issues: [],
		};

		const output = formatSubdomainDiscovery(result, 'compact');
		expect(output).toContain('Subdomain Discovery: example.com');
		expect(output).toContain('2 subdomains');
		expect(output).toContain('5 certificates');
		expect(output).toContain('api.example.com');
		expect(output).toContain('[WILDCARD]');
	});

	it('should format full output with headers and details', async () => {
		const formatSubdomainDiscovery = await getFormatter();

		const result = {
			domain: 'example.com',
			totalSubdomains: 1,
			totalCertificates: 1,
			subdomains: [
				{
					subdomain: 'old.example.com',
					firstSeen: '2023-01-01',
					lastSeen: '2023-01-01',
					issuer: 'R3',
					certCount: 1,
					isWildcard: false,
					isExpired: true,
				},
			],
			wildcardCerts: 0,
			expiredCerts: 1,
			uniqueIssuers: ['R3'],
			issues: [
				{
					type: 'expired_subdomain' as const,
					severity: 'medium' as const,
					detail: 'old.example.com has only expired certificates — may be abandoned',
				},
			],
		};

		const output = formatSubdomainDiscovery(result, 'full');
		expect(output).toContain('# Subdomain Discovery: example.com');
		expect(output).toContain('EXPIRED');
		expect(output).toContain('## Issues');
		expect(output).toContain('[MEDIUM]');
		expect(output).toContain('old.example.com');
	});

	it('should show empty message when no subdomains found', async () => {
		const formatSubdomainDiscovery = await getFormatter();

		const result = {
			domain: 'example.com',
			totalSubdomains: 0,
			totalCertificates: 0,
			subdomains: [],
			wildcardCerts: 0,
			expiredCerts: 0,
			uniqueIssuers: [],
			issues: [],
		};

		const output = formatSubdomainDiscovery(result, 'compact');
		expect(output).toContain('no subdomains found');
	});

	/**
	 * Final review round, item 2: `emptyResult` always attaches a high-severity
	 * `unconfirmed_zero` issue — CT logs are indirect evidence, so even a
	 * completed query cannot positively confirm zero subdomains (see
	 * `emptyResult`'s doc). The prose zero-branch used to render the bare "no
	 * subdomains found" sentence with no disclosure of that caveat — a
	 * confident prose surface next to an honest structured one, the exact
	 * split-surface defect this campaign closes elsewhere. The prose must now
	 * say the zero is unconfirmed, in wording consistent with the issue detail.
	 */
	it('R4 (final review, item 2): the zero-branch prose discloses the zero is unconfirmed, matching the structured unconfirmed_zero issue', async () => {
		const formatSubdomainDiscovery = await getFormatter();

		const result = {
			domain: 'example.com',
			totalSubdomains: 0,
			totalCertificates: 0,
			subdomains: [],
			wildcardCerts: 0,
			expiredCerts: 0,
			uniqueIssuers: [],
			issues: [
				{
					type: 'unconfirmed_zero' as const,
					severity: 'high' as const,
					detail:
						'No Certificate Transparency source has positively confirmed example.com has zero subdomains — CT logs only capture certificate issuance, so this is an unconfirmed measurement, not a verified absence.',
				},
			],
		};

		const output = formatSubdomainDiscovery(result, 'compact');
		expect(output).toContain('no subdomains found');
		expect(output.toLowerCase()).toContain('unconfirmed');
	});

	it('should show overflow count when subdomains are truncated', async () => {
		const formatSubdomainDiscovery = await getFormatter();

		const result = {
			domain: 'example.com',
			totalSubdomains: 150,
			totalCertificates: 150,
			subdomains: Array.from({ length: 100 }, (_, i) => ({
				subdomain: `sub${i}.example.com`,
				firstSeen: '2026-01-01',
				lastSeen: '2026-01-01',
				issuer: 'R3',
				certCount: 1,
				isWildcard: false,
				isExpired: false,
			})),
			wildcardCerts: 0,
			expiredCerts: 0,
			uniqueIssuers: ['R3'],
			issues: [],
		};

		const compactOutput = formatSubdomainDiscovery(result, 'compact');
		expect(compactOutput).toContain('...and 50 more');

		const fullOutput = formatSubdomainDiscovery(result, 'full');
		expect(fullOutput).toContain('50 more subdomains not shown');
	});

	it('formats a partial (timed-out-but-productive) result with a partial banner, distinct from stale', async () => {
		const formatSubdomainDiscovery = await getFormatter();

		const result = {
			domain: 'example.com',
			totalSubdomains: 1,
			totalCertificates: 1,
			subdomains: [
				{ subdomain: 'api.example.com', firstSeen: '', lastSeen: '', issuer: '', certCount: 1, isWildcard: false, isExpired: false },
			],
			wildcardCerts: 0,
			expiredCerts: 0,
			uniqueIssuers: [],
			issues: [],
			partial: true,
		};

		const output = formatSubdomainDiscovery(result, 'compact');
		expect(output).toMatch(/partial/i);
		expect(output).not.toMatch(/stale/i);
		expect(output).toContain('api.example.com');
	});
});

describe('discoverSubdomains — force_refresh threading', () => {
	afterEach(() => restore());

	function certstreamOk(seen: string[]) {
		return vi.fn(async (input: RequestInfo | URL) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
			seen.push(url);
			return new Response(
				JSON.stringify({ domain: 'example.com', subdomains: ['api.example.com'], certificateCount: 1, timedOut: false, cached: false }),
				{ status: 200, headers: { 'Content-Type': 'application/json' } },
			);
		});
	}

	it('threads force_refresh to the certstream endpoint so a stale cached result can be bypassed', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const seen: string[] = [];
		globalThis.fetch = vi.fn(async () => {
			throw new Error('crt.sh should not be used');
		});
		await discoverSubdomains('example.com', { fetch: certstreamOk(seen) as unknown as typeof fetch }, 'tok', { forceRefresh: true });
		expect(seen[0]).toContain('force_refresh=true');
	});

	it('does NOT add force_refresh when not requested (default cache behaviour)', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const seen: string[] = [];
		globalThis.fetch = vi.fn(async () => {
			throw new Error('crt.sh should not be used');
		});
		await discoverSubdomains('example.com', { fetch: certstreamOk(seen) as unknown as typeof fetch }, 'tok');
		expect(seen[0]).not.toContain('force_refresh');
	});
});

describe('discover_subdomains handler — loud degrade on CT-source outage', () => {
	afterEach(() => restore());

	it('returns isError:true (NOT a passing empty) when every CT source is unavailable', async () => {
		const { handleToolsCall } = await import('../src/handlers/tools');
		// certstream binding 503s → null; crt.sh 500s → sourceUnavailable.
		const certstreamFetch = vi.fn(async () => new Response('unavailable', { status: 503 }));
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh')) return Response.json({}, { status: 500 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});
		const result = await handleToolsCall({ name: 'discover_subdomains', arguments: { domain: 'example.com' } }, undefined, {
			certstream: { fetch: certstreamFetch as unknown as typeof fetch },
		} as never);
		expect(result.isError).toBe(true);
		expect((result.structuredContent as Record<string, unknown> | undefined)?.sourceUnavailable).toBe(true);
	});

	it('returns a normal (non-error) result when the source is available but finds nothing', async () => {
		const { handleToolsCall } = await import('../src/handlers/tools');
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh')) return Response.json([], { status: 200 }); // available, genuinely empty
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});
		const result = await handleToolsCall({ name: 'discover_subdomains', arguments: { domain: 'example.com' } }, undefined, undefined);
		expect(result.isError).toBeFalsy();
		expect((result.structuredContent as Record<string, unknown> | undefined)?.sourceUnavailable).toBeFalsy();
	});
});

// Phase 1 of the CT-source plan. Certspotter was queried UNAUTHENTICATED, so the
// per-IP, per-hour free quota was the binding constraint: measured 2026-08-21 it
// returned HTTP 429 `rate_limited` — "For a higher rate limit, please authenticate
// with an API key". bv-web-prod's `cloudflare/certstream` already sends the same
// secret as a Bearer token; this brings bv-mcp's own CT path in line.
//
// ⚠️ Deliberately NOT asserted here because it is NOT true: that a token fixes the
// large-estate failure. It does not. The free tier keeps a 15s per-query timeout,
// and `meta.com` still returns HTTP 504 authenticated (measured). That is #735's
// deterministic timeout and only a paid tier's longer timeout addresses it.
describe('discoverSubdomains — Certspotter authentication', () => {
	/** Capture the request init the CT sources are called with. */
	function captureCertspotter() {
		const calls: Array<{ url: string; auth: string | null }> = [];
		globalThis.fetch = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
			const headers = new Headers(init?.headers ?? {});
			calls.push({ url, auth: headers.get('authorization') });
			// crt.sh is down (502 all day 2026-08-21), forcing the Certspotter path.
			if (url.includes('crt.sh')) return Response.json({}, { status: 502 });
			if (url.includes('certspotter.com')) {
				return Response.json([{ id: '1', dns_names: ['api.example.com'], not_before: '2026-01-01', not_after: '2026-04-01' }], { status: 200 });
			}
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		}) as unknown as typeof fetch;
		return calls;
	}

	it('sends Authorization: Bearer on the Certspotter query when a token is configured', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const calls = captureCertspotter();

		await discoverSubdomains('example.com', undefined, undefined, { certspotterToken: 'test-sslmate-key' });

		const certspotter = calls.filter((c) => c.url.includes('certspotter.com'));
		expect(certspotter.length).toBeGreaterThan(0);
		expect(certspotter.every((c) => c.auth === 'Bearer test-sslmate-key')).toBe(true);
	});

	it('never leaks the token to a different CT source', async () => {
		// crt.sh is a separate operator with no relationship to the SSLMate key.
		// Broadcasting a credential to every upstream is how one source's outage
		// becomes another source's credential disclosure.
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const calls = captureCertspotter();

		await discoverSubdomains('example.com', undefined, undefined, { certspotterToken: 'test-sslmate-key' });

		expect(calls.filter((c) => c.url.includes('crt.sh')).every((c) => c.auth === null)).toBe(true);
	});

	it('stays unauthenticated and functional when no token is configured', async () => {
		// The control. A missing secret must DEGRADE recall, never break enumeration
		// — most self-hosts will never set one.
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const calls = captureCertspotter();

		const result = await discoverSubdomains('example.com');

		const certspotter = calls.filter((c) => c.url.includes('certspotter.com'));
		expect(certspotter.length).toBeGreaterThan(0);
		expect(certspotter.every((c) => c.auth === null)).toBe(true);
		expect(result.totalSubdomains).toBeGreaterThan(0);
	});
});
