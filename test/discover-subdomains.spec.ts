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
