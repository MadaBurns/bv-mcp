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
			return { ok, status: ok ? 200 : 500, json: () => Promise.resolve(response) };
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
		const expiredIssue = result.issues.find(
			(i) => i.type === 'expired_subdomain' && i.detail.includes('old.example.com'),
		);
		expect(expiredIssue).toBeDefined();
		expect(expiredIssue!.severity).toBe('medium');
	});

	it('should handle crt.sh being unavailable (fetch throws)', async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error('Network error'));
		const result = await run();

		expect(result.totalSubdomains).toBe(0);
		expect(result.subdomains).toHaveLength(0);
		expect(result.totalCertificates).toBe(0);
	});

	it('should handle crt.sh returning an error status', async () => {
		mockCrtSh(null, false);
		const result = await run();

		expect(result.totalSubdomains).toBe(0);
		expect(result.subdomains).toHaveLength(0);
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

	it('should limit output to 100 subdomains', async () => {
		// Generate 150 unique subdomains
		const manyEntries = Array.from({ length: 150 }, (_, i) => ({
			name_value: `sub${i}.example.com`,
			issuer_name: 'CN=R3',
			not_before: '2026-01-01',
			not_after: '2026-04-01',
		}));
		mockCrtSh(manyEntries);
		const result = await run();

		expect(result.subdomains).toHaveLength(100);
		expect(result.totalSubdomains).toBe(150);
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
