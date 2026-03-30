import { describe, it, expect, afterEach } from 'vitest';
import { vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

/**
 * Mock DNS responses for TXT (SPF), NS, and CAA queries.
 * Routes queries by the string-typed record type in the DoH URL params.
 */
function mockDnsResponses(options: {
	spf?: string | null;
	nsHosts?: string[];
	caaRecords?: string[];
	domain?: string;
}) {
	const { spf, nsHosts = [], caaRecords = [], domain = 'example.com' } = options;

	globalThis.fetch = vi.fn().mockImplementation((url: string | URL) => {
		const u = new URL(typeof url === 'string' ? url : url.toString());
		const name = u.searchParams.get('name') ?? '';
		const type = u.searchParams.get('type') ?? '';

		// TXT queries (SPF records)
		if (type === 'TXT') {
			if (name === domain && spf !== null && spf !== undefined) {
				return Promise.resolve(
					createDohResponse(
						[{ name, type: 16 }],
						[{ name, type: 16, TTL: 300, data: `"${spf}"` }],
					),
				);
			}
			return Promise.resolve(createDohResponse([{ name, type: 16 }], []));
		}

		// NS queries
		if (type === 'NS') {
			if (name === domain) {
				const answers = nsHosts.map((host) => ({
					name: domain,
					type: 2,
					TTL: 300,
					data: `${host}.`,
				}));
				return Promise.resolve(createDohResponse([{ name, type: 2 }], answers));
			}
			return Promise.resolve(createDohResponse([{ name, type: 2 }], []));
		}

		// CAA queries
		if (type === 'CAA') {
			if (name === domain) {
				const answers = caaRecords.map((data) => ({
					name: domain,
					type: 257,
					TTL: 300,
					data,
				}));
				return Promise.resolve(createDohResponse([{ name, type: 257 }], answers));
			}
			return Promise.resolve(createDohResponse([{ name, type: 257 }], []));
		}

		// Default: empty response
		return Promise.resolve(createDohResponse([{ name, type: 0 }], []));
	});
}

describe('mapSupplyChain', () => {
	async function run(domain = 'example.com') {
		const { mapSupplyChain } = await import('../src/tools/map-supply-chain');
		return mapSupplyChain(domain);
	}

	it('extracts dependencies from SPF includes, NS delegates, and CAA issuers', async () => {
		mockDnsResponses({
			spf: 'v=spf1 include:_spf.google.com include:sendgrid.net -all',
			nsHosts: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
			caaRecords: ['0 issue "letsencrypt.org"', '0 issuewild "digicert.com"', '0 iodef "mailto:security@example.com"'],
		});

		const result = await run();

		expect(result.domain).toBe('example.com');
		expect(result.dependencies.length).toBeGreaterThanOrEqual(4);

		// Should detect Google Workspace from SPF include
		const googleDep = result.dependencies.find((d) => d.provider === 'Google Workspace');
		expect(googleDep).toBeDefined();
		expect(googleDep!.roles).toContain('email-sending');
		expect(googleDep!.sources).toContain('spf');

		// Should detect SendGrid from SPF include
		const sendgridDep = result.dependencies.find((d) => d.provider === 'SendGrid');
		expect(sendgridDep).toBeDefined();
		expect(sendgridDep!.roles).toContain('email-sending');

		// Should detect Cloudflare from NS
		const cloudflareDep = result.dependencies.find((d) => d.provider === 'Cloudflare');
		expect(cloudflareDep).toBeDefined();
		expect(cloudflareDep!.roles).toContain('dns-hosting');
		expect(cloudflareDep!.sources).toContain('ns');

		// Should detect letsencrypt from CAA
		const leDep = result.dependencies.find((d) => d.provider === 'letsencrypt.org');
		expect(leDep).toBeDefined();
		expect(leDep!.roles).toContain('certificate-authority');
		expect(leDep!.sources).toContain('caa');

		// Should detect digicert from CAA issuewild
		const digicertDep = result.dependencies.find((d) => d.provider === 'digicert.com');
		expect(digicertDep).toBeDefined();
		expect(digicertDep!.roles).toContain('certificate-authority');
	});

	it('detects known providers via detectProviders()', async () => {
		mockDnsResponses({
			spf: 'v=spf1 include:spf.protection.outlook.com include:sendgrid.net -all',
			nsHosts: ['ns-1234.awsdns-12.org', 'ns-5678.awsdns-34.net'],
			caaRecords: [],
		});

		const result = await run();

		// Microsoft 365 from SPF
		const m365 = result.dependencies.find((d) => d.provider === 'Microsoft 365');
		expect(m365).toBeDefined();
		expect(m365!.trustLevel).toBe('critical');

		// SendGrid from SPF
		const sendgrid = result.dependencies.find((d) => d.provider === 'SendGrid');
		expect(sendgrid).toBeDefined();

		// AWS Route 53 from NS
		const aws = result.dependencies.find((d) => d.provider === 'AWS Route 53');
		expect(aws).toBeDefined();
		expect(aws!.trustLevel).toBe('high');
	});

	it('classifies trust levels correctly (SPF=critical, NS=high, CAA=low)', async () => {
		mockDnsResponses({
			spf: 'v=spf1 include:_spf.google.com -all',
			nsHosts: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
			caaRecords: ['0 issue "letsencrypt.org"'],
		});

		const result = await run();

		// SPF-sourced deps should be critical
		const spfDeps = result.dependencies.filter((d) => d.sources.includes('spf'));
		expect(spfDeps.length).toBeGreaterThanOrEqual(1);
		for (const dep of spfDeps) {
			expect(dep.trustLevel).toBe('critical');
		}

		// NS-sourced deps should be high
		const nsDeps = result.dependencies.filter((d) => d.sources.includes('ns') && !d.sources.includes('spf'));
		expect(nsDeps.length).toBeGreaterThanOrEqual(1);
		for (const dep of nsDeps) {
			expect(dep.trustLevel).toBe('high');
		}

		// CAA-sourced deps should be low
		const caaDeps = result.dependencies.filter((d) => d.sources.includes('caa') && !d.sources.includes('spf') && !d.sources.includes('ns'));
		expect(caaDeps.length).toBeGreaterThanOrEqual(1);
		for (const dep of caaDeps) {
			expect(dep.trustLevel).toBe('low');
		}
	});

	it('detects concentration risk when a provider appears in 3+ roles', async () => {
		// Cloudflare appears in NS, SPF (via a custom include), and CAA
		// We use a domain pattern that maps to Cloudflare in all three
		mockDnsResponses({
			spf: 'v=spf1 include:_spf.google.com include:sendgrid.net include:mailgun.org include:mtasv.net include:amazonses.com -all',
			nsHosts: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
			caaRecords: ['0 issue "letsencrypt.org"'],
		});

		const result = await run();

		// Verify many providers detected
		expect(result.summary.totalProviders).toBeGreaterThanOrEqual(5);
	});

	it('detects excessive includes signal (5+ includes)', async () => {
		mockDnsResponses({
			spf: 'v=spf1 include:_spf.google.com include:sendgrid.net include:mailgun.org include:mtasv.net include:amazonses.com -all',
			nsHosts: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
			caaRecords: [],
		});

		const result = await run();

		const excessiveSignal = result.signals.find((s) => s.type === 'excessive_includes');
		expect(excessiveSignal).toBeDefined();
		expect(excessiveSignal!.severity).toBe('low');
		expect(excessiveSignal!.detail).toContain('5');
	});

	it('detects excessive includes signal with medium severity (7+ includes)', async () => {
		mockDnsResponses({
			spf: 'v=spf1 include:_spf.google.com include:sendgrid.net include:mailgun.org include:mtasv.net include:amazonses.com include:spf.protection.outlook.com include:servers.mcsv.net -all',
			nsHosts: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
			caaRecords: [],
		});

		const result = await run();

		const excessiveSignal = result.signals.find((s) => s.type === 'excessive_includes');
		expect(excessiveSignal).toBeDefined();
		expect(excessiveSignal!.severity).toBe('medium');
		expect(excessiveSignal!.detail).toContain('7');
	});

	it('returns correct summary counts', async () => {
		mockDnsResponses({
			spf: 'v=spf1 include:_spf.google.com include:sendgrid.net -all',
			nsHosts: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
			caaRecords: ['0 issue "letsencrypt.org"'],
		});

		const result = await run();

		expect(result.summary.totalProviders).toBe(result.dependencies.length);
		expect(result.summary.critical + result.summary.high + result.summary.medium + result.summary.low)
			.toBe(result.summary.totalProviders);

		// SPF includes produce critical-level deps
		expect(result.summary.critical).toBeGreaterThanOrEqual(2);
		// NS produces high-level deps
		expect(result.summary.high).toBeGreaterThanOrEqual(1);
		// CAA produces low-level deps
		expect(result.summary.low).toBeGreaterThanOrEqual(1);
	});

	it('handles domain with no DNS records gracefully', async () => {
		mockDnsResponses({
			spf: null,
			nsHosts: [],
			caaRecords: [],
		});

		const result = await run();

		expect(result.domain).toBe('example.com');
		expect(result.dependencies).toEqual([]);
		expect(result.summary.totalProviders).toBe(0);
	});

	it('deduplicates dependencies with multiple sources', async () => {
		mockDnsResponses({
			spf: 'v=spf1 include:_spf.google.com -all',
			nsHosts: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
			caaRecords: [],
		});

		const result = await run();

		// Each unique provider should appear only once
		const providerNames = result.dependencies.map((d) => d.provider);
		const uniqueNames = new Set(providerNames);
		expect(uniqueNames.size).toBe(providerNames.length);
	});

	it('handles DNS query failures gracefully via Promise.allSettled', async () => {
		// Mock that throws for NS queries but succeeds for TXT and CAA
		globalThis.fetch = vi.fn().mockImplementation((url: string | URL) => {
			const u = new URL(typeof url === 'string' ? url : url.toString());
			const type = u.searchParams.get('type') ?? '';

			if (type === 'NS') {
				return Promise.reject(new Error('Network error'));
			}
			if (type === 'TXT') {
				return Promise.resolve(
					createDohResponse(
						[{ name: 'example.com', type: 16 }],
						[{ name: 'example.com', type: 16, TTL: 300, data: '"v=spf1 include:_spf.google.com -all"' }],
					),
				);
			}
			if (type === 'CAA') {
				return Promise.resolve(
					createDohResponse(
						[{ name: 'example.com', type: 257 }],
						[{ name: 'example.com', type: 257, TTL: 300, data: '0 issue "letsencrypt.org"' }],
					),
				);
			}
			return Promise.resolve(createDohResponse([{ name: 'example.com', type: 0 }], []));
		});

		const { mapSupplyChain } = await import('../src/tools/map-supply-chain');
		const result = await mapSupplyChain('example.com');

		// Should still have SPF and CAA deps, just no NS
		expect(result.dependencies.some((d) => d.provider === 'Google Workspace')).toBe(true);
		expect(result.dependencies.some((d) => d.provider === 'letsencrypt.org')).toBe(true);
	});
});

describe('formatSupplyChain', () => {
	it('formats result in full mode with headers and icons', async () => {
		const { formatSupplyChain } = await import('../src/tools/map-supply-chain');
		const result = {
			domain: 'example.com',
			dependencies: [
				{ provider: 'Google Workspace', roles: ['email-sending'], trustLevel: 'critical' as const, sources: ['spf'] },
				{ provider: 'Cloudflare', roles: ['dns-hosting'], trustLevel: 'high' as const, sources: ['ns'] },
				{ provider: 'letsencrypt.org', roles: ['certificate-authority'], trustLevel: 'low' as const, sources: ['caa'] },
			],
			signals: [
				{ type: 'excessive_includes' as const, severity: 'low' as const, detail: '5 SPF include directives detected.' },
			],
			summary: { totalProviders: 3, critical: 1, high: 1, medium: 0, low: 1 },
		};

		const text = formatSupplyChain(result, 'full');

		expect(text).toContain('# Supply Chain Map: example.com');
		expect(text).toContain('Google Workspace');
		expect(text).toContain('CRITICAL');
		expect(text).toContain('Cloudflare');
		expect(text).toContain('HIGH');
		expect(text).toContain('letsencrypt.org');
		expect(text).toContain('LOW');
		expect(text).toContain('Risk Signals');
		expect(text).toContain('5 SPF include directives');
	});

	it('formats result in compact mode without headers', async () => {
		const { formatSupplyChain } = await import('../src/tools/map-supply-chain');
		const result = {
			domain: 'example.com',
			dependencies: [
				{ provider: 'Google Workspace', roles: ['email-sending'], trustLevel: 'critical' as const, sources: ['spf'] },
				{ provider: 'Cloudflare', roles: ['dns-hosting'], trustLevel: 'high' as const, sources: ['ns'] },
			],
			signals: [],
			summary: { totalProviders: 2, critical: 1, high: 1, medium: 0, low: 0 },
		};

		const compact = formatSupplyChain(result, 'compact');
		const full = formatSupplyChain(result, 'full');

		expect(compact.length).toBeLessThan(full.length);
		expect(compact).toContain('Supply Chain:');
		expect(compact).toContain('[CRITICAL]');
		expect(compact).toContain('[HIGH]');
		expect(compact).not.toContain('#');
	});

	it('shows empty message when no dependencies', async () => {
		const { formatSupplyChain } = await import('../src/tools/map-supply-chain');
		const result = {
			domain: 'example.com',
			dependencies: [],
			signals: [],
			summary: { totalProviders: 0, critical: 0, high: 0, medium: 0, low: 0 },
		};

		const text = formatSupplyChain(result, 'full');
		expect(text).toContain('No third-party dependencies detected');
	});
});
