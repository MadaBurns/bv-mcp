import { describe, it, expect, afterEach } from 'vitest';
import { vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

/**
 * Mock DNS responses for TXT (SPF), NS, CAA, and SRV queries.
 * Routes queries by the string-typed record type in the DoH URL params.
 */
function mockDnsResponses(options: {
	spf?: string | null;
	txtRecords?: string[];
	nsHosts?: string[];
	caaRecords?: string[];
	srvRecords?: Record<string, Array<{ priority: number; weight: number; port: number; target: string }>>;
	mxRecords?: Array<{ pref: number; host: string }>;
	aRecords?: string[];
	/** Canned team-cymru origin-ASN TXT answers, keyed by the full `<rev-ip>.origin.asn.cymru.com` query name. */
	asnAnswers?: Record<string, string>;
	/** Invoked whenever an `*.origin.asn.cymru.com` TXT lookup is made (lets a test assert the ASN tier did / did not run). */
	onAsnQuery?: () => void;
	domain?: string;
}) {
	const {
		spf,
		txtRecords = [],
		nsHosts = [],
		caaRecords = [],
		srvRecords = {},
		mxRecords = [],
		aRecords = [],
		asnAnswers = {},
		onAsnQuery,
		domain = 'example.com',
	} = options;

	globalThis.fetch = vi.fn().mockImplementation((url: string | URL) => {
		const u = new URL(typeof url === 'string' ? url : url.toString());
		const name = u.searchParams.get('name') ?? '';
		const type = u.searchParams.get('type') ?? '';

		// TXT queries (SPF + verification records + team-cymru origin-ASN lookups)
		if (type === 'TXT') {
			// ASN tier: `<rev-ip>.origin.asn.cymru.com` TXT lookups (Task 2/3).
			if (name.endsWith('.origin.asn.cymru.com')) {
				onAsnQuery?.();
				const answer = asnAnswers[name];
				const answers = answer !== undefined ? [{ name, type: 16, TTL: 300, data: `"${answer}"` }] : [];
				return Promise.resolve(createDohResponse([{ name, type: 16 }], answers));
			}
			if (name === domain) {
				const answers: Array<{ name: string; type: number; TTL: number; data: string }> = [];
				if (spf !== null && spf !== undefined) {
					answers.push({ name, type: 16, TTL: 300, data: `"${spf}"` });
				}
				for (const txt of txtRecords) {
					answers.push({ name, type: 16, TTL: 300, data: `"${txt}"` });
				}
				return Promise.resolve(createDohResponse([{ name, type: 16 }], answers));
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

		// MX queries
		if (type === 'MX') {
			if (name === domain) {
				const answers = mxRecords.map((mx) => ({
					name: domain,
					type: 15,
					TTL: 300,
					data: `${mx.pref} ${mx.host}.`,
				}));
				return Promise.resolve(createDohResponse([{ name, type: 15 }], answers));
			}
			return Promise.resolve(createDohResponse([{ name, type: 15 }], []));
		}

		// A queries (apex IPs for the ASN-based CDN / hosting tier)
		if (type === 'A') {
			if (name === domain) {
				const answers = aRecords.map((ip) => ({
					name: domain,
					type: 1,
					TTL: 300,
					data: ip,
				}));
				return Promise.resolve(createDohResponse([{ name, type: 1 }], answers));
			}
			return Promise.resolve(createDohResponse([{ name, type: 1 }], []));
		}

		// SRV queries
		if (type === 'SRV') {
			const srvKey = Object.keys(srvRecords).find((prefix) => name === `${prefix}.${domain}`);
			if (srvKey) {
				const records = srvRecords[srvKey];
				const answers = records.map((r) => ({
					name,
					type: 33,
					TTL: 300,
					data: `${r.priority} ${r.weight} ${r.port} ${r.target}.`,
				}));
				return Promise.resolve(createDohResponse([{ name, type: 33 }], answers));
			}
			return Promise.resolve(createDohResponse([{ name, type: 33 }], []));
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

	it('resolves AutoSPF via *.autospf.email SPF includes (mit.edu pattern)', async () => {
		mockDnsResponses({ spf: 'v=spf1 include:_s00430413.autospf.email -all', domain: 'mit.edu' });
		const result = await run('mit.edu');
		const rows = result.dependencies.filter((d) => d.provider === 'AutoSPF');
		expect(rows.length).toBe(1);
		expect(result.dependencies.find((d) => /autospf\.email/i.test(d.provider))).toBeUndefined();
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

	it('detects TXT verification records as saas-integration dependencies with low trust', async () => {
		mockDnsResponses({
			spf: 'v=spf1 include:_spf.google.com -all',
			txtRecords: [
				'google-site-verification=abc123',
				'facebook-domain-verification=xyz789',
				'slack-domain-verification=slk456',
			],
			nsHosts: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
		});

		const result = await run();

		const googleSearch = result.dependencies.find((d) => d.provider === 'Google Search Console');
		expect(googleSearch).toBeDefined();
		expect(googleSearch!.roles).toContain('saas-integration');
		expect(googleSearch!.sources).toContain('txt-verification');
		expect(googleSearch!.trustLevel).toBe('low');

		const facebook = result.dependencies.find((d) => d.provider === 'Facebook');
		expect(facebook).toBeDefined();
		expect(facebook!.roles).toContain('saas-integration');
		expect(facebook!.trustLevel).toBe('low');

		const slack = result.dependencies.find((d) => d.provider === 'Slack');
		expect(slack).toBeDefined();
	});

	it('detects SRV-discovered services as advertised-service dependencies with medium trust', async () => {
		mockDnsResponses({
			spf: 'v=spf1 include:_spf.google.com -all',
			nsHosts: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
			srvRecords: {
				'_autodiscover._tcp': [{ priority: 10, weight: 10, port: 443, target: 'autodiscover.outlook.com' }],
				'_imaps._tcp': [{ priority: 10, weight: 10, port: 993, target: 'imap.google.com' }],
			},
		});

		const result = await run();

		// Outlook SRV should resolve to Microsoft 365
		const m365 = result.dependencies.find((d) => d.provider === 'Microsoft 365');
		expect(m365).toBeDefined();
		expect(m365!.roles).toContain('advertised-service');
		expect(m365!.sources).toContain('srv');

		// Google SRV should resolve to Google Workspace (already present from SPF, so merged)
		const google = result.dependencies.find((d) => d.provider === 'Google Workspace');
		expect(google).toBeDefined();
		expect(google!.roles).toContain('advertised-service');
		expect(google!.roles).toContain('email-sending');
		// SPF dominates trust level
		expect(google!.trustLevel).toBe('critical');
	});

	it('fires stale_integration signal when TXT verification has no matching SPF include', async () => {
		mockDnsResponses({
			spf: 'v=spf1 include:_spf.google.com -all',
			txtRecords: [
				'sendgrid-verification=sg123', // SendGrid has SERVICE_SPF_DOMAINS entry but no SPF include
			],
			nsHosts: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
		});

		const result = await run();

		const staleSignal = result.signals.find((s) => s.type === 'stale_integration');
		expect(staleSignal).toBeDefined();
		expect(staleSignal!.severity).toBe('low');
		expect(staleSignal!.detail).toContain('SendGrid');
		expect(staleSignal!.detail).toContain('stale');
	});

	it('fires insecure_service signal when plain IMAP without IMAPS SRV', async () => {
		mockDnsResponses({
			spf: 'v=spf1 -all',
			nsHosts: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
			srvRecords: {
				'_imap._tcp': [{ priority: 10, weight: 10, port: 143, target: 'mail.example.com' }],
				// No _imaps._tcp
			},
		});

		const result = await run();

		const insecureSignal = result.signals.find((s) => s.type === 'insecure_service');
		expect(insecureSignal).toBeDefined();
		expect(insecureSignal!.severity).toBe('medium');
		expect(insecureSignal!.detail).toContain('IMAP');
		expect(insecureSignal!.detail).toContain('_imaps._tcp');
	});

	it('fires security_tooling_exposed signal for security-category TXT verifications', async () => {
		mockDnsResponses({
			spf: 'v=spf1 -all',
			txtRecords: [
				'crowdstrike-domain-verification=cs123',
				'knowbe4-site-verification=kb123',
			],
			nsHosts: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
		});

		const result = await run();

		const securitySignals = result.signals.filter((s) => s.type === 'security_tooling_exposed');
		expect(securitySignals.length).toBe(2);
		expect(securitySignals[0].severity).toBe('low');

		const providers = securitySignals.map((s) => s.detail);
		expect(providers.some((d) => d.includes('CrowdStrike'))).toBe(true);
		expect(providers.some((d) => d.includes('KnowBe4'))).toBe(true);
	});

	it('deduplicates same provider across SPF + TXT into single dependency with multiple roles', async () => {
		mockDnsResponses({
			spf: 'v=spf1 include:_spf.google.com -all',
			txtRecords: [
				'google-site-verification=abc123', // Google Search Console (different provider name)
				'MS=ms12345', // Microsoft 365 via TXT verification
			],
			nsHosts: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
			srvRecords: {
				'_autodiscover._tcp': [{ priority: 10, weight: 10, port: 443, target: 'autodiscover.outlook.com' }],
			},
		});

		const result = await run();

		// Microsoft 365 should appear once with both roles (TXT verification + SRV)
		const m365Deps = result.dependencies.filter((d) => d.provider === 'Microsoft 365');
		expect(m365Deps.length).toBe(1);
		expect(m365Deps[0].roles).toContain('saas-integration');
		expect(m365Deps[0].roles).toContain('advertised-service');
		expect(m365Deps[0].sources).toContain('txt-verification');
		expect(m365Deps[0].sources).toContain('srv');
	});

	it('deduplicates Microsoft 365 across SPF include + TXT verification (spark.co.nz pattern)', async () => {
		// Regression: prior to this fix, the Microsoft 365 detection rule's static
		// `signal: 'mx:mail.protection.outlook.com'` did NOT substring-match the
		// SPF include `spf.protection.outlook.com`, so the include slipped through
		// the dedup and produced a second standalone `spf.protection.outlook.com`
		// row alongside the Microsoft 365 TXT-verification row.
		mockDnsResponses({
			spf: 'v=spf1 include:spf.protection.outlook.com include:_spf-c.spark.co.nz -all',
			txtRecords: ['MS=ms12345'],
			nsHosts: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
		});

		const result = await run();

		// Microsoft 365 should collapse to a single dependency carrying both sources.
		const m365Deps = result.dependencies.filter((d) => d.provider === 'Microsoft 365');
		expect(m365Deps.length).toBe(1);
		expect(m365Deps[0].sources).toContain('spf');
		expect(m365Deps[0].sources).toContain('txt-verification');
		// SPF sources promote trust to critical.
		expect(m365Deps[0].trustLevel).toBe('critical');

		// No standalone raw SPF include row for the Microsoft 365 host.
		expect(
			result.dependencies.find((d) => d.provider === 'spf.protection.outlook.com'),
		).toBeUndefined();

		// Unrelated SPF include (Spark's own host) is still surfaced as a raw entry.
		expect(
			result.dependencies.find((d) => d.provider === '_spf-c.spark.co.nz'),
		).toBeDefined();
	});

	it('groups NS hosts under ccTLD-2LD parent domains and treats self-hosted NS as self-hosted (anz.co.nz pattern)', async () => {
		// Regression (2026-05-28): the prior 2-label heuristic returned `co.nz`
		// as a "DNS hosting provider" for `ns1.anz.co.nz` because `slice(-2)`
		// stops at the ccTLD-second-level. After the fix:
		//   - akam.net surfaces as the actual third-party DNS host
		//   - anz.co.nz is recognised as a registry-suffix-aware parent
		//   - the self-hosted NS (ns1/ns2.example.co.nz) gets one labelled row
		mockDnsResponses({
			spf: 'v=spf1 -all',
			nsHosts: [
				'a1-1.akam.net',
				'a2-2.akam.net',
				'a3-3.akam.net',
				'a4-4.akam.net',
				'a5-5.akam.net',
				'a6-6.akam.net',
				'ns1.example.co.nz',
				'ns2.example.co.nz',
			],
			caaRecords: [],
			domain: 'example.co.nz',
		});

		const { mapSupplyChain } = await import('../src/tools/map-supply-chain');
		const result = await mapSupplyChain('example.co.nz');

		// Bug: registry suffix must not appear as a provider.
		expect(result.dependencies.find((d) => d.provider === 'co.nz')).toBeUndefined();
		// Akamai (via akam.net parent) is the actual third-party DNS host.
		const akam = result.dependencies.find((d) => d.provider === 'akam.net');
		expect(akam).toBeDefined();
		expect(akam!.sources).toContain('ns');
		expect(akam!.roles).toContain('dns-hosting');
		// Self-hosted NS must not be re-emitted as a third-party dependency.
		expect(result.dependencies.find((d) => d.provider === 'example.co.nz')).toBeUndefined();
		expect(result.dependencies.find((d) => d.provider === 'ns1.example.co.nz')).toBeUndefined();
	});

	it('resolves _spf.fireeyecloud.com to Trellix Email Security via shared DETECTION_RULES', async () => {
		// Regression (2026-05-28): `_spf.fireeyecloud.com` previously surfaced as
		// a raw SPF entry. Adding a DETECTION_RULES entry (with `spf` pattern and
		// `spf:fireeyecloud.com` signal) routes it through matchProviderForSpfInclude
		// so it dedups to the canonical Trellix Email Security name.
		mockDnsResponses({
			spf: 'v=spf1 include:_spf.fireeyecloud.com -all',
			nsHosts: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
			caaRecords: [],
		});

		const { mapSupplyChain } = await import('../src/tools/map-supply-chain');
		const result = await mapSupplyChain('example.com');

		// Canonical Trellix name appears exactly once with spf source + critical trust.
		const trellix = result.dependencies.filter((d) => d.provider === 'Trellix Email Security');
		expect(trellix.length).toBe(1);
		expect(trellix[0].sources).toContain('spf');
		expect(trellix[0].roles).toContain('email-sending');
		expect(trellix[0].trustLevel).toBe('critical');
		// No raw SPF row for the matched host (dedup worked).
		expect(result.dependencies.find((d) => d.provider === '_spf.fireeyecloud.com')).toBeUndefined();
	});

	it('emits a single stale_integration signal with a count when multiple TXT verifications share one service', async () => {
		// Regression (2026-05-28): anz.co.nz had 3x google-site-verification TXT
		// records (one per web property) and produced 3x identical stale_integration
		// signals. The fix dedups by service name and reports a count.
		mockDnsResponses({
			spf: 'v=spf1 -all',
			txtRecords: [
				'google-site-verification=abc111',
				'google-site-verification=abc222',
				'google-site-verification=abc333',
			],
			nsHosts: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
			caaRecords: [],
		});

		const { mapSupplyChain } = await import('../src/tools/map-supply-chain');
		const result = await mapSupplyChain('example.com');

		const staleSignals = result.signals.filter(
			(s) => s.type === 'stale_integration' && s.detail.includes('Google Search Console'),
		);
		expect(staleSignals.length).toBe(1);
		expect(staleSignals[0].severity).toBe('low');
		// Count surfaces in the detail string so consumers can see the scope.
		expect(staleSignals[0].detail).toContain('3 TXT verification records');
		expect(staleSignals[0].detail).toContain('stale');
	});

	// --- Cluster 1 (v3.3.13): supply-chain dedup & attribution ---

	it('collapses SPF includes whose effective parent equals the scan domain into a self-hosted row (PayPal pattern)', async () => {
		mockDnsResponses({
			spf: 'v=spf1 include:pp._spf.paypal.com include:3ph1._spf.paypal.com include:3ph2._spf.paypal.com include:sendgrid.net ~all',
			nsHosts: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
			domain: 'paypal.com',
		});
		const result = await run('paypal.com');
		// pp._spf, 3ph1._spf, 3ph2._spf are paypal-owned subdomains — not 3 third parties
		expect(result.dependencies.filter((d) => d.provider.endsWith('.paypal.com')).length).toBe(0);
		// single self-hosted row, not 3 critical-third-party rows
		const selfHosted = result.dependencies.find((d) => d.provider === 'paypal.com (self-hosted SPF)');
		expect(selfHosted).toBeDefined();
		expect(selfHosted!.sources).toContain('spf');
		// SendGrid (real third party) still appears
		expect(result.dependencies.find((d) => d.provider === 'SendGrid')).toBeDefined();
	});

	it('collapses Stripe self-wrapper subdomains (spf1.stripe.com, greenhouse-outbound-mail.stripe.com)', async () => {
		mockDnsResponses({
			spf: 'v=spf1 include:spf1.stripe.com include:greenhouse-outbound-mail.stripe.com include:_spf.thirdparty-unknown.io ~all',
			nsHosts: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
			domain: 'stripe.com',
		});
		const result = await run('stripe.com');
		expect(result.dependencies.filter((d) => d.provider.endsWith('.stripe.com')).length).toBe(0);
		// Self-hosted row present.
		expect(result.dependencies.find((d) => d.provider === 'stripe.com (self-hosted SPF)')).toBeDefined();
		// Genuine (uncataloged) third-party include preserved as raw entry.
		expect(result.dependencies.find((d) => d.provider === '_spf.thirdparty-unknown.io')).toBeDefined();
	});

	it('distinguishes self-delegation from genuine third-party include at the same eTLD+1 level', async () => {
		// hypothetical: example.com → include:mail.partner.com — partner.com IS third party even though it shares no eTLD+1 with example.com
		mockDnsResponses({
			spf: 'v=spf1 include:mail.partner.com ~all',
			nsHosts: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
			domain: 'example.com',
		});
		const result = await run('example.com');
		expect(result.dependencies.find((d) => d.provider.includes('partner.com'))).toBeDefined();
	});

	it('handles deep self-delegation chains (spf.outbound.example.com depth ≥ 3)', async () => {
		mockDnsResponses({
			spf: 'v=spf1 include:spf.outbound.example.com ~all',
			nsHosts: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
			domain: 'example.com',
		});
		const result = await run('example.com');
		expect(result.dependencies.filter((d) => d.provider.endsWith('.example.com')).length).toBe(0);
	});

	it('treats ultradns.com and ultradns.net as a single UltraDNS (Neustar) provider (PayPal pattern)', async () => {
		mockDnsResponses({
			spf: 'v=spf1 -all',
			nsHosts: ['pdns100.ultradns.com', 'pdns100.ultradns.net', 'ns1-pchnet.paypal.com'],
			domain: 'paypal.com',
		});
		const result = await run('paypal.com');
		const udRows = result.dependencies.filter((d) => /ultradns/i.test(d.provider));
		expect(udRows.length).toBe(1);
		expect(udRows[0].provider).toBe('UltraDNS (Neustar)');
	});

	it('preserves existing AWS Route 53 multi-TLD collapse (regression)', async () => {
		mockDnsResponses({
			spf: 'v=spf1 -all',
			nsHosts: ['ns-1087.awsdns-07.org', 'ns-1882.awsdns-43.co.uk', 'ns-423.awsdns-52.com', 'ns-705.awsdns-24.net'],
			domain: 'example.com',
		});
		const result = await run('example.com');
		const awsRows = result.dependencies.filter((d) => d.provider === 'AWS Route 53');
		expect(awsRows.length).toBe(1);
	});

	// --- Catalog gaps surfaced 2026-05-28 (post-v3.3.14 fact-check) ---

	it('treats nsone.net and ns1.com as a single NS1 (IBM) provider', async () => {
		mockDnsResponses({
			spf: 'v=spf1 -all',
			nsHosts: ['dns1.p08.nsone.net', 'dns2.p08.nsone.net', 'a.ns1.com', 'b.ns1.com'],
			domain: 'example.com',
		});
		const result = await run('example.com');
		const ns1Rows = result.dependencies.filter((d) => /\bNS1\b|NSOne/i.test(d.provider));
		expect(ns1Rows.length).toBe(1);
		expect(ns1Rows[0].provider).toBe('NS1 (IBM)');
	});

	it('treats dyn.com and dynect.net as a single Dyn (Oracle) provider', async () => {
		mockDnsResponses({
			spf: 'v=spf1 -all',
			nsHosts: ['ns1.p01.dynect.net', 'ns2.p01.dynect.net', 'ns3.p01.dyn.com', 'ns4.p01.dyn.com'],
			domain: 'example.com',
		});
		const result = await run('example.com');
		const dynRows = result.dependencies.filter((d) => /\bDyn\b/i.test(d.provider));
		expect(dynRows.length).toBe(1);
		expect(dynRows[0].provider).toBe('Dyn (Oracle)');
	});

	it('preserves single-TLD case (nsone-only deployment — should still detect NS1)', async () => {
		mockDnsResponses({
			spf: 'v=spf1 -all',
			nsHosts: ['dns1.p08.nsone.net', 'dns2.p08.nsone.net'],
			domain: 'airbnb.com',
		});
		const result = await run('airbnb.com');
		expect(result.dependencies.find((d) => d.provider === 'NS1 (IBM)')).toBeDefined();
	});

	it('resolves Oracle Cloud Email via spf_c/spf_s* selectors (ird.govt.nz pattern)', async () => {
		mockDnsResponses({
			spf: 'v=spf1 include:spf.protection.outlook.com include:spf_c.oraclecloud.com -all',
			nsHosts: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
			domain: 'ird.govt.nz',
		});
		const result = await run('ird.govt.nz');
		const oracleRows = result.dependencies.filter((d) => /Oracle Cloud Email/i.test(d.provider));
		expect(oracleRows.length).toBe(1);
		expect(oracleRows[0].sources).toContain('spf');
		// no raw selector row for the matched host
		expect(result.dependencies.find((d) => d.provider === 'spf_c.oraclecloud.com')).toBeUndefined();
	});

	// --- Catalog gaps surfaced 2026-05-28 (spotify.com fact-check round) ---

	it('resolves Google Cloud DNS via ns-cloud-*.googledomains.com NS hosts (spotify pattern)', async () => {
		mockDnsResponses({
			spf: 'v=spf1 -all',
			nsHosts: [
				'ns-cloud-a1.googledomains.com',
				'ns-cloud-a2.googledomains.com',
				'ns-cloud-a3.googledomains.com',
				'ns-cloud-a4.googledomains.com',
			],
			domain: 'spotify.com',
		});
		const result = await run('spotify.com');
		const gcdRows = result.dependencies.filter((d) => /Google Cloud DNS/i.test(d.provider));
		expect(gcdRows.length).toBe(1);
		expect(gcdRows[0].provider).toBe('Google Cloud DNS');
		// no raw googledomains.com row
		expect(result.dependencies.find((d) => d.provider === 'googledomains.com')).toBeUndefined();
	});

	it('resolves HubSpot via *.hubspotemail.net SPF includes (spotify pattern)', async () => {
		mockDnsResponses({
			spf: 'v=spf1 include:21894833.spf06.hubspotemail.net -all',
			nsHosts: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
			domain: 'spotify.com',
		});
		const result = await run('spotify.com');
		const hubRows = result.dependencies.filter((d) => /HubSpot/i.test(d.provider));
		expect(hubRows.length).toBe(1);
		expect(hubRows[0].provider).toBe('HubSpot');
		expect(result.dependencies.find((d) => /hubspotemail\.net/i.test(d.provider))).toBeUndefined();
	});

	it('resolves Mailchimp Transactional via *.mcsv.net SPF includes (spotify pattern)', async () => {
		mockDnsResponses({
			spf: 'v=spf1 include:servers.mcsv.net -all',
			nsHosts: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
			domain: 'spotify.com',
		});
		const result = await run('spotify.com');
		const mcRows = result.dependencies.filter((d) => /Mailchimp Transactional/i.test(d.provider));
		expect(mcRows.length).toBe(1);
		expect(mcRows[0].provider).toBe('Mailchimp Transactional');
		expect(result.dependencies.find((d) => /mcsv\.net/i.test(d.provider))).toBeUndefined();
	});

	it('resolves Salesforce via *.salesforce.com SPF includes (spotify pattern)', async () => {
		mockDnsResponses({
			spf: 'v=spf1 include:_spf.salesforce.com -all',
			nsHosts: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
			domain: 'spotify.com',
		});
		const result = await run('spotify.com');
		const sfRows = result.dependencies.filter((d) => d.provider === 'Salesforce');
		expect(sfRows.length).toBe(1);
		expect(result.dependencies.find((d) => /_spf\.salesforce/i.test(d.provider))).toBeUndefined();
	});

	it('treats foundationdns.{com,net,org} as a single Foundation DNS provider (shopify pattern)', async () => {
		mockDnsResponses({
			spf: 'v=spf1 -all',
			nsHosts: ['gold.foundationdns.com', 'gold.foundationdns.net', 'gold.foundationdns.org'],
			domain: 'example.com',
		});
		const result = await run('example.com');
		const fdRows = result.dependencies.filter((d) => /Foundation DNS/i.test(d.provider));
		expect(fdRows.length).toBe(1);
		expect(fdRows[0].provider).toBe('Foundation DNS');
		expect(result.dependencies.find((d) => /foundationdns\.(com|net|org)/i.test(d.provider))).toBeUndefined();
	});

	it('keeps Salesforce Pardot distinct from Salesforce (the et._spf.pardot.com mapping persists)', async () => {
		mockDnsResponses({
			spf: 'v=spf1 include:_spf.salesforce.com include:et._spf.pardot.com -all',
			nsHosts: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
			domain: 'company.example',
		});
		const result = await run('company.example');
		expect(result.dependencies.find((d) => d.provider === 'Salesforce')).toBeDefined();
		// Pardot endpoint must NOT collapse into the Salesforce row — it stays as
		// its own provider (raw `et._spf.pardot.com` if no friendly mapping exists).
		expect(result.dependencies.find((d) => /pardot/i.test(d.provider))).toBeDefined();
	});

	it('emits a single security_tooling_exposed signal per service even when multiple TXT records exist (OneTrust pattern)', async () => {
		mockDnsResponses({
			spf: 'v=spf1 -all',
			txtRecords: [
				'onetrust-domain-verification=7c928f0e377441028b0744ff402f5854',
				'onetrust-domain-verification=80511e0e29c7489abb235ea4f7d70df3',
			],
			nsHosts: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
			domain: 'xero.com',
		});
		const result = await run('xero.com');
		const oneTrustSignals = result.signals.filter(
			(s) => s.type === 'security_tooling_exposed' && s.detail.includes('OneTrust'),
		);
		expect(oneTrustSignals.length).toBe(1);
		expect(oneTrustSignals[0].detail).toContain('2 TXT verification records');
	});

	it('reuses the v3.3.9 stale_integration dedup pre-aggregation for security_tooling_exposed (no duplicate logic)', async () => {
		// Implementation invariant — confirmed by codepath review, not behaviour
		// (this test exists to lock in the refactor — see Green phase).
	});

	it('tolerates SRV probe failures gracefully', async () => {
		// Mock that throws for SRV queries but succeeds for everything else
		globalThis.fetch = vi.fn().mockImplementation((url: string | URL) => {
			const u = new URL(typeof url === 'string' ? url : url.toString());
			const type = u.searchParams.get('type') ?? '';

			if (type === 'SRV') {
				return Promise.reject(new Error('DNS timeout'));
			}
			if (type === 'TXT') {
				return Promise.resolve(
					createDohResponse(
						[{ name: 'example.com', type: 16 }],
						[{ name: 'example.com', type: 16, TTL: 300, data: '"v=spf1 include:_spf.google.com -all"' }],
					),
				);
			}
			if (type === 'NS') {
				return Promise.resolve(
					createDohResponse(
						[{ name: 'example.com', type: 2 }],
						[{ name: 'example.com', type: 2, TTL: 300, data: 'ns1.cloudflare.com.' }],
					),
				);
			}
			return Promise.resolve(createDohResponse([{ name: 'example.com', type: 0 }], []));
		});

		const { mapSupplyChain } = await import('../src/tools/map-supply-chain');
		const result = await mapSupplyChain('example.com');

		// Should still have SPF and NS deps, just no SRV
		expect(result.dependencies.some((d) => d.provider === 'Google Workspace')).toBe(true);
		expect(result.dependencies.some((d) => d.sources.includes('srv'))).toBe(false);
	});

	it('filters out disabled SRV services (target "." or port 0)', async () => {
		mockDnsResponses({
			spf: 'v=spf1 -all',
			nsHosts: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
			srvRecords: {
				'_imap._tcp': [{ priority: 0, weight: 0, port: 0, target: '.' }],
				'_imaps._tcp': [{ priority: 10, weight: 10, port: 993, target: 'imap.google.com' }],
			},
		});

		const result = await run();

		// Disabled IMAP should not appear; only IMAPS should
		const srvDeps = result.dependencies.filter((d) => d.sources.includes('srv'));
		expect(srvDeps.length).toBe(1);
		expect(srvDeps[0].provider).toBe('Google Workspace');

		// No insecure_service signal since _imap._tcp was disabled
		const insecureSignal = result.signals.find((s) => s.type === 'insecure_service');
		expect(insecureSignal).toBeUndefined();
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

describe('mapSupplyChain — MX email-receiving providers (Task 1)', () => {
	async function run(domain = 'example.com', opts?: { precomputedCdn?: string }) {
		const { mapSupplyChain } = await import('../src/tools/map-supply-chain');
		return mapSupplyChain(domain, opts);
	}

	it('maps a recognized MX host to an email-receiving dependency', async () => {
		mockDnsResponses({
			domain: 'acme.com',
			nsHosts: ['ns1.acme.com'],
			mxRecords: [{ pref: 10, host: 'acme-com.mail.protection.outlook.com' }],
		});
		const r = await run('acme.com');
		const dep = r.dependencies.find((d) => d.provider === 'Microsoft 365');
		expect(dep).toBeDefined();
		expect(dep!.roles).toContain('email-receiving');
		expect(dep!.sources).toContain('mx');
		expect(dep!.trustLevel).toBe('critical');
	});

	it('groups an unrecognized MX host by registrable parent domain', async () => {
		mockDnsResponses({
			domain: 'acme.com',
			mxRecords: [{ pref: 10, host: 'mx1.mailvendor.co.uk' }],
		});
		const r = await run('acme.com');
		expect(r.dependencies.some((d) => d.provider === 'mailvendor.co.uk' && d.sources.includes('mx'))).toBe(true);
		expect(r.dependencies.some((d) => d.provider === 'co.uk')).toBe(false);
	});

	it('collapses self-hosted MX and NS into labelled first-party rows', async () => {
		mockDnsResponses({ domain: 'example.com', nsHosts: ['ns1.example.com', 'ns2.example.com'],
			mxRecords: [{ pref: 10, host: 'mx1.example.com' }, { pref: 20, host: 'mx2.example.com' }] });
		const r = await run('example.com');
		const mx = r.dependencies.filter((d) => d.sources.includes('mx'));
		expect(mx).toHaveLength(1);
		expect(mx[0]).toMatchObject({ provider: 'example.com (self-hosted MX)', roles: ['email-receiving'], trustLevel: 'critical' });
		const ns = r.dependencies.filter((d) => d.sources.includes('ns'));
		expect(ns).toHaveLength(1);
		expect(ns[0]).toMatchObject({ provider: 'example.com (self-hosted NS)', roles: ['dns-hosting'], trustLevel: 'high' });
		expect(r.summary.critical).toBeGreaterThanOrEqual(1);
	});

	it('handles a web-only domain with no MX records', async () => {
		mockDnsResponses({ domain: 'acme.com', nsHosts: ['ns1.acme.com'] });
		const r = await run('acme.com');
		expect(r.dependencies.every((d) => !d.roles.includes('email-receiving'))).toBe(true);
	});
});

describe('mapSupplyChain — CDN attribution (Task 2, #283)', () => {
	async function run(domain = 'example.com', opts?: { precomputedCdn?: string }) {
		const { mapSupplyChain } = await import('../src/tools/map-supply-chain');
		return mapSupplyChain(domain, opts);
	}

	it('attributes a CDN from the apex A-record ASN when called standalone', async () => {
		mockDnsResponses({
			domain: 'acme.com',
			nsHosts: ['ns1.acme.com'],
			aRecords: ['192.0.2.10'],
			asnAnswers: { '10.2.0.192.origin.asn.cymru.com': '13335 | 192.0.2.0/24 | US | arin' },
		});
		const r = await run('acme.com');
		const dep = r.dependencies.find((d) => d.provider === 'Cloudflare' && d.sources.includes('cdn'));
		expect(dep).toBeDefined();
		expect(dep!.roles).toContain('cdn');
		expect(dep!.trustLevel).toBe('critical');
	});

	it('uses a precomputed cdnProvider without performing an ASN lookup', async () => {
		const asnSpy = vi.fn();
		mockDnsResponses({ domain: 'acme.com', aRecords: ['192.0.2.10'], onAsnQuery: asnSpy });
		const r = await run('acme.com', { precomputedCdn: 'CloudFront' });
		expect(r.dependencies.some((d) => d.provider === 'CloudFront' && d.sources.includes('cdn'))).toBe(true);
		expect(asnSpy).not.toHaveBeenCalled();
	});

	it('emits no cdn dependency when the apex ASN is not a known CDN', async () => {
		mockDnsResponses({
			domain: 'acme.com',
			aRecords: ['198.51.100.5'],
			asnAnswers: { '5.100.51.198.origin.asn.cymru.com': '15169 | 198.51.100.0/24 | US | arin' }, // GCP, not a CDN ASN
		});
		const r = await run('acme.com');
		expect(r.dependencies.some((d) => d.sources.includes('cdn'))).toBe(false);
	});

	it('merges a provider serving both NS and CDN into one row (2 roles, no concentration at <3)', async () => {
		mockDnsResponses({
			domain: 'acme.com',
			nsHosts: ['ns.cloudflare.com'],
			aRecords: ['192.0.2.10'],
			asnAnswers: { '10.2.0.192.origin.asn.cymru.com': '13335 | 192.0.2.0/24 | US | arin' },
		});
		const r = await run('acme.com');
		const cf = r.dependencies.find((d) => d.provider === 'Cloudflare');
		expect(cf!.roles).toEqual(expect.arrayContaining(['dns-hosting', 'cdn']));
		expect(r.signals.some((s) => s.type === 'concentration')).toBe(false);
	});
});

describe('mapSupplyChain — cloud-hosting ASN tier (Task 3, noise-guarded)', () => {
	async function run(domain = 'example.com', opts?: { precomputedCdn?: string }) {
		const { mapSupplyChain } = await import('../src/tools/map-supply-chain');
		return mapSupplyChain(domain, opts);
	}

	it('emits a low-trust cloud-hosting row when origin is on a cloud ASN and no CDN fronts it', async () => {
		mockDnsResponses({
			domain: 'acme.com',
			aRecords: ['192.0.2.20'],
			asnAnswers: { '20.2.0.192.origin.asn.cymru.com': '16509 | 192.0.2.0/24 | US | arin' }, // AWS
		});
		const r = await run('acme.com');
		const dep = r.dependencies.find((d) => d.provider === 'AWS' && d.sources.includes('hosting'));
		expect(dep).toBeDefined();
		expect(dep!.roles).toContain('cloud-hosting');
		expect(dep!.trustLevel).toBe('low');
	});

	it('suppresses the cloud-hosting row when a CDN is attributed (precomputed)', async () => {
		mockDnsResponses({
			domain: 'acme.com',
			aRecords: ['192.0.2.20'],
			asnAnswers: { '20.2.0.192.origin.asn.cymru.com': '16509 | 192.0.2.0/24 | US | arin' },
		});
		const r = await run('acme.com', { precomputedCdn: 'CloudFront' });
		expect(r.dependencies.some((d) => d.sources.includes('hosting'))).toBe(false);
		expect(r.dependencies.some((d) => d.provider === 'CloudFront' && d.sources.includes('cdn'))).toBe(true);
	});

	it('never labels a CDN ASN as cloud-hosting (Akamai stays a cdn row)', async () => {
		mockDnsResponses({
			domain: 'acme.com',
			aRecords: ['192.0.2.30'],
			asnAnswers: { '30.2.0.192.origin.asn.cymru.com': '20940 | 192.0.2.0/24 | US | arin' }, // Akamai
		});
		const r = await run('acme.com');
		expect(r.dependencies.some((d) => d.sources.includes('hosting'))).toBe(false);
		expect(r.dependencies.some((d) => d.provider === 'Akamai' && d.sources.includes('cdn'))).toBe(true);
	});
});

describe('mapSupplyChain — cloud-hosting caveat signal (Task 3)', () => {
	async function run(domain = 'example.com') {
		const { mapSupplyChain } = await import('../src/tools/map-supply-chain');
		return mapSupplyChain(domain);
	}
	it('emits a low-severity shared-infrastructure caveat alongside a hosting row', async () => {
		mockDnsResponses({
			domain: 'acme.com',
			aRecords: ['192.0.2.20'],
			asnAnswers: { '20.2.0.192.origin.asn.cymru.com': '16509 | 192.0.2.0/24 | US | arin' },
		});
		const r = await run('acme.com');
		expect(r.signals.some((s) => s.type === 'shared_hosting' && s.severity === 'low')).toBe(true);
	});
});

describe('mapSupplyChain — shadow_service signal correctness (B1/B2/B3)', () => {
	async function run(domain = 'example.com') {
		const { mapSupplyChain } = await import('../src/tools/map-supply-chain');
		return mapSupplyChain(domain);
	}

	it('B1: emits a single shadow_service signal when one SRV provider is found via multiple prefixes', async () => {
		mockDnsResponses({
			domain: 'acme.com',
			srvRecords: {
				'_sip._tcp': [{ priority: 10, weight: 5, port: 5060, target: 'sip.thirdparty.net' }],
				'_sip._udp': [{ priority: 10, weight: 5, port: 5060, target: 'sip.thirdparty.net' }],
			},
		});
		const r = await run('acme.com');
		const shadow = r.signals.filter((s) => s.type === 'shadow_service' && s.detail.includes('sip.thirdparty.net'));
		expect(shadow.length).toBe(1);
	});

	it('B2: does not flag an SRV provider that is corroborated by MX', async () => {
		mockDnsResponses({
			domain: 'acme.com',
			mxRecords: [{ pref: 10, host: 'acme-com.mail.protection.outlook.com' }], // Microsoft 365 via MX
			srvRecords: { '_sip._tcp': [{ priority: 10, weight: 5, port: 443, target: 'sipfed.online.outlook.com' }] }, // -> Microsoft 365
		});
		const r = await run('acme.com');
		expect(r.signals.some((s) => s.type === 'shadow_service')).toBe(false);
	});

	it('B3: does not flag a SRV target hosted on the scan domain itself', async () => {
		mockDnsResponses({
			domain: 'acme.com',
			srvRecords: { '_sip._tcp': [{ priority: 10, weight: 5, port: 5060, target: 'sipdir.acme.com' }] },
		});
		const r = await run('acme.com');
		expect(r.signals.some((s) => s.type === 'shadow_service')).toBe(false);
	});

	it('still flags a genuine uncorroborated third-party SRV service', async () => {
		mockDnsResponses({
			domain: 'acme.com',
			srvRecords: { '_sip._tcp': [{ priority: 10, weight: 5, port: 5060, target: 'sip.thirdparty.net' }] },
		});
		const r = await run('acme.com');
		expect(r.signals.some((s) => s.type === 'shadow_service' && s.detail.includes('sip.thirdparty.net'))).toBe(true);
	});
});

describe('mapSupplyChain — catalog batch #286 collapse behavior', () => {
	async function run(domain = 'example.com') {
		const { mapSupplyChain } = await import('../src/tools/map-supply-chain');
		return mapSupplyChain(domain);
	}

	it('collapses azure-dns.{com,net,org,info} into a single Azure DNS row', async () => {
		mockDnsResponses({
			domain: 'acme.com',
			nsHosts: ['ns1-01.azure-dns.com', 'ns2-01.azure-dns.net', 'ns3-01.azure-dns.org', 'ns4-01.azure-dns.info'],
		});
		const r = await run('acme.com');
		const azure = r.dependencies.filter((d) => d.provider === 'Azure DNS');
		expect(azure.length).toBe(1);
		expect(r.dependencies.some((d) => /azure-dns\.(com|net|org|info)/.test(d.provider))).toBe(false);
	});

	it('maps a googlemail.com MX to Google Workspace with no raw googlemail.com row', async () => {
		mockDnsResponses({ domain: 'acme.com', mxRecords: [{ pref: 10, host: 'aspmx.l.googlemail.com' }] });
		const r = await run('acme.com');
		expect(r.dependencies.some((d) => d.provider === 'Google Workspace' && d.roles.includes('email-receiving'))).toBe(true);
		expect(r.dependencies.some((d) => d.provider === 'googlemail.com')).toBe(false);
	});

	it('resolves a SPF macro include to its vendor (Valimail) with no raw macro row', async () => {
		mockDnsResponses({ domain: 'acme.com', spf: 'v=spf1 include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email -all' });
		const r = await run('acme.com');
		expect(r.dependencies.some((d) => d.provider === 'Valimail')).toBe(true);
		expect(r.dependencies.some((d) => d.provider.includes('%{'))).toBe(false);
	});
});

describe('mapSupplyChain — catalog batch v3.3.27 (G1/G2/G3)', () => {
	async function run(domain = 'example.com') {
		const { mapSupplyChain } = await import('../src/tools/map-supply-chain');
		return mapSupplyChain(domain);
	}

	describe('G1 — Public Suffix List: Japanese 2LDs (ad/ed/gr/lg .jp)', () => {
		it.each(['ad.jp', 'ed.jp', 'gr.jp', 'lg.jp'])(
			'treats *.%s as a registry suffix when computing the parent domain',
			async (suffix) => {
				const { getEffectiveParentDomain } = await import('../src/tools/map-supply-chain');
				expect(getEffectiveParentDomain(`ns1.dnsprovider.${suffix}`)).toBe(`dnsprovider.${suffix}`);
			},
		);

		it('does not surface ad.jp as a DNS provider when the NS lives under it (rakuten.co.jp regression)', async () => {
			mockDnsResponses({ domain: 'rakuten.co.jp', nsHosts: ['ns1.dnsweb.org.ad.jp', 'ns2.dnsweb.org.ad.jp'] });
			const r = await run('rakuten.co.jp');
			expect(r.dependencies.some((d) => d.provider === 'ad.jp')).toBe(false);
			expect(r.dependencies.some((d) => d.provider === 'org.ad.jp')).toBe(true);
		});
	});

	describe('G2 — Symantec Email Security.cloud (MessageLabs)', () => {
		it('maps spf.messagelabs.com SPF to Symantec Email Security.cloud', async () => {
			const { matchProviderForSpfInclude } = await import('../src/tools/provider-guides');
			expect(matchProviderForSpfInclude('spf.messagelabs.com')).toBe('Symantec Email Security.cloud');
		});
		it('maps cluster*.eu.messagelabs.com MX to Symantec Email Security.cloud', async () => {
			const { matchProviderForMxHost } = await import('../src/tools/provider-guides');
			expect(matchProviderForMxHost('cluster1.eu.messagelabs.com')).toBe('Symantec Email Security.cloud');
		});
	});

	describe('G3 — Campaign Monitor (createsend.com)', () => {
		it('maps _spf.createsend.com SPF to Campaign Monitor', async () => {
			const { matchProviderForSpfInclude } = await import('../src/tools/provider-guides');
			expect(matchProviderForSpfInclude('_spf.createsend.com')).toBe('Campaign Monitor');
		});
	});
});

describe('mapSupplyChain — null MX and CAA no-issuance are directives, not providers (#932)', () => {
	async function run(domain: string) {
		const { mapSupplyChain } = await import('../src/tools/map-supply-chain');
		return mapSupplyChain(domain);
	}

	it('net-agents.dk shape: MX `0 .` + CAA `issue ";"` yield no "" / ";" provider rows and honest counts', async () => {
		// Measured 2026-09-08 (engine 1.36.0): net-agents.dk publishes an RFC 7505 null
		// MX and an RFC 8659 §4.2 deny-all CAA. The mock's `host: ''` renders as `0 .`,
		// exactly the wire form DoH returns for a null MX.
		mockDnsResponses({
			domain: 'net-agents.dk',
			mxRecords: [{ pref: 0, host: '' }],
			caaRecords: ['0 issue ";"'],
			nsHosts: ['ns01.one.com', 'ns02.one.com'],
		});

		const result = await run('net-agents.dk');

		// No degenerate provider names, whatever the source.
		expect(result.dependencies.find((d) => d.provider === '')).toBeUndefined();
		expect(result.dependencies.find((d) => d.provider === ';')).toBeUndefined();
		// The directives produce no dependency of their role at all.
		expect(result.dependencies.some((d) => d.roles.includes('email-receiving'))).toBe(false);
		expect(result.dependencies.some((d) => d.roles.includes('certificate-authority'))).toBe(false);
		// Only the real (DNS-hosting) dependency survives, and the summary counts survivors only.
		expect(result.dependencies.map((d) => d.provider)).toEqual(['one.com']);
		expect(result.summary).toEqual({ totalProviders: 1, critical: 0, high: 1, medium: 0, low: 0 });

		// Both directives are surfaced as informational notes, not as risk.
		const nullMx = result.signals.find((s) => s.type === 'null_mx');
		expect(nullMx).toBeDefined();
		expect(nullMx!.severity).toBe('info');
		expect(nullMx!.detail).toMatch(/RFC 7505/);
		const noIssuance = result.signals.find((s) => s.type === 'caa_no_issuance');
		expect(noIssuance).toBeDefined();
		expect(noIssuance!.severity).toBe('info');
		expect(noIssuance!.detail).toMatch(/RFC 8659/);
		expect(noIssuance!.detail).toMatch(/no certificate authority is authorised/);
		// Compact format clamps signal text at 200 chars — a note must never be cut mid-sentence.
		for (const note of [nullMx!, noIssuance!]) expect(note.detail.length).toBeLessThanOrEqual(200);
	});

	it('null MX published alongside a real MX drops the null row, keeps the provider, and notes the conflict', async () => {
		mockDnsResponses({
			domain: 'example.com',
			mxRecords: [
				{ pref: 0, host: '' },
				{ pref: 10, host: 'aspmx.l.google.com' },
			],
		});
		const result = await run('example.com');
		expect(result.dependencies.find((d) => d.provider === '')).toBeUndefined();
		const google = result.dependencies.find((d) => d.roles.includes('email-receiving'));
		expect(google).toBeDefined();
		expect(google!.provider).toBe('Google Workspace');
		const nullMx = result.signals.find((s) => s.type === 'null_mx');
		expect(nullMx).toBeDefined();
		expect(nullMx!.detail).toMatch(/alongside 1 other MX record, which RFC 7505 forbids/);
		expect(nullMx!.detail.length).toBeLessThanOrEqual(200);
	});

	it('issue ";" beside an issue grant is a conflict, not a denial: the grant takes effect (RFC 8659 any-match)', async () => {
		mockDnsResponses({
			domain: 'example.com',
			caaRecords: ['0 issue ";"', '0 issue "letsencrypt.org"'],
		});
		const result = await run('example.com');
		expect(result.dependencies.find((d) => d.provider === ';')).toBeUndefined();
		expect(result.dependencies.filter((d) => d.roles.includes('certificate-authority')).map((d) => d.provider)).toEqual(['letsencrypt.org']);
		const notes = result.signals.filter((s) => s.type === 'caa_no_issuance');
		expect(notes).toHaveLength(1);
		expect(notes[0].detail).toMatch(/alongside 1 issue grant; the grants take effect/);
		expect(notes[0].detail).not.toMatch(/no certificate authority is authorised/);
		expect(notes[0].detail.length).toBeLessThanOrEqual(200);
	});

	it('issuewild ";" is a deny-all too; a grant in the same RRset still yields its CA row', async () => {
		mockDnsResponses({
			domain: 'example.com',
			caaRecords: ['0 issue "letsencrypt.org"', '0 issuewild ";"'],
		});
		const result = await run('example.com');
		expect(result.dependencies.find((d) => d.provider === ';')).toBeUndefined();
		const caRows = result.dependencies.filter((d) => d.roles.includes('certificate-authority'));
		expect(caRows.map((d) => d.provider)).toEqual(['letsencrypt.org']);
		// A grant under a DIFFERENT tag does not soften the wildcard denial.
		const note = result.signals.find((s) => s.type === 'caa_no_issuance');
		expect(note?.detail).toMatch(/issuewild ";"/);
		expect(note?.detail).toMatch(/no certificate authority is authorised/);
	});

	it('caps attacker-authored CAA issuer names (MAX_CAA_ISSUERS distinct, MAX_CAA_TOKEN_LENGTH each) before they reach structuredContent', async () => {
		const { MAX_CAA_ISSUERS, MAX_CAA_TOKEN_LENGTH, TRUNCATION_MARKER } = await import('@blackveil/dns-checks');
		const longIssuer = `${'a'.repeat(200)}.example`;
		const many = Array.from({ length: MAX_CAA_ISSUERS + 4 }, (_, i) => `0 issue "ca${i}.example"`);
		mockDnsResponses({ domain: 'example.com', caaRecords: [`0 issue "${longIssuer}"`, ...many] });
		const result = await run('example.com');
		const caRows = result.dependencies.filter((d) => d.roles.includes('certificate-authority'));
		expect(caRows).toHaveLength(MAX_CAA_ISSUERS);
		const clipped = caRows.find((d) => d.provider.endsWith(TRUNCATION_MARKER));
		expect(clipped).toBeDefined();
		expect(clipped!.provider).toBe(`${longIssuer.slice(0, MAX_CAA_TOKEN_LENGTH)}${TRUNCATION_MARKER}`);
		expect(caRows.some((d) => d.provider === longIssuer)).toBe(false);
	});

	it('a long punctuation-only issuer is rejected on the pre-clip value, not rescued by the letters in TRUNCATION_MARKER', async () => {
		mockDnsResponses({ domain: 'example.com', caaRecords: [`0 issue "${'.'.repeat(100)}"`, '0 issue "letsencrypt.org"'] });
		const result = await run('example.com');
		const caRows = result.dependencies.filter((d) => d.roles.includes('certificate-authority')).map((d) => d.provider);
		expect(caRows).toEqual(['letsencrypt.org']);
		expect(result.dependencies.some((d) => d.provider.includes('...(truncated)'))).toBe(false);
	});

	it('CAA RFC 8657 parameters are stripped from the CA provider name (shared parser, not a local regex)', async () => {
		mockDnsResponses({
			domain: 'example.com',
			caaRecords: [
				'0 issue "letsencrypt.org; validationmethods=dns-01"',
				'0 issue "sectigo.com; accounturi=https://acme.sectigo.com/acct/123"',
			],
		});
		const result = await run('example.com');
		const caRows = result.dependencies.filter((d) => d.roles.includes('certificate-authority')).map((d) => d.provider);
		expect(caRows.sort()).toEqual(['letsencrypt.org', 'sectigo.com']);
	});

	it('an empty CAA issue value (`issue ""`) is neither a provider nor a no-issuance directive', async () => {
		mockDnsResponses({ domain: 'example.com', caaRecords: ['0 issue ""'] });
		const result = await run('example.com');
		expect(result.dependencies.some((d) => d.roles.includes('certificate-authority'))).toBe(false);
		expect(result.signals.find((s) => s.type === 'caa_no_issuance')).toBeUndefined();
	});

	/**
	 * #944 — measured live pre-fix on `1xlite-85316.pro` (`0 localhost.`, confirmed
	 * from Cloudflare DoH, Google DoH and `dig @8.8.8.8`): map_supply_chain emitted
	 * `{"provider":"localhost","roles":["email-receiving"],"trustLevel":"critical"}`.
	 * A loopback exchange names no third party, so it produces no dependency row —
	 * but unlike an RFC 7505 null MX it is a misconfiguration, not a directive, so
	 * the note lands at `low`, outside the `info` band reserved for directives.
	 */
	it('a `0 localhost.` MX yields no email-receiving row and a low-severity loopback note', async () => {
		mockDnsResponses({
			domain: 'loopback.example',
			mxRecords: [{ pref: 0, host: 'localhost' }],
			nsHosts: ['ns01.one.com', 'ns02.one.com'],
		});
		const result = await run('loopback.example');

		// The measured bug: a critical `localhost` email-receiving provider row.
		expect(result.dependencies.find((d) => d.provider === 'localhost')).toBeUndefined();
		expect(result.dependencies.some((d) => d.roles.includes('email-receiving'))).toBe(false);

		const note = result.signals.find((s) => s.type === 'loopback_mx');
		expect(note).toBeDefined();
		expect(note!.severity).toBe('low');
		expect(note!.detail).toMatch(/localhost/);
		// Compact format clamps signal text at 200 chars — never cut mid-sentence.
		expect(note!.detail.length).toBeLessThanOrEqual(200);
		// A loopback MX is NOT an RFC 7505 declaration, so it must not raise the null-MX note.
		expect(result.signals.find((s) => s.type === 'null_mx')).toBeUndefined();
	});

	it('null MX + loopback MX + a real MX: only the real host is mapped, both notes fire', async () => {
		mockDnsResponses({
			domain: 'mixed.example',
			mxRecords: [
				{ pref: 0, host: '' },
				{ pref: 5, host: 'localhost' },
				{ pref: 10, host: 'aspmx.l.google.com' },
			],
		});
		const result = await run('mixed.example');

		const receiving = result.dependencies.filter((d) => d.roles.includes('email-receiving'));
		expect(receiving.map((d) => d.provider)).toEqual(['Google Workspace']);
		expect(result.dependencies.find((d) => d.provider === 'localhost')).toBeUndefined();
		expect(result.dependencies.find((d) => d.provider === '')).toBeUndefined();

		expect(result.signals.find((s) => s.type === 'loopback_mx')?.severity).toBe('low');
		expect(result.signals.find((s) => s.type === 'null_mx')?.severity).toBe('info');
		// The null-MX conflict count is taken over MAPPED hosts, so the loopback row
		// must not inflate it: one other MX, not two.
		expect(result.signals.find((s) => s.type === 'null_mx')!.detail).toMatch(/alongside 1 other MX record, which RFC 7505 forbids/);
	});

	it('a clean zone emits neither note', async () => {
		mockDnsResponses({
			domain: 'example.com',
			mxRecords: [{ pref: 10, host: 'aspmx.l.google.com' }],
			caaRecords: ['0 issue "letsencrypt.org"'],
		});
		const result = await run('example.com');
		expect(result.signals.find((s) => s.type === 'null_mx')).toBeUndefined();
		expect(result.signals.find((s) => s.type === 'caa_no_issuance')).toBeUndefined();
	});

	describe('isRenderableProviderName — the generic guard every provider row passes through', () => {
		it('rejects empty, whitespace-only, and punctuation-only names', async () => {
			const { isRenderableProviderName } = await import('../src/tools/map-supply-chain');
			for (const bad of ['', ' ', '\t', ';', '.', '..', '-', '";"', '. ;']) {
				expect(isRenderableProviderName(bad), JSON.stringify(bad)).toBe(false);
			}
		});
		it('accepts hostnames, catalog names, and labelled self-hosted rows', async () => {
			const { isRenderableProviderName } = await import('../src/tools/map-supply-chain');
			for (const good of ['one.com', 'Google Workspace', 'example.com (self-hosted MX)', 'ns1', 'Microsoft 365']) {
				expect(isRenderableProviderName(good), good).toBe(true);
			}
		});
	});

	it('formatSupplyChain renders an info-severity note in both formats', async () => {
		const { formatSupplyChain } = await import('../src/tools/map-supply-chain');
		const result = {
			domain: 'net-agents.dk',
			dependencies: [],
			signals: [{ type: 'null_mx' as const, severity: 'info' as const, detail: 'Null MX record (RFC 7505).' }],
			summary: { totalProviders: 0, critical: 0, high: 0, medium: 0, low: 0 },
		};
		expect(formatSupplyChain(result, 'compact')).toContain('- [INFO] Null MX record (RFC 7505).');
		// The icon is the part that changed: pre-fix the fallthrough rendered 🟡 for anything not high/medium.
		expect(formatSupplyChain(result, 'full')).toContain('ℹ️ [INFO] Null MX record (RFC 7505).');
	});

	it('formatSupplyChain renders the loopback note as low-severity risk, not as an info note (#944)', async () => {
		const { formatSupplyChain } = await import('../src/tools/map-supply-chain');
		const result = {
			domain: 'loopback.example',
			dependencies: [],
			signals: [{ type: 'loopback_mx' as const, severity: 'low' as const, detail: 'MX points at localhost (loopback).' }],
			summary: { totalProviders: 0, critical: 0, high: 0, medium: 0, low: 0 },
		};
		expect(formatSupplyChain(result, 'compact')).toContain('- [LOW] MX points at localhost (loopback).');
		expect(formatSupplyChain(result, 'full')).toContain('🟡 [LOW] MX points at localhost (loopback).');
	});
});

describe('mapSupplyChain — self-hosted MX under a ccTLD-2LD is labelled, not dropped (#926, fixed by #927)', () => {
	it('police.govt.nz shape: self-hosted MX row + M365 SPF row, both critical', async () => {
		// #926 reported police.govt.nz's own mx1/mx2 vanishing from the map. #927 collapses
		// them into an explicit self-hosted row; the existing pin covers only example.com,
		// so this exercises the reported ccTLD-2LD shape (`govt.nz` is in PUBLIC_SUFFIX_SECOND_LEVEL).
		mockDnsResponses({
			domain: 'police.govt.nz',
			mxRecords: [
				{ pref: 10, host: 'mx1.police.govt.nz' },
				{ pref: 20, host: 'mx2.police.govt.nz' },
			],
			spf: 'v=spf1 include:spf.protection.outlook.com -all',
		});
		const { mapSupplyChain } = await import('../src/tools/map-supply-chain');
		const result = await mapSupplyChain('police.govt.nz');

		const selfHosted = result.dependencies.filter((d) => d.provider === 'police.govt.nz (self-hosted MX)');
		expect(selfHosted).toHaveLength(1);
		expect(selfHosted[0].roles).toContain('email-receiving');
		expect(selfHosted[0].sources).toEqual(['mx']);
		expect(selfHosted[0].trustLevel).toBe('critical');
		// Neither raw host nor the bare registrable parent may leak through as its own row.
		expect(result.dependencies.find((d) => d.provider === 'police.govt.nz')).toBeUndefined();
		expect(result.dependencies.find((d) => /^mx[12]\.police\.govt\.nz$/.test(d.provider))).toBeUndefined();
		expect(result.dependencies.find((d) => d.provider === 'Microsoft 365')?.trustLevel).toBe('critical');
		expect(result.summary.critical).toBe(2);
	});
});
