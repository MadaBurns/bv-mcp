import { describe, it, expect, afterEach } from 'vitest';
import { vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

/**
 * Parse the DoH query URL to extract queried domain name and record type.
 */
function parseDohQuery(input: string | URL | Request): { name: string; type: string } {
	const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
	const parsed = new URL(url);
	return {
		name: parsed.searchParams.get('name') ?? '',
		type: parsed.searchParams.get('type') ?? '',
	};
}

/**
 * Set up fetch mock that routes DoH responses by domain name.
 * Keys are the queried domain (e.g. 'example.com', '_dmarc.example.com').
 */
function mockDnsResponses(mapping: Record<string, string[]>) {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const { name } = parseDohQuery(input);
		const records = mapping[name] ?? [];
		const answers = records.map((data) => ({
			name,
			type: 16,
			TTL: 300,
			data: `"${data}"`,
		}));
		return Promise.resolve(createDohResponse([{ name, type: 16 }], answers));
	});
}

describe('checkTxtHygiene', () => {
	async function run(domain = 'example.com') {
		const { checkTxtHygiene } = await import('../src/tools/check-txt-hygiene');
		return checkTxtHygiene(domain);
	}

	it('should return clean rating with few TXT records and not flag SPF as verification', async () => {
		mockDnsResponses({
			'example.com': ['v=spf1 include:_spf.google.com -all', 'google-site-verification=abc123'],
			'_dmarc.example.com': ['v=DMARC1; p=reject'],
		});
		const result = await run();
		expect(result.category).toBe('txt_hygiene');
		expect(result.passed).toBe(true);

		// SPF should not be flagged as a service verification
		const spfVerification = result.findings.find(
			(f) => f.title.includes('Service verification detected') && f.detail.toLowerCase().includes('spf'),
		);
		expect(spfVerification).toBeUndefined();

		// Should have a summary with clean rating
		const summary = result.findings.find((f) => f.title.includes('TXT record hygiene'));
		expect(summary).toBeDefined();
		expect(summary!.detail).toContain('Clean');
	});

	it('should flag Yandex verification on government domain as high severity', async () => {
		mockDnsResponses({
			'health.govt.nz': ['yandex-verification:abc123', 'v=spf1 -all'],
			'_dmarc.health.govt.nz': ['v=DMARC1; p=reject'],
		});
		const result = await run('health.govt.nz');
		const finding = result.findings.find((f) => /Russian jurisdiction.*government/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('high');
	});

	it('should flag Yandex verification on commercial domain as medium severity', async () => {
		mockDnsResponses({
			'example.com': ['yandex-verification:abc123', 'v=spf1 -all'],
			'_dmarc.example.com': ['v=DMARC1; p=reject'],
		});
		const result = await run();
		const finding = result.findings.find((f) => /Russian jurisdiction.*verification/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
	});

	it('should not flag Yandex verification on .ru domain', async () => {
		mockDnsResponses({
			'example.ru': ['yandex-verification:abc123', 'v=spf1 -all'],
			'_dmarc.example.ru': ['v=DMARC1; p=reject'],
		});
		const result = await run('example.ru');
		const finding = result.findings.find((f) => /Russian jurisdiction/i.test(f.title));
		expect(finding).toBeUndefined();
	});

	it('should flag Baidu verification on non-.cn domain as medium severity', async () => {
		mockDnsResponses({
			'example.com': ['baidu-site-verification=abc123', 'v=spf1 -all'],
			'_dmarc.example.com': ['v=DMARC1; p=reject'],
		});
		const result = await run();
		const finding = result.findings.find((f) => /Chinese jurisdiction.*verification/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
	});

	it('should flag excessive TXT record accumulation (25+) as medium severity', async () => {
		const records: string[] = [];
		for (let i = 0; i < 26; i++) {
			records.push(`google-site-verification=token${i}`);
		}
		mockDnsResponses({
			'example.com': records,
			'_dmarc.example.com': ['v=DMARC1; p=reject'],
		});
		const result = await run();
		const finding = result.findings.find((f) => /Excessive TXT record accumulation/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
	});

	it('should flag elevated TXT record count (15-24) as low severity', async () => {
		const records: string[] = [];
		for (let i = 0; i < 16; i++) {
			records.push(`google-site-verification=token${i}`);
		}
		mockDnsResponses({
			'example.com': records,
			'_dmarc.example.com': ['v=DMARC1; p=reject'],
		});
		const result = await run();
		const finding = result.findings.find((f) => /Elevated TXT record count/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('low');
	});

	it('should flag moderate TXT record accumulation (10-14) as low severity', async () => {
		const records: string[] = [];
		for (let i = 0; i < 12; i++) {
			records.push(`google-site-verification=token${i}`);
		}
		mockDnsResponses({
			'example.com': records,
			'_dmarc.example.com': ['v=DMARC1; p=reject'],
		});
		const result = await run();
		const finding = result.findings.find((f) => /TXT record accumulation/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('low');
	});

	it('should flag duplicate verification records as low severity (consolidated finding)', async () => {
		mockDnsResponses({
			'example.com': [
				'google-site-verification=abc123',
				'google-site-verification=def456',
				'v=spf1 -all',
			],
			'_dmarc.example.com': ['v=DMARC1; p=reject'],
		});
		const result = await run();
		const finding = result.findings.find((f) => /Duplicate verification records detected/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('low');
		expect(finding!.detail).toContain('Google Search Console');
	});

	it('should flag DMARC misplaced at root as medium severity', async () => {
		mockDnsResponses({
			'example.com': ['v=DMARC1; p=reject', 'v=spf1 -all'],
			'_dmarc.example.com': ['v=DMARC1; p=reject'],
		});
		const result = await run();
		const finding = result.findings.find((f) => /DMARC record misplaced at root/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
	});

	it('should flag TrustedForDomainSharing as medium severity', async () => {
		mockDnsResponses({
			'example.com': ['TrustedForDomainSharing=abc123', 'v=spf1 -all'],
			'_dmarc.example.com': ['v=DMARC1; p=reject'],
		});
		const result = await run();
		const finding = result.findings.find((f) => /Cross-domain trust delegation/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
	});

	it('should flag stale SendGrid integration (verification without SPF include) as low severity', async () => {
		mockDnsResponses({
			'example.com': ['sendgrid-verification=abc123', 'v=spf1 include:_spf.google.com -all'],
			'_dmarc.example.com': ['v=DMARC1; p=reject'],
		});
		const result = await run();
		const finding = result.findings.find((f) => /Possible stale service integration/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('low');
		expect(finding!.title).toContain('SendGrid');
	});

	it('should flag multiple MS= records as low severity', async () => {
		mockDnsResponses({
			'example.com': ['MS=ms12345', 'MS=ms67890', 'v=spf1 -all'],
			'_dmarc.example.com': ['v=DMARC1; p=reject'],
		});
		const result = await run();
		const finding = result.findings.find((f) => /Microsoft tenant migration residue/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('low');
	});

	it('should handle no TXT records gracefully with clean rating', async () => {
		mockDnsResponses({
			'example.com': [],
			'_dmarc.example.com': [],
		});
		const result = await run();
		expect(result.category).toBe('txt_hygiene');

		// Should have info finding about no records
		const noRecords = result.findings.find((f) => /No TXT records/i.test(f.title));
		expect(noRecords).toBeDefined();
		expect(noRecords!.severity).toBe('info');

		// Should have clean summary
		const summary = result.findings.find((f) => f.title.includes('TXT record hygiene'));
		expect(summary).toBeDefined();
		expect(summary!.detail).toContain('Clean');
	});

	it('should classify platform exposure by category', async () => {
		mockDnsResponses({
			'example.com': [
				'google-site-verification=abc123',
				'atlassian-domain-verification=xyz',
				'onetrust-domain-verification=123',
				'hubspot-developer-verification=456',
				'v=spf1 include:_spf.google.com -all',
			],
			'_dmarc.example.com': ['v=DMARC1; p=reject'],
		});
		const result = await run();

		// Check that service verifications are detected with info severity
		const googleFinding = result.findings.find(
			(f) => f.severity === 'info' && f.title.includes('Service verification detected') && f.title.includes('Google Search Console'),
		);
		expect(googleFinding).toBeDefined();
		expect(googleFinding!.metadata?.category).toBe('search_engine');

		const atlassianFinding = result.findings.find(
			(f) => f.severity === 'info' && f.title.includes('Atlassian'),
		);
		expect(atlassianFinding).toBeDefined();
		expect(atlassianFinding!.metadata?.category).toBe('identity_auth');

		const onetrustFinding = result.findings.find(
			(f) => f.severity === 'info' && f.title.includes('OneTrust'),
		);
		expect(onetrustFinding).toBeDefined();
		expect(onetrustFinding!.metadata?.category).toBe('security');

		const hubspotFinding = result.findings.find(
			(f) => f.severity === 'info' && f.title.includes('HubSpot'),
		);
		expect(hubspotFinding).toBeDefined();
		expect(hubspotFinding!.metadata?.category).toBe('marketing');
	});

	it('should flag Baidu on government domain as high severity', async () => {
		mockDnsResponses({
			'agency.gov.au': ['baidu-site-verification=abc123', 'v=spf1 -all'],
			'_dmarc.agency.gov.au': ['v=DMARC1; p=reject'],
		});
		const result = await run('agency.gov.au');
		const finding = result.findings.find((f) => /Chinese jurisdiction.*government/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('high');
	});

	it('should still return results when _dmarc DNS query throws (Promise.allSettled)', async () => {
		// Mock: root TXT succeeds, _dmarc query throws a network error
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name } = parseDohQuery(input);
			if (name === '_dmarc.example.com') {
				return Promise.reject(new Error('DNS timeout'));
			}
			// Root TXT records
			const records = ['v=spf1 -all', 'google-site-verification=abc123'];
			const answers = records.map((data) => ({
				name: 'example.com',
				type: 16,
				TTL: 300,
				data: `"${data}"`,
			}));
			return Promise.resolve(createDohResponse([{ name: 'example.com', type: 16 }], answers));
		});
		const result = await run();
		// Should not throw — should return a valid CheckResult
		expect(result.category).toBe('txt_hygiene');
		expect(result.findings.length).toBeGreaterThan(0);
	});

	it('should NOT flag Baidu verification on native .cn domain', async () => {
		mockDnsResponses({
			'example.cn': ['baidu-site-verification=abc123', 'v=spf1 -all'],
			'_dmarc.example.cn': ['v=DMARC1; p=reject'],
		});
		const result = await run('example.cn');
		const finding = result.findings.find((f) => /Chinese jurisdiction/i.test(f.title));
		expect(finding).toBeUndefined();
	});

	it('should NOT flag stale integration when service has verification AND matching SPF include', async () => {
		mockDnsResponses({
			'example.com': [
				'sendgrid-verification=abc123',
				'v=spf1 include:sendgrid.net -all',
			],
			'_dmarc.example.com': ['v=DMARC1; p=reject'],
		});
		const result = await run();
		const stale = result.findings.find(
			(f) => /Possible stale service integration/i.test(f.title) && f.title.includes('SendGrid'),
		);
		expect(stale).toBeUndefined();
	});

	it('should NOT flag single MS= record as tenant migration', async () => {
		mockDnsResponses({
			'example.com': ['MS=ms12345', 'v=spf1 -all'],
			'_dmarc.example.com': ['v=DMARC1; p=reject'],
		});
		const result = await run();
		const tenantMigration = result.findings.find((f) => /Microsoft tenant migration residue/i.test(f.title));
		expect(tenantMigration).toBeUndefined();
	});

	it('should score enterprise domains with many TXT records in the 50-80 range (not 0)', async () => {
		// Simulate a stripe.com-like scenario: 31 TXT records with duplicates and stale integrations
		const records = [
			'v=spf1 include:_spf.google.com include:sendgrid.net include:mailchimp.com -all',
			// 6 Google Search Console verifications (duplicates)
			'google-site-verification=token1',
			'google-site-verification=token2',
			'google-site-verification=token3',
			'google-site-verification=token4',
			'google-site-verification=token5',
			'google-site-verification=token6',
			// Various service verifications
			'MS=ms12345',
			'MS=ms67890',
			'apple-domain-verification=abc123',
			'facebook-domain-verification=xyz789',
			'atlassian-domain-verification=atlassian1',
			'adobe-idp-site-verification=adobe1',
			'docusign=docusign1',
			'slack-domain-verification=slack1',
			'zoom-domain-verification=zoom1',
			'onetrust-domain-verification=onetrust1',
			'hubspot-developer-verification=hubspot1',
			'stripe-verification=stripe1',
			'globalsign-domain-verification=gs1',
			'have-i-been-pwned-verification=hibp1',
			// Stale services (no SPF include)
			'mailchimp-domain-verification=mc1',
			'pardot_xxx',
			// Filler TXT records to reach ~31
			'keybase-site-verification=kb1',
			'_globalsign-domain-verification=gs2',
			'brave-ledger-verification=brave1',
			'status-page-domain-verification=sp1',
			'workplace-domain-verification=wp1',
			'cisco-ci-domain-verification=cisco1',
			'teamviewer-sso-verification=tv1',
		];
		mockDnsResponses({
			'example.com': records,
			'_dmarc.example.com': ['v=DMARC1; p=reject'],
		});
		const result = await run();
		// Score should be well above 0 — enterprise domains with housekeeping issues
		// should land in the 50-80 range, not catastrophic failure territory
		expect(result.score).toBeGreaterThanOrEqual(50);
		expect(result.passed).toBe(true);
		// Should have the excessive record finding at medium (31 >= 25)
		const excessive = result.findings.find((f) => /Excessive TXT record accumulation/i.test(f.title));
		expect(excessive).toBeDefined();
		expect(excessive!.severity).toBe('medium');
		// Duplicates should be consolidated into a single finding
		const dupFindings = result.findings.filter((f) => /Duplicate verification records/i.test(f.title));
		expect(dupFindings).toHaveLength(1);
		expect(dupFindings[0].severity).toBe('low');
	});

	it('should match verification patterns case-insensitively', async () => {
		mockDnsResponses({
			'example.com': [
				'GOOGLE-SITE-VERIFICATION=abc123',
				'v=spf1 include:_spf.google.com -all',
			],
			'_dmarc.example.com': ['v=DMARC1; p=reject'],
		});
		const result = await run();
		// Should still detect Google Search Console verification
		const googleFinding = result.findings.find(
			(f) => f.severity === 'info' && f.title.includes('Google Search Console'),
		);
		expect(googleFinding).toBeDefined();
	});
});
