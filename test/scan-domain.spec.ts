import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { env } from 'cloudflare:test';
import { setupFetchMock, createDohResponse, txtResponse, nsResponse, caaResponse, dnssecResponse, httpResponse } from './helpers/dns-mock';
import { inMemoryCache } from '../src/lib/cache';
import type { ScanDomainResult } from '../src/tools/scan-domain';

const { restore } = setupFetchMock();

beforeEach(() => inMemoryCache.clear());
afterEach(() => restore());

/**
 * Multi-dispatch fetch mock that returns reasonable defaults for all check types.
 * Routes based on URL patterns used by each check function.
 */
function mockAllChecks(overrides?: { throwForUrl?: string }) {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

		if (overrides?.throwForUrl && url.includes(overrides.throwForUrl)) {
			return Promise.reject(new Error('Simulated check failure'));
		}

		// DoH queries go through cloudflare-dns.com
		if (url.includes('cloudflare-dns.com')) {
			// SPF: TXT record for the domain itself
			if (url.includes('type=TXT') || url.includes('type=16')) {
				if (url.includes('_dmarc.')) {
					return Promise.resolve(txtResponse('_dmarc.example.com', ['v=DMARC1; p=reject']));
				}
				if (url.includes('_domainkey.')) {
					return Promise.resolve(txtResponse('default._domainkey.example.com', ['v=DKIM1; k=rsa; p=MIGf']));
				}
				if (url.includes('_mta-sts.')) {
					return Promise.resolve(txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']));
				}
				if (url.includes('_smtp._tls.')) {
					return Promise.resolve(txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']));
				}
				// Default TXT (SPF)
				return Promise.resolve(txtResponse('example.com', ['v=spf1 include:_spf.google.com -all']));
			}

			// NS records
			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
			}

			// CAA records
			if (url.includes('type=CAA') || url.includes('type=257')) {
				return Promise.resolve(caaResponse('example.com', ['0 issue "letsencrypt.org"']));
			}

			// DNSSEC: A record with AD flag
			if (url.includes('type=A') || url.includes('type=1')) {
				return Promise.resolve(dnssecResponse('example.com', true));
			}

			// Fallback DoH response
			return Promise.resolve(createDohResponse([], []));
		}

		// HTTPS requests for SSL check or MTA-STS policy
		if (url.includes('mta-sts.') && url.includes('.well-known')) {
			return Promise.resolve(httpResponse('version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400'));
		}

		// SSL check hits the domain via HTTPS
		if (url.startsWith('https://')) {
			return Promise.resolve(httpResponse('OK'));
		}

		// Default fallback
		return Promise.resolve(httpResponse('OK'));
	});
}

describe('scanDomain', () => {
	async function run(domain = 'example.com', kv?: KVNamespace) {
		const { scanDomain } = await import('../src/tools/scan-domain');
		return scanDomain(domain, kv);
	}

	it('returns result with correct structure - domain, score, checks, cached, timestamp', async () => {
		mockAllChecks();
		const result = await run();

		expect(result).toHaveProperty('domain', 'example.com');
		expect(result).toHaveProperty('score');
		expect(result).toHaveProperty('checks');
		expect(result).toHaveProperty('cached', false);
		expect(result).toHaveProperty('timestamp');

		// Score structure
		expect(result.score).toHaveProperty('overall');
		expect(result.score).toHaveProperty('grade');
		expect(result.score).toHaveProperty('categoryScores');
		expect(result.score).toHaveProperty('findings');
		expect(result.score).toHaveProperty('summary');
		expect(typeof result.score.overall).toBe('number');
		expect(result.score.overall).toBeGreaterThanOrEqual(0);
		expect(result.score.overall).toBeLessThanOrEqual(100);

		// Timestamp is valid ISO string
		expect(() => new Date(result.timestamp).toISOString()).not.toThrow();
	});

	it('includes all 10 check categories', async () => {
		mockAllChecks();
		const result = await run();

		const categories = result.checks.map((c) => c.category);
		expect(categories).toContain('spf');
		expect(categories).toContain('dmarc');
		expect(categories).toContain('dkim');
		expect(categories).toContain('dnssec');
		expect(categories).toContain('ssl');
		expect(categories).toContain('mta_sts');
		expect(categories).toContain('ns');
		expect(categories).toContain('caa');
		expect(categories).toContain('subdomain_takeover');
		expect(categories).toContain('mx');
		expect(result.checks).toHaveLength(10);

		// Each check result has expected shape
		for (const check of result.checks) {
			expect(check).toHaveProperty('category');
			expect(check).toHaveProperty('passed');
			expect(check).toHaveProperty('score');
			expect(check).toHaveProperty('findings');
			expect(typeof check.score).toBe('number');
		}
	});

	it('isolates individual check failure via safeCheck - other checks still complete', async () => {
		mockAllChecks({ throwForUrl: '_domainkey.' });
		const result = await run();

		// All 10 checks should still be present
		expect(result.checks).toHaveLength(10);

		// The DKIM check should have a degraded finding since DNS failed
		const dkimCheck = result.checks.find((c) => c.category === 'dkim');
		expect(dkimCheck).toBeDefined();
		expect(dkimCheck!.findings.length).toBeGreaterThan(0);
		const dkimRelatedFinding = dkimCheck!.findings.find((f) => f.title.toLowerCase().includes('dkim') || f.detail.toLowerCase().includes('dkim'));
		expect(dkimRelatedFinding).toBeDefined();

		// Other checks should still have completed normally
		const spfCheck = result.checks.find((c) => c.category === 'spf');
		expect(spfCheck).toBeDefined();
		expect(spfCheck!.score).toBeGreaterThan(0);
	});

	it('does not throw on invalid domain input (validation is handled by caller)', async () => {
		mockAllChecks();
		const { scanDomain } = await import('../src/tools/scan-domain');
		await expect(scanDomain('localhost')).resolves.toHaveProperty('domain', 'localhost');
		await expect(scanDomain('test.local')).resolves.toHaveProperty('domain', 'test.local');
	});

	it('caches results with KV and returns cached:true on hit', async () => {
		mockAllChecks();
		const kv = env.SCAN_CACHE as KVNamespace;
		const { scanDomain } = await import('../src/tools/scan-domain');

		// First call - fresh scan
		const first = await scanDomain('example.com', kv);
		expect(first.cached).toBe(false);

		// Second call - should hit cache
		const second = await scanDomain('example.com', kv);
		expect(second.cached).toBe(true);
		expect(second.domain).toBe(first.domain);
		expect(second.score.overall).toBe(first.score.overall);
	});
});

describe('formatScanReport', () => {
	it('returns human-readable string with grade, category scores, and timestamp', async () => {
		const { formatScanReport } = await import('../src/tools/scan-domain');

		const mockResult: ScanDomainResult = {
			domain: 'example.com',
			score: {
				overall: 85,
				grade: 'A-',
				categoryScores: {
					spf: 100,
					dmarc: 100,
					dkim: 75,
					dnssec: 100,
					ssl: 80,
					mta_sts: 60,
					ns: 90,
					caa: 70,
					subdomain_takeover: 100,
					mx: 100,
				},
				findings: [
					{ category: 'dkim', title: 'Weak key', severity: 'high', detail: 'RSA key too short', metadata: { confidence: 'deterministic' } },
					{ category: 'mta_sts', title: 'Testing mode', severity: 'low', detail: 'Not enforcing' },
					{
						category: 'subdomain_takeover',
						title: 'Dangling CNAME: media.example.com -> dead.cloudfront.net',
						severity: 'critical',
						detail: 'Potential takeover vector',
						metadata: { verificationStatus: 'potential', confidence: 'heuristic' },
					},
				],
				summary: '2 issue(s) found. Grade: A-',
			},
			checks: [],
			cached: false,
			timestamp: '2026-02-23T12:00:00.000Z',
		};

		const report = formatScanReport(mockResult);

		// Contains domain header
		expect(report).toContain('DNS Security Scan: example.com');
		// Contains overall score and grade
		expect(report).toContain('Overall Score: 85/100 (A-)');
		// Contains category scores section
		expect(report).toContain('Category Scores:');
		expect(report).toContain('SPF');
		expect(report).toContain('DMARC');
		// Contains findings section
		expect(report).toContain('Findings:');
		expect(report).toContain('[HIGH] Weak key');
		expect(report).toContain('RSA key too short');
		expect(report).toContain('Takeover Verification: potential');
		expect(report).toContain('Confidence: deterministic');
		expect(report).toContain('Confidence: heuristic');
		expect(report).toContain('Potential Impact:');
		expect(report).toContain('Adverse Consequences:');
		// Contains timestamp
		expect(report).toContain('2026-02-23T12:00:00.000Z');
	});

	it('includes cache notice when result is cached', async () => {
		const { formatScanReport } = await import('../src/tools/scan-domain');

		const mockResult: ScanDomainResult = {
			domain: 'example.com',
			score: {
				overall: 100,
				grade: 'A+',
				categoryScores: {
					spf: 100,
					dmarc: 100,
					dkim: 100,
					dnssec: 100,
					ssl: 100,
					mta_sts: 100,
					ns: 100,
					caa: 100,
					subdomain_takeover: 100,
					mx: 100,
				},
				findings: [],
				summary: 'Excellent! No security issues found. Grade: A+',
			},
			checks: [],
			cached: true,
			timestamp: '2026-02-23T12:00:00.000Z',
		};

		const report = formatScanReport(mockResult);
		expect(report).toContain('Results served from cache');
		expect(report).toContain('No security issues found');
	});
});

/**
 * Integration tests: full scanDomain() with mocked DoH responses
 * that simulate specific DMARC/DKIM/DNSSEC/CAA failure and pass scenarios.
 */
describe('scanDomain integration - DMARC/DKIM/DNSSEC/CAA with mocked DoH', () => {
	async function run(domain = 'example.com') {
		const { scanDomain } = await import('../src/tools/scan-domain');
		return scanDomain(domain);
	}

	function findCheck(result: ScanDomainResult, category: string) {
		return result.checks.find((c) => c.category === category);
	}

	/**
	 * Creates a fetch mock that overrides specific URL patterns while
	 * keeping all other checks on healthy defaults via mockAllChecks dispatch.
	 */
	function mockWithOverrides(overrides: Record<string, () => Promise<Response>>) {
		const baseFetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			// Check overrides first
			for (const [pattern, handler] of Object.entries(overrides)) {
				if (url.includes(pattern)) {
					return handler();
				}
			}

			// Default healthy responses for all check types
			if (url.includes('cloudflare-dns.com')) {
				if (url.includes('type=MX') || url.includes('type=15')) {
					return Promise.resolve(
						createDohResponse([{ name: 'example.com', type: 15 }], [{ name: 'example.com', type: 15, TTL: 300, data: '10 mail.example.com.' }]),
					);
				}
				if (url.includes('type=TXT') || url.includes('type=16')) {
					if (url.includes('_dmarc.')) return Promise.resolve(txtResponse('_dmarc.example.com', ['v=DMARC1; p=reject']));
					if (url.includes('_domainkey.'))
					return Promise.resolve(txtResponse('default._domainkey.example.com', ['v=DKIM1; k=rsa; p=MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2a2rwplBCXGHDzhtSF5cz+DfOpZB3Q9nDy0NxQyL8iB4xQoT0Q5Ka0K9KpV4LK3+KZvP5U9ZvL1yR5pZmqZLa5N4H1s7cQ7YQ0+C1jKSRQG7jP8QF1dPLqVfE1pZe7cQ8Kxc6c4PfD8QK9pC7Z1W0K8M3K7N2R4L9Y5L8B3P4N7U5Q6K0O5M5Y6W8P1R7T9A8K6S4P8b0tVm7dC1wYzV6+C2T3U4V5W6X7Y8Z9A0B1C2D3E4F5G6H7I8J9K0L1M2N3O4P5Q6R7S8T9U0V1W2X3Y4z9zzAABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ00112233445566778899aabbccddeeffgghhiijjkkllmmnnooppqqrrssttuuvvwwxxyyzz0011223344556677889900AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZaabbccddeeffgghhiijjkkllmmnnooppqqrrssttuuvvwwxxyyzz']));
					if (url.includes('_mta-sts.')) return Promise.resolve(txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']));
					if (url.includes('_smtp._tls.'))
						return Promise.resolve(txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']));
					return Promise.resolve(txtResponse('example.com', ['v=spf1 include:_spf.google.com -all']));
				}
				if (url.includes('type=NS') || url.includes('type=2'))
					return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
				if (url.includes('type=CAA') || url.includes('type=257'))
					return Promise.resolve(caaResponse('example.com', ['0 issue "letsencrypt.org"']));
				if (url.includes('type=A') || url.includes('type=1')) return Promise.resolve(dnssecResponse('example.com', true));
				return Promise.resolve(createDohResponse([], []));
			}
			if (url.includes('mta-sts.') && url.includes('.well-known')) {
				return Promise.resolve(httpResponse('version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400'));
			}
			if (url.startsWith('https://')) return Promise.resolve(httpResponse('OK'));
			return Promise.resolve(httpResponse('OK'));
		});
		globalThis.fetch = baseFetch;
	}

	// -- DMARC --

	it('detects missing DMARC record and penalises score', async () => {
		mockWithOverrides({
			'_dmarc.': () =>
				Promise.resolve(
					createDohResponse(
						[{ name: '_dmarc.example.com', type: 16 }],
						[], // no records
					),
				),
		});
		const result = await run();
		const dmarc = findCheck(result, 'dmarc');
		expect(dmarc).toBeDefined();
		expect(dmarc!.score).toBeLessThan(100);
		const finding = dmarc!.findings.find((f) => f.severity === 'critical' || f.severity === 'high');
		expect(finding).toBeDefined();
		expect(finding!.title.toLowerCase()).toContain('dmarc');
	});

	it('detects DMARC p=none policy as medium severity', async () => {
		mockWithOverrides({
			'_dmarc.': () => Promise.resolve(txtResponse('_dmarc.example.com', ['v=DMARC1; p=none'])),
		});
		const result = await run();
		const dmarc = findCheck(result, 'dmarc');
		expect(dmarc).toBeDefined();
		const finding = dmarc!.findings.find((f) => f.severity === 'medium' || f.severity === 'high');
		expect(finding).toBeDefined();
	});

	// -- DKIM --

	it('detects missing DKIM records as high severity', async () => {
		mockWithOverrides({
			'_domainkey.': () =>
				Promise.resolve(
					createDohResponse(
						[{ name: 'default._domainkey.example.com', type: 16 }],
						[], // no records
					),
				),
		});
		const result = await run();
		const dkim = findCheck(result, 'dkim');
		expect(dkim).toBeDefined();
		expect(dkim!.score).toBeLessThan(100);
		const finding = dkim!.findings.find((f) => f.severity === 'high' || f.severity === 'critical');
		expect(finding).toBeDefined();
	});

	it('passes DKIM when valid key record exists', async () => {
		mockWithOverrides({}); // all defaults are healthy
		const result = await run();
		const dkim = findCheck(result, 'dkim');
		expect(dkim).toBeDefined();
		expect(dkim!.passed).toBe(true);
	});

	// -- DNSSEC --

	it('detects DNSSEC not enabled (AD=false)', async () => {
		mockWithOverrides({
			'type=A': () => Promise.resolve(dnssecResponse('example.com', false)),
			'type=1': () => Promise.resolve(dnssecResponse('example.com', false)),
		});
		const result = await run();
		const dnssec = findCheck(result, 'dnssec');
		expect(dnssec).toBeDefined();
		expect(dnssec!.passed).toBe(false);
		const finding = dnssec!.findings.find((f) => f.severity !== 'info');
		expect(finding).toBeDefined();
	});

	it('passes DNSSEC when AD flag is set', async () => {
		mockWithOverrides({}); // defaults have AD=true
		const result = await run();
		const dnssec = findCheck(result, 'dnssec');
		expect(dnssec).toBeDefined();
		expect(dnssec!.passed).toBe(true);
	});

	// -- CAA --

	it('detects missing CAA records', async () => {
		mockWithOverrides({
			'type=CAA': () =>
				Promise.resolve(
					createDohResponse(
						[{ name: 'example.com', type: 257 }],
						[], // no records
					),
				),
			'type=257': () =>
				Promise.resolve(
					createDohResponse(
						[{ name: 'example.com', type: 257 }],
						[], // no records
					),
				),
		});
		const result = await run();
		const caa = findCheck(result, 'caa');
		expect(caa).toBeDefined();
		expect(caa!.score).toBeLessThan(100);
		const finding = caa!.findings.find((f) => f.severity !== 'info');
		expect(finding).toBeDefined();
	});

	it('passes CAA when issue tag exists', async () => {
		mockWithOverrides({}); // defaults have CAA issue letsencrypt.org
		const result = await run();
		const caa = findCheck(result, 'caa');
		expect(caa).toBeDefined();
		expect(caa!.passed).toBe(true);
	});
});
