import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { env } from 'cloudflare:test';
import { setupFetchMock, createDohResponse, txtResponse, nsResponse, caaResponse, dnssecResponse, httpResponse } from './helpers/dns-mock';
import { IN_MEMORY_CACHE } from '../src/lib/cache';
import type { ScanDomainResult } from '../src/tools/scan-domain';

const { restore } = setupFetchMock();

beforeEach(() => IN_MEMORY_CACHE.clear());
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
				if (url.includes('default._bimi.')) {
					return Promise.resolve(txtResponse('default._bimi.example.com', ['v=BIMI1; l=https://example.com/logo.svg']));
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
		expect(result).toHaveProperty('maturity');
		expect(result).toHaveProperty('cached', false);
		expect(result).toHaveProperty('timestamp');

		// Maturity structure
		expect(result.maturity).toHaveProperty('stage');
		expect(result.maturity).toHaveProperty('label');
		expect(result.maturity).toHaveProperty('description');
		expect(result.maturity).toHaveProperty('nextStep');
		expect(typeof result.maturity.stage).toBe('number');
		expect(result.maturity.stage).toBeGreaterThanOrEqual(0);
		expect(result.maturity.stage).toBeLessThanOrEqual(4);

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

	it('includes all 17 check categories', async () => {
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
		expect(categories).toContain('http_security');
		expect(categories).toContain('dane');
		expect(categories).toContain('mx');
		expect(categories).toContain('bimi');
		expect(categories).toContain('tlsrpt');
		expect(categories).toContain('dane_https');
		expect(categories).toContain('svcb_https');
		expect(categories).toContain('subdomailing');
		expect(result.checks).toHaveLength(17);

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

		// All 17 checks should still be present
		expect(result.checks).toHaveLength(17);

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

	it('preserves partial results when scan times out', async () => {
		// Create a fetch mock where most checks complete fast but one hangs
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('cloudflare-dns.com')) {
				// Make SSL-related queries hang forever to trigger timeout
				if (url.includes('type=TXT') || url.includes('type=16')) {
					if (url.includes('_dmarc.')) return Promise.resolve(txtResponse('_dmarc.example.com', ['v=DMARC1; p=reject']));
					if (url.includes('_domainkey.'))
						return Promise.resolve(txtResponse('default._domainkey.example.com', ['v=DKIM1; k=rsa; p=MIGf']));
					if (url.includes('_mta-sts.')) return Promise.resolve(txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']));
					if (url.includes('_smtp._tls.'))
						return Promise.resolve(txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']));
					if (url.includes('default._bimi.'))
						return Promise.resolve(txtResponse('default._bimi.example.com', ['v=BIMI1; l=https://example.com/logo.svg']));
					return Promise.resolve(txtResponse('example.com', ['v=spf1 include:_spf.google.com -all']));
				}
				if (url.includes('type=NS') || url.includes('type=2'))
					return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
				if (url.includes('type=CAA') || url.includes('type=257'))
					return Promise.resolve(caaResponse('example.com', ['0 issue "letsencrypt.org"']));
				if (url.includes('type=A') || url.includes('type=1')) return Promise.resolve(dnssecResponse('example.com', true));
				return Promise.resolve(createDohResponse([], []));
			}

			// MTA-STS policy
			if (url.includes('mta-sts.') && url.includes('.well-known')) {
				return Promise.resolve(httpResponse('version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400'));
			}

			// SSL check - make this hang to trigger timeout
			if (url.startsWith('https://example.com')) {
				return new Promise(() => {}); // never resolves
			}

			return Promise.resolve(httpResponse('OK'));
		});

		const { scanDomain } = await import('../src/tools/scan-domain');
		// scanDomain has a 12s timeout and per-check 8s timeout
		// The SSL check will hit the per-check timeout first (8s),
		// so we should still get all results including a degraded SSL result
		const result = await scanDomain('example.com');

		// Even with the hanging SSL check, we should get all 12 checks
		// because safeCheck wraps each with a per-check timeout
		expect(result.checks.length).toBeGreaterThanOrEqual(1);
		expect(result.domain).toBe('example.com');
		expect(result.score).toBeDefined();

		// Per-check timeouts should produce LOW severity (infrastructure issue, not security)
		// and checkStatus: 'timeout' — not HIGH severity 'error'
		const sslCheck = result.checks.find((c) => c.category === 'ssl');
		if (sslCheck?.checkStatus === 'timeout') {
			expect(sslCheck.findings[0]?.severity).toBe('low');
			expect(sslCheck.findings[0]?.title).toContain('timed out');
		}
	}, 15_000);

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
					bimi: 100,
					tlsrpt: 100,
					lookalikes: 100,
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
			maturity: { stage: 3, label: 'Enforcing', description: 'Email authentication is actively enforcing.', nextStep: 'Add MTA-STS, DNSSEC, and BIMI.' },
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
		// Contains maturity section
		expect(report).toContain('Email Security Maturity: Stage 3');
		expect(report).toContain('Enforcing');
		expect(report).toContain('Next step:');
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
					bimi: 100,
					tlsrpt: 100,
					lookalikes: 100,
				},
				findings: [],
				summary: 'Excellent! No security issues found. Grade: A+',
			},
			checks: [],
			maturity: { stage: 4, label: 'Hardened', description: 'Comprehensive security.', nextStep: '' },
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
		// Fully absent DNSSEC → single HIGH finding
		const finding = dnssec!.findings.find((f) => f.severity !== 'info');
		expect(finding).toBeDefined();
		expect(finding!.title).toBe('DNSSEC not enabled');
		expect(finding!.severity).toBe('high');
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

	// -- No-send domain (SPF v=spf1 -all) --

	it('downgrades DKIM/MTA-STS/BIMI findings for no-send domains with MX records', async () => {
		// Custom fetch mock: SPF is v=spf1 -all (no-send), MX exists, DKIM/MTA-STS/BIMI missing
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('cloudflare-dns.com')) {
				if (url.includes('type=MX') || url.includes('type=15')) {
					return Promise.resolve(
						createDohResponse([{ name: 'example.com', type: 15 }], [{ name: 'example.com', type: 15, TTL: 300, data: '10 mail.example.com.' }]),
					);
				}
				if (url.includes('type=TXT') || url.includes('type=16')) {
					if (url.includes('_dmarc.')) return Promise.resolve(txtResponse('_dmarc.example.com', ['v=DMARC1; p=reject']));
					// DKIM: no records found
					if (url.includes('_domainkey.'))
						return Promise.resolve(createDohResponse([{ name: 'default._domainkey.example.com', type: 16 }], []));
					// MTA-STS: no record
					if (url.includes('_mta-sts.'))
						return Promise.resolve(createDohResponse([{ name: '_mta-sts.example.com', type: 16 }], []));
					if (url.includes('_smtp._tls.'))
						return Promise.resolve(createDohResponse([{ name: '_smtp._tls.example.com', type: 16 }], []));
					// BIMI: no record
					if (url.includes('default._bimi.'))
						return Promise.resolve(createDohResponse([{ name: 'default._bimi.example.com', type: 16 }], []));
					// SPF: no-send policy (v=spf1 -all with no authorizing mechanisms)
					return Promise.resolve(txtResponse('example.com', ['v=spf1 -all']));
				}
				if (url.includes('type=NS') || url.includes('type=2'))
					return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
				if (url.includes('type=CAA') || url.includes('type=257'))
					return Promise.resolve(caaResponse('example.com', ['0 issue "letsencrypt.org"']));
				if (url.includes('type=A') || url.includes('type=1')) return Promise.resolve(dnssecResponse('example.com', true));
				return Promise.resolve(createDohResponse([], []));
			}
			if (url.startsWith('https://')) return Promise.resolve(httpResponse('OK'));
			return Promise.resolve(httpResponse('OK'));
		});

		const result = await run();

		// SPF should still pass (v=spf1 -all is valid)
		const spf = findCheck(result, 'spf');
		expect(spf).toBeDefined();
		expect(spf!.passed).toBe(true);

		// DKIM: missing records should be downgraded to info
		const dkim = findCheck(result, 'dkim');
		expect(dkim).toBeDefined();
		const dkimCritHigh = dkim!.findings.filter((f) => f.severity === 'critical' || f.severity === 'high');
		expect(dkimCritHigh).toHaveLength(0);
		const dkimDowngraded = dkim!.findings.find((f) => f.detail.includes('domain SPF policy rejects all outbound mail'));
		expect(dkimDowngraded).toBeDefined();
		expect(dkimDowngraded!.severity).toBe('info');

		// MTA-STS: missing records should be downgraded to info
		const mtaSts = findCheck(result, 'mta_sts');
		expect(mtaSts).toBeDefined();
		const mtaStsCritHigh = mtaSts!.findings.filter((f) => f.severity === 'critical' || f.severity === 'high');
		expect(mtaStsCritHigh).toHaveLength(0);

		// BIMI: missing records should be downgraded to info
		const bimi = findCheck(result, 'bimi');
		expect(bimi).toBeDefined();
		const bimiCritHigh = bimi!.findings.filter((f) => f.severity === 'critical' || f.severity === 'high');
		expect(bimiCritHigh).toHaveLength(0);

		// DMARC should NOT be downgraded (still has its own finding severity)
		const dmarc = findCheck(result, 'dmarc');
		expect(dmarc).toBeDefined();
		expect(dmarc!.passed).toBe(true);
	});
});

describe('scanDomain force_refresh', () => {
	function mockAllChecksFn() {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('cloudflare-dns.com')) {
				if (url.includes('type=TXT') || url.includes('type=16')) {
					if (url.includes('_dmarc.')) return Promise.resolve(txtResponse('_dmarc.force-refresh.com', ['v=DMARC1; p=reject']));
					if (url.includes('_domainkey.'))
						return Promise.resolve(txtResponse('default._domainkey.force-refresh.com', ['v=DKIM1; k=rsa; p=MIGf']));
					if (url.includes('_mta-sts.'))
						return Promise.resolve(txtResponse('_mta-sts.force-refresh.com', ['v=STSv1; id=20240101']));
					if (url.includes('_smtp._tls.'))
						return Promise.resolve(txtResponse('_smtp._tls.force-refresh.com', ['v=TLSRPTv1; rua=mailto:tls@force-refresh.com']));
					if (url.includes('default._bimi.'))
						return Promise.resolve(txtResponse('default._bimi.force-refresh.com', ['v=BIMI1; l=https://force-refresh.com/logo.svg']));
					return Promise.resolve(txtResponse('force-refresh.com', ['v=spf1 include:_spf.google.com -all']));
				}
				if (url.includes('type=NS') || url.includes('type=2'))
					return Promise.resolve(nsResponse('force-refresh.com', ['ns1.force-refresh.com.', 'ns2.force-refresh.com.']));
				if (url.includes('type=CAA') || url.includes('type=257'))
					return Promise.resolve(caaResponse('force-refresh.com', ['0 issue "letsencrypt.org"']));
				if (url.includes('type=A') || url.includes('type=1')) return Promise.resolve(dnssecResponse('force-refresh.com', true));
				return Promise.resolve(createDohResponse([], []));
			}
			if (url.includes('mta-sts.') && url.includes('.well-known'))
				return Promise.resolve(httpResponse('version: STSv1\nmode: enforce\nmx: *.force-refresh.com\nmax_age: 86400'));
			if (url.startsWith('https://')) return Promise.resolve(httpResponse('OK'));
			return Promise.resolve(httpResponse('OK'));
		});
	}

	it('bypasses per-check cache when forceRefresh is true', async () => {
		mockAllChecksFn();
		const { scanDomain } = await import('../src/tools/scan-domain');

		// First scan populates per-check caches
		const first = await scanDomain('force-refresh.com');
		expect(first.cached).toBe(false);

		// Clear only the top-level scan cache so we re-enter orchestration
		IN_MEMORY_CACHE.delete('cache:force-refresh.com');

		// Record how many fetch calls were made so far
		const fetchCountBefore = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls.length;

		// Without force_refresh, per-check caches are warm — should make few/no DNS queries
		const second = await scanDomain('force-refresh.com', undefined, { forceRefresh: false });
		expect(second.cached).toBe(false); // top-level was cleared, re-computed from per-check cache
		const fetchCountAfterNormal = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls.length;
		const normalFetchCount = fetchCountAfterNormal - fetchCountBefore;

		// Clear top-level again for force_refresh test
		IN_MEMORY_CACHE.delete('cache:force-refresh.com');

		// With force_refresh=true, per-check caches MUST be bypassed — all checks should re-execute
		const third = await scanDomain('force-refresh.com', undefined, { forceRefresh: true });
		expect(third.cached).toBe(false);
		const fetchCountAfterForce = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls.length;
		const forceFetchCount = fetchCountAfterForce - fetchCountAfterNormal;

		// force_refresh should make significantly more DNS queries than the cached run
		// because all 16 checks re-execute instead of returning from per-check cache
		expect(forceFetchCount).toBeGreaterThan(normalFetchCount);
	});

	it('uses per-check cache normally when forceRefresh is false', async () => {
		mockAllChecksFn();
		const { scanDomain } = await import('../src/tools/scan-domain');

		// Run a fresh scan first
		const first = await scanDomain('normal-cache.com');
		expect(first.cached).toBe(false);

		// Clear only the top-level scan cache key so scanDomain re-enters orchestration,
		// but per-check caches remain populated
		IN_MEMORY_CACHE.delete('cache:normal-cache.com');

		// Second scan without forceRefresh should use per-check caches (no DNS queries)
		const fetchBefore = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls.length;
		const second = await scanDomain('normal-cache.com', undefined, { forceRefresh: false });
		expect(second.cached).toBe(false); // top-level was cleared, but checks came from per-check cache
		const fetchAfter = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls.length;
		// Should have made very few or no DNS queries since per-check caches are warm
		// (at most a few for post-processing, not 16 checks worth)
		expect(fetchAfter - fetchBefore).toBeLessThan(5);
	});
});

describe('scanDomain cacheTtlSeconds propagation', () => {
	function mockAllChecksFn() {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('cloudflare-dns.com')) {
				if (url.includes('type=TXT') || url.includes('type=16')) {
					if (url.includes('_dmarc.')) return Promise.resolve(txtResponse('_dmarc.ttl-test.com', ['v=DMARC1; p=reject']));
					if (url.includes('_domainkey.'))
						return Promise.resolve(txtResponse('default._domainkey.ttl-test.com', ['v=DKIM1; k=rsa; p=MIGf']));
					if (url.includes('_mta-sts.'))
						return Promise.resolve(txtResponse('_mta-sts.ttl-test.com', ['v=STSv1; id=20240101']));
					if (url.includes('_smtp._tls.'))
						return Promise.resolve(txtResponse('_smtp._tls.ttl-test.com', ['v=TLSRPTv1; rua=mailto:tls@ttl-test.com']));
					if (url.includes('default._bimi.'))
						return Promise.resolve(txtResponse('default._bimi.ttl-test.com', ['v=BIMI1; l=https://ttl-test.com/logo.svg']));
					return Promise.resolve(txtResponse('ttl-test.com', ['v=spf1 include:_spf.google.com -all']));
				}
				if (url.includes('type=NS') || url.includes('type=2'))
					return Promise.resolve(nsResponse('ttl-test.com', ['ns1.ttl-test.com.', 'ns2.ttl-test.com.']));
				if (url.includes('type=CAA') || url.includes('type=257'))
					return Promise.resolve(caaResponse('ttl-test.com', ['0 issue "letsencrypt.org"']));
				if (url.includes('type=A') || url.includes('type=1')) return Promise.resolve(dnssecResponse('ttl-test.com', true));
				return Promise.resolve(createDohResponse([], []));
			}
			if (url.includes('mta-sts.') && url.includes('.well-known'))
				return Promise.resolve(httpResponse('version: STSv1\nmode: enforce\nmx: *.ttl-test.com\nmax_age: 86400'));
			if (url.startsWith('https://')) return Promise.resolve(httpResponse('OK'));
			return Promise.resolve(httpResponse('OK'));
		});
	}

	it('propagates custom cacheTtlSeconds to per-check cache writes via KV', async () => {
		mockAllChecksFn();
		const mockKV = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn().mockResolvedValue(undefined),
		};
		const { scanDomain } = await import('../src/tools/scan-domain');
		await scanDomain('ttl-test.com', mockKV as unknown as KVNamespace, { cacheTtlSeconds: 600 });

		// KV.put should have been called with expirationTtl: 600 for per-check entries
		const putCalls = mockKV.put.mock.calls;
		const perCheckPuts = putCalls.filter((call: unknown[]) => (call[0] as string).includes(':check:') && !(call[0] as string).endsWith(':computing'));
		expect(perCheckPuts.length).toBeGreaterThan(0);
		for (const call of perCheckPuts) {
			expect((call[2] as { expirationTtl: number }).expirationTtl).toBe(600);
		}
	});

	it('uses default 300s TTL when cacheTtlSeconds is not set', async () => {
		mockAllChecksFn();
		const mockKV = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn().mockResolvedValue(undefined),
		};
		const { scanDomain } = await import('../src/tools/scan-domain');
		await scanDomain('ttl-default.com', mockKV as unknown as KVNamespace);

		const putCalls = mockKV.put.mock.calls;
		const perCheckPuts = putCalls.filter((call: unknown[]) => (call[0] as string).includes(':check:') && !(call[0] as string).endsWith(':computing'));
		expect(perCheckPuts.length).toBeGreaterThan(0);
		for (const call of perCheckPuts) {
			expect((call[2] as { expirationTtl: number }).expirationTtl).toBe(300);
		}
	});
});

describe('scanDomain deferred cache write (Fix 3)', () => {
	function mockAllChecksFn() {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('cloudflare-dns.com')) {
				if (url.includes('type=TXT') || url.includes('type=16')) {
					if (url.includes('_dmarc.')) return Promise.resolve(txtResponse('_dmarc.deferred.com', ['v=DMARC1; p=reject']));
					if (url.includes('_domainkey.'))
						return Promise.resolve(txtResponse('default._domainkey.deferred.com', ['v=DKIM1; k=rsa; p=MIGf']));
					if (url.includes('_mta-sts.'))
						return Promise.resolve(txtResponse('_mta-sts.deferred.com', ['v=STSv1; id=20240101']));
					if (url.includes('_smtp._tls.'))
						return Promise.resolve(txtResponse('_smtp._tls.deferred.com', ['v=TLSRPTv1; rua=mailto:tls@deferred.com']));
					if (url.includes('default._bimi.'))
						return Promise.resolve(txtResponse('default._bimi.deferred.com', ['v=BIMI1; l=https://deferred.com/logo.svg']));
					return Promise.resolve(txtResponse('deferred.com', ['v=spf1 include:_spf.google.com -all']));
				}
				if (url.includes('type=NS') || url.includes('type=2'))
					return Promise.resolve(nsResponse('deferred.com', ['ns1.deferred.com.', 'ns2.deferred.com.']));
				if (url.includes('type=CAA') || url.includes('type=257'))
					return Promise.resolve(caaResponse('deferred.com', ['0 issue "letsencrypt.org"']));
				if (url.includes('type=A') || url.includes('type=1')) return Promise.resolve(dnssecResponse('deferred.com', true));
				return Promise.resolve(createDohResponse([], []));
			}
			if (url.includes('mta-sts.') && url.includes('.well-known'))
				return Promise.resolve(httpResponse('version: STSv1\nmode: enforce\nmx: *.deferred.com\nmax_age: 86400'));
			if (url.startsWith('https://')) return Promise.resolve(httpResponse('OK'));
			return Promise.resolve(httpResponse('OK'));
		});
	}

	it('calls waitUntil to defer the full-scan cache write when waitUntil is provided', async () => {
		mockAllChecksFn();
		const waitUntilFn = vi.fn();
		const { scanDomain } = await import('../src/tools/scan-domain');

		const result = await scanDomain('deferred.com', undefined, { waitUntil: waitUntilFn });
		expect(result.cached).toBe(false);
		expect(result.domain).toBe('deferred.com');

		// waitUntil should have been called with a promise (the deferred cache write)
		// It may also be called for telemetry, so we just check it was called at least once
		// with a promise for the cache write
		expect(waitUntilFn).toHaveBeenCalled();
		const calls = waitUntilFn.mock.calls;
		const hasPromiseCall = calls.some((call: unknown[]) => call[0] instanceof Promise);
		expect(hasPromiseCall).toBe(true);
	});

	it('still writes to cache synchronously when waitUntil is not provided', async () => {
		mockAllChecksFn();
		const { scanDomain } = await import('../src/tools/scan-domain');

		const result = await scanDomain('sync-cache.com');
		expect(result.cached).toBe(false);

		// The in-memory cache should have the result after return
		const cached = IN_MEMORY_CACHE.get('cache:sync-cache.com');
		expect(cached).toBeDefined();
	});
});

describe('adaptiveWeightCache eviction (Fix 4)', () => {
	it('evicts expired entries first, not all entries, when at capacity', async () => {
		const { _adaptiveWeightCacheForTest } = await import('../src/tools/scan-domain');
		_adaptiveWeightCacheForTest.clear();

		const now = Date.now();

		// Fill with 99 entries, some expired
		for (let i = 0; i < 50; i++) {
			_adaptiveWeightCacheForTest.set(`expired:${i}`, {
				weights: { weights: {}, sampleCount: 0, boundHits: [] },
				expires: now - 1000, // expired
			});
		}
		for (let i = 0; i < 49; i++) {
			_adaptiveWeightCacheForTest.set(`valid:${i}`, {
				weights: { weights: {}, sampleCount: 0, boundHits: [] },
				expires: now + 60_000, // still valid
			});
		}
		expect(_adaptiveWeightCacheForTest.size).toBe(99);

		// Add one more to hit capacity of 100
		_adaptiveWeightCacheForTest.set(`valid:99`, {
			weights: { weights: {}, sampleCount: 0, boundHits: [] },
			expires: now + 60_000,
		});
		expect(_adaptiveWeightCacheForTest.size).toBe(100);

		// Now trigger eviction by calling the evictAdaptiveWeightCache helper
		// which should evict expired entries first, not clear everything
		const { evictAdaptiveWeightCache } = await import('../src/tools/scan-domain');
		evictAdaptiveWeightCache();

		// Expired entries should be gone, valid entries should remain
		expect(_adaptiveWeightCacheForTest.size).toBeLessThanOrEqual(51);
		// All valid entries should still be present
		for (let i = 0; i < 49; i++) {
			expect(_adaptiveWeightCacheForTest.has(`valid:${i}`)).toBe(true);
		}
	});

	it('evicts only the oldest entry when at capacity and nothing is expired', async () => {
		const { _adaptiveWeightCacheForTest, evictAdaptiveWeightCache } = await import('../src/tools/scan-domain');
		_adaptiveWeightCacheForTest.clear();

		const now = Date.now();

		// Fill to capacity with all valid entries — oldest has the earliest expiry
		for (let i = 0; i < 100; i++) {
			_adaptiveWeightCacheForTest.set(`entry:${i}`, {
				weights: { weights: {}, sampleCount: 0, boundHits: [] },
				expires: now + 60_000 + i * 100, // each one expires slightly later
			});
		}
		expect(_adaptiveWeightCacheForTest.size).toBe(100);

		evictAdaptiveWeightCache();

		// Should have evicted exactly one entry (the oldest by expiry time)
		expect(_adaptiveWeightCacheForTest.size).toBe(99);
		// entry:0 had the earliest expiry — it should be the one evicted
		expect(_adaptiveWeightCacheForTest.has('entry:0')).toBe(false);
		// entry:1 through entry:99 should still be present
		expect(_adaptiveWeightCacheForTest.has('entry:1')).toBe(true);
		expect(_adaptiveWeightCacheForTest.has('entry:99')).toBe(true);
	});
});

describe('scanDomain — transient zero retry', () => {
	/**
	 * Builds a fetch mock that throws on the first N transport-level fetches whose URL
	 * contains `flakyUrl`, then succeeds afterward. DNS_RETRIES=1 means each queryDns()
	 * call issues up to 2 fetches before giving up — so to make a check throw once,
	 * use throwCount >= 2 (both attempts fail, DnsQueryError propagates to safeCheck).
	 * To make it succeed on the retry scan, throwCount of 2 is enough.
	 */
	function mockWithFlakyUrl(flakyUrl: string, throwCount: number) {
		let calls = 0;
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes(flakyUrl)) {
				calls++;
				if (calls <= throwCount) {
					return Promise.reject(new Error('DNS query failed: transient'));
				}
			}

			// Replay the default routing from mockAllChecks
			if (url.includes('cloudflare-dns.com')) {
				if (url.includes('type=TXT') || url.includes('type=16')) {
					if (url.includes('_dmarc.')) return Promise.resolve(txtResponse('_dmarc.example.com', ['v=DMARC1; p=reject']));
					if (url.includes('_domainkey.'))
						return Promise.resolve(txtResponse('default._domainkey.example.com', ['v=DKIM1; k=rsa; p=MIGf']));
					if (url.includes('_mta-sts.')) return Promise.resolve(txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']));
					if (url.includes('_smtp._tls.'))
						return Promise.resolve(txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']));
					if (url.includes('default._bimi.'))
						return Promise.resolve(txtResponse('default._bimi.example.com', ['v=BIMI1; l=https://example.com/logo.svg']));
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
	}

	async function run(domain = 'example.com') {
		const { scanDomain } = await import('../src/tools/scan-domain');
		return scanDomain(domain);
	}

	it('retries a zero-score errored check and uses the successful retry result', async () => {
		// DMARC fetch throws on both initial attempts (2 throws = DNS_RETRIES exhausted),
		// then succeeds on the retry-scan pass. DMARC propagates DnsQueryError up to
		// safeCheck, so we get checkStatus='error' + score=0 on the first pass.
		mockWithFlakyUrl('_dmarc.', 2);
		const result = await run();

		const dmarc = result.checks.find((c) => c.category === 'dmarc');
		expect(dmarc).toBeDefined();
		// After retry succeeded, score should NOT be zero and status should NOT be error
		expect(dmarc!.score).toBeGreaterThan(0);
		expect(dmarc!.checkStatus).not.toBe('error');
	});

	it('keeps original zero-score result when retry also fails', async () => {
		// Throw forever for DMARC — retry also fails → original zero should be preserved.
		mockWithFlakyUrl('_dmarc.', 999);
		const result = await run();

		const dmarc = result.checks.find((c) => c.category === 'dmarc');
		expect(dmarc).toBeDefined();
		expect(dmarc!.score).toBe(0);
		expect(dmarc!.checkStatus).toBe('error');
	});

	it('does not retry checks that returned normally (non-error status)', async () => {
		// All checks succeed → no retries should fire. We verify this by checking that
		// DMARC's TXT query is issued exactly once (not duplicated by a retry pass).
		mockAllChecks();
		const fetchSpy = globalThis.fetch as ReturnType<typeof vi.fn>;
		await run();

		const callUrls = fetchSpy.mock.calls.map((c) => (typeof c[0] === 'string' ? c[0] : ''));
		const dmarcCalls = callUrls.filter((u) => u.includes('_dmarc.'));
		// DMARC issues exactly one TXT query under normal circumstances
		expect(dmarcCalls.length).toBe(1);
	});

	it('fires retries for multiple simultaneously failing checks up to the cap', async () => {
		// Throw on SPF, DMARC, TLSRPT, and BIMI TXT lookups on the first 2 fetches
		// (DNS_RETRIES=1 means 2 fetches per query). Each subsequent fetch succeeds, so the
		// retry pass can recover them. That's 4 qualifying retries; cap is MAX_RETRIES_PER_SCAN=3.
		// The first 3 (by checkResults order: spf, dmarc, bimi) retry successfully; tlsrpt
		// remains errored. (MTA-STS and DKIM are excluded because they swallow DNS errors
		// internally and never propagate to safeCheck.)
		const counters: Record<string, number> = { spf: 0, dmarc: 0, tlsrpt: 0, bimi: 0 };
		function shouldThrow(key: string): boolean {
			counters[key]++;
			return counters[key] <= 2;
		}
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('cloudflare-dns.com')) {
				if (url.includes('type=TXT') || url.includes('type=16')) {
					if (url.includes('_dmarc.')) {
						if (shouldThrow('dmarc')) return Promise.reject(new Error('DNS query failed'));
						return Promise.resolve(txtResponse('_dmarc.example.com', ['v=DMARC1; p=reject']));
					}
					if (url.includes('_mta-sts.')) {
						return Promise.resolve(txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']));
					}
					if (url.includes('_smtp._tls.')) {
						if (shouldThrow('tlsrpt')) return Promise.reject(new Error('DNS query failed'));
						return Promise.resolve(txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']));
					}
					if (url.includes('default._bimi.')) {
						if (shouldThrow('bimi')) return Promise.reject(new Error('DNS query failed'));
						return Promise.resolve(txtResponse('default._bimi.example.com', ['v=BIMI1; l=https://example.com/logo.svg']));
					}
					if (url.includes('_domainkey.')) {
						return Promise.resolve(txtResponse('default._domainkey.example.com', ['v=DKIM1; k=rsa; p=MIGf']));
					}
					// SPF query (plain example.com TXT)
					if (shouldThrow('spf')) return Promise.reject(new Error('DNS query failed'));
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

		const result = await run();

		// Count how many of the 4 originally-failing checks ended up with a non-error result.
		// With MAX_RETRIES_PER_SCAN=3, exactly 3 should have recovered via retry; the 4th stays errored.
		const targets = ['spf', 'dmarc', 'tlsrpt', 'bimi'] as const;
		const recovered = targets
			.map((cat) => result.checks.find((c) => c.category === cat))
			.filter((c) => c && c.checkStatus !== 'error' && c.score > 0);
		expect(recovered.length).toBe(3);
	});
});
