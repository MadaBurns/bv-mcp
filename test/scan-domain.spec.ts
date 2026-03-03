import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { env } from 'cloudflare:test';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';
import { scanCache } from '../src/lib/cache';
import type { ScanDomainResult } from '../src/tools/scan-domain';

const { restore } = setupFetchMock();

beforeEach(() => scanCache.clear());
afterEach(() => restore());

function txtResponse(domain: string, records: string[]) {
	return createDohResponse(
		[{ name: domain, type: 16 }],
		records.map((data) => ({ name: domain, type: 16, TTL: 300, data: `"${data}"` })),
	);
}

function nsResponse(domain: string, nameservers: string[]) {
	return createDohResponse(
		[{ name: domain, type: 2 }],
		nameservers.map((data) => ({ name: domain, type: 2, TTL: 300, data })),
	);
}

function caaResponse(domain: string, records: string[]) {
	return createDohResponse(
		[{ name: domain, type: 257 }],
		records.map((data) => ({ name: domain, type: 257, TTL: 300, data })),
	);
}

function mxResponse(domain: string, records: string[]) {
	return createDohResponse(
		[{ name: domain, type: 15 }],
		records.map((data) => ({ name: domain, type: 15, TTL: 300, data })),
	);
}

function dnssecResponse(domain: string, ad: boolean) {
	return createDohResponse([{ name: domain, type: 1 }], [{ name: domain, type: 1, TTL: 300, data: '1.2.3.4' }], {
		ad,
	});
}

function httpResponse(body: string, status = 200) {
	return {
		ok: status >= 200 && status < 300,
		status,
		text: () => Promise.resolve(body),
		json: () => Promise.resolve({}),
	} as unknown as Response;
}

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

			// MX records
			if (url.includes('type=MX') || url.includes('type=15')) {
				return Promise.resolve(mxResponse('example.com', ['10 mail.example.com.']));
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
		expect(result).toHaveProperty('upgrade_cta');
		expect(typeof result.upgrade_cta).toBe('string');
		expect(result.upgrade_cta).toContain('blackveilsecurity.com');

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
		const degradedFinding = dkimCheck!.findings.find((f) => f.severity !== 'info');
		expect(degradedFinding).toBeDefined();

		// Other checks should still have completed normally
		const spfCheck = result.checks.find((c) => c.category === 'spf');
		expect(spfCheck).toBeDefined();
		expect(spfCheck!.score).toBeGreaterThan(0);
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
					{ category: 'dkim', title: 'Weak key', severity: 'high', detail: 'RSA key too short' },
					{ category: 'mta_sts', title: 'Testing mode', severity: 'low', detail: 'Not enforcing' },
				],
				summary: '2 issue(s) found. Grade: A-',
			},
			checks: [],
			cached: false,
			timestamp: '2026-02-23T12:00:00.000Z',
			upgrade_cta: 'This tool finds problems. BLACKVEIL fixes them automatically \u2192 https://blackveil.co.nz',
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
		// Contains timestamp
		expect(report).toContain('2026-02-23T12:00:00.000Z');
		// Contains upgrade CTA
		expect(report).toContain('BLACKVEIL');
		expect(report).toContain('blackveil.co.nz');
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
			upgrade_cta: 'This tool finds problems. BLACKVEIL fixes them automatically \u2192 https://blackveil.co.nz',
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
				if (url.includes('type=TXT') || url.includes('type=16')) {
					if (url.includes('_dmarc.')) return Promise.resolve(txtResponse('_dmarc.example.com', ['v=DMARC1; p=reject']));
					if (url.includes('_domainkey.'))
						return Promise.resolve(txtResponse('default._domainkey.example.com', ['v=DKIM1; k=rsa; p=MIGf']));
					if (url.includes('_mta-sts.')) return Promise.resolve(txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']));
					if (url.includes('_smtp._tls.'))
						return Promise.resolve(txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']));
					return Promise.resolve(txtResponse('example.com', ['v=spf1 include:_spf.google.com -all']));
				}
				if (url.includes('type=MX') || url.includes('type=15'))
					return Promise.resolve(mxResponse('example.com', ['10 mail.example.com.']));
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

/**
 * Non-mail domain detection: scan_domain should downgrade email auth
 * findings when a domain has no MX records (not a mail domain).
 */
describe('scanDomain - non-mail domain handling', () => {
	async function run(domain = 'example.com') {
		const { scanDomain } = await import('../src/tools/scan-domain');
		return scanDomain(domain);
	}

	function findCheck(result: ScanDomainResult, category: string) {
		return result.checks.find((c) => c.category === category);
	}

	/**
	 * Mock for a subdomain with no MX and no email auth records.
	 * The apex _dmarc query can be controlled via the apexDmarc parameter.
	 */
	function mockNonMailSubdomain(opts: { apexDmarc?: string; hasMx?: boolean } = {}) {
		const baseFetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('cloudflare-dns.com')) {
				if (url.includes('type=TXT') || url.includes('type=16')) {
					// Apex DMARC lookup for sub.example.com → _dmarc.example.com
					if (url.includes('_dmarc.example.com')) {
						if (opts.apexDmarc) {
							return Promise.resolve(txtResponse('_dmarc.example.com', [opts.apexDmarc]));
						}
						return Promise.resolve(createDohResponse([{ name: '_dmarc.example.com', type: 16 }], []));
					}
					// Subdomain's own _dmarc → empty
					if (url.includes('_dmarc.')) {
						return Promise.resolve(createDohResponse([{ name: '_dmarc.sub.example.com', type: 16 }], []));
					}
					if (url.includes('_domainkey.')) {
						return Promise.resolve(createDohResponse([{ name: 'default._domainkey.sub.example.com', type: 16 }], []));
					}
					if (url.includes('_mta-sts.')) {
						return Promise.resolve(createDohResponse([{ name: '_mta-sts.sub.example.com', type: 16 }], []));
					}
					if (url.includes('_smtp._tls.')) {
						return Promise.resolve(createDohResponse([{ name: '_smtp._tls.sub.example.com', type: 16 }], []));
					}
					// No SPF record
					return Promise.resolve(createDohResponse([{ name: 'sub.example.com', type: 16 }], []));
				}
				if (url.includes('type=MX') || url.includes('type=15')) {
					if (opts.hasMx) {
						return Promise.resolve(mxResponse('sub.example.com', ['10 mail.example.com.']));
					}
					return Promise.resolve(createDohResponse([{ name: 'sub.example.com', type: 15 }], []));
				}
				if (url.includes('type=NS') || url.includes('type=2'))
					return Promise.resolve(nsResponse('sub.example.com', ['ns1.example.com.', 'ns2.example.com.']));
				if (url.includes('type=CAA') || url.includes('type=257'))
					return Promise.resolve(caaResponse('sub.example.com', ['0 issue "letsencrypt.org"']));
				if (url.includes('type=A') || url.includes('type=1'))
					return Promise.resolve(dnssecResponse('sub.example.com', true));
				return Promise.resolve(createDohResponse([], []));
			}
			if (url.includes('mta-sts.') && url.includes('.well-known')) {
				return Promise.resolve(httpResponse('', 404));
			}
			if (url.startsWith('https://')) return Promise.resolve(httpResponse('OK'));
			return Promise.resolve(httpResponse('OK'));
		});
		globalThis.fetch = baseFetch;
	}

	it('includes MX check in scan results', async () => {
		mockNonMailSubdomain({ hasMx: true });
		const result = await run('sub.example.com');
		const mx = findCheck(result, 'mx');
		expect(mx).toBeDefined();
		expect(mx!.findings.some((f) => f.title === 'MX records found')).toBe(true);
	});

	it('downgrades email auth findings for non-mail subdomain with apex DMARC', async () => {
		mockNonMailSubdomain({ apexDmarc: 'v=DMARC1; p=reject' });
		const result = await run('sub.example.com');

		// SPF, DMARC, DKIM findings should all be info severity
		for (const cat of ['spf', 'dmarc', 'dkim'] as const) {
			const check = findCheck(result, cat);
			expect(check).toBeDefined();
			const nonInfoFindings = check!.findings.filter((f) => f.severity !== 'info');
			expect(nonInfoFindings).toHaveLength(0);
			// Should contain the explanatory reason
			const adjusted = check!.findings.find((f) => f.detail.includes('parent domain DMARC policy covers subdomains'));
			expect(adjusted).toBeDefined();
		}

		// Score should be high since email findings are downgraded
		expect(result.score.overall).toBeGreaterThanOrEqual(80);
	});

	it('keeps full penalties for domains with MX records', async () => {
		// Domain has MX records AND missing email auth → should keep penalties
		mockNonMailSubdomain({ hasMx: true });
		const result = await run('sub.example.com');

		// SPF should still have high/critical severity (not downgraded)
		const spf = findCheck(result, 'spf');
		expect(spf).toBeDefined();
		const highFinding = spf!.findings.find((f) => f.severity === 'critical' || f.severity === 'high');
		expect(highFinding).toBeDefined();
	});

	it('handles DNS error in apex DMARC lookup gracefully (catch block)', async () => {
		// Mock where the _dmarc.example.com query throws an error
		const baseFetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('cloudflare-dns.com')) {
				if (url.includes('type=TXT') || url.includes('type=16')) {
					// Apex DMARC lookup throws
					if (url.includes('_dmarc.example.com')) {
						return Promise.reject(new Error('DNS timeout for apex DMARC'));
					}
					// Subdomain's own _dmarc → empty
					if (url.includes('_dmarc.')) {
						return Promise.resolve(createDohResponse([{ name: '_dmarc.sub.example.com', type: 16 }], []));
					}
					if (url.includes('_domainkey.')) {
						return Promise.resolve(createDohResponse([{ name: 'default._domainkey.sub.example.com', type: 16 }], []));
					}
					if (url.includes('_mta-sts.')) {
						return Promise.resolve(createDohResponse([{ name: '_mta-sts.sub.example.com', type: 16 }], []));
					}
					if (url.includes('_smtp._tls.')) {
						return Promise.resolve(createDohResponse([{ name: '_smtp._tls.sub.example.com', type: 16 }], []));
					}
					return Promise.resolve(createDohResponse([{ name: 'sub.example.com', type: 16 }], []));
				}
				if (url.includes('type=MX') || url.includes('type=15')) {
					// No MX records → non-mail domain
					return Promise.resolve(createDohResponse([{ name: 'sub.example.com', type: 15 }], []));
				}
				if (url.includes('type=NS') || url.includes('type=2'))
					return Promise.resolve(nsResponse('sub.example.com', ['ns1.example.com.', 'ns2.example.com.']));
				if (url.includes('type=CAA') || url.includes('type=257'))
					return Promise.resolve(caaResponse('sub.example.com', ['0 issue "letsencrypt.org"']));
				if (url.includes('type=A') || url.includes('type=1'))
					return Promise.resolve(dnssecResponse('sub.example.com', true));
				return Promise.resolve(createDohResponse([], []));
			}
			if (url.includes('mta-sts.') && url.includes('.well-known')) {
				return Promise.resolve(httpResponse('', 404));
			}
			if (url.startsWith('https://')) return Promise.resolve(httpResponse('OK'));
			return Promise.resolve(httpResponse('OK'));
		});
		globalThis.fetch = baseFetch;

		const result = await run('sub.example.com');

		// Should still complete successfully — checkApexDmarcPolicy returns false on error
		expect(result.domain).toBe('sub.example.com');
		expect(result.checks).toHaveLength(10);

		// Email findings should be downgraded (without apex DMARC coverage reason)
		const spf = findCheck(result, 'spf');
		expect(spf).toBeDefined();
		const adjusted = spf!.findings.find((f) => f.detail.includes('domain has no MX records'));
		expect(adjusted).toBeDefined();
	});

	it('downgrades findings for non-mail domain even without apex DMARC', async () => {
		// No MX and no apex DMARC → still downgrade (MX alone is sufficient signal)
		mockNonMailSubdomain({ apexDmarc: undefined });
		const result = await run('sub.example.com');

		const spf = findCheck(result, 'spf');
		expect(spf).toBeDefined();
		const nonInfoFindings = spf!.findings.filter((f) => f.severity !== 'info');
		expect(nonInfoFindings).toHaveLength(0);
		// Should contain the simpler reason (no apex DMARC)
		const adjusted = spf!.findings.find((f) => f.detail.includes('domain has no MX records'));
		expect(adjusted).toBeDefined();
	});
});
