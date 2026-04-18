import { describe, it, expect, afterEach, vi } from 'vitest';
import { RecordType } from '../src/lib/dns';
import { setupFetchMock, createDohResponse, mockFetchError } from './helpers/dns-mock';

const { restore } = setupFetchMock();

function mockDnssecResponses(adFlag: boolean, hasDnskey = true, hasDs = true) {
	globalThis.fetch = vi.fn().mockImplementation((url: string) => {
		const typeMatch = url.match(/type=([^&]+)/);
		const type = typeMatch ? typeMatch[1] : '';
		if (type === 'A') {
			return Promise.resolve(
				createDohResponse(
					[{ name: 'example.com', type: 1 }],
					[{ name: 'example.com', type: RecordType.A, TTL: 300, data: '93.184.216.34' }],
					{ ad: adFlag },
				),
			);
		}
		if (type === 'DNSKEY') {
			const answers = hasDnskey ? [{ name: 'example.com', type: RecordType.DNSKEY, TTL: 300, data: '257 3 13 mdsswUyr3DPW...' }] : [];
			return Promise.resolve(createDohResponse([{ name: 'example.com', type: 48 }], answers));
		}
		if (type === 'DS') {
			const answers = hasDs ? [{ name: 'example.com', type: RecordType.DS, TTL: 300, data: '12345 13 2 abc123...' }] : [];
			return Promise.resolve(createDohResponse([{ name: 'example.com', type: 43 }], answers));
		}
		return Promise.resolve(createDohResponse([], []));
	});
}

afterEach(() => restore());

describe('checkDnssec', () => {
	async function run(domain = 'example.com') {
		const { checkDnssec } = await import('../src/tools/check-dnssec');
		return checkDnssec(domain);
	}

	it('should return info finding when DNSSEC is fully valid (AD=true)', async () => {
		mockDnssecResponses(true, true, true);
		const result = await run();
		expect(result.category).toBe('dnssec');
		expect(result.findings[0].severity).toBe('info');
		// With DNSKEY records present, algorithm audit produces a modern algorithm info finding
		expect(result.findings[0].title).toMatch(/Modern DNSSEC algorithm/i);
	});

	it('returns medium finding when DNS query fails entirely', async () => {
		mockFetchError();
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('check failed'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
	});

	it('adds tld_inherited info finding when AD=true but no DNSKEY/DS on domain', async () => {
		mockDnssecResponses(true, false, false);
		const r = await run();
		// Base result has one info finding; augmentation adds the tld_inherited finding
		expect(r.findings.every((f) => f.severity === 'info')).toBe(true);
		const inherited = r.findings.find((f) => f.title === 'DNSSEC inherited from TLD');
		expect(inherited).toBeDefined();
		expect(inherited!.metadata?.dnssecSource).toBe('tld_inherited');
	});
	it('returns info finding when DnsQueryError escapes checkDNSSEC', async () => {
		// Defense-in-depth: tested via dedicated check-dnssec-catch.spec.ts
		// which uses hoisted vi.mock to replace @blackveil/dns-checks.
		// Here we verify the function doesn't crash on DNS network errors.
		mockFetchError();
		const result = await run();
		expect(result.category).toBe('dnssec');
		expect(result.findings.length).toBeGreaterThan(0);
	});
});

describe('DNSSEC finding consolidation', () => {
	async function run(domain = 'example.com') {
		const { checkDnssec } = await import('../src/tools/check-dnssec');
		return checkDnssec(domain);
	}

	it('emits single HIGH finding when DNSSEC is fully absent', async () => {
		// AD=false, no DNSKEY, no DS
		mockDnssecResponses(false, false, false);
		const result = await run();
		const nonInfoFindings = result.findings.filter((f) => f.severity !== 'info');
		expect(nonInfoFindings).toHaveLength(1);
		expect(nonInfoFindings[0].severity).toBe('high');
		expect(nonInfoFindings[0].title).toBe('DNSSEC not enabled');
	});

	it('emits HIGH when DNSKEY present but DS missing', async () => {
		// AD=false, DNSKEY present, no DS
		mockDnssecResponses(false, true, false);
		const result = await run();
		expect(result.findings.some((f) => f.title === 'DNSSEC chain of trust incomplete' && f.severity === 'high')).toBe(true);
	});

	it('does NOT add tld_inherited finding when chain-of-trust is incomplete', async () => {
		// AD=false, DNSKEY present, no DS — domain-operator-configured but broken, not TLD-inherited
		mockDnssecResponses(false, true, false);
		const result = await run();
		const spuriousFinding = result.findings.find((f) => f.title === 'DNSSEC inherited from TLD');
		expect(spuriousFinding).toBeUndefined();
	});

	it('emits HIGH when DNSKEY+DS present but AD not set', async () => {
		// AD=false, DNSKEY present, DS present
		mockDnssecResponses(false, true, true);
		const result = await run();
		expect(result.findings.some((f) => f.title === 'DNSSEC validation failing' && f.severity === 'high')).toBe(true);
	});
});

describe('checkDnssec — dnssecSource detection', () => {
	it('adds tld_inherited finding when DNSSEC validates but no DNSKEY/DS on domain', async () => {
		mockDnssecResponses(true, false, false);
		const { checkDnssec } = await import('../src/tools/check-dnssec');
		const result = await checkDnssec('example.com');
		const inheritedFinding = result.findings.find((f) => f.title === 'DNSSEC inherited from TLD');
		expect(inheritedFinding).toBeDefined();
		expect(inheritedFinding!.severity).toBe('info');
		expect(inheritedFinding!.metadata?.dnssecSource).toBe('tld_inherited');
	});

	it('tags domain_configured when both DNSKEY and DS records are present', async () => {
		mockDnssecResponses(true, true, true);
		const { checkDnssec } = await import('../src/tools/check-dnssec');
		const result = await checkDnssec('example.com');
		const tldFinding = result.findings.find((f) => f.title === 'DNSSEC inherited from TLD');
		expect(tldFinding).toBeUndefined();
		// Source should be domain_configured somewhere in findings metadata
		const hasDomainConfigured = result.findings.some((f) => f.metadata?.dnssecSource === 'domain_configured');
		expect(hasDomainConfigured).toBe(true);
	});

	it('does not add dnssecSource metadata when DNSSEC is fully absent', async () => {
		// AD=false, no DNSKEY, no DS — base result will contain 'DNSSEC not enabled'
		mockDnssecResponses(false, false, false);
		const { checkDnssec } = await import('../src/tools/check-dnssec');
		const result = await checkDnssec('example.com');
		const hasSourceMeta = result.findings.some((f) => f.metadata?.dnssecSource !== undefined);
		expect(hasSourceMeta).toBe(false);
	});
});

describe('checkDnssec — transport-level failure', () => {
	it("returns checkStatus='error' when DNS transport fails entirely", async () => {
		const { restore } = setupFetchMock();
		globalThis.fetch = vi.fn().mockRejectedValue(new TypeError('network down'));
		const { checkDnssec } = await import('../src/tools/check-dnssec');
		const result = await checkDnssec('example.com');
		expect(result.checkStatus).toBe('error');
		// Should not misreport as "not configured"
		expect(result.findings.some((f) => (f.title ?? '').toLowerCase().includes('not configured'))).toBe(false);
		restore();
	});
});

describe('checkDnssec — AD flag confirmation probe', () => {
	/**
	 * Helper that mocks primary Cloudflare DoH responses AND a separate Google DoH
	 * response for the AD confirmation probe. Google calls are identified by URL
	 * prefix `https://dns.google/resolve`.
	 */
	function mockDnssecWithGoogleConfirmation(opts: {
		primaryAd: boolean;
		hasDnskey?: boolean;
		hasDs?: boolean;
		googleAd?: boolean;
		googleThrows?: boolean;
	}) {
		const { primaryAd, hasDnskey = true, hasDs = true, googleAd = true, googleThrows = false } = opts;

		globalThis.fetch = vi.fn().mockImplementation((url: string) => {
			// Google DoH confirmation probe
			if (typeof url === 'string' && url.startsWith('https://dns.google/resolve')) {
				if (googleThrows) {
					return Promise.reject(new Error('Google DoH timeout'));
				}
				return Promise.resolve(
					createDohResponse(
						[{ name: 'example.com', type: 1 }],
						[{ name: 'example.com', type: RecordType.A, TTL: 300, data: '93.184.216.34' }],
						{ ad: googleAd },
					),
				);
			}

			// Primary Cloudflare DoH responses
			const typeMatch = url.match(/type=([^&]+)/);
			const type = typeMatch ? typeMatch[1] : '';
			if (type === 'A') {
				return Promise.resolve(
					createDohResponse(
						[{ name: 'example.com', type: 1 }],
						[{ name: 'example.com', type: RecordType.A, TTL: 300, data: '93.184.216.34' }],
						{ ad: primaryAd },
					),
				);
			}
			if (type === 'DNSKEY') {
				const answers = hasDnskey
					? [{ name: 'example.com', type: RecordType.DNSKEY, TTL: 300, data: '257 3 13 mdsswUyr3DPW...' }]
					: [];
				return Promise.resolve(createDohResponse([{ name: 'example.com', type: 48 }], answers));
			}
			if (type === 'DS') {
				const answers = hasDs ? [{ name: 'example.com', type: RecordType.DS, TTL: 300, data: '12345 13 2 abc123...' }] : [];
				return Promise.resolve(createDohResponse([{ name: 'example.com', type: 43 }], answers));
			}
			if (type === 'NSEC3PARAM') {
				return Promise.resolve(createDohResponse([{ name: 'example.com', type: 50 }], []));
			}
			return Promise.resolve(createDohResponse([], []));
		});
	}

	it('resolves AD flap when Google confirms AD=true', async () => {
		// Primary says AD=false with DNSKEY+DS, but Google says AD=true
		mockDnssecWithGoogleConfirmation({ primaryAd: false, hasDnskey: true, hasDs: true, googleAd: true });
		const { checkDnssec } = await import('../src/tools/check-dnssec');
		const result = await checkDnssec('example.com');

		const validationFailing = result.findings.find((f) => f.title === 'DNSSEC validation failing');
		expect(validationFailing).toBeUndefined();
		expect(result.score).toBeGreaterThan(75);
	});

	it('preserves finding when Google also confirms AD=false', async () => {
		// Both primary and Google say AD=false — DNSSEC really is broken
		mockDnssecWithGoogleConfirmation({ primaryAd: false, hasDnskey: true, hasDs: true, googleAd: false });
		const { checkDnssec } = await import('../src/tools/check-dnssec');
		const result = await checkDnssec('example.com');

		const validationFailing = result.findings.find((f) => f.title === 'DNSSEC validation failing');
		expect(validationFailing).toBeDefined();
		expect(validationFailing!.severity).toBe('high');
	});

	it('degrades gracefully when Google DoH throws an error', async () => {
		// Primary says AD=false with DNSKEY+DS, Google DoH throws
		mockDnssecWithGoogleConfirmation({ primaryAd: false, hasDnskey: true, hasDs: true, googleThrows: true });
		const { checkDnssec } = await import('../src/tools/check-dnssec');
		const result = await checkDnssec('example.com');

		// Original result preserved — "DNSSEC validation failing" still present
		const validationFailing = result.findings.find((f) => f.title === 'DNSSEC validation failing');
		expect(validationFailing).toBeDefined();
		expect(validationFailing!.severity).toBe('high');
	});

	it('does not fire AD confirmation probe when no DNSKEY/DS records exist', async () => {
		// AD=false, no DNSKEY, no DS — should never fire the AD confirmation probe
		mockDnssecResponses(false, false, false);
		const { checkDnssec } = await import('../src/tools/check-dnssec');
		await checkDnssec('example.com');

		// The AD confirmation probe queries Google DoH with type=A specifically.
		// Other Google calls (secondary resolver for DNSKEY/DS empty confirmation) are expected.
		const fetchMock = globalThis.fetch as ReturnType<typeof vi.fn>;
		const adProbeCalls = fetchMock.mock.calls.filter(
			(call: unknown[]) =>
				typeof call[0] === 'string' &&
				call[0].startsWith('https://dns.google/resolve') &&
				call[0].includes('type=A'),
		);
		expect(adProbeCalls).toHaveLength(0);
	});
});
