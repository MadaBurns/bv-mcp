import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

function mockMxRecords(domain: string, records: string[]) {
	const answers = records.map((data) => ({
		name: domain,
		type: 15,
		TTL: 300,
		data,
	}));
	globalThis.fetch = vi.fn().mockResolvedValue(createDohResponse([{ name: domain, type: 15 }], answers));
}

describe('checkMx', () => {
	async function run(domain = 'example.com') {
		const { checkMx } = await import('../src/tools/check-mx');
		return checkMx(domain);
	}

	it('no MX and no SPF → spoofable, recommends v=spf1 -all', async () => {
		// SPF-context (NIST SP 800-177r1 §4.4.2): no MX + no SPF = spoofable (the real
		// gap). One finding, medium, recommending the hard-fail SPF.
		mockMxRecords('nomx.com', []);
		const result = await run('nomx.com');
		expect(result.findings[0].severity).toBe('medium');
		expect(result.findings[0].title).toMatch(/No MX and no SPF/i);
		expect(result.findings[0].detail).toContain('v=spf1 -all');
	});

	it('should return pass if MX records found', async () => {
		mockMxRecords('hasmx.com', ['10 mx1.hasmx.com.', '20 mx2.hasmx.com.']);
		const result = await run('hasmx.com');
		expect(result.passed).toBe(true);
		expect(result.findings[0].title).toMatch(/MX records found/i);
	});

	it('should detect managed email provider', async () => {
		mockMxRecords('outbound.com', ['10 aspmx.l.google.com.']);
		const result = await run('outbound.com');
		expect(result.passed).toBe(true);
		const infoFinding = result.findings.find((f) => f.severity === 'info' && f.title.includes('provider'));
		expect(infoFinding).toBeTruthy();
		expect(infoFinding!.title).toMatch(/Managed email provider detected/i);
		expect(infoFinding!.metadata).toBeDefined();
		expect(infoFinding!.metadata?.detectionType).toBe('inbound');
		expect(infoFinding!.metadata?.providers).toBeDefined();
	});

	it('should avoid false positive suffix matches for provider detection', async () => {
		mockMxRecords('boundary.com', ['10 mail.evilgoogle.com.']);
		const result = await run('boundary.com');
		const infoFinding = result.findings.find((f) => f.title === 'Managed email provider detected');
		expect(infoFinding).toBeUndefined();
	});

	it('should add degraded-source finding when runtime provider source fails', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('cloudflare-dns.com')) {
				const answers = [{ name: 'fallback.com', type: 15, TTL: 300, data: '10 aspmx.l.google.com.' }];
				return Promise.resolve(createDohResponse([{ name: 'fallback.com', type: 15 }], answers));
			}
			throw new Error('Provider signature source unavailable');
		});

		const { checkMx } = await import('../src/tools/check-mx');
		const result = await checkMx('fallback.com', { providerSignaturesUrl: 'https://providers.example/signatures.json' });
		const degradedFinding = result.findings.find((f) => f.title === 'Provider signature source unavailable');
		expect(degradedFinding).toBeDefined();
		expect(degradedFinding!.severity).toBe('info');
		expect(degradedFinding!.metadata?.signatureSource).toBe('built-in');
	});

	it('returns correct category', async () => {
		mockMxRecords('example.com', ['10 mx.example.com.']);
		const result = await run('example.com');
		expect(result.category).toBe('mx');
	});

	it('should detect null MX record (RFC 7505)', async () => {
		mockMxRecords('nullmx.com', ['0 .']);
		const result = await run('nullmx.com');
		const finding = result.findings.find((f) => f.title === 'Null MX record (RFC 7505)');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('info');
	});

	it('should flag MX pointing to IP address as medium severity', async () => {
		mockMxRecords('ipmx.com', ['10 192.168.1.1']);
		const result = await run('ipmx.com');
		const finding = result.findings.find((f) => f.title === 'MX points to IP address');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
	});

	it('should flag single MX record as low severity', async () => {
		mockMxRecords('single.com', ['10 mx.single.com.']);
		const result = await run('single.com');
		const finding = result.findings.find((f) => f.title === 'Single MX record');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('low');
	});

	it('should not flag duplicate MX priorities as a finding', async () => {
		mockMxRecords('dupes.com', ['10 mx1.dupes.com.', '10 mx2.dupes.com.']);
		const result = await run('dupes.com');
		const finding = result.findings.find((f) => f.title === 'Duplicate MX priorities');
		expect(finding).toBeUndefined();
	});

	it('should flag dangling MX that does not resolve', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('type=MX') || url.includes('type=15')) {
				const answers = [{ name: 'dangling.com', type: 15, TTL: 300, data: '10 ghost.dangling.com.' }];
				return Promise.resolve(createDohResponse([{ name: 'dangling.com', type: 15 }], answers));
			}
			// A and AAAA queries return empty
			return Promise.resolve(createDohResponse([{ name: 'ghost.dangling.com', type: 1 }], []));
		});
		const { checkMx } = await import('../src/tools/check-mx');
		const result = await checkMx('dangling.com');
		const finding = result.findings.find((f) => f.title === 'Dangling MX record');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
		expect(finding!.detail).toContain('ghost.dangling.com');
	});

	/**
	 * #944 — a loopback MX is a DEFECT, not an RFC 7505 no-mail declaration.
	 *
	 * Option A (settled on measurement, not preference): 0 loopback-MX domains in a
	 * 992-measured stratified Tranco 1000 corpus; 15/29,385 (0.051%) in a wider
	 * 29,780-domain sample, ALL of them the identical string `0 localhost.` — an
	 * operator reaching for `0 .` and getting the exchange wrong. So `check_mx`
	 * reports it, rather than reclassifying the domain as non-mail.
	 *
	 * The anti-stacking assertions below are the load-bearing half: severity
	 * penalties are additive and `mx` has no cap, so the new medium must REPLACE the
	 * dangling / IP-target mediums, not add to them. Score stays 80 — unchanged from
	 * the live pre-fix behaviour measured on `1xlite-85316.pro`.
	 *
	 * Mock isolation: `checkMx` is imported dynamically inside each case, per the
	 * repo's mock-isolation requirement.
	 */
	function mockLoopbackZone(domain: string, mxData: string[]) {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('type=MX') || url.includes('type=15')) {
				const answers = mxData.map((data) => ({ name: domain, type: 15, TTL: 300, data }));
				return Promise.resolve(createDohResponse([{ name: domain, type: 15 }], answers));
			}
			// Every A/AAAA probe returns empty — so a record that IS probed shows up as dangling.
			return Promise.resolve(createDohResponse([{ name: domain, type: 1 }], []));
		});
	}

	it('flags `0 localhost.` as a loopback defect and does NOT also flag it as dangling (#944)', async () => {
		mockLoopbackZone('loopback.com', ['0 localhost.']);
		const { checkMx } = await import('../src/tools/check-mx');
		const result = await checkMx('loopback.com');

		const loopback = result.findings.find((f) => f.title === 'MX points at localhost');
		expect(loopback).toBeDefined();
		expect(loopback!.severity).toBe('medium');
		expect(loopback!.detail).toContain('localhost');

		// ANTI-STACKING: the loopback finding REPLACES the dangling finding.
		expect(result.findings.find((f) => f.title === 'Dangling MX record')).toBeUndefined();

		// Option A: MX records were measured and are present — still a mail control.
		expect(result.controlPresent).toBe(true);
		// Neutrality claim: one medium (-15) + one low single-MX (-5) = 80, unchanged.
		expect(result.score).toBe(80);
		expect(result.findings.filter((f) => f.severity === 'medium')).toHaveLength(1);
	});

	it('flags `10 127.0.0.1` as loopback and does NOT also flag it as an IP target (#944)', async () => {
		mockLoopbackZone('loopback4.com', ['10 127.0.0.1']);
		const { checkMx } = await import('../src/tools/check-mx');
		const result = await checkMx('loopback4.com');

		const loopback = result.findings.find((f) => f.title === 'MX points at localhost');
		expect(loopback).toBeDefined();
		expect(loopback!.severity).toBe('medium');

		// ANTI-STACKING: loopback records are excluded from the IP-target pass too.
		expect(result.findings.find((f) => f.title === 'MX points to IP address')).toBeUndefined();
		expect(result.findings.filter((f) => f.severity === 'medium')).toHaveLength(1);
		expect(result.score).toBe(80);
	});

	it('a real exchange published beside a loopback MX is still mapped and still probed for dangling', async () => {
		mockLoopbackZone('mixed.com', ['10 mx.example.com.', '20 localhost.']);
		const { checkMx } = await import('../src/tools/check-mx');
		const result = await checkMx('mixed.com');

		expect(result.findings.find((f) => f.title === 'MX points at localhost')).toBeDefined();
		// The routable record keeps its own treatment — exclusion is per-record, not per-zone.
		const dangling = result.findings.find((f) => f.title === 'Dangling MX record');
		expect(dangling).toBeDefined();
		expect(dangling!.detail).toContain('mx.example.com');
		expect(dangling!.detail).not.toContain('localhost');
	});

	it('surfaces providerDetectionFailed metadata when provider signature fetch fails', async () => {
		const { restore: localRestore } = setupFetchMock();
		globalThis.fetch = vi.fn().mockImplementation(async (url: string | URL | Request) => {
			const urlStr = typeof url === 'string' ? url : String((url as URL).href ?? url);
			if (urlStr.includes('provider-signatures') || urlStr.includes('provider_signatures')) {
				throw new TypeError('fetch failed');
			}
			// Return a successful MX response for any DNS query.
			return createDohResponse(
				[{ name: 'example.com', type: 15 }],
				[{ name: 'example.com', type: 15, TTL: 300, data: '10 smtp.google.com.' }],
			);
		});
		const { checkMx } = await import('../src/tools/check-mx');
		const result = await checkMx('example.com', { providerSignaturesUrl: 'https://example.com/provider-signatures' });
		expect((result.metadata as { providerDetectionFailed?: boolean })?.providerDetectionFailed).toBe(true);
		localRestore();
	});

	it('logs warning when provider detection fails', async () => {
		const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
		// First MX query (from checkMX package) succeeds; second (re-query in wrapper) throws
		let mxCallCount = 0;
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('cloudflare-dns.com') && (url.includes('type=MX') || url.includes('type=15'))) {
				mxCallCount++;
				if (mxCallCount <= 1) {
					const answers = [{ name: 'provider-fail.com', type: 15, TTL: 300, data: '10 mx.provider-fail.com.' }];
					return Promise.resolve(createDohResponse([{ name: 'provider-fail.com', type: 15 }], answers));
				}
				// Second MX call (re-query for provider detection) — simulate DNS failure
				return Promise.reject(new Error('DNS query failed'));
			}
			if (url.includes('cloudflare-dns.com') && url.includes('type=TXT')) {
				return Promise.resolve(createDohResponse([{ name: 'provider-fail.com', type: 16 }], []));
			}
			return Promise.resolve(createDohResponse([], []));
		});
		const { checkMx } = await import('../src/tools/check-mx');
		const result = await checkMx('provider-fail.com');
		// Should still return a result (non-critical failure)
		expect(result.category).toBe('mx');
		// Verify warn-level log was emitted
		const logCalls = consoleSpy.mock.calls.map((c) => String(c[0]));
		const warnLog = logCalls.find((l) => l.includes('"severity":"warn"') && l.includes('provider'));
		expect(warnLog).toBeDefined();
		consoleSpy.mockRestore();
	});
});
