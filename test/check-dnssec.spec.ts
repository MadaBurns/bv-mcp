import { describe, it, expect, vi, afterEach } from 'vitest';
import { RecordType } from '../src/lib/dns';
import { setupFetchMock, createDohResponse, mockFetchError } from './helpers/dns-mock';

const { restore } = setupFetchMock();

/**
 * Helper: mock DoH responses for DNSSEC checks.
 * The checkDnssec tool makes up to 3 fetch calls:
 *   1. A record with cd=0 (AD flag check)
 *   2. DNSKEY record query
 *   3. DS record query
 *
 * @param adFlag - Whether the AD flag should be set in the A-record response
 * @param hasDnskey - Whether DNSKEY records exist
 * @param hasDs - Whether DS records exist
 */
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
			const answers = hasDnskey
				? [{ name: 'example.com', type: RecordType.DNSKEY, TTL: 300, data: '257 3 13 mdsswUyr3DPW...' }]
				: [];
			return Promise.resolve(
				createDohResponse([{ name: 'example.com', type: 48 }], answers),
			);
		}

		if (type === 'DS') {
			const answers = hasDs
				? [{ name: 'example.com', type: RecordType.DS, TTL: 300, data: '12345 13 2 abc123...' }]
				: [];
			return Promise.resolve(
				createDohResponse([{ name: 'example.com', type: 43 }], answers),
			);
		}

		// Fallback
		return Promise.resolve(
			createDohResponse([], []),
		);
	});
}

afterEach(() => {
	restore();
});

describe('checkDnssec', () => {
	async function run(domain = 'example.com') {
		const { checkDnssec } = await import('../src/tools/check-dnssec');
		return checkDnssec(domain);
	}

	it('returns info finding when DNSSEC is fully valid (AD=true)', async () => {
		mockDnssecResponses(true, true, true);
		const r = await run();
		expect(r.category).toBe('dnssec');
		expect(r.findings).toHaveLength(1);
		expect(r.findings[0].severity).toBe('info');
		expect(r.findings[0].title).toContain('enabled and validated');
		expect(r.passed).toBe(true);
	});

	it('returns high finding when AD flag is false', async () => {
		mockDnssecResponses(false, true, true);
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('not validated'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('high');
	});

	it('returns high finding for missing DNSKEY when AD=false', async () => {
		mockDnssecResponses(false, false, true);
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('No DNSKEY'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('high');
	});

	it('returns medium finding for missing DS when AD=false', async () => {
		mockDnssecResponses(false, true, false);
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('No DS'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
	});

	it('returns all findings when AD=false, no DNSKEY, no DS', async () => {
		mockDnssecResponses(false, false, false);
		const r = await run();
		expect(r.findings.length).toBeGreaterThanOrEqual(3);
		expect(r.findings.some((f) => f.title.includes('not validated'))).toBe(true);
		expect(r.findings.some((f) => f.title.includes('No DNSKEY'))).toBe(true);
		expect(r.findings.some((f) => f.title.includes('No DS'))).toBe(true);
	});

	it('returns medium finding when DNS query fails entirely', async () => {
		mockFetchError();
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('check failed'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
	});

	it('does not flag missing DNSKEY/DS when AD=true', async () => {
		mockDnssecResponses(true, false, false);
		const r = await run();
		// AD=true means DNSSEC is valid; missing DNSKEY/DS should not be flagged
		expect(r.findings).toHaveLength(1);
		expect(r.findings[0].severity).toBe('info');
	});
});

