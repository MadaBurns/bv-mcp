import { describe, it, expect, afterEach, vi } from 'vitest';
import { RecordType } from '../src/lib/dns';
import { setupFetchMock, createDohResponse, mockFetchError } from './helpers/dns-mock';

const { restore } = setupFetchMock();

interface DnssecMockOptions {
	adFlag: boolean;
	hasDnskey?: boolean;
	hasDs?: boolean;
	/** DNSKEY algorithm number (default 13) */
	dnskeyAlgorithm?: number;
	/** DS digest type (default 2) */
	dsDigestType?: number;
	/** DS algorithm number (default 13) */
	dsAlgorithm?: number;
}

function mockDnssecResponses(opts: DnssecMockOptions): void;
function mockDnssecResponses(adFlag: boolean, hasDnskey?: boolean, hasDs?: boolean): void;
function mockDnssecResponses(
	adFlagOrOpts: boolean | DnssecMockOptions,
	hasDnskey = true,
	hasDs = true,
) {
	let adFlag: boolean;
	let dnskeyAlgorithm: number;
	let dsDigestType: number;
	let dsAlgorithm: number;

	if (typeof adFlagOrOpts === 'object') {
		adFlag = adFlagOrOpts.adFlag;
		hasDnskey = adFlagOrOpts.hasDnskey ?? true;
		hasDs = adFlagOrOpts.hasDs ?? true;
		dnskeyAlgorithm = adFlagOrOpts.dnskeyAlgorithm ?? 13;
		dsDigestType = adFlagOrOpts.dsDigestType ?? 2;
		dsAlgorithm = adFlagOrOpts.dsAlgorithm ?? 13;
	} else {
		adFlag = adFlagOrOpts;
		dnskeyAlgorithm = 13;
		dsDigestType = 2;
		dsAlgorithm = 13;
	}

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
				? [{ name: 'example.com', type: RecordType.DNSKEY, TTL: 300, data: `257 3 ${dnskeyAlgorithm} mdsswUyr3DPW...` }]
				: [];
			return Promise.resolve(createDohResponse([{ name: 'example.com', type: 48 }], answers));
		}
		if (type === 'DS') {
			const answers = hasDs
				? [{ name: 'example.com', type: RecordType.DS, TTL: 300, data: `12345 ${dsAlgorithm} ${dsDigestType} abc123...` }]
				: [];
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
		// Should have algorithm info finding + possibly the "enabled and validated" finding
		const algoFinding = result.findings.find((f) => f.title.includes('Modern DNSSEC algorithm'));
		expect(algoFinding).toBeDefined();
		expect(algoFinding!.severity).toBe('info');
	});

	it('should return high finding when DNSSEC is not validated (AD=false, no keys)', async () => {
		mockDnssecResponses(false, false, false);
		const result = await run();
		expect(result.findings[0].severity).toMatch(/high|critical/);
		expect(result.findings[0].title).toMatch(/DNSSEC not validated/i);
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
		// Only the "DNSSEC enabled and validated" info finding
		expect(r.findings).toHaveLength(1);
		expect(r.findings[0].severity).toBe('info');
	});
});

describe('DNSKEY algorithm auditing', () => {
	async function run(domain = 'example.com') {
		const { checkDnssec } = await import('../src/tools/check-dnssec');
		return checkDnssec(domain);
	}

	it('returns high finding for deprecated algorithm 5 (RSA/SHA-1)', async () => {
		mockDnssecResponses({ adFlag: true, hasDnskey: true, hasDs: true, dnskeyAlgorithm: 5 });
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('Deprecated DNSKEY algorithm'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('high');
		expect(f!.title).toContain('RSA/SHA-1');
	});

	it('returns high finding for deprecated algorithm 7 (RSASHA1-NSEC3)', async () => {
		mockDnssecResponses({ adFlag: true, hasDnskey: true, hasDs: true, dnskeyAlgorithm: 7 });
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('Deprecated DNSKEY algorithm'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('high');
		expect(f!.title).toContain('RSASHA1-NSEC3');
	});

	it('returns info finding for modern algorithm 13 (ECDSA P-256)', async () => {
		mockDnssecResponses({ adFlag: true, hasDnskey: true, hasDs: true, dnskeyAlgorithm: 13 });
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('Modern DNSSEC algorithm'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('info');
		expect(f!.title).toContain('ECDSA P-256');
	});

	it('returns info finding for modern algorithm 15 (Ed25519)', async () => {
		mockDnssecResponses({ adFlag: true, hasDnskey: true, hasDs: true, dnskeyAlgorithm: 15 });
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('Modern DNSSEC algorithm'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('info');
		expect(f!.title).toContain('Ed25519');
	});

	it('returns no algorithm finding for acceptable algorithm 8 (RSA/SHA-256)', async () => {
		mockDnssecResponses({ adFlag: true, hasDnskey: true, hasDs: true, dnskeyAlgorithm: 8 });
		const r = await run();
		const algoFinding = r.findings.find(
			(f) => f.title.includes('DNSKEY algorithm') || f.title.includes('DNSSEC algorithm'),
		);
		expect(algoFinding).toBeUndefined();
	});

	it('returns medium finding for unknown algorithm', async () => {
		mockDnssecResponses({ adFlag: true, hasDnskey: true, hasDs: true, dnskeyAlgorithm: 99 });
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('Unknown DNSKEY algorithm'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
		expect(f!.title).toContain('99');
	});
});

describe('DS digest type auditing', () => {
	async function run(domain = 'example.com') {
		const { checkDnssec } = await import('../src/tools/check-dnssec');
		return checkDnssec(domain);
	}

	it('returns medium finding for deprecated DS digest type 1 (SHA-1)', async () => {
		mockDnssecResponses({ adFlag: true, hasDnskey: true, hasDs: true, dsDigestType: 1 });
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('Deprecated DS digest type'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
		expect(f!.title).toContain('SHA-1');
	});

	it('returns no digest finding for SHA-256 (type 2)', async () => {
		mockDnssecResponses({ adFlag: true, hasDnskey: true, hasDs: true, dsDigestType: 2 });
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('DS digest type'));
		expect(f).toBeUndefined();
	});

	it('returns no digest finding for SHA-384 (type 4)', async () => {
		mockDnssecResponses({ adFlag: true, hasDnskey: true, hasDs: true, dsDigestType: 4 });
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('DS digest type'));
		expect(f).toBeUndefined();
	});
});

describe('parseDnskeyAlgorithm', () => {
	it('parses algorithm from valid DNSKEY data', async () => {
		const { parseDnskeyAlgorithm } = await import('../src/tools/check-dnssec');
		expect(parseDnskeyAlgorithm('257 3 13 mdsswUyr3DPW...')).toBe(13);
		expect(parseDnskeyAlgorithm('256 3 8 AwEAAc...')).toBe(8);
		expect(parseDnskeyAlgorithm('257 3 15 base64key')).toBe(15);
	});

	it('returns null for invalid data', async () => {
		const { parseDnskeyAlgorithm } = await import('../src/tools/check-dnssec');
		expect(parseDnskeyAlgorithm('invalid')).toBeNull();
		expect(parseDnskeyAlgorithm('257 3')).toBeNull();
		expect(parseDnskeyAlgorithm('')).toBeNull();
	});
});

describe('parseDsRecord', () => {
	it('parses algorithm and digest type from valid DS data', async () => {
		const { parseDsRecord } = await import('../src/tools/check-dnssec');
		expect(parseDsRecord('12345 13 2 abc123...')).toEqual({ algorithm: 13, digestType: 2 });
		expect(parseDsRecord('54321 8 1 deadbeef')).toEqual({ algorithm: 8, digestType: 1 });
	});

	it('returns null for invalid data', async () => {
		const { parseDsRecord } = await import('../src/tools/check-dnssec');
		expect(parseDsRecord('invalid')).toBeNull();
		expect(parseDsRecord('12345')).toBeNull();
		expect(parseDsRecord('')).toBeNull();
	});
});
