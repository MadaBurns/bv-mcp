// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for the Tenant DNS fingerprint primitive.
 *
 * Strategy: inject a mock `DnsQueryFn` that returns canned `DohResponse`
 * objects keyed by (qname, type) — same shape Cloudflare DoH would return.
 * No real network, no `safeFetch`, no `cloudflare:workers`.
 */

import { describe, it, expect } from 'vitest';
import {
	computeFingerprint,
	fingerprintsDiffer,
	type DnsQueryFn,
} from '../../src/tenants/dns-fingerprint';
import { RecordType, type DohResponse, type RecordTypeName } from '../../src/lib/dns-types';

type MockAnswer = { name: string; type: number; data: string; TTL?: number };
type RecordMap = Partial<Record<RecordTypeName, MockAnswer[] | 'fail'>>;

/**
 * Build a DnsQueryFn that returns canned answers per (qname, type).
 *
 *   `mocks['example.com'].MX = [{ name: 'example.com', type: 15, data: '10 mail.example.com.' }]`
 *
 * Setting a value to `'fail'` makes that single query reject — useful for
 * partial-failure tests.
 */
function makeDnsQuery(mocks: Record<string, RecordMap>): DnsQueryFn {
	return async (domain: string, type: RecordTypeName): Promise<DohResponse> => {
		const entry = mocks[domain]?.[type];
		if (entry === 'fail') {
			throw new Error(`mock DNS failure for ${domain}/${type}`);
		}
		const answers = (entry ?? []) as MockAnswer[];
		return {
			Status: 0,
			TC: false,
			RD: true,
			RA: true,
			AD: false,
			CD: false,
			Question: [{ name: domain, type: RecordType[type] }],
			Answer: answers.map((a) => ({
				name: a.name,
				type: a.type,
				TTL: a.TTL ?? 300,
				data: a.data,
			})),
		};
	};
}

/** Convenience: build a TXT mock answer with the quoted-rdata form DoH emits. */
function txtAnswer(name: string, payload: string): MockAnswer {
	return { name, type: RecordType.TXT, data: `"${payload}"` };
}

function mxAnswer(name: string, data: string): MockAnswer {
	return { name, type: RecordType.MX, data };
}

function nsAnswer(name: string, data: string): MockAnswer {
	return { name, type: RecordType.NS, data };
}

function caaAnswer(name: string, data: string): MockAnswer {
	return { name, type: RecordType.CAA, data };
}

const HAPPY_PATH_MOCKS: Record<string, RecordMap> = {
	'example.com': {
		TXT: [txtAnswer('example.com', 'v=spf1 -all'), txtAnswer('example.com', 'random=other')],
		MX: [
			mxAnswer('example.com', '10 mail1.example.com.'),
			mxAnswer('example.com', '20 mail2.example.com.'),
		],
		NS: [
			nsAnswer('example.com', 'ns1.example.com.'),
			nsAnswer('example.com', 'ns2.example.com.'),
		],
		CAA: [caaAnswer('example.com', '0 issue "letsencrypt.org"')],
	},
	'_dmarc.example.com': {
		TXT: [txtAnswer('_dmarc.example.com', 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com')],
	},
};

describe('computeFingerprint', () => {
	it('happy path: all five records → ok with stable fingerprint', async () => {
		const dnsQuery = makeDnsQuery(HAPPY_PATH_MOCKS);
		const result = await computeFingerprint('example.com', { dnsQuery });
		expect(result.kind).toBe('ok');
		if (result.kind !== 'ok') return;
		expect(result.domain).toBe('example.com');
		expect(result.fingerprint).toMatch(/^[0-9a-f]{32}$/);
		expect(result.records.spf).toBe('v=spf1 -all');
		expect(result.records.dmarc).toBe('v=DMARC1; p=reject; rua=mailto:dmarc@example.com');
		expect(result.records.mx).toEqual(['10:mail1.example.com', '20:mail2.example.com']);
		expect(result.records.ns).toEqual(['ns1.example.com', 'ns2.example.com']);
		expect(result.records.caa).toEqual(['0 issue "letsencrypt.org"']);
		expect(typeof result.capturedAt).toBe('number');
		expect(result.capturedAt).toBeGreaterThan(0);
	});

	it('determinism: same input → same fingerprint', async () => {
		const dnsQuery = makeDnsQuery(HAPPY_PATH_MOCKS);
		const a = await computeFingerprint('example.com', { dnsQuery });
		const b = await computeFingerprint('example.com', { dnsQuery });
		expect(a.kind).toBe('ok');
		expect(b.kind).toBe('ok');
		if (a.kind === 'ok' && b.kind === 'ok') {
			expect(a.fingerprint).toBe(b.fingerprint);
		}
	});

	it('ordering invariance: reordered MX/NS/CAA in DNS responses → same fingerprint', async () => {
		const reordered: Record<string, RecordMap> = {
			'example.com': {
				TXT: [
					// SPF still wins via prefix match even if other TXTs appear first.
					txtAnswer('example.com', 'random=other'),
					txtAnswer('example.com', 'v=spf1 -all'),
				],
				MX: [
					mxAnswer('example.com', '20 mail2.example.com.'),
					mxAnswer('example.com', '10 mail1.example.com.'),
				],
				NS: [
					nsAnswer('example.com', 'ns2.example.com.'),
					nsAnswer('example.com', 'ns1.example.com.'),
				],
				CAA: [caaAnswer('example.com', '0 issue "letsencrypt.org"')],
			},
			'_dmarc.example.com': HAPPY_PATH_MOCKS['_dmarc.example.com'],
		};
		const original = await computeFingerprint('example.com', { dnsQuery: makeDnsQuery(HAPPY_PATH_MOCKS) });
		const shuffled = await computeFingerprint('example.com', { dnsQuery: makeDnsQuery(reordered) });
		expect(original.kind).toBe('ok');
		expect(shuffled.kind).toBe('ok');
		if (original.kind === 'ok' && shuffled.kind === 'ok') {
			expect(shuffled.fingerprint).toBe(original.fingerprint);
		}
	});

	it('partial DNS failure: 4 of 5 fail → still returns ok with whatever survived', async () => {
		const partialMocks: Record<string, RecordMap> = {
			'example.com': {
				TXT: 'fail',
				MX: 'fail',
				NS: [nsAnswer('example.com', 'ns1.example.com.')],
				CAA: 'fail',
			},
			'_dmarc.example.com': { TXT: 'fail' },
		};
		const result = await computeFingerprint('example.com', { dnsQuery: makeDnsQuery(partialMocks) });
		expect(result.kind).toBe('ok');
		if (result.kind !== 'ok') return;
		expect(result.records.spf).toBeNull();
		expect(result.records.dmarc).toBeNull();
		expect(result.records.mx).toEqual([]);
		expect(result.records.ns).toEqual(['ns1.example.com']);
		expect(result.records.caa).toEqual([]);
		expect(result.fingerprint).toMatch(/^[0-9a-f]{32}$/);
	});

	it('ALL DNS queries fail → error: dns_failure', async () => {
		const allFailMocks: Record<string, RecordMap> = {
			'example.com': { TXT: 'fail', MX: 'fail', NS: 'fail', CAA: 'fail' },
			'_dmarc.example.com': { TXT: 'fail' },
		};
		const result = await computeFingerprint('example.com', { dnsQuery: makeDnsQuery(allFailMocks) });
		expect(result.kind).toBe('error');
		if (result.kind === 'error') {
			expect(result.reason).toBe('dns_failure');
			expect(result.domain).toBe('example.com');
		}
	});

	it('invalid domain → error: invalid_domain (no DNS calls made)', async () => {
		let callCount = 0;
		const dnsQuery: DnsQueryFn = async () => {
			callCount += 1;
			throw new Error('should not be reached');
		};
		const result = await computeFingerprint('not a domain', { dnsQuery });
		expect(result.kind).toBe('error');
		if (result.kind === 'error') {
			expect(result.reason).toBe('invalid_domain');
		}
		expect(callCount).toBe(0);
	});

	it('SPF case-insensitivity: V=SPF1 vs v=spf1 both match', async () => {
		const upperMocks: Record<string, RecordMap> = {
			'example.com': {
				TXT: [txtAnswer('example.com', 'V=SPF1 -all')],
				MX: [],
				NS: [],
				CAA: [],
			},
			'_dmarc.example.com': { TXT: [] },
		};
		const result = await computeFingerprint('example.com', { dnsQuery: makeDnsQuery(upperMocks) });
		expect(result.kind).toBe('ok');
		if (result.kind === 'ok') {
			expect(result.records.spf).toBe('V=SPF1 -all');
		}
	});

	it('DMARC trailing whitespace stripped before hashing', async () => {
		const mocksA: Record<string, RecordMap> = {
			'example.com': { TXT: [], MX: [], NS: [], CAA: [] },
			'_dmarc.example.com': {
				TXT: [txtAnswer('_dmarc.example.com', 'v=DMARC1; p=none')],
			},
		};
		const mocksB: Record<string, RecordMap> = {
			'example.com': { TXT: [], MX: [], NS: [], CAA: [] },
			'_dmarc.example.com': {
				TXT: [txtAnswer('_dmarc.example.com', '   v=DMARC1; p=none   ')],
			},
		};
		const a = await computeFingerprint('example.com', { dnsQuery: makeDnsQuery(mocksA) });
		const b = await computeFingerprint('example.com', { dnsQuery: makeDnsQuery(mocksB) });
		expect(a.kind).toBe('ok');
		expect(b.kind).toBe('ok');
		if (a.kind === 'ok' && b.kind === 'ok') {
			expect(b.records.dmarc).toBe('v=DMARC1; p=none');
			expect(a.fingerprint).toBe(b.fingerprint);
		}
	});

	it('MX rdata canonicalization: trailing-dot variation is equivalent', async () => {
		const withDot: Record<string, RecordMap> = {
			'example.com': {
				TXT: [],
				MX: [mxAnswer('example.com', '10 mail.example.com.')],
				NS: [],
				CAA: [],
			},
			'_dmarc.example.com': { TXT: [] },
		};
		const noDot: Record<string, RecordMap> = {
			'example.com': {
				TXT: [],
				MX: [mxAnswer('example.com', '10 mail.example.com')],
				NS: [],
				CAA: [],
			},
			'_dmarc.example.com': { TXT: [] },
		};
		const a = await computeFingerprint('example.com', { dnsQuery: makeDnsQuery(withDot) });
		const b = await computeFingerprint('example.com', { dnsQuery: makeDnsQuery(noDot) });
		expect(a.kind).toBe('ok');
		expect(b.kind).toBe('ok');
		if (a.kind === 'ok' && b.kind === 'ok') {
			expect(a.records.mx).toEqual(['10:mail.example.com']);
			expect(b.records.mx).toEqual(['10:mail.example.com']);
			expect(a.fingerprint).toBe(b.fingerprint);
		}
	});

	it('fingerprint length is exactly 32 hex chars (16 bytes truncated SHA-256)', async () => {
		const dnsQuery = makeDnsQuery(HAPPY_PATH_MOCKS);
		const result = await computeFingerprint('example.com', { dnsQuery });
		expect(result.kind).toBe('ok');
		if (result.kind === 'ok') {
			expect(result.fingerprint).toHaveLength(32);
			expect(result.fingerprint).toMatch(/^[0-9a-f]{32}$/);
		}
	});

	it('different DNS records → different fingerprints', async () => {
		const baseline = await computeFingerprint('example.com', {
			dnsQuery: makeDnsQuery(HAPPY_PATH_MOCKS),
		});
		const drifted: Record<string, RecordMap> = {
			'example.com': {
				...HAPPY_PATH_MOCKS['example.com'],
				MX: [mxAnswer('example.com', '10 attacker.example.com.')],
			},
			'_dmarc.example.com': HAPPY_PATH_MOCKS['_dmarc.example.com'],
		};
		const after = await computeFingerprint('example.com', { dnsQuery: makeDnsQuery(drifted) });
		expect(baseline.kind).toBe('ok');
		expect(after.kind).toBe('ok');
		if (baseline.kind === 'ok' && after.kind === 'ok') {
			expect(after.fingerprint).not.toBe(baseline.fingerprint);
		}
	});

	it('domain trimmed and lowercased in result', async () => {
		const dnsQuery = makeDnsQuery({
			'example.com': { TXT: [], MX: [], NS: [], CAA: [] },
			'_dmarc.example.com': { TXT: [] },
		});
		const result = await computeFingerprint('  EXAMPLE.com.  ', { dnsQuery });
		expect(result.kind).toBe('ok');
		if (result.kind === 'ok') {
			expect(result.domain).toBe('example.com');
		}
	});
});

describe('fingerprintsDiffer', () => {
	it('returns false for identical non-null hashes', () => {
		expect(fingerprintsDiffer('abc123', 'abc123')).toBe(false);
	});

	it('returns true for differing non-null hashes', () => {
		expect(fingerprintsDiffer('abc123', 'def456')).toBe(true);
	});

	it('returns true when either side is null (no baseline / failed scan)', () => {
		expect(fingerprintsDiffer(null, 'abc123')).toBe(true);
		expect(fingerprintsDiffer('abc123', null)).toBe(true);
		expect(fingerprintsDiffer(null, null)).toBe(true);
	});
});
