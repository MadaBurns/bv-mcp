// SPDX-License-Identifier: BUSL-1.1

/**
 * Output pin for checkDNSSEC (SQ-378, CRAP H1).
 *
 * Every case snapshots the COMPLETE CheckResult plus the exact DNS query sequence the
 * check issued, so a behaviour-preserving refactor of checkDNSSEC cannot move a finding,
 * its order/severity/title/detail/metadata, `passed`, the presence flags or the probe order.
 * Snapshots were captured from the pre-split implementation and must not be regenerated
 * to make a refactor pass.
 */

import { describe, it, expect } from 'vitest';
import { checkDNSSEC } from '../src/checks/check-dnssec';
import type { DNSQueryFunction, DNSQueryOutcome, RawDNSQueryFunction, ZoneContext } from '../src/types';

type Answers = Partial<Record<string, string[] | Error | DNSQueryOutcome>>;

const DNSKEY_OK = '257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==';
const DS_OK = '12345 13 2 abc123def4567890abc123def4567890abc123def4567890abc123def4567890';

interface Trace {
	calls: string[];
	queryDNS: DNSQueryFunction;
	rawQueryDNS: RawDNSQueryFunction;
}

/** A query function keyed by record type (and optionally `type@name`), recording every call in order. */
function makeTrace(answers: Answers, ad: boolean | Error): Trace {
	const calls: string[] = [];
	const lookup = (name: string, type: string) => answers[`${type}@${name}`] ?? answers[type] ?? [];
	const queryDNS = (async (name: string, type: string) => {
		calls.push(`queryDNS ${type} ${name}`);
		const hit = lookup(name, type);
		if (hit instanceof Error) throw hit;
		return Array.isArray(hit) ? hit : hit.records;
	}) as DNSQueryFunction;
	queryDNS.withRcode = async (name: string, type: string) => {
		calls.push(`withRcode ${type} ${name}`);
		const hit = lookup(name, type);
		if (hit instanceof Error) throw hit;
		return Array.isArray(hit) ? { records: hit } : hit;
	};
	const rawQueryDNS = (async (name: string, type: string) => {
		calls.push(`raw ${type} ${name}`);
		if (ad instanceof Error) throw ad;
		return { AD: ad };
	}) as RawDNSQueryFunction;
	return { calls, queryDNS, rawQueryDNS };
}

async function pin(
	domain: string,
	answers: Answers,
	ad: boolean | Error,
	opts: { raw?: boolean; zone?: ZoneContext; timeout?: number } = {},
) {
	const trace = makeTrace(answers, ad);
	const result = await checkDNSSEC(domain, trace.queryDNS, {
		...(opts.raw === false ? {} : { rawQueryDNS: trace.rawQueryDNS }),
		...(opts.zone ? { zone: opts.zone } : {}),
		...(opts.timeout !== undefined ? { timeout: opts.timeout } : {}),
	});
	return { result, calls: trace.calls };
}

describe('checkDNSSEC output pin', () => {
	it('signed zone with AD set and modern algorithm', async () => {
		expect(await pin('example.com', { DNSKEY: [DNSKEY_OK], DS: [DS_OK] }, true)).toMatchSnapshot();
	});

	it('signed zone with NSEC3PARAM audits (excessive iterations + salt)', async () => {
		expect(
			await pin('example.com', { DNSKEY: [DNSKEY_OK], DS: [DS_OK], NSEC3PARAM: ['1 0 150 aabbccdd'] }, true),
		).toMatchSnapshot();
	});

	it('signed zone with NSEC3PARAM non-zero iterations and empty salt', async () => {
		expect(await pin('example.com', { DNSKEY: [DNSKEY_OK], DS: [DS_OK], NSEC3PARAM: ['1 0 5 -'] }, true)).toMatchSnapshot();
	});

	it('validated chain with no auditable material falls back to the affirmative finding', async () => {
		expect(await pin('example.com', { DNSKEY: ['garbage'], DS: ['bad'] }, true)).toMatchSnapshot();
	});

	it('unsigned zone: DNSSEC not enabled with penaltyOverride 40', async () => {
		expect(await pin('example.com', {}, false)).toMatchSnapshot();
	});

	it('unsigned zone with a transient AD=true is still unsigned', async () => {
		expect(await pin('example.com', {}, true)).toMatchSnapshot();
	});

	it('island of trust: DNSKEY without parent DS', async () => {
		expect(await pin('example.com', { DNSKEY: [DNSKEY_OK] }, false)).toMatchSnapshot();
	});

	it('broken chain: parent DS without child DNSKEY', async () => {
		expect(await pin('example.com', { DS: [DS_OK] }, false)).toMatchSnapshot();
	});

	it('validation failing: DNSKEY + DS but AD not set', async () => {
		expect(await pin('example.com', { DNSKEY: [DNSKEY_OK], DS: [DS_OK] }, false)).toMatchSnapshot();
	});

	it('no rawQueryDNS: AD cannot be measured, controlPresent is undefined', async () => {
		expect(await pin('example.com', { DNSKEY: [DNSKEY_OK], DS: [DS_OK] }, true, { raw: false })).toMatchSnapshot();
	});

	it('no rawQueryDNS on an unsigned zone', async () => {
		expect(await pin('example.com', {}, true, { raw: false })).toMatchSnapshot();
	});

	it('weak algorithm: deprecated RSA/SHA-1 DNSKEY with SHA-1 DS digest', async () => {
		expect(
			await pin('example.com', { DNSKEY: ['257 3 5 AwEAAcLegacyKeyMaterial=='], DS: ['12345 5 1 abc123def4567890abc123def4567890abc12345'] }, true),
		).toMatchSnapshot();
	});

	it('algorithm tiers: RSA/SHA-256, RSA/SHA-512 and an IANA mnemonic', async () => {
		expect(
			await pin(
				'example.com',
				{ DNSKEY: ['257 3 8 keyA==', '256 3 10 keyB==', '257 3 ECDSAP256SHA256 keyC==', '257 3 99 keyD==', 'garbage'], DS: [DS_OK, '999 8 2 ffff', 'bad'] },
				true,
			),
		).toMatchSnapshot();
	});

	it('DS references a different algorithm than the published DNSKEY (mismatch shape)', async () => {
		expect(
			await pin('example.com', { DNSKEY: ['257 3 8 keyA=='], DS: ['54321 13 2 abc123def4567890abc123def4567890abc123def4567890abc123def4567890'] }, true),
		).toMatchSnapshot();
	});

	it('AD probe throws: not assessed, no further queries', async () => {
		expect(await pin('example.com', { DNSKEY: [DNSKEY_OK], DS: [DS_OK] }, new Error('boom'))).toMatchSnapshot();
	});

	it('DNSKEY lookup throws while DS answered: chain not assessable', async () => {
		expect(await pin('example.com', { DNSKEY: new Error('timeout'), DS: [DS_OK] }, true)).toMatchSnapshot();
	});

	it('DS lookup throws while DNSKEY answered: chain not assessable', async () => {
		expect(await pin('example.com', { DNSKEY: [DNSKEY_OK], DS: new Error('timeout') }, true)).toMatchSnapshot();
	});

	it('both DS and DNSKEY lookups throw', async () => {
		expect(await pin('example.com', { DNSKEY: new Error('t'), DS: new Error('t') }, false)).toMatchSnapshot();
	});

	it('DNSKEY SERVFAIL with an empty answer is an unmeasured leg, not an unsigned zone', async () => {
		expect(await pin('example.com', { DNSKEY: { records: [], rcode: 2 }, DS: [] }, false)).toMatchSnapshot();
	});

	it('DS REFUSED with an empty answer beside a DNSKEY', async () => {
		expect(await pin('example.com', { DNSKEY: [DNSKEY_OK], DS: { records: [], rcode: 5 } }, false)).toMatchSnapshot();
	});

	it('NXDOMAIN on both legs is a conclusive absence', async () => {
		expect(await pin('example.com', { DNSKEY: { records: [], rcode: 3 }, DS: { records: [], rcode: 3 } }, false)).toMatchSnapshot();
	});

	it('NSEC3PARAM lookup throwing is swallowed', async () => {
		expect(await pin('example.com', { DNSKEY: [DNSKEY_OK], DS: [DS_OK], NSEC3PARAM: new Error('x') }, true)).toMatchSnapshot();
	});

	it('custom timeout is passed through without extra queries', async () => {
		expect(await pin('example.com', { DNSKEY: [DNSKEY_OK], DS: [DS_OK] }, true, { timeout: 1234 })).toMatchSnapshot();
	});

	it('registry-managed ccTLD: validated chain gets the moderate deduction finding', async () => {
		expect(await pin('example.co.tz', { DNSKEY: [DNSKEY_OK], DS: [DS_OK] }, true)).toMatchSnapshot();
	});

	it('registry-managed via NS overlap with the parent zone', async () => {
		expect(
			await pin('sub.example.com', { DNSKEY: [DNSKEY_OK], DS: [DS_OK], 'NS@sub.example.com': ['ns1.reg.net.'], 'NS@example.com': ['NS1.reg.net'] }, true),
		).toMatchSnapshot();
	});

	it('not registry-managed: NS sets do not overlap', async () => {
		expect(
			await pin('sub.example.com', { DNSKEY: [DNSKEY_OK], DS: [DS_OK], 'NS@sub.example.com': ['ns1.own.net.'], 'NS@example.com': ['ns1.reg.net'] }, true),
		).toMatchSnapshot();
	});

	it('registry detection not consulted when AD is unset', async () => {
		expect(await pin('example.co.tz', { DNSKEY: [DNSKEY_OK], DS: [DS_OK] }, false)).toMatchSnapshot();
	});

	describe('zone context', () => {
		const zone = (over: Partial<ZoneContext>): ZoneContext => ({
			scannedLabel: 'www.example.com',
			registrableDomain: 'example.com',
			isApex: false,
			zoneApex: 'example.com',
			apexNsRecords: ['ns1.example.com'],
			delegationStatus: 'inherited',
			...over,
		});

		it('unknown delegation on a non-apex label: not assessed with no queries', async () => {
			expect(await pin('www.example.com', {}, false, { zone: zone({ delegationStatus: 'unknown' }) })).toMatchSnapshot();
		});

		it('inherited label evaluates the apex and leads with the inheritance note (signed)', async () => {
			expect(
				await pin('www.example.com', { DNSKEY: [DNSKEY_OK], DS: [DS_OK] }, true, { zone: zone({}) }),
			).toMatchSnapshot();
		});

		it('inherited label on an unsigned apex', async () => {
			expect(await pin('www.example.com', {}, false, { zone: zone({}) })).toMatchSnapshot();
		});

		it('inherited label whose chain is unmeasured', async () => {
			expect(
				await pin('www.example.com', { DNSKEY: [DNSKEY_OK], DS: new Error('t') }, false, { zone: zone({}) }),
			).toMatchSnapshot();
		});

		it('apex zone context behaves like no zone context', async () => {
			expect(
				await pin('example.com', { DNSKEY: [DNSKEY_OK], DS: [DS_OK] }, true, {
					zone: zone({ scannedLabel: 'example.com', isApex: true, delegationStatus: 'apex' }),
				}),
			).toMatchSnapshot();
		});

		it('non-apex label with a non-inherited status is evaluated as itself', async () => {
			expect(
				await pin('sub.example.com', { DNSKEY: [DNSKEY_OK], DS: [DS_OK] }, true, {
					zone: zone({ scannedLabel: 'sub.example.com', zoneApex: 'sub.example.com', delegationStatus: 'undelegated_broken' }),
				}),
			).toMatchSnapshot();
		});
	});

	it('invariant: the unsigned-zone finding grades 60 and is never a missing control', async () => {
		const { result } = await pin('example.com', {}, false);
		const f = result.findings.find((x) => x.title === 'DNSSEC not enabled');
		expect(f?.metadata).toMatchObject({ penaltyOverride: 40, missingControl: false });
		expect(result.score).toBe(60);
		expect(result.passed).toBe(true);
	});
});
