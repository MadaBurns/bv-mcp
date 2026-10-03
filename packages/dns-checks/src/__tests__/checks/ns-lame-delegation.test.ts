// SPDX-License-Identifier: BUSL-1.1

/**
 * Pure verdict arithmetic + finding shape for lame-delegation ("Sitting Ducks")
 * detection. The I/O side (per-nameserver probing through `checkNS`) is covered
 * end-to-end in `test/check-ns-lame-delegation.spec.ts`.
 *
 * The invariant these cases exist to lock: an `unknown` outcome — a probe that
 * FAILED rather than answered — must never move the verdict toward a scored
 * deficiency. A measurement failure is not a finding.
 */

import { describe, expect, it } from 'vitest';
import { checkNS } from '../../checks/check-ns';
import type { DNSQueryFunction, RawDNSResponse } from '../../types';
import {
	MAX_LAME_DELEGATION_PROBES,
	assessLameDelegation,
	getPartialLameDelegationFinding,
	getTotalLameDelegationFinding,
	type NameserverProbeResult,
} from '../../checks/ns-analysis';

function probes(...pairs: Array<[string, NameserverProbeResult['outcome']]>): NameserverProbeResult[] {
	return pairs.map(([nameserver, outcome]) => ({ nameserver, outcome }));
}

describe('MAX_LAME_DELEGATION_PROBES', () => {
	it('is pinned at 4 — the NS check adds at most 4 subrequests to a healthy scan', () => {
		// A cold scan_domain already fans out ~20 subrequests. Raising this raises the
		// per-scan DNS cost for every domain, so it is a deliberate, tested constant.
		expect(MAX_LAME_DELEGATION_PROBES).toBe(4);
	});
});

describe('assessLameDelegation', () => {
	it('classifies a mixed set as partial — the exploitable Sitting Ducks shape', () => {
		const a = assessLameDelegation(probes(['ns1', 'resolves'], ['ns2', 'no_address']));
		expect(a.verdict).toBe('partial');
		expect(a.resolving).toEqual(['ns1']);
		expect(a.nonResolving).toEqual(['ns2']);
		expect(a.unknown).toEqual([]);
	});

	it('classifies an all-determinately-failing set as total', () => {
		expect(assessLameDelegation(probes(['ns1', 'no_address'], ['ns2', 'no_address'])).verdict).toBe('total');
	});

	it('classifies an all-resolving set as healthy', () => {
		expect(assessLameDelegation(probes(['ns1', 'resolves'], ['ns2', 'resolves'])).verdict).toBe('healthy');
	});

	it('classifies an all-unknown set as indeterminate, never total', () => {
		// Every probe errored: nothing was measured, so nothing is claimed. Reporting
		// `total` here would let a flaky resolver mark a healthy zone inconclusive.
		const a = assessLameDelegation(probes(['ns1', 'unknown'], ['ns2', 'unknown']));
		expect(a.verdict).toBe('indeterminate');
		expect(a.unknown).toEqual(['ns1', 'ns2']);
	});

	it('treats an empty probe set as indeterminate', () => {
		expect(assessLameDelegation([]).verdict).toBe('indeterminate');
	});

	it('an unknown outcome cannot suppress a real partial verdict', () => {
		const a = assessLameDelegation(probes(['ns1', 'resolves'], ['ns2', 'no_address'], ['ns3', 'unknown']));
		expect(a.verdict).toBe('partial');
		expect(a.unknown).toEqual(['ns3']);
	});

	it('one determinate failure with the rest unmeasurable stays inconclusive, not a HIGH claim', () => {
		// Nothing was PROVEN to still answer, so `partial` (a scored HIGH finding) would be
		// asserting more than the evidence supports. `total` routes to the inconclusive
		// path instead — the conservative direction.
		const a = assessLameDelegation(probes(['ns1', 'no_address'], ['ns2', 'unknown']));
		expect(a.verdict).toBe('total');
		expect(a.resolving).toEqual([]);
	});
});

describe('lame-delegation findings', () => {
	it('the partial finding is CRITICAL and names both sides of the split', () => {
		// Was `high` until the Sitting Ducks escalation. Severity is `critical` for BOTH
		// claimability branches — what the claimability probe changes is the CONFIDENCE
		// stamp, and therefore whether the engine's verified-critical penalty fires. The
		// two-argument call here is the not-shown-claimable branch (`claimable` defaults to
		// `[]`), which is the conservative default for any caller that cannot probe.
		// Full escalation coverage: `check-ns-lame-delegation-escalation.test.ts`.
		const a = assessLameDelegation(probes(['ns1.a.com', 'resolves'], ['ns2.b.net', 'no_address']));
		const f = getPartialLameDelegationFinding('example.com', a);
		expect(f.category).toBe('ns');
		expect(f.severity).toBe('critical');
		expect(f.metadata?.confidence).toBe('deterministic');
		expect(f.detail).toContain('ns2.b.net');
		expect(f.detail).toContain('ns1.a.com');
		expect(f.metadata?.lameDelegation).toBe('partial');
	});

	it('the partial finding does NOT set missingControl — it is a penalty, not a category-zeroing absence', () => {
		const a = assessLameDelegation(probes(['ns1.a.com', 'resolves'], ['ns2.b.net', 'no_address']));
		expect(getPartialLameDelegationFinding('example.com', a).metadata?.missingControl).toBeUndefined();
	});

	it('the total finding carries the transient shape so scoring EXCLUDES the category', () => {
		const a = assessLameDelegation(probes(['ns1.a.com', 'no_address'], ['ns2.b.net', 'no_address']));
		const f = getTotalLameDelegationFinding('example.com', a);
		expect(f.severity).toBe('low');
		expect(f.metadata?.errorKind).toBe('dns_error');
		expect(f.metadata?.inconclusive).toBe(true);
	});

	it('the total finding never asserts domainResolves — that key belongs to the NS/A visibility probe', () => {
		// `domainResolves: false` is the package's non-resolving guard key (scoring/resolution.ts).
		// This probe only proves the nameserver HOSTS have no address, which cannot distinguish
		// a dead zone from a resolver-side outage.
		const a = assessLameDelegation(probes(['ns1.a.com', 'no_address'], ['ns2.b.net', 'no_address']));
		expect(getTotalLameDelegationFinding('example.com', a).metadata?.domainResolves).toBeUndefined();
	});
});

// ── SQ-279 item 2: an UNANSWERED host lookup is not a missing address ─────────────────
//
// `probeNameserverReachable` read `A: SERVFAIL` + `AAAA: SERVFAIL` as `no_address`, i.e. a
// lame delegation, and the SOA probe read a SERVFAIL as "No SOA record". A resolver that
// could not answer measured nothing; only NOERROR/NXDOMAIN-empty answers are evidence.

const SERVFAIL = 2;
const NXDOMAIN = 3;
const A_ANSWER = { type: 1, data: '192.0.2.1' };

function nsResolvers(raw: Record<string, Partial<Record<string, RawDNSResponse>>>) {
	const queryDNS = (async (name: string, type: string) => {
		if (type === 'NS' && name === 'victim.example') return ['ns1.healthy.example.', 'ns2.provider.example.'];
		return [];
	}) as never;
	const rawQueryDNS = (async (name: string, type: string): Promise<RawDNSResponse> =>
		raw[name]?.[type] ?? { Status: 0, Answer: [] }) as never;
	return { queryDNS, rawQueryDNS };
}

describe('checkNS — SERVFAIL is unmeasured, not lame (SQ-279 item 2)', () => {
	it('does not file a lame delegation when a nameserver host A and AAAA both SERVFAIL', async () => {
		const { queryDNS, rawQueryDNS } = nsResolvers({
			'ns1.healthy.example': { A: { Status: 0, Answer: [A_ANSWER] } },
			'ns2.provider.example': { A: { Status: SERVFAIL, Answer: [] }, AAAA: { Status: SERVFAIL, Answer: [] } },
		});
		const result = await checkNS('victim.example', queryDNS, { rawQueryDNS });
		expect(result.findings.find((f) => f.metadata?.lameDelegation !== undefined)).toBeUndefined();
	});

	it('does not file a lame delegation when A is NOERROR-empty but AAAA SERVFAILs', async () => {
		const { queryDNS, rawQueryDNS } = nsResolvers({
			'ns1.healthy.example': { A: { Status: 0, Answer: [A_ANSWER] } },
			'ns2.provider.example': { A: { Status: 0, Answer: [] }, AAAA: { Status: SERVFAIL, Answer: [] } },
		});
		const result = await checkNS('victim.example', queryDNS, { rawQueryDNS });
		expect(result.findings.find((f) => f.metadata?.lameDelegation !== undefined)).toBeUndefined();
	});

	it('still files the partial lame delegation for a MEASURED address-less host (positive control)', async () => {
		const { queryDNS, rawQueryDNS } = nsResolvers({
			'ns1.healthy.example': { A: { Status: 0, Answer: [A_ANSWER] } },
			'ns2.provider.example': { A: { Status: NXDOMAIN, Answer: [] }, AAAA: { Status: NXDOMAIN, Answer: [] } },
		});
		const result = await checkNS('victim.example', queryDNS, { rawQueryDNS });
		expect(result.findings.find((f) => f.metadata?.lameDelegation === 'partial')).toBeDefined();
	});

	it('does not file "No SOA record" when the SOA lookup SERVFAILs', async () => {
		const { queryDNS, rawQueryDNS } = nsResolvers({
			'ns1.healthy.example': { A: { Status: 0, Answer: [A_ANSWER] } },
			'ns2.provider.example': { A: { Status: 0, Answer: [A_ANSWER] } },
			'victim.example': { SOA: { Status: SERVFAIL, Answer: [] } },
		});
		const result = await checkNS('victim.example', queryDNS, { rawQueryDNS });
		expect(result.findings.find((f) => f.title === 'No SOA record')).toBeUndefined();
	});

	it('abstains (no "No NS records found" critical) when the NS lookup itself SERVFAILs', async () => {
		const queryDNS = (async () => []) as unknown as DNSQueryFunction;
		queryDNS.withRcode = async () => ({ records: [], rcode: SERVFAIL });
		const result = await checkNS('victim.example', queryDNS, { rawQueryDNS: (async () => ({ Status: 0, Answer: [] })) as never });
		expect(result.checkStatus).toBe('error');
		expect(result.findings.some((f) => f.metadata?.missingControl === true)).toBe(false);
		expect(result.findings.some((f) => f.title === 'No NS records found')).toBe(false);
	});

	it('still files "No NS records found" for a NOERROR-empty NS answer (positive control)', async () => {
		const queryDNS = (async () => []) as unknown as DNSQueryFunction;
		queryDNS.withRcode = async () => ({ records: [], rcode: 0 });
		const result = await checkNS('victim.example', queryDNS, { rawQueryDNS: (async () => ({ Status: 0, Answer: [] })) as never });
		expect(result.findings.some((f) => f.title === 'No NS records found')).toBe(true);
	});

	it('still files "No SOA record" for a NOERROR-empty SOA answer (positive control)', async () => {
		const { queryDNS, rawQueryDNS } = nsResolvers({
			'ns1.healthy.example': { A: { Status: 0, Answer: [A_ANSWER] } },
			'ns2.provider.example': { A: { Status: 0, Answer: [A_ANSWER] } },
		});
		const result = await checkNS('victim.example', queryDNS, { rawQueryDNS });
		expect(result.findings.find((f) => f.title === 'No SOA record')).toBeDefined();
	});
});
