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
	it('the partial finding is HIGH and names both sides of the split', () => {
		const a = assessLameDelegation(probes(['ns1.a.com', 'resolves'], ['ns2.b.net', 'no_address']));
		const f = getPartialLameDelegationFinding('example.com', a);
		expect(f.category).toBe('ns');
		expect(f.severity).toBe('high');
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
