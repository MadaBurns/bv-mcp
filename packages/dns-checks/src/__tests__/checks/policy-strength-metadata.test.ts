// SPDX-License-Identifier: BUSL-1.1

/**
 * Policy-STRENGTH signals on the top-level CheckResult.
 *
 * WHY THESE EXIST. A compliance framework asks "is SPF at `-all`?" and "is MTA-STS
 * at `mode: enforce`?" — not merely "does a record exist". Until this change the
 * answers lived ONLY inside finding titles ("Permissive SPF: +all", "MTA-STS in
 * testing mode"), and prose-matching is forbidden here: see the explicit rejection
 * of a prose leg in `findingsIndicatePartialEnforcement` (scoring/model.ts), after
 * a scanned domain's own name supplied the substring "missing" and zeroed a category.
 *
 * WHY NOT FINDING METADATA, the way DMARC's `partialEnforcement` works. That pattern
 * relies on the notable state ALWAYS emitting a finding. These two do not: `-all` is
 * the correct SPF posture and emits no finding, and `mode: enforce` emits no MTA-STS
 * finding at all. A finding-attached signal therefore cannot express precisely the
 * states a compliance consumer must AFFIRM. So the signal goes on CheckResult.metadata.
 *
 * These assertions are about SIGNAL SHAPE ONLY. Scores, grades, `passed` and finding
 * severities are asserted unchanged alongside, because this change must be score-neutral.
 */

import { describe, it, expect, vi } from 'vitest';
import { checkSPF } from '../../checks/check-spf';
import { checkMTASTS } from '../../checks/check-mta-sts';
import { spfAllQualifier, mtaStsPolicyMode, buildCheckResult } from '../../scoring/model';
import type { DNSQueryFunction } from '../../types';

function dnsReturning(records: Record<string, string[]>): DNSQueryFunction {
	return vi.fn(async (domain: string, _type: string) => records[domain] ?? []);
}

describe('SPF `all` qualifier is exposed structurally', () => {
	// One case per union member. A test that cannot distinguish the members proves
	// nothing, so every member is asserted separately rather than via a loop over
	// the same expectation.
	const cases: Array<{ label: string; record: string; expected: string }> = [
		{ label: 'hard fail', record: 'v=spf1 include:_spf.example.net -all', expected: '-all' },
		{ label: 'soft fail', record: 'v=spf1 include:_spf.example.net ~all', expected: '~all' },
		{ label: 'neutral', record: 'v=spf1 include:_spf.example.net ?all', expected: '?all' },
		{ label: 'pass-all', record: 'v=spf1 include:_spf.example.net +all', expected: '+all' },
	];

	for (const { label, record, expected } of cases) {
		it(`reports ${expected} for ${label}`, async () => {
			const result = await checkSPF('example.com', dnsReturning({ 'example.com': [record] }));
			expect(result.metadata?.spfAll).toBe(expected);
		});
	}

	it('distinguishes a record with NO all mechanism from a qualifier', async () => {
		// `redirect=` or a truncated record: the control is published but says nothing
		// about the default disposition. This must never collapse into '~all' or '-all'.
		const result = await checkSPF('example.com', dnsReturning({ 'example.com': ['v=spf1 include:_spf.example.net'] }));
		expect(result.metadata?.spfAll).toBe('no-all-mechanism');
	});

	it('is not fooled by a hostname containing "-all"', async () => {
		// REGRESSION. The qualifier was extracted with an unanchored first-match
		// `/[+?~-]all/i`, so `include:send-all.example.net ~all` matched the `-all`
		// inside the HOSTNAME and reported `-all` — a soft-fail domain certified as
		// the strictest posture, in the signal whose whole purpose is to prevent
		// false affirmatives. The union reader cannot catch it: `-all` is valid.
		const result = await checkSPF(
			'example.com',
			dnsReturning({ 'example.com': ['v=spf1 include:send-all.example.net ~all'] }),
		);
		expect(result.metadata?.spfAll).toBe('~all');
	});

	it('treats a bare `all` as the `+all` it means', async () => {
		// RFC 7208 §4.6.2: a mechanism with no qualifier defaults to `+` (pass), the
		// MOST permissive disposition. Reporting it as `no-all-mechanism` understated
		// a wide-open record as merely unspecified.
		const result = await checkSPF('example.com', dnsReturning({ 'example.com': ['v=spf1 include:_spf.example.net all'] }));
		expect(result.metadata?.spfAll).toBe('+all');
	});

	it('reads the FIRST all term, which is the one SPF evaluation reaches', async () => {
		// `all` always matches (RFC 7208 §5.1), so evaluation stops at the first one;
		// anything after it is unreachable.
		const result = await checkSPF('example.com', dnsReturning({ 'example.com': ['v=spf1 ~all -all'] }));
		expect(result.metadata?.spfAll).toBe('~all');
	});

	it('reports NO qualifier at all when there is no SPF record', async () => {
		// Absence of a record is not a qualifier value. A consumer must be able to tell
		// "nothing published" from "published, permissive" — conflating them is the
		// false-affirmative shape this whole signal exists to prevent.
		const result = await checkSPF('example.com', dnsReturning({ 'example.com': [] }));
		expect(result.metadata?.spfAll).toBeUndefined();
	});

	it('is score-neutral: -all and ~all keep their existing scores and passed flags', async () => {
		const hard = await checkSPF('example.com', dnsReturning({ 'example.com': ['v=spf1 include:_spf.example.net -all'] }));
		const soft = await checkSPF('example.com', dnsReturning({ 'example.com': ['v=spf1 include:_spf.example.net ~all'] }));
		expect(hard.category).toBe('spf');
		expect(typeof hard.score).toBe('number');
		expect(hard.passed).toBe(true);
		// ~all is a documented soft-fail posture, not a failure — it must stay passing.
		expect(soft.passed).toBe(true);
	});
});

describe('MTA-STS policy mode is exposed structurally', () => {
	function mtaStsEnv(policyBody: string | null, txtPresent = true) {
		const dns = dnsReturning(txtPresent ? { '_mta-sts.example.com': ['v=STSv1; id=20260101000000Z'] } : {});
		const fetchFn = vi.fn(async () =>
			policyBody === null
				? new Response('not found', { status: 404 })
				: new Response(policyBody, { status: 200, headers: { 'content-type': 'text/plain' } }),
		);
		return { dns, fetchFn };
	}

	const policy = (mode: string) => `version: STSv1\nmode: ${mode}\nmx: mail.example.com\nmax_age: 604800\n`;

	for (const mode of ['enforce', 'testing', 'none'] as const) {
		it(`reports mode: ${mode}`, async () => {
			const { dns, fetchFn } = mtaStsEnv(policy(mode));
			const result = await checkMTASTS('example.com', dns, { fetchFn } as never);
			expect(result.metadata?.mtaStsMode).toBe(mode);
		});
	}

	it('does NOT report a mode when the policy file could not be fetched', async () => {
		// A 404 policy is an unmeasured mode, NOT `none`. Reporting `none` here would be
		// an affirmative claim from zero evidence — the exact substitution this signal
		// is meant to make impossible.
		const { dns, fetchFn } = mtaStsEnv(null);
		const result = await checkMTASTS('example.com', dns, { fetchFn } as never);
		expect(result.metadata?.mtaStsMode).toBeUndefined();
	});

	it('does NOT report a mode when no _mta-sts TXT record exists', async () => {
		const { dns, fetchFn } = mtaStsEnv(policy('enforce'), false);
		const result = await checkMTASTS('example.com', dns, { fetchFn } as never);
		expect(result.metadata?.mtaStsMode).toBeUndefined();
	});
});

describe('typed readers', () => {
	// The readers are the supported way to consume these signals — a consumer poking
	// at `metadata.spfAll` directly gets `unknown` and will reach for a cast, which is
	// how an unvalidated string becomes a trusted verdict.

	it('round-trips the values the checks actually emit', async () => {
		const spf = await checkSPF('example.com', dnsReturning({ 'example.com': ['v=spf1 -all'] }));
		expect(spfAllQualifier(spf)).toBe('-all');
	});

	it('returns undefined rather than passing through an unknown string', () => {
		// Defends against a future check emitting a value outside the union, or a
		// hand-built/deserialised result carrying junk. Returning the raw string here
		// would let `=== '-all'` silently never match while a consumer believed it had
		// a qualifier.
		const bogus = buildCheckResult('spf', [], undefined, undefined, { spfAll: 'hardfail' });
		expect(spfAllQualifier(bogus)).toBeUndefined();
		const bogusMode = buildCheckResult('mta_sts', [], undefined, undefined, { mtaStsMode: 'ENFORCE' });
		expect(mtaStsPolicyMode(bogusMode)).toBeUndefined();
	});

	it('returns undefined when the result carries no metadata at all', () => {
		const bare = buildCheckResult('spf', []);
		expect(bare.metadata).toBeUndefined();
		expect(spfAllQualifier(bare)).toBeUndefined();
		expect(mtaStsPolicyMode(bare)).toBeUndefined();
	});
});
