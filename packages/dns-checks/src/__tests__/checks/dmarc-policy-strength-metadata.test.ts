// SPDX-License-Identifier: BUSL-1.1

/**
 * DMARC policy-strength signals on the top-level CheckResult.
 *
 * WHY THESE EXIST. `check-dmarc.ts` has parsed `sp=`, `np=` and `pct=` into
 * `DmarcFacts` since long before this change, and then threw every one of them
 * away: `buildCheckResult('dmarc', findings, dmarcEnforcing, true)` carried no
 * metadata, so the only trace of a subdomain policy that survived to a consumer
 * was a finding TITLE. Prose-matching is forbidden here — see the explicit
 * rejection of a prose leg in `findingsIndicatePartialEnforcement`
 * (scoring/model.ts), after a scanned domain's own name supplied the substring
 * "missing" and zeroed a category.
 *
 * This is the same shape bv-mcp #987 gave SPF and MTA-STS, and it is followed
 * deliberately rather than reinvented: the value goes on
 * `CheckResult.metadata`, a typed reader validates it against a closed union,
 * and a value the reader does not recognise returns `undefined` rather than
 * passing through as a trusted verdict.
 *
 * UNMEASURED IS NOT A VALUE. The three tag readers report `undefined` when NO
 * DMARC record was found at all, and the DISTINCT member `not-specified` when a
 * record exists but omits the tag. Collapsing those is the false-affirmative
 * shape these signals exist to prevent: "we found a record that says nothing
 * about subdomains" and "we found no record" are different facts, and an `sp`
 * default of `none` would be an invented one.
 *
 * These assertions are about SIGNAL SHAPE ONLY. Scores, `passed` and finding
 * severities are asserted UNCHANGED alongside, because this change is
 * score-neutral by construction.
 */

import { describe, it, expect, vi } from 'vitest';
import { checkDMARC } from '../../checks/check-dmarc';
import {
	dmarcPolicyTag,
	dmarcSubdomainPolicy,
	dmarcNonExistentSubdomainPolicy,
	dmarcPctTagPresent,
	dmarcRecordInheritedFromParent,
} from '../../scoring/model';
import type { CheckResult, DNSQueryFunction } from '../../types';

/**
 * A DNS stub that answers TXT for the names given and NODATA (empty) elsewhere.
 * NODATA rather than NXDOMAIN on purpose: NXDOMAIN halts check-dmarc's RFC 9989
 * §4.10 tree walk, which would make a "no record" case pass for the wrong reason.
 */
function dnsReturning(records: Record<string, string[]>): DNSQueryFunction {
	return vi.fn(async (name: string) => records[name] ?? []);
}

async function dmarcFor(record: string | null, domain = 'example.com'): Promise<CheckResult> {
	const records = record === null ? {} : { [`_dmarc.${domain}`]: [record] };
	return checkDMARC(domain, dnsReturning(records));
}

describe('the DMARC p= tag is exposed structurally', () => {
	const cases: Array<{ record: string; expected: string }> = [
		{ record: 'v=DMARC1; p=reject', expected: 'reject' },
		{ record: 'v=DMARC1; p=quarantine', expected: 'quarantine' },
		{ record: 'v=DMARC1; p=none', expected: 'none' },
	];

	for (const { record, expected } of cases) {
		it(`reports ${expected}`, async () => {
			expect(dmarcPolicyTag(await dmarcFor(record))).toBe(expected);
		});
	}

	it('reports `invalid` for a published-but-unparseable p=, never a policy value', async () => {
		// A junk tag is a MEASURED fact about a published record. It must not read as
		// `none` (an affirmative adverse claim) nor as `undefined` (unmeasured).
		expect(dmarcPolicyTag(await dmarcFor('v=DMARC1; p=banana'))).toBe('invalid');
	});

	it('reports `not-specified` when a record omits p= entirely', async () => {
		expect(dmarcPolicyTag(await dmarcFor('v=DMARC1; rua=mailto:x@example.com'))).toBe('not-specified');
	});

	it('reports NOTHING when no DMARC record exists — absence is not a policy', async () => {
		const result = await dmarcFor(null);
		expect(dmarcPolicyTag(result)).toBeUndefined();
		expect(result.metadata).toBeUndefined();
	});
});

describe('the DMARC sp= tag is exposed structurally', () => {
	it('reports none for p=reject; sp=none — the health.govt.nz shape', async () => {
		const result = await dmarcFor('v=DMARC1; p=reject; sp=none; pct=100; rua=mailto:x@example.com;');
		expect(dmarcPolicyTag(result)).toBe('reject');
		expect(dmarcSubdomainPolicy(result)).toBe('none');
	});

	it('reports quarantine and reject distinctly', async () => {
		expect(dmarcSubdomainPolicy(await dmarcFor('v=DMARC1; p=reject; sp=quarantine'))).toBe('quarantine');
		expect(dmarcSubdomainPolicy(await dmarcFor('v=DMARC1; p=reject; sp=reject'))).toBe('reject');
	});

	it('reports `not-specified` — NOT `none` — when sp= is absent', async () => {
		// RFC 9989 §4.7: with no sp=, subdomains inherit p=. That inheritance is the
		// CONSUMER's rule to apply; the signal reports what the record says, and the
		// record says nothing. Defaulting this to `none` would invent an exposure.
		expect(dmarcSubdomainPolicy(await dmarcFor('v=DMARC1; p=reject'))).toBe('not-specified');
	});

	it('reports `invalid` for an out-of-union sp= value', async () => {
		expect(dmarcSubdomainPolicy(await dmarcFor('v=DMARC1; p=reject; sp=nope'))).toBe('invalid');
	});
});

describe('the DMARC np= tag is exposed structurally', () => {
	it('reports the value when present', async () => {
		expect(dmarcNonExistentSubdomainPolicy(await dmarcFor('v=DMARC1; p=reject; sp=none; np=reject'))).toBe('reject');
	});

	it('reports `not-specified` when np= is absent — the RFC 9989 §4.7 fallback is the consumer’s to apply', async () => {
		// Verbatim, RFC 9989 §4.7: "If the 'np' tag is absent, the policy specified by
		// the 'sp' tag (if the 'sp' tag is present) or the policy specified by the 'p'
		// tag (if the 'sp' tag is not present) MUST be applied for non-existent
		// subdomains." The np -> sp -> p chain is therefore resolvable from these three
		// signals; baking the resolution into the signal would destroy the evidence.
		expect(dmarcNonExistentSubdomainPolicy(await dmarcFor('v=DMARC1; p=reject; sp=none'))).toBe('not-specified');
	});
});

describe('the DMARC pct= tag presence is exposed structurally', () => {
	it('reports true when pct= is published at all — even pct=100', async () => {
		// RFC 9989 Appendix A.6 REMOVES the pct tag, and the DIA SGE Deployment Guide
		// lists it among tags that should not be used. So presence is the question, not
		// the value: pct=100 is as removed-from-the-spec as pct=50.
		expect(dmarcPctTagPresent(await dmarcFor('v=DMARC1; p=reject; pct=100'))).toBe(true);
		expect(dmarcPctTagPresent(await dmarcFor('v=DMARC1; p=reject; pct=50'))).toBe(true);
	});

	it('reports false when a record is published without pct=', async () => {
		expect(dmarcPctTagPresent(await dmarcFor('v=DMARC1; p=reject'))).toBe(false);
	});

	it('reports undefined when there is no record to have a pct= tag', async () => {
		expect(dmarcPctTagPresent(await dmarcFor(null))).toBeUndefined();
	});

	it('carries no raw tag text into metadata — presence only', async () => {
		// The raw token is subject-controlled and top-level metadata does NOT pass
		// through sanitizeFindingMetadata (types.ts). A boolean cannot carry a payload.
		const result = await dmarcFor('v=DMARC1; p=reject; pct=<script>alert(1)</script>');
		expect(JSON.stringify(result.metadata)).not.toContain('script');
	});
});

describe('inheritance is exposed structurally', () => {
	it('is false when the record was found at the queried name', async () => {
		expect(dmarcRecordInheritedFromParent(await dmarcFor('v=DMARC1; p=reject'))).toBe(false);
	});

	it('is true when the RFC 9989 §4.10 tree walk found the record above the queried name', async () => {
		// www.example.com has no _dmarc record; the walk finds the org domain's.
		const result = await checkDMARC('www.example.com', dnsReturning({ '_dmarc.example.com': ['v=DMARC1; p=reject; sp=none'] }));
		expect(dmarcRecordInheritedFromParent(result)).toBe(true);
	});
});

describe('the readers refuse junk rather than passing it through', () => {
	it('returns undefined for a metadata value outside the union', async () => {
		const base = await dmarcFor('v=DMARC1; p=reject');
		const tampered: CheckResult = { ...base, metadata: { ...base.metadata, dmarcSubdomainPolicy: 'reject-ish' } };
		expect(dmarcSubdomainPolicy(tampered)).toBeUndefined();
	});

	it('returns undefined for a non-string where a policy value is expected', async () => {
		const base = await dmarcFor('v=DMARC1; p=reject');
		const tampered: CheckResult = { ...base, metadata: { ...base.metadata, dmarcPolicy: 1 } };
		expect(dmarcPolicyTag(tampered)).toBeUndefined();
	});
});

describe('score neutrality — the signals are observational', () => {
	it('leaves score, passed, controlPresent, recordPresent and finding severities untouched', async () => {
		const result = await dmarcFor('v=DMARC1; p=reject; sp=none; pct=100; rua=mailto:x@example.com;');
		// The health.govt.nz shape: enforcing apex, published record, HIGH sp finding.
		expect(result.controlPresent).toBe(true);
		expect(result.recordPresent).toBe(true);
		expect(result.findings.some((f) => f.title === 'Subdomain policy weaker than parent policy' && f.severity === 'high')).toBe(true);
		expect(result.score).toBe(50);
		expect(result.passed).toBe(true);
	});
});
