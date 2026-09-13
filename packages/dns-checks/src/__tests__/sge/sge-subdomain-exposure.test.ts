// SPDX-License-Identifier: BUSL-1.1

/**
 * SGE advisories — the subdomain exposure, and the removed `pct` tag.
 *
 * THE RULING (bv-mcp #991, operator-decided). `p=reject; sp=none` SATISFIES the
 * SGE `dmarc_reject` control. The real exposure is reported as a SEPARATE,
 * distinct finding — never by downgrading `dmarc_reject`.
 *
 * Standards basis:
 * - RFC 9989 §4.7, verbatim: `sp` "applies only to existing subdomains of the
 *   message's Organizational Domain in the DNS hierarchy and not to the
 *   Organizational Domain itself." `sp=none` therefore does NOT weaken the apex
 *   policy that the `dmarc_reject` control is about.
 * - NZ SGE's DMARC requirement, in full: "DMARC needs to be set to p=reject on
 *   all email enabled domains." It never mentions `sp`. NZISM 15 point 2 point
 *   36 point C point 02 — the only binding NZ control naming DMARC — likewise
 *   names `p=reject` and is silent on `sp`.
 * - SGE explicitly REFUSES `sp` as the subdomain mechanism: "This requirement
 *   remains even if the root level domain has SP=reject set within its DMARC
 *   record". Its remedy is an explicit `_dmarc` record on EVERY sub-domain.
 *
 * So the exposure is real and must be visible, but it is NOT a `dmarc_reject`
 * verdict. It surfaces as a typed advisory alongside the controls.
 *
 * WHY THIS IS NOT A STRING. A caller must be able to render the exposure
 * distinctly — its own row, its own severity, its own evidence. Burying it in a
 * control's `requirement` prose or in a summary sentence would make it
 * unrenderable and unparseable, and prose inference is forbidden on this path.
 */

import { describe, it, expect } from 'vitest';
import { evaluateSgeCompliance, SGE_ADVISORY_IDS } from '../../sge';
import type { SgeAdvisoryId, SgeEvaluation } from '../../sge';
import type { CheckCategory, CheckResult, Finding } from '../../types';

function result(category: CheckCategory, over: Partial<CheckResult> = {}): CheckResult {
	return { category, passed: true, score: 100, findings: [] as Finding[], ...over };
}

const MX_PRESENT = result('mx', { controlPresent: true });

/** A dmarc result carrying the structured signals the check emits from 1.44.0. */
function dmarc(metadata: Record<string, unknown>, over: Partial<CheckResult> = {}): CheckResult {
	return result('dmarc', { controlPresent: true, recordPresent: true, metadata, ...over });
}

/** The health.govt.nz record shape: enforcing apex, open existing subdomains, no np=. */
const HEALTH_SHAPE = {
	dmarcPolicy: 'reject',
	dmarcSubdomainPolicy: 'none',
	dmarcNonExistentSubdomainPolicy: 'not-specified',
	dmarcPctPresent: true,
	dmarcInheritedFromParent: false,
};

function advisory(evaluation: SgeEvaluation, id: SgeAdvisoryId) {
	return evaluation.advisories.find((a) => a.id === id);
}

describe('the advisories array is part of the contract, always', () => {
	it('is present and empty rather than absent when there is nothing to say', () => {
		const evaluation = evaluateSgeCompliance('example.test', []);
		expect(Array.isArray(evaluation.advisories)).toBe(true);
		expect(evaluation.advisories).toEqual([]);
	});

	it('declares its ids so a renderer can exhaustively map them', () => {
		expect([...SGE_ADVISORY_IDS]).toEqual(['subdomain_policy_gap', 'pct_tag_present']);
	});
});

describe('p=reject; sp=none — the ruling, enforced in both directions', () => {
	const evaluation = evaluateSgeCompliance('health.govt.nz', [MX_PRESENT, dmarc(HEALTH_SHAPE)]);

	it('keeps dmarc_reject SATISFIED — sp does not weaken the apex policy (RFC 9989 §4.7)', () => {
		const control = evaluation.controls.find((c) => c.control === 'dmarc_reject');
		expect(control?.status).toBe('satisfied');
	});

	it('raises the subdomain exposure as its OWN advisory, not as a control status', () => {
		const found = advisory(evaluation, 'subdomain_policy_gap');
		expect(found).toBeDefined();
		expect(found?.severity).toBe('exposure');
		expect(found?.relatedControl).toBe('dmarc_reject');
	});

	it('records in EVIDENCE that np= is absent and therefore mitigates nothing', () => {
		// RFC 9989 §4.7: with np absent, the policy falls back to sp, then to p. sp=none
		// therefore leaves BOTH existing and non-existent subdomains unenforced.
		const found = advisory(evaluation, 'subdomain_policy_gap');
		expect(found?.evidence).toContainEqual({ signal: 'dmarcNonExistentSubdomainPolicy()', value: 'not-specified' });
		expect(found?.evidence).toContainEqual({ signal: 'npMitigatesNonExistentSubdomains', value: false });
	});

	it('does not move the verdict — the advisory is orthogonal to the six controls', () => {
		const withProbe = evaluateSgeCompliance('health.govt.nz', [MX_PRESENT, dmarc(HEALTH_SHAPE)], { smtpTls: 'enforced' });
		const clean = evaluateSgeCompliance(
			'clean.test',
			[MX_PRESENT, dmarc({ ...HEALTH_SHAPE, dmarcSubdomainPolicy: 'reject', dmarcPctPresent: false })],
			{ smtpTls: 'enforced' },
		);
		// Both reach the same control counts; only the advisories differ.
		expect(withProbe.counts).toEqual(clean.counts);
		expect(withProbe.verdict).toBe(clean.verdict);
		expect(withProbe.advisories.map((a) => a.id)).toEqual(['subdomain_policy_gap', 'pct_tag_present']);
		expect(clean.advisories).toEqual([]);
	});
});

describe('when the exposure exists, and when it does not', () => {
	const cases: Array<{ label: string; sp: string; p: string; expected: boolean }> = [
		{ label: 'reject apex, open subdomains', p: 'reject', sp: 'none', expected: true },
		{ label: 'reject apex, quarantined subdomains', p: 'reject', sp: 'quarantine', expected: true },
		{ label: 'quarantine apex, open subdomains', p: 'quarantine', sp: 'none', expected: true },
		{ label: 'reject apex, reject subdomains', p: 'reject', sp: 'reject', expected: false },
		{ label: 'quarantine apex, quarantine subdomains', p: 'quarantine', sp: 'quarantine', expected: false },
		{ label: 'quarantine apex, reject subdomains (stronger, not weaker)', p: 'quarantine', sp: 'reject', expected: false },
	];

	for (const { label, p, sp, expected } of cases) {
		it(`${expected ? 'raises' : 'does not raise'} the exposure for ${label}`, () => {
			const evaluation = evaluateSgeCompliance('example.test', [
				MX_PRESENT,
				dmarc({ ...HEALTH_SHAPE, dmarcPolicy: p, dmarcSubdomainPolicy: sp, dmarcPctPresent: false }),
			]);
			expect(advisory(evaluation, 'subdomain_policy_gap') !== undefined).toBe(expected);
		});
	}

	it('does not raise the exposure when the apex is NOT enforcing — p=none is a control failure, not a subdomain gap', () => {
		// A p=none domain fails dmarc_reject outright. Adding a subdomain advisory on top
		// would double-report the same absence of enforcement as two separate problems.
		const evaluation = evaluateSgeCompliance('example.test', [
			MX_PRESENT,
			dmarc({ ...HEALTH_SHAPE, dmarcPolicy: 'none', dmarcSubdomainPolicy: 'none' }, { controlPresent: false }),
		]);
		expect(evaluation.controls.find((c) => c.control === 'dmarc_reject')?.status).toBe('not_satisfied');
		expect(advisory(evaluation, 'subdomain_policy_gap')).toBeUndefined();
	});

	it('does not raise the exposure when sp= is merely absent — inheritance means subdomains get p=', () => {
		// RFC 9989 §4.7: no sp means subdomains apply p. There is no gap to report.
		const evaluation = evaluateSgeCompliance('example.test', [
			MX_PRESENT,
			dmarc({ ...HEALTH_SHAPE, dmarcSubdomainPolicy: 'not-specified', dmarcPctPresent: false }),
		]);
		expect(advisory(evaluation, 'subdomain_policy_gap')).toBeUndefined();
	});

	it('does not raise the exposure on an INHERITED record — the queried name is itself a subdomain', () => {
		const evaluation = evaluateSgeCompliance('www.example.test', [
			MX_PRESENT,
			dmarc({ ...HEALTH_SHAPE, dmarcInheritedFromParent: true, dmarcPctPresent: false }),
		]);
		expect(advisory(evaluation, 'subdomain_policy_gap')).toBeUndefined();
	});

	it('raises nothing at all when the dmarc check emitted no structured signals (an older result)', () => {
		// Backward compatibility: a 1.43.0-era CheckResult has no metadata. Absence of a
		// signal is not evidence of a clean subdomain posture, so nothing is ASSERTED —
		// but nothing is invented either.
		const evaluation = evaluateSgeCompliance('example.test', [MX_PRESENT, result('dmarc', { controlPresent: true, recordPresent: true })]);
		expect(evaluation.advisories).toEqual([]);
		expect(evaluation.controls.find((c) => c.control === 'dmarc_reject')?.status).toBe('satisfied');
	});

	it('notes np= mitigation for NON-EXISTENT subdomains without retracting the exposure', () => {
		// np=reject closes the non-existent-subdomain half only. EXISTING subdomains stay
		// unenforced under sp=none, so the advisory still fires — matching the scorer,
		// which downgrades its finding to `low` but never withdraws it.
		const evaluation = evaluateSgeCompliance('example.test', [
			MX_PRESENT,
			dmarc({ ...HEALTH_SHAPE, dmarcNonExistentSubdomainPolicy: 'reject', dmarcPctPresent: false }),
		]);
		const found = advisory(evaluation, 'subdomain_policy_gap');
		expect(found).toBeDefined();
		expect(found?.evidence).toContainEqual({ signal: 'npMitigatesNonExistentSubdomains', value: true });
	});
});

describe('the pct= advisory (RFC 9989 Appendix A.6 removes the tag)', () => {
	it('fires on pct=100 — presence is the question, not the value', () => {
		const evaluation = evaluateSgeCompliance('example.test', [MX_PRESENT, dmarc({ ...HEALTH_SHAPE, dmarcPctPresent: true })]);
		const found = advisory(evaluation, 'pct_tag_present');
		expect(found).toBeDefined();
		expect(found?.severity).toBe('advisory');
		expect(found?.relatedControl).toBe('dmarc_reject');
	});

	it('does not fire when no pct= is published', () => {
		const evaluation = evaluateSgeCompliance('example.test', [MX_PRESENT, dmarc({ ...HEALTH_SHAPE, dmarcPctPresent: false })]);
		expect(advisory(evaluation, 'pct_tag_present')).toBeUndefined();
	});

	it('is an advisory, never an exposure — a removed tag is not an open subdomain tree', () => {
		const evaluation = evaluateSgeCompliance('example.test', [MX_PRESENT, dmarc(HEALTH_SHAPE)]);
		const severities = Object.fromEntries(evaluation.advisories.map((a) => [a.id, a.severity]));
		expect(severities).toEqual({ subdomain_policy_gap: 'exposure', pct_tag_present: 'advisory' });
	});
});
