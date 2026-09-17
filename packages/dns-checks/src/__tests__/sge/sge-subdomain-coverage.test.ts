// SPDX-License-Identifier: BUSL-1.1

/**
 * SGE control 7 — FULL SUB-DOMAIN COVERAGE (bv-mcp #996).
 *
 * THE REQUIREMENT. Every sub-domain publishes its OWN anti-spoofing records: an
 * explicit `_dmarc` record, `v=spf1 -all`, and a null `v=DKIM1; p=` record —
 * applying to a sub-domain consisting of "as little as a single A record".
 *
 * SGE REFUSES `sp=` AS THE MECHANISM, in as many words: "This requirement
 * remains even if the root level domain has SP=reject set within its DMARC
 * record", and "having SP=reject in the root record will only partially resolve
 * the issue". The apex record therefore cannot satisfy, excuse or fail this
 * control, and the evaluator reads none of its tags here.
 *
 * THE ABSTENTION IS THE POINT. The control cannot be evaluated without a
 * sub-domain list, and this package enumerates nothing. With no enumeration
 * input the control is `not_measured` — NEVER `not_satisfied`. "We could not
 * enumerate" is not "the control is absent"; recording the second from the first
 * is the bv-mcp #638 defect class, one level up from a check. A sub-domain that
 * is measurably missing a record IS a failure; an absent input is not.
 *
 * The four cases below are the ones this control exists for, in the order they
 * are decided: a measured failure, an unprovable affirmative, an unmeasured
 * record, and a clean complete enumeration.
 */

import { describe, it, expect } from 'vitest';
import { evaluateSgeCompliance } from '../../sge';
import type { SgeEvaluation, SgeSubdomainCoverage, SgeSubdomainObservation } from '../../sge';
import type { CheckCategory, CheckResult, Finding } from '../../types';

function result(category: CheckCategory, over: Partial<CheckResult> = {}): CheckResult {
	return { category, passed: true, score: 100, findings: [] as Finding[], ...over };
}

const MX_PRESENT = result('mx', { controlPresent: true });

/** A sub-domain with all three records MEASURED and present. */
function covered(name: string, over: Partial<SgeSubdomainObservation> = {}): SgeSubdomainObservation {
	return { name, dmarcRecordPresent: true, spfAll: '-all', dkimNullRecordPresent: true, ...over };
}

function coverage(enumeration: 'complete' | 'partial', observations: SgeSubdomainObservation[]): SgeSubdomainCoverage {
	return { enumeration, source: 'test enumeration', observations };
}

function subdomainControl(evaluation: SgeEvaluation) {
	const found = evaluation.controls.find((c) => c.control === 'subdomain_coverage');
	if (!found) throw new Error('subdomain_coverage missing from evaluation');
	return found;
}

function evaluate(options?: { subdomainCoverage?: SgeSubdomainCoverage; results?: CheckResult[] }) {
	return evaluateSgeCompliance('example.test', options?.results ?? [MX_PRESENT], {
		...(options?.subdomainCoverage ? { subdomainCoverage: options.subdomainCoverage } : {}),
	});
}

describe('sub-domain coverage — no enumeration input ABSTAINS', () => {
	// The single most important assertion in this file. An absent input must not
	// look like a measured absence on any surface.
	it('is not_measured with no_subdomain_enumeration when no coverage is supplied', () => {
		const control = subdomainControl(evaluate());
		expect(control.status).toBe('not_measured');
		expect(control.notMeasuredReason).toBe('no_subdomain_enumeration');
	});

	it('is neither satisfied nor not_satisfied, and is never omitted', () => {
		const evaluation = evaluate();
		const control = subdomainControl(evaluation);
		expect(control.status).not.toBe('satisfied');
		expect(control.status).not.toBe('not_satisfied');
		expect(evaluation.controls.map((c) => c.control)).toContain('subdomain_coverage');
	});

	// The verdict rule, applied to this control: an unmeasured control yields
	// `indeterminate`, never `non_compliant`. A domain is not failed for a control
	// nobody could measure.
	it('leaves the domain indeterminate, not non_compliant', () => {
		const evaluation = evaluateSgeCompliance('example.test', [
			MX_PRESENT,
			result('dmarc', { controlPresent: true, recordPresent: true }),
			result('spf', { metadata: { spfAll: '-all' } }),
			result('dkim', { controlPresent: true }),
			result('mta_sts', { recordPresent: true, metadata: { mtaStsMode: 'enforce' } }),
			result('tlsrpt', { recordPresent: true }),
		]);
		expect(evaluation.verdict).toBe('indeterminate');
		expect(evaluation.counts.notSatisfied).toBe(0);
	});

	it('records the absent input structurally, so the abstention is re-derivable', () => {
		expect(subdomainControl(evaluate()).evidence).toContainEqual({
			signal: 'SgeEvaluateOptions.subdomainCoverage',
			value: undefined,
		});
	});
});

describe('sub-domain coverage — a complete, covered enumeration is satisfied', () => {
	it('is satisfied when every sub-domain carries all three records', () => {
		const control = subdomainControl(
			evaluate({ subdomainCoverage: coverage('complete', [covered('www.example.test'), covered('api.example.test')]) }),
		);
		expect(control.status).toBe('satisfied');
		expect(control.notMeasuredReason).toBeUndefined();
	});

	// Vacuous truth, and the caller owns the `'complete'` claim exactly as it owns
	// the SMTP transport observation.
	it('is satisfied on a complete enumeration that found no sub-domains at all', () => {
		expect(subdomainControl(evaluate({ subdomainCoverage: coverage('complete', []) })).status).toBe('satisfied');
	});

	it('carries the enumeration mode and source as structural evidence', () => {
		const control = subdomainControl(evaluate({ subdomainCoverage: coverage('complete', [covered('www.example.test')]) }));
		expect(control.evidence).toContainEqual({ signal: 'SgeSubdomainCoverage.enumeration', value: 'complete' });
		expect(control.evidence).toContainEqual({ signal: 'SgeSubdomainCoverage.source', value: 'test enumeration' });
		expect(control.evidence).toContainEqual({ signal: 'SgeSubdomainCoverage.observations.length', value: 1 });
	});
});

describe('sub-domain coverage — a sub-domain missing any one record FAILS', () => {
	it.each<[string, Partial<SgeSubdomainObservation>]>([
		['_dmarc', { dmarcRecordPresent: false }],
		['null DKIM', { dkimNullRecordPresent: false }],
		['a hard-fail SPF (~all)', { spfAll: '~all' }],
		['a hard-fail SPF (no all mechanism)', { spfAll: 'no-all-mechanism' }],
	])('is not_satisfied when one sub-domain lacks %s', (_label, missing) => {
		const control = subdomainControl(
			evaluate({
				subdomainCoverage: coverage('complete', [covered('www.example.test'), covered('legacy.example.test', missing)]),
			}),
		);
		expect(control.status).toBe('not_satisfied');
		expect(control.notMeasuredReason).toBeUndefined();
	});

	it('names the failing sub-domains in the evidence', () => {
		const control = subdomainControl(
			evaluate({
				subdomainCoverage: coverage('complete', [
					covered('www.example.test'),
					covered('legacy.example.test', { dmarcRecordPresent: false }),
				]),
			}),
		);
		expect(control.evidence).toContainEqual({ signal: 'subdomainsMeasurablyMissingRecords', value: 'legacy.example.test' });
	});

	it('makes the whole domain non_compliant, not indeterminate', () => {
		const evaluation = evaluate({
			subdomainCoverage: coverage('complete', [covered('legacy.example.test', { dkimNullRecordPresent: false })]),
		});
		expect(evaluation.verdict).toBe('non_compliant');
	});

	// A measured failure is evidence whether or not the LIST is complete. Discarding
	// it because more sub-domains might exist would suppress a real finding — the
	// mirror image of the false affirmative, and against the module's own rule that
	// one measured failure decides.
	it('still fails on an INCOMPLETE enumeration — a measured failure outranks an unprovable list', () => {
		const control = subdomainControl(
			evaluate({ subdomainCoverage: coverage('partial', [covered('legacy.example.test', { dmarcRecordPresent: false })]) }),
		);
		expect(control.status).toBe('not_satisfied');
	});
});

describe('sub-domain coverage — an unprovable affirmative stays unmeasured', () => {
	// "Every sub-domain is covered" is an unbounded negative. No discovery source
	// can prove it, so a partial list can never reach `satisfied` — however many of
	// the sub-domains it DID find pass.
	it('is not_measured on a partial enumeration even when every observed sub-domain passes', () => {
		const control = subdomainControl(
			evaluate({ subdomainCoverage: coverage('partial', [covered('www.example.test'), covered('api.example.test')]) }),
		);
		expect(control.status).toBe('not_measured');
		expect(control.notMeasuredReason).toBe('subdomain_enumeration_incomplete');
	});

	it.each<[string, Partial<SgeSubdomainObservation>]>([
		['dmarcRecordPresent', { dmarcRecordPresent: undefined }],
		['spfAll', { spfAll: undefined }],
		['dkimNullRecordPresent', { dkimNullRecordPresent: undefined }],
	])('is not_measured when a complete enumeration left %s unmeasured on a sub-domain', (_label, unmeasured) => {
		const control = subdomainControl(
			evaluate({
				subdomainCoverage: coverage('complete', [covered('www.example.test'), covered('quiet.example.test', unmeasured)]),
			}),
		);
		expect(control.status).toBe('not_measured');
		expect(control.notMeasuredReason).toBe('subdomain_records_not_measured');
		expect(control.evidence).toContainEqual({ signal: 'subdomainsWithUnmeasuredRecords', value: 'quiet.example.test' });
	});

	// `undefined` is the shape a caller uses for a sub-domain that legitimately
	// SENDS mail and therefore publishes a real DKIM key rather than the null one.
	// It must abstain, not fail a correctly-configured name.
	it('never reads an unmeasured record as a missing one', () => {
		const control = subdomainControl(
			evaluate({ subdomainCoverage: coverage('complete', [covered('mail.example.test', { dkimNullRecordPresent: undefined })]) }),
		);
		expect(control.status).not.toBe('not_satisfied');
	});
});

describe('sub-domain coverage — the apex record can neither satisfy nor excuse it', () => {
	/** An enforcing apex whose `sp=` is the strongest value SGE could be offered. */
	const SP_REJECT = result('dmarc', {
		controlPresent: true,
		recordPresent: true,
		metadata: {
			dmarcPolicy: 'reject',
			dmarcSubdomainPolicy: 'reject',
			dmarcNonExistentSubdomainPolicy: 'reject',
			dmarcInheritedFromParent: false,
		},
	});

	// The requirement SGE states twice: "This requirement remains even if the root
	// level domain has SP=reject set within its DMARC record", and "having SP=reject
	// in the root record will only partially resolve the issue". An implementation
	// that inferred coverage from the apex would pass the domain here.
	it('sp=reject at the apex does NOT satisfy it — with no enumeration it stays unmeasured', () => {
		const evaluation = evaluateSgeCompliance('example.test', [MX_PRESENT, SP_REJECT]);
		const control = subdomainControl(evaluation);
		expect(control.status).toBe('not_measured');
		expect(control.notMeasuredReason).toBe('no_subdomain_enumeration');
		// …and the apex DMARC control is unaffected in the other direction.
		expect(evaluation.controls.find((c) => c.control === 'dmarc_reject')?.status).toBe('satisfied');
	});

	it('sp=reject at the apex does NOT rescue a sub-domain that is measurably missing its records', () => {
		const evaluation = evaluateSgeCompliance('example.test', [MX_PRESENT, SP_REJECT], {
			subdomainCoverage: coverage('complete', [covered('legacy.example.test', { dmarcRecordPresent: false })]),
		});
		expect(subdomainControl(evaluation).status).toBe('not_satisfied');
		expect(evaluation.verdict).toBe('non_compliant');
	});

	// Structural proof that no apex tag reaches this control: the evidence list is
	// identical whether the apex publishes sp=reject or nothing at all.
	it('reads no apex signal at all — the evidence is the same with and without a DMARC record', () => {
		const withApex = subdomainControl(evaluateSgeCompliance('example.test', [MX_PRESENT, SP_REJECT]));
		const withoutApex = subdomainControl(evaluateSgeCompliance('example.test', [MX_PRESENT]));
		expect(withApex.evidence).toEqual(withoutApex.evidence);
		expect(withApex.status).toBe(withoutApex.status);
	});
});
