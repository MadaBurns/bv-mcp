import { describe, it, expect } from 'vitest';
import type { CheckResult } from '../src/lib/scoring';
import { isSatisfiedControl, isUnrebuttedAbsence, notApplicableCategoriesFor } from '../src/lib/control-presence';

/**
 * The truth table of the SHARED control-presence predicate.
 *
 * `map_compliance` (#705, the reporting surface) and `compare_baseline` (#706, the
 * policy gate customers wire into CI) both grade controls on this. It lived
 * privately inside the first tool, so the second shipped the identical defect and
 * was fixed three months later. This spec pins the table itself, so neither
 * consumer can drift on what "satisfied" means without a red test here.
 */
function check(fields: Partial<CheckResult>): CheckResult {
	return { category: 'dnssec', passed: true, score: 100, findings: [], ...fields } as CheckResult;
}

describe('isUnrebuttedAbsence', () => {
	it('is true only for an observed absence with no affirmative controlPresent rebuttal', () => {
		// unsigned zone — nothing published, control not active
		expect(isUnrebuttedAbsence(check({ recordPresent: false, controlPresent: false }))).toBe(true);
		// absence observed, control flag not reported at all (e.g. no raw resolver)
		expect(isUnrebuttedAbsence(check({ recordPresent: false }))).toBe(true);
		// Explicit independent control evidence rebuts the record-presence signal.
		expect(isUnrebuttedAbsence(check({ recordPresent: false, controlPresent: true }))).toBe(false);
		// published but weak/broken — a record exists, so this is not an absence
		expect(isUnrebuttedAbsence(check({ recordPresent: true, controlPresent: false }))).toBe(false);
		// signal not reported (spf/dkim/ssl/ns/http_security) or the query failed:
		// absence of a signal is not evidence of absence
		expect(isUnrebuttedAbsence(check({}))).toBe(false);
	});
});

describe('isSatisfiedControl', () => {
	it('requires the check to have both not penalized AND not observed an unrebutted absence', () => {
		// The #705/#706 defect shape: unpenalized (score 60, passed true) but nothing published.
		expect(isSatisfiedControl(check({ passed: true, score: 60, recordPresent: false, controlPresent: false }))).toBe(false);
		// Split-signal/legacy result: absent records, affirmative control evidence.
		expect(isSatisfiedControl(check({ passed: true, score: 85, recordPresent: false, controlPresent: true }))).toBe(true);
		// Present and satisfied.
		expect(isSatisfiedControl(check({ passed: true, recordPresent: true, controlPresent: true }))).toBe(true);
		// A penalized check is never satisfied, whatever the presence flags say.
		expect(isSatisfiedControl(check({ passed: false, recordPresent: true, controlPresent: true }))).toBe(false);
		// No presence signal reported at all — unchanged behaviour, grade on `passed`.
		expect(isSatisfiedControl(check({ passed: true }))).toBe(true);
	});
});

/**
 * #726 — the severity floor. Asserted as an INVARIANT ("a control cannot be
 * satisfied by a check the same scan flags at medium or worse"), not as a list of
 * per-control expectations: a literal expectation would pin whatever today's
 * mapping table happens to produce, which is how the false affirmative survived
 * two fixes.
 */
function finding(severity: string, metadata?: Record<string, unknown>) {
	return { category: 'http_security', title: `t-${severity}`, severity, detail: '', ...(metadata ? { metadata } : {}) };
}

describe('isSatisfiedControl — severity floor (#726)', () => {
	it('is never satisfied by a check the same scan flags at medium or worse', () => {
		// The five checks that never emit `recordPresent` (spf, dkim, ssl, ns,
		// http_security) reach the floor with BOTH presence clauses inert — which is
		// exactly the state that degraded the predicate back to bare `passed`.
		for (const severity of ['critical', 'high', 'medium']) {
			const result = check({ category: 'http_security', passed: true, score: 65, findings: [finding(severity)] } as Partial<CheckResult>);
			expect(isUnrebuttedAbsence(result)).toBe(false);
			expect(isSatisfiedControl(result)).toBe(false);
		}
	});

	it('regression: a CSP permitting unsafe-inline AND unsafe-eval is not a satisfied control', () => {
		// Measured on wiz.io, 2026-08-20: `http_security` scored 65 with these two
		// findings while `map_compliance` published PCI DSS 6.4.2 (WAF / CSP) as PASS
		// and `simulate_attack_paths` rated the resulting xss_injection path HIGH.
		const result = check({
			category: 'http_security',
			passed: true,
			score: 65,
			findings: [
				{ category: 'http_security', title: 'CSP allows unsafe-inline scripts', severity: 'medium', detail: '' },
				{ category: 'http_security', title: 'CSP allows unsafe-eval', severity: 'medium', detail: '' },
			],
		} as Partial<CheckResult>);
		expect(isSatisfiedControl(result)).toBe(false);
	});

	it('still satisfies on advisory findings — low/info are below the floor', () => {
		for (const severity of ['low', 'info']) {
			expect(isSatisfiedControl(check({ category: 'ssl', passed: true, findings: [finding(severity)] } as Partial<CheckResult>))).toBe(true);
		}
	});

	it('an info-DOWNGRADED finding on an inapplicable control still satisfies', () => {
		// Post-processing rewrites email-auth findings to `info` for a non-mail domain
		// under an enforcing parent DMARC (and DKIM/MTA-STS/BIMI under an SPF
		// noSendPolicy) BEFORE either consumer sees the CheckResult. Reading
		// pre-downgrade severity here would turn the false PASS this closes into a
		// false FAIL on exactly the domains that downgrade protects.
		const downgraded = check({
			category: 'dkim',
			passed: true,
			findings: [
				{
					category: 'dkim',
					title: 'No DKIM records found',
					severity: 'info',
					detail: 'No DKIM selector responded (expected — no MX records and parent domain DMARC policy covers subdomains)',
				},
			],
		} as Partial<CheckResult>);
		expect(isSatisfiedControl(downgraded)).toBe(true);
	});

	it('an UNMEASURED finding does not trip the floor', () => {
		// `inconclusive`/`errorKind` mark a probe that never reached the origin (WAF
		// challenge, auth gate, stalled fetch). "Could not measure" is not evidence the
		// control is unsatisfied — the `checkStatus` channel upstream is what answers
		// for an unmeasured control, via `not_assessed` / `inconclusiveRules`.
		expect(
			isSatisfiedControl(check({ category: 'http_security', passed: true, findings: [finding('medium', { inconclusive: true })] } as Partial<CheckResult>)),
		).toBe(true);
		expect(
			isSatisfiedControl(check({ category: 'ns', passed: true, findings: [finding('high', { errorKind: 'dns_error' })] } as Partial<CheckResult>)),
		).toBe(true);
		// …but a MEASURED finding sitting beside an unmeasured one still disqualifies.
		expect(
			isSatisfiedControl(
				check({ category: 'ns', passed: true, findings: [finding('high', { errorKind: 'dns_error' }), finding('medium')] } as Partial<CheckResult>),
			),
		).toBe(false);
	});

	it('the floor is additive — the #705/#706 presence clauses are unchanged', () => {
		// Unrebutted absence with NO findings at all still fails (the original defect).
		expect(isSatisfiedControl(check({ passed: true, score: 60, recordPresent: false, controlPresent: false }))).toBe(false);
		// An affirmative split signal with only advisory findings still passes.
		expect(
			isSatisfiedControl(check({ passed: true, score: 85, recordPresent: false, controlPresent: true, findings: [finding('low')] } as Partial<CheckResult>)),
		).toBe(true);
	});
});

describe('notApplicableCategoriesFor', () => {
	it('defers to the scan profile — mail-only categories are N/A only under a non-mail profile', () => {
		const checks = [check({ category: 'mta_sts', score: 60 }), check({ category: 'spf', score: 90 })];

		expect(notApplicableCategoriesFor({ checks, score: { categoryScores: {} }, context: { profile: 'web_only' } })).toEqual(['mta_sts']);
		expect(notApplicableCategoriesFor({ checks, score: { categoryScores: {} }, context: { profile: 'mail_enabled' } })).toEqual([]);
		// No context at all defaults to `mail_enabled` — the same default `formatScanReport`
		// uses. Absence of a profile must never disarm a rule.
		expect(notApplicableCategoriesFor({ checks })).toEqual([]);
	});

	it('never files a check that did not COMPLETE as a deliberate N/A', () => {
		// A timed-out check is a measurement failure, not an applicability decision.
		const checks = [check({ category: 'mta_sts', score: 0, passed: false, checkStatus: 'timeout' })];
		expect(notApplicableCategoriesFor({ checks, score: { categoryScores: {} }, context: { profile: 'web_only' } })).toEqual([]);
	});
});
