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
		// registry/ccTLD-signed zone: no DNSKEY/DS of its own, but the chain validates
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
		// Registry-signed: absent records, affirmative control.
		expect(isSatisfiedControl(check({ passed: true, score: 85, recordPresent: false, controlPresent: true }))).toBe(true);
		// Present and satisfied.
		expect(isSatisfiedControl(check({ passed: true, recordPresent: true, controlPresent: true }))).toBe(true);
		// A penalized check is never satisfied, whatever the presence flags say.
		expect(isSatisfiedControl(check({ passed: false, recordPresent: true, controlPresent: true }))).toBe(false);
		// No presence signal reported at all — unchanged behaviour, grade on `passed`.
		expect(isSatisfiedControl(check({ passed: true }))).toBe(true);
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
