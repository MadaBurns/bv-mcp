// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { computeProfileAwareScanScore, type CheckCategory, type CheckResult } from '../../scoring';

function result(category: CheckCategory, passed = true): CheckResult {
	return {
		category,
		passed,
		score: passed ? 100 : 0,
		findings: [],
		checkStatus: 'completed',
		controlPresent: passed,
	};
}

const PARTIAL_ROSTER: CheckResult[] = [
	result('spf'),
	result('dmarc'),
	result('dkim'),
	result('dnssec'),
	result('ssl'),
	result('mta_sts'),
	result('ns'),
	result('caa'),
	result('subdomain_takeover'),
	result('mx'),
	result('lookalikes'),
	result('shadow_domains'),
	result('http_security'),
	result('dane'),
	result('bimi'),
	result('tlsrpt'),
];

describe('hardening roster symmetry', () => {
	it('excludes omitted hardening categories but retains measured failures', () => {
		const base = computeProfileAwareScanScore(PARTIAL_ROSTER, { profile: 'mail_enabled' });
		const omitted = computeProfileAwareScanScore([...PARTIAL_ROSTER], { profile: 'mail_enabled' });
		const submittedFailure = computeProfileAwareScanScore([...PARTIAL_ROSTER, result('ptr', false)], { profile: 'mail_enabled' });

		expect(omitted.score.tierBreakdown?.hardening).toBe(base.score.tierBreakdown?.hardening);
		expect(submittedFailure.score.tierBreakdown?.hardening).toBeLessThan(base.score.tierBreakdown?.hardening ?? 0);
	});
});
