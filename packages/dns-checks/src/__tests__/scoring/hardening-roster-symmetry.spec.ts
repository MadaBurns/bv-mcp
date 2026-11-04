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

// Scoring model 2.0.0 retired the binary hardening tier. These categories are protective
// now and the hardening divisor is gone, so the roster property is a weights property: a
// zero-weight former-hardening category cannot move a score whether it is submitted, failed
// or omitted, and a weighted one (tlsrpt/dane in the mail profiles) moves it only when it is
// MEASURED as failing.
describe('former-hardening roster symmetry', () => {
	it('cross-roster parity: the same 17-check roster scores identically with and without ptr + dnskey_strength', () => {
		for (const profile of ['mail_enabled', 'enterprise_mail'] as const) {
			const base = computeProfileAwareScanScore(PARTIAL_ROSTER, { profile });
			const withExtrasPassing = computeProfileAwareScanScore(
				[...PARTIAL_ROSTER, result('ptr'), result('dnskey_strength')],
				{ profile },
			);
			const withExtrasFailing = computeProfileAwareScanScore(
				[...PARTIAL_ROSTER, result('ptr', false), result('dnskey_strength', false)],
				{ profile },
			);
			expect(withExtrasPassing.score.overall).toBe(base.score.overall);
			expect(withExtrasFailing.score.overall).toBe(base.score.overall);
			expect(withExtrasFailing.score.grade).toBe(base.score.grade);
		}
	});

	it('omitted weighted categories renormalise; a measured failure still costs points', () => {
		const withoutTlsrpt = PARTIAL_ROSTER.filter((r) => r.category !== 'tlsrpt');
		const omitted = computeProfileAwareScanScore(withoutTlsrpt, { profile: 'mail_enabled' });
		const base = computeProfileAwareScanScore(PARTIAL_ROSTER, { profile: 'mail_enabled' });
		const failed = computeProfileAwareScanScore([...withoutTlsrpt, result('tlsrpt', false)], { profile: 'mail_enabled' });

		// Omission forfeits nothing: everything else passes, so the tier renormalises to full credit.
		expect(omitted.score.overall).toBe(base.score.overall);
		expect(omitted.score.tierBreakdown?.protective).toBe(base.score.tierBreakdown?.protective);
		expect(failed.score.overall).toBeLessThan(base.score.overall ?? 0);
		expect(failed.score.tierBreakdown?.hardening).toBe(0);
	});
});
