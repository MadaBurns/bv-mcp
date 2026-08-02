// SPDX-License-Identifier: BUSL-1.1

/**
 * STANDING INVARIANT: an unmeasured check must be exactly equivalent to an absent one.
 *
 * `detectDomainContext` chooses the WEIGHT TABLE that then grades the domain. Three
 * separate times, a check that FAILED to run was allowed to influence that choice — so
 * the measurement failure selected the lens through which the domain was judged:
 *
 *   1. `failureRatio` counted unmeasured checks as failures, flipping domains to the
 *      `minimal` profile. Fixed by introducing `measuredChecks`.
 *   2. `sslPass` / `caaPass` read `controlPresent` with no `checkStatus` check, so an
 *      ERRORED ssl selected `web_only` — the one profile weighting spf/dmarc/dkim/mx at
 *      ZERO. This produced a fabricated 88 on a domain that had been NXDOMAIN for 100
 *      days: the four checks that correctly detected total failure were weighted out.
 *   3. `hasNoMx` asserted "no MX" from an MX lookup that had itself failed.
 *
 * Three instances of one shape is a structural hazard, not three coincidences. Rather
 * than a fourth point fix later, this pins the general property:
 *
 *     detectDomainContext(results where X errored) === detectDomainContext(results without X)
 *
 * ## Why a MATRIX of rosters, not one
 *
 * The property is only sharp when the signal under test is load-bearing for the profile
 * actually being selected. On an all-healthy roster, erroring `ssl` changes nothing
 * (the domain is mail_enabled either way), so a single-roster version of this test
 * silently misses instance #2 — verified: reverting the `measuredChecks` fix fails only
 * the `mx` case against a healthy roster. Each roster below is shaped to put a different
 * signal on the critical path, so the whole class is covered:
 *
 *   - `mailEnabled`   — everything active (exercises hasMx / enterprise detection)
 *   - `webOnlyViaSsl` — no MX, no CAA: `ssl` alone decides web_only vs non_mail
 *   - `webOnlyViaCaa` — no MX, no SSL: `caa` alone decides web_only vs non_mail
 *
 * If someone adds a new signal that reads a check field without consulting
 * `checkStatus`, this fails in CI instead of shipping.
 *
 * Runs against the BUILT package so source→dist drift is caught too.
 */

import { describe, it, expect } from 'vitest';
import { buildCheckResult, createFinding, detectDomainContext } from '@blackveil/dns-checks/scoring';
import type { CheckCategory, CheckResult } from '@blackveil/dns-checks/scoring';

function active(category: CheckCategory): CheckResult {
	return buildCheckResult(category, [createFinding(category, `${category} configured`, 'info', 'active control observed')], true);
}
function absent(category: CheckCategory): CheckResult {
	return buildCheckResult(category, [createFinding(category, `no ${category}`, 'medium', 'absent')], false);
}

const CATEGORIES: CheckCategory[] = ['spf', 'dmarc', 'dkim', 'ssl', 'caa', 'mx', 'mta_sts', 'bimi', 'ns', 'dnssec'];

/** Rosters shaped so that a DIFFERENT detection signal is load-bearing in each. */
const ROSTERS: Record<string, () => CheckResult[]> = {
	mailEnabled: () => CATEGORIES.map(active),
	webOnlyViaSsl: () => CATEGORIES.map((c) => (c === 'mx' || c === 'caa' ? absent(c) : active(c))),
	webOnlyViaCaa: () => CATEGORIES.map((c) => (c === 'mx' || c === 'ssl' ? absent(c) : active(c))),
};

const UNMEASURED = ['timeout', 'error'] as const;

describe('an unmeasured check is equivalent to an absent one (profile detection)', () => {
	for (const [rosterName, roster] of Object.entries(ROSTERS)) {
		describe(rosterName, () => {
			for (const category of CATEGORIES) {
				for (const status of UNMEASURED) {
					it(`${category} '${status}' does not change the detected profile`, () => {
						const withoutCheck = roster().filter((r) => r.category !== category);
						const withUnmeasured = roster().map((r) => (r.category === category ? { ...r, checkStatus: status } : r));

						expect(detectDomainContext(withUnmeasured).profile).toBe(detectDomainContext(withoutCheck).profile);
					});
				}

				it(`a FAILING ${category} that could not be measured cannot assert absence either`, () => {
					// The `hasNoMx` instance: an unmeasured check carrying controlPresent:false
					// must not be read as a determination that the control is absent.
					const withoutCheck = roster().filter((r) => r.category !== category);
					const unmeasuredAbsent = roster().map((r) => (r.category === category ? { ...absent(category), checkStatus: 'error' as const } : r));

					expect(detectDomainContext(unmeasuredAbsent).profile).toBe(detectDomainContext(withoutCheck).profile);
				});
			}
		});
	}

	describe('DISCRIMINATION — the property must not be vacuously true', () => {
		// Without these, the suite above would also pass against an implementation that
		// ignores every check equally, or that never varies the profile at all. Detection
		// must still respond to real, MEASURED evidence — that is the point of profiles.
		it('a measured roster difference DOES move the profile', () => {
			expect(detectDomainContext(ROSTERS.mailEnabled!()).profile).toBe('mail_enabled');
			expect(detectDomainContext(ROSTERS.webOnlyViaSsl!()).profile).not.toBe('mail_enabled');
		});

		it('each no-mail roster reaches web_only through the signal it is named for', () => {
			// Proves ssl and caa are each genuinely load-bearing in their roster — i.e. the
			// corresponding `X 'error'` cases above are real tests, not no-ops.
			expect(detectDomainContext(ROSTERS.webOnlyViaSsl!()).profile).toBe('web_only');
			expect(detectDomainContext(ROSTERS.webOnlyViaCaa!()).profile).toBe('web_only');

			const sslRemoved = ROSTERS.webOnlyViaSsl!().filter((r) => r.category !== 'ssl');
			const caaRemoved = ROSTERS.webOnlyViaCaa!().filter((r) => r.category !== 'caa');
			expect(detectDomainContext(sslRemoved).profile).not.toBe('web_only');
			expect(detectDomainContext(caaRemoved).profile).not.toBe('web_only');
		});
	});
});
