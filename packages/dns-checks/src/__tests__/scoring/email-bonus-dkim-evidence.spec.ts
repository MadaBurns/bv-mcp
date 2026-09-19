// SPDX-License-Identifier: BUSL-1.1

/**
 * The email bonus needs AFFIRMATIVE DKIM evidence (scoring model 1.35.0).
 *
 * The bonus rewards a complete email-authentication stack: strong SPF, a DMARC policy, and
 * DKIM signing. Its DKIM leg used to read `!missingControls['dkim']` — "nobody proved DKIM
 * absent". But DKIM absence is deliberately NOT a missing control (it is inferred from a
 * selector wordlist, so "we did not discover a key" cannot support "this domain does not
 * sign"), which meant that key was effectively never set and the leg was satisfied by every
 * domain, including ones whose DKIM check found nothing and ones whose DKIM check never ran.
 *
 * A reward resting on the absence of counter-evidence is the same false-affirmative shape
 * `controlPresent`, `spfAllQualifier` and `mtaStsPolicyMode` all exist to prevent, and the
 * SPF and DMARC legs of this very bonus already demand a positive measurement.
 *
 * What did NOT change, and is pinned below: "not discovered" is still not "absent". The
 * `dkim` category keeps its graded floor, `missingControls` stays clear, and no critical-gap
 * ceiling fires. Only the 2–5 point bonus moves.
 */

import { describe, expect, it } from 'vitest';
import { computeGenericScore } from '../../scoring/generic';
import type { GenericScoringContext } from '../../scoring/generic';
import { DEFAULT_SCORING_CONFIG } from '../../scoring/config';

/** A mail domain with strong SPF and a reject DMARC — the two non-DKIM legs satisfied. */
function mailContext(overrides: Partial<GenericScoringContext> = {}): GenericScoringContext {
	return {
		categoryScores: { spf: 100, dmarc: 100, dkim: 50, dnssec: 100, ssl: 100 },
		tierMap: { spf: 'core', dmarc: 'core', dkim: 'core', dnssec: 'core', ssl: 'core' },
		weights: { spf: 10, dmarc: 16, dkim: 10, dnssec: 8, ssl: 8 },
		criticalCategories: ['spf', 'dmarc', 'dkim', 'ssl'],
		emailBonusEligible: true,
		missingControls: {},
		hardeningPassed: {},
		...overrides,
	};
}

const FULL_BONUS = DEFAULT_SCORING_CONFIG.thresholds.emailBonusFull;

describe('email bonus — DKIM evidence leg', () => {
	it('is not vacuous: the other two legs really do earn the bonus here', () => {
		const withDkim = computeGenericScore(mailContext({ controlPresent: { dkim: true } }));
		expect(withDkim.emailBonus, 'strong SPF + p=reject DMARC + an observed DKIM key must earn the full bonus').toBe(FULL_BONUS);
	});

	it('withholds the bonus when DKIM was MEASURED and no active key was found', () => {
		const measuredAbsent = computeGenericScore(mailContext({ controlPresent: { dkim: false } }));
		const measuredPresent = computeGenericScore(mailContext({ controlPresent: { dkim: true } }));

		expect(measuredAbsent.emailBonus).toBe(0);
		// The entire behaviour change, stated as a number: the bonus, and nothing else.
		expect(measuredPresent.overall - measuredAbsent.overall).toBe(FULL_BONUS);
	});

	it('does NOT treat "no key discovered" as an absent control', () => {
		const measuredAbsent = computeGenericScore(mailContext({ controlPresent: { dkim: false } }));
		// `dkim` is critical in this context, so a missing-control reading would ALSO cap the
		// whole domain at criticalGapCeiling (64). Neither may happen from this signal alone.
		expect(measuredAbsent.criticalGaps).toEqual([]);
		expect(measuredAbsent.categoryScores.dkim, 'the graded floor must survive — this is a deficiency, not an absence').toBe(50);
		expect(measuredAbsent.overall).toBeGreaterThan(DEFAULT_SCORING_CONFIG.thresholds.criticalGapCeiling);
	});

	it('keeps the LEGACY reading when the check never determined presence', () => {
		// A DKIM check that abstained (every selector probe threw) leaves `controlPresent`
		// undefined and contributes no key. The repo's rule for an unmeasured category is to
		// exclude it, not to penalise it, so the bonus still flows.
		const abstained = computeGenericScore(mailContext({ controlPresent: {} }));
		expect(abstained.emailBonus).toBe(FULL_BONUS);

		// Same for a consumer on the published API that does not populate the map at all —
		// the field is optional and additive, so pre-1.35.0 callers are untouched.
		const legacyCaller = computeGenericScore(mailContext());
		expect(legacyCaller.emailBonus).toBe(FULL_BONUS);
		expect(legacyCaller.overall).toBe(abstained.overall);
	});

	it('still withholds the bonus when DKIM IS declared a missing control', () => {
		// The legacy leg is preserved intact underneath, not replaced by the evidence read.
		const declaredMissing = computeGenericScore(mailContext({ missingControls: { dkim: true } }));
		expect(declaredMissing.emailBonus).toBe(0);
	});

	it('is DKIM-specific: a false reading on another category does not touch the bonus', () => {
		const unrelated = computeGenericScore(mailContext({ controlPresent: { dkim: true, mta_sts: false, bimi: false } }));
		expect(unrelated.emailBonus).toBe(FULL_BONUS);
	});

	it('honours a remapped DKIM key so non-default vocabularies behave the same', () => {
		const remapped = computeGenericScore(
			mailContext({
				categoryScores: { spf: 100, dmarc: 100, email_signing: 50, dnssec: 100, ssl: 100 },
				tierMap: { spf: 'core', dmarc: 'core', email_signing: 'core', dnssec: 'core', ssl: 'core' },
				weights: { spf: 10, dmarc: 16, email_signing: 10, dnssec: 8, ssl: 8 },
				criticalCategories: ['spf', 'dmarc', 'ssl'],
				emailBonusKeys: { spf: 'spf', dkim: 'email_signing', dmarc: 'dmarc' },
				controlPresent: { email_signing: false },
			}),
		);
		expect(remapped.emailBonus).toBe(0);
	});
});
