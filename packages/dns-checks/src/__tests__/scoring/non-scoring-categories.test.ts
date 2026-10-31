// SPDX-License-Identifier: BUSL-1.1

/**
 * US-16 seam: the six non-scoring categories must never move a score.
 *
 * Weight 0 alone does not keep a result out of the score: it still reaches the verified-critical
 * penalty, the summary counts, the evidence ratio and profile detection's failure ratio. So the
 * engine drops these results before any use, and a non-scoring result must produce output
 * DEEP-EQUAL to the same call without it.
 *
 * Every equality test carries its own negative control: the identical result relabelled to a
 * SCORED category must change the output. Without that, an equality assertion over a broken
 * comparison would pass vacuously.
 */

import { describe, expect, it } from 'vitest';
import {
	buildCheckResult,
	CATEGORY_DISPLAY_WEIGHTS,
	CATEGORY_TIERS,
	computeProfileAwareScanScore,
	computeScanEvidence,
	computeScanScore,
	createFinding,
	DEFAULT_SCORING_CONFIG,
	detectDomainContext,
	getProfileWeights,
	IMPORTANCE_WEIGHTS,
	PROFILE_WEIGHTS,
	type DomainContext,
} from '../../scoring';
import { NON_SCORING_CATEGORIES, type CheckCategory, type CheckResult } from '../../types';
import { CheckCategorySchema } from '../../schemas/scoring';

/** Listed literally, so a regression that drops a member from the set fails here rather than shrinking the loop. */
const NON_SCORING: CheckCategory[] = ['web_content', 'csp_quality', 'hsts_preload', 'http_redirect', 'security_txt', 'cert_posture'];

/** Scored categories absent from BASE, used to relabel the non-scoring results for the negative controls. */
const SCORED_STAND_INS: CheckCategory[] = ['http_security', 'subdomain_takeover', 'dane_https', 'svcb_https', 'subdomailing', 'txt_hygiene'];

/** A small, fully passing mail-domain scan. Five results, so six failing extras would flip profile detection to `minimal`. */
const BASE: CheckResult[] = [
	buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'v=spf1 include:_spf.example.net -all')], true, true),
	buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC policy enforced', 'info', 'p=reject')], true, true),
	buildCheckResult('dkim', [createFinding('dkim', 'DKIM key published', 'info', 'selector1 2048-bit RSA')], true, true),
	buildCheckResult('ssl', [createFinding('ssl', 'HTTPS reachable', 'info', 'Valid certificate')], true),
	buildCheckResult('mx', [createFinding('mx', 'Mail routing configured', 'info', 'Two MX hosts')], true),
];

/**
 * A FAILING result (two criticals take the category to 20, so `passed` is false) whose findings
 * are VERIFIED critical: the one shape that arms the overall critical penalty.
 */
function failingResult(category: CheckCategory): CheckResult {
	const result = buildCheckResult(category, [
		createFinding(category, 'Critical posture defect', 'critical', 'A verified critical defect on the web surface.', { confidence: 'verified' }),
		createFinding(category, 'Second critical posture defect', 'critical', 'Another verified critical defect.', { confidence: 'verified' }),
	]);
	expect(result.passed).toBe(false);
	return result;
}

function erroredResult(category: CheckCategory): CheckResult {
	return { ...failingResult(category), checkStatus: 'error', partial: true, passed: false, score: 0 };
}

function mailContext(): DomainContext {
	const detected = detectDomainContext(BASE);
	return { ...detected, weights: getProfileWeights(detected.profile) };
}

describe('NON_SCORING_CATEGORIES', () => {
	it('holds exactly the six US-16 categories', () => {
		expect([...NON_SCORING_CATEGORIES].sort()).toEqual([...NON_SCORING].sort());
	});

	it('keeps every member in the protective tier (hardening ignores weight) at weight 0 in every table', () => {
		for (const category of NON_SCORING) {
			expect(CATEGORY_TIERS[category]).toBe('protective');
			expect(CATEGORY_DISPLAY_WEIGHTS[category]).toBe(0);
			expect(IMPORTANCE_WEIGHTS[category].importance).toBe(0);
			expect(DEFAULT_SCORING_CONFIG.weights[category]).toBe(0);
			for (const profile of Object.keys(PROFILE_WEIGHTS) as Array<keyof typeof PROFILE_WEIGHTS>) {
				expect(PROFILE_WEIGHTS[profile][category].importance).toBe(0);
				expect(DEFAULT_SCORING_CONFIG.profileWeights[profile][category]).toBe(0);
			}
			expect(CheckCategorySchema.parse(category)).toBe(category);
		}
	});
});

describe('a non-scoring result never changes the scan score', () => {
	for (const [index, category] of NON_SCORING.entries()) {
		const standIn = SCORED_STAND_INS[index];

		it(`${category}: a verified-critical failure leaves computeScanScore deep-equal; relabelled ${standIn} it moves score, findings and evidence`, () => {
			const baseline = computeScanScore(BASE);
			const withNonScoring = computeScanScore([...BASE, failingResult(category)]);
			expect(withNonScoring).toEqual(baseline);

			const relabelled = computeScanScore([...BASE, failingResult(standIn)]);
			expect(relabelled.overall).not.toBe(baseline.overall);
			expect(relabelled.findings).toHaveLength(baseline.findings.length + 2);
			expect(relabelled.evidence.attempted).toBe(baseline.evidence.attempted + 1);
			expect(relabelled.summary).not.toBe(baseline.summary);
		});

		it(`${category}: same under an explicit DomainContext and through computeProfileAwareScanScore; relabelled ${standIn} it moves both`, () => {
			const context = mailContext();
			expect(computeScanScore([...BASE, failingResult(category)], context)).toEqual(computeScanScore(BASE, context));
			expect(computeProfileAwareScanScore([...BASE, failingResult(category)])).toEqual(computeProfileAwareScanScore(BASE));

			expect(computeScanScore([...BASE, failingResult(standIn)], context)).not.toEqual(computeScanScore(BASE, context));
			expect(computeProfileAwareScanScore([...BASE, failingResult(standIn)]).score.overall).not.toBe(
				computeProfileAwareScanScore(BASE).score.overall,
			);
		});

		it(`${category}: an errored result leaves evidence and the score deep-equal; relabelled ${standIn} it lowers the evidence ratio`, () => {
			expect(computeScanEvidence([...BASE, erroredResult(category)])).toEqual(computeScanEvidence(BASE));
			expect(computeScanScore([...BASE, erroredResult(category)])).toEqual(computeScanScore(BASE));

			const relabelled = computeScanEvidence([...BASE, erroredResult(standIn)]);
			expect(relabelled.attempted).toBe(BASE.length + 1);
			expect(relabelled.ratio).toBeLessThan(1);
		});
	}

	it('all six failing at once leave the detected profile alone; six failing scored results flip it to minimal', () => {
		const sixNonScoring = NON_SCORING.map(failingResult);
		expect(detectDomainContext([...BASE, ...sixNonScoring])).toEqual(detectDomainContext(BASE));
		expect(computeProfileAwareScanScore([...BASE, ...sixNonScoring])).toEqual(computeProfileAwareScanScore(BASE));

		const sixScored = SCORED_STAND_INS.map(failingResult);
		expect(detectDomainContext(BASE).profile).toBe('mail_enabled');
		expect(detectDomainContext([...BASE, ...sixScored]).profile).toBe('minimal');
	});

	it('a scan of only non-scoring results is the zero-evidence scan; the same results relabelled are graded', () => {
		const onlyNonScoring = computeScanScore(NON_SCORING.map(failingResult));
		expect(onlyNonScoring).toEqual(computeScanScore([]));
		expect(onlyNonScoring.overall).toBeNull();
		expect(onlyNonScoring.evidence.attempted).toBe(0);

		expect(computeScanScore(SCORED_STAND_INS.map(failingResult)).evidence.attempted).toBe(SCORED_STAND_INS.length);
	});
});
