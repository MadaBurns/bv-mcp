// SPDX-License-Identifier: BUSL-1.1

/**
 * Rewording a finding must not move a score.
 *
 * `missing-control-intent.audit.test.ts` proves this ENUMERATIVELY over reconstructed source
 * (every `createFinding` site, parsed). This file proves it END-TO-END on the two checks whose
 * correctness used to rest on word choice, by running the real `checkDKIM` / `checkDNSSEC`
 * against mocked DNS, rewording the finding they emit, and re-scoring it through the real
 * `buildCheckResult` and `computeScanScore`.
 *
 * The two defects, as they stood before scoring model 1.35.0:
 *
 *  - **DKIM** emitted "No DKIM records found among tested selectors", which MATCHES
 *    `MISSING_CONTROL_REGEX`, at `high` severity. It was held out of the gate by its
 *    `confidence: 'heuristic'` metadata, seconded by a literal `text.includes('among tested
 *    selectors')` in `inferFindingConfidence` — a prose defence against a prose trigger. `dkim`
 *    is a critical category in `mail_enabled` and `enterprise_mail`, so the failure mode was not
 *    a lost category: it was every DKIM-less mail domain capped at `criticalGapCeiling` (64 →
 *    NIST grade D).
 *  - **DNSSEC** carried an in-source note that its unsigned-zone detail "deliberately avoids
 *    'no … record / missing / not found'". `dnssec` is critical in EVERY profile, so the same
 *    64-point cap sat behind one sentence nothing enforced.
 *
 * Both now declare `metadata.missingControl: false`, which `findingsIndicateMissingControl`
 * resolves BEFORE the regex. The tests below reword each finding into the most hostile prose
 * available and assert every downstream number is byte-identical.
 */

import { describe, expect, it, vi } from 'vitest';
import { checkDKIM } from '../../checks/check-dkim';
import { checkDNSSEC } from '../../checks/check-dnssec';
import { buildCheckResult, findingsIndicateMissingControl, scoreIndicatesMissingControl } from '../../scoring/model';
import { computeProfileAwareScanScore } from '../../scoring/engine';
import type { CheckResult, DNSQueryFunction, Finding, RawDNSQueryFunction } from '../../types';

const emptyDNS: DNSQueryFunction = vi.fn(async () => []);
const unsignedRawDNS: RawDNSQueryFunction = vi.fn(async () => ({ AD: false }));

/** Prose engineered to hit every branch of `MISSING_CONTROL_REGEX`. */
const HOSTILE_TITLE = 'No such record found';
const HOSTILE_DETAIL = 'The required control is missing: no policy record was found for this domain.';

/**
 * Re-score a check result through the real `buildCheckResult`, optionally replacing one
 * finding's prose first.
 *
 * Both the baseline and the reworded variant go through this same rebuild, deliberately.
 * `checkDKIM` applies a score FLOOR of its own after `buildCheckResult` returns (100 − 25 for
 * one `high` finding is 75, which understates a probe that found nothing), so comparing a
 * rebuilt variant against the check's post-floor number would compare two different code
 * paths and hide the thing under test.
 */
function rescore(result: CheckResult, rewrite?: { title: string; replacement: { title: string; detail: string } }): CheckResult {
	const findings: Finding[] = rewrite
		? result.findings.map((f) => (f.title === rewrite.title ? { ...f, ...rewrite.replacement } : f))
		: result.findings;
	return buildCheckResult(result.category, findings, result.controlPresent, result.recordPresent, result.metadata);
}

/** Assert two rebuilt results are indistinguishable on every scored field. */
function expectSameScoring(reworded: CheckResult, baseline: CheckResult, why: string): void {
	expect(reworded.score, why).toBe(baseline.score);
	expect(reworded.passed, why).toBe(baseline.passed);
	expect(findingsIndicateMissingControl(reworded.findings), why).toBe(findingsIndicateMissingControl(baseline.findings));
}

describe('prose independence — DKIM absence', () => {
	const TITLE = 'No DKIM records found among tested selectors';

	it('the finding still MATCHES the missing-control regex — this guard is not vacuous', async () => {
		const result = await checkDKIM('example.com', emptyDNS);
		const finding = result.findings.find((f) => f.title === TITLE);
		expect(finding, 'the DKIM absence finding was not emitted').toBeDefined();
		expect(finding!.severity, 'a sub-`high` finding would never reach the gate anyway').toBe('high');

		// Strip the declaration and the declared confidence. What is left is the sentence, and the
		// sentence alone is still enough to zero a core category. If this goes false the wording
		// became harmless on its own and every assertion below stops proving anything.
		const proseOnly: Finding = { ...finding!, metadata: { confidence: 'deterministic' } };
		expect(scoreIndicatesMissingControl([proseOnly])).toBe(true);
	});

	it('declares the decision structurally instead of relying on its wording', async () => {
		const result = await checkDKIM('example.com', emptyDNS);
		const finding = result.findings.find((f) => f.title === TITLE)!;
		expect(finding.metadata?.missingControl).toBe(false);
		expect(findingsIndicateMissingControl([finding])).toBe(false);
	});

	it('REWORDING THE TITLE DOES NOT CHANGE THE SCORE', async () => {
		const result = await checkDKIM('example.com', emptyDNS);
		// The check's own post-`buildCheckResult` floor. Pinned so a regression that zeroed the
		// category would be visible here too, not only in the comparisons below.
		expect(result.score).toBe(50);
		expect(result.passed).toBe(true);

		const baseline = rescore(result);
		expect(baseline.score, 'the baseline rebuild already zeroed — nothing below is meaningful').toBeGreaterThan(0);

		// The exact reword named in the defect report: one definite article, nothing else.
		const article = rescore(result, {
			title: TITLE,
			replacement: { title: 'No DKIM records found among the tested selectors', detail: HOSTILE_DETAIL },
		});
		expectSameScoring(article, baseline, 'adding one word to the title changed the score');

		const hostile = rescore(result, { title: TITLE, replacement: { title: HOSTILE_TITLE, detail: HOSTILE_DETAIL } });
		expectSameScoring(hostile, baseline, 'maximally hostile prose changed the score');

		const neutral = rescore(result, {
			title: TITLE,
			replacement: { title: 'DKIM selector sweep completed', detail: 'The sweep returned no keys.' },
		});
		expectSameScoring(neutral, baseline, 'neutral prose changed the score');
	});

	it('the reword does not move the OVERALL score, grade or critical gaps either', async () => {
		const dkim = await checkDKIM('example.com', emptyDNS);
		const baseline = rescore(dkim);
		const hostile = rescore(dkim, { title: TITLE, replacement: { title: HOSTILE_TITLE, detail: HOSTILE_DETAIL } });

		// `mail_enabled` is a profile where `dkim` is a critical category, so a zeroing here
		// would cap the whole domain at `criticalGapCeiling` (64 → NIST grade D) as well as
		// emptying the category — the exact re-grade this file exists to prevent.
		const before = computeProfileAwareScanScore([baseline], { profile: 'mail_enabled' });
		const after = computeProfileAwareScanScore([hostile], { profile: 'mail_enabled' });

		expect(after.score.overall).toBe(before.score.overall);
		expect(after.score.grade).toBe(before.score.grade);
		expect(after.score.criticalGaps ?? [], 'the reworded finding armed the critical-gap ceiling').toEqual(before.score.criticalGaps ?? []);
		expect(before.score.criticalGaps ?? []).not.toContain('dkim');
	});
});

describe('prose independence — DNSSEC unsigned zone', () => {
	const TITLE = 'DNSSEC not enabled';

	it('declares the graded-not-zeroed decision structurally', async () => {
		const result = await checkDNSSEC('example.com', emptyDNS, { rawQueryDNS: unsignedRawDNS });
		const finding = result.findings.find((f) => f.title === TITLE);
		expect(finding, 'the unsigned-zone finding was not emitted').toBeDefined();
		expect(finding!.metadata?.penaltyOverride).toBe(40);
		expect(finding!.metadata?.missingControl).toBe(false);
		expect(result.score).toBe(60);
		expect(result.passed).toBe(true);
	});

	it('REWORDING THE DETAIL INTO THE FORBIDDEN WORDS DOES NOT CHANGE THE SCORE', async () => {
		const result = await checkDNSSEC('example.com', emptyDNS, { rawQueryDNS: unsignedRawDNS });

		expect(result.score).toBe(60);

		// Verbatim the phrasing the deleted source comment forbade.
		const forbidden = rescore(result, {
			title: TITLE,
			replacement: {
				title: 'No DNSSEC record found',
				detail: 'DNSSEC is missing for this zone: no DS record was found and validation is required.',
			},
		});
		expect(forbidden.score, 'the copywriting constraint is still load-bearing').toBe(60);
		expect(forbidden.passed).toBe(true);
		expect(findingsIndicateMissingControl(forbidden.findings)).toBe(false);
	});

	it('a genuinely BROKEN chain still zeroes — the veto retracts one claim, not the check', async () => {
		// DS published, DNSKEY absent: a validating resolver cannot authenticate the zone. That
		// finding declares `missingControl: true` and must be unaffected by the sibling `false`.
		const queryDNS: DNSQueryFunction = vi.fn(async (_domain: string, type: string) => (type === 'DS' ? ['12345 13 2 abcdef'] : []));
		const result = await checkDNSSEC('example.com', queryDNS, { rawQueryDNS: unsignedRawDNS });

		expect(result.findings.some((f) => f.title === 'DNSSEC chain of trust incomplete')).toBe(true);
		expect(result.score).toBe(0);
		expect(result.passed).toBe(false);
	});
});
