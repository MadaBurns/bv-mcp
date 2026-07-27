// SPDX-License-Identifier: BUSL-1.1

/**
 * CONTRACT — the maturity ladder's evidence invariant (issue #574).
 *
 * Both ladders must obey the rule #455 / v3.25.4 established for
 * `check_mta_sts`: **an unmeasurable input produces an abstention, never a
 * confident verdict.** Stated as two properties that hold for EVERY category
 * either ladder reads:
 *
 *   1. MONOTONICITY — replacing a completed check with an inconclusive one
 *      (`checkStatus: 'error' | 'timeout'`) never RAISES the stage. Violating
 *      this is false reassurance: it is how an errored `spf`/`dmarc`/`dkim`
 *      (whose absence-of-finding probes then read `true`) inflated maturity.
 *   2. NO CONFIDENT BOTTOM RUNG — if the degraded input lands the domain on the
 *      bottom rung, that result must be flagged `indeterminate`, because every
 *      bottom-rung description is an affirmative factual claim ("No TLS
 *      detected…", "No email authentication…") that the missing measurement
 *      cannot support.
 *
 * This is a property test over the category set, not a fixture test: a NEW
 * signal wired into either ladder is covered the moment it is added to the
 * arrays below, and the ladder's own baseline is asserted first so the whole
 * file cannot pass vacuously.
 */

import { describe, it, expect } from 'vitest';
import { computeMaturityStage } from '../../src/tools/scan/maturity-staging';
import { buildCheckResult, createFinding } from '../../src/lib/scoring';
import type { CheckResult } from '../../src/lib/scoring';

/** The exact shape `scan-domain.ts` re-stamps onto an inconclusive check. */
function inconclusive(category: Parameters<typeof buildCheckResult>[0], status: 'error' | 'timeout'): CheckResult {
	return {
		...buildCheckResult(category, [createFinding(category, `${category} check error`, 'high', 'Check failed: probe did not complete')]),
		score: 0,
		passed: false,
		checkStatus: status,
		partial: true,
	};
}

function pass(category: Parameters<typeof buildCheckResult>[0], title: string): CheckResult {
	return buildCheckResult(category, [createFinding(category, title, 'info', 'ok')]);
}

/** Ladder A (web_only): a fully-measured stage-4 "Comprehensive" domain. */
const WEB_ONLY_BASELINE: CheckResult[] = [
	buildCheckResult('mx', [createFinding('mx', 'No MX records found', 'info', 'web-only')]),
	buildCheckResult('spf', [createFinding('spf', 'SPF record found', 'info', 'v=spf1 -all')]),
	buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC record found', 'info', 'p=reject')]),
	pass('ssl', 'SSL certificate valid'),
	pass('dnssec', 'DNSSEC validated'),
	buildCheckResult('http_security', [createFinding('http_security', 'HSTS configured (preload)', 'info', 'HSTS')]),
];
const WEB_ONLY_CATEGORIES = ['ssl', 'dnssec', 'http_security', 'spf', 'dmarc'] as const;

/** Ladder B (mail_enabled): a fully-measured stage-4 "Hardened" domain. */
const MAIL_BASELINE: CheckResult[] = [
	buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 records')]),
	buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
	buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC record found', 'info', 'p=reject')]),
	buildCheckResult('dkim', [createFinding('dkim', 'DKIM configured', 'info', 'selectors', { selectorsFound: ['s1'] })]),
	pass('mta_sts', 'MTA-STS configured'),
	pass('dnssec', 'DNSSEC validated'),
	pass('caa', 'CAA records found'),
	buildCheckResult('bimi', [createFinding('bimi', 'BIMI record configured', 'info', 'ok')]),
	buildCheckResult('dane', [createFinding('dane', 'DANE TLSA configured', 'info', 'ok')]),
];
const MAIL_CATEGORIES = ['spf', 'dmarc', 'dkim', 'mta_sts', 'dnssec', 'bimi', 'dane', 'caa'] as const;

function degrade(checks: CheckResult[], category: string, status: 'error' | 'timeout'): CheckResult[] {
	return checks.map((c) => (c.category === category ? inconclusive(c.category, status) : c));
}

describe('CONTRACT: maturity ladders are evidence-gated (#574)', () => {
	it('baseline (non-vacuity): both ladders reach stage 4 when everything is measured', () => {
		const web = computeMaturityStage(WEB_ONLY_BASELINE, 'web_only');
		expect(web.stage).toBe(4);
		expect(web.indeterminate).toBeUndefined();

		const mail = computeMaturityStage(MAIL_BASELINE, 'mail_enabled');
		expect(mail.stage).toBe(4);
		expect(mail.indeterminate).toBeUndefined();
	});

	describe.each([['web_only', WEB_ONLY_BASELINE, WEB_ONLY_CATEGORIES] as const, ['mail_enabled', MAIL_BASELINE, MAIL_CATEGORIES] as const])(
		'%s ladder',
		(profile, baseline, categories) => {
			const baselineStage = () => computeMaturityStage(baseline, profile).stage;

			it.each(categories.flatMap((c) => [[c, 'error'] as const, [c, 'timeout'] as const]))(
				'an inconclusive %s (%s) never RAISES the stage',
				(category, status) => {
					const degraded = computeMaturityStage(degrade(baseline, category, status), profile);
					expect(degraded.stage).toBeLessThanOrEqual(baselineStage());
				},
			);

			it.each(categories.flatMap((c) => [[c, 'error'] as const, [c, 'timeout'] as const]))(
				'an inconclusive %s (%s) never yields a CONFIDENT bottom-rung verdict',
				(category, status) => {
					const degraded = computeMaturityStage(degrade(baseline, category, status), profile);
					if (degraded.stage === 0) {
						expect(degraded.indeterminate, `${profile}/${category}/${status} landed on stage 0 as a confident verdict`).toBe(true);
					}
					// An indeterminate result must never carry a bottom-rung factual claim.
					if (degraded.indeterminate) {
						const prose = `${degraded.label} ${degraded.description}`;
						expect(prose).not.toMatch(/No TLS detected|not authenticated or encrypted|No email authentication|any server can send/i);
					}
				},
			);
		},
	);
});
