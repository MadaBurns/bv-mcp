// SPDX-License-Identifier: BUSL-1.1

/**
 * Evidence-gate safety corpus.
 *
 * The gate exists to withhold a grade from a scan that measured almost nothing. The
 * failure mode of the gate itself is the opposite and worse: silently ungrading
 * domains that WERE measured. Everything here asserts a NEGATIVE ("the gate did not
 * fire"), which is the most vacuity-prone shape there is — so each case pins a
 * concrete non-null grade rather than merely asserting the absence of a flag, and the
 * whole file is validated by the mutation check in this task's Step 4.
 */

import { describe, expect, it } from 'vitest';
import type { CheckCategory, CheckResult } from '../src/lib/scoring';

/** The 19 categories a real scan_domain run submits. */
const SCAN_CATEGORIES: CheckCategory[] = [
	'spf',
	'dmarc',
	'dkim',
	'dnssec',
	'ssl',
	'mta_sts',
	'ns',
	'caa',
	'subdomain_takeover',
	'mx',
	'bimi',
	'tlsrpt',
	'txt_hygiene',
	'http_security',
	'dane',
	'subdomailing',
	'zone_hygiene',
	'srv',
	'ptr',
];

describe('evidence gate does NOT fire on a measured scan', () => {
	it('a fully healthy 19/19 scan keeps its grade and reports ratio 1', async () => {
		const { computeScanScore, buildCheckResult, createFinding } = await import('@blackveil/dns-checks/scoring');
		const results: CheckResult[] = SCAN_CATEGORIES.map((c) => ({
			...buildCheckResult(c, [createFinding(c, `${c} OK`, 'info', 'Check passed')], true),
			checkStatus: 'completed' as const,
		}));

		const score = computeScanScore(results);

		expect(score.evidence).toEqual({ attempted: 19, completed: 19, ratio: 1 });
		expect(score.evidenceInsufficient).toBeUndefined();
		expect(score.overall).toBeGreaterThan(0);
		expect(typeof score.grade).toBe('string');
		expect(score.grade).toMatch(/^[A-F][+]?$/);
	});

	it('a genuinely BAD but fully measured scan is still graded — a bad domain is not an unmeasured one', async () => {
		const { computeScanScore, buildCheckResult, createFinding } = await import('@blackveil/dns-checks/scoring');
		// Every check ran; every check failed. This must produce a real (low) grade.
		const results: CheckResult[] = SCAN_CATEGORIES.map((c) => ({
			...buildCheckResult(c, [createFinding(c, `No ${c} record found`, 'critical', 'Missing record')], false),
			score: 0,
			passed: false,
			checkStatus: 'completed' as const,
		}));

		const score = computeScanScore(results);

		expect(score.evidence.completed).toBe(19);
		expect(score.evidenceInsufficient).toBeUndefined();
		expect(score.overall).not.toBeNull();
		expect(score.grade).not.toBeNull();
	});

	it('a scan with a MINORITY of failed-to-run checks is still graded', async () => {
		const { computeScanScore, buildCheckResult, createFinding } = await import('@blackveil/dns-checks/scoring');
		// 14 completed, 5 timed out = 73.7%, comfortably above the 60% threshold.
		const results: CheckResult[] = SCAN_CATEGORIES.map((c, i) =>
			i < 14
				? { ...buildCheckResult(c, [createFinding(c, `${c} OK`, 'info', 'ok')], true), checkStatus: 'completed' as const }
				: {
						...buildCheckResult(c, [createFinding(c, `${c} timed out`, 'low', 'no run')]),
						score: 0,
						passed: false,
						checkStatus: 'timeout' as const,
					},
		);

		const score = computeScanScore(results);

		expect(score.evidence.completed).toBe(14);
		expect(score.evidence.ratio).toBeGreaterThan(0.6);
		expect(score.evidenceInsufficient).toBeUndefined();
		expect(score.overall).not.toBeNull();
	});

	it('the profile-aware entry point behaves identically on a healthy scan', async () => {
		const { computeProfileAwareScanScore, buildCheckResult, createFinding } = await import('@blackveil/dns-checks/scoring');
		const results: CheckResult[] = SCAN_CATEGORIES.map((c) => ({
			...buildCheckResult(c, [createFinding(c, `${c} OK`, 'info', 'Check passed')], true),
			checkStatus: 'completed' as const,
		}));

		const { score } = computeProfileAwareScanScore(results, { profile: 'auto' });

		expect(score.evidenceInsufficient).toBeUndefined();
		expect(score.overall).not.toBeNull();
		expect(score.grade).not.toBeNull();
	});

	// Task 6 dependency: buildStructuredScanResult does not carry evidence yet. it.fails
	// is self-enforcing — the moment Task 6 lands this turns RED and Task 6 must flip it
	// to a plain it().
	it.fails('the structured wire result of a healthy scan carries a grade and full coverage', async () => {
		const { buildStructuredScanResult } = await import('../src/tools/scan/format-report');
		const { computeScanScore, buildCheckResult, createFinding } = await import('@blackveil/dns-checks/scoring');
		const checks: CheckResult[] = SCAN_CATEGORIES.map((c) => ({
			...buildCheckResult(c, [createFinding(c, `${c} OK`, 'info', 'Check passed')], true),
			checkStatus: 'completed' as const,
		}));
		const score = computeScanScore(checks);

		const structured = buildStructuredScanResult({
			domain: 'healthy.example',
			score,
			checks,
			maturity: null,
			context: { profile: 'mail_enabled', signals: [], weights: {}, detectedProvider: null },
			cached: false,
			timestamp: '2026-07-26T00:00:00Z',
			scoringNote: null,
			adaptiveWeightDeltas: null,
			interactionEffects: [],
		} as unknown as Parameters<typeof buildStructuredScanResult>[0]);

		expect(structured.score).not.toBeNull();
		expect(structured.grade).not.toBeNull();
		expect(structured.evidenceInsufficient).toBe(false);
		expect(structured.evidence).toEqual({ attempted: 19, completed: 19, ratio: 1 });
		expect(structured.measured).toBe(true);
	});
});
