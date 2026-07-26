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
 *
 * The category set is deliberately NOT hard-coded here: it is pulled from the real
 * `SCAN_CATEGORIES` SSOT (`src/tools/scan-domain.ts`) via dynamic import in every
 * test body, so this corpus tracks the actual scanned set (currently 19, but never
 * assumed) rather than a private copy that can silently drift from it.
 */

import { describe, expect, it } from 'vitest';
import type { CheckResult } from '../src/lib/scoring';

describe('evidence gate does NOT fire on a measured scan', () => {
	it('a fully healthy scan keeps its grade and reports ratio 1', async () => {
		const { SCAN_CATEGORIES } = await import('../src/tools/scan-domain');
		const { computeScanScore, buildCheckResult, createFinding } = await import('@blackveil/dns-checks/scoring');
		const results: CheckResult[] = SCAN_CATEGORIES.map((c) => ({
			...buildCheckResult(c, [createFinding(c, `${c} OK`, 'info', 'Check passed')], true),
			checkStatus: 'completed' as const,
		}));

		const score = computeScanScore(results);

		expect(score.evidence).toEqual({ attempted: SCAN_CATEGORIES.length, completed: SCAN_CATEGORIES.length, ratio: 1 });
		expect(score.evidenceInsufficient).toBeUndefined();
		expect(score.overall).toBeGreaterThan(0);
		expect(typeof score.grade).toBe('string');
		expect(score.grade).toMatch(/^[A-F][+]?$/);
	});

	it('a genuinely BAD but fully measured scan is still graded — a bad domain is not an unmeasured one', async () => {
		const { SCAN_CATEGORIES } = await import('../src/tools/scan-domain');
		const { computeScanScore, buildCheckResult, createFinding } = await import('@blackveil/dns-checks/scoring');
		// Every check ran; every check failed. This must produce a real (low) grade.
		const results: CheckResult[] = SCAN_CATEGORIES.map((c) => ({
			...buildCheckResult(c, [createFinding(c, `No ${c} record found`, 'critical', 'Missing record')], false),
			score: 0,
			passed: false,
			checkStatus: 'completed' as const,
		}));

		const score = computeScanScore(results);

		expect(score.evidence.completed).toBe(SCAN_CATEGORIES.length);
		expect(score.evidenceInsufficient).toBeUndefined();
		expect(score.overall).not.toBeNull();
		expect(score.grade).not.toBeNull();
	});

	it('a scan with a MINORITY of failed-to-run checks is still graded', async () => {
		const { SCAN_CATEGORIES } = await import('../src/tools/scan-domain');
		const { computeScanScore, buildCheckResult, createFinding, EVIDENCE_SUFFICIENCY_THRESHOLD } =
			await import('@blackveil/dns-checks/scoring');
		// 14 completed, 5 failed-to-run — comfortably above EVIDENCE_SUFFICIENCY_THRESHOLD.
		// The 5 non-completed checks are split across BOTH transient classes: 2 'error'
		// (the dominant real-world class — buildDnsErrorResult's shape) and 3 'timeout',
		// so this doesn't accidentally only exercise one of the two.
		const nCompleted = 14;
		const results: CheckResult[] = SCAN_CATEGORIES.map((c, i) => {
			if (i < nCompleted) {
				return { ...buildCheckResult(c, [createFinding(c, `${c} OK`, 'info', 'ok')], true), checkStatus: 'completed' as const };
			}
			const failedIndex = i - nCompleted;
			const checkStatus = failedIndex < 2 ? ('error' as const) : ('timeout' as const);
			return {
				...buildCheckResult(c, [createFinding(c, `${c} ${checkStatus === 'error' ? 'errored' : 'timed out'}`, 'low', 'no run')]),
				score: 0,
				passed: false,
				checkStatus,
			};
		});

		const score = computeScanScore(results);

		expect(score.evidence.completed).toBe(nCompleted);
		expect(score.evidence.ratio).toBeGreaterThan(EVIDENCE_SUFFICIENCY_THRESHOLD);
		expect(score.evidenceInsufficient).toBeUndefined();
		expect(score.overall).not.toBeNull();
	});

	it('the profile-aware entry point behaves identically on a healthy scan', async () => {
		const { SCAN_CATEGORIES } = await import('../src/tools/scan-domain');
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

	// Task 6 landed: buildStructuredScanResult now carries evidence, so this runs as a
	// normal assertion rather than the `it.fails` placeholder that pinned the gap.
	it('the structured wire result of a healthy scan carries a grade and full coverage', async () => {
		const { SCAN_CATEGORIES } = await import('../src/tools/scan-domain');
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
		expect(structured.evidence).toEqual({ attempted: SCAN_CATEGORIES.length, completed: SCAN_CATEGORIES.length, ratio: 1 });
		expect(structured.measured).toBe(true);
	});
});
