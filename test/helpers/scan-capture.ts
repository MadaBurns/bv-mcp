// SPDX-License-Identifier: BUSL-1.1

/**
 * Test helper for driving `scanResultCapture` from a mocked `handleToolsCall`.
 *
 * Tenant scan paths persist what `scan_domain` hands back through
 * `ToolRuntimeOptions.scanResultCapture`. Tests that mock `handleToolsCall`
 * must emit through the SAME hook the real handler uses — `resultCapture` is
 * the single-`CheckResult` hook and is never invoked for `scan_domain`, so a
 * mock that calls it produces a shape production never emits and lets a broken
 * capture path pass. (That is exactly how the tenant paths shipped persisting
 * null score/grade/result_json on every scan.)
 *
 * Emits a `ScanDomainResult`-shaped payload — nested `score.overall` /
 * `score.grade` / `score.findings` plus `maturity` — matching what `scanDomain`
 * actually returns.
 */

import { computeScanEvidence } from '@blackveil/dns-checks/scoring';
import type { CheckResult, Finding } from '../../src/lib/scoring';
import type { ScanDomainResult } from '../../src/tools/scan-domain';

export interface ScanCaptureOptions {
	score?: number;
	grade?: string;
	maturityStage?: number;
	findings?: Finding[];
}

/**
 * Build a minimal-but-shape-accurate `ScanDomainResult`.
 *
 * `checks` is non-empty and that is load-bearing, not decoration. Every caller of
 * this helper wants a GRADED scan (they assert a real `score`/`grade` landed in
 * the tenant `scans` row), and on this branch a graded scan is one that actually
 * measured something: `checks: []` alongside a confident 80/'B+' models a scan
 * that ran zero checks yet carries a grade — the exact contradiction the evidence
 * accounting exists to remove (`isMeasured` reads `checks.length > 0`, and
 * `computeScanEvidence([])` yields `ratio: 0`, below every valid threshold).
 *
 * So the helper emits one completed `CheckResult` that mirrors `categoryScores`
 * and carries the same findings the aggregate does, and derives `evidence` from
 * that array via the real `computeScanEvidence` rather than a hand-written
 * literal — so the two can never drift apart.
 */
export function makeScanDomainResult(domain: string, opts: ScanCaptureOptions = {}): ScanDomainResult {
	const overall = opts.score ?? 80;
	const grade = opts.grade ?? 'B+';
	const findings = opts.findings ?? [];
	// One real, completed check backing the single `categoryScores` entry below.
	const checks: CheckResult[] = [
		{
			category: 'spf',
			passed: overall >= 50,
			score: overall,
			findings,
			checkStatus: 'completed',
		},
	];
	return {
		domain,
		score: {
			overall,
			grade,
			categoryScores: { spf: overall } as ScanDomainResult['score']['categoryScores'],
			findings,
			summary: `${domain} scored ${overall}/100. Grade: ${grade}`,
			// Derived, never hand-written: 1 of 1 attempted checks completed (ratio 1),
			// which is consistent with emitting a confident grade.
			evidence: computeScanEvidence(checks),
		},
		checks,
		maturity: {
			stage: opts.maturityStage ?? 2,
			label: 'Developing',
			description: 'partial coverage',
			nextStep: 'Enforce DMARC.',
		},
		context: { profile: 'mail_enabled', signals: [], weights: {} as never, detectedProvider: null },
		cached: false,
		timestamp: '2026-06-02T00:00:00.000Z',
		scoringNote: null,
		adaptiveWeightDeltas: null,
		interactionEffects: [],
	};
}

/**
 * Invoke `scanResultCapture` on a mocked `handleToolsCall`'s runtimeOptions,
 * the way the real `scan_domain` case does.
 */
export function emitScanCapture(runtimeOptions: unknown, domain: string, opts: ScanCaptureOptions = {}): void {
	const ro = runtimeOptions as { scanResultCapture?: (r: ScanDomainResult) => void } | undefined;
	ro?.scanResultCapture?.(makeScanDomainResult(domain, opts));
}
