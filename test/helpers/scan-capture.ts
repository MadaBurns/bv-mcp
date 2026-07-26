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

import type { Finding } from '../../src/lib/scoring';
import type { ScanDomainResult } from '../../src/tools/scan-domain';

export interface ScanCaptureOptions {
	score?: number;
	grade?: string;
	maturityStage?: number;
	findings?: Finding[];
}

/** Build a minimal-but-shape-accurate `ScanDomainResult`. */
export function makeScanDomainResult(domain: string, opts: ScanCaptureOptions = {}): ScanDomainResult {
	const overall = opts.score ?? 80;
	const grade = opts.grade ?? 'B+';
	const findings = opts.findings ?? [];
	return {
		domain,
		score: {
			overall,
			grade,
			categoryScores: { spf: overall } as ScanDomainResult['score']['categoryScores'],
			findings,
			summary: `${domain} scored ${overall}/100. Grade: ${grade}`,
		},
		checks: [],
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
