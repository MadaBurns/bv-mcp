// SPDX-License-Identifier: BUSL-1.1

/**
 * SQ-66: direct coverage for the display-grade chokepoint (`src/lib/ungraded-display.ts`),
 * the npm package surface built on it (`src/package.ts`), and the `StructuredScanResult`
 * `passed`/`grade` agreement it enables (`src/tools/scan/format-report.ts`).
 *
 * Every case is titled to include "scoring" so the ticket's pinned
 * `npx vitest run test/package test/ungraded-display packages/dns-checks/src/__tests__ -t scoring`
 * selects it.
 */

import { describe, it, expect } from 'vitest';
import { nistScoreToGrade, scoreToGrade } from '@blackveil/dns-checks/scoring';
import type { ScanScore } from '@blackveil/dns-checks/scoring';
import { displayGradeFor, formatScoreGrade, UNGRADED_DISPLAY } from '../src/lib/ungraded-display';
import type { ScanDomainResult } from '../src/tools/scan-domain';

describe('displayGradeFor — the scoring display chokepoint', () => {
	it('scoring: returns null for an ungraded score rather than fabricating a letter', () => {
		expect(displayGradeFor({ overall: null, grade: null })).toBeNull();
	});

	it('scoring: renders the NIST display letter for a measured score (control)', () => {
		expect(displayGradeFor({ overall: 78, grade: scoreToGrade(78) })).toBe(nistScoreToGrade(78));
	});

	it('scoring: formatScoreGrade abstains to UNGRADED_DISPLAY rather than interpolating null', () => {
		expect(formatScoreGrade(null, null)).toBe(UNGRADED_DISPLAY);
		expect(formatScoreGrade(78, 'C')).toBe('78/100 (C)');
	});
});

describe('package surface scoring exports (SQ-66)', () => {
	it('scoring: exposes displayGradeFor from src/package.ts, not just the internal scoreToGrade', async () => {
		const mod = await import('../src/package');

		expect(mod.displayGradeFor).toBeTypeOf('function');
		expect(mod.nistScoreToGrade).toBeTypeOf('function');
		expect(mod.scoreToGrade).toBeTypeOf('function');
	});

	it('scoring: a null/ungraded score does NOT yield "F" through the package surface', async () => {
		const { displayGradeFor: packageDisplayGradeFor } = await import('../src/package');

		expect(packageDisplayGradeFor({ overall: null, grade: null })).toBeNull();
	});
});

describe('StructuredScanResult passed/grade agreement (SQ-66 scoring)', () => {
	function scanResult(score: ScanScore): ScanDomainResult {
		return {
			domain: 'example.com',
			score,
			checks: [{ category: 'spf', passed: true, score: 100, findings: [] }] as ScanDomainResult['checks'],
			maturity: { stage: 2, label: 'Basic', description: 'Some controls detected.', nextStep: 'Add DMARC.' },
			context: { profile: 'mail_enabled', signals: [], detectedProvider: null } as unknown as ScanDomainResult['context'],
			cached: false,
			timestamp: new Date().toISOString(),
			scoringNote: null,
			adaptiveWeightDeltas: null,
			interactionEffects: [],
		};
	}

	it('scoring: never reports passed:true alongside a displayed grade of F', async () => {
		// The NIST display floor is 60 (NIST_GRADE_THRESHOLDS.D). The old `passed` read
		// `overall >= 50` — a SEPARATE threshold — so a scan scoring 50-59 emitted
		// `grade: 'F'` alongside `passed: true`: a customer-visible contradiction.
		const { buildStructuredScanResult } = await import('../src/tools/scan/format-report');
		const structured = buildStructuredScanResult(
			scanResult({
				overall: 55,
				grade: scoreToGrade(55),
				categoryScores: { spf: 100 } as unknown as ScanScore['categoryScores'],
				findings: [],
				summary: 'test',
				evidence: { attempted: 19, completed: 19, ratio: 1 },
			}),
		);

		expect(structured.score).toBe(55);
		expect(structured.grade).toBe('F');
		expect(structured.passed).toBe(false);
	});

	it('scoring: still reports passed:true for a real passing grade (control)', async () => {
		const { buildStructuredScanResult } = await import('../src/tools/scan/format-report');
		const structured = buildStructuredScanResult(
			scanResult({
				overall: 78,
				grade: scoreToGrade(78),
				categoryScores: { spf: 100 } as unknown as ScanScore['categoryScores'],
				findings: [],
				summary: 'test',
				evidence: { attempted: 19, completed: 19, ratio: 1 },
			}),
		);

		expect(structured.score).toBe(78);
		expect(structured.grade).toBe('C');
		expect(structured.passed).toBe(true);
	});
});
