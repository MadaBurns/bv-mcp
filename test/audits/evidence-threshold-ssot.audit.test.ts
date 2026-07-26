// SPDX-License-Identifier: BUSL-1.1

/**
 * The evidence threshold must live in exactly ONE named constant.
 *
 * A magic `0.6` scattered across call sites is how a gate silently diverges from its
 * config override — one site honours SCORING_CONFIG, another does not, and a domain's
 * grade depends on which code path reached it. This audit fails if a bare numeric
 * comparison against the threshold reappears anywhere in the scoring engine or the
 * report layer.
 *
 * The "no other module hard-codes 0.6" check is deliberately narrower than a blanket
 * `/\b0\.6\b/` scan: `config.ts` legitimately contains unrelated `0.6` literals (the
 * proofpoint/mimecast DKIM provider-confidence defaults, and the legacy
 * emailBonusImportance→emailBonusMid migration factor `v * 0.6`) that have nothing to
 * do with the evidence-sufficiency gate. A whole-file literal ban would false-positive
 * on those forever. Instead this matches the SHAPES a threshold regression actually
 * takes: a comparison operator adjacent to `0.6` (`< 0.6`, `>= 0.6`, `= 0.6`, …) or the
 * literal sitting next to the `evidenceSufficiency` key — both are how a divergent
 * hard-coded threshold would actually be written; a colon-assignment to an unrelated
 * key or a multiplication factor is not.
 */

import { describe, expect, it } from 'vitest';
import evidenceSource from '../../packages/dns-checks/src/scoring/evidence.ts?raw';
import engineSource from '../../packages/dns-checks/src/scoring/engine.ts?raw';
import configSource from '../../packages/dns-checks/src/scoring/config.ts?raw';
import formatReportSource from '../../src/tools/scan/format-report.ts?raw';
import batchScanSource from '../../src/tools/batch-scan.ts?raw';
import { EVIDENCE_SUFFICIENCY_THRESHOLD, DEFAULT_SCORING_CONFIG } from '@blackveil/dns-checks/scoring';

/** Comparison-shaped or evidenceSufficiency-adjacent `0.6` — see file-level doc above. */
const SUSPICIOUS_THRESHOLD_LITERAL = /[=<>!]=?\s*0\.6\b|\b0\.6\s*[=<>!]|evidenceSufficiency[^\n]{0,30}0\.6/;

describe('evidence threshold SSOT', () => {
	it('declares the literal 0.6 exactly once, in evidence.ts', () => {
		const declarations = evidenceSource.match(/EVIDENCE_SUFFICIENCY_THRESHOLD\s*=\s*0\.6/g) ?? [];
		expect(declarations).toHaveLength(1);
	});

	it('has no OTHER module hard-coding the threshold value', () => {
		const consumers: Array<[string, string]> = [
			['engine.ts', engineSource],
			['config.ts', configSource],
			['format-report.ts', formatReportSource],
			['batch-scan.ts', batchScanSource],
		];
		// Non-empty guard: if this list is ever emptied the loop below becomes vacuous.
		expect(consumers.length).toBeGreaterThan(0);
		for (const [name, source] of consumers) {
			expect(
				source,
				`${name} must reference EVIDENCE_SUFFICIENCY_THRESHOLD / thresholds.evidenceSufficiency, never a hard-coded 0.6 comparison`,
			).not.toMatch(SUSPICIOUS_THRESHOLD_LITERAL);
		}
	});

	it('sources the runtime config default from the constant, not a restatement', () => {
		expect(DEFAULT_SCORING_CONFIG.thresholds.evidenceSufficiency).toBe(EVIDENCE_SUFFICIENCY_THRESHOLD);
		expect(configSource).toContain('evidenceSufficiency: EVIDENCE_SUFFICIENCY_THRESHOLD');
	});
});
