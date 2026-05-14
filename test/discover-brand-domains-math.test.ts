// SPDX-License-Identifier: BUSL-1.1

/**
 * Slice 4 — regression locks for the confidence-combination math.
 *
 * These are characterization tests, not TDD-RED-first work. They pass on
 * first write. Their purpose is to *prevent silent drift* in the math that
 * the "Zero False Positive" mandate depends on — particularly the user's
 * explicit invariant that san+markov can never cross 0.5.
 *
 * If a future change to DEFAULT_SIGNAL_CONFIDENCE or combineConfidences
 * breaks these, that's the signal to revisit the v2.14.0 audit (LR-1..LR-3)
 * and decide whether the precision posture is actually changing.
 */

import { describe, it, expect } from 'vitest';
import {
	combineConfidences,
	round4,
	DEFAULT_SIGNAL_CONFIDENCE,
} from '../src/tools/discover-brand-domains';

describe('combineConfidences — independent-events probability', () => {
	it('empty input yields 0', () => {
		expect(combineConfidences([])).toBe(0);
	});

	it('single value passes through (modulo clamp)', () => {
		expect(round4(combineConfidences([0.6]))).toBe(0.6);
		expect(round4(combineConfidences([0.95]))).toBe(0.95);
	});

	it('clamps values to [0, 1]', () => {
		expect(combineConfidences([1.5])).toBe(1);
		expect(combineConfidences([-0.5])).toBe(0);
	});
});

describe('confidence math — mandated invariants', () => {
	it('USER MANDATE: san + markov_gen stays below default min_confidence', () => {
		// Combined = 1 - (1 - 0.1)(1 - 0.01) = 0.109
		// The "Zero False Positive" mandate requires this pair never cross 0.5.
		const combined = round4(combineConfidences([
			DEFAULT_SIGNAL_CONFIDENCE.san,
			DEFAULT_SIGNAL_CONFIDENCE.markov_gen,
		]));
		expect(combined).toBe(0.109);
		expect(combined).toBeLessThan(0.5);
	});

	it('san + dmarc_rua (related@0.6) combines to 0.64', () => {
		// 1 - (1 - 0.1)(1 - 0.6) = 0.64. Above 0.5 — corroborated pair surfaces.
		expect(round4(combineConfidences([0.1, 0.6]))).toBe(0.64);
	});

	it('san + dkim_key_reuse combines to 0.955', () => {
		// 1 - (1 - 0.1)(1 - 0.95) = 0.955. Above AUTO_INCLUDE_THRESHOLD (0.85).
		expect(round4(combineConfidences([
			DEFAULT_SIGNAL_CONFIDENCE.san,
			DEFAULT_SIGNAL_CONFIDENCE.dkim_key_reuse,
		]))).toBe(0.955);
	});

	it('DEFAULT_SIGNAL_CONFIDENCE values match the audit-time matrix', () => {
		// Locks the v2.14.0 calibration. Changes here should require an audit
		// pass on LR-1..LR-3 to confirm the precision posture still holds.
		expect(DEFAULT_SIGNAL_CONFIDENCE.san).toBe(0.1);
		expect(DEFAULT_SIGNAL_CONFIDENCE.ns).toBe(0.9);
		expect(DEFAULT_SIGNAL_CONFIDENCE.dkim_key_reuse).toBe(0.95);
		expect(DEFAULT_SIGNAL_CONFIDENCE.markov_gen).toBe(0.01);
		// dmarc_rua is intentionally NOT pinned here — Slice 5 reconciles
		// the dead 0.8 default against the miner's emitted 0.6.
	});
});
