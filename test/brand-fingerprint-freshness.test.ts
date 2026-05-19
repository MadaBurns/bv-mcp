// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for the pure freshness-fallback decision module.
 *
 * Pyramid layer: Unit. No I/O, no bindings, no network.
 * The function is shared by the Tier 1 and Tier 2 service-binding wrappers,
 * so it lives in `src/lib/` independent of either consumer.
 */

import { describe, it, expect } from 'vitest';
import { shouldTriggerLiveFallback } from '../src/lib/brand-fingerprint-freshness';

describe('shouldTriggerLiveFallback', () => {
	it('returns false when overallStaleness === "fresh"', () => {
		expect(
			shouldTriggerLiveFallback({ perSignalType: {}, overallStaleness: 'fresh' }),
		).toBe(false);
	});

	it('returns false when overallStaleness === "partial"', () => {
		expect(
			shouldTriggerLiveFallback({ perSignalType: {}, overallStaleness: 'partial' }),
		).toBe(false);
	});

	it('returns false when overallStaleness === "stale"', () => {
		// stale (7d-30d) is recoverable by re-fetching all signals — not a
		// live-sweep trigger. Only very_stale (>30d, signals dead) triggers it.
		expect(
			shouldTriggerLiveFallback({ perSignalType: {}, overallStaleness: 'stale' }),
		).toBe(false);
	});

	it('returns true when overallStaleness === "very_stale"', () => {
		expect(
			shouldTriggerLiveFallback({ perSignalType: {}, overallStaleness: 'very_stale' }),
		).toBe(true);
	});

	it('ignores perSignalType contents — decision is purely on overallStaleness', () => {
		// Per-signal data may be empty even with very_stale overall; or rich
		// even with fresh overall. The consumer doesn't compute its own
		// rollup — it trusts the producer's overallStaleness verdict.
		expect(
			shouldTriggerLiveFallback({
				perSignalType: { mx: { capturedAt: 1, ageHours: 99_999 } },
				overallStaleness: 'fresh',
			}),
		).toBe(false);
		expect(
			shouldTriggerLiveFallback({
				perSignalType: {},
				overallStaleness: 'very_stale',
			}),
		).toBe(true);
	});
});
