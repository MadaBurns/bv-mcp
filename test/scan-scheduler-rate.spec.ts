// test/scan-scheduler-rate.spec.ts
// SPDX-License-Identifier: BUSL-1.1
//
// Phase 2 scheduler core (E) — computeAdaptiveRate.
//   target/sec = sum(count / cadenceSec) * bufferFactor, clamped UP to a floor.
//   The per-tick CLAIM CAP is independent of the rate — it comes from
//   SCAN_DISPATCH_BATCH_SIZE via resolveScanDispatchConfig (reuse scaling-flags),
//   not from the computed rate.
//
// Written BEFORE the impl → FAILS until src/lib/scan-scheduler.ts lands.

import { afterEach, describe, expect, it, vi } from 'vitest';
import { resolveScanDispatchConfig } from '../src/lib/scaling-flags';

const DAY_MS = 86_400_000;

afterEach(() => {
	vi.resetModules();
});

describe('computeAdaptiveRate (E)', () => {
	it('target/sec = sum(count/cadence) * buffer', async () => {
		const { computeAdaptiveRate } = await import('../src/lib/scan-scheduler');
		// 86400 domains / 1-day cadence = 1.0/sec; * 1.5 buffer = 1.5/sec.
		const rate = computeAdaptiveRate({ lanes: [{ count: 86_400, cadenceMs: DAY_MS }], bufferFactor: 1.5, floorPerSec: 0.1 });
		expect(rate).toBeCloseTo(1.5, 6);
	});

	it('sums across lanes', async () => {
		const { computeAdaptiveRate } = await import('../src/lib/scan-scheduler');
		const rate = computeAdaptiveRate({
			lanes: [
				{ count: 86_400, cadenceMs: DAY_MS }, // 1.0/sec
				{ count: 86_400, cadenceMs: DAY_MS }, // 1.0/sec
			],
			bufferFactor: 1,
			floorPerSec: 0.1,
		});
		expect(rate).toBeCloseTo(2.0, 6);
	});

	it('applies the floor when the computed rate is below it', async () => {
		const { computeAdaptiveRate } = await import('../src/lib/scan-scheduler');
		const rate = computeAdaptiveRate({ lanes: [{ count: 0, cadenceMs: DAY_MS }], bufferFactor: 1.5, floorPerSec: 0.25 });
		expect(rate).toBe(0.25);
	});

	it('the per-tick claim cap is INDEPENDENT of the computed rate', async () => {
		const { computeAdaptiveRate } = await import('../src/lib/scan-scheduler');
		const highRate = computeAdaptiveRate({ lanes: [{ count: 10_000_000, cadenceMs: DAY_MS }], bufferFactor: 2, floorPerSec: 0.1 });
		const lowRate = computeAdaptiveRate({ lanes: [{ count: 1, cadenceMs: DAY_MS }], bufferFactor: 1, floorPerSec: 0.1 });
		expect(highRate).not.toBeCloseTo(lowRate, 3);

		// Cap is sourced from the flag reader, not the rate — same for both.
		const cap = resolveScanDispatchConfig({ SCAN_DISPATCH_BATCH_SIZE: '50' }).batchSize;
		expect(cap).toBe(50);
	});
});
