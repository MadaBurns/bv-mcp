import { describe, expect, it } from 'vitest';
import { PER_CHECK_TIMEOUT_MS, SCAN_TIMEOUT_MS } from '../src/lib/config';
import { resolveScanTimeoutBudget } from '../src/tools/scan/timeouts';

describe('resolveScanTimeoutBudget', () => {
	it('uses config constants as defaults', () => {
		expect(resolveScanTimeoutBudget()).toMatchObject({
			scanTimeoutMs: SCAN_TIMEOUT_MS,
			perCheckTimeoutMs: PER_CHECK_TIMEOUT_MS,
		});
	});

	it('uses runtime overrides when dispatch passes them', () => {
		expect(resolveScanTimeoutBudget({ scanTimeoutMs: 20_000, perCheckTimeoutMs: 6_000 })).toMatchObject({
			scanTimeoutMs: 20_000,
			perCheckTimeoutMs: 6_000,
		});
	});
	it('caps the per-check budget below the scan timeout when the two overrides contradict (#674)', async () => {
		const { resolveScanTimeoutBudget } = await import('../src/tools/scan/timeouts');

		// Both clamps accept this independently — parsePerCheckTimeout allows up to 15s,
		// parseScanTimeout down to 5s — so a self-host can configure a single check to
		// outlive the entire scan. Left unreconciled, safeCheck's killer becomes dead
		// code and fetchBudgetFor() sizes the #641 fetch budget against a timer that can
		// never fire, discarding checks with their findings already in hand.
		const budget = resolveScanTimeoutBudget({ scanTimeoutMs: 5_000, perCheckTimeoutMs: 15_000 });

		expect(budget.scanTimeoutMs).toBe(5_000);
		expect(budget.perCheckTimeoutMs).toBeLessThan(budget.scanTimeoutMs);
		// Retry budget preserved, so the transient-zero retry pass stays reachable.
		expect(budget.perCheckTimeoutMs).toBe(5_000 - budget.retryBudgetMs);
	});

	it('leaves a non-contradictory pair untouched', async () => {
		const { resolveScanTimeoutBudget } = await import('../src/tools/scan/timeouts');

		// The cap must not perturb ordinary configurations — only the contradictory ones.
		expect(resolveScanTimeoutBudget().perCheckTimeoutMs).toBe(8_000);
		expect(resolveScanTimeoutBudget({ scanTimeoutMs: 20_000, perCheckTimeoutMs: 6_000 }).perCheckTimeoutMs).toBe(6_000);
	});
});
