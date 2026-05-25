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
});
