// test/scheduled-retention.spec.ts
import { afterEach, describe, expect, it, vi } from 'vitest';
afterEach(() => vi.restoreAllMocks());

describe('access-log retention', () => {
	it('binds the configured ANALYTICS_RETENTION_DAYS seconds (default 90)', async () => {
		const { clampRetentionDays } = await import('../src/scheduled');
		expect(clampRetentionDays(undefined)).toBe(90);
		expect(clampRetentionDays('30')).toBe(30);
		expect(clampRetentionDays('0')).toBe(1); // floor
		expect(clampRetentionDays('5000')).toBe(365); // ceiling
		expect(clampRetentionDays('abc')).toBe(90);
	});
});
