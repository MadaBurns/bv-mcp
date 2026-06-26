// test/analytics-pii.spec.ts
import { afterEach, describe, expect, it, vi } from 'vitest';

afterEach(() => vi.restoreAllMocks());

describe('parseAnalyticsPiiLevel', () => {
	it('defaults to coarse on undefined/unknown and is case-insensitive', async () => {
		const { parseAnalyticsPiiLevel } = await import('../src/lib/analytics-pii');
		expect(parseAnalyticsPiiLevel(undefined)).toBe('coarse');
		expect(parseAnalyticsPiiLevel('nonsense')).toBe('coarse');
		expect(parseAnalyticsPiiLevel('FULL')).toBe('full');
		expect(parseAnalyticsPiiLevel('Standard')).toBe('standard');
	});
});

describe('piiAllows', () => {
	it('gates ciphertext+city at standard, precise_geo+ptr at full', async () => {
		const { piiAllows } = await import('../src/lib/analytics-pii');
		expect(piiAllows('coarse', 'ciphertext')).toBe(false);
		expect(piiAllows('coarse', 'ptr')).toBe(false);
		expect(piiAllows('standard', 'ciphertext')).toBe(true);
		expect(piiAllows('standard', 'city')).toBe(true);
		expect(piiAllows('standard', 'precise_geo')).toBe(false);
		expect(piiAllows('standard', 'ptr')).toBe(false);
		expect(piiAllows('full', 'precise_geo')).toBe(true);
		expect(piiAllows('full', 'ptr')).toBe(true);
	});
});
