import { describe, it, expect } from 'vitest';
import { parseCacheTtl, TIER_DAILY_LIMITS, TIER_TOOL_DAILY_LIMITS } from '../src/lib/config';
import type { McpApiKeyTier } from '../src/lib/config';

describe('parseCacheTtl', () => {
	it('returns default 300 when env is undefined', () => {
		expect(parseCacheTtl(undefined)).toBe(300);
	});

	it('returns default 300 when env is empty string', () => {
		expect(parseCacheTtl('')).toBe(300);
	});

	it('parses valid integer', () => {
		expect(parseCacheTtl('600')).toBe(600);
	});

	it('clamps to minimum of 60', () => {
		expect(parseCacheTtl('10')).toBe(300); // falls back to default since < 60
	});

	it('clamps to maximum of 3600', () => {
		expect(parseCacheTtl('7200')).toBe(3600);
	});

	it('returns default for non-numeric input', () => {
		expect(parseCacheTtl('abc')).toBe(300);
	});

	it('returns default for NaN', () => {
		expect(parseCacheTtl('NaN')).toBe(300);
	});

	it('accepts 60 as minimum valid value', () => {
		expect(parseCacheTtl('60')).toBe(60);
	});

	it('accepts 3600 as maximum valid value', () => {
		expect(parseCacheTtl('3600')).toBe(3600);
	});

	it('accepts 1800 for CSC 30-min monitoring use case', () => {
		expect(parseCacheTtl('1800')).toBe(1800);
	});
});

describe('partner tier', () => {
	it('is included in McpApiKeyTier', () => {
		const tier: McpApiKeyTier = 'partner';
		expect(tier).toBe('partner');
	});

	it('has 100K daily limit', () => {
		expect(TIER_DAILY_LIMITS.partner).toBe(100_000);
	});

	it('has per-tool daily limits', () => {
		const partnerLimits = TIER_TOOL_DAILY_LIMITS.partner;
		expect(partnerLimits).toBeDefined();
		expect(partnerLimits!.scan_domain).toBe(100_000);
		expect(partnerLimits!.check_spf).toBe(500_000);
		expect(partnerLimits!.check_lookalikes).toBe(50_000);
	});

	it('per-tool limit takes precedence over flat tier limit', () => {
		const tier: McpApiKeyTier = 'partner';
		const toolName = 'check_spf';
		const limit = TIER_TOOL_DAILY_LIMITS[tier]?.[toolName] ?? TIER_DAILY_LIMITS[tier];
		expect(limit).toBe(500_000); // per-tool override, not flat 100K
	});

	it('falls back to flat limit for unknown tool', () => {
		const tier: McpApiKeyTier = 'partner';
		const toolName = 'unknown_tool';
		const limit = TIER_TOOL_DAILY_LIMITS[tier]?.[toolName] ?? TIER_DAILY_LIMITS[tier];
		expect(limit).toBe(100_000); // flat tier limit
	});

	it('enterprise tier has no per-tool overrides', () => {
		expect(TIER_TOOL_DAILY_LIMITS.enterprise).toBeUndefined();
	});
});
