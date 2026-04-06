import { describe, it, expect } from 'vitest';
import {
	parseCacheTtl,
	parseDnsTimeout,
	parseInflightCleanup,
	parseGlobalDailyLimit,
	parseScanTimeout,
	parsePerCheckTimeout,
	TIER_DAILY_LIMITS,
	TIER_TOOL_DAILY_LIMITS,
	DNS_TIMEOUT_MS,
	INFLIGHT_CLEANUP_MS,
	GLOBAL_DAILY_TOOL_LIMIT,
} from '../src/lib/config';
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

	it('accepts 1800 for 30-min monitoring use case', () => {
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

describe('parseDnsTimeout', () => {
	it('returns default when env is undefined', () => {
		expect(parseDnsTimeout(undefined)).toBe(DNS_TIMEOUT_MS);
	});

	it('returns default for empty string', () => {
		expect(parseDnsTimeout('')).toBe(DNS_TIMEOUT_MS);
	});

	it('parses valid integer', () => {
		expect(parseDnsTimeout('5000')).toBe(5000);
	});

	it('clamps to minimum of 1000', () => {
		expect(parseDnsTimeout('500')).toBe(DNS_TIMEOUT_MS);
	});

	it('clamps to maximum of 10000', () => {
		expect(parseDnsTimeout('15000')).toBe(10000);
	});

	it('returns default for NaN', () => {
		expect(parseDnsTimeout('abc')).toBe(DNS_TIMEOUT_MS);
	});

	it('returns default for negative values', () => {
		expect(parseDnsTimeout('-1')).toBe(DNS_TIMEOUT_MS);
	});
});

describe('parseInflightCleanup', () => {
	it('returns default when env is undefined', () => {
		expect(parseInflightCleanup(undefined)).toBe(INFLIGHT_CLEANUP_MS);
	});

	it('parses valid value', () => {
		expect(parseInflightCleanup('60000')).toBe(60000);
	});

	it('clamps to minimum of 5000', () => {
		expect(parseInflightCleanup('1000')).toBe(INFLIGHT_CLEANUP_MS);
	});

	it('clamps to maximum of 120000', () => {
		expect(parseInflightCleanup('200000')).toBe(120000);
	});

	it('returns default for non-numeric input', () => {
		expect(parseInflightCleanup('x')).toBe(INFLIGHT_CLEANUP_MS);
	});
});

describe('parseGlobalDailyLimit', () => {
	it('returns default when env is undefined', () => {
		expect(parseGlobalDailyLimit(undefined)).toBe(GLOBAL_DAILY_TOOL_LIMIT);
	});

	it('parses valid value', () => {
		expect(parseGlobalDailyLimit('1000000')).toBe(1000000);
	});

	it('clamps to minimum of 10000', () => {
		expect(parseGlobalDailyLimit('100')).toBe(GLOBAL_DAILY_TOOL_LIMIT);
	});

	it('clamps to maximum of 5000000', () => {
		expect(parseGlobalDailyLimit('10000000')).toBe(5000000);
	});

	it('returns default for NaN', () => {
		expect(parseGlobalDailyLimit('NaN')).toBe(GLOBAL_DAILY_TOOL_LIMIT);
	});
});

describe('parseScanTimeout', () => {
	it('returns 12000 when env is undefined', () => {
		expect(parseScanTimeout(undefined)).toBe(12000);
	});

	it('parses valid value', () => {
		expect(parseScanTimeout('20000')).toBe(20000);
	});

	it('clamps to minimum of 5000', () => {
		expect(parseScanTimeout('2000')).toBe(12000);
	});

	it('clamps to maximum of 30000', () => {
		expect(parseScanTimeout('50000')).toBe(30000);
	});

	it('returns default for non-numeric input', () => {
		expect(parseScanTimeout('slow')).toBe(12000);
	});
});

describe('parsePerCheckTimeout', () => {
	it('returns 8000 when env is undefined', () => {
		expect(parsePerCheckTimeout(undefined)).toBe(8000);
	});

	it('parses valid value', () => {
		expect(parsePerCheckTimeout('6000')).toBe(6000);
	});

	it('clamps to minimum of 2000', () => {
		expect(parsePerCheckTimeout('1000')).toBe(8000);
	});

	it('clamps to maximum of 15000', () => {
		expect(parsePerCheckTimeout('20000')).toBe(15000);
	});

	it('returns default for non-numeric input', () => {
		expect(parsePerCheckTimeout('fast')).toBe(8000);
	});
});
