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
	FREE_TOOL_DAILY_LIMITS,
	DNS_TIMEOUT_MS,
	INFLIGHT_CLEANUP_MS,
	GLOBAL_DAILY_TOOL_LIMIT,
	SCAN_TIMEOUT_MS,
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
		expect(partnerLimits!.scan_domain).toBe(2_500_000);
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

	it('per-tier brand_audit_single overrides match BRAND_AUDIT_QUOTAS', () => {
		// brand_audit_single is gated per-tier — free=0 via FREE_TOOL_DAILY_LIMITS,
		// agent=0/developer=50/partner=200/enterprise=500 via per-tool overrides.
		expect(TIER_TOOL_DAILY_LIMITS.agent?.brand_audit_single).toBe(0);
		expect(TIER_TOOL_DAILY_LIMITS.developer?.brand_audit_single).toBe(50);
		expect(TIER_TOOL_DAILY_LIMITS.partner?.brand_audit_single).toBe(200);
		expect(TIER_TOOL_DAILY_LIMITS.enterprise?.brand_audit_single).toBe(500);
	});
});

describe('free tier tool quota policy', () => {
	it('keeps high-cost or private-probe tools on tight free anonymous limits', () => {
		expect(FREE_TOOL_DAILY_LIMITS.discover_brand_domains).toBe(1);
		expect(FREE_TOOL_DAILY_LIMITS.check_authoritative_dns_infra).toBe(25);
		expect(FREE_TOOL_DAILY_LIMITS.check_fast_flux).toBe(3);
	});

	it('keeps high-query brand-threat tools on bounded free demo limits', () => {
		expect(FREE_TOOL_DAILY_LIMITS.check_lookalikes).toBe(5);
		expect(FREE_TOOL_DAILY_LIMITS.check_shadow_domains).toBe(5);
		expect(FREE_TOOL_DAILY_LIMITS.check_root_server_set).toBe(25);
		expect(FREE_TOOL_DAILY_LIMITS.check_subdomain_takeover).toBe(25);
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
	// Tests reference SCAN_TIMEOUT_MS directly so a future bump of the default
	// (e.g. 12000 → 15000 in v2.10.14 to cover observed prod p50) is a single
	// source of truth instead of a multi-site update.
	it('returns SCAN_TIMEOUT_MS default when env is undefined', () => {
		expect(parseScanTimeout(undefined)).toBe(SCAN_TIMEOUT_MS);
	});

	it('parses valid value', () => {
		expect(parseScanTimeout('20000')).toBe(20000);
	});

	it('clamps to minimum of 5000 (returns default for sub-floor input)', () => {
		expect(parseScanTimeout('2000')).toBe(SCAN_TIMEOUT_MS);
	});

	it('clamps to maximum of 30000', () => {
		expect(parseScanTimeout('50000')).toBe(30000);
	});

	it('returns default for non-numeric input', () => {
		expect(parseScanTimeout('slow')).toBe(SCAN_TIMEOUT_MS);
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
