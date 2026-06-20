import { describe, it, expect } from 'vitest';
import {
	queryDailyActiveUsers,
	queryToolPopularity,
	queryErrorRate,
	queryLatencyPercentiles,
	queryClientBreakdown,
	queryGeoDistribution,
	queryRateLimitHits,
	queryTierBreakdown,
	queryRecentAnomalies,
	queryRecentAnomaliesByColo,
	queryRateLimitSurge,
	queryTierToolUsage,
	queryTierLatency,
	queryTierErrorRate,
	queryTierCachePerformance,
	queryTierRateLimits,
	queryTierSessions,
	queryTierDailyTrend,
	queryTierTopTools,
	queryKeyUsage,
	queryTierDigest,
	queryBindingDegradation,
	queryQueueFailures,
} from '../src/lib/analytics-queries';

describe('analytics query builders', () => {
	it('queryDailyActiveUsers returns valid SQL referencing MCP_ANALYTICS', () => {
		const sql = queryDailyActiveUsers('1');
		expect(sql).toContain('MCP_ANALYTICS');
		expect(sql).toContain('blob9'); // session hash
		expect(sql).toContain('SUM(_sample_interval)');
		expect(sql).toContain("INTERVAL '1' DAY");
	});

	it('queryToolPopularity accepts custom interval', () => {
		const sql = queryToolPopularity('7');
		expect(sql).toContain("INTERVAL '7' DAY");
		expect(sql).toContain("index1 = 'tool_call'");
	});

	it('queryErrorRate returns rate calculation', () => {
		const sql = queryErrorRate('1');
		expect(sql).toContain("blob3 = 'error'");
		expect(sql).toContain('tool_call');
	});

	it('queryLatencyPercentiles uses quantile function', () => {
		const sql = queryLatencyPercentiles('1');
		expect(sql).toMatch(/quantile/i);
	});

	it('queryClientBreakdown groups by blob7', () => {
		const sql = queryClientBreakdown('1');
		expect(sql).toContain('blob7'); // client type
	});

	it('queryGeoDistribution groups by blob6', () => {
		const sql = queryGeoDistribution('1');
		expect(sql).toContain('blob6'); // country
	});

	it('queryRateLimitHits filters rate_limit index', () => {
		const sql = queryRateLimitHits('1');
		expect(sql).toContain("index1 = 'rate_limit'");
	});

	it('sanitizes interval parameter to prevent injection', () => {
		const sql = queryDailyActiveUsers("1'; DROP TABLE --");
		expect(sql).toContain("INTERVAL '1' DAY");
		expect(sql).not.toContain('DROP');
	});

	it('queryTierBreakdown reads blob8 from mcp_request events', () => {
		const sql = queryTierBreakdown('7');
		expect(sql).toContain("index1 = 'mcp_request'");
		expect(sql).toContain('blob8 AS tier');
		expect(sql).toContain("INTERVAL '7' DAY");
		expect(sql).toContain('SUM(_sample_interval)');
	});

	it('queryRecentAnomalies returns error rate and p95 for tool_call events', () => {
		const sql = queryRecentAnomalies('15');
		expect(sql).toContain("index1 = 'tool_call'");
		expect(sql).toContain("blob3 = 'error'");
		expect(sql).toContain('error_pct');
		expect(sql).toContain('p95_ms');
		expect(sql).toContain("INTERVAL '15' MINUTE");
		expect(sql).toContain('GREATEST');
	});

	it('queryRecentAnomalies sanitizes minutes parameter', () => {
		const sql = queryRecentAnomalies("10'; DROP TABLE --");
		expect(sql).toContain("INTERVAL '10' MINUTE");
		expect(sql).not.toContain('DROP');
	});

	it('queryRecentAnomalies stays unchanged (no colo grouping leaks into the global aggregate query)', () => {
		// Append-only guard: the global anomaly query must NOT start grouping by colo —
		// it remains the global p95/error-rate aggregate. Per-colo lives in its own variant.
		const sql = queryRecentAnomalies('15');
		expect(sql).not.toContain('blob11');
		expect(sql).not.toMatch(/GROUP BY\s+colo/);
	});

	it('queryRecentAnomaliesByColo groups error rate + p95 by edge colo (blob11)', () => {
		const sql = queryRecentAnomaliesByColo('15');
		expect(sql).toContain("index1 = 'tool_call'");
		expect(sql).toContain('blob11 AS colo');
		expect(sql).toContain("blob11 != 'unknown'");
		expect(sql).toContain('GROUP BY colo');
		expect(sql).toContain('error_pct');
		expect(sql).toContain('p95_ms');
		expect(sql).toContain("INTERVAL '15' MINUTE");
		expect(sql).toContain('GREATEST');
	});

	it('queryRecentAnomaliesByColo sanitizes minutes parameter', () => {
		const sql = queryRecentAnomaliesByColo("10'; DROP TABLE --");
		expect(sql).toContain("INTERVAL '10' MINUTE");
		expect(sql).not.toContain('DROP');
	});

	it('queryRateLimitSurge returns total hits for rate_limit events', () => {
		const sql = queryRateLimitSurge('15');
		expect(sql).toContain("index1 = 'rate_limit'");
		expect(sql).toContain('total_hits');
		expect(sql).toContain("INTERVAL '15' MINUTE");
	});

	it('queryRateLimitSurge sanitizes minutes parameter', () => {
		const sql = queryRateLimitSurge('abc');
		expect(sql).toContain("INTERVAL '1' MINUTE");
	});

	it('queryBindingDegradation counts present-binding degradation events, excluding kv_fallback', () => {
		const sql = queryBindingDegradation('15');
		expect(sql).toContain("index1 = 'degradation'");
		expect(sql).toContain("blob1 != 'kv_fallback'");
		expect(sql).toContain('blob2 AS component');
		expect(sql).toContain('blob1 AS degradation_type');
		expect(sql).toContain('event_count');
		expect(sql).toContain("INTERVAL '15' MINUTE");
	});

	it('queryBindingDegradation sanitizes minutes parameter', () => {
		const sql = queryBindingDegradation("10'; DROP TABLE --");
		expect(sql).toContain("INTERVAL '10' MINUTE");
		expect(sql).not.toContain('DROP TABLE');
	});

	it('queryQueueFailures aggregates queue_batch errors + failure counts per handler', () => {
		const sql = queryQueueFailures('15');
		expect(sql).toContain("index1 = 'queue_batch'");
		expect(sql).toContain('blob1 AS handler');
		expect(sql).toContain('error_batch_count');
		expect(sql).toContain('failure_count');
		// double2 carries the per-batch failure count.
		expect(sql).toContain('double2');
		// Only surface handlers that actually saw a failure.
		expect(sql).toContain('HAVING error_batch_count > 0 OR failure_count > 0');
		expect(sql).toContain("INTERVAL '15' MINUTE");
	});

	it('queryQueueFailures sanitizes minutes parameter', () => {
		const sql = queryQueueFailures("10'; DROP TABLE --");
		expect(sql).toContain("INTERVAL '10' MINUTE");
		expect(sql).not.toContain('DROP TABLE');
	});
});

describe('per-tier analytics query builders', () => {
	it('queryTierToolUsage groups by tier when no tier specified', () => {
		const sql = queryTierToolUsage('7');
		expect(sql).toContain("index1 = 'tool_call'");
		expect(sql).toContain('blob7 AS tier');
		expect(sql).toContain("INTERVAL '7' DAY");
		expect(sql).not.toContain("blob7 = '");
	});

	it('queryTierToolUsage filters by tier when specified', () => {
		const sql = queryTierToolUsage('7', 'developer');
		expect(sql).toContain("blob7 = 'developer'");
		expect(sql).not.toContain('blob7 AS tier');
	});

	it('queryTierToolUsage sanitizes tier parameter', () => {
		const sql = queryTierToolUsage('7', "developer'; DROP TABLE --");
		expect(sql).not.toContain('DROP');
		expect(sql).not.toContain('TABLE');
	});

	it('queryTierLatency includes percentile functions', () => {
		const sql = queryTierLatency('7');
		expect(sql).toMatch(/quantile/i);
		expect(sql).toContain('p50_ms');
		expect(sql).toContain('p95_ms');
	});

	it('queryTierErrorRate calculates error percentage', () => {
		const sql = queryTierErrorRate('7');
		expect(sql).toContain("blob3 = 'error'");
		expect(sql).toContain('error_pct');
		expect(sql).toContain('GREATEST');
	});

	it('queryTierCachePerformance groups by cache status', () => {
		const sql = queryTierCachePerformance('7');
		expect(sql).toContain('cache_status');
		expect(sql).toContain('call_count');
	});

	it('queryTierRateLimits reads rate_limit events', () => {
		const sql = queryTierRateLimits('7');
		expect(sql).toContain("index1 = 'rate_limit'");
	});

	it('queryTierSessions reads session events', () => {
		const sql = queryTierSessions('7');
		expect(sql).toContain("index1 = 'session'");
	});

	it('queryTierDailyTrend groups by date', () => {
		const sql = queryTierDailyTrend('7');
		expect(sql).toContain('toStartOfDay');
		expect(sql).toContain('day');
	});

	it('queryTierTopTools groups by tier and tool', () => {
		const sql = queryTierTopTools('24');
		expect(sql).toContain('blob7 AS tier');
		expect(sql).toContain('blob1 AS tool_name');
		expect(sql).toContain("INTERVAL '24' HOUR");
	});

	it('queryKeyUsage groups by key hash prefix', () => {
		const sql = queryKeyUsage('7');
		expect(sql).toContain('blob9 AS key_hash');
		expect(sql).toContain("index1 = 'tool_call'");
	});

	it('queryKeyUsage filters by specific key hash', () => {
		const sql = queryKeyUsage('7', 'abc123');
		expect(sql).toContain("blob9 = 'abc123'");
	});

	it('queryTierDigest returns per-tier summary', () => {
		const sql = queryTierDigest('24');
		expect(sql).toContain('blob7 AS tier');
		expect(sql).toContain('total_calls');
		expect(sql).toContain('error_pct');
		expect(sql).toContain("INTERVAL '24' HOUR");
	});

	it('tier queries sanitize days parameter', () => {
		const sql = queryTierToolUsage("1'; DROP TABLE --");
		expect(sql).toContain("INTERVAL '1' DAY");
		expect(sql).not.toContain('DROP');
	});
});
