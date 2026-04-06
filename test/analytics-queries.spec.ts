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
	queryRateLimitSurge,
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
});
