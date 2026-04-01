import { describe, it, expect } from 'vitest';
import {
	queryDailyActiveUsers,
	queryToolPopularity,
	queryErrorRate,
	queryLatencyPercentiles,
	queryClientBreakdown,
	queryGeoDistribution,
	queryRateLimitHits,
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
});
