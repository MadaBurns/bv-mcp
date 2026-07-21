// SPDX-License-Identifier: BUSL-1.1

/**
 * Regression guard: the Analytics Engine query builders must target the DATASET
 * name (`bv_dns_security_mcp`), never the Worker BINDING name (`MCP_ANALYTICS`).
 *
 * Background (empirically confirmed against the live account): AE's SQL API
 * queries by dataset name, not by Worker binding name. The binding `MCP_ANALYTICS`
 * maps to `dataset: "bv_dns_security_mcp"` in prod. A query of `FROM MCP_ANALYTICS`
 * returns 0 rows silently — which made every cron alert and `/internal/analytics/*`
 * endpoint blind. This test locks out a regression to the binding-name literal.
 *
 * CI-safe: the prod dataset name lives in a GITIGNORED wrangler overlay that is
 * ABSENT in CI, so we assert against the in-code DEFAULT, not any wrangler file.
 */

import { describe, it, expect } from 'vitest';
import * as Q from '../../src/lib/analytics-queries';
import { DEFAULT_ANALYTICS_DATASET, resolveAnalyticsDataset } from '../../src/lib/analytics-queries';

describe('analytics dataset name (regression guard)', () => {
	it('default dataset constant is the AE dataset name, not the binding name', () => {
		expect(DEFAULT_ANALYTICS_DATASET).toBe('bv_dns_security_mcp');
		expect(DEFAULT_ANALYTICS_DATASET).not.toBe('MCP_ANALYTICS');
	});

	// Every query builder: calling with just the time window must produce SQL that
	// reads FROM the dataset name and NEVER the binding name.
	const builders: Array<[string, () => string]> = [
		['queryDailyActiveUsers', () => Q.queryDailyActiveUsers('1')],
		['queryToolPopularity', () => Q.queryToolPopularity('1')],
		['queryErrorRate', () => Q.queryErrorRate('1')],
		['queryLatencyPercentiles', () => Q.queryLatencyPercentiles('1')],
		['queryClientBreakdown', () => Q.queryClientBreakdown('1')],
		['queryGeoDistribution', () => Q.queryGeoDistribution('1')],
		['queryGeoRollup', () => Q.queryGeoRollup('1')],
		['queryRateLimitHits', () => Q.queryRateLimitHits('1')],
		['queryTierBreakdown', () => Q.queryTierBreakdown('1')],
		['queryRecentAnomalies', () => Q.queryRecentAnomalies('15')],
		['queryRecentAnomaliesByColo', () => Q.queryRecentAnomaliesByColo('15')],
		['queryRateLimitSurge', () => Q.queryRateLimitSurge('15')],
		['queryBindingDegradation', () => Q.queryBindingDegradation('15')],
		['queryQuotaShardSkew', () => Q.queryQuotaShardSkew('15')],
		['queryQueueFailures', () => Q.queryQueueFailures('15')],
		['queryTailExceptions', () => Q.queryTailExceptions('15')],
		['queryTierToolUsage', () => Q.queryTierToolUsage('1')],
		['queryTierLatency', () => Q.queryTierLatency('1')],
		['queryTierErrorRate', () => Q.queryTierErrorRate('1')],
		['queryTierCachePerformance', () => Q.queryTierCachePerformance('1')],
		['queryTierRateLimits', () => Q.queryTierRateLimits('1')],
		['queryTierSessions', () => Q.queryTierSessions('1')],
		['queryTierDomainDiversity', () => Q.queryTierDomainDiversity('1')],
		['queryTierScoreDistribution', () => Q.queryTierScoreDistribution('1')],
		['queryTierDailyTrend', () => Q.queryTierDailyTrend('1')],
		['queryTierClientTypes', () => Q.queryTierClientTypes('1')],
		['queryKeyUsage', () => Q.queryKeyUsage('1')],
		['queryTierDigest', () => Q.queryTierDigest('24')],
		['queryTierTopTools', () => Q.queryTierTopTools('24')],
	];

	for (const [name, build] of builders) {
		it(`${name} emits FROM ${DEFAULT_ANALYTICS_DATASET} and never FROM MCP_ANALYTICS`, () => {
			const sql = build();
			expect(sql).toContain(`FROM ${DEFAULT_ANALYTICS_DATASET}`);
			expect(sql).not.toContain('FROM MCP_ANALYTICS');
			expect(sql).not.toContain('MCP_ANALYTICS');
		});
	}

	it('accepts a validated env override for the dataset name', () => {
		const sql = Q.queryRecentAnomalies('15', 'bv_mcp_usage_reporting');
		expect(sql).toContain('FROM bv_mcp_usage_reporting');
		expect(sql).not.toContain('MCP_ANALYTICS');
	});

	it('rejects an injection-shaped override and falls back to the default (defense-in-depth)', () => {
		const evil = "bv_mcp'; DROP TABLE users; --";
		expect(resolveAnalyticsDataset(evil)).toBe(DEFAULT_ANALYTICS_DATASET);
		const sql = Q.queryRecentAnomalies('15', evil);
		expect(sql).toContain(`FROM ${DEFAULT_ANALYTICS_DATASET}`);
		expect(sql).not.toContain('DROP');
	});

	it('resolveAnalyticsDataset returns the default for undefined/empty/invalid', () => {
		expect(resolveAnalyticsDataset(undefined)).toBe(DEFAULT_ANALYTICS_DATASET);
		expect(resolveAnalyticsDataset('')).toBe(DEFAULT_ANALYTICS_DATASET);
		expect(resolveAnalyticsDataset('Bad-Name!')).toBe(DEFAULT_ANALYTICS_DATASET);
	});
});
