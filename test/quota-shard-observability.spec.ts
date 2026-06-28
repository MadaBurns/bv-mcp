// SPDX-License-Identifier: BUSL-1.1

/**
 * Phase 3 (decisions #3 + #4): R8 per-shard observability + the salt-missing config
 * guard.
 *
 *  - `emitQuotaShardEvent` writes a low-cardinality `quota_shard` AE row carrying the
 *    resolved shard index (skew detection via `queryQuotaShardSkew`).
 *  - `isQuotaShardSaltMissing` flags the misconfiguration (sharding ON, salt unset) so
 *    the caller can emit a `quota_shard_salt_missing` degradation event.
 *  - `queryBindingDegradation` does NOT swallow that member; `queryQuotaShardSkew`
 *    aggregates per-shard load into max/mean/ratio.
 */
import { describe, it, expect, vi } from 'vitest';
import { createAnalyticsClient } from '../src/lib/analytics';
import { isQuotaShardSaltMissing, type ShardRouting } from '../src/lib/quota-coordinator';
import { queryQuotaShardSkew, queryBindingDegradation } from '../src/lib/analytics-queries';

function mockDataset() {
	return { writeDataPoint: vi.fn() };
}

describe('isQuotaShardSaltMissing (decision #4)', () => {
	it('is true only when sharding is ENABLED and the salt is empty', () => {
		expect(isQuotaShardSaltMissing({ enabled: true, salt: '' })).toBe(true);
	});

	it('is false when sharding is enabled WITH a salt', () => {
		expect(isQuotaShardSaltMissing({ enabled: true, salt: 'deploy-secret' })).toBe(false);
	});

	it('is false when sharding is disabled (salt irrelevant)', () => {
		const off: ShardRouting = { enabled: false, salt: '' };
		expect(isQuotaShardSaltMissing(off)).toBe(false);
		expect(isQuotaShardSaltMissing({ enabled: false, salt: 'x' })).toBe(false);
	});
});

describe('emitQuotaShardEvent (decision #3)', () => {
	it('writes a quota_shard row with the shard index in blob1', () => {
		const ds = mockDataset();
		const client = createAnalyticsClient(ds);
		client.emitQuotaShardEvent({ shardIndex: 7, country: 'NZ', authTier: 'developer' });
		expect(ds.writeDataPoint).toHaveBeenCalledOnce();
		const point = ds.writeDataPoint.mock.calls[0][0];
		expect(point.indexes).toEqual(['quota_shard']);
		expect(point.blobs[0]).toBe('7');
		expect(point.blobs[1]).toBe('NZ');
		expect(point.blobs[2]).toBe('developer');
	});

	it('keeps the shard index a low-cardinality integer string (truncates / clamps)', () => {
		const ds = mockDataset();
		const client = createAnalyticsClient(ds);
		client.emitQuotaShardEvent({ shardIndex: 3.9 });
		client.emitQuotaShardEvent({ shardIndex: -1 });
		client.emitQuotaShardEvent({ shardIndex: Number.NaN });
		expect(ds.writeDataPoint.mock.calls[0][0].blobs[0]).toBe('3');
		expect(ds.writeDataPoint.mock.calls[1][0].blobs[0]).toBe('0');
		expect(ds.writeDataPoint.mock.calls[2][0].blobs[0]).toBe('0');
	});

	it('is a no-op (never throws) when no dataset is configured', () => {
		const client = createAnalyticsClient(undefined);
		expect(client.enabled).toBe(false);
		expect(() => client.emitQuotaShardEvent({ shardIndex: 1 })).not.toThrow();
	});
});

describe('quota_shard_salt_missing degradation member', () => {
	it('emits the new member to blob1 (queryable, not swallowed)', () => {
		const ds = mockDataset();
		const client = createAnalyticsClient(ds);
		client.emitDegradationEvent({ degradationType: 'quota_shard_salt_missing', component: 'quota_coordinator' });
		const point = ds.writeDataPoint.mock.calls[0][0];
		expect(point.indexes).toEqual(['degradation']);
		expect(point.blobs[0]).toBe('quota_shard_salt_missing');
		expect(point.blobs[1]).toBe('quota_coordinator');
	});
});

describe('analytics-queries — quota shard skew + degradation exclusion', () => {
	it('queryQuotaShardSkew aggregates per-shard load into max/mean/ratio', () => {
		const sql = queryQuotaShardSkew('60');
		expect(sql).toContain('MCP_ANALYTICS');
		expect(sql).toContain("index1 = 'quota_shard'");
		expect(sql).toContain('max_shard_load');
		expect(sql).toContain('mean_shard_load');
		expect(sql).toContain('skew_ratio');
		expect(sql).toContain('GROUP BY shard');
		expect(sql).toContain("INTERVAL '60' MINUTE");
	});

	it('queryQuotaShardSkew sanitizes a non-numeric interval', () => {
		const sql = queryQuotaShardSkew('"; DROP TABLE x; --');
		expect(sql).toContain("INTERVAL '1' MINUTE");
		expect(sql).not.toContain('DROP TABLE');
	});

	it('queryBindingDegradation excludes the salt-missing member (config noise, not a binding failure)', () => {
		const sql = queryBindingDegradation('15');
		expect(sql).toContain("blob1 != 'quota_shard_salt_missing'");
		expect(sql).toContain("blob1 != 'kv_fallback'");
		expect(sql).toContain("blob1 != 'quota_coordinator_fallback'");
	});
});
