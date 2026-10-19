// SPDX-License-Identifier: BUSL-1.1

/**
 * SQ-214 emit: `emitUngradedNotCachedEvent` writes one `scan_ungraded` data point.
 * Asserts the writeDataPoint call shape (an emit, not an AE SQL query): index, blob order,
 * the hashed (never raw) domain, and the `?? 'unknown' / 'anon'` fallbacks.
 */

import { describe, it, expect, vi } from 'vitest';

describe('emitUngradedNotCachedEvent', () => {
	it('writes the scan_ungraded point with a hashed domain and the supplied context', async () => {
		const { createAnalyticsClient, hashDomain } = await import('../src/lib/analytics');
		const ds = { writeDataPoint: vi.fn() };
		const client = createAnalyticsClient(ds);

		client.emitUngradedNotCachedEvent({
			domain: 'example.com',
			repeat: true,
			country: 'NZ',
			clientType: 'claude_code',
			authTier: 'owner',
		});

		expect(ds.writeDataPoint).toHaveBeenCalledTimes(1);
		const point = ds.writeDataPoint.mock.calls[0][0] as { indexes: string[]; blobs: string[] };
		expect(point.indexes).toEqual(['scan_ungraded']);
		expect(point.blobs).toEqual(['ungraded_not_cached', hashDomain('example.com'), 'repeat', 'NZ', 'claude_code', 'owner']);
		// The raw domain must never reach the dataset.
		expect(JSON.stringify(point)).not.toContain('example.com');
	});

	it('marks a first occurrence and falls back to unknown/anon when context is absent', async () => {
		const { createAnalyticsClient, hashDomain } = await import('../src/lib/analytics');
		const ds = { writeDataPoint: vi.fn() };
		const client = createAnalyticsClient(ds);

		client.emitUngradedNotCachedEvent({ domain: 'example.org', repeat: false });

		const point = ds.writeDataPoint.mock.calls[0][0] as { indexes: string[]; blobs: string[] };
		expect(point.indexes).toEqual(['scan_ungraded']);
		expect(point.blobs).toEqual(['ungraded_not_cached', hashDomain('example.org'), 'first', 'unknown', 'unknown', 'anon']);
	});

	it('is a no-op when no dataset is configured', async () => {
		const { createAnalyticsClient } = await import('../src/lib/analytics');
		const client = createAnalyticsClient();
		expect(() => client.emitUngradedNotCachedEvent({ domain: 'example.com', repeat: false })).not.toThrow();
	});
});
