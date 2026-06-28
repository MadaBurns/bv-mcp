import { afterEach, describe, expect, it, vi } from 'vitest';
afterEach(() => vi.restoreAllMocks());

describe('emitToolEvent geo blobs', () => {
	it('appends region/city/asn as trailing blobs (positions 13-15), leaving 1-12 unchanged', async () => {
		const { createAnalyticsClient } = await import('../src/lib/analytics');
		const writes: { blobs?: string[] }[] = [];
		const client = createAnalyticsClient({ writeDataPoint: (p) => writes.push(p) });
		client.emitToolEvent({
			toolName: 'check_spf',
			status: 'pass',
			durationMs: 3,
			isError: false,
			region: 'Auckland',
			city: 'Auckland',
			asn: 13335,
		} as Parameters<typeof client.emitToolEvent>[0]);
		const blobs = writes[0].blobs!;
		expect(blobs[0]).toBe('check_spf'); // position 1 unchanged
		expect(blobs[12]).toBe('auckland'); // blob13 region (normalized)
		expect(blobs[13]).toBe('auckland'); // blob14 city
		expect(blobs[14]).toBe('13335'); // blob15 asn
	});
});
