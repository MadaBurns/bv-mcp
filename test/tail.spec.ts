// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, vi } from 'vitest';

function mockDataset() {
	return { writeDataPoint: vi.fn() };
}

/** Minimal synthetic TraceItem — only the fields the tail handler reads. */
function traceItem(opts: { outcome: string; scriptName?: string | null; colo?: string; exceptions?: number }): TraceItem {
	return {
		event:
			opts.colo !== undefined
				? ({ request: { cf: { colo: opts.colo }, headers: {}, method: 'POST', url: 'https://x/mcp' } } as unknown)
				: null,
		eventTimestamp: Date.now(),
		logs: [],
		exceptions: Array.from({ length: opts.exceptions ?? 0 }, (_, i) => ({
			timestamp: Date.now(),
			message: `boom ${i}`,
			name: 'Error',
		})),
		diagnosticsChannelEvents: [],
		scriptName: opts.scriptName === undefined ? 'bv-dns-security-mcp' : opts.scriptName,
		outcome: opts.outcome,
		executionModel: 'stateless',
		truncated: false,
		cpuTime: 1,
		wallTime: 1,
	} as unknown as TraceItem;
}

describe('aggregateTraceItems', () => {
	it('folds invocations into one bucket per colo+outcome+scriptName and counts exceptions', async () => {
		const { aggregateTraceItems } = await import('../src/tail');
		const buckets = aggregateTraceItems([
			traceItem({ outcome: 'ok', colo: 'AKL' }),
			traceItem({ outcome: 'ok', colo: 'AKL' }),
			traceItem({ outcome: 'exception', colo: 'AKL', exceptions: 1 }),
			traceItem({ outcome: 'ok', colo: 'SYD' }),
		]);

		expect(buckets).toHaveLength(3);
		const ok = buckets.find((b) => b.colo === 'AKL' && b.outcome === 'ok')!;
		expect(ok.invocations).toBe(2);
		expect(ok.exceptions).toBe(0);

		const exc = buckets.find((b) => b.outcome === 'exception')!;
		expect(exc.colo).toBe('AKL');
		expect(exc.invocations).toBe(1);
		expect(exc.exceptions).toBe(1);
	});

	it('falls back to unknown colo/scriptName when absent', async () => {
		const { aggregateTraceItems } = await import('../src/tail');
		const [bucket] = aggregateTraceItems([traceItem({ outcome: 'ok', scriptName: null })]);
		expect(bucket.colo).toBe('unknown');
		expect(bucket.scriptName).toBe('unknown');
	});
});

describe('handleTail', () => {
	it('writes one aggregated AE row per bucket capturing exceptions', async () => {
		const { handleTail } = await import('../src/tail');
		const ds = mockDataset();

		handleTail(
			[
				traceItem({ outcome: 'ok', colo: 'AKL' }),
				traceItem({ outcome: 'ok', colo: 'AKL' }),
				traceItem({ outcome: 'exception', colo: 'AKL', exceptions: 2 }),
			],
			{ MCP_ANALYTICS: ds as unknown as AnalyticsEngineDataset },
		);

		// Two distinct buckets (AKL/ok and AKL/exception) → two AE rows.
		expect(ds.writeDataPoint).toHaveBeenCalledTimes(2);
		const points = ds.writeDataPoint.mock.calls.map((c) => c[0]);
		for (const point of points) {
			expect(point.indexes).toEqual(['tail']);
		}

		const okPoint = points.find((p) => p.blobs[1] === 'ok')!;
		// blob1=colo, blob2=outcome, blob3=scriptName; colo mirrored into blob6.
		expect(okPoint.blobs[0]).toBe('akl');
		expect(okPoint.blobs[2]).toBe('bv-dns-security-mcp');
		expect(okPoint.blobs[5]).toBe('akl');
		// double1=invocations, double2=exceptions.
		expect(okPoint.doubles).toEqual([2, 0]);

		const excPoint = points.find((p) => p.blobs[1] === 'exception')!;
		expect(excPoint.doubles).toEqual([1, 1]);
	});

	it('is a no-op when the analytics binding is absent', async () => {
		const { handleTail } = await import('../src/tail');
		// Must not throw when MCP_ANALYTICS is undefined.
		expect(() => handleTail([traceItem({ outcome: 'ok', colo: 'AKL' })], {})).not.toThrow();
	});

	it('never throws on a malformed trace batch (fail-open)', async () => {
		const { handleTail } = await import('../src/tail');
		const ds = mockDataset();
		expect(() =>
			handleTail([null as unknown as TraceItem, undefined as unknown as TraceItem], {
				MCP_ANALYTICS: ds as unknown as AnalyticsEngineDataset,
			}),
		).not.toThrow();
	});
});
