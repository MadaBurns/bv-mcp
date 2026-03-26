import { afterEach, describe, expect, it, vi } from 'vitest';

afterEach(() => {
	vi.restoreAllMocks();
});

describe('legacy SSE stream management', () => {
	it('adds a createdAt timestamp to new stream records', async () => {
		const { openLegacySseStream, resetLegacySseState, getLegacyStreamRecord } = await import(
			'../src/lib/legacy-sse'
		);
		try {
			const before = Date.now();
			openLegacySseStream('session-ts', '/mcp/messages?sessionId=session-ts');
			const record = getLegacyStreamRecord('session-ts');
			expect(record).toBeDefined();
			expect(record!.createdAt).toBeGreaterThanOrEqual(before);
			expect(record!.createdAt).toBeLessThanOrEqual(Date.now());
		} finally {
			resetLegacySseState();
		}
	});

	it('enforces size cap by evicting oldest entries when at capacity', async () => {
		const {
			openLegacySseStream,
			resetLegacySseState,
			getLegacyStreamCount,
			getLegacyStreamRecord,
			MAX_LEGACY_STREAMS,
		} = await import('../src/lib/legacy-sse');
		try {
			const nowSpy = vi.spyOn(Date, 'now');

			// Fill to capacity with active entries
			for (let i = 0; i < MAX_LEGACY_STREAMS; i++) {
				nowSpy.mockReturnValue(1_000_000 + i * 1000);
				const sid = `entry-${i}`;
				openLegacySseStream(sid, `/mcp/messages?sessionId=${sid}`);
			}

			expect(getLegacyStreamCount()).toBe(MAX_LEGACY_STREAMS);

			// Adding a new entry should evict the oldest (entry-0)
			nowSpy.mockReturnValue(1_000_000 + MAX_LEGACY_STREAMS * 1000);
			openLegacySseStream('new-entry', '/mcp/messages?sessionId=new-entry');

			expect(getLegacyStreamCount()).toBeLessThanOrEqual(MAX_LEGACY_STREAMS);
			expect(getLegacyStreamRecord('new-entry')).toBeDefined();
			expect(getLegacyStreamRecord('new-entry')!.controller).toBeDefined();
			// entry-0 was created earliest and should have been evicted
			expect(getLegacyStreamRecord('entry-0')).toBeUndefined();
			// entry-1 should still be present
			expect(getLegacyStreamRecord('entry-1')).toBeDefined();
		} finally {
			resetLegacySseState();
		}
	});

	it('evicts zombie entries before active entries when at capacity', async () => {
		const {
			openLegacySseStream,
			resetLegacySseState,
			getLegacyStreamCount,
			getLegacyStreamRecord,
			MAX_LEGACY_STREAMS,
			setLegacyStreamRecordForTest,
		} = await import('../src/lib/legacy-sse');
		try {
			const nowSpy = vi.spyOn(Date, 'now');

			// Create one active entry at the start
			nowSpy.mockReturnValue(1_000_000);
			openLegacySseStream('active-keep', '/mcp/messages?sessionId=active-keep');

			// Inject zombie entries directly (simulates accumulated zombies from
			// unclean disconnects that bypassed closeLegacyStream cleanup)
			for (let i = 1; i < MAX_LEGACY_STREAMS; i++) {
				setLegacyStreamRecordForTest(`zombie-${i}`, {
					queue: [],
					createdAt: 1_000_000 + i * 1000,
				});
			}

			expect(getLegacyStreamCount()).toBe(MAX_LEGACY_STREAMS);

			// Adding a new entry should evict a zombie, not the active entry
			nowSpy.mockReturnValue(2_000_000);
			openLegacySseStream('new-entry', '/mcp/messages?sessionId=new-entry');

			expect(getLegacyStreamCount()).toBeLessThanOrEqual(MAX_LEGACY_STREAMS);
			// Active entry should be preserved
			expect(getLegacyStreamRecord('active-keep')).toBeDefined();
			expect(getLegacyStreamRecord('active-keep')!.controller).toBeDefined();
			// New entry should exist
			expect(getLegacyStreamRecord('new-entry')).toBeDefined();
		} finally {
			resetLegacySseState();
		}
	});

	it('closeLegacyStream with deleteRecord=false cleans up zombie entries', async () => {
		const { openLegacySseStream, closeLegacyStream, resetLegacySseState, getLegacyStreamRecord } =
			await import('../src/lib/legacy-sse');
		try {
			// Create a stream, then close it without deleting the record
			openLegacySseStream('zombie-test', '/mcp/messages?sessionId=zombie-test');
			closeLegacyStream('zombie-test', false);

			// The record should be cleaned up since it's a zombie (no controller, empty queue)
			expect(getLegacyStreamRecord('zombie-test')).toBeUndefined();
		} finally {
			resetLegacySseState();
		}
	});

	it('closeLegacyStream with deleteRecord=false keeps entries with queued events', async () => {
		const {
			openLegacySseStream,
			enqueueLegacyMessage,
			closeLegacyStream,
			resetLegacySseState,
			getLegacyStreamRecord,
		} = await import('../src/lib/legacy-sse');
		try {
			// Create a stream and enqueue a message before the controller is set
			// We need to simulate a pre-controller state: create record, add queue item, then close
			openLegacySseStream('queued-test', '/mcp/messages?sessionId=queued-test');
			// Enqueue a message while the controller is active
			enqueueLegacyMessage('queued-test', { jsonrpc: '2.0', id: 1, result: {} });
			// The record has a controller, close it but don't delete
			closeLegacyStream('queued-test', false);

			// After closing, controller is removed and queue is cleared — it's a zombie, so cleaned up
			expect(getLegacyStreamRecord('queued-test')).toBeUndefined();
		} finally {
			resetLegacySseState();
		}
	});
});
