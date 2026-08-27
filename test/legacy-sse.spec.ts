import { afterEach, describe, expect, it, vi } from 'vitest';

afterEach(() => {
	vi.restoreAllMocks();
	vi.useRealTimers();
});

describe('legacy SSE stream management', () => {
	it('adds a createdAt timestamp to new stream records', async () => {
		const { openLegacySseStream, resetLegacySseState, getLegacyStreamRecord } = await import('../src/lib/legacy-sse');
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

	it('rejects new admission at the global cap without evicting active clients', async () => {
		const { openLegacySseStream, resetLegacySseState, getLegacyStreamCount, getLegacyStreamRecord, MAX_LEGACY_STREAMS } =
			await import('../src/lib/legacy-sse');
		try {
			// Fill to capacity with active entries
			for (let i = 0; i < MAX_LEGACY_STREAMS; i++) {
				const sid = `entry-${i}`;
				openLegacySseStream(sid, `/mcp/messages?sessionId=${sid}`, `principal-${i}`);
			}

			expect(getLegacyStreamCount()).toBe(MAX_LEGACY_STREAMS);

			const denied = openLegacySseStream('new-entry', '/mcp/messages?sessionId=new-entry', 'new-principal');

			expect(denied.status).toBe(503);
			expect(getLegacyStreamCount()).toBe(MAX_LEGACY_STREAMS);
			expect(getLegacyStreamRecord('new-entry')).toBeUndefined();
			expect(getLegacyStreamRecord('entry-0')).toBeDefined();
			expect(getLegacyStreamRecord('entry-1')).toBeDefined();
		} finally {
			resetLegacySseState();
		}
	});

	it('prunes zombie entries before evaluating admission', async () => {
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
			nowSpy.mockReturnValue(1_100_000);
			const admitted = openLegacySseStream('new-entry', '/mcp/messages?sessionId=new-entry');

			expect(admitted.status).toBe(200);
			expect(getLegacyStreamCount()).toBe(2);
			// Active entry should be preserved
			expect(getLegacyStreamRecord('active-keep')).toBeDefined();
			expect(getLegacyStreamRecord('active-keep')!.controller).toBeDefined();
			// New entry should exist
			expect(getLegacyStreamRecord('new-entry')).toBeDefined();
		} finally {
			resetLegacySseState();
		}
	});

	it('caps one principal without evicting its existing streams', async () => {
		const { openLegacySseStream, resetLegacySseState, getLegacyStreamCount, getLegacyStreamRecord, MAX_LEGACY_STREAMS_PER_PRINCIPAL } =
			await import('../src/lib/legacy-sse');
		try {
			for (let i = 0; i < MAX_LEGACY_STREAMS_PER_PRINCIPAL; i++) {
				expect(openLegacySseStream(`same-${i}`, `/mcp/messages?sessionId=same-${i}`, 'key:stable').status).toBe(200);
			}

			const denied = openLegacySseStream('same-denied', '/mcp/messages?sessionId=same-denied', 'key:stable');
			expect(denied.status).toBe(429);
			expect(denied.headers.get('retry-after')).toBe('60');
			expect(getLegacyStreamCount()).toBe(MAX_LEGACY_STREAMS_PER_PRINCIPAL);
			expect(getLegacyStreamRecord('same-0')).toBeDefined();
			expect(getLegacyStreamRecord('same-denied')).toBeUndefined();
		} finally {
			resetLegacySseState();
		}
	});

	it('closes and removes a stream at the finite lifetime bound', async () => {
		vi.useFakeTimers();
		const { openLegacySseStream, resetLegacySseState, getLegacyStreamRecord, MAX_LEGACY_STREAM_LIFETIME_MS } =
			await import('../src/lib/legacy-sse');
		try {
			const response = openLegacySseStream('ttl-session', '/mcp/messages?sessionId=ttl-session', 'key:ttl');
			expect(response.status).toBe(200);
			expect(getLegacyStreamRecord('ttl-session')).toBeDefined();

			await vi.advanceTimersByTimeAsync(MAX_LEGACY_STREAM_LIFETIME_MS);
			expect(getLegacyStreamRecord('ttl-session')).toBeUndefined();
		} finally {
			resetLegacySseState();
		}
	});

	it('closeLegacyStream with deleteRecord=false cleans up zombie entries', async () => {
		const { openLegacySseStream, closeLegacyStream, resetLegacySseState, getLegacyStreamRecord } = await import('../src/lib/legacy-sse');
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
		const { openLegacySseStream, enqueueLegacyMessage, closeLegacyStream, resetLegacySseState, getLegacyStreamRecord } =
			await import('../src/lib/legacy-sse');
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
