// SPDX-License-Identifier: BUSL-1.1

import { sseEvent } from './sse';

interface LegacyStreamRecord {
	controller?: ReadableStreamDefaultController<Uint8Array>;
	queue: string[];
	heartbeat?: number;
	createdAt: number;
}

const LEGACY_STREAMS = new Map<string, LegacyStreamRecord>();
const HEARTBEAT_INTERVAL_MS = 5_000;

/** Maximum number of concurrent legacy SSE stream records before eviction kicks in. */
export const MAX_LEGACY_STREAMS = 500;

function endpointEvent(endpointUrl: string): string {
	return `event: endpoint\ndata: ${endpointUrl}\n\n`;
}

/** Check whether a record is a zombie (no active controller and empty queue). */
function isZombie(record: LegacyStreamRecord): boolean {
	return !record.controller && record.queue.length === 0;
}

/**
 * Evict entries when the map exceeds MAX_LEGACY_STREAMS.
 * Strategy: remove zombie entries (no controller, empty queue) first,
 * then evict the oldest by createdAt if still over capacity.
 */
function evictIfNeeded(): void {
	if (LEGACY_STREAMS.size < MAX_LEGACY_STREAMS) return;

	// Phase 1: remove zombie entries
	for (const [id, record] of LEGACY_STREAMS.entries()) {
		if (isZombie(record)) {
			LEGACY_STREAMS.delete(id);
			if (LEGACY_STREAMS.size < MAX_LEGACY_STREAMS) return;
		}
	}

	// Phase 2: evict oldest by createdAt
	while (LEGACY_STREAMS.size >= MAX_LEGACY_STREAMS) {
		let oldestId: string | undefined;
		let oldestTime = Number.POSITIVE_INFINITY;
		for (const [id, record] of LEGACY_STREAMS.entries()) {
			if (record.createdAt < oldestTime) {
				oldestTime = record.createdAt;
				oldestId = id;
			}
		}
		if (oldestId) {
			// Close the stream before evicting to clean up heartbeat interval
			const evictedRecord = LEGACY_STREAMS.get(oldestId);
			if (evictedRecord) {
				if (evictedRecord.heartbeat !== undefined) {
					clearInterval(evictedRecord.heartbeat);
				}
				if (evictedRecord.controller) {
					try {
						evictedRecord.controller.close();
					} catch {
						// ignore closed stream errors
					}
				}
			}
			LEGACY_STREAMS.delete(oldestId);
		} else {
			break;
		}
	}
}

function getOrCreateRecord(sessionId: string): LegacyStreamRecord {
	const existing = LEGACY_STREAMS.get(sessionId);
	if (existing) return existing;
	// Evict before adding so the new entry isn't considered a zombie
	// (its controller isn't set until the ReadableStream start() callback fires)
	evictIfNeeded();
	const created: LegacyStreamRecord = { queue: [], createdAt: Date.now() };
	LEGACY_STREAMS.set(sessionId, created);
	return created;
}

export function resetLegacySseState(): void {
	for (const sessionId of LEGACY_STREAMS.keys()) {
		closeLegacyStream(sessionId);
	}
	LEGACY_STREAMS.clear();
}

/** Get the current number of entries in the LEGACY_STREAMS map (test helper). */
export function getLegacyStreamCount(): number {
	return LEGACY_STREAMS.size;
}

/** Get a stream record by session ID (test helper). */
export function getLegacyStreamRecord(sessionId: string): LegacyStreamRecord | undefined {
	return LEGACY_STREAMS.get(sessionId);
}

/** Inject a stream record directly (test helper — bypasses normal creation flow). */
export function setLegacyStreamRecordForTest(sessionId: string, record: Omit<LegacyStreamRecord, 'heartbeat'>): void {
	LEGACY_STREAMS.set(sessionId, { ...record, heartbeat: undefined });
}

export function openLegacySseStream(sessionId: string, endpointUrl: string): Response {
	const encoder = new TextEncoder();
	const record = getOrCreateRecord(sessionId);

	const stream = new ReadableStream<Uint8Array>({
		start(controller) {
			record.controller = controller;
			controller.enqueue(encoder.encode(endpointEvent(endpointUrl)));
			for (const queuedEvent of record.queue) {
				controller.enqueue(encoder.encode(queuedEvent));
			}
			record.queue = [];
			record.heartbeat = setInterval(() => {
				try {
					controller.enqueue(encoder.encode(': heartbeat\n\n'));
				} catch {
					closeLegacyStream(sessionId);
				}
			}, HEARTBEAT_INTERVAL_MS) as unknown as number;
		},
		cancel() {
			closeLegacyStream(sessionId, false);
		},
	});

	return new Response(stream, {
		status: 200,
		headers: {
			'Content-Type': 'text/event-stream',
			'Cache-Control': 'no-cache',
			'mcp-session-id': sessionId,
		},
	});
}

export function enqueueLegacyMessage(sessionId: string, payload: unknown): boolean {
	const record = LEGACY_STREAMS.get(sessionId);
	if (!record) return false;

	const event = sseEvent(payload);
	if (record.controller) {
		record.controller.enqueue(new TextEncoder().encode(event));
	} else {
		record.queue.push(event);
	}

	return true;
}

export function closeLegacyStream(sessionId: string, deleteRecord = true): void {
	const record = LEGACY_STREAMS.get(sessionId);
	if (!record) return;

	if (record.heartbeat !== undefined) {
		clearInterval(record.heartbeat);
	}
	if (record.controller) {
		try {
			record.controller.close();
		} catch {
			// ignore closed stream errors
		}
	}
	record.controller = undefined;
	record.queue = [];
	if (deleteRecord) {
		LEGACY_STREAMS.delete(sessionId);
	} else {
		// When not deleting the record, clean up zombies (no controller, empty queue)
		// to prevent accumulation of dead entries from abrupt client disconnects
		if (isZombie(record)) {
			LEGACY_STREAMS.delete(sessionId);
		}
	}
}
