// SPDX-License-Identifier: BUSL-1.1

import { sseEvent } from './sse';

interface LegacyStreamRecord {
	controller?: ReadableStreamDefaultController<Uint8Array>;
	queue: string[];
	heartbeat?: number;
	lifetime?: number;
	createdAt: number;
	principal: string;
}

const LEGACY_STREAMS = new Map<string, LegacyStreamRecord>();
const HEARTBEAT_INTERVAL_MS = 5_000;

/** Hard isolate-wide admission cap. New streams are rejected; active clients are never evicted. */
export const MAX_LEGACY_STREAMS = 500;

/** Bound one caller's concurrent isolate-local footprint even across rate-limit windows. */
export const MAX_LEGACY_STREAMS_PER_PRINCIPAL = 30;

/** Legacy streams cannot retain a heartbeat/controller indefinitely. */
export const MAX_LEGACY_STREAM_LIFETIME_MS = 5 * 60_000;

/** Maximum pre-controller queue depth per stream to prevent memory exhaustion. */
const MAX_LEGACY_QUEUE_DEPTH = 100;

function endpointEvent(endpointUrl: string): string {
	return `event: endpoint\ndata: ${endpointUrl}\n\n`;
}

/** Check whether a record is a zombie (no active controller and empty queue). */
function isZombie(record: LegacyStreamRecord): boolean {
	return !record.controller && record.queue.length === 0;
}

/** Remove dead/expired records before admission; never evict a live peer for a newcomer. */
function pruneLegacyStreams(now = Date.now()): void {
	for (const [id, record] of LEGACY_STREAMS.entries()) {
		if (isZombie(record) || now - record.createdAt >= MAX_LEGACY_STREAM_LIFETIME_MS) {
			closeLegacyStream(id);
		}
	}
}

function countPrincipalStreams(principal: string): number {
	let count = 0;
	for (const record of LEGACY_STREAMS.values()) {
		if (record.principal === principal) count += 1;
	}
	return count;
}

function getOrCreateRecord(sessionId: string, principal: string): LegacyStreamRecord | undefined {
	const existing = LEGACY_STREAMS.get(sessionId);
	if (existing) return existing;
	pruneLegacyStreams();
	if (LEGACY_STREAMS.size >= MAX_LEGACY_STREAMS) return undefined;
	if (countPrincipalStreams(principal) >= MAX_LEGACY_STREAMS_PER_PRINCIPAL) return undefined;
	const created: LegacyStreamRecord = { queue: [], createdAt: Date.now(), principal };
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
export function setLegacyStreamRecordForTest(
	sessionId: string,
	record: Omit<LegacyStreamRecord, 'heartbeat' | 'lifetime' | 'principal'> & { principal?: string },
): void {
	LEGACY_STREAMS.set(sessionId, {
		...record,
		heartbeat: undefined,
		lifetime: undefined,
		principal: record.principal ?? `test:${sessionId}`,
	});
}

export function openLegacySseStream(sessionId: string, endpointUrl: string, principal = `session:${sessionId}`): Response {
	const encoder = new TextEncoder();
	const record = getOrCreateRecord(sessionId, principal);
	if (!record) {
		const principalAtCapacity = countPrincipalStreams(principal) >= MAX_LEGACY_STREAMS_PER_PRINCIPAL;
		return new Response(principalAtCapacity ? 'Too many concurrent legacy SSE streams' : 'Legacy SSE capacity unavailable', {
			status: principalAtCapacity ? 429 : 503,
			headers: { 'retry-after': principalAtCapacity ? '60' : '5' },
		});
	}

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
			record.lifetime = setTimeout(() => {
				closeLegacyStream(sessionId);
			}, MAX_LEGACY_STREAM_LIFETIME_MS) as unknown as number;
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
	} else if (record.queue.length < MAX_LEGACY_QUEUE_DEPTH) {
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
	if (record.lifetime !== undefined) {
		clearTimeout(record.lifetime);
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
