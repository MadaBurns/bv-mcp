// SPDX-License-Identifier: BUSL-1.1

import { sseEvent } from './sse';

interface LegacyStreamRecord {
	controller?: ReadableStreamDefaultController<Uint8Array>;
	queue: string[];
	heartbeat?: number;
}

const LEGACY_STREAMS = new Map<string, LegacyStreamRecord>();
const HEARTBEAT_INTERVAL_MS = 5_000;

function endpointEvent(endpointUrl: string): string {
	return `event: endpoint\ndata: ${endpointUrl}\n\n`;
}

function getOrCreateRecord(sessionId: string): LegacyStreamRecord {
	const existing = LEGACY_STREAMS.get(sessionId);
	if (existing) return existing;
	const created: LegacyStreamRecord = { queue: [] };
	LEGACY_STREAMS.set(sessionId, created);
	return created;
}

export function resetLegacySseState(): void {
	for (const sessionId of LEGACY_STREAMS.keys()) {
		closeLegacyStream(sessionId);
	}
	LEGACY_STREAMS.clear();
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
	}
}