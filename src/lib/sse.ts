/**
 * SSE Transport Helpers
 *
 * Utilities for Server-Sent Events (SSE) formatting used by the
 * MCP Streamable HTTP transport layer.
 */

/** Format a JSON-RPC message as an SSE `message` event */
export function sseEvent(data: unknown, eventId?: string): string {
	let event = '';
	if (eventId) {
		event += `id: ${eventId}\n`;
	}
	event += `event: message\ndata: ${JSON.stringify(data)}\n\n`;
	return event;
}

/** Check whether the Accept header includes text/event-stream */
export function acceptsSSE(accept: string | undefined): boolean {
	return !!accept && accept.includes('text/event-stream');
}

/** Create a ReadableStream that emits pre-formatted SSE text and then closes */
export function createSseStream(events: string): ReadableStream<Uint8Array> {
	return new ReadableStream({
		start(controller) {
			controller.enqueue(new TextEncoder().encode(events));
			controller.close();
		},
	});
}