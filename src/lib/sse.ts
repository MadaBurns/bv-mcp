// SPDX-License-Identifier: MIT

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

/**
 * Build a Response for an error payload, using SSE format when the client
 * sent `Accept: text/event-stream` so that SSE-only transports (e.g. mcp-remote)
 * receive the error instead of hanging.
 */
export function sseErrorResponse(
	payload: unknown,
	status: number,
	accept: string | undefined,
	extraHeaders?: Record<string, string>,
	eventId?: string,
): Response {
	if (acceptsSSE(accept)) {
		const body = sseEvent(payload, eventId);
		return new Response(body, {
			status: 200,
			headers: {
				'Content-Type': 'text/event-stream',
				'Cache-Control': 'no-cache',
				'Content-Length': String(new TextEncoder().encode(body).byteLength),
				...extraHeaders,
			},
		});
	}
	return Response.json(payload, { status, headers: extraHeaders });
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