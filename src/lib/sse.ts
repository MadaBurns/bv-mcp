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

/** Interval between SSE heartbeat comments (ms). */
const HEARTBEAT_INTERVAL_MS = 5_000;

/**
 * Create a streaming SSE Response that sends heartbeat comments while
 * a long-running operation executes.  This keeps the TCP connection alive
 * and prevents proxy/client-side idle timeouts (e.g. mcp-remote / Claude Desktop).
 *
 * The stream emits `: heartbeat\n\n` comments (ignored by SSE EventSource
 * listeners per spec) every HEARTBEAT_INTERVAL_MS until the operation
 * resolves, then sends the result as a final `message` event and closes.
 */
export function createStreamingSseResponse<T>(
	operation: Promise<T>,
	formatResult: (result: T) => string,
	headers: Record<string, string>,
): Response {
	const encoder = new TextEncoder();
	const stream = new ReadableStream<Uint8Array>({
		start(controller) {
			let closed = false;

			const heartbeat = setInterval(() => {
				if (closed) return;
				try {
					controller.enqueue(encoder.encode(': heartbeat\n\n'));
				} catch {
					// Stream already closed/errored — clean up
					clearInterval(heartbeat);
				}
			}, HEARTBEAT_INTERVAL_MS);

			operation
				.then((result) => {
					if (closed) return;
					closed = true;
					clearInterval(heartbeat);
					controller.enqueue(encoder.encode(formatResult(result)));
					controller.close();
				})
				.catch((err) => {
					if (closed) return;
					closed = true;
					clearInterval(heartbeat);
					// Emit error as SSE event so the client sees it
					const message = err instanceof Error ? err.message : 'Internal error';
					controller.enqueue(encoder.encode(`event: message\ndata: ${JSON.stringify({ error: message })}\n\n`));
					controller.close();
				});
		},
	});

	return new Response(stream, {
		status: 200,
		headers: {
			'Content-Type': 'text/event-stream',
			'Cache-Control': 'no-cache',
			...headers,
		},
	});
}