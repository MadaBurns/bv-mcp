// SPDX-License-Identifier: BUSL-1.1

/**
 * SSE Transport Helpers
 *
 * Utilities for Server-Sent Events (SSE) formatting used by the
 * MCP Streamable HTTP transport layer.
 */

import { sanitizeErrorMessage } from './json-rpc';

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
 *
 * Uses the actual HTTP status code so MCP clients can detect session expiry (404)
 * and other errors at the HTTP level, as required by the MCP spec.
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
			status,
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

/**
 * Duration (ms) to keep the SSE notification stream alive before closing.
 * Workers Standard has no strict wall-time limit for streaming responses;
 * 5s heartbeats keep the connection alive well within Cloudflare proxy
 * idle timeouts. 5 minutes reduces mcp-remote reconnection churn to
 * ~0.2/min — the previous 55s TTL caused ~1/min reconnections that
 * created race conditions during continuous scanning from Claude Desktop.
 */
const NOTIFICATION_STREAM_TTL_MS = 300_000;

/**
 * Create a long-lived SSE notification stream with periodic heartbeats.
 *
 * Unlike `createSseStream` (which closes immediately), this keeps the
 * connection alive for NOTIFICATION_STREAM_TTL_MS to prevent mcp-remote
 * reconnection storms that cause "client side tool call failed" errors
 * in Claude Desktop.
 */
export function createNotificationStream(): ReadableStream<Uint8Array> {
	const encoder = new TextEncoder();
	return new ReadableStream({
		start(controller) {
			let closed = false;

			controller.enqueue(encoder.encode(': stream opened\n\n'));

			const heartbeat = setInterval(() => {
				if (closed) return;
				try {
					controller.enqueue(encoder.encode(': heartbeat\n\n'));
				} catch {
					closed = true;
					clearInterval(heartbeat);
				}
			}, HEARTBEAT_INTERVAL_MS);

			setTimeout(() => {
				if (closed) return;
				closed = true;
				clearInterval(heartbeat);
				controller.close();
			}, NOTIFICATION_STREAM_TTL_MS);
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
					// Emit error as a proper JSON-RPC error SSE event so MCP clients can parse it
					const message = sanitizeErrorMessage(err, 'Internal error');
					const jsonRpcErr = { jsonrpc: '2.0', id: null, error: { code: -32603, message } };
					controller.enqueue(encoder.encode(`event: message\ndata: ${JSON.stringify(jsonRpcErr)}\n\n`));
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