import { describe, expect, it } from 'vitest';
import { sseErrorResponse } from '../src/lib/sse';
import { jsonRpcError, JSON_RPC_ERRORS } from '../src/lib/json-rpc';

describe('sseErrorResponse', () => {
	it('returns the actual HTTP status code for SSE clients instead of 200', () => {
		const payload = jsonRpcError(1, JSON_RPC_ERRORS.INVALID_REQUEST, 'Not Found: session expired or terminated');
		const response = sseErrorResponse(payload, 404, 'text/event-stream');

		expect(response.status).toBe(404);
		expect(response.headers.get('content-type')).toBe('text/event-stream');
	});

	it('returns 429 status for rate-limited SSE clients', () => {
		const payload = jsonRpcError(1, JSON_RPC_ERRORS.RATE_LIMITED, 'Rate limit exceeded');
		const response = sseErrorResponse(payload, 429, 'text/event-stream', { 'retry-after': '5' });

		expect(response.status).toBe(429);
		expect(response.headers.get('retry-after')).toBe('5');
	});

	it('returns 400 status for missing session SSE clients', () => {
		const payload = jsonRpcError(1, JSON_RPC_ERRORS.INVALID_REQUEST, 'Bad Request: missing session');
		const response = sseErrorResponse(payload, 400, 'text/event-stream');

		expect(response.status).toBe(400);
	});

	it('still returns JSON with actual status for non-SSE clients', () => {
		const payload = jsonRpcError(1, JSON_RPC_ERRORS.INVALID_REQUEST, 'Not Found: session expired or terminated');
		const response = sseErrorResponse(payload, 404, 'application/json');

		expect(response.status).toBe(404);
	});

	it('includes SSE event body when client accepts SSE', async () => {
		const payload = jsonRpcError(1, JSON_RPC_ERRORS.INVALID_REQUEST, 'session expired');
		const response = sseErrorResponse(payload, 404, 'text/event-stream');

		const body = await response.text();
		expect(body).toContain('event: message');
		expect(body).toContain('session expired');
	});
});
