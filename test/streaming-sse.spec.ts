import { describe, it, expect, vi, afterEach } from 'vitest';
import { createStreamingSseResponse, sseEvent } from '../src/lib/sse';

afterEach(() => {
	vi.useRealTimers();
	vi.restoreAllMocks();
});

/** Read all chunks from a ReadableStream until it closes */
async function drainStream(response: Response): Promise<string> {
	const reader = response.body!.getReader();
	const decoder = new TextDecoder();
	let result = '';
	for (;;) {
		const { value, done } = await reader.read();
		if (done) break;
		result += decoder.decode(value, { stream: true });
	}
	return result;
}

/** Read a single chunk from a ReadableStream */
async function readChunk(reader: ReadableStreamDefaultReader<Uint8Array>): Promise<string> {
	const { value, done } = await reader.read();
	if (done || !value) throw new Error('Expected a chunk but stream ended');
	return new TextDecoder().decode(value);
}

describe('Streaming SSE - Heartbeat delivery', () => {
	it('emits no heartbeat before 5s', async () => {
		vi.useFakeTimers();
		let resolve: (v: string) => void;
		const operation = new Promise<string>((r) => {
			resolve = r;
		});

		const response = createStreamingSseResponse(
			operation,
			(result) => sseEvent({ jsonrpc: '2.0', id: 1, result }, '1'),
			{},
		);
		const reader = response.body!.getReader();

		// Advance 4.9s — should not get any output yet
		vi.advanceTimersByTime(4_900);

		// Resolve the operation so the stream closes
		resolve!('early');
		await vi.advanceTimersByTimeAsync(0);

		const full = await drainStream(new Response(new ReadableStream({
			start(controller) {
				// Replay: read whatever the original reader has
				(async () => {
					for (;;) {
						const { value, done } = await reader.read();
						if (done) { controller.close(); break; }
						controller.enqueue(value);
					}
				})();
			},
		})));

		// Should contain the result but no heartbeat
		expect(full).not.toContain(': heartbeat');
		expect(full).toContain('event: message');
	});

	it('emits heartbeats at 5s intervals while operation is pending (fake timers)', async () => {
		vi.useFakeTimers();
		let resolve: (v: string) => void;
		const operation = new Promise<string>((r) => {
			resolve = r;
		});

		const response = createStreamingSseResponse(
			operation,
			(result) => sseEvent({ jsonrpc: '2.0', id: 1, result }, '1'),
			{},
		);
		const reader = response.body!.getReader();

		// First heartbeat at 5s
		vi.advanceTimersByTime(5_000);
		const chunk1 = await readChunk(reader);
		expect(chunk1).toBe(': heartbeat\n\n');

		// Second heartbeat at 10s
		vi.advanceTimersByTime(5_000);
		const chunk2 = await readChunk(reader);
		expect(chunk2).toBe(': heartbeat\n\n');

		// Third heartbeat at 15s
		vi.advanceTimersByTime(5_000);
		const chunk3 = await readChunk(reader);
		expect(chunk3).toBe(': heartbeat\n\n');

		// Resolve to clean up
		resolve!('done');
		await vi.advanceTimersByTimeAsync(0);
		reader.releaseLock();
	});

	it('accumulates multiple heartbeats over 15s (3 heartbeats)', async () => {
		vi.useFakeTimers();
		let resolve: (v: string) => void;
		const operation = new Promise<string>((r) => {
			resolve = r;
		});

		const response = createStreamingSseResponse(
			operation,
			(result) => sseEvent({ jsonrpc: '2.0', id: 1, result }, '1'),
			{},
		);

		// Advance 15s then resolve
		vi.advanceTimersByTime(15_000);
		resolve!('done');
		await vi.advanceTimersByTimeAsync(0);

		const full = await drainStream(response);
		const heartbeatCount = (full.match(/: heartbeat\n\n/g) || []).length;
		expect(heartbeatCount).toBe(3);
	});
});

describe('Streaming SSE - Stream lifecycle', () => {
	it('returns response immediately before operation resolves', () => {
		const operation = new Promise<string>(() => {
			// never resolves
		});

		const response = createStreamingSseResponse(
			operation,
			(result) => sseEvent({ result }, '1'),
			{},
		);

		// Response object is returned synchronously
		expect(response).toBeInstanceOf(Response);
		expect(response.status).toBe(200);
		expect(response.body).toBeTruthy();
	});

	it('includes correct SSE headers', () => {
		const operation = new Promise<string>(() => {});
		const response = createStreamingSseResponse(
			operation,
			(result) => sseEvent({ result }, '1'),
			{ 'mcp-session-id': 'test-session' },
		);

		expect(response.headers.get('content-type')).toBe('text/event-stream');
		expect(response.headers.get('cache-control')).toBe('no-cache');
		expect(response.headers.get('mcp-session-id')).toBe('test-session');
	});

	it('delivers final result as SSE message event then closes stream', async () => {
		vi.useFakeTimers();
		let resolve: (v: string) => void;
		const operation = new Promise<string>((r) => {
			resolve = r;
		});

		const response = createStreamingSseResponse(
			operation,
			(result) => sseEvent({ jsonrpc: '2.0', id: 1, result: { content: result } }, '1'),
			{},
		);
		const reader = response.body!.getReader();

		// Get a heartbeat first
		vi.advanceTimersByTime(5_000);
		const hb = await readChunk(reader);
		expect(hb).toBe(': heartbeat\n\n');

		// Resolve the operation
		resolve!('tool-output');
		await vi.advanceTimersByTimeAsync(0);

		// Next chunk is the result
		const result = await readChunk(reader);
		expect(result).toContain('event: message');
		expect(result).toContain('"tool-output"');
		expect(result).toContain('id: 1');

		// Stream should now be closed
		const final = await reader.read();
		expect(final.done).toBe(true);
	});

	it('stops heartbeats after operation resolves', async () => {
		vi.useFakeTimers();
		let resolve: (v: string) => void;
		const operation = new Promise<string>((r) => {
			resolve = r;
		});

		const response = createStreamingSseResponse(
			operation,
			(result) => sseEvent({ result }, '1'),
			{},
		);

		// Resolve immediately (before any heartbeat)
		resolve!('fast');
		await vi.advanceTimersByTimeAsync(0);

		const full = await drainStream(response);
		// No heartbeats — operation resolved before 5s
		expect(full).not.toContain(': heartbeat');
		expect(full).toContain('event: message');
	});
});

describe('Streaming SSE - Error recovery', () => {
	it('emits JSON-RPC error event when operation rejects', async () => {
		vi.useFakeTimers();
		let reject: (e: Error) => void;
		const operation = new Promise<string>((_, r) => {
			reject = r;
		});

		const response = createStreamingSseResponse(
			operation,
			(result) => sseEvent({ jsonrpc: '2.0', id: 1, result }, '1'),
			{},
		);

		reject!(new Error('Something went wrong'));
		await vi.advanceTimersByTimeAsync(0);

		const full = await drainStream(response);
		expect(full).toContain('event: message');
		expect(full).toContain('"error"');
		expect(full).toContain('-32603');
	});

	it('sanitizes unexpected error messages', async () => {
		vi.useFakeTimers();
		let reject: (e: Error) => void;
		const operation = new Promise<string>((_, r) => {
			reject = r;
		});

		const response = createStreamingSseResponse(
			operation,
			(result) => sseEvent({ jsonrpc: '2.0', id: 1, result }, '1'),
			{},
		);

		reject!(new Error('Database connection string: postgres://user:pass@host'));
		await vi.advanceTimersByTimeAsync(0);

		const full = await drainStream(response);
		// The error message should be sanitized — should not leak connection details
		expect(full).not.toContain('postgres://');
		expect(full).toContain('"error"');
	});

	it('closes stream cleanly after error (no further heartbeats)', async () => {
		vi.useFakeTimers();
		let reject: (e: Error) => void;
		const operation = new Promise<string>((_, r) => {
			reject = r;
		});

		const response = createStreamingSseResponse(
			operation,
			(result) => sseEvent({ result }, '1'),
			{},
		);

		// Let one heartbeat through
		vi.advanceTimersByTime(5_000);

		// Then reject
		reject!(new Error('fail'));
		await vi.advanceTimersByTimeAsync(0);

		const full = await drainStream(response);
		const heartbeatCount = (full.match(/: heartbeat\n\n/g) || []).length;
		expect(heartbeatCount).toBe(1); // Only the one before the error
		expect(full).toContain('"error"');
	});
});

describe('Streaming SSE - Batch mode', () => {
	it('batch requests return single SSE event without heartbeats (integration)', async () => {
		// Import integration helpers
		const { env, createExecutionContext, waitOnExecutionContext } = await import('cloudflare:test');
		const { default: worker } = await import('../src');
		const { resetAllRateLimits } = await import('../src/lib/rate-limiter');
		const { resetSessions } = await import('../src/lib/session');
		const { resetLegacySseState } = await import('../src/lib/legacy-sse');

		resetAllRateLimits();
		resetSessions();
		resetLegacySseState();

		// Initialize session first
		const initReq = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ jsonrpc: '2.0', id: 0, method: 'initialize', params: {} }),
		});
		const initCtx = createExecutionContext();
		const initRes = await worker.fetch(initReq, env, initCtx);
		await waitOnExecutionContext(initCtx);
		const sessionId = initRes.headers.get('mcp-session-id')!;

		// Send batch with Accept: text/event-stream
		const batchReq = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Accept: 'text/event-stream',
				'Mcp-Session-Id': sessionId,
			},
			body: JSON.stringify([
				{ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} },
				{ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
			]),
		});
		const batchCtx = createExecutionContext();
		const batchRes = await worker.fetch(batchReq, env, batchCtx);
		await waitOnExecutionContext(batchCtx);

		expect(batchRes.status).toBe(200);
		expect(batchRes.headers.get('content-type')).toBe('text/event-stream');

		const body = await batchRes.text();
		// Should be a single SSE event with batch results — no heartbeats
		expect(body).not.toContain(': heartbeat');
		expect(body).toContain('event: message');
	});

	it('non-SSE tools/call returns JSON without streaming', async () => {
		const { env, createExecutionContext, waitOnExecutionContext } = await import('cloudflare:test');
		const { default: worker } = await import('../src');
		const { resetAllRateLimits } = await import('../src/lib/rate-limiter');
		const { resetSessions } = await import('../src/lib/session');
		const { resetLegacySseState } = await import('../src/lib/legacy-sse');

		resetAllRateLimits();
		resetSessions();
		resetLegacySseState();

		// Initialize session
		const initReq = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ jsonrpc: '2.0', id: 0, method: 'initialize', params: {} }),
		});
		const initCtx = createExecutionContext();
		const initRes = await worker.fetch(initReq, env, initCtx);
		await waitOnExecutionContext(initCtx);
		const sessionId = initRes.headers.get('mcp-session-id')!;

		// tools/call with Accept: application/json (no SSE)
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Accept: 'application/json',
				'Mcp-Session-Id': sessionId,
			},
			body: JSON.stringify({
				jsonrpc: '2.0',
				id: 1,
				method: 'tools/call',
				params: { name: 'explain_finding', arguments: { checkType: 'SPF', status: 'fail' } },
			}),
		});
		const ctx = createExecutionContext();
		const res = await worker.fetch(req, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(res.status).toBe(200);
		expect(res.headers.get('content-type')).toContain('application/json');

		const body = await res.text();
		expect(body).not.toContain(': heartbeat');
		expect(body).not.toContain('event: message');

		const json = JSON.parse(body) as { result: { content: Array<{ text: string }> } };
		expect(json.result.content[0].text).toContain('SPF');
	});
});

describe('Streaming SSE - Real timer smoke test', () => {
	it('heartbeat arrives within ~5s with real timers', async () => {
		let resolve: (v: string) => void;
		const operation = new Promise<string>((r) => {
			resolve = r;
		});

		const response = createStreamingSseResponse(
			operation,
			(result) => sseEvent({ jsonrpc: '2.0', id: 1, result }, '1'),
			{},
		);
		const reader = response.body!.getReader();

		const start = Date.now();
		const chunk = await readChunk(reader);
		const elapsed = Date.now() - start;

		expect(chunk).toBe(': heartbeat\n\n');
		// Should arrive around 5s (allow 4-7s range for CI variance)
		expect(elapsed).toBeGreaterThanOrEqual(4_000);
		expect(elapsed).toBeLessThanOrEqual(7_000);

		// Clean up
		resolve!('done');
		reader.releaseLock();
	}, 10_000);
});
