// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';

/** Build a ReadableStream that emits the given Uint8Array chunks. */
function streamFrom(chunks: Uint8Array[], onCancel?: () => void): ReadableStream<Uint8Array> {
	let i = 0;
	return new ReadableStream<Uint8Array>({
		pull(controller) {
			if (i < chunks.length) {
				controller.enqueue(chunks[i++]);
			} else {
				controller.close();
			}
		},
		cancel() {
			onCancel?.();
		},
	});
}

/** A stream whose reader.read() rejects on the first pull. */
function rejectingStream(): ReadableStream<Uint8Array> {
	return new ReadableStream<Uint8Array>({
		pull() {
			throw new Error('boom');
		},
	});
}

describe('readBoundedText', () => {
	it('bounds on UTF-8 byte length, not UTF-16 code-unit length, for multi-byte bodies', async () => {
		const { readBoundedText } = await import('../src/lib/response-body');
		// '€' encodes to 3 UTF-8 bytes. 1000 of them = 3000 bytes but only 1000 code units.
		const full = new TextEncoder().encode('€'.repeat(1000));
		expect(full.byteLength).toBe(3000);
		// Emit in small chunks so the cap can be hit mid-stream.
		const chunks: Uint8Array[] = [];
		for (let o = 0; o < full.byteLength; o += 128) {
			chunks.push(full.slice(o, o + 128));
		}
		const result = await readBoundedText(streamFrom(chunks), 600);
		const resultBytes = new TextEncoder().encode(result).byteLength;
		// Bounded by BYTES: the decoded prefix must never exceed the configured cap.
		expect(resultBytes).toBeLessThanOrEqual(600);
		// And crucially it must NOT have read the whole 3000-byte body.
		expect(resultBytes).toBeLessThan(3000);
		// Sanity: result.length (UTF-16 units) is far below what a length-based bound would allow.
		expect(result.length).toBeGreaterThan(0);
	});

	it('returns the bounded prefix when the body overflows (truncate, never throws)', async () => {
		const { readBoundedText } = await import('../src/lib/response-body');
		// Deliver in small chunks so the cap can be hit before the whole body buffers.
		const full = new TextEncoder().encode('a'.repeat(10000));
		const chunks: Uint8Array[] = [];
		for (let o = 0; o < full.byteLength; o += 50) chunks.push(full.slice(o, o + 50));
		const result = await readBoundedText(streamFrom(chunks), 100);
		const resultBytes = new TextEncoder().encode(result).byteLength;
		expect(resultBytes).toBeGreaterThan(0);
		expect(resultBytes).toBeLessThanOrEqual(100);
		expect(resultBytes).toBeLessThan(10000);
	});

	it('returns the full body when under the cap', async () => {
		const { readBoundedText } = await import('../src/lib/response-body');
		const result = await readBoundedText(streamFrom([new TextEncoder().encode('hello')]), 1024);
		expect(result).toBe('hello');
	});

	it('returns "" for a null body', async () => {
		const { readBoundedText } = await import('../src/lib/response-body');
		expect(await readBoundedText(null, 1024)).toBe('');
	});

	it('returns "" for an empty stream', async () => {
		const { readBoundedText } = await import('../src/lib/response-body');
		expect(await readBoundedText(streamFrom([]), 1024)).toBe('');
	});

	it('returns "" (never throws) when the reader rejects', async () => {
		const { readBoundedText } = await import('../src/lib/response-body');
		await expect(readBoundedText(rejectingStream(), 1024)).resolves.toBe('');
	});
});

describe('readBoundedOrNull', () => {
	it('accepts a body exactly equal to the byte cap', async () => {
		const { readBoundedOrNull } = await import('../src/lib/response-body');
		const result = await readBoundedOrNull(streamFrom([new TextEncoder().encode('12345')]), 5);
		expect(result).toBe('12345');
	});

	it('returns null on overflow (preserves check-agent-discovery semantics)', async () => {
		const { readBoundedOrNull } = await import('../src/lib/response-body');
		const full = new TextEncoder().encode('a'.repeat(10000));
		const result = await readBoundedOrNull(streamFrom([full]), 100);
		expect(result).toBeNull();
	});

	it('cancels the unread remainder at cap plus one', async () => {
		const { readBoundedOrNull } = await import('../src/lib/response-body');
		const cancelled = vi.fn();
		const result = await readBoundedOrNull(
			streamFrom([new TextEncoder().encode('12345'), new TextEncoder().encode('6'), new TextEncoder().encode('unread')], cancelled),
			5,
		);
		expect(result).toBeNull();
		expect(cancelled).toHaveBeenCalledOnce();
	});

	it('returns the decoded body when under the cap', async () => {
		const { readBoundedOrNull } = await import('../src/lib/response-body');
		const result = await readBoundedOrNull(streamFrom([new TextEncoder().encode('hello')]), 1024);
		expect(result).toBe('hello');
	});

	it('returns null for a null body', async () => {
		const { readBoundedOrNull } = await import('../src/lib/response-body');
		expect(await readBoundedOrNull(null, 1024)).toBeNull();
	});

	it('returns null (never throws) when the reader rejects', async () => {
		const { readBoundedOrNull } = await import('../src/lib/response-body');
		await expect(readBoundedOrNull(rejectingStream(), 1024)).resolves.toBeNull();
	});
});

describe('readTextResponseCappedDetailed', () => {
	it('reports the bytes consumed when a chunked response overflows', async () => {
		const { readTextResponseCappedDetailed } = await import('../src/lib/response-body');
		const cancelled = vi.fn();
		const response = new Response(
			streamFrom([new TextEncoder().encode('1234'), new TextEncoder().encode('5678'), new TextEncoder().encode('unread')], cancelled),
		);

		await expect(readTextResponseCappedDetailed(response, 6)).resolves.toEqual({
			text: null,
			bytesRead: 8,
			overflowed: true,
			errored: false,
		});
		expect(cancelled).toHaveBeenCalledOnce();
	});

	it('returns an error stamp instead of throwing for a locked response body', async () => {
		const { readTextResponseCappedDetailed } = await import('../src/lib/response-body');
		const response = new Response('locked');
		const lock = response.body!.getReader();
		await expect(readTextResponseCappedDetailed(response, 32)).resolves.toEqual({
			text: null,
			bytesRead: 0,
			overflowed: false,
			errored: true,
		});
		lock.releaseLock();
	});

	it('returns an error stamp instead of throwing when a response stream rejects', async () => {
		const { readTextResponseCappedDetailed } = await import('../src/lib/response-body');
		const response = new Response(rejectingStream());
		await expect(readTextResponseCappedDetailed(response, 32)).resolves.toEqual({
			text: null,
			bytesRead: 0,
			overflowed: false,
			errored: true,
		});
	});
});

describe('readJsonResponseCapped', () => {
	it('parses JSON below the cap', async () => {
		const { readJsonResponseCapped } = await import('../src/lib/response-body');
		await expect(readJsonResponseCapped<{ ok: boolean }>(Response.json({ ok: true }), 1024)).resolves.toEqual({ ok: true });
	});

	it('rejects and cancels JSON that exceeds the streamed byte cap', async () => {
		const { readJsonResponseCapped } = await import('../src/lib/response-body');
		const cancelled = vi.fn();
		const response = new Response(
			streamFrom([new TextEncoder().encode('{"x":"1234'), new TextEncoder().encode('5"}'), new TextEncoder().encode('unread')], cancelled),
			{ headers: { 'content-type': 'application/json', 'content-length': '2', 'content-encoding': 'gzip' } },
		);
		await expect(readJsonResponseCapped(response, 10)).resolves.toBeNull();
		expect(cancelled).toHaveBeenCalledOnce();
	});

	it('rejects malformed JSON', async () => {
		const { readJsonResponseCapped } = await import('../src/lib/response-body');
		await expect(readJsonResponseCapped(new Response('{nope'), 1024)).resolves.toBeNull();
	});
});

describe('WAF response body hardening', () => {
	it('reads only a bounded prefix from target-controlled HTML', async () => {
		const { readWafResponseBody } = await import('../src/tools/check-http-security');
		const response = new Response(`<title>Just a moment...</title>${'x'.repeat(100_000)}`);
		Object.defineProperty(response, 'text', {
			value: () => Promise.reject(new Error('unbounded response.text() must not be used')),
		});

		const body = await readWafResponseBody(response);
		expect(body).toContain('Just a moment');
		expect(new TextEncoder().encode(body).byteLength).toBeLessThanOrEqual(64 * 1024);
	});
});
