// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';
import { readResponseTextCapped } from '../response-body';

function chunkedResponse(chunks: Uint8Array[], headers?: HeadersInit, onCancel?: () => void): Response {
	let index = 0;
	return new Response(
		new ReadableStream<Uint8Array>({
			pull(controller) {
				const chunk = chunks[index++];
				if (chunk) controller.enqueue(chunk);
				else controller.close();
			},
			cancel() {
				onCancel?.();
			},
		}),
		{ headers },
	);
}

describe('readResponseTextCapped', () => {
	it('accepts an exact-cap chunked body without Content-Length', async () => {
		const response = chunkedResponse([new TextEncoder().encode('12'), new TextEncoder().encode('345')]);
		expect(response.headers.get('content-length')).toBeNull();
		await expect(readResponseTextCapped(response, 5)).resolves.toBe('12345');
	});

	it('cancels at cap plus one without calling Response.text()', async () => {
		const cancelled = vi.fn();
		const response = chunkedResponse(
			[new TextEncoder().encode('12345'), new TextEncoder().encode('6'), new TextEncoder().encode('never-read')],
			undefined,
			cancelled,
		);
		Object.defineProperty(response, 'text', {
			value: () => Promise.reject(new Error('unbounded Response.text() must not be used')),
		});

		await expect(readResponseTextCapped(response, 5)).resolves.toBeNull();
		expect(cancelled).toHaveBeenCalledOnce();
	});

	it('uses streamed bytes rather than a misleading compressed Content-Length', async () => {
		// Models the decoded stream exposed by fetch when the wire representation was compressed.
		const cancelled = vi.fn();
		const response = chunkedResponse(
			[new TextEncoder().encode('a'.repeat(8)), new TextEncoder().encode('b'), new TextEncoder().encode('never-read')],
			{ 'content-encoding': 'gzip', 'content-length': '2' },
			cancelled,
		);

		await expect(readResponseTextCapped(response, 8)).resolves.toBeNull();
		expect(cancelled).toHaveBeenCalledOnce();
	});

	it('rejects an oversized declared length before pulling the body', async () => {
		const cancelled = vi.fn();
		const response = chunkedResponse([new TextEncoder().encode('small')], { 'content-length': '999' }, cancelled);

		await expect(readResponseTextCapped(response, 8)).resolves.toBeNull();
		expect(cancelled).toHaveBeenCalledOnce();
	});
});
