// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';
import { fetchCertIssuerFromCertstream } from '../src/tools/scan/post-processing';

describe('cert-meta response safety', () => {
	it('accepts a measured issuer string without changing it', async () => {
		const certstream = { fetch: vi.fn().mockResolvedValue(Response.json({ issuer: 'Cloudflare Inc ECC CA-3' })) };
		expect(await fetchCertIssuerFromCertstream('example.test', certstream)).toBe('Cloudflare Inc ECC CA-3');
	});

	it.each([
		{ worker: 'synthetic-ct-worker', enabled: true },
		{ issuer: ['Cloudflare Inc ECC CA-3'] },
		{ issuer: { name: 'Cloudflare Inc ECC CA-3' } },
		{ issuer: 42 },
		{ issuer: true },
		{ issuer: null },
		{ issuer: '' },
		{ issuer: '   ' },
		{ issuer: 'Cloudflare Inc ECC CA-3', error: 'measurement failed' },
		['Cloudflare Inc ECC CA-3'],
		'Cloudflare Inc ECC CA-3',
		null,
	])('withholds issuer evidence for malformed or unrelated HTTP 200 payload %j', async (payload) => {
		const certstream = { fetch: vi.fn().mockResolvedValue(Response.json(payload)) };
		expect(await fetchCertIssuerFromCertstream('example.test', certstream)).toBeNull();
	});

	it('keeps the timeout active while the response body stalls after headers', async () => {
		let requestSignal: AbortSignal | null | undefined;
		const certstream = {
			fetch: vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
				requestSignal = init?.signal;
				let bodyController: ReadableStreamDefaultController<Uint8Array>;
				const body = new ReadableStream<Uint8Array>({ start: (controller) => (bodyController = controller) });
				init?.signal?.addEventListener('abort', () => bodyController.error(init.signal?.reason), { once: true });
				return new Response(body, { status: 200 });
			}),
		};

		const issuer = await fetchCertIssuerFromCertstream('example.com', certstream, undefined, 5);

		expect(issuer).toBeNull();
		expect(requestSignal?.aborted).toBe(true);
	});

	it('cancels an unread non-2xx response body', async () => {
		const cancelled = vi.fn();
		const certstream = {
			fetch: vi.fn().mockResolvedValue(
				new Response(new ReadableStream<Uint8Array>({ cancel: cancelled }), { status: 502 }),
			),
		};

		expect(await fetchCertIssuerFromCertstream('example.com', certstream)).toBeNull();
		expect(cancelled).toHaveBeenCalledOnce();
	});

	it('rejects an oversized success body and cancels its unread stream', async () => {
		const cancelled = vi.fn();
		const certstream = {
			fetch: vi.fn().mockResolvedValue(
				new Response(new ReadableStream<Uint8Array>({ cancel: cancelled }), {
					status: 200,
					headers: { 'content-length': String(64 * 1024 + 1) },
				}),
			),
		};

		expect(await fetchCertIssuerFromCertstream('example.com', certstream)).toBeNull();
		expect(cancelled).toHaveBeenCalledOnce();
	});
});
