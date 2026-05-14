// SPDX-License-Identifier: BUSL-1.1
/**
 * Unit tests for the TCP/43 WHOIS transport.
 *
 * Layer: Unit. Uses a fake socket factory to avoid real network I/O.
 */

import { describe, it, expect, vi } from 'vitest';
import { whoisQuery, type SocketLike, type SocketFactory } from '../transport';

/** Build a fake socket that emits `responseText` and records writes. */
function makeFakeSocket(responseText: string, opts: { stallReadMs?: number; failConnect?: boolean } = {}): {
	factory: SocketFactory;
	writes: string[];
	hostnameSeen: string | null;
} {
	const writes: string[] = [];
	let hostnameSeen: string | null = null;

	const factory: SocketFactory = {
		async connect({ hostname }) {
			if (opts.failConnect) throw new Error('econnrefused');
			hostnameSeen = hostname;

			const writable = new WritableStream<Uint8Array>({
				write(chunk) {
					writes.push(new TextDecoder().decode(chunk));
				},
			});

			const readable = new ReadableStream<Uint8Array>({
				async start(controller) {
					if (opts.stallReadMs) await new Promise(r => setTimeout(r, opts.stallReadMs));
					controller.enqueue(new TextEncoder().encode(responseText));
					controller.close();
				},
			});

			const socket: SocketLike = { writable, readable, close: () => Promise.resolve() };
			return socket;
		},
	};

	return { factory, writes, get hostnameSeen() { return hostnameSeen; } } as never;
}

describe('whoisQuery', () => {
	it('writes the query followed by CRLF and returns the response text', async () => {
		const { factory, writes } = makeFakeSocket('Registrar: TestReg Inc.\n');

		const result = await whoisQuery('whois.example.com', 'example.com', { socketFactory: factory });

		expect(result).toBe('Registrar: TestReg Inc.\n');
		expect(writes.join('')).toBe('example.com\r\n');
	});

	it('connects to the requested hostname on port 43', async () => {
		const connectSpy = vi.fn(async ({ port }) => {
			expect(port).toBe(43);
			return {
				writable: new WritableStream({ write() {} }),
				readable: new ReadableStream({
					start(c) { c.enqueue(new TextEncoder().encode('ok')); c.close(); },
				}),
				close: () => Promise.resolve(),
			} as SocketLike;
		});

		await whoisQuery('whois.example.com', 'q', { socketFactory: { connect: connectSpy } });

		expect(connectSpy).toHaveBeenCalledWith(expect.objectContaining({ hostname: 'whois.example.com', port: 43 }));
	});

	it('rejects with timeout error when read stalls beyond timeoutMs', async () => {
		const { factory } = makeFakeSocket('late', { stallReadMs: 2000 });

		await expect(
			whoisQuery('whois.example.com', 'q', { timeoutMs: 50, socketFactory: factory })
		).rejects.toThrow(/timeout/i);
	});

	it('rejects when connect fails', async () => {
		const { factory } = makeFakeSocket('', { failConnect: true });

		await expect(
			whoisQuery('whois.example.com', 'q', { socketFactory: factory })
		).rejects.toThrow(/econnrefused/i);
	});

	it('rejects when hostname fails SSRF validation (private IP)', async () => {
		const { factory } = makeFakeSocket('ok');

		await expect(
			whoisQuery('127.0.0.1', 'q', { socketFactory: factory })
		).rejects.toThrow(/invalid|blocked|private/i);
	});

	it('rejects when hostname fails SSRF validation (localhost)', async () => {
		const { factory } = makeFakeSocket('ok');

		await expect(
			whoisQuery('localhost', 'q', { socketFactory: factory })
		).rejects.toThrow(/invalid|blocked|private/i);
	});

	it('rejects all-numeric label forms that could route to private IPs via octal/numeric parsing', async () => {
		const { factory } = makeFakeSocket('ok');

		await expect(
			whoisQuery('0177.0.0.1', 'q', { socketFactory: factory })
		).rejects.toThrow(/invalid|numeric/i);
	});

	it('concatenates multi-chunk reads into a single response string', async () => {
		const factory: SocketFactory = {
			async connect() {
				return {
					writable: new WritableStream({ write() {} }),
					readable: new ReadableStream({
						start(c) {
							c.enqueue(new TextEncoder().encode('part1\n'));
							c.enqueue(new TextEncoder().encode('part2\n'));
							c.enqueue(new TextEncoder().encode('Registrar: X\n'));
							c.close();
						},
					}),
					close: () => Promise.resolve(),
				};
			},
		};

		const result = await whoisQuery('whois.example.com', 'q', { socketFactory: factory });
		expect(result).toBe('part1\npart2\nRegistrar: X\n');
	});

	it('truncates response at MAX_RESPONSE_BYTES to prevent flood', async () => {
		const huge = '#'.repeat(200_000);
		const { factory } = makeFakeSocket(huge);

		const result = await whoisQuery('whois.example.com', 'q', { socketFactory: factory });
		expect(result.length).toBeLessThanOrEqual(64 * 1024);
	});
});
