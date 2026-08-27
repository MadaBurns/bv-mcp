// SPDX-License-Identifier: BUSL-1.1
/**
 * Unit tests for the TCP/43 WHOIS transport.
 *
 * Layer: Unit. Uses a fake socket factory to avoid real network I/O.
 */

import { describe, it, expect, vi } from 'vitest';
import { MAX_RESPONSE_BYTES } from '@blackveil/dns-checks/whois';
import { whoisQuery, type SocketLike, type SocketFactory } from '../transport';

/** Build a fake socket that emits `responseText` and records writes. */
function makeFakeSocket(
	responseText: string,
	opts: { stallReadMs?: number; failConnect?: boolean } = {},
): {
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
					if (opts.stallReadMs) await new Promise((r) => setTimeout(r, opts.stallReadMs));
					controller.enqueue(new TextEncoder().encode(responseText));
					controller.close();
				},
			});

			const socket: SocketLike = { writable, readable, close: () => Promise.resolve() };
			return socket;
		},
	};

	return {
		factory,
		writes,
		get hostnameSeen() {
			return hostnameSeen;
		},
	} as never;
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
					start(c) {
						c.enqueue(new TextEncoder().encode('ok'));
						c.close();
					},
				}),
				close: () => Promise.resolve(),
			} as SocketLike;
		});

		await whoisQuery('whois.example.com', 'q', { socketFactory: { connect: connectSpy } });

		expect(connectSpy).toHaveBeenCalledWith(expect.objectContaining({ hostname: 'whois.example.com', port: 43 }));
	});

	it('rejects with timeout error when read stalls beyond timeoutMs', async () => {
		const { factory } = makeFakeSocket('late', { stallReadMs: 2000 });

		await expect(whoisQuery('whois.example.com', 'q', { timeoutMs: 50, socketFactory: factory })).rejects.toThrow(/timeout/i);
	});

	it('applies the absolute deadline to a factory.connect call that never resolves', async () => {
		const connect = vi.fn(() => new Promise<SocketLike>(() => {}));

		await expect(
			whoisQuery('whois.example.com', 'q', {
				timeoutMs: 20,
				socketFactory: { connect },
			}),
		).rejects.toThrow(/timeout/i);
		expect(connect).toHaveBeenCalledTimes(1);
	});

	it('closes the socket without writing when socket.opened never resolves', async () => {
		const write = vi.fn();
		const close = vi.fn(() => Promise.resolve());
		const socket: SocketLike = {
			opened: new Promise(() => {}),
			writable: new WritableStream({ write }),
			readable: new ReadableStream(),
			close,
		};

		await expect(
			whoisQuery('whois.example.com', 'q', {
				timeoutMs: 20,
				socketFactory: { connect: async () => socket },
			}),
		).rejects.toThrow(/timeout/i);
		expect(write).not.toHaveBeenCalled();
		expect(close).toHaveBeenCalledTimes(1);
	});

	it('aborts/releases the writer and closes the socket when writer.write never resolves', async () => {
		const write = vi.fn(() => new Promise<void>(() => {}));
		const abort = vi.fn(() => Promise.resolve());
		const releaseLock = vi.fn();
		const getReader = vi.fn();
		const close = vi.fn(() => Promise.resolve());
		const socket: SocketLike = {
			opened: Promise.resolve(),
			writable: {
				getWriter: () => ({ write, abort, releaseLock }),
			} as unknown as WritableStream<Uint8Array>,
			readable: { getReader } as unknown as ReadableStream<Uint8Array>,
			close,
		};

		await expect(
			whoisQuery('whois.example.com', 'q', {
				timeoutMs: 20,
				socketFactory: { connect: async () => socket },
			}),
		).rejects.toThrow(/timeout/i);
		expect(abort).toHaveBeenCalledTimes(1);
		expect(releaseLock).toHaveBeenCalled();
		expect(getReader).not.toHaveBeenCalled();
		expect(close).toHaveBeenCalledTimes(1);
	});

	it('cancels/releases a stalled reader and closes the socket at the same deadline', async () => {
		const writerRelease = vi.fn();
		const read = vi.fn(() => new Promise<ReadableStreamReadResult<Uint8Array>>(() => {}));
		const cancel = vi.fn(() => Promise.resolve());
		const readerRelease = vi.fn();
		const close = vi.fn(() => Promise.resolve());
		const socket: SocketLike = {
			writable: {
				getWriter: () => ({
					write: vi.fn(() => Promise.resolve()),
					abort: vi.fn(() => Promise.resolve()),
					releaseLock: writerRelease,
				}),
			} as unknown as WritableStream<Uint8Array>,
			readable: {
				getReader: () => ({ read, cancel, releaseLock: readerRelease }),
			} as unknown as ReadableStream<Uint8Array>,
			close,
		};

		await expect(
			whoisQuery('whois.example.com', 'q', {
				timeoutMs: 20,
				socketFactory: { connect: async () => socket },
			}),
		).rejects.toThrow(/timeout/i);
		expect(writerRelease).toHaveBeenCalledTimes(1);
		expect(cancel).toHaveBeenCalledTimes(1);
		expect(readerRelease).toHaveBeenCalled();
		expect(close).toHaveBeenCalledTimes(1);
	});

	it('rejects when connect fails', async () => {
		const { factory } = makeFakeSocket('', { failConnect: true });

		await expect(whoisQuery('whois.example.com', 'q', { socketFactory: factory })).rejects.toThrow(/econnrefused/i);
	});

	it('rejects when hostname fails SSRF validation (private IP)', async () => {
		const { factory } = makeFakeSocket('ok');

		await expect(whoisQuery('127.0.0.1', 'q', { socketFactory: factory })).rejects.toThrow(/invalid|blocked|private/i);
	});

	it('rejects when hostname fails SSRF validation (localhost)', async () => {
		const { factory } = makeFakeSocket('ok');

		await expect(whoisQuery('localhost', 'q', { socketFactory: factory })).rejects.toThrow(/invalid|blocked|private/i);
	});

	it('rejects all-numeric label forms that could route to private IPs via octal/numeric parsing', async () => {
		const { factory } = makeFakeSocket('ok');

		await expect(whoisQuery('0177.0.0.1', 'q', { socketFactory: factory })).rejects.toThrow(/invalid|numeric/i);
	});

	it('does NOT call writer.close() — regression: 100-domain chaos run showed 98/98 zero-byte reads', async () => {
		// cloudflare:sockets has no half-close: calling `writer.close()` shuts down the
		// entire socket and the server never sees our query before the FIN. The prior
		// async-fire-and-forget pattern called writer.close() and produced 100% empty reads.
		// Invariant: our transport must release the writer's lock, not close it.
		let writerCloseCalled = false;

		const factory: SocketFactory = {
			async connect() {
				return {
					writable: new WritableStream({
						write() {},
						close() {
							writerCloseCalled = true;
						},
					}),
					readable: new ReadableStream({
						start(controller) {
							controller.enqueue(new TextEncoder().encode('Registrar: TestReg\n'));
							controller.close();
						},
					}),
					close: () => Promise.resolve(),
				};
			},
		};

		const result = await whoisQuery('whois.example.com', 'q', { socketFactory: factory });

		expect(writerCloseCalled).toBe(false);
		expect(result).toContain('Registrar: TestReg');
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

	it('uses one cleared absolute timer rather than allocating a timer per read', async () => {
		const setTimeoutSpy = vi.spyOn(globalThis, 'setTimeout');
		const clearTimeoutSpy = vi.spyOn(globalThis, 'clearTimeout');
		try {
			const factory: SocketFactory = {
				async connect() {
					return {
						writable: new WritableStream({ write() {} }),
						readable: new ReadableStream({
							start(controller) {
								for (let i = 0; i < 20; i += 1) {
									controller.enqueue(new TextEncoder().encode(`part-${i}\n`));
								}
								controller.close();
							},
						}),
						close: () => Promise.resolve(),
					};
				},
			};

			await whoisQuery('whois.example.com', 'q', { socketFactory: factory });
			expect(setTimeoutSpy).toHaveBeenCalledTimes(1);
			expect(clearTimeoutSpy).toHaveBeenCalledTimes(1);
		} finally {
			setTimeoutSpy.mockRestore();
			clearTimeoutSpy.mockRestore();
		}
	});

	it('rejects a response larger than MAX_RESPONSE_BYTES to prevent flood', async () => {
		const huge = '#'.repeat(200_000);
		const { factory } = makeFakeSocket(huge);

		await expect(whoisQuery('whois.example.com', 'q', { socketFactory: factory })).rejects.toThrow(/exceeded|too large/i);
	});

	it('rejects a single MAX_RESPONSE_BYTES+N chunk before copy/decode and cancels overflow', async () => {
		const oversized = new Uint8Array(MAX_RESPONSE_BYTES + 17).fill('#'.charCodeAt(0));
		const cancel = vi.fn(() => Promise.resolve());
		const releaseLock = vi.fn();
		const close = vi.fn(() => Promise.resolve());
		let readCount = 0;
		const socket: SocketLike = {
			writable: new WritableStream({ write() {} }),
			readable: {
				getReader: () => ({
					read: async () => (readCount++ === 0 ? { done: false as const, value: oversized } : { done: true as const, value: undefined }),
					cancel,
					releaseLock,
				}),
			} as unknown as ReadableStream<Uint8Array>,
			close,
		};

		await expect(
			whoisQuery('whois.example.com', 'q', {
				socketFactory: { connect: async () => socket },
			}),
		).rejects.toThrow(/exceeded|too large/i);
		expect(cancel).toHaveBeenCalledWith('response too large');
		expect(releaseLock).toHaveBeenCalled();
		expect(close).toHaveBeenCalledTimes(1);
	});

	it('applies the byte cap before UTF-8 decoding when the boundary splits a multibyte code point', async () => {
		const exactLimit = new Uint8Array(MAX_RESPONSE_BYTES).fill('a'.charCodeAt(0));
		exactLimit[MAX_RESPONSE_BYTES - 1] = 0xc3; // lead byte; continuation would exceed the cap
		const socketFactory: SocketFactory = {
			async connect() {
				return {
					writable: new WritableStream({ write() {} }),
					readable: new ReadableStream({
						start(controller) {
							controller.enqueue(exactLimit);
							controller.close();
						},
					}),
					close: () => Promise.resolve(),
				};
			},
		};

		const result = await whoisQuery('whois.example.com', 'q', { socketFactory });
		expect(result).toBe(`${'a'.repeat(MAX_RESPONSE_BYTES - 1)}\uFFFD`);
		expect(result).not.toContain('é');
	});
});
