// SPDX-License-Identifier: BUSL-1.1
/**
 * WHOIS-over-TCP/43 transport for the bv-whois shim Worker.
 *
 * Uses Cloudflare's `connect()` from `cloudflare:sockets` in production. Tests
 * inject a fake `SocketFactory` to keep unit-layer fast and offline.
 */

import { MAX_RESPONSE_BYTES } from '@blackveil/dns-checks/whois';

/** Minimal socket shape we depend on — matches `cloudflare:sockets` Socket. */
export interface SocketLike {
	writable: WritableStream<Uint8Array>;
	readable: ReadableStream<Uint8Array>;
	close(): Promise<void>;
	/** Promise that resolves when the TCP handshake completes (or rejects on connection failure). */
	opened?: Promise<unknown>;
}

/** Pluggable socket factory — production uses `cloudflare:sockets`. */
export interface SocketFactory {
	connect(opts: { hostname: string; port: number; secureTransport?: 'off' | 'on' | 'starttls' }): Promise<SocketLike>;
}

const DEFAULT_TIMEOUT_MS = 5_000;
const WHOIS_PORT = 43;

/** Reject hostnames that would target private/internal networks. */
function validateHost(hostname: string): void {
	if (!hostname || typeof hostname !== 'string') {
		throw new Error('Invalid hostname');
	}
	const lower = hostname.toLowerCase();

	// Reject localhost, loopback, IP literals — defense against SSRF.
	if (lower === 'localhost' || lower === 'ip6-localhost' || lower === 'ip6-loopback') {
		throw new Error(`Invalid hostname: ${hostname} (private/loopback)`);
	}
	// IPv4 dotted form — reject private ranges & loopback.
	const ipv4 = lower.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
	if (ipv4) {
		const [, a, b] = ipv4;
		const oct1 = parseInt(a, 10);
		const oct2 = parseInt(b, 10);
		if (
			oct1 === 10 ||
			oct1 === 127 ||
			oct1 === 0 ||
			(oct1 === 172 && oct2 >= 16 && oct2 <= 31) ||
			(oct1 === 192 && oct2 === 168) ||
			(oct1 === 169 && oct2 === 254) ||
			oct1 >= 224
		) {
			throw new Error(`Invalid hostname: ${hostname} (private/blocked IP)`);
		}
		// Reject all bare IP literals too — WHOIS servers should be named hosts.
		throw new Error(`Invalid hostname: ${hostname} (IP literal not allowed)`);
	}
	// IPv6 — reject any literal containing colons.
	if (lower.includes(':')) {
		throw new Error(`Invalid hostname: ${hostname} (IPv6 literal not allowed)`);
	}
	// Must look like a hostname: at least one dot, valid chars.
	if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/i.test(hostname)) {
		throw new Error(`Invalid hostname: ${hostname}`);
	}
	// Reject all-numeric forms (octal/numeric IPv4 bypass — e.g. "0177.0.0.1" passes
	// the IPv4 dotted check above because labels are 4 digits, but routes to 127.0.0.1).
	const labels = lower.split('.');
	if (labels.every((label) => /^[0-9]+$/.test(label))) {
		throw new Error(`Invalid hostname: ${hostname} (all-numeric labels not allowed)`);
	}
}

/**
 * Open a TCP/43 connection to a WHOIS server, send the query (CRLF-terminated),
 * collect the full response, and return as a string. Response is capped at
 * MAX_RESPONSE_BYTES and the connection is aborted on timeout.
 */
export async function whoisQuery(
	server: string,
	query: string,
	options: { timeoutMs?: number; socketFactory?: SocketFactory } = {},
): Promise<string> {
	validateHost(server);

	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const factory = options.socketFactory ?? defaultSocketFactory;
	const timeoutError = () => new Error(`WHOIS timeout after ${timeoutMs}ms`);

	let timer: ReturnType<typeof setTimeout> | undefined;
	let stopRequested = false;
	let completed = false;
	let socket: SocketLike | undefined;
	let writer: WritableStreamDefaultWriter<Uint8Array> | undefined;
	let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
	let writerAbort: Promise<void> | undefined;
	let readerCancel: Promise<void> | undefined;

	const closeSocket = (target: SocketLike): void => {
		try {
			void target.close().catch(() => undefined);
		} catch {
			// Cleanup is best-effort; preserve the original transport failure.
		}
	};
	const abortWriter = (reason: unknown): void => {
		if (!writer || writerAbort) return;
		try {
			writerAbort = writer.abort(reason).catch(() => undefined);
		} catch {
			writerAbort = Promise.resolve();
		}
	};
	const cancelReader = (reason: unknown): void => {
		if (!reader || readerCancel) return;
		try {
			readerCancel = reader.cancel(reason).catch(() => undefined);
		} catch {
			readerCancel = Promise.resolve();
		}
	};
	const releaseWriter = (): void => {
		if (!writer) return;
		const activeWriter = writer;
		const release = () => {
			try {
				activeWriter.releaseLock();
			} catch {
				// A pending write keeps the lock until abort settles.
			}
		};
		release();
		if (writerAbort) void writerAbort.finally(release);
		writer = undefined;
	};
	const releaseReader = (): void => {
		if (!reader) return;
		const activeReader = reader;
		const release = () => {
			try {
				activeReader.releaseLock();
			} catch {
				// A pending read keeps the lock until cancellation settles.
			}
		};
		release();
		if (readerCancel) void readerCancel.finally(release);
		reader = undefined;
	};

	const timeoutPromise = new Promise<never>((_, reject) => {
		timer = setTimeout(() => {
			stopRequested = true;
			reject(timeoutError());
		}, timeoutMs);
	});

	const operation = (async (): Promise<string> => {
		const connected = await factory.connect({ hostname: server, port: WHOIS_PORT });
		if (stopRequested) {
			closeSocket(connected);
			throw timeoutError();
		}
		socket = connected;

		// `connect()` may return before the TCP handshake. The one outer deadline
		// covers this wait as well as socket creation, write, and every read.
		if (socket.opened) await socket.opened;
		if (stopRequested) throw timeoutError();

		// Write the query AND complete the write before starting to read.
		// `cloudflare:sockets` has no half-close: writer.close() would close the
		// whole socket, so release the lock after a successful flush instead.
		writer = socket.writable.getWriter();
		let writeCompleted = false;
		try {
			await writer.write(new TextEncoder().encode(`${query}\r\n`));
			writeCompleted = true;
		} finally {
			if (writeCompleted) releaseWriter();
		}
		if (stopRequested) throw timeoutError();

		reader = socket.readable.getReader();
		// Fixed-size byte accumulation prevents attacker-controlled reallocations
		// and ensures an oversized chunk is bounded before any copy or decode.
		const response = new Uint8Array(MAX_RESPONSE_BYTES);
		let responseBytes = 0;

		while (responseBytes < MAX_RESPONSE_BYTES) {
			const result = await reader.read();
			if (stopRequested) throw timeoutError();
			if (result.done) break;
			if (!result.value?.byteLength) continue;

			const remaining = MAX_RESPONSE_BYTES - responseBytes;
			if (result.value.byteLength > remaining) {
				cancelReader('response too large');
				throw new Error(`WHOIS response exceeded ${MAX_RESPONSE_BYTES} bytes`);
			}

			response.set(result.value, responseBytes);
			responseBytes += result.value.byteLength;
			if (responseBytes === MAX_RESPONSE_BYTES) {
				cancelReader('response limit reached');
				break;
			}
		}

		// Decode only the bounded byte buffer. TextDecoder safely replaces an
		// incomplete final UTF-8 sequence if the byte limit splits a code point.
		return new TextDecoder().decode(response.subarray(0, responseBytes));
	})();

	try {
		const result = await Promise.race([operation, timeoutPromise]);
		completed = true;
		return result;
	} catch (error) {
		abortWriter(error);
		cancelReader(error);
		throw error;
	} finally {
		stopRequested = true;
		if (timer !== undefined) clearTimeout(timer);
		if (!completed) {
			abortWriter(timeoutError());
			cancelReader(timeoutError());
		}
		releaseWriter();
		releaseReader();
		if (socket) closeSocket(socket);
	}
}

/** Default factory uses `cloudflare:sockets`. Lazy-loaded so tests don't need it. */
const defaultSocketFactory: SocketFactory = {
	async connect(opts) {
		const { connect } = (await import('cloudflare:sockets')) as {
			connect: (o: { hostname: string; port: number; secureTransport?: string }) => SocketLike;
		};
		return connect({ ...opts, secureTransport: 'off' });
	},
};
