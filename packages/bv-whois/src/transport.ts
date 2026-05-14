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
	if (labels.every(label => /^[0-9]+$/.test(label))) {
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

	const socket = await factory.connect({ hostname: server, port: WHOIS_PORT });

	// Fire-and-await the write, but don't let it pin the whole budget.
	const writer = socket.writable.getWriter();
	const writePromise = (async () => {
		await writer.write(new TextEncoder().encode(`${query}\r\n`));
		await writer.close();
	})().catch(() => { /* socket errors will surface on read */ });

	const reader = socket.readable.getReader();
	const decoder = new TextDecoder();
	const chunks: string[] = [];
	let totalBytes = 0;

	const deadline = Date.now() + timeoutMs;

	try {
		while (true) {
			const remaining = deadline - Date.now();
			if (remaining <= 0) {
				throw new Error(`WHOIS timeout after ${timeoutMs}ms`);
			}

			const readPromise = reader.read();
			const timeoutPromise = new Promise<never>((_, reject) =>
				setTimeout(() => reject(new Error(`WHOIS timeout after ${timeoutMs}ms`)), remaining),
			);

			const result = await Promise.race([readPromise, timeoutPromise]);
			if (result.done) break;

			chunks.push(decoder.decode(result.value, { stream: true }));
			totalBytes += result.value.byteLength;

			if (totalBytes >= MAX_RESPONSE_BYTES) {
				try { await reader.cancel('response too large'); } catch { /* ignore */ }
				break;
			}
		}
		chunks.push(decoder.decode());
	} finally {
		try { reader.releaseLock(); } catch { /* ignore */ }
		try { await socket.close(); } catch { /* ignore */ }
		await writePromise;
	}

	const full = chunks.join('');
	return full.length > MAX_RESPONSE_BYTES ? full.slice(0, MAX_RESPONSE_BYTES) : full;
}

/** Default factory uses `cloudflare:sockets`. Lazy-loaded so tests don't need it. */
const defaultSocketFactory: SocketFactory = {
	async connect(opts) {
		const { connect } = (await import('cloudflare:sockets')) as { connect: (o: { hostname: string; port: number; secureTransport?: string }) => SocketLike };
		return connect({ ...opts, secureTransport: 'off' });
	},
};
