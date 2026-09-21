// SPDX-License-Identifier: BUSL-1.1

/**
 * Minimal DNS-over-TCP client for direct authoritative queries.
 *
 * This deliberately supports only the record types needed by delegation
 * analysis (A, AAAA, NS). It sends RD=0 so the response is evidence from the
 * selected nameserver, not a recursive resolver projection.
 */

import { queryDns } from '../dns-transport';
import { RecordType, type RecordTypeName } from '../dns-types';

const DNS_PORT = 53;
const DNS_HEADER_BYTES = 12;
const DNS_CLASS_IN = 1;
const MAX_DNS_MESSAGE_BYTES = 65_535;
const MAX_NAMESERVER_ADDRESSES = 16;
// EDNS0 OPT pseudo-RR (RFC 6891): root owner + type(2) + class-as-udp-size(2) +
// ttl-as-extended-flags(4) + rdlength(2), no options.
const OPT_RECORD_TYPE = 41;
const EDNS0_UDP_PAYLOAD_SIZE = 1232;
const EDNS0_DO_BIT = 0x0000_8000;
const OPT_RECORD_BYTES = 11;

export interface DirectDnsRecord {
	name: string;
	type: number;
	data: string;
}

export interface DirectDnsResponse {
	aa: boolean;
	// Optional so existing fakes and fixtures that build a response literal keep compiling;
	// `parseDirectDnsResponse` always sets both. Read them as `=== true`.
	ra?: boolean;
	tc?: boolean;
	rcode: number;
	answers: DirectDnsRecord[];
	authority: DirectDnsRecord[];
	additional: DirectDnsRecord[];
}

/** Options for `buildDirectDnsQuery`. RD is never settable here: it stays 0 always. */
export interface DirectQueryOptions {
	/** Query class. Defaults to IN (1). CHAOS is 3 (`version.bind` / `id.server`). */
	qclass?: number;
	/** When true, append one EDNS0 OPT RR with the DNSSEC OK (DO) bit set. */
	dnssecOk?: boolean;
}

export type DirectDnsQuery = (
	nameserver: string,
	name: string,
	type: number,
	timeoutMs?: number,
) => Promise<DirectDnsResponse>;

export type NameserverAddressResolver = (
	nameserver: string,
	type: Extract<RecordTypeName, 'A' | 'AAAA'>,
	timeoutMs: number,
) => Promise<string[]>;

function parseIpv4(address: string): number[] | null {
	const parts = address.split('.');
	if (parts.length !== 4) return null;
	const octets: number[] = [];
	for (const part of parts) {
		if (!/^(?:0|[1-9]\d{0,2})$/.test(part)) return null;
		const value = Number(part);
		if (!Number.isSafeInteger(value) || value > 255) return null;
		octets.push(value);
	}
	return octets;
}

function parseIpv6(address: string): number[] | null {
	if (!address.includes(':') || address.includes('%')) return null;
	const halves = address.toLowerCase().split('::');
	if (halves.length > 2) return null;

	const parseHalf = (half: string): number[] | null => {
		if (!half) return [];
		const tokens = half.split(':');
		const groups: number[] = [];
		for (let index = 0; index < tokens.length; index += 1) {
			const token = tokens[index];
			if (token.includes('.')) {
				if (index !== tokens.length - 1) return null;
				const ipv4 = parseIpv4(token);
				if (!ipv4) return null;
				groups.push((ipv4[0] << 8) | ipv4[1], (ipv4[2] << 8) | ipv4[3]);
				continue;
			}
			if (!/^[0-9a-f]{1,4}$/.test(token)) return null;
			groups.push(Number.parseInt(token, 16));
		}
		return groups;
	};

	const left = parseHalf(halves[0]);
	const right = parseHalf(halves[1] ?? '');
	if (!left || !right) return null;
	if (halves.length === 1) return left.length === 8 ? left : null;
	if (left.length + right.length >= 8) return null; // `::` must compress at least one group.
	return [...left, ...Array(8 - left.length - right.length).fill(0), ...right];
}

/** Conservative global-unicast allowlist for raw socket destinations. */
export function isGloballyRoutableIp(address: string): boolean {
	const ipv4 = parseIpv4(address);
	if (ipv4) {
		const [a, b, c] = ipv4;
		if (a === 0 || a === 10 || a === 127) return false;
		if (a === 100 && b >= 64 && b <= 127) return false; // shared address space
		if (a === 169 && b === 254) return false;
		if (a === 172 && b >= 16 && b <= 31) return false;
		if (a === 192 && b === 0 && c === 0) return false;
		if (a === 192 && b === 0 && c === 2) return false;
		if (a === 192 && b === 88 && c === 99) return false;
		if (a === 192 && b === 168) return false;
		if (a === 198 && (b === 18 || b === 19)) return false;
		if (a === 198 && b === 51 && c === 100) return false;
		if (a === 203 && b === 0 && c === 113) return false;
		if (a >= 224) return false; // multicast, reserved, limited broadcast
		return true;
	}

	const ipv6 = parseIpv6(address);
	if (!ipv6) return false;
	const [first, second] = ipv6;
	// Current global unicast allocation is 2000::/3. Staying inside that prefix
	// is intentionally conservative for a DNS server that must be public.
	if (first < 0x2000 || first > 0x3fff) return false;
	if (first === 0x2001 && second <= 0x01ff) return false; // IETF special-purpose space
	if (first === 0x2001 && second === 0x0db8) return false; // documentation
	if (first === 0x2002 || first === 0x3ffe) return false; // deprecated 6to4 / 6bone
	return true;
}

function canonicalIp(address: string): string | null {
	const ipv4 = parseIpv4(address);
	if (ipv4) return ipv4.join('.');
	const ipv6 = parseIpv6(address);
	return ipv6 ? ipv6.map((group) => group.toString(16)).join(':') : null;
}

async function defaultNameserverAddressResolver(
	nameserver: string,
	type: Extract<RecordTypeName, 'A' | 'AAAA'>,
	timeoutMs: number,
): Promise<string[]> {
	const response = await queryDns(nameserver, type, false, {
		timeoutMs,
		retries: 0,
		confirmWithSecondaryOnEmpty: false,
	});
	return (response.Answer ?? [])
		.filter((answer) => answer.type === RecordType[type])
		.map((answer) => answer.data.replace(/\.$/, '').toLowerCase());
}

/** Resolve once through trusted DoH, reject mixed/private answers, then return IP literals for socket pinning. */
export async function resolvePublicNameserverAddresses(
	nameserver: string,
	resolver: NameserverAddressResolver = defaultNameserverAddressResolver,
	timeoutMs = 2_500,
): Promise<string[]> {
	const normalized = nameserver.trim().replace(/\.$/, '').toLowerCase();
	const literal = canonicalIp(normalized);
	if (literal) {
		if (!isGloballyRoutableIp(literal)) throw new Error('Nameserver address is not globally routable');
		return [literal];
	}
	if (normalized.includes(':') || /^\d+(?:\.\d+){1,3}$/.test(normalized)) {
		throw new Error('Invalid nameserver address');
	}
	if (
		normalized.length > 253 ||
		!normalized.includes('.') ||
		normalized.split('.').some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
	) {
		throw new Error('Invalid nameserver hostname');
	}

	const settled = await Promise.allSettled([
		resolver(normalized, 'A', timeoutMs),
		resolver(normalized, 'AAAA', timeoutMs),
	]);
	const rawAddresses = settled.flatMap((result) => (result.status === 'fulfilled' ? result.value : []));
	if (rawAddresses.length === 0 || rawAddresses.length > MAX_NAMESERVER_ADDRESSES) {
		throw new Error('Nameserver has no bounded public address set');
	}
	const addresses = [...new Set(rawAddresses.map((address) => canonicalIp(address)))];
	if (addresses.some((address) => address === null || !isGloballyRoutableIp(address))) {
		throw new Error('Nameserver resolution included a non-public address');
	}
	return (addresses as string[]).sort();
}

function encodeName(name: string): Uint8Array {
	const normalized = name.replace(/\.$/, '').toLowerCase();
	// The root zone is the one legal name with zero labels: a single terminating octet.
	// Without this, `.` was rejected as invalid, so no root-zone query (`. NS`, `. SOA`,
	// `. DNSKEY`) could ever be built and every live root probe abstained. An EMPTY string
	// is still rejected — only an explicit `.` means the root.
	if (name === '.') return new Uint8Array([0]);
	const labels = normalized.split('.');
	if (!normalized || labels.some((label) => label.length === 0 || label.length > 63)) {
		throw new Error('Invalid DNS name');
	}

	const encoder = new TextEncoder();
	const encodedLabels = labels.map((label) => encoder.encode(label));
	const size = encodedLabels.reduce((total, label) => total + 1 + label.length, 1);
	if (size > 255) throw new Error('DNS name is too long');

	const output = new Uint8Array(size);
	let offset = 0;
	for (const label of encodedLabels) {
		output[offset++] = label.length;
		output.set(label, offset);
		offset += label.length;
	}
	output[offset] = 0;
	return output;
}

export function buildDirectDnsQuery(name: string, type: number, id: number, options?: DirectQueryOptions): Uint8Array {
	const qname = encodeName(name);
	const qclass = options?.qclass ?? DNS_CLASS_IN;
	const dnssecOk = options?.dnssecOk === true;
	const message = new Uint8Array(DNS_HEADER_BYTES + qname.length + 4 + (dnssecOk ? OPT_RECORD_BYTES : 0));
	const view = new DataView(message.buffer);
	view.setUint16(0, id);
	view.setUint16(2, 0); // RD=0: ask this server directly; never recurse.
	view.setUint16(4, 1); // QDCOUNT
	view.setUint16(10, dnssecOk ? 1 : 0); // ARCOUNT
	message.set(qname, DNS_HEADER_BYTES);
	const tail = DNS_HEADER_BYTES + qname.length;
	view.setUint16(tail, type);
	view.setUint16(tail + 2, qclass);
	if (dnssecOk) {
		const optOffset = tail + 4;
		message[optOffset] = 0; // root owner name
		view.setUint16(optOffset + 1, OPT_RECORD_TYPE);
		view.setUint16(optOffset + 3, EDNS0_UDP_PAYLOAD_SIZE); // "class" repurposed as UDP payload size
		view.setUint32(optOffset + 5, EDNS0_DO_BIT); // extended-rcode(0) + version(0) + DO flag + Z(0)
		view.setUint16(optOffset + 9, 0); // RDLENGTH=0, no options
	}
	return message;
}

interface DecodedName {
	name: string;
	nextOffset: number;
}

function decodeName(message: Uint8Array, startOffset: number): DecodedName {
	const labels: string[] = [];
	const visited = new Set<number>();
	const decoder = new TextDecoder();
	let offset = startOffset;
	let nextOffset = startOffset;
	let jumped = false;

	for (let hops = 0; hops < 128; hops += 1) {
		if (offset >= message.length || visited.has(offset)) throw new Error('Malformed compressed DNS name');
		visited.add(offset);
		const length = message[offset];

		if ((length & 0xc0) === 0xc0) {
			if (offset + 1 >= message.length) throw new Error('Truncated DNS compression pointer');
			const pointer = ((length & 0x3f) << 8) | message[offset + 1];
			if (!jumped) nextOffset = offset + 2;
			offset = pointer;
			jumped = true;
			continue;
		}
		if ((length & 0xc0) !== 0) throw new Error('Unsupported DNS label encoding');
		if (length === 0) {
			if (!jumped) nextOffset = offset + 1;
			return { name: labels.join('.').toLowerCase(), nextOffset };
		}

		const labelStart = offset + 1;
		const labelEnd = labelStart + length;
		if (labelEnd > message.length) throw new Error('Truncated DNS label');
		labels.push(decoder.decode(message.subarray(labelStart, labelEnd)));
		offset = labelEnd;
		if (!jumped) nextOffset = offset;
	}

	throw new Error('DNS compression chain is too deep');
}

function ipv6Presentation(bytes: Uint8Array): string {
	if (bytes.length !== 16) throw new Error('Invalid AAAA record length');
	const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	const groups: string[] = [];
	for (let i = 0; i < 8; i += 1) groups.push(view.getUint16(i * 2).toString(16).padStart(4, '0'));
	return groups.join(':');
}

function parseRecord(message: Uint8Array, startOffset: number): { record: DirectDnsRecord; nextOffset: number } {
	const owner = decodeName(message, startOffset);
	if (owner.nextOffset + 10 > message.length) throw new Error('Truncated DNS resource record');
	const view = new DataView(message.buffer, message.byteOffset, message.byteLength);
	const type = view.getUint16(owner.nextOffset);
	const dataLength = view.getUint16(owner.nextOffset + 8);
	const dataOffset = owner.nextOffset + 10;
	const nextOffset = dataOffset + dataLength;
	if (nextOffset > message.length) throw new Error('Truncated DNS RDATA');

	let data = '';
	if (type === 1 && dataLength === 4) {
		data = [...message.subarray(dataOffset, nextOffset)].join('.');
	} else if (type === 28) {
		data = ipv6Presentation(message.subarray(dataOffset, nextOffset));
	} else if (type === 2 || type === 5 || type === 12) {
		data = decodeName(message, dataOffset).name;
	} else if (type === 6) {
		// SOA -> serial only, as a decimal string (skip MNAME/RNAME via decodeName).
		const mname = decodeName(message, dataOffset);
		const rname = decodeName(message, mname.nextOffset);
		if (rname.nextOffset + 4 > message.length) throw new Error('Truncated SOA serial');
		data = String(view.getUint32(rname.nextOffset));
	} else if (type === 16) {
		// TXT -> first character-string only, capped at 255 bytes (its own max length).
		if (dataLength >= 1) {
			const txtLength = Math.min(message[dataOffset], 255, dataLength - 1);
			const txtStart = dataOffset + 1;
			data = new TextDecoder().decode(message.subarray(txtStart, txtStart + txtLength));
		}
	} else if (type === 48 || type === 46) {
		// DNSKEY / RRSIG -> presence only, RDATA is not decoded.
		data = '';
	}

	return { record: { name: owner.name, type, data }, nextOffset };
}

export function parseDirectDnsResponse(message: Uint8Array, expectedId: number): DirectDnsResponse {
	if (message.length < DNS_HEADER_BYTES) throw new Error('Truncated DNS response');
	const view = new DataView(message.buffer, message.byteOffset, message.byteLength);
	if (view.getUint16(0) !== expectedId) throw new Error('DNS transaction ID mismatch');
	const flags = view.getUint16(2);
	if ((flags & 0x8000) === 0) throw new Error('DNS packet is not a response');

	const questionCount = view.getUint16(4);
	const sectionCounts = [view.getUint16(6), view.getUint16(8), view.getUint16(10)];
	let offset = DNS_HEADER_BYTES;
	for (let i = 0; i < questionCount; i += 1) {
		const question = decodeName(message, offset);
		offset = question.nextOffset + 4;
		if (offset > message.length) throw new Error('Truncated DNS question');
	}

	const sections: DirectDnsRecord[][] = [[], [], []];
	for (let section = 0; section < sections.length; section += 1) {
		for (let i = 0; i < sectionCounts[section]; i += 1) {
			const parsed = parseRecord(message, offset);
			sections[section].push(parsed.record);
			offset = parsed.nextOffset;
		}
	}

	return {
		aa: (flags & 0x0400) !== 0,
		tc: (flags & 0x0200) !== 0,
		ra: (flags & 0x0080) !== 0,
		rcode: flags & 0x000f,
		answers: sections[0],
		authority: sections[1],
		additional: sections[2],
	};
}

function frameQuery(message: Uint8Array): Uint8Array {
	const framed = new Uint8Array(message.length + 2);
	new DataView(framed.buffer).setUint16(0, message.length);
	framed.set(message, 2);
	return framed;
}

export async function readFramedResponse(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
	const reader = stream.getReader();
	const maxFrameBytes = MAX_DNS_MESSAGE_BYTES + 2;
	// One fixed, protocol-sized buffer avoids attacker-controlled realloc/copy
	// amplification as socket chunks arrive. Never copy a byte until both the
	// per-chunk and cumulative bounds have been checked.
	const buffered = new Uint8Array(maxFrameBytes);
	let bufferedLength = 0;
	let expectedLength: number | undefined;
	const rejectFrame = async (message: string): Promise<never> => {
		await reader.cancel(message).catch(() => undefined);
		throw new Error(message);
	};
	try {
		while (true) {
			const { value, done } = await reader.read();
			if (done) throw new Error('DNS TCP connection closed before a full response');
			if (!value?.length) continue;
			if (value.length > maxFrameBytes - bufferedLength) {
				return rejectFrame('DNS TCP response exceeded the maximum frame size');
			}
			if (expectedLength !== undefined && value.length > expectedLength + 2 - bufferedLength) {
				return rejectFrame('DNS TCP response contained trailing frame data');
			}
			buffered.set(value, bufferedLength);
			bufferedLength += value.length;

			if (expectedLength === undefined && bufferedLength >= 2) {
				expectedLength = new DataView(buffered.buffer, 0, 2).getUint16(0);
				if (expectedLength === 0 || expectedLength > MAX_DNS_MESSAGE_BYTES) {
					return rejectFrame('Invalid DNS TCP frame length');
				}
				if (bufferedLength > expectedLength + 2) {
					return rejectFrame('DNS TCP response contained trailing frame data');
				}
			}
			if (expectedLength !== undefined && bufferedLength === expectedLength + 2) {
				return buffered.slice(2, expectedLength + 2);
			}
		}
	} finally {
		reader.releaseLock();
	}
}

/**
 * Like `readFramedResponse`, but for a probe that must hang up after the
 * first message no matter what the server keeps sending next (an AXFR
 * refusal test: never let a zone transfer accumulate in memory). Same fixed,
 * protocol-sized buffer discipline; any bytes beyond frame 1 are truncated at
 * the copy step rather than buffered, and the reader is cancelled as soon as
 * frame 1 completes.
 */
export async function readFirstFramedResponse(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
	const reader = stream.getReader();
	const maxFrameBytes = MAX_DNS_MESSAGE_BYTES + 2;
	const buffered = new Uint8Array(maxFrameBytes);
	let bufferedLength = 0;
	let expectedLength: number | undefined;

	try {
		while (true) {
			const { value, done } = await reader.read();
			if (done) throw new Error('DNS TCP connection closed before a full response');
			if (!value?.length) continue;

			// Never copy past the frame boundary (once known) or past the fixed
			// buffer (before it's known); anything beyond that is discarded.
			const remainingFrameBytes = expectedLength === undefined ? maxFrameBytes - bufferedLength : expectedLength + 2 - bufferedLength;
			const usable = value.length > remainingFrameBytes ? value.subarray(0, remainingFrameBytes) : value;
			buffered.set(usable, bufferedLength);
			bufferedLength += usable.length;

			if (expectedLength === undefined && bufferedLength >= 2) {
				expectedLength = new DataView(buffered.buffer, 0, 2).getUint16(0);
				if (expectedLength === 0 || expectedLength > MAX_DNS_MESSAGE_BYTES) {
					await reader.cancel('Invalid DNS TCP frame length').catch(() => undefined);
					throw new Error('Invalid DNS TCP frame length');
				}
				if (bufferedLength > expectedLength + 2) bufferedLength = expectedLength + 2;
			}

			if (expectedLength !== undefined && bufferedLength === expectedLength + 2) {
				await reader.cancel('DNS TCP first-frame response complete; discarding anything further').catch(() => undefined);
				return buffered.slice(2, expectedLength + 2);
			}
		}
	} finally {
		reader.releaseLock();
	}
}

async function withTimeout<T>(operation: Promise<T>, timeoutMs: number): Promise<T> {
	let timer: ReturnType<typeof setTimeout> | undefined;
	try {
		return await Promise.race([
			operation,
			new Promise<never>((_, reject) => {
				timer = setTimeout(() => reject(new Error('Direct DNS query timed out')), timeoutMs);
			}),
		]);
	} finally {
		if (timer !== undefined) clearTimeout(timer);
	}
}

export const directDnsQuery: DirectDnsQuery = async (nameserver, name, type, timeoutMs = 2500) => {
	const startedAt = Date.now();
	const pinnedAddresses = await withTimeout(resolvePublicNameserverAddresses(nameserver, defaultNameserverAddressResolver, timeoutMs), timeoutMs);
	const pinnedAddress = pinnedAddresses[0];
	const remainingMs = Math.max(1, timeoutMs - (Date.now() - startedAt));
	// Keep the runtime-only module behind the execution seam so Node-side tooling
	// can import and test the wire codec without trying to resolve cloudflare: URLs.
	const { connect } = await import('cloudflare:sockets');
	const id = crypto.getRandomValues(new Uint16Array(1))[0];
	const query = buildDirectDnsQuery(name, type, id);
	// Connect to the validated IP literal, never the attacker-controlled hostname.
	// This removes the second DNS lookup where a rebinding target could change.
	const socket = connect({ hostname: pinnedAddress, port: DNS_PORT }, { secureTransport: 'off', allowHalfOpen: true });
	void socket.closed.catch(() => undefined);

	try {
		const response = await withTimeout(
			(async () => {
				await socket.opened;
				const writer = socket.writable.getWriter();
				try {
					await writer.write(frameQuery(query));
				} finally {
					writer.releaseLock();
				}
				return readFramedResponse(socket.readable);
			})(),
			remainingMs,
		);
		return parseDirectDnsResponse(response, id);
	} finally {
		await socket.close().catch(() => undefined);
	}
};

/** A single TCP connection to one authoritative address, used for multiple sequential queries (RFC 7766). */
export interface DnsTcpSession {
	/** Writes one framed query and reads exactly one framed response before resolving. Never pipelined. */
	query(name: string, type: number, options?: DirectQueryOptions): Promise<DirectDnsResponse>;
	/** Idempotent; always closes the underlying socket. */
	close(): Promise<void>;
}

export type DnsTcpSessionFactory = (pinnedAddress: string, timeoutMs: number) => Promise<DnsTcpSession>;

/**
 * Opens one TCP socket to a pinned IP literal and lets the caller run several
 * queries over it sequentially, sharing a single overall deadline. The
 * address is never a hostname: it must already have passed
 * `isGloballyRoutableIp` (SSRF pinning happens once, before this is called;
 * this function refuses to connect otherwise).
 */
export const openDnsTcpSession: DnsTcpSessionFactory = async (pinnedAddress, timeoutMs) => {
	if (!isGloballyRoutableIp(pinnedAddress)) {
		throw new Error('DNS TCP session requires a globally routable IP literal');
	}

	const deadline = Date.now() + timeoutMs;
	// Keep the runtime-only module behind the execution seam so Node-side tooling
	// can import and test the wire codec without trying to resolve cloudflare: URLs.
	const { connect } = await import('cloudflare:sockets');
	const socket = connect({ hostname: pinnedAddress, port: DNS_PORT }, { secureTransport: 'off', allowHalfOpen: true });
	void socket.closed.catch(() => undefined);

	let closed = false;
	const close = async (): Promise<void> => {
		if (closed) return;
		closed = true;
		await socket.close().catch(() => undefined);
	};

	// Chains queries onto the previous one so the wire is never pipelined, even
	// if a caller fires several `query()` calls without awaiting between them.
	let pending: Promise<unknown> = Promise.resolve();

	const query = (name: string, type: number, options?: DirectQueryOptions): Promise<DirectDnsResponse> => {
		const run = async (): Promise<DirectDnsResponse> => {
			if (closed) throw new Error('DNS TCP session is closed');
			const remainingMs = deadline - Date.now();
			if (remainingMs <= 0) throw new Error('DNS TCP session deadline exceeded');
			const id = crypto.getRandomValues(new Uint16Array(1))[0];
			const built = buildDirectDnsQuery(name, type, id, options);
			return withTimeout(
				(async () => {
					await socket.opened;
					const writer = socket.writable.getWriter();
					try {
						await writer.write(frameQuery(built));
					} finally {
						writer.releaseLock();
					}
					const response = await readFramedResponse(socket.readable);
					return parseDirectDnsResponse(response, id);
				})(),
				remainingMs,
			);
		};
		const result = pending.then(run, run);
		pending = result.then(
			() => undefined,
			() => undefined,
		);
		return result;
	};

	return { query, close };
};
