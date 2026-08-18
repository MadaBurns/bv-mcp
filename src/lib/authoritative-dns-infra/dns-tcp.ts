// SPDX-License-Identifier: BUSL-1.1

/**
 * Minimal DNS-over-TCP client for direct authoritative queries.
 *
 * This deliberately supports only the record types needed by delegation
 * analysis (A, AAAA, NS). It sends RD=0 so the response is evidence from the
 * selected nameserver, not a recursive resolver projection.
 */

const DNS_PORT = 53;
const DNS_HEADER_BYTES = 12;
const DNS_CLASS_IN = 1;
const MAX_DNS_MESSAGE_BYTES = 65_535;

export interface DirectDnsRecord {
	name: string;
	type: number;
	data: string;
}

export interface DirectDnsResponse {
	aa: boolean;
	rcode: number;
	answers: DirectDnsRecord[];
	authority: DirectDnsRecord[];
	additional: DirectDnsRecord[];
}

export type DirectDnsQuery = (
	nameserver: string,
	name: string,
	type: number,
	timeoutMs?: number,
) => Promise<DirectDnsResponse>;

function encodeName(name: string): Uint8Array {
	const normalized = name.replace(/\.$/, '').toLowerCase();
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

export function buildDirectDnsQuery(name: string, type: number, id: number): Uint8Array {
	const qname = encodeName(name);
	const message = new Uint8Array(DNS_HEADER_BYTES + qname.length + 4);
	const view = new DataView(message.buffer);
	view.setUint16(0, id);
	view.setUint16(2, 0); // RD=0: ask this server directly; never recurse.
	view.setUint16(4, 1); // QDCOUNT
	message.set(qname, DNS_HEADER_BYTES);
	const tail = DNS_HEADER_BYTES + qname.length;
	view.setUint16(tail, type);
	view.setUint16(tail + 2, DNS_CLASS_IN);
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

async function readFramedResponse(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
	const reader = stream.getReader();
	let buffered = new Uint8Array(0);
	let expectedLength: number | undefined;
	try {
		while (true) {
			const { value, done } = await reader.read();
			if (done) throw new Error('DNS TCP connection closed before a full response');
			if (!value?.length) continue;
			const next = new Uint8Array(buffered.length + value.length);
			next.set(buffered);
			next.set(value, buffered.length);
			buffered = next;

			if (expectedLength === undefined && buffered.length >= 2) {
				expectedLength = new DataView(buffered.buffer, buffered.byteOffset, buffered.byteLength).getUint16(0);
				if (expectedLength === 0 || expectedLength > MAX_DNS_MESSAGE_BYTES) throw new Error('Invalid DNS TCP frame length');
			}
			if (expectedLength !== undefined && buffered.length >= expectedLength + 2) {
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
	// Keep the runtime-only module behind the execution seam so Node-side tooling
	// can import and test the wire codec without trying to resolve cloudflare: URLs.
	const { connect } = await import('cloudflare:sockets');
	const id = crypto.getRandomValues(new Uint16Array(1))[0];
	const query = buildDirectDnsQuery(name, type, id);
	const socket = connect({ hostname: nameserver, port: DNS_PORT }, { secureTransport: 'off', allowHalfOpen: true });
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
			timeoutMs,
		);
		return parseDirectDnsResponse(response, id);
	} finally {
		await socket.close().catch(() => undefined);
	}
};
