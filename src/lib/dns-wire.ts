// SPDX-License-Identifier: BUSL-1.1

import { RecordType, type DohResponse, type DnsAnswer, type RecordTypeName } from './dns-types';

/** RFC 8484 query: ID zero (HTTP correlates responses), recursion desired, one IN question. */
export function encodeDnsQuery(domain: string, type: RecordTypeName): Uint8Array {
	const labels = domain.replace(/\.$/, '').split('.');
	if (labels.some((label) => !/^[\x21-\x7e]{1,63}$/.test(label))) throw new Error('Invalid DNS name');
	const bytes = new Uint8Array(12 + labels.reduce((n, label) => n + label.length + 1, 0) + 5);
	if (bytes.length > 271 || !RecordType[type]) throw new Error('Invalid DNS question');
	const view = new DataView(bytes.buffer);
	view.setUint16(2, 0x0100);
	view.setUint16(4, 1);
	let offset = 12;
	for (const label of labels) {
		bytes[offset++] = label.length;
		for (const char of label) bytes[offset++] = char.charCodeAt(0);
	}
	offset++;
	view.setUint16(offset, RecordType[type]);
	view.setUint16(offset + 2, 1);
	return bytes;
}

/** Decode bounded DNS messages. Reject malformed compression/RDATA rather than compare partial answers. */
export function decodeDnsResponse(bytes: Uint8Array, domain: string, type: RecordTypeName): DohResponse {
	const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	const need = (offset: number, length: number, end = bytes.length) => {
		if (offset < 0 || offset + length > end) throw new Error('Invalid DNS message');
	};
	const name = (start: number, end = bytes.length): { value: string; next: number } => {
		let offset = start;
		let next = -1;
		let length = 1;
		const labels: string[] = [];
		for (let hops = 0; hops < 128; hops++) {
			need(offset, 1, end);
			const size = bytes[offset++];
			if ((size & 0xc0) === 0xc0) {
				need(offset, 1, end);
				const pointer = ((size & 0x3f) << 8) | bytes[offset++];
				if (pointer >= offset - 2 || pointer < 12) throw new Error('Invalid DNS compression');
				if (next === -1) next = offset;
				offset = pointer;
				end = bytes.length;
				continue;
			}
			if (size & 0xc0) throw new Error('Invalid DNS label');
			if (!size) return { value: labels.join('.') + '.', next: next === -1 ? offset : next };
			need(offset, size, end);
			length += size + 1;
			if (length > 255) throw new Error('Invalid DNS name length');
			let label = '';
			for (let i = 0; i < size; i++) {
				const byte = bytes[offset++];
				// Hostname presentation must not create ambiguous embedded dots or controls.
				if (byte < 33 || byte > 126 || byte === 46 || byte === 92) throw new Error('Invalid DNS label byte');
				label += String.fromCharCode(byte);
			}
			labels.push(label);
		}
		throw new Error('Invalid DNS compression depth');
	};
	need(0, 12);
	const flags = view.getUint16(2);
	if (view.getUint16(0) !== 0 || (flags & 0xf800) !== 0x8000 || flags & 0x0200 || view.getUint16(4) !== 1) {
		throw new Error('Invalid DNS response header');
	}
	const question = name(12);
	need(question.next, 4);
	if (
		question.value.toLowerCase().replace(/\.$/, '') !== domain.toLowerCase().replace(/\.$/, '') ||
		view.getUint16(question.next) !== RecordType[type] ||
		view.getUint16(question.next + 2) !== 1
	) {
		throw new Error('Invalid DNS response question');
	}
	let offset = question.next + 4;
	const answers: DnsAnswer[] = [];
	const counts = [view.getUint16(6), view.getUint16(8), view.getUint16(10)];
	for (let section = 0; section < counts.length; section++) {
		for (let i = 0; i < counts[section]; i++) {
			const owner = name(offset);
			offset = owner.next;
			need(offset, 10);
			const code = view.getUint16(offset);
			const klass = view.getUint16(offset + 2);
			const ttl = view.getUint32(offset + 4);
			const size = view.getUint16(offset + 8);
			// Extended EDNS errors cannot be mistaken for an agreeing NOERROR empty answer.
			if (code === 41 && ttl >>> 24) throw new Error('Invalid DNS extended response code');
			offset += 10;
			const end = offset + size;
			need(offset, size);
			if (section === 0 && klass === 1 && code === RecordType[type]) {
				let data: string;
				if (type === 'A' && size === 4) data = Array.from(bytes.subarray(offset, end)).join('.');
				else if (type === 'AAAA' && size === 16) {
					// URL's IPv6 serializer supplies the same compressed presentation as JSON DoH.
					const groups = Array.from({ length: 8 }, (_, n) => view.getUint16(offset + n * 2).toString(16));
					data = new URL(`https://[${groups.join(':')}]/`).hostname.slice(1, -1);
				} else if (type === 'NS' || type === 'CNAME' || type === 'PTR') {
					const decoded = name(offset, end);
					if (decoded.next !== end) throw new Error('Invalid DNS name data');
					data = decoded.value;
				} else if (type === 'MX') {
					need(offset, 3, end);
					const decoded = name(offset + 2, end);
					if (decoded.next !== end) throw new Error('Invalid DNS MX data');
					data = `${view.getUint16(offset)} ${decoded.value}`;
				} else if (type === 'TXT') {
					const segments: string[] = [];
					let cursor = offset;
					while (cursor < end) {
						const length = bytes[cursor++];
						need(cursor, length, end);
						let segment = '';
						for (const byte of bytes.subarray(cursor, cursor + length)) {
							segment +=
								byte === 34 || byte === 92
									? `\\${String.fromCharCode(byte)}`
									: byte < 32 || byte > 126
										? `\\${String(byte).padStart(3, '0')}`
										: String.fromCharCode(byte);
						}
						segments.push(`"${segment}"`);
						cursor += length;
					}
					if (!segments.length) throw new Error('Invalid DNS TXT data');
					data = segments.join(' ');
				} else if (type === 'SOA') {
					const mname = name(offset, end);
					const rname = name(mname.next, end);
					if (rname.next + 20 !== end) throw new Error('Invalid DNS SOA data');
					data = `${mname.value} ${rname.value} ${Array.from({ length: 5 }, (_, n) => view.getUint32(rname.next + n * 4)).join(' ')}`;
				} else if (type === 'CAA') {
					need(offset, 2, end);
					const tagLength = bytes[offset + 1];
					need(offset + 2, tagLength, end);
					const text = (start: number, finish: number) =>
						Array.from(bytes.subarray(start, finish), (b) => {
							if (b < 32 || b > 126 || b === 34 || b === 92) throw new Error('Invalid DNS CAA text');
							return String.fromCharCode(b);
						}).join('');
					data = `${bytes[offset]} ${text(offset + 2, offset + 2 + tagLength)} "${text(offset + 2 + tagLength, end)}"`;
				} else throw new Error('Unsupported DNS answer data');
				answers.push({ name: owner.value, type: code, TTL: ttl, data });
			}
			offset = end;
		}
	}
	if (offset !== bytes.length) throw new Error('Invalid DNS trailing data');
	return {
		Status: flags & 15,
		TC: false,
		RD: !!(flags & 256),
		RA: !!(flags & 128),
		AD: !!(flags & 32),
		CD: !!(flags & 16),
		Question: [{ name: question.value, type: RecordType[type] }],
		Answer: answers,
	};
}

/** Identifies body-stream failures separately from malformed DNS payloads. */
export class DnsMessageNetworkError extends Error {}

/** Bounded binary body reader; rejects a prefix rather than interpreting it as a complete DNS message. */
export async function readDnsMessage(response: Response, maxBytes: number): Promise<Uint8Array> {
	const reader = response.body?.getReader();
	if (!reader) throw new Error('Invalid DNS body');
	const chunks: Uint8Array[] = [];
	let total = 0;
	let finished = false;
	try {
		for (;;) {
			let item: ReadableStreamReadResult<Uint8Array>;
			try {
				item = await reader.read();
			} catch {
				throw new DnsMessageNetworkError('DNS response stream failed');
			}
			const { value, done } = item;
			if (done) {
				finished = true;
				break;
			}
			if (!value) continue;
			total += value.byteLength;
			if (total > maxBytes) throw new Error('Invalid DNS body size');
			chunks.push(value);
		}
	} finally {
		if (!finished) {
			try {
				await reader.cancel();
			} catch {
				/* already aborted */
			}
		}
		reader.releaseLock();
	}
	const bytes = new Uint8Array(total);
	let offset = 0;
	for (const chunk of chunks) {
		bytes.set(chunk, offset);
		offset += chunk.length;
	}
	return bytes;
}
