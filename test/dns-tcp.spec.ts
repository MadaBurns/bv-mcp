// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { buildDirectDnsQuery, parseDirectDnsResponse } from '../src/lib/authoritative-dns-infra/dns-tcp';

function concat(...parts: Uint8Array[]): Uint8Array {
	const output = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
	let offset = 0;
	for (const part of parts) {
		output.set(part, offset);
		offset += part.length;
	}
	return output;
}

function uint16(value: number): Uint8Array {
	const bytes = new Uint8Array(2);
	new DataView(bytes.buffer).setUint16(0, value);
	return bytes;
}

describe('direct DNS-over-TCP wire codec', () => {
	it('builds a recursion-disabled NS query', () => {
		const query = buildDirectDnsQuery('Example.COM.', 2, 0x1234);
		const view = new DataView(query.buffer);
		expect(view.getUint16(0)).toBe(0x1234);
		expect(view.getUint16(2)).toBe(0); // RD is deliberately disabled
		expect(view.getUint16(4)).toBe(1);
		expect([...query.slice(12, 25)]).toEqual([7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0]);
	});

	it('parses a compressed authoritative NS answer', () => {
		const query = buildDirectDnsQuery('example.com', 2, 0x1234);
		const header = new Uint8Array(12);
		const view = new DataView(header.buffer);
		view.setUint16(0, 0x1234);
		view.setUint16(2, 0x8400); // QR + AA
		view.setUint16(4, 1);
		view.setUint16(6, 1);
		const question = query.slice(12);
		const rdata = new Uint8Array([3, 110, 115, 49, 0xc0, 0x0c]); // ns1 + pointer to example.com
		const answer = concat(
			new Uint8Array([0xc0, 0x0c]),
			uint16(2),
			uint16(1),
			new Uint8Array([0, 0, 0, 60]),
			uint16(rdata.length),
			rdata,
		);

		const parsed = parseDirectDnsResponse(concat(header, question, answer), 0x1234);
		expect(parsed.aa).toBe(true);
		expect(parsed.rcode).toBe(0);
		expect(parsed.answers).toEqual([{ name: 'example.com', type: 2, data: 'ns1.example.com' }]);
	});
});
