// SPDX-License-Identifier: BUSL-1.1

/**
 * Wire-level pin for the resource-record parser behind `parseDirectDnsResponse`
 * (`parseRecord` is module-private). Every RDATA decoder branch, and every bounds
 * check that rejects a truncated or malformed record, is exercised on a single-answer message.
 */
import { describe, expect, it } from 'vitest';
import { parseDirectDnsResponse } from '../src/lib/authoritative-dns-infra/dns-tcp';

const ID = 0x1234;

function bytes(...parts: Array<number[] | Uint8Array>): Uint8Array {
	const out: number[] = [];
	for (const part of parts) out.push(...part);
	return Uint8Array.from(out);
}

function u16(value: number): number[] {
	return [(value >> 8) & 0xff, value & 0xff];
}

function u32(value: number): number[] {
	return [(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff];
}

/** Wire form of a dotted name, e.g. name('a.test') -> 1 'a' 4 'test' 0. */
function name(value: string): number[] {
	const out: number[] = [];
	for (const label of value.split('.')) out.push(label.length, ...[...label].map((c) => c.charCodeAt(0)));
	out.push(0);
	return out;
}

/** Header (1 answer, no question) followed by `body`; `body` is the record, possibly truncated. */
function response(body: number[], answerCount = 1): Uint8Array {
	return bytes(u16(ID), u16(0x8400), u16(0), u16(answerCount), u16(0), u16(0), body);
}

function record(owner: number[], type: number, rdata: number[], declaredLength = rdata.length): number[] {
	return [...owner, ...u16(type), ...u16(1), ...u32(60), ...u16(declaredLength), ...rdata];
}

function parseSingle(body: number[]) {
	return parseDirectDnsResponse(response(body), ID).answers[0];
}

describe('parseRecord RDATA decoding', () => {
	it('decodes an A record as a dotted quad', () => {
		expect(parseSingle(record(name('a.test'), 1, [192, 0, 2, 7]))).toEqual({ name: 'a.test', type: 1, data: '192.0.2.7' });
	});

	it('leaves an A record with RDLENGTH other than 4 empty rather than guessing', () => {
		expect(parseSingle(record(name('a.test'), 1, [192, 0, 2])).data).toBe('');
		expect(parseSingle(record(name('a.test'), 1, [192, 0, 2, 7, 9])).data).toBe('');
		expect(parseSingle(record(name('a.test'), 1, [])).data).toBe('');
	});

	it('decodes an AAAA record as eight zero-padded groups', () => {
		const rdata = [0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11];
		expect(parseSingle(record(name('a.test'), 28, rdata)).data).toBe('2606:4700:0000:0000:0000:0000:0000:1111');
	});

	it.each([0, 4, 15, 17])('rejects an AAAA record of %i bytes', (length) => {
		expect(() => parseSingle(record(name('a.test'), 28, new Array<number>(length).fill(1)))).toThrow('Invalid AAAA record length');
	});

	it.each([
		[2, 'NS'],
		[5, 'CNAME'],
		[12, 'PTR'],
	])('decodes the target name of a type %i (%s) record', (type) => {
		expect(parseSingle(record(name('a.test'), type, name('ns1.example.net'))).data).toBe('ns1.example.net');
	});

	it('decodes an SOA record to its serial only', () => {
		const rdata = [
			...name('ns.test'),
			...name('hostmaster.test'),
			...u32(2026101901),
			...u32(7200),
			...u32(900),
			...u32(1209600),
			...u32(300),
		];
		expect(parseSingle(record(name('a.test'), 6, rdata)).data).toBe('2026101901');
	});

	it('rejects an SOA record whose serial is cut off', () => {
		// RDATA ends right after RNAME: the 4-byte serial that follows would run past the message.
		const rdata = [...name('ns.test'), ...name('hostmaster.test')];
		expect(() => parseSingle(record(name('a.test'), 6, rdata))).toThrow('Truncated SOA serial');
	});

	it('decodes only the first TXT character-string', () => {
		const rdata = [3, 0x66, 0x6f, 0x6f, 3, 0x62, 0x61, 0x72];
		expect(parseSingle(record(name('a.test'), 16, rdata)).data).toBe('foo');
	});

	it('caps a TXT string at the declared RDLENGTH even when its own length byte claims more', () => {
		const rdata = [200, 0x61, 0x62, 0x63];
		expect(parseSingle(record(name('a.test'), 16, rdata)).data).toBe('abc');
	});

	it('returns an empty string for a TXT record with no RDATA', () => {
		expect(parseSingle(record(name('a.test'), 16, [])).data).toBe('');
	});

	it('returns an empty string for an empty TXT character-string', () => {
		expect(parseSingle(record(name('a.test'), 16, [0])).data).toBe('');
	});

	it.each([
		[48, 'DNSKEY'],
		[46, 'RRSIG'],
		[99, 'unclassified type'],
	])('reports presence only (empty data) for type %i (%s)', (type) => {
		expect(parseSingle(record(name('a.test'), type, [1, 2, 3, 4, 5]))).toEqual({ name: 'a.test', type, data: '' });
	});

	it('parses several records across sections and advances past each RDATA', () => {
		const first = record(name('a.test'), 1, [192, 0, 2, 7]);
		const second = record(name('b.test'), 16, [2, 0x68, 0x69]);
		const parsed = parseDirectDnsResponse(response([...first, ...second], 2), ID);
		expect(parsed.answers.map((r) => r.data)).toEqual(['192.0.2.7', 'hi']);
	});
});

describe('parseRecord bounds checks', () => {
	it('rejects a record cut inside the fixed 10-byte header after the owner name', () => {
		const full = record(name('a.test'), 1, [192, 0, 2, 7]);
		const ownerLength = name('a.test').length;
		for (let keep = ownerLength; keep < ownerLength + 10; keep += 1) {
			expect(() => parseDirectDnsResponse(response(full.slice(0, keep)), ID), `keep=${keep}`).toThrow('Truncated DNS resource record');
		}
	});

	it('rejects RDATA whose declared length runs past the end of the message', () => {
		expect(() => parseSingle(record(name('a.test'), 1, [192, 0, 2, 7], 5))).toThrow('Truncated DNS RDATA');
		expect(() => parseSingle(record(name('a.test'), 16, [3, 0x66], 0xffff))).toThrow('Truncated DNS RDATA');
	});

	it('rejects a message that promises more records than it carries', () => {
		const only = record(name('a.test'), 1, [192, 0, 2, 7]);
		expect(() => parseDirectDnsResponse(response(only, 2), ID)).toThrow();
	});

	it('rejects an owner name that runs off the end of the message', () => {
		expect(() => parseSingle([5, 0x61, 0x62])).toThrow();
	});

	it('rejects an NS target that points outside the message', () => {
		expect(() => parseSingle(record(name('a.test'), 2, [0xc0, 0xff]))).toThrow();
	});

	it('accepts a record whose RDATA ends exactly at the end of the message', () => {
		const exact = record(name('a.test'), 1, [10, 0, 0, 1]);
		expect(parseDirectDnsResponse(response(exact), ID).answers).toHaveLength(1);
	});
});
