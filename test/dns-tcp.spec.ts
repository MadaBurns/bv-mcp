// SPDX-License-Identifier: BUSL-1.1

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Mock } from 'vitest';
import {
	buildDirectDnsQuery,
	isGloballyRoutableIp,
	parseDirectDnsResponse,
	readFirstFramedResponse,
	readFramedResponse,
	resolvePublicNameserverAddresses,
} from '../src/lib/authoritative-dns-infra/dns-tcp';

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

function uint32(value: number): Uint8Array {
	const bytes = new Uint8Array(4);
	new DataView(bytes.buffer).setUint32(0, value);
	return bytes;
}

/** A pointer to offset 12, i.e. the start of the question name in these fixtures. */
function pointerToQuestion(): Uint8Array {
	return new Uint8Array([0xc0, 0x0c]);
}

function rr(owner: Uint8Array, type: number, rdata: Uint8Array): Uint8Array {
	return concat(owner, uint16(type), uint16(1), uint32(60), uint16(rdata.length), rdata);
}

function framedStream(chunks: Uint8Array[], onCancel: () => void): ReadableStream<Uint8Array> {
	return new ReadableStream<Uint8Array>({
		start(controller) {
			for (const chunk of chunks) controller.enqueue(chunk);
		},
		cancel() {
			onCancel();
		},
	});
}

describe('direct DNS-over-TCP wire codec', () => {
	// The root zone is the only name with zero labels. `encodeName` rejected it as invalid,
	// so no `. NS` / `. SOA` / `. DNSKEY` query could be built and every LIVE root probe
	// abstained — invisible to the lane specs, which inject fake sessions.
	it('builds a query for the root zone as a single terminating octet', () => {
		const query = buildDirectDnsQuery('.', 2, 0x0001);
		expect(query.length).toBe(12 + 1 + 4);
		expect(query[12]).toBe(0);
		const view = new DataView(query.buffer);
		expect(view.getUint16(13)).toBe(2); // QTYPE NS
		expect(view.getUint16(15)).toBe(1); // QCLASS IN
	});

	it('still rejects an empty name — only an explicit "." means the root', () => {
		expect(() => buildDirectDnsQuery('', 2, 0x0001)).toThrow('Invalid DNS name');
		expect(() => buildDirectDnsQuery('a..b', 2, 0x0001)).toThrow('Invalid DNS name');
	});

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

	it('parses RA and TC independently of AA', () => {
		const query = buildDirectDnsQuery('example.com', 2, 0x5678);
		const header = new Uint8Array(12);
		const view = new DataView(header.buffer);
		view.setUint16(0, 0x5678);
		view.setUint16(2, 0x8280); // QR + TC + RA, AA deliberately unset
		view.setUint16(4, 1);
		const question = query.slice(12);

		const parsed = parseDirectDnsResponse(concat(header, question), 0x5678);
		expect(parsed.aa).toBe(false);
		expect(parsed.tc).toBe(true);
		expect(parsed.ra).toBe(true);
	});

	it('defaults to class IN and no OPT record when options are omitted', () => {
		const query = buildDirectDnsQuery('example.com', 1, 0x1111);
		const view = new DataView(query.buffer);
		expect(view.getUint16(10)).toBe(0); // ARCOUNT
		expect(view.getUint16(query.length - 2)).toBe(1); // QCLASS = IN, at the very end of the message
	});

	it('builds a CHAOS query with an EDNS0 OPT record and the DO bit set', () => {
		const query = buildDirectDnsQuery('version.bind', 16, 0x1234, { qclass: 3, dnssecOk: true });
		const view = new DataView(query.buffer);
		expect(view.getUint16(4)).toBe(1); // QDCOUNT
		expect(view.getUint16(6)).toBe(0); // ANCOUNT
		expect(view.getUint16(8)).toBe(0); // NSCOUNT
		expect(view.getUint16(10)).toBe(1); // ARCOUNT

		// version.bind = 7-byte label "version" + 4-byte label "bind" + root: 8 + 5 + 1 = 14 bytes.
		const tail = 12 + 14;
		expect(view.getUint16(tail)).toBe(16); // QTYPE = TXT
		expect(view.getUint16(tail + 2)).toBe(3); // QCLASS = CHAOS

		const optOffset = tail + 4;
		expect(query[optOffset]).toBe(0); // OPT owner is the root name
		expect(view.getUint16(optOffset + 1)).toBe(41); // OPT record type
		expect(view.getUint16(optOffset + 3)).toBe(1232); // "class" repurposed as UDP payload size
		expect(view.getUint32(optOffset + 5)).toBe(0x8000); // DO bit set; extended rcode/version both 0
		expect(view.getUint16(optOffset + 9)).toBe(0); // RDLENGTH = 0
		expect(query.length).toBe(optOffset + 11);
	});

	it('decodes an SOA serial, the first TXT character-string, and DNSKEY/RRSIG as presence-only', () => {
		const query = buildDirectDnsQuery('example.com', 6, 0x2222);
		const header = new Uint8Array(12);
		const headerView = new DataView(header.buffer);
		headerView.setUint16(0, 0x2222);
		headerView.setUint16(2, 0x8400); // QR + AA
		headerView.setUint16(4, 1); // QDCOUNT
		headerView.setUint16(6, 4); // ANCOUNT: SOA, TXT, DNSKEY, RRSIG
		const question = query.slice(12);

		const soaRdata = concat(
			pointerToQuestion(), // MNAME
			pointerToQuestion(), // RNAME
			uint32(2026092201), // SERIAL
			uint32(3600),
			uint32(600),
			uint32(1_209_600),
			uint32(60),
		);
		const soaRecord = rr(pointerToQuestion(), 6, soaRdata);

		const txtRdata = concat(
			new Uint8Array([11]),
			new TextEncoder().encode('first-chunk'),
			new Uint8Array([6]),
			new TextEncoder().encode('second'),
		);
		const txtRecord = rr(pointerToQuestion(), 16, txtRdata);

		const dnskeyRecord = rr(pointerToQuestion(), 48, new Uint8Array([1, 1, 3, 8, 0xaa, 0xbb]));
		const rrsigRecord = rr(pointerToQuestion(), 46, new Uint8Array([0, 6, 8, 2, 0, 0, 14, 16]));

		const parsed = parseDirectDnsResponse(concat(header, question, soaRecord, txtRecord, dnskeyRecord, rrsigRecord), 0x2222);

		expect(parsed.answers[0]).toEqual({ name: 'example.com', type: 6, data: '2026092201' });
		expect(parsed.answers[1]).toEqual({ name: 'example.com', type: 16, data: 'first-chunk' });
		expect(parsed.answers[2]).toEqual({ name: 'example.com', type: 48, data: '' });
		expect(parsed.answers[3]).toEqual({ name: 'example.com', type: 46, data: '' });
	});

	it('caps a TXT character-string at its 255-byte wire maximum', () => {
		const query = buildDirectDnsQuery('example.com', 16, 0x3333);
		const header = new Uint8Array(12);
		const headerView = new DataView(header.buffer);
		headerView.setUint16(0, 0x3333);
		headerView.setUint16(2, 0x8400);
		headerView.setUint16(4, 1);
		headerView.setUint16(6, 1);
		const question = query.slice(12);
		const longText = 'a'.repeat(255);
		const txtRdata = concat(new Uint8Array([255]), new TextEncoder().encode(longText));
		const txtRecord = rr(pointerToQuestion(), 16, txtRdata);

		const parsed = parseDirectDnsResponse(concat(header, question, txtRecord), 0x3333);
		expect(parsed.answers[0].data).toBe(longText);
		expect(parsed.answers[0].data.length).toBe(255);
	});

	it('parses an OPT record in the additional section without throwing', () => {
		const query = buildDirectDnsQuery('example.com', 1, 0x4444, { dnssecOk: true });
		const header = new Uint8Array(12);
		const headerView = new DataView(header.buffer);
		headerView.setUint16(0, 0x4444);
		headerView.setUint16(2, 0x8400); // QR + AA
		headerView.setUint16(4, 1); // QDCOUNT
		headerView.setUint16(10, 1); // ARCOUNT
		const question = query.slice(12);
		const optRecord = concat(new Uint8Array([0]), uint16(41), uint16(1232), uint32(0x8000), uint16(0));

		const parsed = parseDirectDnsResponse(concat(header, question, optRecord), 0x4444);
		expect(parsed.additional).toEqual([{ name: '', type: 41, data: '' }]);
	});
});

describe('direct DNS raw-socket destination policy', () => {
	it('allows ordinary public unicast IPs and rejects private or reserved ranges', () => {
		expect(isGloballyRoutableIp('1.1.1.1')).toBe(true);
		expect(isGloballyRoutableIp('2606:4700:4700::1111')).toBe(true);
		for (const blocked of [
			'0.0.0.0',
			'10.0.0.1',
			'100.64.0.1',
			'127.0.0.1',
			'169.254.169.254',
			'172.16.0.1',
			'192.168.1.1',
			'198.18.0.1',
			'192.0.2.1',
			'224.0.0.1',
			'::1',
			'::ffff:127.0.0.1',
			'fc00::1',
			'fe80::1',
			'2001:db8::1',
		]) {
			expect(isGloballyRoutableIp(blocked), blocked).toBe(false);
		}
	});

	it('returns canonical public literals that can be pinned into connect()', async () => {
		const resolver = async (_hostname: string, type: 'A' | 'AAAA') =>
			type === 'A' ? ['1.1.1.1'] : ['2606:4700:4700::1111'];

		await expect(resolvePublicNameserverAddresses('ns1.example.net.', resolver)).resolves.toEqual([
			'1.1.1.1',
			'2606:4700:4700:0:0:0:0:1111',
		]);
	});

	it('fails closed when one DNS family returns a private address', async () => {
		const resolver = async (_hostname: string, type: 'A' | 'AAAA') =>
			type === 'A' ? ['1.1.1.1', '169.254.169.254'] : ['2606:4700:4700::1111'];

		await expect(resolvePublicNameserverAddresses('ns1.example.net', resolver)).rejects.toThrow('non-public');
	});

	it('rejects private literals without invoking DNS resolution', async () => {
		let calls = 0;
		const resolver = async () => {
			calls += 1;
			return ['1.1.1.1'];
		};

		await expect(resolvePublicNameserverAddresses('127.0.0.1', resolver)).rejects.toThrow('not globally routable');
		expect(calls).toBe(0);
	});
});

describe('direct DNS TCP frame memory bounds', () => {
	it('rejects and cancels a first socket chunk larger than the DNS frame ceiling', async () => {
		let cancelled = false;
		const stream = framedStream([new Uint8Array(65_538)], () => {
			cancelled = true;
		});

		await expect(readFramedResponse(stream)).rejects.toThrow(/maximum frame size/);
		expect(cancelled).toBe(true);
	});

	it('rejects and cancels oversized trailing data before copying it', async () => {
		let cancelled = false;
		const partialFrame = concat(uint16(4), new Uint8Array([0xaa]));
		const stream = framedStream([partialFrame, new Uint8Array(65_535)], () => {
			cancelled = true;
		});

		await expect(readFramedResponse(stream)).rejects.toThrow(/maximum frame size|trailing frame data/);
		expect(cancelled).toBe(true);
	});
});

describe('first-framed-response reader (AXFR refusal probe)', () => {
	it('returns frame 1 and cancels when a second frame arrives in the same chunk', async () => {
		let cancelled = false;
		const frame1 = concat(uint16(4), new Uint8Array([1, 2, 3, 4]));
		const frame2 = concat(uint16(4), new Uint8Array([9, 9, 9, 9]));
		const stream = framedStream([concat(frame1, frame2)], () => {
			cancelled = true;
		});

		const result = await readFirstFramedResponse(stream);
		expect([...result]).toEqual([1, 2, 3, 4]);
		expect(cancelled).toBe(true);
	});

	it('returns frame 1 when it is split across chunks and a second frame trails after', async () => {
		let cancelled = false;
		const frame1 = concat(uint16(6), new Uint8Array([1, 2, 3, 4, 5, 6]));
		const frame2 = concat(uint16(4), new Uint8Array([9, 9, 9, 9]));
		const stream = framedStream([frame1.slice(0, 3), concat(frame1.slice(3), frame2)], () => {
			cancelled = true;
		});

		const result = await readFirstFramedResponse(stream);
		expect([...result]).toEqual([1, 2, 3, 4, 5, 6]);
		expect(cancelled).toBe(true);
	});

	it('never buffers past the fixed frame bound even with a large trailing chunk', async () => {
		let cancelled = false;
		const frame1 = concat(uint16(3), new Uint8Array([7, 8, 9]));
		const trailing = new Uint8Array(65_535); // pushes the single chunk near the frame ceiling
		const stream = framedStream([concat(frame1, trailing)], () => {
			cancelled = true;
		});

		const result = await readFirstFramedResponse(stream);
		expect([...result]).toEqual([7, 8, 9]);
		expect(cancelled).toBe(true);
	});
});

// The session opens a real socket via a dynamic `import('cloudflare:sockets')`, so it's
// mocked at that virtual specifier and exercised with a fake in-memory duplex.
let connectSpy: Mock<(...args: unknown[]) => unknown>;

vi.mock('cloudflare:sockets', () => ({
	connect: (...args: unknown[]) => connectSpy(...args),
}));

interface FakeSocket {
	opened: Promise<unknown>;
	closed: Promise<void>;
	readable: ReadableStream<Uint8Array>;
	writable: WritableStream<Uint8Array>;
	close: ReturnType<typeof vi.fn>;
}

/** Echoes a framed response (built from the outgoing query's transaction id) back on the readable side. */
function fakeDnsSocket(buildResponse: (queryId: number) => Uint8Array): FakeSocket {
	let controller: ReadableStreamDefaultController<Uint8Array> | undefined;
	const readable = new ReadableStream<Uint8Array>({
		start(c) {
			controller = c;
		},
	});
	const writable = new WritableStream<Uint8Array>({
		write(chunk: Uint8Array) {
			const view = new DataView(chunk.buffer, chunk.byteOffset, chunk.byteLength);
			const queryId = view.getUint16(2); // framed: [len(2)][id(2) ...]
			const responseMessage = buildResponse(queryId);
			controller?.enqueue(concat(uint16(responseMessage.length), responseMessage));
		},
	});
	return {
		opened: Promise.resolve({}),
		closed: new Promise<void>(() => undefined),
		readable,
		writable,
		close: vi.fn(async () => undefined),
	};
}

function minimalResponse(id: number): Uint8Array {
	const header = new Uint8Array(12);
	new DataView(header.buffer).setUint16(0, id);
	new DataView(header.buffer).setUint16(2, 0x8400); // QR + AA, no question/answer sections
	return header;
}

describe('DNS TCP session (one socket, sequential multi-query per RFC 7766)', () => {
	beforeEach(() => {
		connectSpy = vi.fn<(...args: unknown[]) => unknown>();
	});

	afterEach(() => {
		vi.clearAllMocks();
	});

	it('runs 3 queries fired concurrently over one fake duplex strictly sequentially, each with a fresh id', async () => {
		const { openDnsTcpSession } = await import('../src/lib/authoritative-dns-infra/dns-tcp');
		const seenIds: number[] = [];
		const socket = fakeDnsSocket((id) => {
			seenIds.push(id);
			return minimalResponse(id);
		});
		connectSpy.mockReturnValue(socket);

		const session = await openDnsTcpSession('1.1.1.1', 5000);
		expect(connectSpy).toHaveBeenCalledTimes(1);
		expect(connectSpy).toHaveBeenCalledWith({ hostname: '1.1.1.1', port: 53 }, expect.any(Object));

		// Fired without awaiting in between: if the session pipelined these onto one
		// socket instead of serializing them, getReader()/getWriter() would throw on an
		// already-locked stream, or a response would be read by the wrong query and fail
		// the transaction-id check inside parseDirectDnsResponse.
		const results = await Promise.all([
			session.query('a.example.com', 1),
			session.query('b.example.com', 1),
			session.query('c.example.com', 1),
		]);

		expect(results.every((result) => result.aa === true)).toBe(true);
		expect(seenIds).toHaveLength(3);
		expect(new Set(seenIds).size).toBe(3); // fresh id per query

		await session.close();
		expect(socket.close).toHaveBeenCalledTimes(1);
		await session.close(); // idempotent
		expect(socket.close).toHaveBeenCalledTimes(1);
	});

	it('refuses a hostname before opening a socket', async () => {
		const { openDnsTcpSession } = await import('../src/lib/authoritative-dns-infra/dns-tcp');
		await expect(openDnsTcpSession('ns1.example.com', 1000)).rejects.toThrow('globally routable IP literal');
		expect(connectSpy).not.toHaveBeenCalled();
	});

	it('refuses a private or loopback IP literal before opening a socket', async () => {
		const { openDnsTcpSession } = await import('../src/lib/authoritative-dns-infra/dns-tcp');
		await expect(openDnsTcpSession('127.0.0.1', 1000)).rejects.toThrow('globally routable IP literal');
		await expect(openDnsTcpSession('10.0.0.1', 1000)).rejects.toThrow('globally routable IP literal');
		expect(connectSpy).not.toHaveBeenCalled();
	});
});
