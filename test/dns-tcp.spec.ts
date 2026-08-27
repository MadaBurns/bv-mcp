// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import {
	buildDirectDnsQuery,
	isGloballyRoutableIp,
	parseDirectDnsResponse,
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
