// SPDX-License-Identifier: BUSL-1.1

/**
 * Two production-only paths of dns-tcp.ts that the injected-fake specs (dns-tcp.spec.ts) never reach:
 * - `defaultNameserverAddressResolver`, the resolver `resolvePublicNameserverAddresses` falls back to when
 *   none is injected. Reached here through the DoH transport with `globalThis.fetch` mocked (dns-mock),
 *   never a live network.
 * - `ipv6Presentation`, the AAAA RDATA formatter inside the wire parser.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildDirectDnsQuery, parseDirectDnsResponse, resolvePublicNameserverAddresses } from '../src/lib/authoritative-dns-infra/dns-tcp';
import { RecordType } from '../src/lib/dns-types';
import { createDohResponse, setupFetchMock } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

const TYPE_CODES: Record<string, number> = { A: 1, NS: 2, AAAA: 28 };

function mockDoh(answersFor: (name: string, type: string) => Array<{ type: number; data: string }>): { urls: URL[] } {
	const urls: URL[] = [];
	globalThis.fetch = vi.fn().mockImplementation((url: string | URL) => {
		const u = new URL(typeof url === 'string' ? url : url.toString());
		urls.push(u);
		const name = u.searchParams.get('name') ?? '';
		const type = u.searchParams.get('type') ?? '';
		const answers = answersFor(name, type).map((answer) => ({ name, TTL: 300, ...answer }));
		return Promise.resolve(createDohResponse([{ name, type: TYPE_CODES[type] ?? -1 }], answers));
	});
	return { urls };
}

describe('resolvePublicNameserverAddresses default resolver', () => {
	it('asks DoH for A and AAAA of the normalized name and pins the canonical public literals', async () => {
		const { urls } = mockDoh((_name, type) =>
			type === 'A'
				? [
						{ type: RecordType.A, data: '1.1.1.1' },
						// A non-A answer in the same response (a CNAME chain) must be filtered out.
						{ type: RecordType.CNAME, data: 'alias.example.net.' },
					]
				: [{ type: RecordType.AAAA, data: '2606:4700:4700::1111' }],
		);

		await expect(resolvePublicNameserverAddresses('NS1.Example.NET.')).resolves.toEqual(['1.1.1.1', '2606:4700:4700:0:0:0:0:1111']);

		const asked = urls.map((u) => `${u.searchParams.get('name')}/${u.searchParams.get('type')}`).sort();
		expect(asked).toEqual(['ns1.example.net/A', 'ns1.example.net/AAAA']);
	});

	it('lowercases answers and strips a trailing dot before the routability check', async () => {
		mockDoh((_name, type) => (type === 'A' ? [{ type: RecordType.A, data: '1.0.0.1.' }] : []));

		await expect(resolvePublicNameserverAddresses('ns1.example.net')).resolves.toEqual(['1.0.0.1']);
	});

	it('fails closed when DoH answers with a private address', async () => {
		mockDoh((_name, type) => (type === 'A' ? [{ type: RecordType.A, data: '10.0.0.1' }] : []));

		await expect(resolvePublicNameserverAddresses('ns1.example.net')).rejects.toThrow('non-public');
	});

	it('fails closed with no bounded address set when DoH answers nothing, or the transport fails', async () => {
		mockDoh(() => []);
		await expect(resolvePublicNameserverAddresses('ns1.example.net')).rejects.toThrow('no bounded public address set');

		globalThis.fetch = vi.fn().mockRejectedValue(new Error('network down'));
		await expect(resolvePublicNameserverAddresses('ns1.example.net')).rejects.toThrow('no bounded public address set');
	});
});

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

/** A NOERROR response to an `example.com` query carrying one answer RR whose owner is a pointer to the question. */
function responseWithAnswer(type: number, rdata: Uint8Array): Uint8Array {
	const query = buildDirectDnsQuery('example.com', type, 0x4242);
	const header = new Uint8Array(12);
	const view = new DataView(header.buffer);
	view.setUint16(0, 0x4242);
	view.setUint16(2, 0x8400); // QR + AA
	view.setUint16(4, 1);
	view.setUint16(6, 1);
	const answer = concat(new Uint8Array([0xc0, 0x0c]), uint16(type), uint16(1), new Uint8Array([0, 0, 0, 60]), uint16(rdata.length), rdata);
	return concat(header, query.slice(12), answer);
}

describe('AAAA RDATA presentation', () => {
	it('renders all eight groups zero-padded to four hex digits, uncompressed', () => {
		const rdata = new Uint8Array([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xab, 0xcd]);

		const parsed = parseDirectDnsResponse(responseWithAnswer(28, rdata), 0x4242);

		expect(parsed.answers).toEqual([{ name: 'example.com', type: 28, data: '2001:0db8:0000:0000:0000:0000:0000:abcd' }]);
	});

	it('rejects an AAAA record whose RDATA is not exactly 16 octets', () => {
		expect(() => parseDirectDnsResponse(responseWithAnswer(28, new Uint8Array(4)), 0x4242)).toThrow('Invalid AAAA record length');
		expect(() => parseDirectDnsResponse(responseWithAnswer(28, new Uint8Array(17)), 0x4242)).toThrow('Invalid AAAA record length');
	});
});
