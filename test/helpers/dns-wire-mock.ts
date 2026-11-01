// SPDX-License-Identifier: BUSL-1.1

import { vi } from 'vitest';
import { RecordType } from '../../src/lib/dns-types';

/** Convert small synthetic JSON fixtures to RFC 8484 responses for the wire-only providers. */
export function mockResolverFetch(implementation: (url: string | URL, init?: RequestInit) => Promise<Response>) {
	globalThis.fetch = vi.fn().mockImplementation(async (url: string | URL, init?: RequestInit) => {
		let fixtureUrl = url;
		if (new Headers(init?.headers).get('Accept') === 'application/dns-message') {
			const query = new Uint8Array(init?.body as ArrayBuffer);
			let offset = 12;
			const labels: string[] = [];
			while (query[offset]) {
				const size = query[offset++];
				labels.push(String.fromCharCode(...query.subarray(offset, offset + size)));
				offset += size;
			}
			const type = new DataView(query.buffer).getUint16(offset + 1);
			const fixture = new URL(String(url));
			fixture.searchParams.set('name', labels.join('.'));
			fixture.searchParams.set('type', Object.entries(RecordType).find(([, code]) => code === type)?.[0] ?? 'A');
			fixtureUrl = fixture;
		}
		const response = await implementation(fixtureUrl, init);
		if (new Headers(init?.headers).get('Accept') !== 'application/dns-message') return response;
		const json = (await response.json()) as { Status: number; Answer?: Array<{ type: number; TTL: number; data: string }> };
		return wireFixture(new Uint8Array(init?.body as ArrayBuffer), json.Answer ?? [], json.Status);
	});
}

export function wireFixture(query: Uint8Array, answers: Array<{ type: number; TTL: number; data: string }>, rcode = 0): Response {
	const bytes = Array.from(query);
	bytes[2] = 0x81;
	bytes[3] = 0x80 | rcode;
	bytes[6] = answers.length >> 8;
	bytes[7] = answers.length & 255;
	const nameBytes = (value: string) =>
		value
			.replace(/\.$/, '')
			.split('.')
			.flatMap((s) => [s.length, ...Array.from(s, (c) => c.charCodeAt(0))])
			.concat(0);
	for (const answer of answers) {
		let data: number[];
		if (answer.type === 1) data = answer.data.split('.').map(Number);
		else if (answer.type === 28) data = answer.data.split(':').flatMap((s) => [parseInt(s, 16) >> 8, parseInt(s, 16) & 255]);
		else if (answer.type === 15) {
			const [priority, host] = answer.data.split(' ');
			data = [Number(priority) >> 8, Number(priority) & 255, ...nameBytes(host)];
		} else if (answer.type === 16) {
			// These fixtures exercise the observed JSON presentation conventions, including escaped quotes.
			const segments = answer.data.startsWith('"') && answer.data.endsWith('"') ? answer.data.slice(1, -1).split('" "') : [answer.data];
			data = segments.flatMap((part) => {
				const value = part.replace(/\\(["\\])/g, '$1');
				return [value.length, ...Array.from(value, (c) => c.charCodeAt(0))];
			});
		} else if (answer.type === 6) {
			const [mname, rname, ...numbers] = answer.data.split(' ');
			data = [
				...nameBytes(mname),
				...nameBytes(rname),
				...numbers.flatMap((s) => {
					const n = Number(s);
					return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
				}),
			];
		} else if (answer.type === 257) {
			const match = /^(\d+) (\w+) "(.*)"$/.exec(answer.data)!;
			data = [Number(match[1]), match[2].length, ...Array.from(match[2] + match[3], (c) => c.charCodeAt(0))];
		} else data = nameBytes(answer.data);
		bytes.push(
			0xc0,
			12,
			answer.type >> 8,
			answer.type & 255,
			0,
			1,
			(answer.TTL >>> 24) & 255,
			(answer.TTL >>> 16) & 255,
			(answer.TTL >>> 8) & 255,
			answer.TTL & 255,
			data.length >> 8,
			data.length & 255,
			...data,
		);
	}
	return new Response(new Uint8Array(bytes), { headers: { 'Content-Type': 'application/dns-message' } });
}
