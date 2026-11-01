// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach } from 'vitest';
import { vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';
import { mockResolverFetch, wireFixture } from './helpers/dns-wire-mock';
import { encodeDnsQuery, decodeDnsResponse } from '../src/lib/dns-wire';
import { queryMultiResolver, checkMultiResolverConsistency, RESOLVERS, CONSISTENCY_QUORUM } from '../src/lib/dns-multi-resolver';

const { restore } = setupFetchMock();

afterEach(() => restore());

/** Mock all resolvers to return the same A records. */
function mockConsistentResolvers(answers: Array<{ name: string; type: number; TTL: number; data: string }> = []) {
	mockResolverFetch(() => {
		return Promise.resolve(createDohResponse([{ name: 'example.com', type: 1 }], answers));
	});
}

/** Mock resolvers to return different answers based on resolver endpoint. */
function mockSplitResolvers() {
	mockResolverFetch((url: string | URL) => {
		const urlStr = typeof url === 'string' ? url : url.toString();
		const isCloudflare = urlStr.includes('cloudflare');
		const isGoogle = urlStr.includes('dns.google');
		const u = new URL(urlStr);
		const name = u.searchParams.get('name') ?? 'example.com';
		const type = Number(u.searchParams.get('type') ?? '1');

		if (isCloudflare || isGoogle) {
			return Promise.resolve(createDohResponse([{ name, type }], [{ name, type: 1, TTL: 300, data: '192.0.2.1' }]));
		}
		// Other resolvers return different IP
		return Promise.resolve(createDohResponse([{ name, type }], [{ name, type: 1, TTL: 300, data: '198.51.100.20' }]));
	});
}

/**
 * Mock resolvers with per-resolver TXT `data` payloads, keyed by whether the
 * request URL identifies as Cloudflare or Google. Lets a fixture send the
 * SAME logical TXT value dressed in two different DoH presentation styles.
 */
function mockPerResolverTxt(cloudflareData: string[], googleData: string[]) {
	mockResolverFetch((url: string | URL) => {
		const urlStr = typeof url === 'string' ? url : url.toString();
		const isCloudflare = urlStr.includes('cloudflare');
		const u = new URL(urlStr);
		const name = u.searchParams.get('name') ?? 'example.com';
		const type = Number(u.searchParams.get('type') ?? '16');
		const data = isCloudflare ? cloudflareData : googleData;
		const answers = data.map((d) => ({ name, type: 16, TTL: 300, data: d }));
		return Promise.resolve(createDohResponse([{ name, type }], answers));
	});
}

describe('queryMultiResolver', () => {
	it('returns CONSISTENT when all resolvers agree', async () => {
		mockConsistentResolvers([{ name: 'example.com', type: 1, TTL: 300, data: '192.0.2.10' }]);

		const result = await queryMultiResolver('example.com', 'A');
		expect(result.recordType).toBe('A');
		expect(result.status).toBe('CONSISTENT');
		expect(result.resolverAnswers.length).toBe(RESOLVERS.length);
	});

	it('returns CONSISTENT for empty records', async () => {
		mockConsistentResolvers([]);

		const result = await queryMultiResolver('example.com', 'AAAA');
		expect(result.status).toBe('CONSISTENT');
		expect(result.detail).toContain('No AAAA records');
	});

	it('returns SPLIT_HORIZON when resolvers disagree', async () => {
		mockSplitResolvers();

		const result = await queryMultiResolver('example.com', 'A');
		expect(result.status).toBe('SPLIT_HORIZON');
		expect(result.detail).toContain('differ');
	});

	it('handles resolver timeouts gracefully', async () => {
		mockResolverFetch(() => {
			return new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 50));
		});

		const result = await queryMultiResolver('example.com', 'A');
		// All resolvers timeout — should be INCOMPLETE
		expect(result.status).toBe('INCOMPLETE');
		expect(result.respondedCount).toBe(0);
		expect(result.quorumMet).toBe(false);
	});

	it('caps and cancels oversized resolver response bodies', async () => {
		const cancelled = vi.fn();
		globalThis.fetch = vi.fn().mockImplementation(() => {
			let pull = 0;
			return Promise.resolve(
				new Response(
					new ReadableStream<Uint8Array>({
						pull(controller) {
							if (pull++ === 0) controller.enqueue(new Uint8Array(512 * 1024));
							else controller.enqueue(new Uint8Array([1]));
						},
						cancel: cancelled,
					}),
					{ status: 200, headers: { 'Content-Type': 'application/dns-json' } },
				),
			);
		});

		const result = await queryMultiResolver('example.com', 'A');

		expect(result.status).toBe('INCOMPLETE');
		expect(cancelled).toHaveBeenCalledTimes(RESOLVERS.length);
	});

	it('returns per-resolver answers', async () => {
		mockConsistentResolvers([{ name: 'example.com', type: 1, TTL: 300, data: '192.0.2.10' }]);

		const result = await queryMultiResolver('example.com', 'A');
		for (const ra of result.resolverAnswers) {
			expect(ra).toHaveProperty('resolver');
			expect(ra).toHaveProperty('status');
			expect(ra).toHaveProperty('answers');
		}
	});

	it('does not follow resolver redirects', async () => {
		mockConsistentResolvers([]);

		await queryMultiResolver('example.com', 'A');

		for (const [, init] of vi.mocked(globalThis.fetch).mock.calls) {
			expect(init?.redirect).toBe('manual');
		}
	});

	// #811: Cloudflare's DoH JSON wraps TXT strings in RFC 1035 presentation
	// quotes; Google's does not. The two must normalize to the same logical
	// value so identical TXT records don't get misreported as SPLIT_HORIZON.
	describe('TXT quote normalization (#811)', () => {
		it("treats a quote-wrapped Cloudflare TXT value as CONSISTENT with Google's bare value", async () => {
			mockPerResolverTxt(['"MS=ms70274184"'], ['MS=ms70274184']);

			const result = await queryMultiResolver('example.com', 'TXT');

			expect(result.status).toBe('CONSISTENT');
			expect(result.detail).toContain('identical');
			// The displayed evidence must match what was actually compared.
			for (const ra of result.resolverAnswers) {
				if (ra.status === 'ok') {
					expect(ra.answers).toEqual(['ms=ms70274184']);
				}
			}
		});

		it('still reports SPLIT_HORIZON when the underlying TXT values genuinely differ', async () => {
			mockPerResolverTxt(['"MS=ms70274184"'], ['MS=some-other-value']);

			const result = await queryMultiResolver('example.com', 'TXT');

			expect(result.status).toBe('SPLIT_HORIZON');
		});

		it("joins a multi-string TXT record's quoted segments before comparing", async () => {
			// Cloudflare-style: two adjacent quoted segments of one logical record.
			mockPerResolverTxt(['"part1" "part2"'], ['part1part2']);

			const result = await queryMultiResolver('example.com', 'TXT');

			expect(result.status).toBe('CONSISTENT');
		});

		// Follow-up review finding on #811: normalizeAnswerData() does textual
		// quote-stripping, not RFC 1035 unescaping, so a TXT value containing a
		// literal/escaped quote is only partially handled. Pin the SAFE direction
		// here: Cloudflare's escaped-quote form and Google's bare form must never
		// collapse to CONSISTENT when their content differs after only an outer
		// unwrap (a spurious SPLIT_HORIZON is acceptable; a false CONSISTENT is not).
		it('reports SPLIT_HORIZON (never a false CONSISTENT) for a TXT value containing an escaped quote', async () => {
			// Real content: he said "hi" — Cloudflare wraps + backslash-escapes the
			// interior quotes; Google returns the bare value with real quote chars.
			mockPerResolverTxt(['"he said \\"hi\\""'], ['he said "hi"']);

			const result = await queryMultiResolver('example.com', 'TXT');

			expect(['SPLIT_HORIZON', 'SUSPICIOUS']).toContain(result.status);
		});

		// Contrived dangerous-direction case flagged in review: a resolver's bare
		// (unwrapped) TXT content can itself be byte-for-byte identical to what
		// wrapping produces for a DIFFERENT real value on another resolver — e.g.
		// Cloudflare's real value `foo` is wrapped to the raw string `"foo"`, and
		// Google's real value happens to BE the 5-byte string `"foo"` (quotes as
		// literal content). The two raw DoH answers are then byte-identical, so
		// no per-answer textual heuristic (including the outer-quote-pair guard
		// added here) can tell them apart — this is pinned as a known, inherent
		// limitation (see the LIMITATION note on normalizeAnswerData), NOT
		// silently treated as fixed. Resolving it would require passing resolver
		// identity into the normalizer, which is deliberately out of scope.
		it("KNOWN LIMITATION: cannot distinguish a bare value that collides byte-for-byte with another resolver's wrapped value", async () => {
			mockPerResolverTxt(['"foo"'], ['"foo"']);

			const result = await queryMultiResolver('example.com', 'TXT');

			// Pinning current (inherent, documented) behavior — not asserting this
			// is correct or desirable, only that it is understood and unchanged.
			expect(result.status).toBe('CONSISTENT');
		});
	});
});

/**
 * Mock a fan-out where the named resolvers answer from `answersByResolver` and every other
 * resolver is unreachable (fetch rejects). Resolver identity comes from the request URL.
 */
function mockReachable(answersByResolver: Record<string, string[]>) {
	const hostToName: Array<[string, string]> = [
		['cloudflare', 'Cloudflare'],
		['dns.google', 'Google'],
		['quad9', 'Quad9'],
		['opendns', 'OpenDNS'],
	];
	mockResolverFetch((url: string | URL) => {
		const urlStr = typeof url === 'string' ? url : url.toString();
		const name = hostToName.find(([host]) => urlStr.includes(host))?.[1] ?? '';
		const data = answersByResolver[name];
		if (!data) return Promise.reject(new Error(`${name} unreachable`));
		const u = new URL(urlStr);
		const qname = u.searchParams.get('name') ?? 'example.com';
		return Promise.resolve(
			createDohResponse(
				[{ name: qname, type: 1 }],
				data.map((d) => ({ name: qname, type: 1, TTL: 300, data: d })),
			),
		);
	});
}

describe('queryMultiResolver — responder quorum (#1199)', () => {
	it('exports a quorum of 3', () => {
		expect(CONSISTENCY_QUORUM).toBe(3);
	});

	it('2-of-4 unanimous non-empty answers are INCOMPLETE, not CONSISTENT, and name the unreachable resolvers', async () => {
		mockReachable({ Cloudflare: ['192.0.2.1'], Google: ['192.0.2.1'] });

		const result = await queryMultiResolver('example.com', 'A');

		expect(result.status).toBe('INCOMPLETE');
		expect(result.quorumMet).toBe(false);
		expect(result.quorum).toBe(3);
		expect(result.resolversQueried).toBe(4);
		expect(result.respondedCount).toBe(2);
		expect(result.unreachableResolvers).toEqual(['Quad9', 'OpenDNS']);
		expect(result.detail).toContain('Only 2 of 4 resolvers answered for A records (Quad9, OpenDNS unreachable)');
		expect(result.detail).toContain('below the quorum of 3');
	});

	it('2-of-4 unanimous EMPTY answers are INCOMPLETE too (no "all agree" claim)', async () => {
		mockReachable({ Cloudflare: [], Google: [] });

		const result = await queryMultiResolver('example.com', 'A');

		expect(result.status).toBe('INCOMPLETE');
		expect(result.detail).not.toContain('all 2 resolvers agree');
		expect(result.quorumMet).toBe(false);
	});

	it('3-of-4 unanimous answers are CONSISTENT with one unreachable resolver reported', async () => {
		mockReachable({ Cloudflare: ['192.0.2.1'], Google: ['192.0.2.1'], Quad9: ['192.0.2.1'] });

		const result = await queryMultiResolver('example.com', 'A');

		expect(result.status).toBe('CONSISTENT');
		expect(result.quorumMet).toBe(true);
		expect(result.respondedCount).toBe(3);
		expect(result.unreachableResolvers).toHaveLength(1);
		expect(result.unreachableResolvers).toEqual(['OpenDNS']);
	});

	it('4-of-4 unanimous answers are CONSISTENT with no unreachable resolvers', async () => {
		mockConsistentResolvers([{ name: 'example.com', type: 1, TTL: 300, data: '192.0.2.10' }]);

		const result = await queryMultiResolver('example.com', 'A');

		expect(result.status).toBe('CONSISTENT');
		expect(result.unreachableResolvers).toEqual([]);
		expect(result.respondedCount).toBe(4);
		expect(result.quorumMet).toBe(true);
	});

	it('2-of-4 DIVERGENT answers stay SPLIT_HORIZON (quorum gates only the clean claim)', async () => {
		mockReachable({ Cloudflare: ['192.0.2.1'], Google: ['198.51.100.7'] });

		const result = await queryMultiResolver('example.com', 'A');

		expect(result.status).toBe('SPLIT_HORIZON');
		expect(result.quorumMet).toBe(false);
		expect(result.unreachableResolvers).toEqual(['Quad9', 'OpenDNS']);
	});

	it('names late resolvers by fan-out index (not "unknown") when the overall timeout fires', async () => {
		vi.useFakeTimers();
		try {
			mockResolverFetch((url: string | URL) => {
				const urlStr = typeof url === 'string' ? url : url.toString();
				if (urlStr.includes('quad9') || urlStr.includes('opendns')) return new Promise(() => {}); // never settles
				const qname = new URL(urlStr).searchParams.get('name') ?? 'example.com';
				return Promise.resolve(createDohResponse([{ name: qname, type: 1 }], [{ name: qname, type: 1, TTL: 300, data: '192.0.2.1' }]));
			});

			const pending = queryMultiResolver('example.com', 'A');
			await vi.advanceTimersByTimeAsync(5_100);
			const result = await pending;

			expect(result.unreachableResolvers).toEqual(['Quad9', 'OpenDNS']);
			expect(result.resolverAnswers.map((r) => r.resolver)).toEqual(['Cloudflare', 'Google', 'Quad9', 'OpenDNS']);
			expect(result.status).toBe('INCOMPLETE');
		} finally {
			vi.useRealTimers();
		}
	});
});

describe('checkMultiResolverConsistency', () => {
	it('checks multiple record types', async () => {
		mockConsistentResolvers([]);

		const results = await checkMultiResolverConsistency('example.com', ['A', 'MX']);
		expect(results).toHaveLength(2);
		expect(results[0].recordType).toBe('A');
		expect(results[1].recordType).toBe('MX');
	});

	it('defaults to 5 record types', async () => {
		mockConsistentResolvers([]);

		const results = await checkMultiResolverConsistency('example.com');
		expect(results).toHaveLength(5);
	});
});

describe('queryMultiResolver — SERVFAIL/REFUSED are not agreeing empties (T6 item 6)', () => {
	function mockRcode(status: number) {
		mockResolverFetch((url: string | URL) => {
			const u = new URL(typeof url === 'string' ? url : url.toString());
			const name = u.searchParams.get('name') ?? 'example.com';
			return Promise.resolve(createDohResponse([{ name, type: 1 }], [], { status }));
		});
	}

	it('records four SERVFAILs as errors, never as CONSISTENT "all resolvers agree"', async () => {
		mockRcode(2);

		const result = await queryMultiResolver('example.com', 'A');

		expect(result.status).not.toBe('CONSISTENT');
		expect(result.status).toBe('INCOMPLETE');
		expect(result.detail).not.toContain('agree');
		expect(result.resolverAnswers.every((r) => r.status === 'error')).toBe(true);
	});

	it('records four REFUSEDs as errors, never as CONSISTENT', async () => {
		mockRcode(5);

		const result = await queryMultiResolver('example.com', 'A');

		expect(result.status).toBe('INCOMPLETE');
		expect(result.resolverAnswers.every((r) => r.status === 'error')).toBe(true);
	});

	it('still treats NXDOMAIN from every resolver as a real, agreeing empty answer', async () => {
		mockRcode(3);

		const result = await queryMultiResolver('example.com', 'A');

		expect(result.status).toBe('CONSISTENT');
		expect(result.resolverAnswers.every((r) => r.status === 'ok')).toBe(true);
	});
});

describe('RFC 8484 resolver transports (#1346)', () => {
	it('uses JSON for Cloudflare/Google and binary POST on port 443 for Quad9/OpenDNS', async () => {
		mockConsistentResolvers([{ name: 'example.com', type: 1, TTL: 300, data: '192.0.2.1' }]);
		const result = await queryMultiResolver('example.com', 'A');
		expect(result.respondedCount).toBe(4);
		for (const [url, init] of vi.mocked(fetch).mock.calls) {
			const endpoint = new URL(String(url));
			if (endpoint.hostname.includes('quad9') || endpoint.hostname.includes('opendns')) {
				expect(endpoint.port).toBe('');
				expect(endpoint.search).toBe('');
				expect(init?.method).toBe('POST');
				expect(new Headers(init?.headers).get('Content-Type')).toBe('application/dns-message');
				expect(new Uint8Array(init?.body as ArrayBuffer)).toEqual(encodeDnsQuery('example.com', 'A'));
			} else expect(init?.method).toBe('GET');
		}
	});

	it.each([
		['AAAA', 28, '2001:db8:0:0:0:0:0:1', '2001:db8::1'],
		['MX', 15, '10 mail.example.test.', '10 mail.example.test.'],
		['NS', 2, 'ns.example.test.', 'ns.example.test.'],
		['CNAME', 5, 'alias.example.test.', 'alias.example.test.'],
		['TXT', 16, '"part1" "part2"', '"part1" "part2"'],
		[
			'SOA',
			6,
			'ns.example.test. hostmaster.example.test. 1 3600 600 86400 60',
			'ns.example.test. hostmaster.example.test. 1 3600 600 86400 60',
		],
		['CAA', 257, '0 issue "ca.example.test"', '0 issue "ca.example.test"'],
	] as const)('decodes %s RDATA without comparing wire bytes with JSON presentation', async (type, code, data, expected) => {
		const response = wireFixture(encodeDnsQuery('example.test', type), [{ type: code, TTL: 300, data }]);
		const decoded = decodeDnsResponse(new Uint8Array(await response.arrayBuffer()), 'example.test', type);
		expect(decoded.Answer?.[0].data).toBe(expected);
	});

	it('accepts compressed domain-name RDATA and rejects compression loops', async () => {
		const response = wireFixture(encodeDnsQuery('example.test', 'NS'), [{ type: 2, TTL: 60, data: 'ns.example.test' }]);
		const bytes = new Uint8Array(await response.arrayBuffer());
		const start = encodeDnsQuery('example.test', 'NS').length + 12;
		const compressed = new Uint8Array([...bytes.slice(0, start - 2), 0, 2, 0xc0, 12]);
		expect(decodeDnsResponse(compressed, 'example.test', 'NS').Answer?.[0].data).toBe('example.test.');
		compressed[compressed.length - 1] = compressed.length - 2;
		expect(() => decodeDnsResponse(compressed, 'example.test', 'NS')).toThrow();
	});

	it('keeps HTTP status separate from parse and network failures without exception text', async () => {
		globalThis.fetch = vi.fn().mockImplementation((url: string) => {
			if (url.includes('quad9')) return Promise.resolve(new Response('private upstream body', { status: 504 }));
			if (url.includes('opendns')) return Promise.resolve(new Response(new Uint8Array([0, 1])));
			if (url.includes('google')) return Promise.reject(new Error('private network details'));
			return Promise.resolve(createDohResponse([{ name: 'example.com', type: 1 }], []));
		});
		const result = await queryMultiResolver('example.com', 'A');
		expect(result.resolverAnswers[1]).toMatchObject({ status: 'error', failureKind: 'network' });
		expect(result.resolverAnswers[2]).toMatchObject({ status: 'error', failureKind: 'http', httpStatus: 504 });
		expect(result.resolverAnswers[3]).toMatchObject({ status: 'error', failureKind: 'parse', httpStatus: 200 });
		expect(JSON.stringify(result)).not.toContain('private');
	});

	it('distinguishes actual deadline cancellation from a network exception', async () => {
		vi.useFakeTimers();
		try {
			globalThis.fetch = vi.fn().mockImplementation(
				(_url: string, init?: RequestInit) =>
					new Promise((_, reject) => {
						init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), { once: true });
					}),
			);
			const pending = queryMultiResolver('example.com', 'A');
			await vi.advanceTimersByTimeAsync(3_100);
			const result = await pending;
			expect(result.resolverAnswers.every((r) => r.status === 'timeout' && r.failureKind === 'deadline')).toBe(true);
		} finally {
			vi.useRealTimers();
		}
	});

	it('rejects truncated packets, mismatched questions and invalid RDATA', async () => {
		const response = wireFixture(encodeDnsQuery('example.test', 'A'), [{ type: 1, TTL: 60, data: '192.0.2.1' }]);
		const bytes = new Uint8Array(await response.arrayBuffer());
		expect(() => decodeDnsResponse(bytes.slice(0, -1), 'example.test', 'A')).toThrow();
		expect(() => decodeDnsResponse(bytes, 'other.example.test', 'A')).toThrow();
		bytes[2] |= 2;
		expect(() => decodeDnsResponse(bytes, 'example.test', 'A')).toThrow();
	});
});
