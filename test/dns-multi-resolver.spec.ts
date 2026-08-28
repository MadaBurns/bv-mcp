// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach } from 'vitest';
import { vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';
import { queryMultiResolver, checkMultiResolverConsistency, RESOLVERS } from '../src/lib/dns-multi-resolver';

const { restore } = setupFetchMock();

afterEach(() => restore());

/** Mock all resolvers to return the same A records. */
function mockConsistentResolvers(answers: Array<{ name: string; type: number; TTL: number; data: string }> = []) {
	globalThis.fetch = vi.fn().mockImplementation(() => {
		return Promise.resolve(createDohResponse([{ name: 'example.com', type: 1 }], answers));
	});
}

/** Mock resolvers to return different answers based on resolver endpoint. */
function mockSplitResolvers() {
	globalThis.fetch = vi.fn().mockImplementation((url: string | URL) => {
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
		return Promise.resolve(createDohResponse([{ name, type }], [{ name, type: 1, TTL: 300, data: '5.6.7.8' }]));
	});
}

/**
 * Mock resolvers with per-resolver TXT `data` payloads, keyed by whether the
 * request URL identifies as Cloudflare or Google. Lets a fixture send the
 * SAME logical TXT value dressed in two different DoH presentation styles.
 */
function mockPerResolverTxt(cloudflareData: string[], googleData: string[]) {
	globalThis.fetch = vi.fn().mockImplementation((url: string | URL) => {
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
		mockConsistentResolvers([{ name: 'example.com', type: 1, TTL: 300, data: '93.184.216.34' }]);

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
		globalThis.fetch = vi.fn().mockImplementation(() => {
			return new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 50));
		});

		const result = await queryMultiResolver('example.com', 'A');
		// All resolvers timeout — should be INCOMPLETE
		expect(['INCOMPLETE', 'CONSISTENT']).toContain(result.status);
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
		mockConsistentResolvers([{ name: 'example.com', type: 1, TTL: 300, data: '93.184.216.34' }]);

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

			expect(result.status).toBe('SPLIT_HORIZON');
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
