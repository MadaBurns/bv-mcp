// SPDX-License-Identifier: BUSL-1.1
/**
 * Unit tests for resolveWhoisServer — TLD → server resolution with KV cache.
 */

import { describe, it, expect, vi } from 'vitest';
import { resolveWhoisServer, IANA_TTL_SECONDS, type WhoisQueryFn } from '../resolver';

/**
 * KV fake. Behaviors-only — no escape-hatch into internal state. To assert
 * what was written, wrap the `put` method with a vi.fn and inspect calls.
 */
function makeMemoryKV() {
	const data = new Map<string, string>();
	return {
		get: vi.fn(async (key: string) => (data.has(key) ? data.get(key)! : null)),
		put: vi.fn(async (key: string, value: string, _opts?: { expirationTtl?: number }) => {
			data.set(key, value);
		}),
		delete: vi.fn(async (key: string) => {
			data.delete(key);
		}),
	};
}

describe('resolveWhoisServer', () => {
	it('returns hardcoded server for .com without hitting IANA', async () => {
		const kv = makeMemoryKV();
		const whoisQuery = vi.fn();

		const result = await resolveWhoisServer('com', { kv: kv as never, whoisQuery });

		expect(result).toBe('whois.verisign-grs.com');
		expect(whoisQuery).not.toHaveBeenCalled();
	});

	it('queries IANA on cache miss for unknown TLD', async () => {
		const kv = makeMemoryKV();
		const whoisQuery: WhoisQueryFn = vi.fn(async (server: string, query: string) => {
			expect(server).toBe('whois.iana.org');
			expect(query).toBe('xyz');
			return 'whois:        whois.nic.xyz\nstatus:       ACTIVE\n';
		});

		const result = await resolveWhoisServer('xyz', { kv: kv as never, whoisQuery });

		expect(result).toBe('whois.nic.xyz');
		expect(whoisQuery).toHaveBeenCalledOnce();
	});

	it('persists IANA result to KV with the configured TTL (Phase 5: JSON envelope)', async () => {
		const kv = makeMemoryKV();
		const whoisQuery: WhoisQueryFn = async () => 'whois:        whois.nic.xyz\n';

		await resolveWhoisServer('xyz', { kv: kv as never, whoisQuery });

		expect(kv.put).toHaveBeenCalledWith(
			'iana:xyz',
			JSON.stringify({ server: 'whois.nic.xyz' }),
			{ expirationTtl: IANA_TTL_SECONDS },
		);
	});

	it('reads from KV cache on subsequent calls without re-querying IANA', async () => {
		const kv = makeMemoryKV();
		await kv.put('iana:xyz', 'whois.nic.xyz', { expirationTtl: IANA_TTL_SECONDS });
		const whoisQuery = vi.fn();

		const result = await resolveWhoisServer('xyz', { kv: kv as never, whoisQuery });

		expect(result).toBe('whois.nic.xyz');
		expect(whoisQuery).not.toHaveBeenCalled();
	});

	it('returns null when IANA has no record for the TLD', async () => {
		const kv = makeMemoryKV();
		const whoisQuery: WhoisQueryFn = async () =>
			'% IANA WHOIS server\n% This query returned 0 objects.\n';

		const result = await resolveWhoisServer('fakefaketld', { kv: kv as never, whoisQuery });

		expect(result).toBeNull();
	});

	it('caches null IANA results to KV (Phase 5: negative cache prevents IANA hammering)', async () => {
		const kv = makeMemoryKV();
		const whoisQuery: WhoisQueryFn = async () => '% returned 0 objects\n';

		await resolveWhoisServer('fakefaketld', { kv: kv as never, whoisQuery });

		// Phase 5 contract: a null IANA referral now writes a {server:null} envelope
		// with the shorter 24h TTL. A subsequent call within the TTL skips IANA.
		expect(kv.put).toHaveBeenCalledTimes(1);
		const [key, value] = kv.put.mock.calls[0];
		expect(key).toBe('iana:fakefaketld');
		expect(JSON.parse(value)).toEqual({ server: null });
	});

	it('normalizes TLD to lowercase before lookup', async () => {
		const kv = makeMemoryKV();
		await kv.put('iana:xyz', 'whois.nic.xyz', { expirationTtl: IANA_TTL_SECONDS });
		const whoisQuery = vi.fn();

		const result = await resolveWhoisServer('XYZ', { kv: kv as never, whoisQuery });

		expect(result).toBe('whois.nic.xyz');
		expect(whoisQuery).not.toHaveBeenCalled();
	});

	it('returns null on whoisQuery error (fail-soft)', async () => {
		const kv = makeMemoryKV();
		const whoisQuery: WhoisQueryFn = async () => {
			throw new Error('connection refused');
		};

		const result = await resolveWhoisServer('xyz', { kv: kv as never, whoisQuery });

		expect(result).toBeNull();
	});
});
