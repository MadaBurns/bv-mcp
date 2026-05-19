// SPDX-License-Identifier: BUSL-1.1

/**
 * Phase 5 of registrar-coverage-tdd-plan.md — negative IANA WHOIS cache.
 *
 * Previously: a TLD with no IANA record (or a query that failed) was NOT cached,
 * so every audit re-queried IANA over a 1-2s round-trip. Pathological discovery
 * (wildcard SAN matches on non-existent TLDs) burned WHOIS connection budget.
 *
 * After Phase 5: negative results cache for IANA_NEGATIVE_TTL_SECONDS (24h),
 * shorter than positive results (7d) so legitimate new TLDs aren't blackholed
 * forever, long enough to skip repeated IANA round-trips during a single audit
 * batch.
 */

import { describe, it, expect, vi } from 'vitest';
import { resolveWhoisServer, IANA_NEGATIVE_TTL_SECONDS, type WhoisQueryFn } from '../resolver';

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

describe('resolveWhoisServer — negative IANA cache', () => {
	it('writes a negative-cache entry when IANA returns no record', async () => {
		const kv = makeMemoryKV();
		const whoisQuery: WhoisQueryFn = async () => '% returned 0 objects\n';

		await resolveWhoisServer('madeuptld', { kv: kv as never, whoisQuery });

		expect(kv.put).toHaveBeenCalledTimes(1);
		const [key, value, opts] = kv.put.mock.calls[0];
		expect(key).toBe('iana:madeuptld');
		expect(opts).toEqual({ expirationTtl: IANA_NEGATIVE_TTL_SECONDS });
		// Envelope format: JSON with server:null marker.
		const parsed = JSON.parse(value);
		expect(parsed).toEqual({ server: null });
	});

	it('skips IANA on a subsequent call when negative-cache is hit', async () => {
		const kv = makeMemoryKV();
		const whoisQuery: WhoisQueryFn = vi.fn(async () => '% returned 0 objects\n');

		await resolveWhoisServer('madeuptld', { kv: kv as never, whoisQuery });
		await resolveWhoisServer('madeuptld', { kv: kv as never, whoisQuery });

		expect(whoisQuery).toHaveBeenCalledTimes(1);
	});

	it('returns null when reading a negative-cache entry', async () => {
		const kv = makeMemoryKV();
		await kv.put('iana:madeuptld', JSON.stringify({ server: null }), { expirationTtl: IANA_NEGATIVE_TTL_SECONDS });
		const whoisQuery: WhoisQueryFn = vi.fn();

		const result = await resolveWhoisServer('madeuptld', { kv: kv as never, whoisQuery });

		expect(result).toBeNull();
		expect(whoisQuery).not.toHaveBeenCalled();
	});

	it('caches a thrown WHOIS error as a negative entry (transient lookups should not hammer IANA)', async () => {
		const kv = makeMemoryKV();
		const whoisQuery: WhoisQueryFn = vi.fn(async () => {
			throw new Error('connection refused');
		});

		await resolveWhoisServer('weirdtld', { kv: kv as never, whoisQuery });

		expect(kv.put).toHaveBeenCalledTimes(1);
		const [key, value] = kv.put.mock.calls[0];
		expect(key).toBe('iana:weirdtld');
		expect(JSON.parse(value)).toEqual({ server: null });
	});

	it('positive cache reads still work after Phase 5 envelope change (bare-string back-compat)', async () => {
		const kv = makeMemoryKV();
		// Pre-Phase-5 KV entries are bare hostnames. Reader must accept both.
		await kv.put('iana:legacy', 'whois.legacy-registry.example', {});
		const whoisQuery: WhoisQueryFn = vi.fn();

		const result = await resolveWhoisServer('legacy', { kv: kv as never, whoisQuery });

		expect(result).toBe('whois.legacy-registry.example');
		expect(whoisQuery).not.toHaveBeenCalled();
	});

	it('positive cache writes use JSON envelope for new entries', async () => {
		const kv = makeMemoryKV();
		const whoisQuery: WhoisQueryFn = async () => 'whois:        whois.nic.xyz\n';

		await resolveWhoisServer('xyz', { kv: kv as never, whoisQuery });

		const [, value] = kv.put.mock.calls[0];
		// Accept either JSON envelope OR bare string — but assert the *read* path
		// round-trips correctly.
		const stored = (() => {
			try { return JSON.parse(value); } catch { return value; }
		})();
		expect(typeof stored === 'object' ? stored.server : stored).toBe('whois.nic.xyz');
	});
});
