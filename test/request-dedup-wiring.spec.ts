// SPDX-License-Identifier: BUSL-1.1
//
// #363 item 3 — wiring guard: handleToolsCall routes the mutating *_start/register
// tools through the request-dedup window (keyed off runtimeOptions.rateLimitKv +
// principal), and the dedup set is EXACTLY the 8 mutating non-destructive tools.

import { describe, it, expect, vi } from 'vitest';
import { handleToolsCall, MUTATING_DEDUP_TOOLS } from '../src/handlers/tools';

describe('mutating-dedup tool set (SSOT)', () => {
	it('is exactly the 9 mutating, non-destructive start/register tools', () => {
		expect([...MUTATING_DEDUP_TOOLS].sort()).toEqual(
			[
				'brand_audit_batch_start',
				'discover_brand_domains_start',
				'osint_investigate_domain_start',
				'osint_investigate_email_start',
				'osint_investigate_infrastructure_start',
				'osint_investigate_supply_chain_start',
				'osint_investigate_username_start',
				'register_brand_audit_watch',
				'scan_buckets_start',
			].sort(),
		);
	});

	it('excludes the naturally-idempotent destructive delete and all read tools', () => {
		expect(MUTATING_DEDUP_TOOLS.has('delete_brand_audit_watch')).toBe(false);
		expect(MUTATING_DEDUP_TOOLS.has('scan_buckets_status')).toBe(false);
		expect(MUTATING_DEDUP_TOOLS.has('scan_domain')).toBe(false);
		expect(MUTATING_DEDUP_TOOLS.has('check_spf')).toBe(false);
	});
});

describe('handleToolsCall dedup wiring', () => {
	function fakeKv() {
		const store = new Map<string, string>();
		return {
			gets: [] as string[],
			kv: {
				get: vi.fn(async function (this: void, k: string) {
					return store.get(k) ?? null;
				}),
				put: vi.fn(async (k: string, v: string) => void store.set(k, v)),
			} as unknown as KVNamespace,
		};
	}

	it('reads an idem: key for a mutating tool (dedup path entered)', async () => {
		const { kv } = fakeKv();
		await handleToolsCall(
			{ name: 'scan_buckets_start', arguments: { target: 'acme.example' } },
			undefined,
			{ rateLimitKv: kv, keyHash: 'key_abc' },
		);
		const getMock = kv.get as ReturnType<typeof vi.fn>;
		const sawIdemKey = getMock.mock.calls.some((c) => typeof c[0] === 'string' && c[0].startsWith('idem:scan_buckets_start:'));
		expect(sawIdemKey).toBe(true);
	});

	it('does NOT enter the dedup path without a principal (no idem: read)', async () => {
		const { kv } = fakeKv();
		await handleToolsCall({ name: 'scan_buckets_start', arguments: { target: 'acme.example' } }, undefined, { rateLimitKv: kv });
		const getMock = kv.get as ReturnType<typeof vi.fn>;
		const sawIdemKey = getMock.mock.calls.some((c) => typeof c[0] === 'string' && c[0].startsWith('idem:'));
		expect(sawIdemKey).toBe(false);
	});

	// Cross-principal-leak guard: an UNAUTHENTICATED caller's principalId is the
	// ipHash (keyHash ?? ipHash, execute.ts) — truthy, so keying dedup on
	// principalId would let two NAT'd unauth callers share a fingerprint and
	// replay each other's operation IDs. Dedup must key on keyHash ONLY (set only
	// for authenticated callers); an ipHash-only principal must be SKIPPED.
	it('does NOT dedup an unauthenticated caller (ipHash principalId, no keyHash)', async () => {
		const { kv } = fakeKv();
		await handleToolsCall({ name: 'scan_buckets_start', arguments: { target: 'acme.example' } }, undefined, {
			rateLimitKv: kv,
			principalId: 'i_deadbeef', // ipHash for an unauth caller — keyHash deliberately absent
		});
		const getMock = kv.get as ReturnType<typeof vi.fn>;
		const sawIdemKey = getMock.mock.calls.some((c) => typeof c[0] === 'string' && c[0].startsWith('idem:'));
		expect(sawIdemKey).toBe(false);
	});

	// End-to-end seam: a *successful* mutating dispatch (here the deterministic
	// `unprovisioned` result when BV_RECON is absent — falsy isError) must be
	// STORED on the first call and REPLAYED on the second. If buildToolResult's
	// success result were ever isError-truthy the store would silently no-op and
	// the window would be a dead feature; this proves store-and-replay through the
	// real handleToolsCall, not just the wrapper in a vacuum.
	it('stores a successful mutating result and replays it on a duplicate', async () => {
		const { kv } = fakeKv();
		const args = { target: 'acme.example' };
		const opts = { rateLimitKv: kv, keyHash: 'key_abc' };

		const first = await handleToolsCall({ name: 'scan_buckets_start', arguments: args }, undefined, opts);
		const second = await handleToolsCall({ name: 'scan_buckets_start', arguments: args }, undefined, opts);

		const putMock = kv.put as ReturnType<typeof vi.fn>;
		const idemPuts = putMock.mock.calls.filter((c) => typeof c[0] === 'string' && c[0].startsWith('idem:scan_buckets_start:'));
		expect(idemPuts).toHaveLength(1); // second call replayed — did not re-store
		expect(second).toEqual(first); // identical operation result returned
	});
});
