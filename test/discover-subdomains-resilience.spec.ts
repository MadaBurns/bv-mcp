// SPDX-License-Identifier: BUSL-1.1
//
// Resilience for `discover_subdomains` CT enumeration (issue: "Certificate
// Transparency source persistently unavailable"). The direct path must:
//   1. Fail over from crt.sh to a second public source (Certspotter) instead of
//      zeroing the result when crt.sh is down.
//   2. Serve a last-known-good cached enumeration (marked `stale` + age) when
//      EVERY live source fails, rather than an empty "source unavailable".
//   3. Emit a per-source health log (ok / http_error / timeout) so outages are
//      observable.
//   4. Keep `force_refresh` bypassing the fetch cache while still allowing the
//      stale-on-total-failure fallback.

import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { setupFetchMock } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

/**
 * Minimal in-memory KV mock (get/put/delete) sufficient for the LKG cache.
 * Cast to KVNamespace at the call site (codebase idiom) to avoid depending on
 * the ambient worker-types resolution in this spec file.
 */
function makeKv() {
	const store = new Map<string, string>();
	return {
		store,
		get: async (key: string, type?: string) => {
			const raw = store.get(key);
			if (raw === undefined) return null;
			return type === 'json' ? JSON.parse(raw) : raw;
		},
		put: async (key: string, value: string) => {
			store.set(key, value);
		},
		delete: async (key: string) => {
			store.delete(key);
		},
	};
}

/** A crt.sh JSON entry for one cert. */
function crtEntry(name: string) {
	return { name_value: name, issuer_name: "CN=R3, O=Let's Encrypt", not_before: '2026-02-01', not_after: '2026-05-01' };
}

/** A Certspotter issuance object (expand=dns_names,issuer). */
function certspotterEntry(names: string[]) {
	return { id: '1', dns_names: names, not_before: '2026-02-01', not_after: '2026-05-01', issuer: { name: "C=US, O=Let's Encrypt, CN=R11" } };
}

describe('discoverSubdomains — multi-source resilience', () => {
	beforeEach(() => {
		vi.spyOn(console, 'log').mockImplementation(() => {});
	});
	afterEach(() => vi.restoreAllMocks());

	it('fails over to Certspotter when crt.sh returns an error status', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh')) return Response.json({}, { status: 500 });
			if (s.includes('certspotter.com')) return Response.json([certspotterEntry(['api.example.com', 'secure.example.com'])], { status: 200 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});

		const result = await discoverSubdomains('example.com');

		expect(result.sourceUnavailable).toBeFalsy();
		expect(result.subdomains.map((s) => s.subdomain).sort()).toEqual(['api.example.com', 'secure.example.com']);
	});

	it('emits a per-source health log line for each attempted CT source', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh')) return Response.json({}, { status: 500 });
			if (s.includes('certspotter.com')) return Response.json([certspotterEntry(['api.example.com'])], { status: 200 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});

		await discoverSubdomains('example.com');

		const logged = logSpy.mock.calls.map((c) => String(c[0]));
		const ctLogs = logged.filter((l) => l.includes('ct_source'));
		expect(ctLogs.some((l) => l.includes('crtsh') && l.includes('http_error'))).toBe(true);
		expect(ctLogs.some((l) => l.includes('certspotter') && l.includes('ok'))).toBe(true);
	});

	it('caches a successful enumeration and serves it stale when every source later fails', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const kv = makeKv();

		// First call: crt.sh succeeds → result cached.
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh')) return Response.json([crtEntry('api.example.com'), crtEntry('vpn.example.com')], { status: 200 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});
		const fresh = await discoverSubdomains('example.com', undefined, undefined, { cacheKv: kv });
		expect(fresh.subdomains.map((s) => s.subdomain).sort()).toEqual(['api.example.com', 'vpn.example.com']);
		expect(kv.store.size).toBeGreaterThan(0);

		// Second call: every source fails → must serve the cached set marked stale.
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh') || s.includes('certspotter.com')) return Response.json({}, { status: 503 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});
		const stale = await discoverSubdomains('example.com', undefined, undefined, { cacheKv: kv });

		expect(stale.stale).toBe(true);
		expect(stale.sourceUnavailable).toBeFalsy();
		expect(typeof stale.cacheAgeMinutes).toBe('number');
		expect(stale.subdomains.map((s) => s.subdomain).sort()).toEqual(['api.example.com', 'vpn.example.com']);
	});

	it('returns the explicit source-unavailable error when all sources fail and no cache exists', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const kv = makeKv();
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh') || s.includes('certspotter.com')) return Response.json({}, { status: 503 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});

		const result = await discoverSubdomains('example.com', undefined, undefined, { cacheKv: kv });

		expect(result.sourceUnavailable).toBe(true);
		expect(result.stale).toBeFalsy();
		expect(result.subdomains).toEqual([]);
	});

	it('still serves stale on total failure even when force_refresh is set', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const kv = makeKv();

		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh')) return Response.json([crtEntry('api.example.com')], { status: 200 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});
		await discoverSubdomains('example.com', undefined, undefined, { cacheKv: kv });

		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh') || s.includes('certspotter.com')) return Response.json({}, { status: 503 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});
		const result = await discoverSubdomains('example.com', undefined, undefined, { cacheKv: kv, forceRefresh: true });

		expect(result.stale).toBe(true);
		expect(result.subdomains.map((s) => s.subdomain)).toEqual(['api.example.com']);
	});

	it('formats a stale result with an explicit staleness banner', async () => {
		const { formatSubdomainDiscovery } = await import('../src/tools/discover-subdomains');
		const text = formatSubdomainDiscovery(
			{
				domain: 'example.com',
				totalSubdomains: 1,
				totalCertificates: 1,
				subdomains: [{ subdomain: 'api.example.com', firstSeen: '', lastSeen: '', issuer: '', certCount: 1, isWildcard: false, isExpired: false }],
				wildcardCerts: 0,
				expiredCerts: 0,
				uniqueIssuers: [],
				issues: [],
				stale: true,
				cacheAgeMinutes: 125,
			},
			'compact',
		);

		expect(text).toContain('STALE');
		expect(text).toContain('2 hours ago');
		// The actual data is still present — a stale answer is a usable answer.
		expect(text).toContain('api.example.com');
	});

	it('serves stale rather than an empty error when the budget trips before any direct source runs', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const kv = makeKv();

		// Seed the LKG cache from a healthy call.
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh')) return Response.json([crtEntry('api.example.com')], { status: 200 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});
		await discoverSubdomains('example.com', undefined, undefined, { cacheKv: kv });

		// Budget already blown (e.g. the certstream fast path consumed all of it):
		// a KV read is still affordable, so we must return data, not an error.
		const result = await discoverSubdomains('example.com', undefined, undefined, { cacheKv: kv, deadlineMs: Date.now() - 1 });

		expect(result.stale).toBe(true);
		expect(result.partial).toBe(true);
		expect(result.sourceUnavailable).toBeFalsy();
		expect(result.subdomains.map((s) => s.subdomain)).toEqual(['api.example.com']);
	});

	it('never renders a stale result as a confident "none found"', async () => {
		const { formatSubdomainDiscovery } = await import('../src/tools/discover-subdomains');
		const text = formatSubdomainDiscovery(
			{
				domain: 'example.com',
				totalSubdomains: 0,
				totalCertificates: 0,
				subdomains: [],
				wildcardCerts: 0,
				expiredCerts: 0,
				uniqueIssuers: [],
				issues: [],
				stale: true,
				cacheAgeMinutes: 30,
			},
			'compact',
		);

		// The zero-subdomain branch must not swallow the staleness marker — an
		// unreliable empty answer presented as confident is the original bug class.
		expect(text).toMatch(/stale/i);
		expect(text).not.toBe('Subdomain Discovery: example.com — no subdomains found in Certificate Transparency logs');
	});

	it('does not store an empty enumeration as last-known-good', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const kv = makeKv();
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh')) return Response.json([], { status: 200 }); // available, genuinely empty
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});

		const result = await discoverSubdomains('example.com', undefined, undefined, { cacheKv: kv });

		expect(result.sourceUnavailable).toBeFalsy();
		// An empty result is a weak fallback: re-serving "0 subdomains (stale)" is no
		// more useful than the explicit outage error, and risks reading as confident.
		expect(kv.store.size).toBe(0);
	});

	it('does not overwrite the last-known-good cache with a source-unavailable result', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const kv = makeKv();


		// Seed cache with a good result.
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh')) return Response.json([crtEntry('api.example.com')], { status: 200 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});
		await discoverSubdomains('example.com', undefined, undefined, { cacheKv: kv });
		const afterSeed = kv.store.get([...kv.store.keys()][0]);

		// Outage: must NOT clobber the cached good set with an empty/unavailable one.
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh') || s.includes('certspotter.com')) return Response.json({}, { status: 503 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});
		await discoverSubdomains('example.com', undefined, undefined, { cacheKv: kv });

		expect(kv.store.get([...kv.store.keys()][0])).toBe(afterSeed);
	});
});

describe('discover_subdomains handler — LKG cache wiring', () => {
	beforeEach(() => {
		vi.spyOn(console, 'log').mockImplementation(() => {});
	});
	afterEach(() => {
		restore();
		vi.restoreAllMocks();
	});

	// Guards the production seam: the handler must thread its scanCacheKV into
	// discoverSubdomains as cacheKv. Without that thread the resilience cache
	// silently never populates in prod even though the unit tests pass.
	it('populates the LKG cache through the handler and serves stale on a later total outage', async () => {
		const { handleToolsCall } = await import('../src/handlers/tools');
		const kv = makeKv();

		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh')) return Response.json([crtEntry('api.example.com')], { status: 200 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});
		const fresh = await handleToolsCall({ name: 'discover_subdomains', arguments: { domain: 'example.com' } }, kv as never, undefined);
		expect(fresh.isError).toBeFalsy();
		expect(kv.store.size).toBeGreaterThan(0);

		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh') || s.includes('certspotter.com')) return Response.json({}, { status: 503 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});
		const stale = await handleToolsCall({ name: 'discover_subdomains', arguments: { domain: 'example.com' } }, kv as never, undefined);

		// Stale carries data → NOT an error, unlike the cold-cache outage case.
		expect(stale.isError).toBeFalsy();
		const payload = stale.structuredContent as Record<string, unknown> | undefined;
		expect(payload?.stale).toBe(true);
		expect(payload?.sourceUnavailable).toBeFalsy();
	});
});
