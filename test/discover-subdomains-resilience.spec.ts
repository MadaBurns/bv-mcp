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
 * Minimal in-memory KV mock (get/put/delete) sufficient for the subdomain cache.
 * The module under test uses only those three methods; `list` and
 * `getWithMetadata` are deliberately not implemented.
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

/**
 * Widen the mock to the full `KVNamespace` surface for the call sites.
 *
 * Done ONCE here rather than at each call site: this file previously carried 10
 * standing TS2739 errors from passing the bare mock, tracked by the
 * `typecheck:tests` ratchet. One documented widening in one place drops that
 * count to zero instead of growing it with every new spec.
 */
function asKv(kv: ReturnType<typeof makeKv>): KVNamespace {
	return kv as unknown as KVNamespace;
}

/**
 * Mirror of `SUBDOMAIN_FRESH_TTL_SECONDS` in the module under test. Kept as a
 * local literal ON PURPOSE: importing the constant would make these specs agree
 * with the implementation by construction, so a bad TTL edit could never fail
 * them. If this drifts, the `honours the configured fresh window` test fails —
 * which is the intended alarm, not a nuisance.
 */
const FRESH_TTL_MS = 60 * 60 * 1000;

/**
 * Backdate every cached entry by `ms`, simulating the passage of time without
 * fake timers (which fight the async fetch mocks in this suite). Operates on the
 * raw JSON so it stays honest about the on-disk shape.
 */
function advanceCacheAge(kv: ReturnType<typeof makeKv>, ms: number) {
	for (const [key, raw] of kv.store) {
		const entry = JSON.parse(raw) as { cachedAt?: number };
		if (typeof entry.cachedAt === 'number') {
			entry.cachedAt -= ms;
			kv.store.set(key, JSON.stringify(entry));
		}
	}
}

/** Count CT-source fetches only — the suite's mock also answers DoH lookups. */
function ctFetchCount(mock: ReturnType<typeof vi.fn>): number {
	return mock.mock.calls.filter((c) => {
		const u = c[0];
		const s = typeof u === 'string' ? u : u instanceof URL ? u.toString() : String((u as Request)?.url ?? '');
		return s.includes('crt.sh') || s.includes('certspotter.com');
	}).length;
}

/** A crt.sh JSON entry for one cert. */
function crtEntry(name: string) {
	return { name_value: name, issuer_name: "CN=R3, O=Let's Encrypt", not_before: '2026-02-01', not_after: '2026-05-01' };
}

/** A Certspotter issuance object (expand=dns_names,issuer). */
function certspotterEntry(names: string[]) {
	return {
		id: '1',
		dns_names: names,
		not_before: '2026-02-01',
		not_after: '2026-05-01',
		issuer: { name: "C=US, O=Let's Encrypt, CN=R11" },
	};
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
			if (s.includes('certspotter.com'))
				return Response.json([certspotterEntry(['api.example.com', 'secure.example.com'])], { status: 200 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});

		const result = await discoverSubdomains('example.com');

		expect(result.sourceUnavailable).toBeFalsy();
		expect(result.subdomains.map((s) => s.subdomain).sort()).toEqual(['api.example.com', 'secure.example.com']);
	});

	// Ordering guard: re-asking a source that just timed out costs another full
	// timeout and delays the source that could actually answer. Every source must
	// be tried ONCE before any source is retried — a same-source retry ahead of
	// failover previously pushed a caller past its 15s budget.
	it('tries every source once before retrying any source', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const order: string[] = [];
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh')) {
				order.push('crtsh');
				return Response.json({}, { status: 503 });
			}
			if (s.includes('certspotter.com')) {
				order.push('certspotter');
				return Response.json({}, { status: 503 });
			}
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});

		await discoverSubdomains('example.com');

		// First pass must be one attempt per source, in failover order — NOT
		// ['crtsh','crtsh',...].
		expect(order.slice(0, 2)).toEqual(['crtsh', 'certspotter']);
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
		const fresh = await discoverSubdomains('example.com', undefined, undefined, { cacheKv: asKv(kv) });
		expect(fresh.subdomains.map((s) => s.subdomain).sort()).toEqual(['api.example.com', 'vpn.example.com']);
		expect(kv.store.size).toBeGreaterThan(0);

		// Age the entry out of the fresh-read window, or the second call would be
		// served from cache and never reach the (failing) sources this test is about.
		advanceCacheAge(kv, FRESH_TTL_MS + 60_000);

		// Second call: every source fails → must serve the cached set marked stale.
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh') || s.includes('certspotter.com')) return Response.json({}, { status: 503 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});
		const stale = await discoverSubdomains('example.com', undefined, undefined, { cacheKv: asKv(kv) });

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

		const result = await discoverSubdomains('example.com', undefined, undefined, { cacheKv: asKv(kv) });

		expect(result.sourceUnavailable).toBe(true);
		expect(result.stale).toBeFalsy();
		expect(result.subdomains).toEqual([]);
	});

	it('records HTTP 429 as rate_limited, not as a generic http_error (#735)', async () => {
		// Measured 2026-08-21: after certspotter 504s on a large estate it starts
		// returning 429 to the SAME unauthenticated caller, and the lockout outlived
		// a 75-second wait. Collapsing that into `http_error` makes the banner tell
		// the caller a retry is worthwhile — which extends the lockout and poisons
		// the shared quota for every OTHER domain scanned next.
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh') || s.includes('certspotter.com')) {
				return Response.json({ code: 'rate_limited' }, { status: 429 });
			}
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});

		const result = await discoverSubdomains('example.com');

		expect(result.sourceUnavailable).toBe(true);
		const outcomes = (result.coverage?.perSource ?? []).map((s) => s.outcome);
		expect(outcomes).toContain('rate_limited');
		expect(outcomes).not.toContain('http_error');
	});

	it('still records a non-429 upstream failure as http_error (#735 control)', async () => {
		// Discriminating half: 503 must NOT be swept into the new bucket, or the
		// retry guidance disappears for the one case where retrying is correct.
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh') || s.includes('certspotter.com')) return Response.json({}, { status: 503 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});

		const result = await discoverSubdomains('example.com');
		const outcomes = (result.coverage?.perSource ?? []).map((s) => s.outcome);
		expect(outcomes).toContain('http_error');
		expect(outcomes).not.toContain('rate_limited');
	});

	it('still serves stale on total failure even when force_refresh is set', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const kv = makeKv();

		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh')) return Response.json([crtEntry('api.example.com')], { status: 200 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});
		await discoverSubdomains('example.com', undefined, undefined, { cacheKv: asKv(kv) });

		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh') || s.includes('certspotter.com')) return Response.json({}, { status: 503 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});
		const result = await discoverSubdomains('example.com', undefined, undefined, { cacheKv: asKv(kv), forceRefresh: true });

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
				subdomains: [
					{ subdomain: 'api.example.com', firstSeen: '', lastSeen: '', issuer: '', certCount: 1, isWildcard: false, isExpired: false },
				],
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
		await discoverSubdomains('example.com', undefined, undefined, { cacheKv: asKv(kv) });

		// Past the fresh window, so the entry is an outage net rather than the
		// answer — otherwise the fresh-read path would satisfy this call before the
		// deadline gate is ever reached (covered separately below).
		advanceCacheAge(kv, FRESH_TTL_MS + 60_000);

		// Budget already blown (e.g. the certstream fast path consumed all of it):
		// a KV read is still affordable, so we must return data, not an error.
		const result = await discoverSubdomains('example.com', undefined, undefined, { cacheKv: asKv(kv), deadlineMs: Date.now() - 1 });

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

		const result = await discoverSubdomains('example.com', undefined, undefined, { cacheKv: asKv(kv) });

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
		await discoverSubdomains('example.com', undefined, undefined, { cacheKv: asKv(kv) });
		const afterSeed = kv.store.get([...kv.store.keys()][0]);

		// Outage: must NOT clobber the cached good set with an empty/unavailable one.
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh') || s.includes('certspotter.com')) return Response.json({}, { status: 503 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});
		await discoverSubdomains('example.com', undefined, undefined, { cacheKv: asKv(kv) });

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

		// Past the fresh-read window, so this exercises the outage path and not
		// the cache-hit path (which has its own coverage below).
		advanceCacheAge(kv, FRESH_TTL_MS + 60_000);

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

/**
 * Fresh-read cache (quota conservation).
 *
 * The LKG cache was written on every success but READ only on total-outage or
 * deadline-trip, so a repeat scan of the same domain always spent a live query.
 * On CertSpotter's free "Small" tier that bucket is 10 full-domain queries/HOUR,
 * shared account-wide with bv2-certstream — so five scans of one domain could
 * exhaust half the estate's daily discovery budget for zero new information.
 *
 * These specs pin the fix: inside the fresh window a cached answer is served
 * with ZERO upstream CT calls, and it is labelled `cached` (never `stale`, which
 * means "every live source was unreachable" and would misreport a healthy hit
 * as an outage).
 */
describe('discoverSubdomains — fresh-read cache', () => {
	beforeEach(() => {
		vi.spyOn(console, 'log').mockImplementation(() => {});
	});
	afterEach(() => vi.restoreAllMocks());

	/** Prime the cache with one successful crt.sh enumeration. */
	async function prime(kv: ReturnType<typeof makeKv>) {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh')) return Response.json([crtEntry('api.example.com'), crtEntry('vpn.example.com')], { status: 200 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});
		await discoverSubdomains('example.com', undefined, undefined, { cacheKv: asKv(kv) });
		expect(kv.store.size).toBeGreaterThan(0);
	}

	it('serves a repeat scan from cache without spending ANY upstream CT query', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const kv = makeKv();
		await prime(kv);

		// Any CT call in this window is a quota spend the fix exists to prevent,
		// so the sources are wired to throw rather than merely to fail.
		const spy = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh') || s.includes('certspotter.com')) throw new Error('quota spent on a cache-hit path');
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});
		globalThis.fetch = spy;

		const hit = await discoverSubdomains('example.com', undefined, undefined, { cacheKv: asKv(kv) });

		expect(ctFetchCount(spy)).toBe(0);
		expect(hit.subdomains.map((s) => s.subdomain).sort()).toEqual(['api.example.com', 'vpn.example.com']);
	});

	it('labels a cache hit `cached` and NOT `stale`, with an age', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const kv = makeKv();
		await prime(kv);

		const hit = await discoverSubdomains('example.com', undefined, undefined, { cacheKv: asKv(kv) });

		// `stale` is documented as "every live CT source was unreachable". A healthy
		// cache hit is not an outage, and a consumer branching on `stale` to warn
		// about degraded data must not fire here.
		expect(hit.cached).toBe(true);
		expect(hit.stale).toBeFalsy();
		expect(hit.sourceUnavailable).toBeFalsy();
		expect(typeof hit.cacheAgeMinutes).toBe('number');
	});

	it('honours the configured fresh window — an older entry goes back to the network', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const kv = makeKv();
		await prime(kv);
		advanceCacheAge(kv, FRESH_TTL_MS + 60_000);

		const spy = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh')) return Response.json([crtEntry('new.example.com')], { status: 200 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});
		globalThis.fetch = spy;

		const refreshed = await discoverSubdomains('example.com', undefined, undefined, { cacheKv: asKv(kv) });

		expect(ctFetchCount(spy)).toBeGreaterThan(0);
		expect(refreshed.cached).toBeFalsy();
		expect(refreshed.subdomains.map((s) => s.subdomain)).toEqual(['new.example.com']);
	});

	it('an entry just INSIDE the window is still served from cache (boundary control)', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const kv = makeKv();
		await prime(kv);
		advanceCacheAge(kv, FRESH_TTL_MS - 60_000);

		const spy = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh') || s.includes('certspotter.com')) throw new Error('should not be reached');
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});
		globalThis.fetch = spy;

		const hit = await discoverSubdomains('example.com', undefined, undefined, { cacheKv: asKv(kv) });

		expect(ctFetchCount(spy)).toBe(0);
		expect(hit.cached).toBe(true);
	});

	it('force_refresh bypasses the fresh cache and queries live sources', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const kv = makeKv();
		await prime(kv);

		const spy = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh')) return Response.json([crtEntry('forced.example.com')], { status: 200 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});
		globalThis.fetch = spy;

		const forced = await discoverSubdomains('example.com', undefined, undefined, { cacheKv: asKv(kv), forceRefresh: true });

		expect(ctFetchCount(spy)).toBeGreaterThan(0);
		expect(forced.cached).toBeFalsy();
		expect(forced.subdomains.map((s) => s.subdomain)).toEqual(['forced.example.com']);
	});

	it('without a cacheKv every call still queries live sources (control)', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const spy = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh')) return Response.json([crtEntry('api.example.com')], { status: 200 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});
		globalThis.fetch = spy;

		await discoverSubdomains('example.com');
		const first = ctFetchCount(spy);
		await discoverSubdomains('example.com');

		expect(first).toBeGreaterThan(0);
		expect(ctFetchCount(spy)).toBeGreaterThan(first);
	});

	it('a fresh cache hit answers even when the deadline has already tripped', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const kv = makeKv();
		await prime(kv);

		// A blown budget is a reason to AVOID the network, not a reason to degrade
		// the answer: a KV read costs milliseconds. The result must be the accurate
		// `cached`, not `stale`/`partial` — nothing is stale and nothing was skipped.
		const spy = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh') || s.includes('certspotter.com')) throw new Error('should not be reached');
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});
		globalThis.fetch = spy;

		const hit = await discoverSubdomains('example.com', undefined, undefined, { cacheKv: asKv(kv), deadlineMs: Date.now() - 1 });

		expect(ctFetchCount(spy)).toBe(0);
		expect(hit.cached).toBe(true);
		expect(hit.stale).toBeFalsy();
		expect(hit.partial).toBeFalsy();
		expect(hit.subdomains.map((s) => s.subdomain).sort()).toEqual(['api.example.com', 'vpn.example.com']);
	});

	it('does not serve one domain’s cache entry for another domain', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const kv = makeKv();
		await prime(kv);

		const spy = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh')) return Response.json([crtEntry('api.other.com')], { status: 200 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});
		globalThis.fetch = spy;

		const other = await discoverSubdomains('other.com', undefined, undefined, { cacheKv: asKv(kv) });

		expect(ctFetchCount(spy)).toBeGreaterThan(0);
		expect(other.cached).toBeFalsy();
		expect(other.subdomains.map((s) => s.subdomain)).toEqual(['api.other.com']);
	});
});
