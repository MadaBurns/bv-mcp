// SPDX-License-Identifier: BUSL-1.1
//
// Regression suite for #866 — a degraded single-source count presented as a bare
// integer.
//
// Measured 2026-08-31 on anthropic.com: crt.sh returned `http_error`, certstream
// was not bound, and Certspotter — the ONLY contributor — reported
// `indexExhausted: true` over a `recent-window` history. The payload still led
// with `totalSubdomains: 107`, shaped exactly like a complete count, while the
// caveat lived in `coverage.caveat` and an `info` finding. Ten of the 107 were
// wildcard patterns (`*.anthropic.com` …), which resolve to no host.
//
// What is locked here:
//   1. `countBasis` says whether `totalSubdomains` is the tool's normal reach
//      (`'sample'`) or a `'floor'` from a run whose recall was cut — a source
//      failed, an index was not read to the end, the budget tripped, or the data
//      is a stale re-serve. NOTE: it is deliberately NOT keyed on
//      `coverage.degraded`, which is `true` on every run (the direct ladder is
//      crt.sh → Certspotter-as-fallback, so a healthy crt.sh answer always leaves
//      Certspotter `notConsulted`) and therefore cannot discriminate.
//   2. Under a floor the payload carries `minSubdomainsObserved` — its PRESENCE is
//      the shape signal — and `totalSubdomains` stays numerically present so no
//      existing reader breaks.
//   3. `concreteSubdomains` (non-wildcard) is always split out of the headline.
//   4. The standing `ct_sample_not_inventory` caveat is `low` under a floor, and
//      stays `info` on a healthy run — a one-exhausted-index result is a
//      scan-quality finding, not a note.
//   5. Both prose formats say "at least N … observed" with the concrete/wildcard
//      split under a floor, never a bare "N subdomains".

import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { setupFetchMock } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

function entry(name: string, i: number) {
	return {
		name_value: name,
		issuer_name: "CN=R3, O=Let's Encrypt",
		not_before: `2026-01-01T00:00:00.${String(9_999 - i).padStart(4, '0')}Z`,
		not_after: '2030-01-01T00:00:00Z',
	};
}

function issuance(id: number, names: string[]) {
	return {
		id: String(id),
		dns_names: names,
		not_before: '2026-02-01T00:00:00Z',
		not_after: '2030-05-01T00:00:00Z',
		issuer: { name: "C=US, O=Let's Encrypt, CN=R11" },
	};
}

function urlOf(url: string | URL | Request): string {
	return typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
}

/** The production #866 shape: crt.sh fails, Certspotter alone answers (index exhausted). */
function mockDegradedSingleSource() {
	globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
		const s = urlOf(url);
		if (s.includes('crt.sh')) return Response.json({}, { status: 502 });
		if (s.includes('certspotter.com')) {
			return Response.json(
				[issuance(1, ['api.example.com']), issuance(2, ['vpn.example.com']), issuance(3, ['*.example.com'])],
				{ status: 200 },
			);
		}
		return Response.json({ Status: 0, Answer: [] }, { status: 200 });
	});
}

/** A healthy run: the first source answers and is read to the end. */
function mockHealthy() {
	globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
		const s = urlOf(url);
		if (s.includes('crt.sh')) {
			return Response.json([entry('api.example.com', 0), entry('vpn.example.com', 1), entry('*.example.com', 2)], { status: 200 });
		}
		return Response.json({ Status: 0, Answer: [] }, { status: 200 });
	});
}

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

function asKv(kv: ReturnType<typeof makeKv>): KVNamespace {
	return kv as unknown as KVNamespace;
}

describe('discover_subdomains — degraded single-source run is a FLOOR, not a count (#866)', () => {
	beforeEach(() => {
		vi.spyOn(console, 'log').mockImplementation(() => {});
	});
	afterEach(() => vi.restoreAllMocks());

	it('marks the count as a floor and keeps totalSubdomains numerically present', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		mockDegradedSingleSource();

		const result = await discoverSubdomains('example.com');

		// Premise: this IS the production shape — one contributor, index exhausted, crt.sh failed.
		expect(result.coverage?.contributing).toEqual(['certspotter']);
		expect(result.coverage?.perSource.find((s) => s.source === 'crtsh')?.outcome).toBe('http_error');
		expect(result.coverage?.perSource.find((s) => s.source === 'certspotter')?.indexExhausted).toBe(true);

		expect(result.countBasis).toBe('floor');
		expect(result.minSubdomainsObserved).toBe(3);
		// Backward compatibility: every existing reader keys on this integer.
		expect(result.totalSubdomains).toBe(3);
	});

	it('splits wildcard patterns out of the headline count', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		mockDegradedSingleSource();

		const result = await discoverSubdomains('example.com');

		expect(result.wildcardCerts).toBe(1);
		expect(result.concreteSubdomains).toBe(2);
		expect(result.concreteSubdomains).toBe(result.totalSubdomains - result.wildcardCerts);
	});

	it('raises the sample caveat to LOW and words it as a floor', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		mockDegradedSingleSource();

		const result = await discoverSubdomains('example.com');
		const caveat = result.issues.find((i) => i.type === 'ct_sample_not_inventory');

		expect(caveat).toBeDefined();
		expect(caveat?.severity).toBe('low');
		expect(caveat?.detail).toMatch(/at least 3/i);
		expect(caveat?.detail).toMatch(/floor/i);
		expect(caveat?.detail).toMatch(/2 concrete/);
		expect(caveat?.detail).toMatch(/1 wildcard/);
		// Must still name the failed source so the reader knows WHY it is a floor.
		expect(caveat?.detail).toMatch(/crtsh/);
		// Survives the 200-char compact sanitizer intact (see coverage spec).
		expect(caveat!.detail.length).toBeLessThanOrEqual(200);
		// Still the first issue — a display-truncated list must not drop it.
		expect(result.issues[0].type).toBe('ct_sample_not_inventory');
	});

	it.each(['compact', 'full'] as const)('%s prose says "at least N observed" with the split, never a bare count', async (format) => {
		const { discoverSubdomains, formatSubdomainDiscovery } = await import('../src/tools/discover-subdomains');
		mockDegradedSingleSource();

		const result = await discoverSubdomains('example.com');
		const output = formatSubdomainDiscovery(result, format);

		expect(output).toMatch(/at least 3 subdomains observed/i);
		expect(output).toMatch(/2 concrete/);
		expect(output).toMatch(/1 wildcard pattern/);
		expect(output).toMatch(/floor/i);
		// The pre-fix headline shapes.
		expect(output).not.toMatch(/— 3 subdomains \(/);
		expect(output).not.toMatch(/Total: 3 subdomains across/);
		expect(output).toMatch(/\[LOW\]/);
	});

	it('carries the floor contract through the MCP handler structuredContent', async () => {
		const { handleToolsCall } = await import('../src/handlers/tools');
		mockDegradedSingleSource();

		const res = await handleToolsCall({ name: 'discover_subdomains', arguments: { domain: 'example.com' } }, undefined, undefined);
		const payload = res.structuredContent as Record<string, unknown>;

		expect(payload.countBasis).toBe('floor');
		expect(payload.minSubdomainsObserved).toBe(3);
		expect(payload.concreteSubdomains).toBe(2);
		expect(payload.totalSubdomains).toBe(3);
	});
});

describe('discover_subdomains — a healthy run is unchanged', () => {
	beforeEach(() => {
		vi.spyOn(console, 'log').mockImplementation(() => {});
	});
	afterEach(() => vi.restoreAllMocks());

	it('reports countBasis sample, no floor member, and keeps the caveat at info', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		mockHealthy();

		const result = await discoverSubdomains('example.com');

		// Control for the discriminator: `coverage.degraded` is true here too
		// (Certspotter was never needed), yet nothing about THIS run cut recall.
		expect(result.coverage?.degraded).toBe(true);
		expect(result.countBasis).toBe('sample');
		expect(result).not.toHaveProperty('minSubdomainsObserved');
		expect(result.totalSubdomains).toBe(3);
		expect(result.concreteSubdomains).toBe(2);

		const caveat = result.issues.find((i) => i.type === 'ct_sample_not_inventory');
		expect(caveat?.severity).toBe('info');
		expect(result.issues.some((i) => i.severity === 'low')).toBe(false);
	});

	it.each(['compact', 'full'] as const)('%s prose keeps a plain count but still shows the concrete/wildcard split', async (format) => {
		const { discoverSubdomains, formatSubdomainDiscovery } = await import('../src/tools/discover-subdomains');
		mockHealthy();

		const result = await discoverSubdomains('example.com');
		const output = formatSubdomainDiscovery(result, format);

		expect(output).toMatch(/3 subdomains \(2 concrete, 1 wildcard pattern\)/);
		expect(output).not.toMatch(/at least 3/i);
		expect(output).not.toMatch(/\[LOW\]/);
	});
});

describe('discover_subdomains — other recall-cut paths are floors too', () => {
	beforeEach(() => {
		vi.spyOn(console, 'log').mockImplementation(() => {});
	});
	afterEach(() => vi.restoreAllMocks());

	it('a certstream answer that timed out mid-query (partial, index not exhausted) is a floor', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const certstreamFetch = vi.fn(async () =>
			Response.json({ domain: 'example.com', subdomains: ['api.example.com', '*.example.com'], certificateCount: 2, timedOut: true, cached: false }),
		);
		globalThis.fetch = vi.fn(async () => {
			throw new Error('direct sources must not be used when certstream answers');
		});

		const result = await discoverSubdomains('example.com', { fetch: certstreamFetch as unknown as typeof fetch });

		expect(result.partial).toBe(true);
		expect(result.sourceIndexExhausted).toBe(false);
		expect(result.countBasis).toBe('floor');
		expect(result.minSubdomainsObserved).toBe(2);
		expect(result.concreteSubdomains).toBe(1);
		expect(result.issues.find((i) => i.type === 'ct_sample_not_inventory')?.severity).toBe('low');
	});

	it('a stale last-known-good re-serve is a floor even though the cached run was healthy', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const kv = makeKv();

		mockHealthy();
		const fresh = await discoverSubdomains('example.com', undefined, undefined, { cacheKv: asKv(kv) });
		expect(fresh.countBasis).toBe('sample');

		// Age past the fresh window so the next call reaches the (failing) sources.
		for (const [key, raw] of kv.store) {
			const e = JSON.parse(raw) as { cachedAt?: number };
			if (typeof e.cachedAt === 'number') kv.store.set(key, JSON.stringify({ ...e, cachedAt: e.cachedAt - 2 * 60 * 60 * 1000 }));
		}
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = urlOf(url);
			if (s.includes('crt.sh') || s.includes('certspotter.com')) return Response.json({}, { status: 503 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});

		const stale = await discoverSubdomains('example.com', undefined, undefined, { cacheKv: asKv(kv) });

		expect(stale.stale).toBe(true);
		expect(stale.countBasis).toBe('floor');
		expect(stale.minSubdomainsObserved).toBe(3);
		expect(stale.concreteSubdomains).toBe(2);

		// The caveat must be REWRITTEN, not merely re-tagged: a `[LOW]` issue that
		// still carries the healthy sample wording is the #866 shape on a new path.
		const caveat = stale.issues.find((i) => i.type === 'ct_sample_not_inventory');
		expect(caveat?.severity).toBe('low');
		expect(caveat?.detail).toMatch(/floor/i);
		expect(caveat?.detail).toMatch(/recall was cut/i);
		expect(caveat?.detail).toMatch(/stale/i);
		expect(caveat?.detail).not.toMatch(/is a LOWER BOUND from a CT sample/);
		expect(caveat!.detail.length).toBeLessThanOrEqual(200);
		expect(stale.issues[0].type).toBe('ct_sample_not_inventory');
		// The stale caveat also renders, in both formats.
		const { formatSubdomainDiscovery } = await import('../src/tools/discover-subdomains');
		expect(formatSubdomainDiscovery(stale, 'compact')).toContain(caveat!.detail);
		expect(formatSubdomainDiscovery(stale, 'full')).toMatch(/\[LOW\]/);
	});
});

describe('discover_subdomains — total failure keeps the existing not-assessed shape', () => {
	beforeEach(() => {
		vi.spyOn(console, 'log').mockImplementation(() => {});
	});
	afterEach(() => vi.restoreAllMocks());

	it('still reports sourceUnavailable + a high unconfirmed_zero, and never claims a sample basis', async () => {
		const { discoverSubdomains, formatSubdomainDiscovery } = await import('../src/tools/discover-subdomains');
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = urlOf(url);
			if (s.includes('crt.sh') || s.includes('certspotter.com')) return Response.json({}, { status: 503 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});

		const result = await discoverSubdomains('example.com');

		expect(result.sourceUnavailable).toBe(true);
		expect(result.totalSubdomains).toBe(0);
		expect(result.issues.find((i) => i.type === 'unconfirmed_zero')?.severity).toBe('high');
		expect(result.countBasis).toBe('floor');
		expect(result.minSubdomainsObserved).toBe(0);
		expect(result.concreteSubdomains).toBe(0);
		// The prose branch for an outage is untouched.
		expect(formatSubdomainDiscovery(result, 'full')).toMatch(/source unavailable/i);
	});
});

describe('discover_subdomains — standalone: this change cannot move a scan score', () => {
	it('is not a scan-included category and carries no scoring tier', async () => {
		const { TOOLS } = await import('../src/schemas/tool-definitions');
		const def = TOOLS.find((t) => t.name === 'discover_subdomains') as { scanIncluded?: boolean; tier?: unknown; group?: string } | undefined;
		expect(def).toBeDefined();
		expect(def!.scanIncluded).toBe(false);
		expect(def!.tier).toBeUndefined();
		expect(def!.group).toBe('intelligence');
	});
});
