// SPDX-License-Identifier: BUSL-1.1
//
// Regression suite for the CT ENUMERATION-HONESTY defect (follow-on to #573/#577).
//
// #577 fixed a real silent truncation and, in doing so, shipped a field named
// `enumerationComplete`. Its authored meaning was narrow and true — "we
// paginated the ONE source that answered to the end of its index" — but its
// NAME asserts something far larger, and a reasonable consumer reads
// `enumerationComplete: true` as "this is the estate".
//
// Measured against production on 2026-07-27 (bnz.co.nz):
//   - the tool returned 165 unique names, `sources: ["certspotter"]`,
//     `truncated: false`, `enumerationComplete: true`;
//   - crt.sh's full CT history for the same estate holds 420 unique names;
//   - four of the missing names — ams.privatebank / realme / cardsecurity /
//     myaccess .bnz.co.nz — resolve to live production IPs.
// So a `true` flag accompanied a ~60%-short answer about a bank's external
// attack surface. That is the same false-confidence class the whole #573/#575/
// #577 campaign exists to remove, one level up.
//
// What is locked here:
//   1. NO field on the result may assert estate-level completeness. The
//      `enumerationComplete` NAME is gone; the narrow truth it encoded lives on
//      as `sourceIndexExhausted`, which cannot be misread.
//   2. Every result carries a `coverage` record whose `basis` is the literal
//      'ct-sample' — a one-member union, so there is no representable value
//      meaning "inventory".
//   3. Coverage names which sources contributed, which were attempted and
//      failed, and which were never consulted at all — the production payload
//      showed `["certspotter"]` with no hint that crt.sh had been asked and had
//      failed, nor that Certspotter's free tier only sees a ~1-year window.
//   4. The rendered text ALWAYS carries the sample caveat, including on the
//      fully-successful single-source path — the exact case that read as
//      authoritative before.

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

/** One Certspotter issuance with an `id` (the pagination cursor). */
function issuance(id: number, names: string[]) {
	return {
		id: String(id),
		dns_names: names,
		not_before: '2026-02-01T00:00:00Z',
		not_after: '2030-05-01T00:00:00Z',
		issuer: { name: "C=US, O=Let's Encrypt, CN=R11" },
	};
}

describe('discover_subdomains — no field may assert estate completeness', () => {
	beforeEach(() => {
		vi.spyOn(console, 'log').mockImplementation(() => {});
	});
	afterEach(() => vi.restoreAllMocks());

	it('does not expose an `enumerationComplete` field at all', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh')) return Response.json([entry('a.example.com', 0)], { status: 200 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});

		const result = await discoverSubdomains('example.com');

		// The name is the defect. Not renamed-and-aliased — gone.
		expect(result).not.toHaveProperty('enumerationComplete');
		expect(JSON.stringify(result)).not.toContain('enumerationComplete');
	});

	it('reports the narrow per-source truth as `sourceIndexExhausted` while refusing the inventory claim', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh')) return Response.json([entry('a.example.com', 0), entry('b.example.com', 1)], { status: 200 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});

		const result = await discoverSubdomains('example.com');

		// We DID read crt.sh's answer to the end — that narrow claim survives…
		expect(result.sourceIndexExhausted).toBe(true);
		// …but it is explicitly NOT an estate inventory.
		expect(result.coverage?.basis).toBe('ct-sample');
		expect(result.coverage?.caveat).toMatch(/not (an )?(estate )?inventory/i);
	});
});

describe('discover_subdomains — per-source coverage record', () => {
	beforeEach(() => {
		vi.spyOn(console, 'log').mockImplementation(() => {});
	});
	afterEach(() => vi.restoreAllMocks());

	it('records a failed source alongside the one that answered (the production bnz.co.nz shape)', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			// crt.sh 502s — exactly what it did on 6 of 8 live samples on 2026-07-27.
			if (s.includes('crt.sh')) return Response.json({}, { status: 502 });
			if (s.includes('certspotter.com')) {
				return Response.json([issuance(1, ['api.example.com']), issuance(2, ['vpn.example.com'])], { status: 200 });
			}
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});

		const result = await discoverSubdomains('example.com');

		expect(result.sources).toEqual(['certspotter']);
		// The old payload stopped there. A caller could not tell that crt.sh had
		// been asked and had failed — i.e. that recall was degraded.
		const crtsh = result.coverage?.perSource.find((s) => s.source === 'crtsh');
		expect(crtsh).toBeDefined();
		expect(crtsh?.outcome).toBe('http_error');
		expect(crtsh?.contributed).toBe(false);
		expect(result.coverage?.contributing).toEqual(['certspotter']);
		expect(result.coverage?.degraded).toBe(true);
	});

	it('names the sources that were never consulted on the certstream fast path', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const certstreamFetch = vi.fn(async () =>
			Response.json({
				domain: 'example.com',
				subdomains: ['api.example.com', 'vpn.example.com'],
				certificateCount: 2,
				timedOut: false,
				cached: false,
			}),
		);
		globalThis.fetch = vi.fn(async () => {
			throw new Error('direct sources must not be used when certstream answers');
		});

		const result = await discoverSubdomains('example.com', { fetch: certstreamFetch as unknown as typeof fetch });

		expect(result.coverage?.contributing).toEqual(['certstream']);
		// A fast-path answer is ONE source's view. crt.sh and Certspotter were
		// never asked, and the caller has to be able to see that.
		expect(result.coverage?.notConsulted).toContain('crtsh');
		expect(result.coverage?.notConsulted).toContain('certspotter');
	});

	it('labels each source with the slice of CT history it can even see', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh')) return Response.json({}, { status: 502 });
			if (s.includes('certspotter.com')) return Response.json([issuance(1, ['api.example.com'])], { status: 200 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});

		const result = await discoverSubdomains('example.com');

		// Measured 2026-07-27: Certspotter's unauthenticated feed for bnz.co.nz
		// spanned 2025-07-07 → 2026-07-27 only. Exhausting its index is therefore
		// structurally incapable of covering an estate's certificate history.
		const cs = result.coverage?.perSource.find((s) => s.source === 'certspotter');
		expect(cs?.indexExhausted).toBe(true);
		expect(cs?.historyWindow).toBe('recent-window');

		// crt.sh is queried with `exclude=expired`, so even a healthy crt.sh only
		// ever shows currently-valid certificates.
		const crt = result.coverage?.perSource.find((s) => s.source === 'crtsh');
		expect(crt?.historyWindow).toBe('unexpired-only');
	});

	it('carries coverage through the MCP handler structuredContent', async () => {
		const { handleToolsCall } = await import('../src/handlers/tools');
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh')) return Response.json([entry('a.example.com', 0)], { status: 200 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});

		const res = await handleToolsCall({ name: 'discover_subdomains', arguments: { domain: 'example.com' } }, undefined, undefined);
		const payload = res.structuredContent as Record<string, unknown>;

		expect(payload).not.toHaveProperty('enumerationComplete');
		expect((payload.coverage as { basis?: string } | undefined)?.basis).toBe('ct-sample');
	});
});

describe('discover_subdomains — issues[] carries the sample caveat', () => {
	beforeEach(() => {
		vi.spyOn(console, 'log').mockImplementation(() => {});
	});
	afterEach(() => vi.restoreAllMocks());

	it('always emits a ct_sample_not_inventory issue on a non-empty result', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh')) return Response.json([entry('a.example.com', 0)], { status: 200 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});

		const result = await discoverSubdomains('example.com');

		// Structured consumers that read ONLY `issues[]` (the failure mode the
		// `unconfirmed_zero` issue was added for) must also see the caveat.
		const caveat = result.issues.find((i) => i.type === 'ct_sample_not_inventory');
		expect(caveat).toBeDefined();
		expect(caveat?.detail).toMatch(/lower bound|not an inventory|not a complete/i);
	});

	it('keeps the caveat detail short enough to survive the 200-char compact sanitizer', async () => {
		const { discoverSubdomains, formatSubdomainDiscovery } = await import('../src/tools/discover-subdomains');
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh')) return Response.json([entry('a.example.com', 0)], { status: 200 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});

		const result = await discoverSubdomains('example.com');
		const caveat = result.issues.find((i) => i.type === 'ct_sample_not_inventory');

		// `formatCompact` pushes issue details through `sanitizeOutputText(…, 200)`.
		// A caveat truncated mid-sentence loses the clause that carries the meaning,
		// so the rendered line must be a complete sentence.
		expect(caveat!.detail.length).toBeLessThanOrEqual(200);
		expect(formatSubdomainDiscovery(result, 'compact')).toContain(caveat!.detail);
	});

	it('prepends the caveat so a display-truncated issue list cannot drop it', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh')) {
				return Response.json(
					Array.from({ length: 40 }, (_, i) => entry(`shadow${i}.example.com`, i)),
					{ status: 200 },
				);
			}
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});

		const result = await discoverSubdomains('example.com');
		expect(result.issues[0].type).toBe('ct_sample_not_inventory');
	});
});

describe('discover_subdomains — rendered text always states the sample caveat', () => {
	beforeEach(() => {
		vi.spyOn(console, 'log').mockImplementation(() => {});
	});
	afterEach(() => vi.restoreAllMocks());

	async function renderLiveRun(format: 'full' | 'compact') {
		const { discoverSubdomains, formatSubdomainDiscovery } = await import('../src/tools/discover-subdomains');
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh')) return Response.json({}, { status: 502 });
			if (s.includes('certspotter.com')) return Response.json([issuance(1, ['api.example.com'])], { status: 200 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});
		const result = await discoverSubdomains('example.com');
		return formatSubdomainDiscovery(result, format);
	}

	it('states the caveat in full format even when the single source was exhausted', async () => {
		const output = await renderLiveRun('full');
		expect(output).toMatch(/lower bound/i);
		expect(output).toMatch(/sample/i);
		// It must never read as an inventory.
		expect(output).not.toMatch(/complete inventory|full inventory|entire estate/i);
	});

	it('states the caveat in compact format too', async () => {
		const output = await renderLiveRun('compact');
		expect(output).toMatch(/lower bound/i);
	});

	it('names the failed source in the rendered coverage line', async () => {
		const output = await renderLiveRun('full');
		expect(output).toContain('crtsh');
		expect(output).toContain('certspotter');
	});
});
