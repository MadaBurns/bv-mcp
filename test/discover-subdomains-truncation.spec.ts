// SPDX-License-Identifier: BUSL-1.1
//
// Regression suite for issue #573 — `discover_subdomains` silently returned a
// partial, biased subset of a domain's CT-attested hostnames and reported
// totals that made the truncation undetectable by the caller.
//
// Four defect classes are locked here:
//   A. cap with no signal          → `truncated` / `returned` / `sources` /
//                                    `enumerationComplete` on the result.
//   B. single-page Certspotter     → follow `Link: rel="next"` via `after=`,
//                                    bounded by MAX_CT_PAGES + the sync budget.
//   C. wildcard/expired counted     → counts are taken over the WHOLE enumerated
//      after the display slice        set, never the returned slice.
//   D. certstream path sliced       → totals computed pre-slice.
//      before counting
//
// The pre-existing cap test gave every name its own cert and NO wildcards, so
// the post-slice counting bug (C) was never exercised. These fixtures do the
// opposite: the wildcards/expired names sort to the BACK of the list, exactly
// where the display slice would drop them.

import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { setupFetchMock } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

/**
 * Build a crt.sh entry whose `not_before` sorts deterministically: `rank` 0 is
 * the NEWEST (sorted first), higher ranks sort later — i.e. toward the slice
 * boundary. Lexicographic ISO comparison is what the tool actually uses.
 */
function rankedEntry(name: string, rank: number, expired = false) {
	const millis = String(9_999 - rank).padStart(4, '0');
	return {
		name_value: name,
		issuer_name: "CN=R3, O=Let's Encrypt",
		not_before: `2026-01-01T00:00:00.${millis}Z`,
		not_after: expired ? '2020-01-02T00:00:00Z' : '2030-01-01T00:00:00Z',
	};
}

/** Mock ONLY crt.sh; everything else resolves as an empty DoH answer. */
function mockCrtSh(response: unknown, ok = true) {
	globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
		const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
		if (s.includes('crt.sh')) return Response.json(response, { status: ok ? 200 : 500 });
		return Response.json({ Status: 0, Answer: [] }, { status: 200 });
	});
}

describe('discover_subdomains — whole-set counting (defect C)', () => {
	beforeEach(() => {
		vi.spyOn(console, 'log').mockImplementation(() => {});
	});
	afterEach(() => vi.restoreAllMocks());

	it('counts wildcards and expired certs over the FULL set, not the returned slice', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');

		// 600 names: the first 500 are plain + current, and the 3 wildcards + 4
		// expired names deliberately sort past the 500-name return cap. A
		// post-slice count reports 0/0 here; the honest count is 3/4.
		const entries = [
			...Array.from({ length: 520 }, (_, i) => rankedEntry(`sub${i}.example.com`, i)),
			rankedEntry('*.a.example.com', 550),
			rankedEntry('*.b.example.com', 551),
			rankedEntry('*.c.example.com', 552),
			rankedEntry('gone1.example.com', 560, true),
			rankedEntry('gone2.example.com', 561, true),
			rankedEntry('gone3.example.com', 562, true),
			rankedEntry('gone4.example.com', 563, true),
		];
		mockCrtSh(entries);

		const result = await discoverSubdomains('example.com');

		expect(result.totalSubdomains).toBe(527);
		expect(result.subdomains).toHaveLength(500);
		// None of the wildcard/expired names survive the slice…
		expect(result.subdomains.some((s) => s.isWildcard)).toBe(false);
		expect(result.subdomains.some((s) => s.isExpired)).toBe(false);
		// …but the counts are still the truth about the estate.
		expect(result.wildcardCerts).toBe(3);
		expect(result.expiredCerts).toBe(4);

		// And the derived issues follow the counts, not the slice.
		const wildcardIssue = result.issues.find((i) => i.type === 'wildcard_exposure');
		expect(wildcardIssue?.detail).toContain('3 wildcard');
		expect(result.issues.some((i) => i.type === 'expired_subdomain')).toBe(true);
	});

	it('keeps per-name issue rows bounded so a 500-name estate cannot flood the output', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const entries = Array.from({ length: 300 }, (_, i) => rankedEntry(`gone${i}.example.com`, i, true));
		mockCrtSh(entries);

		const result = await discoverSubdomains('example.com');

		expect(result.expiredCerts).toBe(300);
		const expiredRows = result.issues.filter((i) => i.type === 'expired_subdomain');
		// Bounded rows + one roll-up row naming the remainder.
		expect(expiredRows.length).toBeLessThanOrEqual(26);
		expect(expiredRows.some((i) => /further|more/i.test(i.detail))).toBe(true);
	});
});

describe('discover_subdomains — explicit truncation contract (defect A)', () => {
	beforeEach(() => {
		vi.spyOn(console, 'log').mockImplementation(() => {});
	});
	afterEach(() => vi.restoreAllMocks());

	it('sets truncated:true with an accurate `returned` when the set exceeds the cap', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		mockCrtSh(Array.from({ length: 640 }, (_, i) => rankedEntry(`sub${i}.example.com`, i)));

		const result = await discoverSubdomains('example.com');

		expect(result.totalSubdomains).toBe(640);
		expect(result.returned).toBe(500);
		expect(result.subdomains).toHaveLength(500);
		expect(result.truncated).toBe(true);
		expect(result.sources).toContain('crtsh');
		// crt.sh answers in one shot — the ENUMERATION was complete even though
		// the returned list is capped.
		expect(result.enumerationComplete).toBe(true);
	});

	it('leaves truncated falsy and reports `returned` when the set fits under the cap', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		mockCrtSh(Array.from({ length: 12 }, (_, i) => rankedEntry(`sub${i}.example.com`, i)));

		const result = await discoverSubdomains('example.com');

		expect(result.totalSubdomains).toBe(12);
		expect(result.returned).toBe(12);
		expect(result.truncated).toBeFalsy();
		expect(result.enumerationComplete).toBe(true);
	});

	it('surfaces the contract through the MCP handler structuredContent', async () => {
		const { handleToolsCall } = await import('../src/handlers/tools');
		mockCrtSh(Array.from({ length: 640 }, (_, i) => rankedEntry(`sub${i}.example.com`, i)));

		const res = await handleToolsCall({ name: 'discover_subdomains', arguments: { domain: 'example.com' } }, undefined, undefined);
		const payload = res.structuredContent as Record<string, unknown>;

		expect(payload.truncated).toBe(true);
		expect(payload.returned).toBe(500);
		expect(payload.sources).toEqual(['crtsh']);
	});
});

describe('discover_subdomains — Certspotter pagination (defect B)', () => {
	beforeEach(() => {
		vi.spyOn(console, 'log').mockImplementation(() => {});
	});
	afterEach(() => vi.restoreAllMocks());

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

	function certspotterPage(body: unknown, next: boolean) {
		return Response.json(body, {
			status: 200,
			headers: next ? { Link: '<https://api.certspotter.com/v1/issuances?after=next>; rel="next"' } : {},
		});
	}

	it('follows Link: rel="next" via after=<id> and unions every page', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const urls: string[] = [];
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh')) return Response.json({}, { status: 503 });
			if (s.includes('certspotter.com')) {
				urls.push(s);
				if (!s.includes('after=')) {
					// Page 1: full page + a next link.
					return certspotterPage(
						Array.from({ length: 100 }, (_, i) => issuance(i + 1, [`page1-${i}.example.com`])),
						true,
					);
				}
				// Page 2: short page, no next link.
				return certspotterPage([issuance(101, ['page2-a.example.com']), issuance(102, ['page2-b.example.com'])], false);
			}
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});

		const result = await discoverSubdomains('example.com');

		expect(urls).toHaveLength(2);
		// The cursor must be the LAST issuance id of the previous page.
		expect(urls[1]).toContain('after=100');

		const names = result.subdomains.map((s) => s.subdomain);
		expect(names).toContain('page1-0.example.com');
		expect(names).toContain('page1-99.example.com');
		expect(names).toContain('page2-a.example.com');
		expect(names).toContain('page2-b.example.com');
		expect(result.totalSubdomains).toBe(102);
		expect(result.sources).toContain('certspotter');
		expect(result.enumerationComplete).toBe(true);
		expect(result.truncated).toBeFalsy();
	});

	it('stops at MAX_CT_PAGES and reports the enumeration as incomplete', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		let pages = 0;
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh')) return Response.json({}, { status: 503 });
			if (s.includes('certspotter.com')) {
				pages++;
				// Never-ending index: every page is full and advertises a next link.
				return certspotterPage(
					Array.from({ length: 20 }, (_, i) => issuance(pages * 1000 + i, [`p${pages}-${i}.example.com`])),
					true,
				);
			}
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});

		const result = await discoverSubdomains('example.com');

		expect(pages).toBe(8); // MAX_CT_PAGES
		expect(result.enumerationComplete).toBe(false);
		expect(result.truncated).toBe(true);
		expect(result.totalSubdomains).toBe(160);
	});

	it('stops paginating when the synchronous budget is exhausted, keeping page-1 data', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		let pages = 0;
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh')) return Response.json({}, { status: 503 });
			if (s.includes('certspotter.com')) {
				pages++;
				return certspotterPage(
					Array.from({ length: 5 }, (_, i) => issuance(pages * 1000 + i, [`p${pages}-${i}.example.com`])),
					true,
				);
			}
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});

		// A deadline that flips from "plenty" to "exhausted" the instant page 1 is
		// read, so the BUDGET — not MAX_CT_PAGES — is what terminates the loop.
		// (A getter keeps the wall-clock cost of the assertion at zero.)
		const options = {
			get deadlineMs() {
				return pages >= 1 ? Date.now() - 1 : Date.now() + 20_000;
			},
		};

		const result = await discoverSubdomains('example.com', undefined, undefined, options);

		expect(pages).toBe(1);
		expect(result.subdomains.map((s) => s.subdomain)).toContain('p1-0.example.com');
		expect(result.enumerationComplete).toBe(false);
		expect(result.truncated).toBe(true);
	});

	it('treats a first-page failure as a source failure (unchanged failover semantics)', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
			const s = typeof url === 'string' ? url : url instanceof URL ? url.toString() : (url as Request).url;
			if (s.includes('crt.sh') || s.includes('certspotter.com')) return Response.json({}, { status: 503 });
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});

		const result = await discoverSubdomains('example.com');
		expect(result.sourceUnavailable).toBe(true);
	});
});

describe('discover_subdomains — certstream path totals (defect D)', () => {
	beforeEach(() => {
		vi.spyOn(console, 'log').mockImplementation(() => {});
	});
	afterEach(() => vi.restoreAllMocks());

	it('computes totals BEFORE the return cap on the certstream fast path', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const names = Array.from({ length: 640 }, (_, i) => `cs${i}.example.com`);
		const certstreamFetch = vi.fn(async () =>
			Response.json({ domain: 'example.com', subdomains: names, certificateCount: 700, timedOut: false, cached: false }),
		);
		globalThis.fetch = vi.fn(async () => {
			throw new Error('crt.sh fallback should not be used');
		});

		const result = await discoverSubdomains('example.com', { fetch: certstreamFetch as unknown as typeof fetch });

		expect(result.totalSubdomains).toBe(640);
		expect(result.returned).toBe(500);
		expect(result.subdomains).toHaveLength(500);
		expect(result.truncated).toBe(true);
		expect(result.sources).toContain('certstream');
	});

	it('reads the certstream /sans `truncated` flag into enumerationComplete', async () => {
		const { discoverSubdomains } = await import('../src/tools/discover-subdomains');
		const certstreamFetch = vi.fn(async (input: RequestInfo | URL) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
			if (url.includes('/enumerate')) return new Response('{}', { status: 502 });
			return Response.json({
				domain: 'example.com',
				names: ['api.example.com', 'vpn.example.com'],
				certificateCount: 2,
				timedOut: false,
				truncated: true,
				cached: false,
			});
		});
		globalThis.fetch = vi.fn(async () => {
			throw new Error('crt.sh fallback should not be used');
		});

		const result = await discoverSubdomains('example.com', { fetch: certstreamFetch as unknown as typeof fetch });

		expect(result.totalSubdomains).toBe(2);
		expect(result.enumerationComplete).toBe(false);
		// An incomplete upstream enumeration is a truncated answer even though
		// every enumerated name was returned.
		expect(result.truncated).toBe(true);
	});
});

describe('discover_subdomains — honest overflow wording', () => {
	async function fmt() {
		const { formatSubdomainDiscovery } = await import('../src/tools/discover-subdomains');
		return formatSubdomainDiscovery;
	}

	function bulkResult(overrides: Record<string, unknown>) {
		return {
			domain: 'bnz.co.nz',
			totalSubdomains: 140,
			totalCertificates: 100,
			subdomains: Array.from({ length: 140 }, (_, i) => ({
				subdomain: `sub${i}.bnz.co.nz`,
				firstSeen: '2026-01-01',
				lastSeen: '2026-01-01',
				issuer: 'R3',
				certCount: 1,
				isWildcard: false,
				isExpired: false,
			})),
			wildcardCerts: 0,
			expiredCerts: 0,
			uniqueIssuers: ['R3'],
			issues: [],
			...overrides,
		};
	}

	it('caps the RENDERED host list at 100 even when 500 are returned structurally', async () => {
		const formatSubdomainDiscovery = await fmt();
		const output = formatSubdomainDiscovery(bulkResult({ returned: 140, truncated: false, enumerationComplete: true }), 'full');

		expect(output).toContain('sub99.bnz.co.nz');
		expect(output).not.toContain('sub100.bnz.co.nz');
		expect(output).toContain('40 more subdomains not shown');
	});

	it('says "at least N more" and names the source when the enumeration was incomplete', async () => {
		const formatSubdomainDiscovery = await fmt();
		const result = bulkResult({ returned: 140, truncated: true, enumerationComplete: false, sources: ['certspotter'] });

		const full = formatSubdomainDiscovery(result, 'full');
		expect(full).toContain('at least 40 more');
		expect(full).toMatch(/incomplete/i);
		expect(full).toContain('certspotter');

		const compact = formatSubdomainDiscovery(result, 'compact');
		expect(compact).toContain('at least 40 more');
		expect(compact).toMatch(/incomplete/i);
	});

	it('warns about an incomplete enumeration even when nothing is hidden by the display cap', async () => {
		const formatSubdomainDiscovery = await fmt();
		const result = {
			domain: 'bnz.co.nz',
			totalSubdomains: 2,
			totalCertificates: 2,
			subdomains: [
				{ subdomain: 'a.bnz.co.nz', firstSeen: '', lastSeen: '', issuer: 'R3', certCount: 1, isWildcard: false, isExpired: false },
				{ subdomain: 'b.bnz.co.nz', firstSeen: '', lastSeen: '', issuer: 'R3', certCount: 1, isWildcard: false, isExpired: false },
			],
			wildcardCerts: 0,
			expiredCerts: 0,
			uniqueIssuers: ['R3'],
			issues: [],
			returned: 2,
			truncated: true,
			enumerationComplete: false,
			sources: ['certspotter'],
		};

		const full = formatSubdomainDiscovery(result, 'full');
		expect(full).toMatch(/incomplete/i);
		expect(full).toContain('certspotter');
		// No phantom "and 0 more".
		expect(full).not.toMatch(/and (at least )?0 more/);
	});

	it('keeps the exact wording when the display cap alone hides names', async () => {
		const formatSubdomainDiscovery = await fmt();
		const output = formatSubdomainDiscovery(bulkResult({ returned: 140, truncated: false, enumerationComplete: true }), 'compact');

		expect(output).toContain('...and 40 more');
		expect(output).not.toContain('at least');
	});
});
