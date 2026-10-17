// SPDX-License-Identifier: BUSL-1.1

// #738 item 3 — the Certspotter fallback was STRUCTURALLY UNREACHABLE.
//
// `queryDirectSources` refuses to start a source it cannot finish inside the
// caller's deadline (`hasBudgetFor(options, source.timeoutMs)`), an all-or-
// nothing gate. With crt.sh at a hardcoded 10s out of the 24s handler budget,
// the remainder was 24_000 - 10_000 = 14_000 = exactly `CERTSPOTTER_TIMEOUT_MS`,
// so ANY elapsed time at all (cache read, fast-path check, JSON parse) made the
// gate false and Certspotter was never asked. Measured live on v3.58.0:
// `crtsh=timeout, certspotter=not-consulted` for meta.com AND anthropic.com,
// while Certspotter answered anthropic.com directly in HTTP 200 / 43 KB.
//
// These are assertions against the real constants, not comments: any future
// bump of one timeout that re-closes the failover window fails here.

import { describe, expect, it, vi, afterEach } from 'vitest';
import {
	CERTSPOTTER_TIMEOUT_MS,
	CT_FAILOVER_HEADROOM_MS,
	CT_SOURCE_TIMEOUT_MS,
	DISCOVER_SUBDOMAINS_SYNC_BUDGET_MS,
	discoverSubdomains,
} from '../src/tools/discover-subdomains';

describe('CT failover budget invariant (#738)', () => {
	it('leaves a FULL Certspotter attempt inside the handler budget after crt.sh burns its whole timeout', () => {
		expect(CT_SOURCE_TIMEOUT_MS + CERTSPOTTER_TIMEOUT_MS).toBeLessThanOrEqual(DISCOVER_SUBDOMAINS_SYNC_BUDGET_MS);
		// Strictly less: equality is the pre-fix state, where the gate fails on any
		// non-zero elapsed time.
		expect(DISCOVER_SUBDOMAINS_SYNC_BUDGET_MS - CT_SOURCE_TIMEOUT_MS - CERTSPOTTER_TIMEOUT_MS).toBeGreaterThanOrEqual(
			CT_FAILOVER_HEADROOM_MS,
		);
	});

	it('keeps crt.sh a useful primary rather than trimming it to nothing', () => {
		expect(CT_SOURCE_TIMEOUT_MS).toBeGreaterThanOrEqual(5_000);
	});

	it('still consults Certspotter after crt.sh consumes its entire timeout', async () => {
		const consulted: string[] = [];
		vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = String(input instanceof Request ? input.url : input);
			if (url.includes('crt.sh')) {
				consulted.push('crtsh');
				// crt.sh hangs until its per-source abort signal fires — the exact
				// production shape that used to consume the whole budget.
				return await new Promise<Response>((_resolve, reject) => {
					init?.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true });
				});
			}
			if (url.includes('certspotter.com')) {
				consulted.push('certspotter');
				return Response.json([{ id: '1', dns_names: ['api.example.com'], not_before: '', not_after: '' }], { status: 200 });
			}
			return Response.json({}, { status: 404 });
		});

		// The real handler deadline. Elapsed time is non-zero by the time crt.sh
		// aborts, which is precisely what the pre-fix arithmetic could not absorb.
		// Faked clock, NOT a shortened budget: the arithmetic under test is between
		// the production constants, so shrinking any of them would test different
		// numbers than the ones that ship. `composeAbortSignal` arms the per-source
		// cut with a plain `setTimeout`, so advancing the clock reaches the identical
		// abort — without the 8s of real waiting CT_SOURCE_TIMEOUT_MS otherwise costs.
		let result: Awaited<ReturnType<typeof discoverSubdomains>>;
		vi.useFakeTimers();
		try {
			const pending = discoverSubdomains('example.com', undefined, undefined, {
				deadlineMs: Date.now() + DISCOVER_SUBDOMAINS_SYNC_BUDGET_MS,
			});
			// Past CT_SOURCE_TIMEOUT_MS so crt.sh is cut, but short of the handler
			// deadline so Certspotter still has its window — the whole point here.
			await vi.advanceTimersByTimeAsync(CT_SOURCE_TIMEOUT_MS + CT_FAILOVER_HEADROOM_MS);
			result = await pending;
		} finally {
			vi.useRealTimers();
		}

		expect(consulted).toEqual(['crtsh', 'certspotter']);
		expect(result.coverage?.notConsulted ?? []).not.toContain('certspotter');
		expect(result.totalSubdomains).toBe(1);
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});
});

// SQ-345 — a young owned CT index (`bv-ct-index`) no longer ends the ladder, so the
// budget arithmetic above must still hold when it answers FIRST: the extra fallback
// consult may not starve Certspotter, and an exhausted budget must still skip the
// direct sources rather than start a fetch it cannot finish.
describe('CT failover budget with a young owned index in front (SQ-345)', () => {
	const youngIndex = (subdomains: string[]) =>
		vi.fn(async () =>
			Response.json({
				domain: 'example.com',
				subdomains,
				certificateCount: subdomains.length,
				timedOut: false,
				cached: false,
				truncated: false,
				coverage: {
					source: 'bv-ct-index',
					indexStartedAt: new Date(Date.now() - 30 * 86_400_000).toISOString(),
					freshThrough: new Date().toISOString(),
					historyWindow: 'forward-from',
					truncated: false,
				},
			}),
		) as unknown as typeof fetch;

	afterEach(() => {
		vi.unstubAllGlobals();
		vi.useRealTimers();
		vi.restoreAllMocks();
	});

	it('still reaches Certspotter after the index answered and crt.sh burned its whole timeout', async () => {
		vi.spyOn(console, 'log').mockImplementation(() => {});
		const consulted: string[] = [];
		vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = String(input instanceof Request ? input.url : input);
			if (url.includes('crt.sh')) {
				consulted.push('crtsh');
				return await new Promise<Response>((_resolve, reject) => {
					init?.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true });
				});
			}
			if (url.includes('certspotter.com')) {
				consulted.push('certspotter');
				return Response.json([{ id: '1', dns_names: ['api.example.com'], not_before: '', not_after: '' }], { status: 200 });
			}
			return Response.json({}, { status: 404 });
		});

		let result: Awaited<ReturnType<typeof discoverSubdomains>>;
		vi.useFakeTimers();
		try {
			const pending = discoverSubdomains('example.com', { fetch: youngIndex(['idx.example.com']) }, undefined, {
				deadlineMs: Date.now() + DISCOVER_SUBDOMAINS_SYNC_BUDGET_MS,
			});
			await vi.advanceTimersByTimeAsync(CT_SOURCE_TIMEOUT_MS + CT_FAILOVER_HEADROOM_MS);
			result = await pending;
		} finally {
			vi.useRealTimers();
		}

		expect(consulted).toEqual(['crtsh', 'certspotter']);
		expect(result.coverage?.perSource.map((s) => s.source)).toEqual(['certstream', 'crtsh', 'certspotter']);
		expect(result.subdomains.map((s) => s.subdomain).sort()).toEqual(['api.example.com', 'idx.example.com']);
	});

	// SQ-357: the zero-latency test above cannot exercise the 2 s headroom (8 + 14 + 2 = 24). A SLOW index
	// eats into it: after a 6 s answer only 18 s remain, crt.sh (8 s) still fits, Certspotter (14 s) no longer
	// does. The honest outcome is to NOT start a fetch it cannot finish, report Certspotter as never
	// consulted (not failed), serve the index names as a floor, and return inside the handler budget.
	it('respects the 24 s budget when the index itself takes 6 s: crt.sh runs, Certspotter is skipped, nothing overruns', async () => {
		vi.spyOn(console, 'log').mockImplementation(() => {});
		const consulted: string[] = [];
		vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = String(input instanceof Request ? input.url : input);
			if (url.includes('crt.sh')) {
				consulted.push('crtsh');
				return await new Promise<Response>((_resolve, reject) => {
					init?.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true });
				});
			}
			if (url.includes('certspotter.com')) {
				consulted.push('certspotter');
				return Response.json([{ id: '1', dns_names: ['late.example.com'], not_before: '', not_after: '' }], { status: 200 });
			}
			return Response.json({}, { status: 404 });
		});
		const index = youngIndex(['idx.example.com']) as unknown as (...a: Parameters<typeof fetch>) => Promise<Response>;
		const slowBinding = (async (...args: Parameters<typeof fetch>) => {
			await new Promise((r) => setTimeout(r, 6_000));
			return index(...args);
		}) as unknown as typeof fetch;

		let result: Awaited<ReturnType<typeof discoverSubdomains>>;
		let elapsedMs = 0;
		vi.useFakeTimers();
		try {
			const startedAt = Date.now();
			const pending = discoverSubdomains('example.com', { fetch: slowBinding }, undefined, {
				deadlineMs: startedAt + DISCOVER_SUBDOMAINS_SYNC_BUDGET_MS,
			});
			await vi.advanceTimersByTimeAsync(DISCOVER_SUBDOMAINS_SYNC_BUDGET_MS);
			result = await pending;
			elapsedMs = Date.now() - startedAt;
		} finally {
			vi.useRealTimers();
		}

		expect(consulted).toContain('crtsh');
		expect(consulted).not.toContain('certspotter');
		expect(elapsedMs).toBeLessThanOrEqual(DISCOVER_SUBDOMAINS_SYNC_BUDGET_MS);
		expect(result.subdomains.map((s) => s.subdomain)).toEqual(['idx.example.com']);
		expect(result.sourceUnavailable).toBeFalsy();
		expect(result.countBasis).toBe('floor');
		expect(result.coverage?.notConsulted).toContain('certspotter');
		expect(result.coverage?.perSource.find((s) => s.source === 'certstream')).toMatchObject({ outcome: 'ok', contributed: true });
	});

	it('serves the index names without asking crt.sh when the budget is already spent', async () => {
		vi.spyOn(console, 'log').mockImplementation(() => {});
		const fetchSpy = vi.fn(async () => Response.json({}, { status: 404 }));
		vi.stubGlobal('fetch', fetchSpy);
		const slowIndex = youngIndex(['idx.example.com']);
		const binding = vi.fn(async (...args: Parameters<typeof fetch>) => {
			await new Promise((r) => setTimeout(r, 120));
			return (slowIndex as unknown as (...a: Parameters<typeof fetch>) => Promise<Response>)(...args);
		}) as unknown as typeof fetch;

		const result = await discoverSubdomains('example.com', { fetch: binding }, undefined, { deadlineMs: Date.now() + 60 });

		expect(fetchSpy).not.toHaveBeenCalled();
		expect(result.subdomains.map((s) => s.subdomain)).toEqual(['idx.example.com']);
		// Not asked is not failed: the direct sources read as notConsulted, and the count is a floor.
		expect(result.coverage?.notConsulted).toEqual(expect.arrayContaining(['crtsh', 'certspotter']));
		expect(result.countBasis).toBe('floor');
		expect(result.sourceUnavailable).toBeFalsy();
	});
});

// SQ-2 — a 403 refusal is still a FAILOVER, not an abort.
//
// Classifying the refusal distinctly (`provider_restricted`) changes what the
// caller is TOLD, and must change nothing about control flow: the ladder has to
// keep walking to the next source exactly as it does for a 5xx, or a single
// provider's policy would take the whole tool down for that domain.
describe('CT failover past a declared provider restriction (SQ-2)', () => {
	afterEach(() => {
		vi.unstubAllGlobals();
		vi.restoreAllMocks();
	});

	it('still consults Certspotter when crt.sh refuses the query outright', async () => {
		vi.spyOn(console, 'log').mockImplementation(() => {});
		const consulted: string[] = [];
		vi.stubGlobal('fetch', async (input: RequestInfo | URL) => {
			const url = String(input instanceof Request ? input.url : input);
			if (url.includes('crt.sh')) {
				consulted.push('crtsh');
				return Response.json({ code: 'not_allowed_by_plan', message: '<upstream prose not reproduced>' }, { status: 403 });
			}
			if (url.includes('certspotter.com')) {
				consulted.push('certspotter');
				return Response.json([{ id: '1', dns_names: ['api.example.com'], not_before: '', not_after: '' }], { status: 200 });
			}
			return Response.json({ Status: 0, Answer: [] }, { status: 200 });
		});

		const result = await discoverSubdomains('example.com');

		expect(consulted).toEqual(['crtsh', 'certspotter']);
		expect(result.totalSubdomains).toBe(1);
		expect(result.coverage?.perSource.find((s) => s.source === 'crtsh')?.outcome).toBe('provider_restricted');
		// A refused source is a cut in recall, so the count is a floor (#866).
		expect(result.countBasis).toBe('floor');
	});
});
