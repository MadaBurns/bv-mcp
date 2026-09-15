// SPDX-License-Identifier: BUSL-1.1
//
// #1004 — a public-suffix apex (an ICANN eTLD such as `govt.nz`, `co.nz`)
// reserved CERTSPOTTER_TIMEOUT_MS (14s) of the 24s sync budget for a provider
// that refuses that whole input class in ~0.65s with a categorical
// `not_allowed_by_plan` 403 (#1003 fixed the 403 LABEL; this is the second,
// budget-allocation cause). crt.sh was left only CT_SOURCE_TIMEOUT_MS (8s),
// and a warm crt.sh query for a large PSL apex measured ~8.3s — so it missed
// its own slot and the tool reported `sourceUnavailable` while crt.sh was in
// fact up and answering.
//
// Fix: for a public-suffix apex, `queryDirectSources` never calls Certspotter
// at all and gives crt.sh the whole synchronous budget
// (CT_SOURCE_TIMEOUT_MS_PSL_APEX = 24_000 - CT_FAILOVER_HEADROOM_MS = 22_000).
// Every other apex keeps the existing ladder and timeouts unchanged.

import { describe, expect, it, vi, afterEach } from 'vitest';
import {
	CT_FAILOVER_HEADROOM_MS,
	CT_SOURCE_TIMEOUT_MS,
	CT_SOURCE_TIMEOUT_MS_PSL_APEX,
	CERTSPOTTER_TIMEOUT_MS,
	DISCOVER_SUBDOMAINS_SYNC_BUDGET_MS,
	discoverSubdomains,
} from '../src/tools/discover-subdomains';

function crtShResponse(names: string[]): Response {
	const now = new Date().toISOString();
	return Response.json(
		names.map((name) => ({ name_value: name, issuer_name: 'CN=Test CA', not_before: now, not_after: '2999-01-01T00:00:00Z' })),
		{ status: 200 },
	);
}

describe('discoverSubdomains — public-suffix apex ladder (#1004)', () => {
	afterEach(() => {
		vi.unstubAllGlobals();
		vi.useRealTimers();
	});

	it('gives crt.sh the whole budget instead of the shared 8s slot', () => {
		expect(CT_SOURCE_TIMEOUT_MS_PSL_APEX).toBe(DISCOVER_SUBDOMAINS_SYNC_BUDGET_MS - CT_FAILOVER_HEADROOM_MS);
		// Sanity: the PSL-apex slot is materially larger than the shared-ladder
		// slot it replaces (8s today) — otherwise the fix does nothing.
		expect(CT_SOURCE_TIMEOUT_MS_PSL_APEX).toBeGreaterThan(CT_SOURCE_TIMEOUT_MS);
	});

	it('never fetches CertSpotter for a public-suffix apex, and answers from a crt.sh response too slow for the old 8s slot', async () => {
		const consulted: string[] = [];
		vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = String(input instanceof Request ? input.url : input);
			if (url.includes('crt.sh')) {
				consulted.push('crtsh');
				// Slower than the OLD CT_SOURCE_TIMEOUT_MS (8s) but well inside the
				// new PSL-apex budget (22s) — the exact measured govt.nz shape (~8.3s).
				return await new Promise<Response>((resolve, reject) => {
					const id = setTimeout(() => resolve(crtShResponse(['health.govt.nz', 'www.govt.nz'])), CT_SOURCE_TIMEOUT_MS + 2_000);
					init?.signal?.addEventListener(
						'abort',
						() => {
							clearTimeout(id);
							reject(new DOMException('Aborted', 'AbortError'));
						},
						{ once: true },
					);
				});
			}
			if (url.includes('certspotter.com')) {
				consulted.push('certspotter');
				return Response.json([], { status: 200 });
			}
			return Response.json({}, { status: 404 });
		});

		let result: Awaited<ReturnType<typeof discoverSubdomains>>;
		vi.useFakeTimers();
		try {
			const pending = discoverSubdomains('govt.nz', undefined, undefined, {
				deadlineMs: Date.now() + DISCOVER_SUBDOMAINS_SYNC_BUDGET_MS,
			});
			// Past the OLD 8s slot but short of the new 22s one — the exact window
			// that used to abort crt.sh and now must not.
			await vi.advanceTimersByTimeAsync(CT_SOURCE_TIMEOUT_MS + 2_000);
			result = await pending;
		} finally {
			vi.useRealTimers();
		}

		// CertSpotter is never asked for a PSL apex.
		expect(consulted).toEqual(['crtsh']);

		// crt.sh answered — this is not an outage.
		expect(result.sourceUnavailable).not.toBe(true);
		expect(result.totalSubdomains).toBeGreaterThan(0);

		// CertSpotter is reported with the reason it was skipped, not as a bare
		// "not consulted" or a generic failure.
		const certspotterAttempt = result.coverage?.perSource.find((s) => s.source === 'certspotter');
		expect(certspotterAttempt?.outcome).toBe('provider_restricted');
		expect(result.coverage?.notConsulted ?? []).not.toContain('certspotter');

		const crtshAttempt = result.coverage?.perSource.find((s) => s.source === 'crtsh');
		expect(crtshAttempt?.outcome).toBe('ok');
	});

	it('keeps the normal ladder unchanged for a non-PSL apex: crt.sh at CT_SOURCE_TIMEOUT_MS, Certspotter still consulted on failover', async () => {
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
			const pending = discoverSubdomains('example.com', undefined, undefined, {
				deadlineMs: Date.now() + DISCOVER_SUBDOMAINS_SYNC_BUDGET_MS,
			});
			await vi.advanceTimersByTimeAsync(CT_SOURCE_TIMEOUT_MS + CT_FAILOVER_HEADROOM_MS);
			result = await pending;
		} finally {
			vi.useRealTimers();
		}

		expect(consulted).toEqual(['crtsh', 'certspotter']);
		expect(result.totalSubdomains).toBe(1);
		// Untouched by the PSL-apex branch: still the shared 14s slot.
		expect(CERTSPOTTER_TIMEOUT_MS).toBe(14_000);
	});
});
