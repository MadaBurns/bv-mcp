// SPDX-License-Identifier: BUSL-1.1

/**
 * Chaos hypotheses for the brand-discovery SAN-signal certstream-auth fix (3.20.0).
 *
 * The bug: `attemptCertstreamSans` queried the bv-certstream-worker `/sans`
 * endpoint with NO `Authorization` header, so the worker's admin route 401'd,
 * the result was folded to `null`, and `correlateSans` silently fell through to
 * direct crt.sh — which is per-IP throttled and 5xx's for large brand
 * portfolios, surfacing `san: error` and starving the high-confidence
 * `san_recursive` cross-confirmation. The fix threads a bearer token through to
 * the `/sans` fetch.
 *
 * Given the certstream binding fails in ANY way, correlateSans must degrade to
 * direct crt.sh and return a valid result — never throw, never leak the token.
 * Given a HEALTHY certstream + token, the cached path must be used and crt.sh
 * must never be touched (this is the fix: pre-fix the missing header forced the
 * 401→crt.sh path for every brand). Given the SAN signal fails outright, the
 * discovery orchestrator must still complete.
 */

import { describe, it, expect, vi } from 'vitest';
import type { DiscoverBrandDomainsDeps } from '../../src/tools/discover-brand-domains';

const TOKEN = 'chaos-bearer-token-abc123';

/** A crt.sh JSON response (the direct-fallback path), content-length set so the streaming parser is happy. */
function crtShResponse(entries: Array<{ id: number; name_value: string }>): Response {
	const body = new TextEncoder().encode(JSON.stringify(entries));
	return new Response(body, { status: 200, headers: { 'content-type': 'application/json', 'content-length': String(body.length) } });
}

/** A healthy bv-certstream `/sans` response carrying sibling SANs. */
function certstreamOk(names: string[]): Response {
	return Response.json({ domain: 'seed', names, certificateCount: names.length, timedOut: false, cached: true });
}

/** Every way the certstream binding can betray us. Each must degrade to crt.sh, never throw. */
const CERTSTREAM_FAULTS: Array<{ label: string; make: () => Response | never }> = [
	{ label: '401 (the original bug — auth rejected)', make: () => new Response('unauthorized', { status: 401 }) },
	{ label: '403 forbidden', make: () => new Response('forbidden', { status: 403 }) },
	{ label: '429 rate limited', make: () => new Response('slow down', { status: 429 }) },
	{ label: '500 internal error', make: () => new Response('boom', { status: 500 }) },
	{ label: '503 unavailable', make: () => new Response('down', { status: 503 }) },
	{ label: 'malformed JSON body', make: () => new Response('{not json', { status: 200, headers: { 'content-type': 'application/json' } }) },
	{
		label: 'error field set in payload',
		make: () => Response.json({ domain: 'seed', error: 'upstream failure', names: [], certificateCount: 0, timedOut: false }),
	},
	{
		label: 'network throw',
		make: () => {
			throw new TypeError('connection reset');
		},
	},
];

describe('chaos: SAN certstream-auth degradation', () => {
	it.each(CERTSTREAM_FAULTS)('Given certstream $label, correlateSans falls back to direct crt.sh and never throws', async ({ make }) => {
		const { correlateSans } = await import('../../src/tenants/discovery/san-correlator');
		const certFetch = vi.fn<typeof fetch>().mockImplementation(() => {
			const r = make(); // throw-faults reject the fetch; status-faults resolve
			return Promise.resolve(r);
		});
		const directFetch = vi.fn<typeof fetch>().mockResolvedValue(crtShResponse([{ id: 1, name_value: 'seed.com\nfallback-sibling.com' }]));
		const sleepFn = vi.fn<(ms: number) => Promise<void>>().mockResolvedValue(undefined);

		const result = await correlateSans('seed.com', {
			certstream: { fetch: certFetch },
			certstreamAuthToken: TOKEN,
			fetchFn: directFetch,
			sleepFn,
			maxRetries: 0,
		});

		// Degraded gracefully to the fallback — never threw, produced a valid result.
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual(['fallback-sibling.com']);
		expect(directFetch).toHaveBeenCalledTimes(1); // fallback engaged
	});

	it('Given a healthy certstream + token, the cached /sans path is used and crt.sh is NEVER touched (the fix)', async () => {
		const { correlateSans } = await import('../../src/tenants/discovery/san-correlator');
		// A spread of seed shapes — the token+cached-path invariant must hold for every brand, not just one.
		const seeds = ['seed.com', 'paypal.com', 'a-very-long-brand-name.com', 'xn--mnchen-3ya.de', 'brand.co.uk'];
		for (const seed of seeds) {
			const certFetch = vi.fn<typeof fetch>().mockResolvedValue(certstreamOk(['sib-one.com', 'sib-two.com']));
			const directFetch = vi.fn<typeof fetch>(); // must never be invoked
			const result = await correlateSans(seed, {
				certstream: { fetch: certFetch },
				certstreamAuthToken: TOKEN,
				fetchFn: directFetch as unknown as typeof fetch,
				maxRetries: 0,
			});
			expect(result.queryStatus).toBe('ok');
			// The fix: bearer attached on the /sans call...
			const init = certFetch.mock.calls[0][1] as RequestInit | undefined;
			expect(new Headers(init?.headers).get('authorization')).toBe(`Bearer ${TOKEN}`);
			// ...so the cached path succeeds and the throttled crt.sh fallback is never reached.
			expect(directFetch).not.toHaveBeenCalled();
		}
	});

	it('Given NO token (BSL self-host), the /sans call carries no auth header and still degrades cleanly on 401', async () => {
		const { correlateSans } = await import('../../src/tenants/discovery/san-correlator');
		const certFetch = vi.fn<typeof fetch>().mockResolvedValue(new Response('unauthorized', { status: 401 }));
		const directFetch = vi.fn<typeof fetch>().mockResolvedValue(crtShResponse([{ id: 1, name_value: 'seed.com\nbsl-sibling.com' }]));
		const result = await correlateSans('seed.com', {
			certstream: { fetch: certFetch },
			fetchFn: directFetch,
			maxRetries: 0,
		});
		const init = certFetch.mock.calls[0][1] as RequestInit | undefined;
		expect(new Headers(init?.headers).get('authorization')).toBeNull(); // token optional — no header when absent
		expect(result.queryStatus).toBe('ok'); // fell back, no throw
		expect(result.coOwnedDomains).toEqual(['bsl-sibling.com']);
	});

	it('Given the SAN signal fails outright, discoverBrandDomains still completes (no throw, san marked failed)', async () => {
		const { discoverBrandDomains } = await import('../../src/tools/discover-brand-domains');
		const correlateSans = vi.fn().mockRejectedValue(new Error('certstream + crt.sh both dead'));
		const correlateSansRecursive = vi
			.fn()
			.mockResolvedValue({ seedDomain: 'seed.com', crossConfirmed: [], probed: [], queryStatus: 'ok' as const });
		const deps = { correlateSans, correlateSansRecursive } as unknown as DiscoverBrandDomainsDeps;

		const result = await discoverBrandDomains('seed.com', { signals: ['san', 'san_recursive'] }, deps);

		// Orchestrator degraded, didn't crash: a CheckResult came back...
		expect(result).toBeTruthy();
		expect(Array.isArray(result.findings)).toBe(true);
		// ...and the san signal is reflected as not-ok rather than sinking the whole discovery.
		const summary = result.findings.find((f) => f.metadata?.summary)?.metadata as
			| { signalStatus?: Record<string, { status: string }> }
			| undefined;
		expect(summary?.signalStatus?.san?.status).not.toBe('ok');
	});
});
