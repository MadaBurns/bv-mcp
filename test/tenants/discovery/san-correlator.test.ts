// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for the SAN-cert correlator (Phase-4 brand-discovery, tier-1 signal).
 *
 * The correlator queries crt.sh for a seed domain, extracts every Subject
 * Alternative Name from the returned certificates, and filters to sibling
 * co-owned domains (not the seed itself, not subdomains, not invalid hosts).
 *
 * Tests inject a `fetchFn` rather than spying on `safeFetch` — the implementation
 * exposes the dependency for exactly this reason.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';
import { correlateSans } from '../../../src/tenants/discovery/san-correlator';

interface CrtShFixtureEntry {
	id?: number;
	name_value: string;
	entry_timestamp?: string;
}

function jsonResponse(body: unknown, init?: ResponseInit): Response {
	const text = JSON.stringify(body);
	const encoder = new TextEncoder();
	const uint8 = encoder.encode(text);
	return new Response(uint8, {
		status: 200,
		headers: { 'content-type': 'application/json', 'content-length': String(uint8.length) },
		...init,
	});
}

function mockFetchOk(entries: CrtShFixtureEntry[]): typeof fetch {
	return vi.fn().mockResolvedValue(jsonResponse(entries)) as unknown as typeof fetch;
}

describe('correlateSans', () => {
	it('returns sibling SANs from a single cert (happy path)', async () => {
		const fetchFn = mockFetchOk([
			{ id: 1, name_value: 'foo.com\nbar.com\nbaz.com' },
		]);
		const result = await correlateSans('foo.com', { fetchFn });
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual(['bar.com', 'baz.com']);
		expect(result.seedDomain).toBe('foo.com');
	});

	it('drops wildcards and subdomains of the seed', async () => {
		const fetchFn = mockFetchOk([
			{ id: 1, name_value: '*.example.com\nexample.com\nshop.example.com' },
		]);
		const result = await correlateSans('example.com', { fetchFn });
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual([]);
	});

	it('deduplicates SANs across multiple certs and sorts the result', async () => {
		const fetchFn = mockFetchOk([
			{ id: 1, name_value: 'foo.com\nbar.com\ncharlie.com' },
			{ id: 2, name_value: 'foo.com\nbar.com\nalpha.com' },
		]);
		const result = await correlateSans('foo.com', { fetchFn });
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual(['alpha.com', 'bar.com', 'charlie.com']);
	});

	it('caps the cert count via maxCertsPerDomain', async () => {
		const entries: CrtShFixtureEntry[] = [];
		for (let i = 0; i < 100; i++) {
			entries.push({
				id: i,
				name_value: `foo.com\nsibling${String(i).padStart(3, '0')}.com`,
			});
		}
		const fetchFn = mockFetchOk(entries);
		const result = await correlateSans('foo.com', { fetchFn, maxCertsPerDomain: 10 });
		expect(result.queryStatus).toBe('ok');
		// Streaming processes first 10 entries from the "server" response.
		expect(result.coOwnedDomains.length).toBe(10);
		const expected = Array.from({ length: 10 }, (_, k) => `sibling${String(k).padStart(3, '0')}.com`).sort();
		expect(result.coOwnedDomains).toEqual(expected);
	});

	it('aborts early on signal saturation', async () => {
		const entries: CrtShFixtureEntry[] = [];
		// 1. Initial discovery
		entries.push({ id: 1, name_value: 'foo.com\nsibling.com' });
		// 2. 101 redundant entries (saturation threshold is 100)
		for (let i = 0; i < 101; i++) {
			entries.push({ id: i + 2, name_value: 'foo.com\nsibling.com' });
		}
		// 3. This one should NOT be reached
		entries.push({ id: 999, name_value: 'foo.com\nnever-found.com' });

		const fetchFn = mockFetchOk(entries);
		const result = await correlateSans('foo.com', { fetchFn, maxCertsPerDomain: 500 });
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual(['sibling.com']);
		expect(result.coOwnedDomains).not.toContain('never-found.com');
	});

	it('throws on invalid seed input with the expected error prefix', async () => {
		await expect(correlateSans('not a domain')).rejects.toThrow(/^Domain validation failed:/);
	});

	it('returns rate_limited status on 429 without throwing', async () => {
		// Fresh response per call: crt.sh 429s, then the Certspotter failover (#1189) 429s too.
		const cancels: Array<ReturnType<typeof vi.spyOn>> = [];
		const fetchFn = vi.fn(async () => {
			const response = new Response('rate', { status: 429 });
			cancels.push(vi.spyOn(response.body!, 'cancel'));
			return response;
		}) as unknown as typeof fetch;
		const result = await correlateSans('foo.com', { fetchFn, maxRetries: 0 });
		expect(result.queryStatus).toBe('rate_limited');
		expect(result.coOwnedDomains).toEqual([]);
		expect(cancels).toHaveLength(2);
		// The unread crt.sh body is cancelled, not leaked.
		expect(cancels[0]).toHaveBeenCalledOnce();
	});

	it('keeps the direct crt.sh timeout active while the body stalls after headers', async () => {
		let requestSignal: AbortSignal | null | undefined;
		const fetchFn = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
			requestSignal = init?.signal;
			let bodyController: ReadableStreamDefaultController<Uint8Array>;
			const body = new ReadableStream<Uint8Array>({ start: (controller) => (bodyController = controller) });
			init?.signal?.addEventListener('abort', () => bodyController.error(init.signal?.reason), { once: true });
			return new Response(body, { status: 200 });
		}) as unknown as typeof fetch;

		const result = await correlateSans('foo.com', { fetchFn, maxRetries: 0, timeoutMs: 5 });

		expect(result.queryStatus).toBe('timeout');
		expect(requestSignal?.aborted).toBe(true);
	});

	it('returns timeout status when fetch throws an AbortError', async () => {
		const abortErr = new Error('aborted');
		abortErr.name = 'AbortError';
		const fetchFn = vi.fn().mockRejectedValue(abortErr) as unknown as typeof fetch;
		const result = await correlateSans('foo.com', { fetchFn, maxRetries: 0 });
		expect(result.queryStatus).toBe('timeout');
		expect(result.coOwnedDomains).toEqual([]);
	});

	it('returns error status on a generic network failure without throwing', async () => {
		const fetchFn = vi.fn().mockRejectedValue(new TypeError('network down')) as unknown as typeof fetch;
		const result = await correlateSans('foo.com', { fetchFn, maxRetries: 0 });
		expect(result.queryStatus).toBe('error');
		expect(result.coOwnedDomains).toEqual([]);
	});

	it('silently drops invalid SAN entries while keeping valid ones', async () => {
		const fetchFn = mockFetchOk([
			{ id: 1, name_value: 'valid.com\nnot a domain\nfoo.com' },
		]);
		const result = await correlateSans('foo.com', { fetchFn });
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual(['valid.com']);
	});

	it('drops the seed itself even when present in SAN list', async () => {
		const fetchFn = mockFetchOk([
			{ id: 1, name_value: 'foo.com\nFoo.com\nbar.com' },
		]);
		const result = await correlateSans('foo.com', { fetchFn });
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual(['bar.com']);
	});

	it('retries on transient error and surfaces eventual success', async () => {
		const okResponse = jsonResponse([{ id: 1, name_value: 'foo.com\nbar.com' }]);
		const fetchFn = vi
			.fn<typeof fetch>()
			.mockRejectedValueOnce(new TypeError('network down'))
			.mockResolvedValueOnce(new Response('boom', { status: 503 }))
			.mockResolvedValueOnce(okResponse);
		const sleepFn = vi.fn<(ms: number) => Promise<void>>().mockResolvedValue(undefined);
		const result = await correlateSans('foo.com', { fetchFn, sleepFn, maxRetries: 2, initialBackoffMs: 1 });
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual(['bar.com']);
		expect(fetchFn).toHaveBeenCalledTimes(3);
		expect(sleepFn).toHaveBeenCalledTimes(2);
	});

	it('retries on rate_limited (429) before giving up', async () => {
		const fetchFn = vi
			.fn<typeof fetch>()
			.mockResolvedValue(new Response('rate', { status: 429 }));
		const sleepFn = vi.fn<(ms: number) => Promise<void>>().mockResolvedValue(undefined);
		const result = await correlateSans('foo.com', { fetchFn, sleepFn, maxRetries: 2, initialBackoffMs: 1 });
		expect(result.queryStatus).toBe('rate_limited');
		// 3 crt.sh attempts + 1 Certspotter failover (#1189), which also 429s.
		expect(fetchFn).toHaveBeenCalledTimes(4);
		expect(sleepFn).toHaveBeenCalledTimes(2);
	});

	it('returns last attempt status after exhausting retries', async () => {
		const fetchFn = vi
			.fn<typeof fetch>()
			.mockRejectedValueOnce(new TypeError('first'))
			.mockResolvedValueOnce(new Response('rate', { status: 429 }))
			.mockRejectedValueOnce(new TypeError('third'));
		const sleepFn = vi.fn<(ms: number) => Promise<void>>().mockResolvedValue(undefined);
		const result = await correlateSans('foo.com', { fetchFn, sleepFn, maxRetries: 2, initialBackoffMs: 1 });
		// Last attempt rejected → 'error' status
		expect(result.queryStatus).toBe('error');
		// 3 crt.sh attempts + 1 Certspotter failover (#1189; the unscripted 4th call yields no Response).
		expect(fetchFn).toHaveBeenCalledTimes(4);
	});

	it('uses bv-certstream service binding when provided and returns siblings', async () => {
		const csFetch = vi.fn<typeof fetch>().mockResolvedValue(
			Response.json({
				domain: 'foo.com',
				names: ['bar.com', 'baz.com', '*.foo.com', 'foo.com', 'shop.foo.com', 'not a domain', 'alpha.com'],
				certificateCount: 5,
				timedOut: false,
				cached: true,
			}),
		);
		const directFetch = vi.fn() as unknown as typeof fetch;
		const result = await correlateSans('foo.com', {
			certstream: { fetch: csFetch },
			fetchFn: directFetch,
			maxRetries: 0,
		});
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual(['alpha.com', 'bar.com', 'baz.com']);
		expect(csFetch).toHaveBeenCalledTimes(1);
		const callUrl = (csFetch.mock.calls[0][0] as string);
		expect(callUrl).toContain('/sans?domain=foo.com');
		// Direct crt.sh fallback must not have been invoked.
		expect(directFetch).not.toHaveBeenCalled();
	});

	it('sends the certstream Bearer token on the /sans request when provided', async () => {
		const csFetch = vi.fn<typeof fetch>().mockResolvedValue(
			Response.json({ domain: 'foo.com', names: ['bar.com'], certificateCount: 1, timedOut: false, cached: true }),
		);
		const directFetch = vi.fn() as unknown as typeof fetch;
		const result = await correlateSans('foo.com', {
			certstream: { fetch: csFetch },
			certstreamAuthToken: 'secret-token',
			fetchFn: directFetch,
			maxRetries: 0,
		});
		expect(result.queryStatus).toBe('ok');
		const init = csFetch.mock.calls[0][1] as RequestInit | undefined;
		const headers = new Headers(init?.headers);
		expect(headers.get('authorization')).toBe('Bearer secret-token');
		expect(directFetch).not.toHaveBeenCalled();
	});

	it('falls back to direct crt.sh when certstream binding fails', async () => {
		const csFetch = vi.fn<typeof fetch>().mockResolvedValue(new Response('boom', { status: 503 }));
		const directFetch = mockFetchOk([{ id: 7, name_value: 'foo.com\nfallback-sibling.com' }]);
		const sleepFn = vi.fn<(ms: number) => Promise<void>>().mockResolvedValue(undefined);
		const result = await correlateSans('foo.com', {
			certstream: { fetch: csFetch },
			fetchFn: directFetch,
			sleepFn,
			maxRetries: 0,
		});
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual(['fallback-sibling.com']);
		expect(csFetch).toHaveBeenCalledTimes(1);
		expect(directFetch).toHaveBeenCalledTimes(1);
	});

	it('keeps the certstream timeout active while the /sans body stalls after headers', async () => {
		let requestSignal: AbortSignal | null | undefined;
		const csFetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
			requestSignal = init?.signal;
			let bodyController: ReadableStreamDefaultController<Uint8Array>;
			const body = new ReadableStream<Uint8Array>({ start: (controller) => (bodyController = controller) });
			init?.signal?.addEventListener('abort', () => bodyController.error(init.signal?.reason), { once: true });
			return new Response(body, { status: 200 });
		}) as unknown as typeof fetch;
		const directFetch = mockFetchOk([{ id: 7, name_value: 'foo.com\nfallback-sibling.com' }]);

		const result = await correlateSans('foo.com', {
			certstream: { fetch: csFetch },
			fetchFn: directFetch,
			maxRetries: 0,
			// Whole-call budget: certstream may take 30% of it, then crt.sh still has its own slice.
			timeoutMs: 200,
		});

		expect(result.coOwnedDomains).toEqual(['fallback-sibling.com']);
		expect(requestSignal?.aborted).toBe(true);
	});

	it('cancels unread certstream /sans body before falling back to direct crt.sh', async () => {
		const certstreamResponse = new Response('boom', { status: 503 });
		const certstreamCancel = vi.spyOn(certstreamResponse.body!, 'cancel');
		const csFetch = vi.fn<typeof fetch>().mockResolvedValue(certstreamResponse);
		const directFetch = mockFetchOk([{ id: 7, name_value: 'foo.com\nfallback-sibling.com' }]);
		const sleepFn = vi.fn<(ms: number) => Promise<void>>().mockResolvedValue(undefined);

		const result = await correlateSans('foo.com', {
			certstream: { fetch: csFetch },
			fetchFn: directFetch,
			sleepFn,
			maxRetries: 0,
		});

		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual(['fallback-sibling.com']);
		expect(certstreamCancel).toHaveBeenCalledTimes(1);
	});

	it('falls back when certstream response sets error or timedOut', async () => {
		const csFetch = vi.fn<typeof fetch>().mockResolvedValue(
			Response.json({ domain: 'foo.com', names: [], certificateCount: 0, timedOut: true, cached: false }),
		);
		const directFetch = mockFetchOk([{ id: 1, name_value: 'foo.com\nrecovered.com' }]);
		const result = await correlateSans('foo.com', {
			certstream: { fetch: csFetch },
			fetchFn: directFetch,
			maxRetries: 0,
		});
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual(['recovered.com']);
		expect(directFetch).toHaveBeenCalledTimes(1);
	});

	it('returns partial certstream SAN names when the service times out after collecting data', async () => {
		const csFetch = vi.fn<typeof fetch>().mockResolvedValue(
			Response.json({
				domain: 'foo.com',
				names: ['partial-one.com', 'partial-two.com', 'shop.foo.com'],
				certificateCount: 50,
				timedOut: true,
				cached: false,
			}),
		);
		const directFetch = vi.fn() as unknown as typeof fetch;
		const result = await correlateSans('foo.com', {
			certstream: { fetch: csFetch },
			fetchFn: directFetch,
			maxRetries: 0,
		});

		expect(result.queryStatus).toBe('partial');
		expect(result.coOwnedDomains).toEqual(['partial-one.com', 'partial-two.com']);
		expect(directFetch).not.toHaveBeenCalled();
	});
});

// ---------------------------------------------------------------------------
// Certspotter failover + CT coverage record (#1189)
// ---------------------------------------------------------------------------

const CRTSH_PREFIX = 'https://crt.sh/';
const CERTSPOTTER_PREFIX = 'https://api.certspotter.com/';

interface RoutedFetch {
	fetchFn: typeof fetch;
	urls: string[];
	inits: Array<RequestInit | undefined>;
	crtshCalls: () => number;
	certspotterCalls: () => number;
}

/** One fetch mock serving both CT backends, so call counts are attributable per backend. */
function routedFetch(handlers: {
	crtsh: (init?: RequestInit) => Response | Promise<Response>;
	certspotter?: (init?: RequestInit) => Response | Promise<Response>;
}): RoutedFetch {
	const urls: string[] = [];
	const inits: Array<RequestInit | undefined> = [];
	const fetchFn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		urls.push(url);
		inits.push(init);
		if (url.startsWith(CRTSH_PREFIX)) return handlers.crtsh(init);
		if (url.startsWith(CERTSPOTTER_PREFIX)) {
			if (!handlers.certspotter) throw new Error('unexpected Certspotter fetch: ' + url);
			return handlers.certspotter(init);
		}
		throw new Error('unexpected url ' + url);
	}) as unknown as typeof fetch;
	return {
		fetchFn,
		urls,
		inits,
		crtshCalls: () => urls.filter((u) => u.startsWith(CRTSH_PREFIX)).length,
		certspotterCalls: () => urls.filter((u) => u.startsWith(CERTSPOTTER_PREFIX)).length,
	};
}

function certspotterIssuances(dnsNames: string[][]): Response {
	return jsonResponse(dnsNames.map((names, i) => ({ id: String(i + 1), dns_names: names, issuer: { name: 'CN=Test CA' } })));
}

const noSleep = vi.fn<(ms: number) => Promise<void>>().mockResolvedValue(undefined);

describe('correlateSans — Certspotter failover and CT coverage (#1189)', () => {
	afterEach(() => {
		vi.useRealTimers();
	});

	it('(a) crt.sh 429 on every attempt, Certspotter answers: sibling surfaces, status ok, coverage names both', async () => {
		const routed = routedFetch({
			crtsh: () => new Response('rate', { status: 429 }),
			certspotter: () => certspotterIssuances([['foo.com', 'www.foo.com', 'sibling.com']]),
		});
		const result = await correlateSans('foo.com', {
			fetchFn: routed.fetchFn,
			sleepFn: noSleep,
			certspotterToken: 'cs-token',
		});

		expect(result.coOwnedDomains).toEqual(['sibling.com']);
		expect(result.queryStatus).toBe('ok');
		expect(result.coverage.contributing).toEqual(['certspotter']);
		const crtsh = result.coverage.perSource.find((s) => s.source === 'crtsh');
		expect(crtsh).toMatchObject({ outcome: 'rate_limited', contributed: false });
		expect(result.coverage.degraded).toBe(true);
		// Default retries: 3 crt.sh attempts, then exactly one Certspotter attempt.
		expect(routed.crtshCalls()).toBe(3);
		expect(routed.certspotterCalls()).toBe(1);
		// Request shape is the shared one from discover_subdomains: dns_names expansion + bearer token.
		const csUrl = routed.urls.find((u) => u.startsWith(CERTSPOTTER_PREFIX)) as string;
		expect(csUrl).toContain('domain=foo.com');
		expect(csUrl).toContain('include_subdomains=true');
		expect(csUrl).toContain('expand=dns_names');
		const csInit = routed.inits[routed.urls.indexOf(csUrl)];
		expect((csInit?.headers as Record<string, string>).Authorization).toBe('Bearer cs-token');
	});

	it('(b) crt.sh reveals a sibling via common_name: Certspotter is NOT fetched and stays notConsulted', async () => {
		const routed = routedFetch({
			crtsh: () => jsonResponse([{ id: 1, name_value: 'foo.com', common_name: 'brand-alt.com' }]),
		});
		const result = await correlateSans('foo.com', { fetchFn: routed.fetchFn, sleepFn: noSleep });

		expect(result.coOwnedDomains).toEqual(['brand-alt.com']);
		expect(result.queryStatus).toBe('ok');
		expect(routed.certspotterCalls()).toBe(0);
		expect(result.coverage.contributing).toEqual(['crtsh']);
		expect(result.coverage.notConsulted).toContain('certspotter');
	});

	it('crt.sh 200 naming only the seed cannot answer the co-listing question: Certspotter IS fetched and contributes', async () => {
		// crt.sh lists in name_value only the names that matched the query (SQ-302).
		const routed = routedFetch({
			crtsh: () => jsonResponse([{ id: 1, name_value: 'foo.com\nwww.foo.com', common_name: 'foo.com' }]),
			certspotter: () => certspotterIssuances([['foo.com', 'foo-sibling.net']]),
		});
		const result = await correlateSans('foo.com', { fetchFn: routed.fetchFn, sleepFn: noSleep });

		expect(routed.crtshCalls()).toBe(1);
		expect(routed.certspotterCalls()).toBe(1);
		expect(result.coOwnedDomains).toEqual(['foo-sibling.net']);
		expect(result.queryStatus).toBe('ok');
		expect(result.coverage.contributing).toEqual(['certspotter']);
		expect(result.coverage.perSource.find((s) => s.source === 'crtsh')).toMatchObject({ outcome: 'empty', contributed: false });
	});

	it('crt.sh empty and Certspotter throttled: status stays ok (crt.sh answered) and coverage records the throttle', async () => {
		const routed = routedFetch({
			crtsh: () => jsonResponse([{ id: 1, name_value: 'foo.com' }]),
			certspotter: () => new Response('slow down', { status: 429 }),
		});
		const result = await correlateSans('foo.com', { fetchFn: routed.fetchFn, sleepFn: noSleep });

		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual([]);
		expect(result.coverage.perSource.find((s) => s.source === 'certspotter')).toMatchObject({
			outcome: 'rate_limited',
			contributed: false,
		});
		expect(result.coverage.degraded).toBe(true);
	});

	it('every consulted backend failing keeps the primary failure status and records both', async () => {
		const routed = routedFetch({
			crtsh: () => new Response('rate', { status: 429 }),
			certspotter: () => new Response('boom', { status: 500 }),
		});
		const result = await correlateSans('foo.com', { fetchFn: routed.fetchFn, sleepFn: noSleep, maxRetries: 0 });

		expect(result.queryStatus).toBe('rate_limited');
		expect(result.coOwnedDomains).toEqual([]);
		expect(result.coverage.unavailable).toEqual(['crtsh', 'certspotter']);
		expect(result.coverage.contributing).toEqual([]);
	});

	it('Certspotter pagination cut short is reported as partial', async () => {
		let page = 0;
		const routed = routedFetch({
			crtsh: () => new Response('boom', { status: 500 }),
			certspotter: () => {
				page++;
				// Always advertises a next page with a cursor → hits the page cap → truncated.
				return new Response(JSON.stringify([{ id: String(page), dns_names: ['foo.com', `sib${page}.com`] }]), {
					status: 200,
					headers: { 'content-type': 'application/json', link: '<https://api.certspotter.com/next>; rel="next"' },
				});
			},
		});
		const result = await correlateSans('foo.com', { fetchFn: routed.fetchFn, sleepFn: noSleep, maxRetries: 0 });

		expect(result.queryStatus).toBe('partial');
		expect(result.coOwnedDomains.length).toBeGreaterThan(1);
		expect(result.coverage.perSource.find((s) => s.source === 'certspotter')).toMatchObject({
			contributed: true,
			indexExhausted: false,
		});
	});

	it('(c) a public-suffix apex records Certspotter provider_restricted up front and never fetches it', async () => {
		for (const crtsh of [() => new Response('rate', { status: 429 }), () => jsonResponse([{ id: 1, name_value: 'co.nz' }])]) {
			const routed = routedFetch({ crtsh });
			const result = await correlateSans('co.nz', { fetchFn: routed.fetchFn, sleepFn: noSleep, maxRetries: 0 });

			expect(routed.certspotterCalls()).toBe(0);
			expect(result.coverage.perSource.find((s) => s.source === 'certspotter')).toMatchObject({
				outcome: 'provider_restricted',
				contributed: false,
			});
			expect(result.coverage.notConsulted).not.toContain('certspotter');
		}
	});

	it('does not consult Certspotter once the caller has cancelled, or when told to skip it', async () => {
		const controller = new AbortController();
		controller.abort();
		const aborted = routedFetch({ crtsh: () => new Response('rate', { status: 429 }) });
		await correlateSans('foo.com', { fetchFn: aborted.fetchFn, sleepFn: noSleep, signal: controller.signal });
		expect(aborted.certspotterCalls()).toBe(0);

		const skipped = routedFetch({ crtsh: () => new Response('rate', { status: 429 }) });
		const result = await correlateSans('foo.com', { fetchFn: skipped.fetchFn, sleepFn: noSleep, maxRetries: 0, skipCertspotter: true });
		expect(skipped.certspotterCalls()).toBe(0);
		expect(result.coverage.notConsulted).toContain('certspotter');
	});

	it('(d) timeoutMs bounds the crt.sh ladder so a Certspotter attempt starts well before the deadline', async () => {
		vi.useFakeTimers();
		const t0 = Date.now();
		const startedAt: { crtsh: number[]; certspotter: number[] } = { crtsh: [], certspotter: [] };
		const hangUntilAborted = (init?: RequestInit) =>
			new Promise<Response>((_resolve, reject) => {
				init?.signal?.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })), { once: true });
			});
		const routed = routedFetch({
			crtsh: (init) => {
				startedAt.crtsh.push(Date.now() - t0);
				return hangUntilAborted(init);
			},
			certspotter: () => {
				startedAt.certspotter.push(Date.now() - t0);
				return certspotterIssuances([['foo.com', 'late-sibling.com']]);
			},
		});

		const pending = correlateSans('foo.com', { fetchFn: routed.fetchFn, sleepFn: noSleep, timeoutMs: 1000 });
		await vi.advanceTimersByTimeAsync(1000);
		const result = await pending;

		// crt.sh (all retries together) was confined to 60% of the 1000ms budget...
		expect(startedAt.crtsh.length).toBeGreaterThanOrEqual(1);
		// ...so Certspotter started inside the budget, with time left to answer.
		expect(startedAt.certspotter).toHaveLength(1);
		expect(startedAt.certspotter[0]).toBeGreaterThanOrEqual(600);
		expect(startedAt.certspotter[0]).toBeLessThan(1000);
		expect(result.coOwnedDomains).toEqual(['late-sibling.com']);
		expect(result.coverage.perSource.find((s) => s.source === 'crtsh')).toMatchObject({ outcome: 'timeout' });
	});
});
