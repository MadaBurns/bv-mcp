// SPDX-License-Identifier: BUSL-1.1
//
// PR #894 residual 2: `probeHasWebContent` mapped a genuine timeout to
// `hasWebContent: false` — the "no reachable web content" HIGH corroborator in
// the #264 severity matrix — contradicting the module doc ("a probe that never
// ran cannot synthesise a HIGH"). A host that did not answer within the budget
// is UNKNOWN, not "no content": unknown must fail toward `true`.
//
// A measured refusal (connection reset, TLS failure, NXDOMAIN at the socket)
// stays `false` — that IS the "parked / unreachable" signal the corroborator
// exists for.

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => {
	restore();
	vi.restoreAllMocks();
});

function hangHonouringSignal(signal: AbortSignal | null | undefined): Promise<Response> {
	return new Promise<Response>((_, reject) => {
		const abort = () =>
			reject(signal?.reason instanceof Error ? signal.reason : new DOMException('The operation was aborted', 'AbortError'));
		if (signal?.aborted) return abort();
		signal?.addEventListener('abort', abort, { once: true });
	});
}

async function load() {
	return import('../src/tools/lookalike-enrichment');
}

describe('probeHasWebContent — failure direction (#894 residual 2)', () => {
	it('a HEAD probe that times out reports true (unknown), never the no-content HIGH corroborator', async () => {
		globalThis.fetch = vi.fn().mockImplementation((_input: unknown, init?: RequestInit) => hangHonouringSignal(init?.signal));
		const { probeHasWebContent } = await load();
		// Deadline-clamped so the per-probe timer fires quickly.
		const reachable = await probeHasWebContent('slow-parked.com', Date.now() + 150);
		expect(reachable).toBe(true);
	});

	it('a measured transport refusal still reports false', async () => {
		globalThis.fetch = vi.fn().mockImplementation(() => Promise.reject(new TypeError('connection refused')));
		const { probeHasWebContent } = await load();
		expect(await probeHasWebContent('dark.com')).toBe(false);
	});

	it('any HTTP response — 200, 3xx, 5xx — is reachable', async () => {
		const { probeHasWebContent } = await load();
		for (const status of [200, 302, 503]) {
			globalThis.fetch = vi.fn().mockImplementation(() => Promise.resolve(new Response(null, { status })));
			expect(await probeHasWebContent('live.com'), `status ${status}`).toBe(true);
		}
	});

	it('a probe whose turn comes after the deadline is not issued and reports true', async () => {
		const fetchSpy = vi.fn().mockImplementation(() => Promise.resolve(new Response(null, { status: 200 })));
		globalThis.fetch = fetchSpy;
		const { probeHasWebContent } = await load();
		expect(await probeHasWebContent('late.com', Date.now() - 1)).toBe(true);
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it('through enrichLookalikes: a hung HEAD probe cannot lift a candidate to the no-content corroborator', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request, init?: RequestInit) => {
			const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
			if (url.pathname.includes('/domain/')) return Promise.resolve(new Response(JSON.stringify({ events: [] }), { status: 200 }));
			return hangHonouringSignal(init?.signal);
		});
		const { enrichLookalikes } = await load();
		const enrichment = await enrichLookalikes(
			[{ domain: 'slow.com', hasA: true, hasMX: true, mxExchanges: ['mx.slow.com'], probeDegraded: false }],
			{
				deadlineMs: Date.now() + 200,
			},
		);
		expect(enrichment.get('slow.com')?.hasWebContent).toBe(true);
	});
});
