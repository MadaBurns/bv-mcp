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

// ---------------------------------------------------------------------------
// #1202 — the tri-state web reading carried beside `hasWebContent`.
// ---------------------------------------------------------------------------

type Candidate = Parameters<Awaited<ReturnType<typeof load>>['enrichLookalikes']>[0][number];

function candidate(overrides: Partial<Candidate> & { domain: string }): Candidate {
	return { hasA: true, hasMX: true, mxExchanges: [`mx.${overrides.domain}`], probeDegraded: false, ...overrides };
}

/** RDAP answers with no events; every HEAD probe gets `head`. Returns the HEAD-probe call count. */
function mockHead(head: 'ok' | 'refused' | 'hang'): { headCalls: () => number } {
	let headCalls = 0;
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request, init?: RequestInit) => {
		const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
		if (url.pathname.includes('/domain/')) return Promise.resolve(new Response(JSON.stringify({ events: [] }), { status: 200 }));
		headCalls++;
		if (head === 'refused') return Promise.reject(new TypeError('connection refused'));
		if (head === 'hang') return hangHonouringSignal(init?.signal);
		return Promise.resolve(new Response(null, { status: 200 }));
	});
	return { headCalls: () => headCalls };
}

describe('probeWebPresence — the HEAD probe reading (#1202)', () => {
	it('HTTP answer → content; measured refusal → none; timeout and not-issued → unmeasured (never content)', async () => {
		const { probeWebPresence } = await load();
		mockHead('ok');
		expect(await probeWebPresence('live.com')).toMatchObject({ hasWebContent: true, webPresence: 'content' });
		mockHead('refused');
		expect(await probeWebPresence('dark.com')).toMatchObject({ hasWebContent: false, webPresence: 'none' });
		mockHead('hang');
		expect(await probeWebPresence('slow.com', Date.now() + 150)).toMatchObject({ hasWebContent: true, webPresence: 'unmeasured' });
		const late = mockHead('ok');
		expect(await probeWebPresence('late.com', Date.now() - 1)).toMatchObject({ hasWebContent: true, webPresence: 'unmeasured' });
		expect(late.headCalls()).toBe(0);
	});
});

describe('collectParkingSignals — read from DNS already fetched, no query (#1202)', () => {
	it('each signal alone', async () => {
		const { collectParkingSignals } = await load();
		expect(collectParkingSignals({ mxExchanges: ['park-mx.above.com'] })).toEqual(['parking_mx']);
		expect(collectParkingSignals({ mxExchanges: ['mx.plain.com'] }, ['ns1.sedoparking.com', 'ns2.sedoparking.com'])).toEqual([
			'parking_ns',
		]);
		expect(collectParkingSignals({ mxExchanges: ['mx.plain.com'], wildcardProbe: 'wildcard' })).toEqual(['wildcard_a']);
	});

	it('combined, in a stable order', async () => {
		const { collectParkingSignals } = await load();
		expect(collectParkingSignals({ mxExchanges: ['park-mx.above.com'], wildcardProbe: 'wildcard' }, ['ns1.above.com'])).toEqual([
			'parking_mx',
			'parking_ns',
			'wildcard_a',
		]);
	});

	it('nothing for plain hosts, registrar defaults that serve live zones too, or a wildcard probe that measured nothing', async () => {
		const { collectParkingSignals } = await load();
		expect(collectParkingSignals({ mxExchanges: ['mx.plain.com'] }, ['ns1.plain-dns.com'])).toEqual([]);
		expect(collectParkingSignals({ mxExchanges: ['mx.plain.com'] }, ['ns1.dns-parking.com', 'ns01.domaincontrol.com'])).toEqual([]);
		expect(collectParkingSignals({ mxExchanges: ['mx.example.test'] }, ['ns1.dnsowl.com', 'ns2.dnsowl.com'])).toEqual([]);
		for (const wildcardProbe of ['no_wildcard', 'not_probed', undefined] as const) {
			expect(collectParkingSignals({ mxExchanges: ['mx.plain.com'], wildcardProbe }), String(wildcardProbe)).toEqual([]);
		}
	});
});

describe('resolveWebPresence — folding parking signals into the HEAD reading (#1202)', () => {
	it('parking MX or NS → parked whatever the HEAD probe saw, except a measured refusal', async () => {
		const { resolveWebPresence } = await load();
		for (const signal of ['parking_mx', 'parking_ns'] as const) {
			expect(resolveWebPresence('content', [signal]), signal).toBe('parked');
			expect(resolveWebPresence('unmeasured', [signal]), signal).toBe('parked');
			expect(resolveWebPresence('none', [signal]), signal).toBe('none');
		}
	});

	it('a wildcard zone is parked ONLY when the HEAD probe answered (fail-soft: an unanswered probe never makes it parked)', async () => {
		const { resolveWebPresence } = await load();
		expect(resolveWebPresence('content', ['wildcard_a'])).toBe('parked');
		expect(resolveWebPresence('unmeasured', ['wildcard_a'])).toBe('unmeasured');
		expect(resolveWebPresence('none', ['wildcard_a'])).toBe('none');
	});

	it('no parking signal leaves the HEAD reading unchanged', async () => {
		const { resolveWebPresence } = await load();
		for (const head of ['content', 'none', 'unmeasured'] as const) expect(resolveWebPresence(head, [])).toBe(head);
	});
});

describe('enrichLookalikes — webPresence beside an unchanged hasWebContent (#1202)', () => {
	it('no A record: unmeasured, not content — and no HEAD probe is issued', async () => {
		const { headCalls } = mockHead('ok');
		const { enrichLookalikes } = await load();
		const c = (await enrichLookalikes([candidate({ domain: 'mxonly.com', hasA: false, mxExchanges: ['mxa.mailgun.org'] })])).get(
			'mxonly.com',
		);
		expect(c).toMatchObject({ hasWebContent: true, webPresence: 'unmeasured', parkingSignals: [], wildcardProbe: 'not_probed' });
		expect(headCalls()).toBe(0);
	});

	it('no A record but a parking-network MX: parked from the MX answer alone', async () => {
		mockHead('ok');
		const { enrichLookalikes } = await load();
		const c = (await enrichLookalikes([candidate({ domain: 'parkmx.com', hasA: false, mxExchanges: ['park-mx.above.com'] })])).get(
			'parkmx.com',
		);
		expect(c).toMatchObject({ hasWebContent: true, webPresence: 'parked', parkingSignals: ['parking_mx'] });
	});

	it('parking NS from the phase-1 answers passed in candidateNs', async () => {
		mockHead('ok');
		const { enrichLookalikes } = await load();
		const enrichment = await enrichLookalikes([candidate({ domain: 'parkns.com' })], {
			candidateNs: new Map([['parkns.com', new Set(['ns1.sedoparking.com'])]]),
		});
		expect(enrichment.get('parkns.com')).toMatchObject({ hasWebContent: true, webPresence: 'parked', parkingSignals: ['parking_ns'] });
	});

	it('a wildcard zone whose HEAD probe answered is parked; with a plain zone the same answer is content', async () => {
		mockHead('ok');
		const { enrichLookalikes } = await load();
		const enrichment = await enrichLookalikes([
			candidate({ domain: 'wild.com', wildcardProbe: 'wildcard' }),
			candidate({ domain: 'plain.com', wildcardProbe: 'no_wildcard' }),
		]);
		expect(enrichment.get('wild.com')).toMatchObject({
			hasWebContent: true,
			webPresence: 'parked',
			parkingSignals: ['wildcard_a'],
			wildcardProbe: 'wildcard',
		});
		expect(enrichment.get('plain.com')).toMatchObject({
			hasWebContent: true,
			webPresence: 'content',
			parkingSignals: [],
			wildcardProbe: 'no_wildcard',
		});
	});

	it('a wildcard zone whose HEAD probe hung stays unmeasured — a starved probe never synthesises parked', async () => {
		mockHead('hang');
		const { enrichLookalikes } = await load();
		const enrichment = await enrichLookalikes([candidate({ domain: 'wildslow.com', wildcardProbe: 'wildcard' })], {
			deadlineMs: Date.now() + 200,
		});
		expect(enrichment.get('wildslow.com')).toMatchObject({
			hasWebContent: true,
			webPresence: 'unmeasured',
			parkingSignals: ['wildcard_a'],
		});
	});

	it('a measured refusal stays none (hasWebContent false, exactly as before) even on a parking MX', async () => {
		mockHead('refused');
		const { enrichLookalikes } = await load();
		const enrichment = await enrichLookalikes([candidate({ domain: 'refused.com', mxExchanges: ['park-mx.above.com'] })]);
		expect(enrichment.get('refused.com')).toMatchObject({ hasWebContent: false, webPresence: 'none', parkingSignals: ['parking_mx'] });
	});
});
