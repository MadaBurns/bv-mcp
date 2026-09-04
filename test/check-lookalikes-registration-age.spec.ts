// SPDX-License-Identifier: BUSL-1.1
//
// Regression for #867 (the inversion of #780): `registrationDays` was null for
// MOST `.com` candidates of a large seed (anthropic.com: 8 populated / 24 null;
// cohere.com: 14 of 15 mail-capable null) while small `.ai` seeds populated
// fully.
//
// ROOT CAUSE — connection-slot starvation, not a TLD map or a parser.
// `enrichLookalikes()` fanned out EVERY candidate's RDAP fetch + HEAD probe at
// once (`Promise.allSettled(candidates.map(...))`), each armed with
// `AbortSignal.timeout(2500)` AT CALL TIME. A Worker invocation may hold at most
// SIX connections simultaneously waiting for response headers
// (developers.cloudflare.com/workers/platform/limits/#simultaneous-open-connections);
// the rest queue. The 'REPRODUCTION' case below runs the pre-fix fan-out shape
// against an emulated six-slot runtime and shows the tail nulling. A 25-candidate seed dispatches ~48 fetches; the 2.5s timers of
// the ~42 queued ones run while they WAIT for a slot, so they abort before the
// request is ever sent and fail-soft to `registrationDays: null` (and, for the
// HEAD probe, to `hasWebContent: false` — a manufactured HIGH corroborator).
// Measured live 2026-09-04 on anthropic.com: candidates in processing order,
// exactly the first 8 carry an age and the first 6 `hasWebContent: true`; every
// later candidate is `null` + `false`. RDAP and HEAD target different hosts, so
// a registry rate limit cannot explain both. `.ai` seeds only LOOKED fixed
// because a short brand yields few candidates (x.ai: 7 → 14 fetches, all served
// within 2.5s).
//
// The fix bounds the fan-out to the platform's connection cap (RDAP pool 4 +
// HEAD pool 2), arms each timeout when the fetch is actually dispatched,
// prioritises mail-capable candidates, and reports WHY an age is unknown.

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';
import type { LookalikeResult } from '../src/tools/lookalike-dns';

const { restore } = setupFetchMock();

afterEach(() => {
	restore();
	vi.restoreAllMocks();
});

type FetchInput = string | URL | Request;

function urlOf(input: FetchInput): string {
	return typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
}

function candidate(domain: string, opts: { hasA?: boolean; hasMX?: boolean } = {}): LookalikeResult {
	const hasMX = opts.hasMX ?? false;
	return {
		domain,
		hasA: opts.hasA ?? true,
		hasMX,
		mxExchanges: hasMX ? ['mail.example.net'] : [],
		probeDegraded: false,
	};
}

function rdapBody(daysAgo: number | null): Record<string, unknown> {
	return {
		objectClassName: 'domain',
		events: daysAgo === null ? [] : [{ eventAction: 'registration', eventDate: new Date(Date.now() - daysAgo * 86_400_000).toISOString() }],
		entities: [
			{
				objectClassName: 'entity',
				roles: ['registrar'],
				publicIds: [{ type: 'IANA Registrar ID', identifier: '1234' }],
				vcardArray: ['vcard', [['fn', {}, 'text', 'Example Registrar']]],
			},
		],
	};
}

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/rdap+json' } });
}

/** Resolve after `ms`, or reject with an AbortError as soon as `signal` fires — the shape a real fetch has. */
function delayHonouringSignal<T>(ms: number, value: () => T, signal: AbortSignal | null | undefined): Promise<T> {
	return new Promise<T>((resolve, reject) => {
		const abort = () => {
			clearTimeout(timer);
			reject(signal?.reason instanceof Error ? signal.reason : new DOMException('The operation was aborted', 'AbortError'));
		};
		if (signal?.aborted) {
			abort();
			return;
		}
		const timer = setTimeout(() => {
			signal?.removeEventListener('abort', abort);
			resolve(value());
		}, ms);
		signal?.addEventListener('abort', abort, { once: true });
	});
}

async function loadEnrichment() {
	return import('../src/tools/lookalike-enrichment');
}

// ---------------------------------------------------------------------------
// The fan-out contract — the mechanism behind #867.
// ---------------------------------------------------------------------------

describe('enrichLookalikes — bounded fan-out (#867)', () => {
	it('never has more than six enrichment fetches in flight, and every .com candidate of a 30+ set gets an age', async () => {
		let inFlight = 0;
		let peakInFlight = 0;
		globalThis.fetch = vi.fn().mockImplementation((input: FetchInput, init?: RequestInit) => {
			const url = new URL(urlOf(input));
			inFlight++;
			peakInFlight = Math.max(peakInFlight, inFlight);
			const release = () => {
				inFlight--;
			};
			if (url.pathname.includes('/domain/')) {
				return delayHonouringSignal(15, () => jsonResponse(rdapBody(400)), init?.signal).finally(release);
			}
			// HEAD probe of the candidate itself.
			return delayHonouringSignal(15, () => new Response(null, { status: 200 }), init?.signal).finally(release);
		});

		const candidates = Array.from({ length: 32 }, (_, i) => candidate(`brand${i}.com`, { hasA: true, hasMX: i % 2 === 0 }));
		const { enrichLookalikes } = await loadEnrichment();
		const enrichment = await enrichLookalikes(candidates);

		// The platform cap: six connections per invocation. Before the fix this was 64.
		expect(peakInFlight).toBeLessThanOrEqual(6);
		expect(enrichment.size).toBe(32);
		for (const c of candidates) {
			const corroborators = enrichment.get(c.domain);
			expect(corroborators?.registrationDays, c.domain).toBe(400);
			expect(corroborators?.ageUnknown, c.domain).toBe(false);
			expect(corroborators?.registrationLookup, c.domain).toBe('ok');
			expect(corroborators?.hasWebContent, c.domain).toBe(true);
		}
	});

	/**
	 * Emulate the Workers runtime: at most `SLOTS` fetches are "connected" at a
	 * time; the rest wait in a FIFO queue with their AbortSignal already ticking,
	 * exactly as the real queue behaves. `HOLD_MS` is how long a connected fetch
	 * occupies its slot. With 50 fetches through 6 slots, a fetch dispatched at
	 * position p waits ≈ floor(p / 6) × HOLD_MS; at 600ms the fifth round onward
	 * (p ≥ 30) waits > 2500ms — past the REAL `RDAP_PROBE_TIMEOUT_MS` — so a
	 * pre-armed timer fires while its fetch is still queued. `peakWaiting` is
	 * the deterministic tell: it is > 0 iff something ever queued.
	 */
	function buildSixSlotRuntime(holdMs: number) {
		const SLOTS = 6;
		let active = 0;
		const waiting: Array<() => void> = [];
		/**
		 * `queuedThenAborted` counts fetches that had to WAIT for a slot and were
		 * then torn down by their own timer before completing a hold — i.e. the
		 * request's budget was spent in the queue, not at the server. (Every
		 * signal here is created within the same millisecond, so at T+2500 the
		 * in-hold fetches abort, each release hands its slot to a waiter whose own
		 * timer fires a microtask later, and the whole tail collapses in one
		 * grant-then-abort cascade — which is why the count is taken on the
		 * rejection, not on the `abort` event.)
		 */
		const stats = { peakWaiting: 0, queuedThenAborted: 0 };
		const releaseSlot = () => {
			active--;
			// Drain until one waiter actually takes the slot (an already-aborted
			// waiter is rejected by `grant` without occupying it).
			while (active < SLOTS && waiting.length > 0) {
				const before = active;
				waiting.shift()!();
				if (active > before) break;
			}
		};
		const fetchImpl = async (input: FetchInput, init?: RequestInit): Promise<Response> => {
			const url = new URL(urlOf(input));
			const signal = init?.signal;
			let wasQueued = false;
			// Waiting for a slot is abortable — a queued fetch whose timer fires
			// rejects without ever being sent (and leaves the queue).
			await new Promise<void>((resolve, reject) => {
				const abortReason = () => signal?.reason ?? new DOMException('aborted', 'AbortError');
				const grant = () => {
					signal?.removeEventListener('abort', onAbort);
					// The runtime hands the slot to a fetch whose timer already fired:
					// it is torn down without being sent. Counted here as well as in
					// the listener because workerd does not reliably dispatch the
					// `abort` event to a listener registered on a signal that is
					// merely parked in a queue (observed 2026-09-04); the flag is
					// authoritative either way.
					if (signal?.aborted) {
						stats.queuedThenAborted++;
						reject(abortReason());
						return;
					}
					active++;
					resolve();
				};
				const onAbort = () => {
					const idx = waiting.indexOf(grant);
					if (idx >= 0) {
						waiting.splice(idx, 1);
						stats.queuedThenAborted++;
					}
					reject(abortReason());
				};
				if (signal?.aborted) return onAbort();
				signal?.addEventListener('abort', onAbort, { once: true });
				if (active < SLOTS) {
					grant();
				} else {
					wasQueued = true;
					waiting.push(grant);
					stats.peakWaiting = Math.max(stats.peakWaiting, waiting.length);
				}
			});
			try {
				return await delayHonouringSignal(
					holdMs,
					() => (url.pathname.includes('/domain/') ? jsonResponse(rdapBody(400)) : new Response(null, { status: 200 })),
					signal,
				);
			} catch (err) {
				// Granted in the cascade described above, then killed by a timer
				// that was armed while it sat in the queue.
				if (wasQueued) stats.queuedThenAborted++;
				throw err;
			} finally {
				releaseSlot();
			}
		};
		return { fetchImpl, stats };
	}

	const QUEUE_HOLD_MS = 600;
	const queueCandidates = () => Array.from({ length: 30 }, (_, i) => candidate(`starve${i}.com`, { hasA: i < 20, hasMX: true }));

	it('REPRODUCTION (pre-fix shape): the old per-candidate fan-out queues behind six slots and its pre-armed timers null the tail', async () => {
		const { fetchImpl, stats } = buildSixSlotRuntime(QUEUE_HOLD_MS);
		globalThis.fetch = vi.fn().mockImplementation(fetchImpl);
		const { probePrimaryRegistration, probeHasWebContent } = await loadEnrichment();

		// EXACTLY the #867 code path: `Promise.allSettled(candidates.map(...))`
		// dispatching RDAP + HEAD for every candidate at once, each probe arming
		// its own 2500ms timer at call time. `probePrimaryRegistration` IS the
		// per-candidate `probeRdap` (same function, no deadline), and
		// `probeHasWebContent` is the same HEAD probe the old loop called.
		const candidates = queueCandidates();
		const results = new Map<string, { registrationDays: number | null; lookup: string; hasWebContent: boolean }>();
		await Promise.allSettled(
			candidates.map(async (c) => {
				const [rdap, hasWebContent] = await Promise.all([
					probePrimaryRegistration(c.domain),
					c.hasA ? probeHasWebContent(c.domain) : Promise.resolve(true),
				]);
				results.set(c.domain, { registrationDays: rdap.registrationDays, lookup: rdap.lookup, hasWebContent });
			}),
		);

		// Something queued — the branch the bounded path must never reach.
		expect(stats.peakWaiting).toBeGreaterThan(0);
		expect(stats.queuedThenAborted).toBeGreaterThanOrEqual(10);
		// The tail aborted IN THE QUEUE: null age, recorded as a timeout, with no
		// server ever answering slowly. Positions ≥ 30 of 50 → ≥ 10 RDAP probes.
		const starved = candidates.filter((c) => results.get(c.domain)?.registrationDays === null);
		expect(starved.length).toBeGreaterThanOrEqual(10);
		for (const c of starved) expect(results.get(c.domain)?.lookup, c.domain).toBe('timeout');
		// The same starvation used to manufacture the "no reachable web content"
		// HIGH corroborator for HEAD probes that were never sent (#894 residual
		// 2, closed with the #865 follow-up): a HEAD probe that times out — in
		// the queue or at the server — is UNKNOWN and fails toward `true`, so
		// even this pre-fix fan-out shape can no longer synthesise it.
		expect(candidates.every((c) => results.get(c.domain)?.hasWebContent === true)).toBe(true);
	});

	it('bounded fan-out never queues behind the six slots, so no timer runs while waiting and every candidate is populated', async () => {
		const { fetchImpl, stats } = buildSixSlotRuntime(QUEUE_HOLD_MS);
		globalThis.fetch = vi.fn().mockImplementation(fetchImpl);

		const candidates = queueCandidates();
		const { enrichLookalikes } = await loadEnrichment();
		const enrichment = await enrichLookalikes(candidates, { deadlineMs: Date.now() + 10_000 });

		// The load-bearing guard against a pool-width regression: with
		// RDAP_PROBE_CONCURRENCY + WEB_PROBE_CONCURRENCY ≤ 6 nothing can ever
		// wait for a slot. Any widening past six turns this red deterministically
		// — the timer-based assertions below would only catch a LARGE overshoot,
		// because a queued fetch must wait ≥ 5 rounds to outlive 2500ms.
		expect(stats.peakWaiting).toBe(0);
		expect(stats.queuedThenAborted).toBe(0);

		const populated = candidates.filter((c) => enrichment.get(c.domain)?.registrationDays === 400).length;
		expect(populated).toBe(30);
		for (const c of candidates) expect(enrichment.get(c.domain)?.registrationLookup, c.domain).toBe('ok');
		const noContent = candidates.filter((c) => enrichment.get(c.domain)?.hasWebContent === false).length;
		expect(noContent).toBe(0);
	});

	it('dispatches mail-capable candidates before web-only ones, so a tight budget protects the ones the age signal matters for', async () => {
		const rdapOrder: string[] = [];
		globalThis.fetch = vi.fn().mockImplementation((input: FetchInput, init?: RequestInit) => {
			const url = new URL(urlOf(input));
			if (url.pathname.includes('/domain/')) {
				rdapOrder.push(url.pathname.split('/domain/')[1]);
				return delayHonouringSignal(5, () => jsonResponse(rdapBody(400)), init?.signal);
			}
			return delayHonouringSignal(5, () => new Response(null, { status: 200 }), init?.signal);
		});

		// Web-only candidates listed FIRST; mail-capable ones last.
		const webOnly = Array.from({ length: 6 }, (_, i) => candidate(`web${i}.com`, { hasA: true, hasMX: false }));
		const mail = Array.from({ length: 6 }, (_, i) => candidate(`mail${i}.com`, { hasA: true, hasMX: true }));
		const { enrichLookalikes } = await loadEnrichment();
		await enrichLookalikes([...webOnly, ...mail]);

		expect(rdapOrder.slice(0, 6).sort()).toEqual(mail.map((c) => c.domain).sort());
		expect(rdapOrder.slice(6).sort()).toEqual(webOnly.map((c) => c.domain).sort());
	});

	it('with the deadline already spent, issues NO fetch and marks every candidate not_attempted (never a bare null)', async () => {
		const fetchSpy = vi.fn().mockImplementation(() => Promise.resolve(jsonResponse(rdapBody(400))));
		globalThis.fetch = fetchSpy;

		const candidates = [candidate('late1.com', { hasMX: true }), candidate('late2.com', { hasA: true })];
		const { enrichLookalikes } = await loadEnrichment();
		const enrichment = await enrichLookalikes(candidates, { deadlineMs: Date.now() - 1 });

		expect(fetchSpy).not.toHaveBeenCalled();
		for (const c of candidates) {
			const corroborators = enrichment.get(c.domain);
			expect(corroborators?.registrationDays).toBeNull();
			expect(corroborators?.ageUnknown).toBe(true);
			expect(corroborators?.registrationLookup).toBe('not_attempted');
			// An unattempted HEAD probe is "unknown", which fails soft to "has
			// content" — it must never synthesise the no-content HIGH corroborator.
			expect(corroborators?.hasWebContent).toBe(true);
		}
	});
});

// ---------------------------------------------------------------------------
// Explicit unknown-age reasons — "unknown" must be distinguishable from "absent".
// ---------------------------------------------------------------------------

describe('enrichLookalikes — registrationLookup outcomes (#867)', () => {
	async function outcomeFor(domain: string, respond: (init?: RequestInit) => Promise<Response>, deadlineMs?: number) {
		globalThis.fetch = vi.fn().mockImplementation((input: FetchInput, init?: RequestInit) => {
			const url = new URL(urlOf(input));
			if (url.pathname.includes('/domain/')) return respond(init);
			return Promise.resolve(new Response(null, { status: 200 }));
		});
		const { enrichLookalikes } = await loadEnrichment();
		const enrichment = await enrichLookalikes([candidate(domain, { hasA: true, hasMX: true })], deadlineMs ? { deadlineMs } : undefined);
		return enrichment.get(domain)!;
	}

	it('populated age → ok, ageUnknown false', async () => {
		const c = await outcomeFor('ok.com', () => Promise.resolve(jsonResponse(rdapBody(10_000))));
		expect(c.registrationDays).toBe(10_000);
		expect(c.ageUnknown).toBe(false);
		expect(c.registrationLookup).toBe('ok');
	});

	it('HTTP 429 → throttled', async () => {
		const c = await outcomeFor('busy.com', () => Promise.resolve(new Response('slow down', { status: 429 })));
		expect(c.registrationDays).toBeNull();
		expect(c.ageUnknown).toBe(true);
		expect(c.registrationLookup).toBe('throttled');
	});

	it('HTTP 404 → not_found', async () => {
		const c = await outcomeFor('gone.com', () => Promise.resolve(new Response('nope', { status: 404 })));
		expect(c.registrationLookup).toBe('not_found');
		expect(c.ageUnknown).toBe(true);
	});

	it('other HTTP failure → failed', async () => {
		const c = await outcomeFor('broken.com', () => Promise.resolve(new Response('boom', { status: 503 })));
		expect(c.registrationLookup).toBe('failed');
		expect(c.ageUnknown).toBe(true);
	});

	it('transport error → failed', async () => {
		const c = await outcomeFor('dead.com', () => Promise.reject(new TypeError('connection reset')));
		expect(c.registrationLookup).toBe('failed');
		expect(c.ageUnknown).toBe(true);
	});

	it('server hangs past the (deadline-clamped) timeout → timeout', async () => {
		const c = await outcomeFor(
			'slow.com',
			(init) => delayHonouringSignal(10_000, () => jsonResponse(rdapBody(400)), init?.signal),
			Date.now() + 150,
		);
		expect(c.registrationDays).toBeNull();
		expect(c.ageUnknown).toBe(true);
		expect(c.registrationLookup).toBe('timeout');
	});

	it('200 with no registration event → no_registration_event, registrar still harvested', async () => {
		const c = await outcomeFor('noevent.com', () => Promise.resolve(jsonResponse(rdapBody(null))));
		expect(c.registrationDays).toBeNull();
		expect(c.ageUnknown).toBe(true);
		expect(c.registrationLookup).toBe('no_registration_event');
		expect(c.registrarIanaId).toBe('1234');
	});

	it('TLD with no RDAP server in the map (.co) → unsupported_tld, no fetch issued', async () => {
		const fetchSpy = vi.fn().mockImplementation(() => Promise.resolve(new Response(null, { status: 200 })));
		globalThis.fetch = fetchSpy;
		const { enrichLookalikes } = await loadEnrichment();
		const enrichment = await enrichLookalikes([candidate('brand.co', { hasA: false, hasMX: true })]);
		const c = enrichment.get('brand.co')!;
		expect(c.registrationLookup).toBe('unsupported_tld');
		expect(c.ageUnknown).toBe(true);
		expect(fetchSpy.mock.calls.map((call) => urlOf(call[0] as FetchInput)).filter((u) => u.includes('/domain/'))).toEqual([]);
	});
});

// ---------------------------------------------------------------------------
// End to end through checkLookalikes: .com AND .ai populate, and the finding
// metadata carries the explicit unknown marker.
// ---------------------------------------------------------------------------

describe('checkLookalikes — registration age end to end (#867)', () => {
	/**
	 * DoH: every candidate under `tld` that is not the seed resolves with NS + A
	 * + MX (so it reaches enrichment as mail-capable). RDAP: `rdapDaysAgo` for
	 * every domain, or a per-domain override. HEAD: 200.
	 */
	function mockPipeline(opts: {
		seed: string;
		tld: string;
		rdapDaysAgo: number;
		rdapOverride?: (domain: string) => Response | null;
		onRdapHost?: (host: string) => void;
	}) {
		const enrichmentInFlight = { now: 0, peak: 0 };
		globalThis.fetch = vi.fn().mockImplementation((input: FetchInput, init?: RequestInit) => {
			const url = new URL(urlOf(input));
			if (url.pathname === '/dns-query') {
				const name = url.searchParams.get('name') ?? '';
				const type = url.searchParams.get('type') ?? '';
				const isCandidate = name !== opts.seed && name.endsWith(`.${opts.tld}`) && name.split('.').length === 2;
				if (isCandidate) {
					if (type === 'NS' || type === '2') {
						return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.other-registrar.net.' }]));
					}
					if (type === 'MX' || type === '15') {
						return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mx.other-mail.net.' }]));
					}
					if (type === 'A' || type === '1') {
						return Promise.resolve(createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '192.0.2.10' }]));
					}
				}
				if (name === opts.seed && (type === 'NS' || type === '2')) {
					return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.seed-dns.example.' }]));
				}
				return Promise.resolve(createDohResponse([], []));
			}
			enrichmentInFlight.now++;
			enrichmentInFlight.peak = Math.max(enrichmentInFlight.peak, enrichmentInFlight.now);
			const release = () => {
				enrichmentInFlight.now--;
			};
			if (url.pathname.includes('/domain/')) {
				opts.onRdapHost?.(url.hostname);
				const domain = url.pathname.split('/domain/')[1];
				const override = opts.rdapOverride?.(domain);
				return delayHonouringSignal(5, () => override ?? jsonResponse(rdapBody(opts.rdapDaysAgo)), init?.signal).finally(release);
			}
			return delayHonouringSignal(5, () => new Response(null, { status: 200 }), init?.signal).finally(release);
		});
		return enrichmentInFlight;
	}

	it('.com seed with 30+ mail-capable candidates: every .com candidate carries a populated age and registrationLookup: ok', async () => {
		const inFlight = mockPipeline({ seed: 'example.com', tld: 'com', rdapDaysAgo: 365 });
		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		const result = await checkLookalikes('example.com');

		const observations = result.findings.filter(
			(f) =>
				f.metadata?.findingAxis === 'threat_observation' && typeof f.metadata?.lookalikeDomain === 'string' && f.metadata.hasMX === true,
		);
		const comObservations = observations.filter((f) => String(f.metadata?.lookalikeDomain).endsWith('.com'));
		// The premise of #867 is a LARGE candidate set — anthropic.com resolved 25.
		expect(comObservations.length).toBeGreaterThanOrEqual(30);
		for (const f of comObservations) {
			expect(f.metadata?.registrationDays, String(f.metadata?.lookalikeDomain)).toBe(365);
			expect(f.metadata?.ageUnknown, String(f.metadata?.lookalikeDomain)).toBe(false);
			expect(f.metadata?.registrationLookup, String(f.metadata?.lookalikeDomain)).toBe('ok');
		}
		expect(inFlight.peak).toBeLessThanOrEqual(6);
	});

	it('.ai seed still populates (Identity Digital RDAP host, #780 stays fixed)', async () => {
		const hosts = new Set<string>();
		mockPipeline({ seed: 'openclaw.ai', tld: 'ai', rdapDaysAgo: 20, onRdapHost: (h) => hosts.add(h) });
		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		const result = await checkLookalikes('openclaw.ai');

		const aiObservations = result.findings.filter(
			(f) =>
				f.metadata?.findingAxis === 'threat_observation' &&
				String(f.metadata?.lookalikeDomain).endsWith('.ai') &&
				f.metadata?.hasMX === true,
		);
		expect(aiObservations.length).toBeGreaterThan(0);
		for (const f of aiObservations) {
			expect(f.metadata?.registrationDays, String(f.metadata?.lookalikeDomain)).toBe(20);
			expect(f.metadata?.registrationLookup).toBe('ok');
		}
		expect(hosts.has('rdap.identitydigital.services')).toBe(true);
		expect(hosts.has('rdap.nic.ai')).toBe(false);
	});

	it('a failed lookup is marked ageUnknown with a reason on the finding, and a pre-dating candidate keeps its real age so the age filter can exclude it', async () => {
		mockPipeline({
			seed: 'example.com',
			tld: 'com',
			rdapDaysAgo: 30,
			rdapOverride: (domain) => {
				if (domain === 'exmple.com') return new Response('rate limited', { status: 429 });
				// Registered ~1998 — predates any brand founded after it, so a
				// consumer's "a typosquat cannot predate the brand" filter must be
				// able to see the age rather than a null it would read as "not excluded".
				if (domain === 'exampl.com') return jsonResponse(rdapBody(10_000));
				return null;
			},
		});
		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		const result = await checkLookalikes('example.com');

		const threatFor = (d: string) =>
			result.findings.find((f) => f.metadata?.findingAxis === 'threat_observation' && f.metadata?.lookalikeDomain === d);

		const throttled = threatFor('exmple.com');
		expect(throttled).toBeDefined();
		expect(throttled!.metadata?.registrationDays).toBeNull();
		expect(throttled!.metadata?.ageUnknown).toBe(true);
		expect(throttled!.metadata?.registrationLookup).toBe('throttled');
		// Unknown age never elevates: mail-infra with no corroborator is MEDIUM.
		expect(throttled!.severity).toBe('medium');

		const ancient = threatFor('exampl.com');
		expect(ancient).toBeDefined();
		expect(ancient!.metadata?.registrationDays).toBe(10_000);
		expect(ancient!.metadata?.ageUnknown).toBe(false);
		expect(ancient!.metadata?.registrationLookup).toBe('ok');
		// Not "recent" → no elevation from age.
		expect(ancient!.severity).toBe('medium');

		// A recent one (30 days) elevates to HIGH — the signal the lookup exists for.
		const recent = result.findings.find(
			(f) =>
				f.metadata?.findingAxis === 'threat_observation' &&
				f.metadata?.registrationDays === 30 &&
				f.metadata?.lookalikeDomain !== 'exmple.com' &&
				f.metadata?.lookalikeDomain !== 'exampl.com',
		);
		expect(recent).toBeDefined();
		expect(recent!.severity).toBe('high');
		expect(recent!.metadata?.registrationLookup).toBe('ok');
	});
});
