// SPDX-License-Identifier: BUSL-1.1
//
// Regression for the DNS-phase half of #867 / #865 (the residual PR #894 left).
//
// `filterByNsExistence` dispatched EVERY permutation's NS query at once
// (`Promise.allSettled(domains.map(...))`) with `AbortSignal.timeout(2000)`
// armed at call time, and `probeWithAdaptiveBatching` did the same for a
// 10-candidate batch (20 A/MX queries plus their secondary confirmations). A
// Worker invocation may hold at most SIX connections simultaneously
// (developers.cloudflare.com/workers/platform/limits/#simultaneous-open-connections);
// the rest queue with their timers already running. Any permutation whose
// authoritative servers are lame or slow holds its slot for the WHOLE 2s
// window, so a handful of them parks every slot and the queue behind them
// aborts before a single byte is sent.
//
// Measured 2026-09-04 (the numbers in the PR): openai.com has 11 of 90
// permutations whose NS lookup hangs to the 2s timer even when queried ALONE.
// Replaying the measured per-name latencies through a six-slot FIFO with
// pre-armed timers predicts 70 unresolved; production reported 76 (#865: 77).
// The same code on an uncapped local workerd against the same resolver:
// 12 unresolved, 54 candidates — so the resolver is not refusing the burst
// (90 simultaneous queries from Node: zero HTTP 429); the platform queue is.
// #892's rollup then abstains at >= 50% unresolved — an abstention the tool
// inflicted on itself.

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => {
	restore();
	vi.restoreAllMocks();
});

type FetchInput = string | URL | Request;

function urlOf(input: FetchInput): string {
	return typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
}

function dohQuery(input: FetchInput): { name: string; type: string } {
	const url = new URL(urlOf(input));
	return { name: url.searchParams.get('name') ?? '', type: url.searchParams.get('type') ?? '' };
}

function nsAnswer(name: string): Response {
	return createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: `ns1.${name}.` }]);
}

function typedAnswer(name: string, type: string): Response {
	if (type === 'NS' || type === '2') return nsAnswer(name);
	if (type === 'A' || type === '1') return createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '192.0.2.10' }]);
	if (type === 'MX' || type === '15')
		return createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mx.example.net.' }]);
	return createDohResponse([], []);
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

/**
 * Emulate the Workers runtime: at most `SLOTS` fetches are "connected" at a
 * time; the rest wait in a FIFO queue with their AbortSignal already ticking,
 * exactly as the real queue behaves. Same emulation as
 * `test/check-lookalikes-registration-age.spec.ts` (#894), with a per-name
 * hold: `holdFor(name)` returns how long a connected fetch occupies its slot,
 * or `Infinity` for a name whose authoritative servers never answer — the
 * measured openai.com shape (11 of 90 hang to the timer even queried alone).
 * `peakWaiting` is the deterministic tell: it is > 0 iff something ever queued.
 */
function buildSixSlotDohRuntime(holdFor: (name: string) => number) {
	const SLOTS = 6;
	let active = 0;
	const waiting: Array<() => void> = [];
	const stats = { peakWaiting: 0, queuedThenAborted: 0, issued: 0, peakInFlight: 0 };
	const releaseSlot = () => {
		active--;
		while (active < SLOTS && waiting.length > 0) {
			const before = active;
			waiting.shift()!();
			if (active > before) break;
		}
	};
	const fetchImpl = async (input: FetchInput, init?: RequestInit): Promise<Response> => {
		const { name, type } = dohQuery(input);
		const signal = init?.signal;
		let wasQueued = false;
		await new Promise<void>((resolve, reject) => {
			const abortReason = () => signal?.reason ?? new DOMException('aborted', 'AbortError');
			const grant = () => {
				signal?.removeEventListener('abort', onAbort);
				if (signal?.aborted) {
					stats.queuedThenAborted++;
					reject(abortReason());
					return;
				}
				active++;
				stats.peakInFlight = Math.max(stats.peakInFlight, active);
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
		stats.issued++;
		try {
			const hold = holdFor(name);
			if (!Number.isFinite(hold)) {
				// Never answers: the slot is held until the caller's own timer fires.
				return await delayHonouringSignal(60_000, () => typedAnswer(name, type), signal);
			}
			return await delayHonouringSignal(hold, () => typedAnswer(name, type), signal);
		} catch (err) {
			if (wasQueued) stats.queuedThenAborted++;
			throw err;
		} finally {
			releaseSlot();
		}
	};
	return { fetchImpl, stats };
}

/** 90 permutations, of which every 12th (7 in all) hangs — the openai.com shape at a slightly lower hang rate. */
const HANG_EVERY = 12;
const FAST_HOLD_MS = 50;
function starvationSet(): { domains: string[]; hangs: Set<string> } {
	const domains = Array.from({ length: 90 }, (_, i) => `perm${i}.com`);
	const hangs = new Set(domains.filter((_, i) => i % HANG_EVERY === HANG_EVERY - 1));
	return { domains, hangs };
}
const holdForStarvation = (hangs: Set<string>) => (name: string) => (hangs.has(name) ? Infinity : FAST_HOLD_MS);

async function loadDns() {
	return import('../src/tools/lookalike-dns');
}

// ---------------------------------------------------------------------------
// Phase 1 — NS existence.
// ---------------------------------------------------------------------------

describe('filterByNsExistence — bounded to the Workers connection cap (#865 follow-up)', () => {
	it('REPRODUCTION (pre-fix shape): the per-permutation fan-out queues behind six slots; a few hanging names park every slot and the queue aborts unsent', async () => {
		const { domains, hangs } = starvationSet();
		const { fetchImpl, stats } = buildSixSlotDohRuntime(holdForStarvation(hangs));
		globalThis.fetch = vi.fn().mockImplementation(fetchImpl);
		const { PHASE1_DNS_OPTS } = await loadDns();
		const { queryDnsRecords } = await import('../src/lib/dns');

		// EXACTLY the pre-fix `filterByNsExistence` body: every NS query at once,
		// each arming its 2000ms timer (PHASE1_DNS_OPTS) at call time.
		const results = await Promise.allSettled(domains.map((domain) => queryDnsRecords(domain, 'NS', PHASE1_DNS_OPTS)));
		const rejected = results.filter((r) => r.status === 'rejected').length;

		expect(stats.peakWaiting).toBeGreaterThan(0);
		// Six hangs (positions 11..71) kill all six slots; everything queued
		// behind position 71 — 18 names, 17 of them perfectly resolvable — aborts
		// at 2000ms without ever being sent. Only `hangs.size` were ever unreachable.
		expect(stats.queuedThenAborted).toBeGreaterThanOrEqual(15);
		expect(rejected).toBeGreaterThanOrEqual(hangs.size + 15);
	}, 15_000);

	it('bounded pool: never queues behind the six slots, so only the names that genuinely never answer are unresolved — and they are counted with a reason', async () => {
		const { domains, hangs } = starvationSet();
		const { fetchImpl, stats } = buildSixSlotDohRuntime(holdForStarvation(hangs));
		globalThis.fetch = vi.fn().mockImplementation(fetchImpl);
		const { filterByNsExistence, LOOKALIKE_DNS_PROBE_CONCURRENCY } = await loadDns();

		const result = await filterByNsExistence(domains, { deadlineMs: Date.now() + 14_000 });

		// The load-bearing guard against a pool-width regression: with the pool at
		// or under six nothing can ever wait for a slot. Any widening past six
		// turns this red deterministically (mutation-checked in the PR).
		expect(LOOKALIKE_DNS_PROBE_CONCURRENCY).toBeLessThanOrEqual(6);
		expect(stats.peakInFlight).toBeLessThanOrEqual(6);
		expect(stats.peakWaiting).toBe(0);
		expect(stats.queuedThenAborted).toBe(0);

		expect(result.registered.length).toBe(domains.length - hangs.size);
		expect(result.unresolved).toBe(hangs.size);
		expect(result.unresolvedByReason).toEqual({ timeout: hangs.size, deadline: 0, failed: 0 });
		for (const hang of hangs) expect(result.registered).not.toContain(hang);
	}, 15_000);

	it('a permutation whose turn comes after the phase deadline is NOT issued, and is counted unresolved with reason `deadline` — never as "no NS"', async () => {
		const domains = Array.from({ length: 30 }, (_, i) => `late${i}.com`);
		const { fetchImpl, stats } = buildSixSlotDohRuntime(() => 100);
		globalThis.fetch = vi.fn().mockImplementation(fetchImpl);
		const { filterByNsExistence } = await loadDns();

		// Two rounds of six fit; the rest find the deadline spent.
		const result = await filterByNsExistence(domains, { deadlineMs: Date.now() + 230 });

		expect(stats.issued).toBeLessThan(domains.length);
		expect(result.unresolvedByReason.deadline).toBeGreaterThan(0);
		// Every permutation that was never issued is a deadline cut (not a timeout,
		// not a failure — nothing was measured).
		expect(result.unresolvedByReason.deadline).toBeGreaterThanOrEqual(domains.length - stats.issued);
		// Nothing is dropped silently: every permutation is either registered or unresolved.
		expect(result.registered.length + result.unresolved).toBe(domains.length);
		expect(result.unresolved).toBe(
			result.unresolvedByReason.timeout + result.unresolvedByReason.deadline + result.unresolvedByReason.failed,
		);
		// Every name that WAS issued resolved (100ms hold, no hangs).
		expect(result.registered.length).toBeGreaterThanOrEqual(12);
		expect(result.registered.length).toBe(domains.length - result.unresolved);
	});

	it('a query cut mid-flight by the deadline is `deadline`, a query the resolver never answered is `timeout`, a transport failure is `failed`', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: FetchInput, init?: RequestInit) => {
			const { name } = dohQuery(input);
			if (name === 'broken.com') return Promise.reject(new TypeError('connection reset'));
			// Both remaining names hang; only the deadline distinguishes them.
			return delayHonouringSignal(60_000, () => nsAnswer(name), init?.signal);
		});
		const { filterByNsExistence } = await loadDns();
		const result = await filterByNsExistence(['broken.com', 'hang.com'], { deadlineMs: Date.now() + 300 });
		expect(result.registered).toEqual([]);
		expect(result.unresolved).toBe(2);
		expect(result.unresolvedByReason).toEqual({ timeout: 0, deadline: 1, failed: 1 });
	});

	it('without a deadline (direct callers) behaves as before: a hang is a timeout after PHASE1_DNS_OPTS.timeoutMs', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: FetchInput, init?: RequestInit) => {
			const { name } = dohQuery(input);
			if (name === 'hang.com') return delayHonouringSignal(60_000, () => nsAnswer(name), init?.signal);
			return Promise.resolve(nsAnswer(name));
		});
		const { filterByNsExistence } = await loadDns();
		const result = await filterByNsExistence(['ok.com', 'hang.com']);
		expect(result.registered).toEqual(['ok.com']);
		expect(result.unresolved).toBe(1);
		expect(result.unresolvedByReason).toEqual({ timeout: 1, deadline: 0, failed: 0 });
	});
});

// ---------------------------------------------------------------------------
// Phase 2 — A/MX detail probe.
// ---------------------------------------------------------------------------

describe('probeWithAdaptiveBatching — bounded to the Workers connection cap', () => {
	it('candidate A/MX legs keep the default timer and secondary confirmation but never retry (a lame candidate must not hold a slot for two attempts)', async () => {
		const { PHASE2_DNS_OPTS } = await loadDns();
		expect(PHASE2_DNS_OPTS).toEqual({ retries: 0 });

		let mxAttempts = 0;
		globalThis.fetch = vi.fn().mockImplementation((input: FetchInput, init?: RequestInit) => {
			const { name, type } = dohQuery(input);
			if (name === 'lame.com' && (type === 'MX' || type === '15')) {
				mxAttempts++;
				return delayHonouringSignal(60_000, () => typedAnswer(name, type), init?.signal);
			}
			return Promise.resolve(typedAnswer(name, type));
		});
		const { probeWithAdaptiveBatching } = await loadDns();
		const [r] = await probeWithAdaptiveBatching(['lame.com']);
		expect(r.status).toBe('fulfilled');
		if (r.status === 'fulfilled') {
			expect(r.value.probeDegraded).toBe(true);
			expect(r.value.probeDegradedReason).toBe('timeout');
			expect(r.value.hasA).toBe(true);
		}
		expect(mxAttempts).toBe(1);
	}, 15_000);

	it('a 10-candidate batch (20 queries) never has more than six DoH fetches in flight and every candidate is measured', async () => {
		const { fetchImpl, stats } = buildSixSlotDohRuntime(() => 30);
		globalThis.fetch = vi.fn().mockImplementation(fetchImpl);
		const { probeWithAdaptiveBatching } = await loadDns();
		const candidates = Array.from({ length: 25 }, (_, i) => `cand${i}.com`);

		const results = await probeWithAdaptiveBatching(candidates, { deadlineMs: Date.now() + 14_000 });

		expect(stats.peakInFlight).toBeLessThanOrEqual(6);
		expect(stats.peakWaiting).toBe(0);
		expect(results).toHaveLength(25);
		for (const r of results) {
			expect(r.status).toBe('fulfilled');
			if (r.status === 'fulfilled') {
				expect(r.value.probeDegraded).toBe(false);
				expect(r.value.hasA).toBe(true);
				expect(r.value.hasMX).toBe(true);
			}
		}
	});

	it('candidates whose turn comes after the deadline are returned DEGRADED with reason `deadline` (infrastructure unmeasured), never as registered-but-dark', async () => {
		const fetchSpy = vi.fn().mockImplementation((input: FetchInput) => {
			const { name, type } = dohQuery(input);
			return Promise.resolve(typedAnswer(name, type));
		});
		globalThis.fetch = fetchSpy;
		const { probeWithAdaptiveBatching } = await loadDns();
		const candidates = Array.from({ length: 12 }, (_, i) => `cut${i}.com`);

		const results = await probeWithAdaptiveBatching(candidates, { deadlineMs: Date.now() - 1 });

		expect(fetchSpy).not.toHaveBeenCalled();
		expect(results).toHaveLength(12);
		for (const r of results) {
			expect(r.status).toBe('fulfilled');
			if (r.status === 'fulfilled') {
				expect(r.value.probeDegraded).toBe(true);
				expect(r.value.probeDegradedReason).toBe('deadline');
				// UNFETCHED, not measured: no positive signal may be synthesised either way.
				expect(r.value.hasA).toBe(false);
				expect(r.value.hasMX).toBe(false);
				expect(r.value.mxExchanges).toEqual([]);
			}
		}
	});

	it('an empty-answer candidate whose SECONDARY confirmation hangs is cut at deadlineMs (not deadlineMs + DNS_TIMEOUT_MS), counted `deadline`, and the phase returns within budget', async () => {
		// The PR #903 review case: typosquats holding NS only answer EMPTY for
		// A/MX, which triggers the secondary-resolver confirmation — a fetch the
		// caller's deadline used to have no reach into.
		let secondaryCalls = 0;
		globalThis.fetch = vi.fn().mockImplementation((input: FetchInput, init?: RequestInit) => {
			const url = new URL(urlOf(input));
			if (url.hostname === 'dns.google') {
				secondaryCalls++;
				return delayHonouringSignal(60_000, () => createDohResponse([], []), init?.signal);
			}
			const { name } = dohQuery(input);
			return Promise.resolve(createDohResponse([{ name, type: 1 }], []));
		});
		const { probeWithAdaptiveBatching } = await loadDns();
		const BUDGET_MS = 400;
		const started = Date.now();
		const results = await probeWithAdaptiveBatching(['nsonly.com'], { deadlineMs: started + BUDGET_MS });
		const elapsed = Date.now() - started;

		expect(secondaryCalls).toBeGreaterThan(0);
		// Within budget (plus scheduling slack) — nowhere near the 3s the secondary's own timer would allow.
		expect(elapsed).toBeLessThan(BUDGET_MS + 300);
		expect(results).toHaveLength(1);
		const r = results[0];
		expect(r.status).toBe('fulfilled');
		if (r.status === 'fulfilled') {
			expect(r.value.probeDegraded).toBe(true);
			expect(r.value.probeDegradedReason).toBe('deadline');
			// An aborted confirmation is not a measured absence.
			expect(r.value.hasA).toBe(false);
			expect(r.value.hasMX).toBe(false);
		}
	});

	it('a candidate whose A or MX query hung is degraded with reason `timeout`; a transport failure with `failed`', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: FetchInput, init?: RequestInit) => {
			const { name, type } = dohQuery(input);
			if (name === 'slowmx.com' && (type === 'MX' || type === '15'))
				return delayHonouringSignal(60_000, () => typedAnswer(name, type), init?.signal);
			if (name === 'brokena.com' && (type === 'A' || type === '1')) return Promise.reject(new TypeError('connection reset'));
			return Promise.resolve(typedAnswer(name, type));
		});
		const { probeWithAdaptiveBatching } = await loadDns();
		const results = await probeWithAdaptiveBatching(['slowmx.com', 'brokena.com', 'fine.com'], { deadlineMs: Date.now() + 1_500 });
		const byDomain = new Map(results.map((r) => (r.status === 'fulfilled' ? [r.value.domain, r.value] : ['?', undefined])));
		// A hang past the deadline is a deadline cut, not a resolver timeout — the
		// default per-attempt timer (3s) never got to fire.
		expect(byDomain.get('slowmx.com')?.probeDegraded).toBe(true);
		expect(byDomain.get('slowmx.com')?.probeDegradedReason).toBe('deadline');
		expect(byDomain.get('slowmx.com')?.hasA).toBe(true);
		expect(byDomain.get('brokena.com')?.probeDegraded).toBe(true);
		expect(byDomain.get('brokena.com')?.probeDegradedReason).toBe('failed');
		expect(byDomain.get('brokena.com')?.hasMX).toBe(true);
		expect(byDomain.get('fine.com')?.probeDegraded).toBe(false);
		expect(byDomain.get('fine.com')?.probeDegradedReason).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// End to end through checkLookalikes — the enumeration contract #892 reads.
// ---------------------------------------------------------------------------

describe('checkLookalikes — DNS phases end to end', () => {
	it('keeps the DoH fan-out at or under six for a 90-permutation seed, and the enumeration stats contract is byte-compatible', async () => {
		let inFlight = 0;
		let peakInFlight = 0;
		globalThis.fetch = vi.fn().mockImplementation((input: FetchInput, init?: RequestInit) => {
			const url = new URL(urlOf(input));
			if (url.pathname !== '/dns-query') return Promise.resolve(new Response(null, { status: 200 }));
			const { name, type } = dohQuery(input);
			inFlight++;
			peakInFlight = Math.max(peakInFlight, inFlight);
			const release = () => {
				inFlight--;
			};
			// Non-seed .com names resolve fully; everything else is empty.
			const answers = name !== 'example.com' && name.endsWith('.com') && name.split('.').length === 2;
			return delayHonouringSignal(5, () => (answers ? typedAnswer(name, type) : createDohResponse([], [])), init?.signal).finally(release);
		});
		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		const result = await checkLookalikes('example.com');

		expect(peakInFlight).toBeLessThanOrEqual(6);
		const withEnum = result.findings.find((f) => f.metadata?.enumeration !== undefined);
		expect(withEnum).toBeDefined();
		const enumeration = withEnum!.metadata!.enumeration as Record<string, unknown>;
		// Byte-compatible with what #892's rollup reads: exactly these five keys.
		expect(Object.keys(enumeration).sort()).toEqual([
			'candidatesResolved',
			'complete',
			'permutationsGenerated',
			'permutationsProbed',
			'unresolvedCount',
		]);
		expect(enumeration.complete).toBe(true);
		expect(enumeration.unresolvedCount).toBe(0);
		expect(result.findings.some((f) => /enumeration was incomplete/i.test(f.title))).toBe(false);
	});

	it('when NO candidate resolved because every lookup was unresolved, the run reports an incomplete enumeration (partial) — not a clean "no active registrations"', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: FetchInput) => {
			const url = new URL(urlOf(input));
			if (url.pathname !== '/dns-query') return Promise.resolve(new Response(null, { status: 200 }));
			const { name, type } = dohQuery(input);
			if (name === 'example.com') return Promise.resolve(typedAnswer(name, type));
			// Every permutation's lookup fails at the transport — the shape of a run
			// whose phase 1 was entirely cut or refused.
			return Promise.reject(new TypeError('connection reset'));
		});
		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		const result = await checkLookalikes('example.com');

		expect(result.partial).toBe(true);
		expect(result.findings.some((f) => /no active lookalike domains detected/i.test(f.title))).toBe(false);
		const incomplete = result.findings.find((f) => /enumeration was incomplete/i.test(f.title));
		expect(incomplete).toBeDefined();
		const enumeration = incomplete!.metadata!.enumeration as Record<string, unknown>;
		expect(Object.keys(enumeration).sort()).toEqual([
			'candidatesResolved',
			'complete',
			'permutationsGenerated',
			'permutationsProbed',
			'unresolvedCount',
		]);
		expect(enumeration.candidatesResolved).toBe(0);
		expect(enumeration.complete).toBe(false);
		expect(enumeration.unresolvedCount).toBe(enumeration.permutationsProbed);
		const reasons = incomplete!.metadata!.unresolvedByReason as { timeout: number; deadline: number; failed: number };
		expect(reasons.failed).toBe(enumeration.permutationsProbed);
		// Nothing in the run may claim determinism about the set.
		for (const f of result.findings) expect(f.metadata?.confidence, f.title).not.toBe('deterministic');
	});

	it('when some lookups measured an absence and the rest were unresolved, "no registered candidates" is kept but demoted to heuristic, beside the incomplete notice', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: FetchInput) => {
			const url = new URL(urlOf(input));
			if (url.pathname !== '/dns-query') return Promise.resolve(new Response(null, { status: 200 }));
			const { name, type } = dohQuery(input);
			if (name === 'example.com') return Promise.resolve(typedAnswer(name, type));
			if (name === 'exampl.com') return Promise.reject(new TypeError('connection reset'));
			return Promise.resolve(createDohResponse([], []));
		});
		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		const result = await checkLookalikes('example.com');

		expect(result.partial).toBe(true);
		const none = result.findings.find((f) => /no active lookalike domains detected/i.test(f.title));
		expect(none).toBeDefined();
		expect(none!.metadata?.confidence).toBe('heuristic');
		const incomplete = result.findings.find((f) => /enumeration was incomplete/i.test(f.title));
		expect(incomplete).toBeDefined();
		expect((incomplete!.metadata!.enumeration as { unresolvedCount: number }).unresolvedCount).toBe(1);
		expect(incomplete!.metadata!.unresolvedByReason).toEqual({ timeout: 0, deadline: 0, failed: 1 });
	});

	it('an incomplete run reports WHY on the scan_status finding, and the reasons sum to unresolvedCount', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: FetchInput, init?: RequestInit) => {
			const url = new URL(urlOf(input));
			if (url.pathname !== '/dns-query') return Promise.resolve(new Response(null, { status: 200 }));
			const { name, type } = dohQuery(input);
			if (name === 'example.com') return Promise.resolve(typedAnswer(name, type));
			if (name === 'exampl.com') return Promise.resolve(typedAnswer(name, type));
			if (name === 'exmple.com') return Promise.reject(new TypeError('connection reset'));
			if (name === 'examle.com') return delayHonouringSignal(60_000, () => typedAnswer(name, type), init?.signal);
			return Promise.resolve(createDohResponse([], []));
		});
		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		const result = await checkLookalikes('example.com');

		const incomplete = result.findings.find((f) => /enumeration was incomplete/i.test(f.title));
		expect(incomplete).toBeDefined();
		const enumeration = incomplete!.metadata!.enumeration as { unresolvedCount: number; complete: boolean };
		expect(enumeration.complete).toBe(false);
		expect(enumeration.unresolvedCount).toBe(2);
		expect(Object.keys(incomplete!.metadata!.enumeration as object).sort()).toEqual([
			'candidatesResolved',
			'complete',
			'permutationsGenerated',
			'permutationsProbed',
			'unresolvedCount',
		]);
		const reasons = incomplete!.metadata!.unresolvedByReason as { timeout: number; deadline: number; failed: number };
		expect(reasons).toEqual({ timeout: 1, deadline: 0, failed: 1 });
		expect(reasons.timeout + reasons.deadline + reasons.failed).toBe(enumeration.unresolvedCount);
	}, 15_000);
});
