/**
 * SubdoMailing bounded-parallelism parity guard (#674).
 *
 * `check_subdomailing`'s cost is the COUNT of serial DoH round-trips, so the fix is bounded
 * parallelism, not a fetch budget. The hazard that makes it a SCORING change rather than a
 * scheduling change: `MAX_INCLUDE_PROBES` is tested MID-ITERATION in DFS order, so a naive
 * breadth-first parallelization collects a DIFFERENT set of 15 include domains whenever the cap
 * binds — different findings, different score, silently.
 *
 * These cases pin the three things the rewrite must not move:
 *   1. findings + score, INCLUDING a tree where the cap actually binds (the case a naive
 *      rewrite breaks — see `capBindingZone`);
 *   2. the DNS query multiset (only scheduling may change);
 *   3. that a hung lookup no longer serializes its siblings, and that the check's peak
 *      in-flight lookup count does not rise above the 5 the batched code already ran at.
 *
 * Expected values were captured from the PRE-change implementation.
 *
 * Runs against the BUILT `@blackveil/dns-checks` — rebuild the package after editing its
 * source or this spec validates stale code.
 */

import { describe, it, expect } from 'vitest';
import type { DNSQueryFunction } from '@blackveil/dns-checks';

// ── Harness ──────────────────────────────────────────────────────────────────

interface ZoneEntry {
	txt?: string[];
	cname?: string[];
	ns?: string[];
	a?: string[];
}
type Zone = Record<string, ZoneEntry>;

interface ResolverOptions {
	/** Uniform per-query delay (ms). */
	delayMs?: number;
	/** Per-`TYPE:name` delay overrides (ms) — used to model one hung lookup. */
	slow?: Record<string, number>;
	/**
	 * Like `slow`, but applied ONLY to the first occurrence of the key. Phase 1 (the SPF-chain
	 * walk) and phase 2 (the per-include probe) both issue a `TXT` lookup for the same names, so
	 * an unqualified `slow` entry would be satisfied by phase 2's already-parallel batch and
	 * would not measure phase 1 at all.
	 */
	slowFirst?: Record<string, number>;
}

function makeResolver(zone: Zone, options?: ResolverOptions) {
	const calls: string[] = [];
	let inFlight = 0;
	let maxInFlight = 0;
	let maxInFlightPhase1 = 0;
	let slowInFlight = 0;
	const seen = new Set<string>();
	const startedDuringSlowLookup: string[] = [];

	const queryDNS: DNSQueryFunction = async (domain, recordType) => {
		const key = `${recordType}:${domain}`;
		const firstOccurrence = !seen.has(key);
		seen.add(key);
		// Phase 2 opens with the first CNAME lookup; everything before it is the chain walk.
		const inPhase1 = !calls.some((c) => c.startsWith('CNAME:'));
		calls.push(key);
		inFlight++;
		if (inFlight > maxInFlight) maxInFlight = inFlight;
		if (inPhase1 && inFlight > maxInFlightPhase1) maxInFlightPhase1 = inFlight;
		if (slowInFlight > 0) startedDuringSlowLookup.push(key);

		const slowMs = (options?.slow?.[key] ?? 0) || (firstOccurrence ? (options?.slowFirst?.[key] ?? 0) : 0);
		const delay = slowMs || options?.delayMs || 0;
		if (slowMs > 0) slowInFlight++;
		try {
			if (delay > 0) await new Promise((resolve) => setTimeout(resolve, delay));
		} finally {
			if (slowMs > 0) slowInFlight--;
			inFlight--;
		}

		const entry = zone[domain];
		if (!entry) return [];
		if (recordType === 'TXT') return entry.txt ?? [];
		if (recordType === 'CNAME') return entry.cname ?? [];
		if (recordType === 'NS') return entry.ns ?? [];
		if (recordType === 'A') return entry.a ?? [];
		return [];
	};

	return {
		queryDNS,
		calls,
		get maxInFlight() {
			return maxInFlight;
		},
		get maxInFlightPhase1() {
			return maxInFlightPhase1;
		},
		startedDuringSlowLookup,
	};
}

async function runCheck(zone: Zone, options?: ResolverOptions) {
	const resolver = makeResolver(zone, options);
	const { checkSubdomailing } = await import('@blackveil/dns-checks');
	const result = await checkSubdomailing('root.example', resolver.queryDNS, { timeout: 1000 });
	return { result, resolver };
}

/** Findings projected to the fields that drive the report and the score. */
function project(findings: readonly { title: string; severity: string; metadata?: Record<string, unknown> }[]) {
	return findings.map((f) => ({
		title: f.title,
		severity: f.severity,
		includeDomain: f.metadata?.includeDomain,
		riskType: f.metadata?.riskType,
	}));
}

function callCounts(calls: readonly string[]) {
	const byType: Record<string, number> = {};
	for (const call of calls) {
		const type = call.split(':')[0];
		byType[type] = (byType[type] ?? 0) + 1;
	}
	return { total: calls.length, byType };
}

// ── Zones ────────────────────────────────────────────────────────────────────

const CLEAN_SPF = 'v=spf1 ip4:203.0.113.0/24 -all';
const NS_OK = { a: ['198.51.100.1'] };
const clean = (): ZoneEntry => ({ txt: [CLEAN_SPF], ns: ['ns1.p.example.'] });

/** Nested (depth-3) tree with a void include and a dangling CNAME. The cap does NOT bind. */
const nestedZone: Zone = {
	'root.example': { txt: ['v=spf1 include:a.example include:b.example include:c.example -all'] },
	'a.example': { txt: ['v=spf1 include:a1.example include:a2.example -all'], ns: ['ns1.p.example.'] },
	'a1.example': { txt: ['v=spf1 include:a1x.example -all'], ns: ['ns1.p.example.'] },
	'a1x.example': clean(),
	'a2.example': { txt: ['not-spf'], ns: ['ns1.p.example.'] },
	'b.example': clean(),
	'c.example': { txt: [], cname: ['old-app.herokuapp.com.'] },
	'ns1.p.example': NS_OK,
};

/**
 * The crux. `MAX_INCLUDE_PROBES` binds, and DFS order and breadth-first order disagree about
 * WHICH 15 domains get collected:
 *   depth-first  → a, a1..a10, b, b1, b2, b3   (c and d are never reached)
 *   breadth-first→ a, b, c, d, a1..a10, b1     (b2/b3 never reached)
 * `c.example` carries a dangling CNAME (critical) and `b2`/`b3` are void includes (low), so the
 * two orders produce visibly different findings AND a different score. Depth-first is the
 * pre-change behaviour and the one that must survive.
 */
const capBindingZone: Zone = (() => {
	const zone: Zone = {
		'root.example': { txt: ['v=spf1 include:a.example include:b.example include:c.example include:d.example -all'] },
		'a.example': {
			txt: [`v=spf1 ${Array.from({ length: 10 }, (_, i) => `include:a${i + 1}.example`).join(' ')} -all`],
			ns: ['ns1.p.example.'],
		},
		'b.example': { txt: ['v=spf1 include:b1.example include:b2.example include:b3.example -all'], ns: ['ns1.p.example.'] },
		'c.example': { txt: [], cname: ['gone.herokuapp.com.'] },
		'd.example': clean(),
		'ns1.p.example': NS_OK,
		'b1.example': clean(),
		'b2.example': { txt: ['not-spf'], ns: ['ns1.p.example.'] },
		'b3.example': { txt: ['not-spf'], ns: ['ns1.p.example.'] },
	};
	for (let i = 1; i <= 10; i++) zone[`a${i}.example`] = clean();
	return zone;
})();

/** One include publishing four nameservers — exercises the per-NS `A` fan-out. */
const multiNsZone: Zone = {
	'root.example': { txt: ['v=spf1 include:m.example -all'] },
	'm.example': { txt: ['v=spf1 -all'], ns: ['ns1.q.example.', 'ns2.q.example.', 'ns3.q.example.', 'ns4.q.example.'] },
	'ns1.q.example': NS_OK,
	'ns2.q.example': NS_OK,
	'ns3.q.example': NS_OK,
	'ns4.q.example': NS_OK,
};

/** Wide, flat tree — 12 sibling includes, the shape serial walking punished hardest. */
const wideZone: Zone = (() => {
	const zone: Zone = {
		'root.example': { txt: [`v=spf1 ${Array.from({ length: 12 }, (_, i) => `include:w${i + 1}.example`).join(' ')} -all`] },
		'ns1.p.example': NS_OK,
	};
	for (let i = 1; i <= 12; i++) zone[`w${i}.example`] = clean();
	return zone;
})();

// ── 1. Scoring parity ────────────────────────────────────────────────────────

describe('subdomailing parallelization — scoring parity', () => {
	it('nested include tree: identical findings and score', async () => {
		const { result } = await runCheck(nestedZone);

		expect(result.score).toBe(55);
		expect(result.passed).toBe(true);
		expect(result.checkStatus).toBeUndefined();
		expect(project(result.findings)).toEqual([
			{ title: 'Void SPF include', severity: 'low', includeDomain: 'a2.example', riskType: 'void_include' },
			{
				title: 'Dangling CNAME in SPF include chain',
				severity: 'critical',
				includeDomain: 'c.example',
				riskType: 'dangling_cname',
			},
		]);
		expect(result.findings[1].metadata?.cnameTarget).toBe('old-app.herokuapp.com');
	});

	it('cap-binding tree: the DEPTH-FIRST 15 are collected, not the breadth-first 15', async () => {
		const { result } = await runCheck(capBindingZone);

		// Pre-change values. A breadth-first cap would report c.example's dangling CNAME
		// (critical) and would NOT report b2/b3 — a different score, silently.
		expect(result.score).toBe(90);
		expect(result.passed).toBe(true);
		expect(project(result.findings)).toEqual([
			{ title: 'Void SPF include', severity: 'low', includeDomain: 'b2.example', riskType: 'void_include' },
			{ title: 'Void SPF include', severity: 'low', includeDomain: 'b3.example', riskType: 'void_include' },
		]);

		// The load-bearing negative: c.example sits past the depth-first cap, so its
		// dangling CNAME is out of scope for this scan and must NOT be reported.
		expect(result.findings.some((f) => f.severity === 'critical')).toBe(false);
		expect(result.findings.some((f) => f.metadata?.includeDomain === 'c.example')).toBe(false);
	});

	it('circular include chain terminates with the same result', async () => {
		// The materialize/replay loop must not spin on a cycle: the walk's `visited` guard is
		// replayed verbatim, so `root -> a -> root` closes after one extra round.
		const circularZone: Zone = {
			'root.example': { txt: ['v=spf1 include:a.example -all'] },
			'a.example': { txt: ['v=spf1 include:root.example -all'], ns: ['ns1.p.example.'] },
			'ns1.p.example': NS_OK,
		};
		const { result, resolver } = await runCheck(circularZone);

		expect(result.score).toBe(100);
		expect(project(result.findings)).toEqual([
			{ title: 'No SubdoMailing risk detected', severity: 'info', includeDomain: undefined, riskType: undefined },
		]);
		expect(result.findings[0].metadata?.includeCount).toBe(2);
		expect(callCounts(resolver.calls)).toEqual({ total: 9, byType: { TXT: 4, CNAME: 2, NS: 2, A: 1 } });
	});

	it('multi-nameserver include: identical clean result', async () => {
		const { result } = await runCheck(multiNsZone);

		expect(result.score).toBe(100);
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].title).toMatch(/No SubdoMailing risk/i);
		expect(result.findings[0].metadata?.includeCount).toBe(1);
	});
});

// ── 2. Query-count invariance ────────────────────────────────────────────────

describe('subdomailing parallelization — query count', () => {
	it('nested tree issues exactly the pre-change queries', async () => {
		const { resolver } = await runCheck(nestedZone);
		// Pre-change: 29 lookups (12 TXT, 6 CNAME, 5 NS, 6 A).
		expect(callCounts(resolver.calls)).toEqual({ total: 29, byType: { TXT: 12, CNAME: 6, NS: 5, A: 6 } });
	});

	it('wide tree issues exactly the pre-change queries', async () => {
		const { resolver } = await runCheck(wideZone);
		// Pre-change: 61 lookups (25 TXT, 12 CNAME, 12 NS, 12 A).
		expect(callCounts(resolver.calls)).toEqual({ total: 61, byType: { TXT: 25, CNAME: 12, NS: 12, A: 12 } });
	});

	it('multi-nameserver include issues exactly the pre-change queries', async () => {
		const { resolver } = await runCheck(multiNsZone);
		expect(callCounts(resolver.calls)).toEqual({ total: 9, byType: { TXT: 3, CNAME: 1, NS: 1, A: 4 } });
	});

	it('cap-binding tree costs at most the bounded speculation, and never re-queries a domain', async () => {
		const { resolver } = await runCheck(capBindingZone);
		const counts = callCounts(resolver.calls);

		// Pre-change: 75 lookups (30 TXT). Materializing the tree level-parallel resolves the
		// root's four includes together, and two of them (c, d) turn out to sit past the cap
		// once `a`'s ten children are known — the ONLY divergence, and it is bounded by
		// SPECULATIVE_LOOKUP_BUDGET, costs 2 here, and changes no finding and no score.
		expect(counts.total).toBe(77);
		expect(counts.byType.TXT).toBe(32);
		expect(counts.byType).toMatchObject({ CNAME: 15, NS: 15, A: 15 });

		// Phase 1 must still resolve each domain's SPF adjacency at most once.
		const phase1Txt = resolver.calls.slice(0, resolver.calls.indexOf('CNAME:a.example')).filter((c) => c.startsWith('TXT:'));
		expect(new Set(phase1Txt).size).toBe(phase1Txt.length);
	});
});

// ── 3. Scheduling: no serialization, no extra contention ─────────────────────

describe('subdomailing parallelization — scheduling', () => {
	it('a hung chain lookup no longer blocks its siblings', async () => {
		// `w1.example`'s CHAIN-WALK TXT lookup hangs (first occurrence only — phase 2 re-queries
		// the same name and was already batched). Pre-change the walk was strictly serial, so
		// ZERO other lookups could start while it was in flight: every one of the 11 siblings
		// waited it out, and at a real 3s resolver timeout + 1 retry that is ~6.5s of the 8s
		// per-check budget spent on one name.
		const { resolver } = await runCheck(wideZone, { delayMs: 1, slowFirst: { 'TXT:w1.example': 120 } });

		expect(resolver.startedDuringSlowLookup.length).toBeGreaterThanOrEqual(3);
		expect(resolver.maxInFlightPhase1).toBeGreaterThan(1);
	});

	it('peak in-flight lookups stay within the 5 the batched implementation already used', async () => {
		const { resolver } = await runCheck(wideZone, { delayMs: 2 });

		// Phase 1 is pooled at 4 and phase 2 is gated at 5 across BOTH its per-domain fan-out
		// and the per-NS fan-out nested inside it, so the check never claims more of the
		// scan-wide SCAN_DNS_CONCURRENCY=12 budget than it did before. Nested pools would have
		// multiplied (5 x 4 = 20) — this is the guard against that.
		expect(resolver.maxInFlight).toBeLessThanOrEqual(5);
		expect(resolver.maxInFlightPhase1).toBeLessThanOrEqual(4);
		// ...and it is genuinely running in parallel, not accidentally serialized.
		expect(resolver.maxInFlightPhase1).toBeGreaterThan(1);
	});

	it('the per-NS fan-out is bounded and order-preserving', async () => {
		// All four nameservers dangle: the detail string joins them in NS-record order, which
		// index-ordered writeback must preserve regardless of which lookup settles first.
		const zone: Zone = {
			...multiNsZone,
			'ns1.q.example': {},
			'ns2.q.example': {},
			'ns3.q.example': {},
			'ns4.q.example': {},
		};
		const { result, resolver } = await runCheck(zone, { delayMs: 1, slow: { 'A:ns1.q.example': 40 } });

		const dangling = result.findings.find((f) => f.metadata?.riskType === 'dangling_ns');
		expect(dangling).toBeDefined();
		expect(dangling!.metadata?.nsTargets).toEqual(['ns1.q.example', 'ns2.q.example', 'ns3.q.example', 'ns4.q.example']);
		expect(dangling!.detail).toContain('ns1.q.example, ns2.q.example, ns3.q.example, ns4.q.example');
		expect(resolver.maxInFlight).toBeLessThanOrEqual(5);
	});
});
