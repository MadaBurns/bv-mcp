// SPDX-License-Identifier: BUSL-1.1

/**
 * SubdoMailing analysis helpers.
 * Detects SPF include/redirect domains vulnerable to takeover via
 * dangling CNAME, hijackable NS delegation, or expired/parked domains.
 *
 * Reference: Guardio Labs SubdoMailing report (Feb 2024).
 *
 * Both phases schedule their DNS lookups through a bounded pool — see
 * `CHAIN_LOOKUP_CONCURRENCY` / `PROBE_CONCURRENCY`. The SAME queries are issued
 * and the SAME findings/score are produced; only the scheduling changes.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { DNSQueryFunction, Finding, Severity } from '../types';
import { createFinding } from '../check-utils';
import { isThirdPartyTakeoverService } from './subdomain-takeover-analysis';
import { extractLookupDomains } from './spf-analysis';

/** Maximum number of include domains to probe (latency cap). */
export const MAX_INCLUDE_PROBES = 15;

/** Maximum SPF include recursion depth. */
const MAX_RECURSION_DEPTH = 3;

/** Per-domain probe timeout (ms). */
const PROBE_TIMEOUT_MS = 3_000;

/**
 * Max TXT lookups the SPF-chain materialization (phase 1) keeps in flight.
 *
 * Phase 1 walks the SPF include tree, which is intrinsically a DFS: `MAX_INCLUDE_PROBES`
 * is applied MID-ITERATION in DFS order, so which 15 domains get collected — and therefore
 * which findings and which score come out — depends on that order. Walking it serially cost
 * 1–16 back-to-back TXT round-trips; at the resolver's 3s timeout + 1 retry, ONE hung lookup
 * costs ~6.5s on its own and blocks every sibling behind it, blowing the 8s per-check budget
 * regardless of how fast the rest were (#674, the same failure shape as the `ptr` timeout in
 * #641). Materializing the tree level-parallel collapses that to ~4 rounds.
 *
 * **Why 4, and why bounded at all.** Inside `scan_domain` this composes with the scan-wide
 * `Semaphore(SCAN_DNS_CONCURRENCY = 12)` shared across all 19 concurrent categories, and
 * those permits are zero-sum: a wider pool here would claim a larger share of the whole scan's
 * DoH budget for a weight-3 *protective* category while `dmarc` (core, 16) and `spf` (core, 10)
 * queue behind it. 4 matches `check_ptr`'s `PTR_LOOKUP_CONCURRENCY` and stays under the 5-wide
 * batch that phase 2 already ran at, so the check's PEAK in-flight lookup count does not rise.
 * On a DIRECT `check_subdomailing` call there is no such semaphore, which is why the bound
 * lives here rather than being left to the caller. Raising `SCAN_DNS_CONCURRENCY` instead is
 * NOT the fix — it re-times every check and pushes peak subrequests toward the Free-plan
 * 50-per-invocation ceiling; that is a measured operator decision, not a side effect.
 */
const CHAIN_LOOKUP_CONCURRENCY = 4;

/**
 * Max DNS lookups the probe phase (phase 2) keeps in flight — counted ACROSS the per-domain
 * fan-out and the per-NS fan-out nested inside it, because they are gated by one shared
 * counter rather than by nested pools (nested pools would multiply: 5 x 4 = 20 in flight).
 *
 * Deliberately 5: the exact width of the fixed-size `Promise.allSettled` batches this replaced,
 * so phase 2's peak subrequest pressure is UNCHANGED. What changes is the barrier — a batch
 * made every domain wait for the slowest member of its batch before the next batch started, so
 * one 6.5s hang stalled all remaining domains. Gating instead of batching lets a finished worker
 * pick up the next domain immediately, and folds the per-NS A lookups into the same budget.
 */
const PROBE_CONCURRENCY = 5;

/**
 * Max per-NS `A` lookups a single `probeIncludeDomain` call issues at once.
 *
 * Only binds on a DIRECT call to the exported `probeIncludeDomain`; under `probeAllIncludes`
 * the shared `PROBE_CONCURRENCY` gate is the tighter constraint.
 */
const NS_LOOKUP_CONCURRENCY = 4;

/**
 * How many *extra* TXT lookups phase 1 may spend on speculation before it degrades to the
 * strictly serial walk.
 *
 * Each materialization round resolves the frontier the in-memory replay actually asked for.
 * The FIRST unknown in that frontier is always genuinely needed (everything before it is
 * already known and replayed identically to the serial walk), so it is never charged here;
 * only the siblings resolved alongside it are speculative, and a sibling is wasted only when
 * an earlier unknown turns out to have children that consume the `MAX_INCLUDE_PROBES` headroom
 * first. Because the replay applies the cap while it walks, that is rare — on the shapes
 * measured for #674 the speculative cost was 0. When the budget IS exhausted the loop keeps
 * running at width 1, which IS the pre-change serial DFS, so the fallback cannot diverge: it
 * is the same code path, not a second implementation. Total lookups are therefore bounded by
 * `serial count + SPECULATIVE_LOOKUP_BUDGET`.
 */
const SPECULATIVE_LOOKUP_BUDGET = 1 + MAX_INCLUDE_PROBES;

export type SubdomailingRiskType = 'dangling_cname' | 'dangling_ns' | 'expired_domain' | 'void_include';

export interface SubdomailingProbeResult {
	domain: string;
	mechanism: string;
	riskType: SubdomailingRiskType | null;
	severity: Severity;
	cnameTarget?: string;
	nsTargets?: string[];
	takeoverService?: string;
	detail: string;
	/**
	 * True when at least one of this domain's takeover-relevant DNS lookups (the CNAME-target
	 * `A` lookup, an `A` lookup in the NS-host fan-out, or the TXT lookup) THREW rather than
	 * answering, and no positive risk finding was otherwise determined. Only an ANSWERED-EMPTY
	 * lookup is evidence of non-resolution (#1103); a throw means this domain could not be
	 * fully cleared, so callers must not count it toward "resolves correctly".
	 */
	unmeasured?: true;
}

/**
 * Run `fn` over `items` with at most `limit` in flight, writing results back BY INDEX.
 *
 * A verbatim local copy of `src/lib/map-concurrent.ts`: this package is the runtime-agnostic
 * core and must not import from the Worker tree, so the idiom is duplicated rather than shared.
 */
async function mapConcurrent<T, R>(items: readonly T[], limit: number, fn: (item: T, index: number) => Promise<R>): Promise<R[]> {
	const out: R[] = new Array(items.length);
	let next = 0;
	const workerCount = Math.max(1, Math.min(Number.isFinite(limit) ? Math.floor(limit) : 1, items.length));

	async function worker(): Promise<void> {
		while (true) {
			const index = next++;
			if (index >= items.length) return;
			out[index] = await fn(items[index], index);
		}
	}

	await Promise.all(Array.from({ length: workerCount }, () => worker()));
	return out;
}

/**
 * Wrap a `DNSQueryFunction` so at most `limit` calls are in flight at once, however many
 * nested fan-outs sit above it. A permit is handed straight to the next waiter on release
 * (rather than decremented and re-acquired), so the ceiling can never be overshot by a caller
 * that slips in between the release and the waiter resuming.
 */
function gateQueries(queryDNS: DNSQueryFunction, limit: number): DNSQueryFunction {
	let active = 0;
	const waiting: Array<() => void> = [];

	return async (domain, recordType, options) => {
		if (active < limit) {
			active++;
		} else {
			await new Promise<void>((resolve) => waiting.push(resolve));
		}
		try {
			return await queryDNS(domain, recordType, options);
		} finally {
			const next = waiting.shift();
			if (next) next();
			else active--;
		}
	};
}

/** One domain's SPF adjacency: the record it publishes and the lookup domains that record names. */
interface SpfNode {
	spfRecord: string;
	includes: string[];
	redirect?: string;
}

/**
 * Resolve one domain's SPF adjacency.
 *
 * For an INCLUDED domain this is TOTAL — never throws: collapsing "the TXT query threw" and "no
 * SPF record present" into a single `null` matches the serial walk exactly (both made it
 * `return` without recursing), and the include itself is still probed — with its own
 * unmeasured accounting (#1103) — by `probeIncludeDomain`.
 *
 * For the ROOT (`propagateFailure`), a thrown TXT lookup is re-thrown. Collapsed to `null` it
 * read as "the domain publishes no SPF record", so a probe that never reached a resolver
 * returned a COMPLETED "No SPF record" verdict scored 100 (SQ-201). Re-thrown, it reaches
 * `checkSubdomailing`'s not-assessed catch instead. An answered-empty or NXDOMAIN root lookup
 * does not throw, so a genuinely SPF-less domain still reads as "No SPF record".
 */
async function resolveSpfNode(
	domain: string,
	queryDNS: DNSQueryFunction,
	timeout: number,
	propagateFailure = false,
): Promise<SpfNode | null> {
	let txtRecords: string[];
	try {
		txtRecords = await queryDNS(domain, 'TXT', { timeout });
	} catch (err) {
		if (propagateFailure) throw err;
		return null;
	}

	const spfRecord = txtRecords.find((r) => r.trimStart().startsWith('v=spf1'));
	if (!spfRecord) return null;

	return { spfRecord, ...extractLookupDomains(spfRecord) };
}

interface ReplayResult {
	domains: Map<string, string>;
	spfRecord: string | null;
	/** Domains the walk reached whose adjacency is not in the map yet, in DFS-visit order. */
	unresolved: string[];
}

/**
 * Replay the include walk PURELY IN MEMORY over a (possibly partial) adjacency map.
 *
 * This is the original depth-first walk with its network step removed — same visit order, same
 * `MAX_INCLUDE_PROBES` test in the same mid-iteration position, same `visited` short-circuit.
 * That is the whole point: `MAX_INCLUDE_PROBES` is applied in DFS order, so a breadth-first
 * rewrite would collect a DIFFERENT set of 15 domains whenever the cap binds, and therefore
 * emit different findings and a different score. Keeping the cap in a replay of the original
 * order makes that class of divergence structurally impossible.
 *
 * A domain missing from `adjacency` is treated as a childless leaf and recorded in `unresolved`.
 * Because a leaf consumes exactly one cap slot and can never consume more, that assumption makes
 * the cap bind no EARLIER than the truth, so the replayed visit set is always a SUPERSET of the
 * true one — sound for choosing what to fetch next. Its output is only ever used once
 * `unresolved` is empty, i.e. once the adjacency is complete for everything the walk touched.
 */
function replayIncludeWalk(domain: string, adjacency: ReadonlyMap<string, SpfNode | null>): ReplayResult {
	const collected = new Map<string, string>(); // domain → mechanism (e.g., "include:spf.example.com")
	const visited = new Set<string>();
	const unresolved: string[] = [];

	let rootSpf: string | null = null;

	function resolve(d: string, depth: number): void {
		if (depth > MAX_RECURSION_DEPTH || collected.size >= MAX_INCLUDE_PROBES) return;
		const normalized = d.toLowerCase();
		if (visited.has(normalized)) return;
		visited.add(normalized);

		if (!adjacency.has(normalized)) {
			unresolved.push(normalized);
			return;
		}

		const node = adjacency.get(normalized);
		if (!node) return;

		if (depth === 0) rootSpf = node.spfRecord;

		for (const inc of node.includes) {
			if (collected.size >= MAX_INCLUDE_PROBES) break;
			if (!collected.has(inc)) {
				collected.set(inc, `include:${inc}`);
			}
			resolve(inc, depth + 1);
		}

		if (node.redirect && !collected.has(node.redirect) && collected.size < MAX_INCLUDE_PROBES) {
			collected.set(node.redirect, `redirect=${node.redirect}`);
			resolve(node.redirect, depth + 1);
		}
	}

	resolve(domain, 0);
	return { domains: collected, spfRecord: rootSpf, unresolved };
}

/**
 * Recursively extract all include/redirect domains from an SPF record chain.
 * Capped at MAX_RECURSION_DEPTH and MAX_INCLUDE_PROBES total domains.
 *
 * Two passes: materialize the include tree with bounded parallelism, then replay the original
 * depth-first walk over it in memory. The walk's ONLY network dependence is "which lookup
 * domains does D publish", so materializing that answer first lets the cap be applied in the
 * original DFS order — identical `domains` map, identical `spfRecord`, identical findings and
 * score for any given DNS state.
 *
 * Each round resolves exactly the frontier the replay asked for, in parallel, so a tree of
 * depth d converges in d+1 rounds instead of one round-trip per domain. Rounds are bounded:
 * with the speculative budget available a round advances a whole depth level (at most
 * `MAX_RECURSION_DEPTH + 2` rounds); once it is spent a round still resolves at least the one
 * domain the walk provably needs next, and the walk visits at most `1 + MAX_INCLUDE_PROBES`
 * domains, so the loop always terminates.
 *
 * Throws when the ROOT domain's own TXT lookup throws (see `resolveSpfNode`): with no answer for
 * the root there is no chain to report, and `spfRecord: null` would claim a measured absence.
 */
export async function extractSpfIncludeChain(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number },
): Promise<{ domains: Map<string, string>; spfRecord: string | null }> {
	const timeout = options?.timeout ?? PROBE_TIMEOUT_MS;
	const adjacency = new Map<string, SpfNode | null>();
	let speculationBudget = SPECULATIVE_LOOKUP_BUDGET;
	// The replay records domains lowercased, so this is the root's key in `frontier`.
	const root = domain.toLowerCase();

	for (;;) {
		const replay = replayIncludeWalk(domain, adjacency);
		if (replay.unresolved.length === 0) {
			return { domains: replay.domains, spfRecord: replay.spfRecord };
		}

		// `unresolved[0]` is never speculative — everything the replay did before reaching it
		// used known-correct adjacency, so the serial walk would have queried it too. Only the
		// siblings taken alongside it are charged, and once the budget is gone the width drops
		// to 1, which is precisely the pre-change serial walk.
		const width = speculationBudget > 0 ? Math.min(replay.unresolved.length, 1 + speculationBudget) : 1;
		const frontier = replay.unresolved.slice(0, width);
		speculationBudget -= frontier.length - 1;

		const nodes = await mapConcurrent(frontier, CHAIN_LOOKUP_CONCURRENCY, (d) => resolveSpfNode(d, queryDNS, timeout, d === root));
		frontier.forEach((d, index) => adjacency.set(d, nodes[index]));
	}
}

/**
 * Probe a single SPF include domain for SubdoMailing risk indicators.
 *
 * Checks (in order):
 * 1. CNAME → dangling CNAME to a known takeover service
 * 2. NS → unresolvable nameserver targets (NS delegation hijack)
 * 3. TXT → void include (no SPF record on the included domain)
 *
 * The three steps stay STRICTLY SEQUENTIAL: each one can return early, so running them
 * concurrently would issue lookups the current code never makes. Only the per-NS `A` lookups
 * inside step 2 — a pure independent fan-out — are pooled.
 */
export async function probeIncludeDomain(
	includeDomain: string,
	mechanism: string,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number },
): Promise<SubdomailingProbeResult> {
	const timeout = options?.timeout ?? PROBE_TIMEOUT_MS;
	const base: Omit<SubdomailingProbeResult, 'riskType' | 'severity' | 'detail' | 'unmeasured'> = {
		domain: includeDomain,
		mechanism,
	};

	// Set when a takeover-relevant lookup THREW rather than answering, so evidence for that
	// vector is missing. Only an ANSWERED-EMPTY (`[]`) result is evidence of non-resolution
	// (#1103) — a throw is never used to infer or rule out a finding on its own. A later step
	// finding a genuine (answered) risk still returns that finding regardless of this flag:
	// positive evidence stands even when a sibling probe was inconclusive.
	let unmeasured = false;

	// ── 1. CNAME probe ──────────────────────────────────────────────────────
	try {
		const cnameRecords = await queryDNS(includeDomain, 'CNAME', { timeout });
		if (cnameRecords.length > 0) {
			const cname = cnameRecords[0].replace(/\.$/, '').toLowerCase();

			if (isThirdPartyTakeoverService(cname)) {
				// Check if the CNAME target actually resolves. A throw here is UNMEASURED, not
				// "does not resolve" — never guess a dangling CNAME from the CNAME alone (#1103).
				let resolves = false;
				let targetUnmeasured = false;
				try {
					const aRecords = await queryDNS(cname, 'A', { timeout });
					resolves = aRecords.length > 0;
				} catch {
					targetUnmeasured = true;
				}

				if (targetUnmeasured) {
					unmeasured = true;
				} else if (!resolves) {
					return {
						...base,
						riskType: 'dangling_cname',
						severity: 'critical',
						cnameTarget: cname,
						takeoverService: cname,
						detail: `SPF ${mechanism} points to ${includeDomain} which has a dangling CNAME to ${cname}. An attacker could claim this resource and send authenticated email as the target domain.`,
					};
				}
			}
		}
	} catch {
		// CNAME query failure — continue to NS check
	}

	// ── 2. NS delegation probe ──────────────────────────────────────────────
	try {
		const nsRecords = await queryDNS(includeDomain, 'NS', { timeout });
		if (nsRecords.length > 0) {
			const nsHosts = nsRecords.map((ns) => ns.replace(/\.$/, '').toLowerCase());

			// One `A` lookup per nameserver, independent of each other. Written back BY INDEX so
			// `danglingNs` keeps NS-record order exactly as the serial loop produced it. A thrown
			// lookup is UNMEASURED, not dangling (#1103) — `dangling_ns` is only ever emitted for
			// hosts whose `A` lookup ANSWERED empty. If every candidate threw, there is no finding
			// for this step at all, just an unmeasured domain.
			const outcomes = await mapConcurrent(nsHosts, NS_LOOKUP_CONCURRENCY, async (nsHost): Promise<'dangling' | 'resolves' | 'unmeasured'> => {
				try {
					const aRecords = await queryDNS(nsHost, 'A', { timeout });
					return aRecords.length === 0 ? 'dangling' : 'resolves';
				} catch {
					return 'unmeasured';
				}
			});
			const danglingNs = nsHosts.filter((_, index) => outcomes[index] === 'dangling');

			if (danglingNs.length > 0) {
				return {
					...base,
					riskType: 'dangling_ns',
					severity: 'high',
					nsTargets: danglingNs,
					detail: `SPF ${mechanism} points to ${includeDomain} whose nameserver(s) do not resolve: ${danglingNs.join(', ')}. An attacker could register these NS targets and control the SPF authorization for the domain.`,
				};
			}

			if (outcomes.some((outcome) => outcome === 'unmeasured')) {
				unmeasured = true;
			}
		}
	} catch {
		// NS query failure — continue to TXT check
	}

	// ── 3. Void include (no SPF record) ─────────────────────────────────────
	try {
		const txtRecords = await queryDNS(includeDomain, 'TXT', { timeout });
		const hasSpf = txtRecords.some((r) => r.trimStart().startsWith('v=spf1'));
		if (!hasSpf) {
			return {
				...base,
				riskType: 'void_include',
				severity: 'low',
				detail: `SPF ${mechanism} points to ${includeDomain} which has no SPF record. This wastes a DNS lookup and could become exploitable if the domain is abandoned.`,
			};
		}
	} catch {
		// TXT query threw — UNMEASURED, not void_include (#1103): we never learned whether the
		// include publishes SPF, so this cannot be recorded as "no SPF record".
		unmeasured = true;
	}

	if (unmeasured) {
		return {
			...base,
			riskType: null,
			severity: 'info',
			unmeasured: true,
			detail: `SPF ${mechanism} points to ${includeDomain} — one or more DNS lookups could not be queried, so this include could not be fully assessed. This is not evidence that it is safe.`,
		};
	}

	// All clean
	return {
		...base,
		riskType: null,
		severity: 'info',
		detail: `SPF ${mechanism} points to ${includeDomain} — no takeover risk detected.`,
	};
}

/** Result of probing every SPF include/redirect domain in a chain. */
export interface SubdomailingProbeSummary {
	findings: Finding[];
	/** Total include domains probed. */
	probedCount: number;
	/**
	 * How many of those probes could not be fully assessed (`SubdomailingProbeResult.unmeasured`)
	 * because a takeover-relevant DNS lookup threw. Lets the caller disclose partial coverage
	 * instead of claiming every include "resolves correctly" (#1103).
	 */
	unmeasuredCount: number;
}

/**
 * Probe all include domains through a bounded query gate.
 * Returns findings for any domains with detected risks, plus how many domains were probed
 * and how many of those could not be fully assessed.
 *
 * Every domain is dispatched at once and the `PROBE_CONCURRENCY` gate — not a batch boundary —
 * is what bounds the DNS lookups, so a domain that hangs occupies one permit instead of
 * stalling the whole remaining batch. Results are consumed in INDEX order, so the findings
 * array is ordered exactly as the sequential batches produced it.
 */
export async function probeAllIncludes(
	includes: Map<string, string>,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number },
): Promise<SubdomailingProbeSummary> {
	const findings: Finding[] = [];
	const entries = Array.from(includes.entries());
	const gatedQuery = gateQueries(queryDNS, PROBE_CONCURRENCY);

	const results = await Promise.allSettled(entries.map(([domain, mechanism]) => probeIncludeDomain(domain, mechanism, gatedQuery, options)));

	let unmeasuredCount = 0;
	for (const result of results) {
		if (result.status !== 'fulfilled') continue;
		const probe = result.value;
		if (probe.unmeasured) unmeasuredCount++;
		if (probe.riskType === null) continue;

		findings.push(
			createFinding('subdomailing', titleForRisk(probe.riskType), probe.severity, probe.detail, {
				includeDomain: probe.domain,
				mechanism: probe.mechanism,
				riskType: probe.riskType,
				...(probe.cnameTarget ? { cnameTarget: probe.cnameTarget } : {}),
				...(probe.nsTargets ? { nsTargets: probe.nsTargets } : {}),
				...(probe.takeoverService ? { takeoverService: probe.takeoverService } : {}),
			}),
		);
	}

	return { findings, probedCount: entries.length, unmeasuredCount };
}

function titleForRisk(riskType: SubdomailingRiskType): string {
	switch (riskType) {
		case 'dangling_cname':
			return 'Dangling CNAME in SPF include chain';
		case 'dangling_ns':
			return 'Dangling NS delegation in SPF include chain';
		case 'expired_domain':
			return 'Expired domain in SPF include chain';
		case 'void_include':
			return 'Void SPF include';
	}
}
