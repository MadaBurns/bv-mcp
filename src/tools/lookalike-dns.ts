// SPDX-License-Identifier: BUSL-1.1

/**
 * DNS resolution layer for the lookalike check.
 *
 * Extracted from `check-lookalikes.ts`: everything here is the "does this
 * candidate exist, and what infrastructure does it carry" question — NS
 * existence filtering, the wildcard-parent canary probe, the adaptive-batching
 * A/MX detail probe, and the two seed-side queries (`NS` for the ownership
 * verdict, `MX` for the D4 overlap corroboration signal).
 *
 * Nothing in this module builds a Finding, decides a severity, or makes an
 * ownership claim — it only measures. The tuning constants live here rather
 * than in the orchestrator because they are properties of the query plane, and
 * `test/check-lookalikes.spec.ts` pins their exact values through the tool's
 * re-export.
 *
 * ⚠️ FAN-OUT IS BOUNDED, AND THE BOUND IS THE PLATFORM'S (#865 — the DNS half
 * of #867). A Worker invocation may hold at most SIX connections simultaneously
 * (developers.cloudflare.com/workers/platform/limits/#simultaneous-open-connections);
 * further `fetch()` calls QUEUE, with whatever timer the caller armed already
 * running. Phase 1 used to dispatch every permutation's NS query at once
 * (`Promise.allSettled(domains.map(...))`, ~90 fetches) and the detail probe
 * 20 A/MX queries per batch, each arming `AbortSignal.timeout` at call time.
 * Any permutation whose authoritative servers are lame or slow then holds its
 * slot for the WHOLE timer window, so a handful of them parks every slot and
 * the queue behind them aborts before a single byte is sent — and the tool
 * reports the names it never asked about as "DNS timeout or rate limiting".
 *
 * Measured 2026-09-04: openai.com has 11 of 90 permutations whose NS lookup
 * hangs to the 2s timer even when queried ALONE. Replaying the measured
 * per-name latencies through a six-slot FIFO with pre-armed timers predicts
 * 70 unresolved; production reported 76 (#865: 77). The same code on an
 * uncapped local workerd against the same resolver: 12 unresolved, 54
 * candidates. Ninety simultaneous queries from Node: zero HTTP 429. The
 * resolver was never refusing the burst; the platform queue was — and #892's
 * rollup then abstained at ≥ 50% unresolved, an abstention the tool inflicted
 * on itself.
 *
 * Every DoH fan-out here now runs through a {@link LOOKALIKE_DNS_PROBE_CONCURRENCY}-
 * wide pool, arms its timers when the query is actually dispatched, and is
 * cut by a per-phase deadline whose victims are COUNTED, with a reason — never
 * dropped, never recorded as "no NS". Do not re-introduce a
 * `domains.map(queryDns...)` fan-out anywhere in this module.
 */

import { DnsQueryError, queryDnsRecords, queryMxRecords, queryTxtRecords } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import { mapConcurrent } from '../lib/map-concurrent';
import { isInBailiwick, parseDmarcReportReceivers, type DmarcReportAuthorisation } from '../lib/ownership-attribution';
import { getRegistrableDomain } from '../lib/public-suffix';

/** Default and minimum batch sizes for adaptive batching */
export const INITIAL_BATCH_SIZE = 10;
export const MIN_BATCH_SIZE = 3;
export const BACKOFF_DELAY_MS = 500;
export const FAILURE_THRESHOLD = 2;

/** Canary label used for wildcard detection on parent domains */
export const WILDCARD_CANARY_LABEL = '_bv-wc-probe';

/** Lean DNS options for Phase 1 existence checks — fast, no retries, no secondary confirmation. */
export const PHASE1_DNS_OPTS: QueryDnsOptions = {
	timeoutMs: 2000,
	retries: 0,
	skipSecondaryConfirmation: true,
};

/**
 * DNS options for the Phase 2 A/MX legs of a REGISTERED candidate. The default
 * per-attempt timer and the secondary-resolver confirmation on an empty answer
 * are kept (an empty A/MX is a measurement, and it is worth confirming), but
 * there is NO retry: a candidate whose NS answered from the parent zone while
 * its own servers are lame hangs BOTH legs, and with the default single retry
 * each leg held one of the six connection slots for 3s + 3s. Eleven such
 * candidates in a 54-candidate seed (openai.com, measured) spent the whole
 * phase budget on names that were never going to answer, and the budget cuts
 * landed on candidates that would have. #853's case for retries is the SEED's
 * lookups, which gate every verdict; a candidate leg is one disposable
 * permutation and its failure is COUNTED (`probeDegradedReason`), not lost.
 */
export const PHASE2_DNS_OPTS: QueryDnsOptions = {
	retries: 0,
};

/**
 * Width of every DoH pool in this module, counted in QUERIES in flight (not
 * candidates): the Workers simultaneous-open-connection cap is six, and the
 * DNS phases run alone — phase 0 (seed NS/MX) is awaited before phase 1, the
 * detail probe follows phase 1, enrichment (`lookalike-enrichment.ts`, whose
 * two pools also sum to six) follows the detail probe — so each phase owns
 * the whole budget. Retries and the secondary-resolver confirmation happen
 * SEQUENTIALLY inside one query, so a pooled query never holds more than one
 * connection. Not `SCAN_DNS_CONCURRENCY` (12): `check_lookalikes` is
 * `scanIncluded: false` and never competes with a scan.
 *
 * Do not widen past six: `test/check-lookalikes-dns-starvation.spec.ts` runs
 * the pool against an emulated six-slot runtime and turns red the moment
 * anything queues.
 */
export const LOOKALIKE_DNS_PROBE_CONCURRENCY = 6;

/**
 * Why a DNS probe did not produce a measurement.
 *
 *  - `timeout`  — the resolver never answered within the per-query timer
 *                 (`PHASE1_DNS_OPTS.timeoutMs` / `DNS_TIMEOUT_MS`), the query
 *                 having been dispatched with a free connection slot.
 *  - `deadline` — the phase deadline cut it: either its turn came after the
 *                 deadline (never issued) or it was aborted mid-flight.
 *  - `failed`   — transport error, non-2xx DoH response, or unparseable body.
 *
 * Reported per phase so a consumer can tell "the resolver is slow for these
 * names" from "this run was budget-cut" — the two need different responses
 * (re-run vs. nothing to do) and #865's rollup abstention hides the difference.
 */
export type DnsProbeFailureReason = 'timeout' | 'deadline' | 'failed';

/** Per-reason tally of unresolved probes for one phase. */
export type UnresolvedByReason = Record<DnsProbeFailureReason, number>;

/** A zeroed {@link UnresolvedByReason}. */
export function emptyUnresolvedByReason(): UnresolvedByReason {
	return { timeout: 0, deadline: 0, failed: 0 };
}

export interface DnsPhaseOptions {
	/**
	 * Wall-clock deadline (epoch ms) for the phase. A query whose turn comes
	 * after it is NOT issued (`deadline`); a query dispatched before it carries
	 * a caller-abort signal armed at dispatch, so the deadline bounds the whole
	 * query including retries and secondary confirmation. Absent → each query
	 * gets its full per-query budget (direct callers).
	 */
	deadlineMs?: number;
}

/** Milliseconds left before `deadlineMs`; +Infinity when there is no deadline. */
function remainingMs(deadlineMs: number | undefined): number {
	return typeof deadlineMs === 'number' ? deadlineMs - Date.now() : Number.POSITIVE_INFINITY;
}

/**
 * Caller-abort signal for ONE dispatched query, armed HERE — inside a pool
 * worker, once a connection slot is free — never at enqueue. The transport
 * composes it with its own per-attempt timer (`AbortSignal.any`) and a caller
 * abort short-circuits its retry loop. `undefined` when there is no deadline.
 */
function deadlineSignal(deadlineMs: number | undefined): AbortSignal | undefined {
	if (typeof deadlineMs !== 'number') return undefined;
	return AbortSignal.timeout(Math.max(1, deadlineMs - Date.now()));
}

/**
 * Classify a rejected query. The deadline signal is authoritative: a query it
 * aborted is a budget cut, whatever the transport called it. A per-attempt
 * timer expiry surfaces as `DNS query timed out after Nms` OR — because
 * `AbortSignal.timeout()` rejects with a `TimeoutError`, not the `AbortError`
 * the transport's retry branch tests for — as `DNS query failed: The operation
 * was aborted due to timeout`; both are the resolver not answering.
 */
function classifyDnsFailure(err: unknown, deadline: AbortSignal | undefined): DnsProbeFailureReason {
	if (deadline?.aborted) return 'deadline';
	if (err instanceof DnsQueryError && /timed out|timeout/i.test(err.message)) return 'timeout';
	return 'failed';
}

/** The "never measured" candidate shape: no positive signal, no measured absence, and the reason it is neither. */
function unmeasuredResult(domain: string, reason: DnsProbeFailureReason): LookalikeResult {
	return { domain, hasA: false, hasMX: false, mxExchanges: [], probeDegraded: true, probeDegradedReason: reason };
}

/**
 * Resilient DNS options for the SEED domain's own NS/MX lookups (#853).
 *
 * The blast radius is what separates these from `PHASE1_DNS_OPTS`, not the
 * record type. A dropped CANDIDATE probe costs one disposable permutation out
 * of ~66. A dropped SEED NS probe voids EVERY ownership verdict in the run —
 * all candidates degrade to `unmeasured` and impersonation-shaped findings are
 * withheld wholesale — so the lean no-retry preset was being applied to the one
 * query that could least afford to lose. Two extra queries with retries; they
 * gate the interpretive value of all the others.
 */
export const SEED_DNS_OPTS: QueryDnsOptions = {
	timeoutMs: 5000,
	retries: 2,
	skipSecondaryConfirmation: true,
};

export interface LookalikeResult {
	domain: string;
	hasA: boolean;
	hasMX: boolean;
	/** MX exchange hosts (lowercased, trailing-dot-stripped) — empty when no real MX. */
	mxExchanges: string[];
	/**
	 * True when the A or MX lookup for this candidate REJECTED (timeout /
	 * throttling), so the corresponding `false` above is UNFETCHED, not
	 * measured (#831/#832). A candidate with no positive signal and a degraded
	 * probe must never be reported as "registered but dark" — that would
	 * compile a non-answer into a custody record.
	 */
	probeDegraded: boolean;
	/** Why the probe is degraded (present iff `probeDegraded`). See {@link DnsProbeFailureReason}. */
	probeDegradedReason?: DnsProbeFailureReason;
}

/**
 * Check whether an MX record represents real mail infrastructure.
 *
 * RFC 7505 defines the canonical null MX as priority-0 with exchange `.` (root),
 * meaning "this domain does not accept mail". A legacy convention used by some
 * operators is `0 localhost.` (or `0 localhost`), which has the same intent —
 * mail is null-routed to the sender's own localhost and is functionally rejected.
 * Both patterns must be excluded from the "has mail infrastructure" signal to
 * avoid false-positive HIGH typosquat findings on domains that have applied the
 * recommended anti-spoofing posture.
 */
function isRealMxRecord(data: string): boolean {
	const trimmed = data.trim().toLowerCase();
	// Format from queryDnsRecords is "<priority> <target>", possibly with trailing dot.
	const match = trimmed.match(/^(\d+)[\s\t]+(.*?)\.?$/);
	if (!match) return true;
	const [, priority, target] = match;
	if (priority !== '0') return true;
	return target !== '' && target !== 'localhost';
}

/**
 * Extract the lowercase exchange host from an MX record `"<priority> <target>"`.
 * Returns `null` when the record fails to parse or is a null MX. Used to feed
 * the disposable-MX detector in `calibrateLookalikeSeverity`.
 */
function extractMxExchange(raw: string): string | null {
	const trimmed = raw.trim().toLowerCase();
	const match = trimmed.match(/^(\d+)[\s\t]+(.*?)\.?$/);
	if (!match) return null;
	const [, , target] = match;
	if (target === '' || target === 'localhost') return null;
	return target;
}

/** One leg of a candidate's detail probe, as the pool sees it. */
type DetailLegOutcome = { ok: true; records: string[] } | { ok: false; reason: DnsProbeFailureReason };

/** Worst-first precedence when both legs of a candidate degraded: a budget cut outranks a resolver timeout outranks a transport failure. */
function worstReason(a: DnsProbeFailureReason | undefined, b: DnsProbeFailureReason | undefined): DnsProbeFailureReason | undefined {
	const rank: Record<DnsProbeFailureReason, number> = { deadline: 3, timeout: 2, failed: 1 };
	if (!a) return b;
	if (!b) return a;
	return rank[a] >= rank[b] ? a : b;
}

/**
 * Detail-probe one batch of registered candidates: A + MX per candidate,
 * flattened to individual queries and run through the connection-cap pool
 * (two candidate legs are independent, so flattening keeps every slot busy
 * where a per-candidate pool of three would idle one whenever the legs finish
 * apart). Filters out null MX records (RFC 7505) to avoid false positives.
 *
 * Both legs run on {@link PHASE2_DNS_OPTS}: the default per-attempt timer and
 * the secondary confirmation on empty are kept, so the measurement semantics
 * of `hasA` / `hasMX` are unchanged; the retry is dropped (see the preset).
 */
async function probeDetailBatch(batch: string[], deadlineMs: number | undefined): Promise<LookalikeResult[]> {
	const legs = batch.flatMap((domain) => [
		{ domain, type: 'A' as const },
		{ domain, type: 'MX' as const },
	]);
	const outcomes = await mapConcurrent(legs, LOOKALIKE_DNS_PROBE_CONCURRENCY, async (leg): Promise<DetailLegOutcome> => {
		if (remainingMs(deadlineMs) <= 0) return { ok: false, reason: 'deadline' };
		// Armed HERE, at dispatch — the pool guarantees a connection slot is free.
		const deadline = deadlineSignal(deadlineMs);
		try {
			const records = await queryDnsRecords(leg.domain, leg.type, deadline ? { ...PHASE2_DNS_OPTS, signal: deadline } : PHASE2_DNS_OPTS);
			return { ok: true, records };
		} catch (err) {
			return { ok: false, reason: classifyDnsFailure(err, deadline) };
		}
	});
	return batch.map((domain, i) => {
		const a = outcomes[2 * i];
		const mx = outcomes[2 * i + 1];
		const realMxRecords = mx.ok ? mx.records.filter(isRealMxRecord) : [];
		const mxExchanges = realMxRecords.map(extractMxExchange).filter((host): host is string => host !== null);
		const reason = worstReason(a.ok ? undefined : a.reason, mx.ok ? undefined : mx.reason);
		return {
			domain,
			hasA: a.ok && a.records.length > 0,
			hasMX: realMxRecords.length > 0,
			mxExchanges,
			probeDegraded: reason !== undefined,
			...(reason !== undefined ? { probeDegradedReason: reason } : {}),
		};
	});
}

/**
 * Count the number of labels (dot-separated segments) in a domain.
 */
export function labelCount(domain: string): number {
	return domain.split('.').length;
}

/**
 * Extract the parent domain from a dot-insertion permutation.
 * E.g., "blackve.ilsecurity.com" → "ilsecurity.com"
 */
export function getParentDomain(domain: string): string {
	const parts = domain.split('.');
	return parts.slice(1).join('.');
}

/**
 * Detect wildcard DNS on a set of parent domains by probing a canary subdomain.
 * Returns a Set of parent domains that have wildcard A records.
 */
export async function detectWildcardParents(parentDomains: string[]): Promise<Set<string>> {
	const wildcardParents = new Set<string>();
	// A long brand yields one dot-insertion parent per label position, so this
	// is pooled like every other fan-out here (a 16-label brand is 16 canaries),
	// and it runs on the lean Phase-1 preset: it precedes the NS phase, whose
	// budget it would otherwise eat — a canary under a lame parent zone used to
	// cost 3s + one retry + a secondary-resolver confirmation, ~7s, before the
	// first permutation was ever asked about. A canary that fails is "not a
	// wildcard", which only means the parent's permutations get probed like any
	// other; nothing is concluded from it.
	await mapConcurrent(parentDomains, LOOKALIKE_DNS_PROBE_CONCURRENCY, async (parent) => {
		try {
			const canary = `${WILDCARD_CANARY_LABEL}.${parent}`;
			const records = await queryDnsRecords(canary, 'A', PHASE1_DNS_OPTS);
			if (records.length > 0) {
				wildcardParents.add(parent);
			}
		} catch {
			// Query failed — not a wildcard
		}
	});
	return wildcardParents;
}

/** Outcome of the pooled Phase 1 result: either a measured NS answer, or why there is none. */
type NsExistenceOutcome =
	{ domain: string; measured: true; ns: string[] } | { domain: string; measured: false; reason: DnsProbeFailureReason };

/**
 * Phase 1: NS existence check for all domains through the connection-cap
 * pool. Returns only domains that have NS records (i.e., are registered),
 * along with their normalized NS record data for ownership comparison, plus
 * the count — and the reasons — of lookups that produced NO measurement.
 *
 * A REJECTED NS lookup is not "unregistered" — it is UNKNOWN, and dropping it
 * silently is the primary source of run-to-run variance (#781). This phase
 * gates everything downstream, so a timed-out NS query makes a registered
 * domain vanish from the result set entirely, with nothing in the response
 * distinguishing that from a deregistration. Measured on openclaw.ai: three
 * `force_refresh` runs minutes apart returned 12, 10 and 13 candidates, with
 * three names appearing only in the third. The same law applies to a lookup
 * the phase deadline cut: counted, with reason `deadline`, never "no NS".
 */
export async function filterByNsExistence(
	domains: string[],
	options: DnsPhaseOptions = {},
): Promise<{ registered: string[]; nsMap: Map<string, Set<string>>; unresolved: number; unresolvedByReason: UnresolvedByReason }> {
	const nsMap = new Map<string, Set<string>>();
	const outcomes = await mapConcurrent(domains, LOOKALIKE_DNS_PROBE_CONCURRENCY, async (domain): Promise<NsExistenceOutcome> => {
		if (remainingMs(options.deadlineMs) <= 0) return { domain, measured: false, reason: 'deadline' };
		// Armed HERE, at dispatch — the pool guarantees a connection slot is free,
		// so both this signal and the transport's PHASE1 timer measure the
		// resolver, not a queue.
		const deadline = deadlineSignal(options.deadlineMs);
		try {
			const ns = await queryDnsRecords(domain, 'NS', deadline ? { ...PHASE1_DNS_OPTS, signal: deadline } : PHASE1_DNS_OPTS);
			return { domain, measured: true, ns };
		} catch (err) {
			return { domain, measured: false, reason: classifyDnsFailure(err, deadline) };
		}
	});
	const registered: string[] = [];
	const unresolvedByReason = emptyUnresolvedByReason();
	for (const outcome of outcomes) {
		if (!outcome.measured) {
			unresolvedByReason[outcome.reason]++;
			continue;
		}
		if (outcome.ns.length > 0) {
			nsMap.set(outcome.domain, normalizeNsSet(outcome.ns));
			registered.push(outcome.domain);
		}
	}
	const unresolved = unresolvedByReason.timeout + unresolvedByReason.deadline + unresolvedByReason.failed;
	return { registered, nsMap, unresolved, unresolvedByReason };
}

/**
 * Normalize a set of NS record values for comparison.
 * Strips trailing dots, lowercases, and returns a Set.
 */
function normalizeNsSet(nsRecords: string[]): Set<string> {
	return new Set(nsRecords.map((ns) => ns.replace(/\.$/, '').toLowerCase()));
}

/** Result of the seed-side NS probe: the answer set plus whether the lookup actually resolved. */
export interface PrimaryNsResult {
	ns: Set<string>;
	/**
	 * False when the NS query REJECTED (timeout / throttling). The distinction
	 * is load-bearing (#832): an empty set from a FAILED lookup means the
	 * ownership comparison has nothing to compare against — every downstream
	 * verdict must be `unmeasured`, never `third_party`. An empty set from a
	 * resolved lookup is a real measurement.
	 */
	resolved: boolean;
}

/**
 * Query NS records for the primary domain to use for ownership comparison.
 * Fail-soft on the SET (empty), but the failure itself is surfaced via
 * `resolved: false` so the attribution layer can decline to attribute (#832)
 * rather than reading "unfetched" as "distinct infrastructure".
 */
export async function queryPrimaryNs(domain: string): Promise<PrimaryNsResult> {
	try {
		const ns = await queryDnsRecords(domain, 'NS', SEED_DNS_OPTS);
		return { ns: normalizeNsSet(ns), resolved: true };
	} catch {
		return { ns: new Set<string>(), resolved: false };
	}
}

/**
 * #864 — bounded pool for the per-candidate seed-side authorisation probe
 * behind `classifyOwnership()` step 5b. The probe is gated to candidates whose
 * MX already routes into the seed apex, so the eligible set is tiny on any
 * real scan; the pool is a ceiling, not a throughput target. Sized well under
 * the adaptive-batching A/MX probe's INITIAL_BATCH_SIZE so it can never
 * out-fan the pass it follows.
 */
export const SEED_AUTHORISATION_CONCURRENCY = 3;

/** Cap on distinct in-seed report receivers checked per candidate (each costs one authorisation lookup + one canary). */
export const MAX_SEED_REPORT_RECEIVERS = 2;

/**
 * #864 — seed-side probe: does the seed publish the RFC 7489 §7.1 external-
 * destination authorisation for this candidate's DMARC reports?
 *
 *  1. `_dmarc.<candidate>` TXT (candidate-published, free to forge — this only
 *     tells us WHERE to look on the seed side).
 *  2. For each `rua`/`ruf` mailbox domain inside the seed apex (at most
 *     {@link MAX_SEED_REPORT_RECEIVERS}): `<candidate>._report._dmarc.<receiver>`
 *     TXT must carry `v=DMARC1`. That record lives in the RECEIVER's zone —
 *     under the seed apex — and only its owner can publish it.
 *  3. A canary label under the same `_report._dmarc` distinguishes a
 *     per-domain grant from a wildcard (`*._report._dmarc.<receiver>`), which
 *     authorises reports about ANY domain and is therefore evidence-only.
 *
 * Uses the lean Phase-1 preset. Failure semantics are ASYMMETRIC by design
 * (PR #897 re-review, High): stage 1 queries the CANDIDATE's zone, which the
 * attacker controls end to end — a squatter who copies the seed MX and then
 * blackholes its own `_dmarc` must not be rewarded with an `unmeasured` that
 * withholds its threat finding, so that failure is `candidate_unresolved`, a
 * DECLINE. Only stages 2–3 (the grant and its canary, both in the SEED's
 * zone) may yield `unresolved` → `unmeasured` (#832's law). NXDOMAIN / empty
 * answers are MEASURED absences (the DoH layer never throws on an rcode);
 * only a timeout / abort / transport failure is a rejection.
 */
export async function probeDmarcReportAuthorisation(candidate: string, seedDomain: string): Promise<DmarcReportAuthorisation> {
	const normalisedSeed = seedDomain.trim().toLowerCase().replace(/\.$/, '');
	const seedApex = getRegistrableDomain(normalisedSeed) ?? normalisedSeed;

	let dmarcRecords: string[];
	try {
		dmarcRecords = await queryTxtRecords(`_dmarc.${candidate}`, PHASE1_DNS_OPTS);
	} catch {
		// Attacker-controlled zone failed to answer: decline, never a measurement gap.
		return { status: 'candidate_unresolved', seedReceivers: [] };
	}
	const dmarc = dmarcRecords.find((r) => /^\s*v=DMARC1\b/i.test(r));
	if (!dmarc) return { status: 'no_seed_receiver', seedReceivers: [] };

	const seedReceivers = parseDmarcReportReceivers(dmarc)
		.filter((receiver) => isInBailiwick(receiver, seedApex))
		.slice(0, MAX_SEED_REPORT_RECEIVERS);
	if (seedReceivers.length === 0) return { status: 'no_seed_receiver', seedReceivers };

	let sawWildcard: string | undefined;
	for (const receiver of seedReceivers) {
		const authorisationRecord = `${candidate}._report._dmarc.${receiver}`;
		let grant: string[];
		try {
			grant = await queryTxtRecords(authorisationRecord, PHASE1_DNS_OPTS);
		} catch {
			return { status: 'unresolved', seedReceivers };
		}
		if (!grant.some((r) => /^\s*v=DMARC1\b/i.test(r))) continue;

		// A grant answered — is it specific to this candidate, or a wildcard?
		let canary: string[];
		try {
			canary = await queryTxtRecords(`${WILDCARD_CANARY_LABEL}._report._dmarc.${receiver}`, PHASE1_DNS_OPTS);
		} catch {
			// Cannot tell per-domain from wildcard: nothing was measured.
			return { status: 'unresolved', seedReceivers };
		}
		if (canary.some((r) => /^\s*v=DMARC1\b/i.test(r))) {
			sawWildcard = receiver;
			continue;
		}
		return { status: 'authorised', seedReceivers, receiverDomain: receiver, authorisationRecord };
	}
	if (sawWildcard !== undefined) return { status: 'wildcard', seedReceivers, receiverDomain: sawWildcard };
	return { status: 'not_authorised', seedReceivers };
}

/**
 * Query MX records for the primary domain — the D4 (2026-07-26
 * correctness-defects design) MX-overlap corroboration signal for
 * `attributionConfidence()`. Fail-soft: an empty set just means the guard
 * falls back to "no corroboration" rather than throwing.
 */
export async function queryPrimaryMx(domain: string): Promise<Set<string>> {
	try {
		const mx = await queryMxRecords(domain, SEED_DNS_OPTS);
		return new Set(mx.map((r) => r.exchange.toLowerCase().replace(/\.$/, '')));
	} catch {
		return new Set<string>();
	}
}

/**
 * Phase 2: detail-probe (A + MX) the registered candidates in batches of up to
 * INITIAL_BATCH_SIZE, each batch through the connection-cap pool. Halves the
 * batch on repeated failures (floor at MIN_BATCH_SIZE) with a BACKOFF_DELAY_MS
 * pause, and recovers on clean batches.
 *
 * "Failure" here is a candidate whose A or MX leg the resolver did not answer
 * (`timeout` / `failed`). The pre-pool version counted REJECTED per-candidate
 * promises — which could never occur, because the per-candidate probe settled
 * both legs internally — so the backoff was unreachable, and it hid a second
 * defect: the loop advanced by the NEW batch size after halving, so a live
 * backoff would have re-probed half of the batch it had just finished. Both
 * fixed here; a deadline cut is not a resolver failure and never triggers a
 * backoff (there is nothing left to be polite about).
 *
 * Every candidate comes back FULFILLED — a degraded one carries
 * `probeDegraded: true` + `probeDegradedReason`. The `PromiseSettledResult`
 * return shape is kept for the orchestrator's existing accounting.
 */
export async function probeWithAdaptiveBatching(
	permutations: string[],
	options: DnsPhaseOptions = {},
): Promise<PromiseSettledResult<LookalikeResult>[]> {
	const allResults: PromiseSettledResult<LookalikeResult>[] = [];
	let batchSize = INITIAL_BATCH_SIZE;
	let delayMs = 0;

	let i = 0;
	while (i < permutations.length) {
		if (remainingMs(options.deadlineMs) <= 0) {
			// Budget spent: everything left is UNMEASURED with a stated reason —
			// never dropped, never reported as registered-but-dark.
			for (const domain of permutations.slice(i)) {
				allResults.push({ status: 'fulfilled', value: unmeasuredResult(domain, 'deadline') });
			}
			break;
		}
		if (delayMs > 0) {
			await new Promise((resolve) => setTimeout(resolve, delayMs));
		}

		const batch = permutations.slice(i, i + batchSize);
		i += batch.length;
		const batchResults = await probeDetailBatch(batch, options.deadlineMs);
		for (const value of batchResults) allResults.push({ status: 'fulfilled', value });

		const failures = batchResults.filter((r) => r.probeDegraded && r.probeDegradedReason !== 'deadline').length;
		if (failures > FAILURE_THRESHOLD) {
			// Back off: halve batch size (floor to MIN_BATCH_SIZE) and add delay
			batchSize = Math.max(MIN_BATCH_SIZE, Math.floor(batchSize / 2));
			delayMs = BACKOFF_DELAY_MS;
		} else if (delayMs > 0 && failures === 0) {
			// Recover: if a clean batch after backoff, try increasing again
			batchSize = Math.min(INITIAL_BATCH_SIZE, batchSize + 2);
			delayMs = 0;
		}
	}

	return allResults;
}
