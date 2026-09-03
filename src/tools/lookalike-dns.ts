// SPDX-License-Identifier: BUSL-1.1

/**
 * DNS resolution layer for the lookalike check.
 *
 * Extracted VERBATIM from `check-lookalikes.ts` (pure split, no behaviour
 * change): everything here is the "does this candidate exist, and what
 * infrastructure does it carry" question — NS existence filtering, the
 * wildcard-parent canary probe, the adaptive-batching A/MX detail probe, and
 * the two seed-side queries (`NS` for the ownership verdict, `MX` for the D4
 * overlap corroboration signal).
 *
 * Nothing in this module builds a Finding, decides a severity, or makes an
 * ownership claim — it only measures. The tuning constants live here rather
 * than in the orchestrator because they are properties of the query plane, and
 * `test/check-lookalikes.spec.ts` pins their exact values through the tool's
 * re-export.
 */

import { queryDnsRecords, queryMxRecords } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import type { SoaAuthority } from '../lib/ownership-attribution';

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

/**
 * Check a single lookalike domain for DNS and MX records.
 * Filters out null MX records (RFC 7505) to avoid false positives.
 */
async function probeLookalike(domain: string): Promise<LookalikeResult> {
	const [aRecords, mxRecords] = await Promise.allSettled([queryDnsRecords(domain, 'A'), queryDnsRecords(domain, 'MX')]);

	const realMxRecords = mxRecords.status === 'fulfilled' ? mxRecords.value.filter(isRealMxRecord) : [];
	const mxExchanges = realMxRecords.map(extractMxExchange).filter((host): host is string => host !== null);

	return {
		domain,
		hasA: aRecords.status === 'fulfilled' && aRecords.value.length > 0,
		hasMX: realMxRecords.length > 0,
		mxExchanges,
		probeDegraded: aRecords.status === 'rejected' || mxRecords.status === 'rejected',
	};
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
	const probes = parentDomains.map(async (parent) => {
		try {
			const canary = `${WILDCARD_CANARY_LABEL}.${parent}`;
			const records = await queryDnsRecords(canary, 'A');
			if (records.length > 0) {
				wildcardParents.add(parent);
			}
		} catch {
			// Query failed — not a wildcard
		}
	});
	await Promise.allSettled(probes);
	return wildcardParents;
}

/**
 * Phase 1: Fast NS existence check for all domains in parallel.
 * Returns only domains that have NS records (i.e., are registered),
 * along with their normalized NS record data for ownership comparison.
 */
export async function filterByNsExistence(
	domains: string[],
): Promise<{ registered: string[]; nsMap: Map<string, Set<string>>; unresolved: number }> {
	const nsMap = new Map<string, Set<string>>();
	const results = await Promise.allSettled(
		domains.map(async (domain) => {
			const ns = await queryDnsRecords(domain, 'NS', PHASE1_DNS_OPTS);
			if (ns.length > 0) {
				nsMap.set(domain, normalizeNsSet(ns));
			}
			return { domain, hasNs: ns.length > 0 };
		}),
	);
	const registered = results
		.filter((r): r is PromiseFulfilledResult<{ domain: string; hasNs: boolean }> => r.status === 'fulfilled' && r.value.hasNs)
		.map((r) => r.value.domain);
	// A REJECTED NS lookup is not "unregistered" — it is UNKNOWN, and dropping it
	// silently is the primary source of run-to-run variance (#781). This phase
	// gates everything downstream, so a timed-out NS query makes a registered
	// domain vanish from the result set entirely, with nothing in the response
	// distinguishing that from a deregistration. Measured on openclaw.ai: three
	// `force_refresh` runs minutes apart returned 12, 10 and 13 candidates, with
	// three names appearing only in the third.
	const unresolved = results.filter((r) => r.status === 'rejected').length;
	return { registered, nsMap, unresolved };
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
 * #864 — bounded pool for the per-candidate SOA probe behind the in-bailiwick
 * convergence arm (`classifyOwnership()` step 5b). The probe is gated to
 * candidates whose MX already routes into the seed apex, so the eligible set
 * is tiny on any real scan; the pool is a ceiling, not a throughput target.
 * Sized well under the adaptive-batching A/MX probe's INITIAL_BATCH_SIZE so
 * it can never out-fan the pass it follows.
 */
export const BAILIWICK_SOA_CONCURRENCY = 3;

/** Result of the #864 candidate SOA probe: the parsed authority fields plus whether the lookup actually resolved. */
export interface CandidateSoaResult {
	/** `null` when no SOA answered OR the lookup rejected — `resolved` tells the two apart. */
	soa: SoaAuthority | null;
	/**
	 * False when the SOA query REJECTED (timeout / throttling). Load-bearing
	 * for the same reason as `PrimaryNsResult.resolved` (#832): an absent SOA
	 * from a FAILED lookup is unfetched, not measured, and the attribution
	 * layer must say `unmeasured` rather than the contrary `third_party`.
	 */
	resolved: boolean;
}

/**
 * Query the candidate's SOA record (#864) and return its MNAME / RNAME,
 * lowercased with trailing dots stripped. Uses the lean Phase-1 preset: this
 * is one disposable candidate probe, not a seed-side query — losing it costs
 * an `unmeasured` verdict for that candidate this run, never a wrong one.
 */
export async function queryCandidateSoa(domain: string): Promise<CandidateSoaResult> {
	try {
		const records = await queryDnsRecords(domain, 'SOA', PHASE1_DNS_OPTS);
		const first = records[0];
		if (!first) return { soa: null, resolved: true };
		// Presentation format: "<mname> <rname> <serial> <refresh> <retry> <expire> <minimum>".
		const [mname, rname] = first.trim().split(/\s+/);
		if (!mname || !rname) return { soa: null, resolved: true };
		return {
			soa: { mname: mname.toLowerCase().replace(/\.$/, ''), rname: rname.toLowerCase().replace(/\.$/, '') },
			resolved: true,
		};
	} catch {
		return { soa: null, resolved: false };
	}
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
 * Run permutation probes with adaptive batch sizing and backoff.
 * Starts at INITIAL_BATCH_SIZE, halves on repeated failures (floor at MIN_BATCH_SIZE),
 * recovers on clean batches.
 */
export async function probeWithAdaptiveBatching(permutations: string[]): Promise<PromiseSettledResult<LookalikeResult>[]> {
	const allResults: PromiseSettledResult<LookalikeResult>[] = [];
	let batchSize = INITIAL_BATCH_SIZE;
	let delayMs = 0;

	for (let i = 0; i < permutations.length; i += batchSize) {
		if (delayMs > 0) {
			await new Promise((resolve) => setTimeout(resolve, delayMs));
		}

		const batch = permutations.slice(i, i + batchSize);
		const batchResults = await Promise.allSettled(batch.map((d) => probeLookalike(d)));
		allResults.push(...batchResults);

		// Count failures in this batch
		const failures = batchResults.filter((r) => r.status === 'rejected').length;
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
