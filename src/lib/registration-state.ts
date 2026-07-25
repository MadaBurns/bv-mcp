// SPDX-License-Identifier: BUSL-1.1

/**
 * Registration-state resolution.
 *
 * `queryDnsRecords` returns `string[]`, which collapses three distinct DNS
 * outcomes — NXDOMAIN, SERVFAIL and NOERROR-with-no-answers — into the same
 * empty array. Callers then cannot tell "this domain does not exist" from "the
 * lookup failed", and historically resolved that ambiguity toward the
 * confident, customer-visible claim ("not registered. Consider defensive
 * registration"), which was wrong for every domain whose resolver SERVFAILed.
 *
 * This module reads the DoH `Status` rcode that the wrapper discards and
 * returns a three-state union instead. Only NXDOMAIN may support an
 * "unregistered" claim; everything else is explicitly `unknown`.
 */

import { DnsQueryError, queryDns } from './dns';
import { RecordType } from './dns-types';
import type { DohResponse, QueryDnsOptions } from './dns-types';

/** Which record type positively demonstrated that the name exists. */
export type RegistrationEvidence = 'ns' | 'soa' | 'a';

/** Why a registration state could not be determined. */
export type UnknownReason = 'servfail' | 'refused' | 'timeout' | 'truncated' | 'network' | 'empty_noerror';

/**
 * Tri-state registration result. `unregistered` is deliberately the narrowest
 * arm: it is reachable only from an NXDOMAIN with no contradicting positive
 * record, and it carries no payload, so it is structurally impossible to
 * attach observed records (NS/MX/SPF) to an "unregistered" verdict.
 */
export type RegistrationState =
	| { state: 'registered'; ns: string[]; evidence: RegistrationEvidence[] }
	| { state: 'unregistered' }
	| { state: 'unknown'; reason: UnknownReason };

/**
 * Per-scan memoisation. Keyed by lowercased domain, holding the in-flight
 * Promise so concurrent callers share one lookup. Mirrors the existing
 * `QueryDnsOptions.queryCache` convention.
 */
export type RegistrationCache = Map<string, Promise<RegistrationState>>;

/** DNS RCODEs (RFC 1035 §4.1.1, RFC 2136). */
const RCODE_SERVFAIL = 2;
const RCODE_NXDOMAIN = 3;
const RCODE_REFUSED = 5;

function answersOfType(resp: DohResponse, type: number): string[] {
	return (resp.Answer ?? []).filter((a) => a.type === type).map((a) => a.data);
}

function isTimeoutError(err: unknown): boolean {
	return err instanceof DnsQueryError && /timed out/i.test(err.message);
}

/**
 * Resolve whether a domain is registered (internal uncached implementation).
 *
 * Costs 2 subrequests (NS + SOA) in the common case, escalating to a third (A)
 * only when both come back NOERROR-with-no-answers — the empty-non-terminal
 * case, where a name legitimately exists without records at that exact label.
 *
 * Never throws: transport failures are folded into `{ state: 'unknown' }`.
 */
export async function resolveRegistrationUncached(domain: string, opts?: QueryDnsOptions): Promise<RegistrationState> {
	const settled = await Promise.allSettled([queryDns(domain, 'NS', false, opts), queryDns(domain, 'SOA', false, opts)]);

	const responses: DohResponse[] = [];
	let sawTimeout = false;
	let transportFailures = 0;
	for (const outcome of settled) {
		if (outcome.status === 'fulfilled') {
			responses.push(outcome.value);
		} else {
			transportFailures++;
			if (isTimeoutError(outcome.reason)) sawTimeout = true;
		}
	}

	// 1. Positive evidence wins outright, regardless of what the other query did.
	const evidence: RegistrationEvidence[] = [];
	let ns: string[] = [];
	for (const resp of responses) {
		const nsData = answersOfType(resp, RecordType.NS);
		if (nsData.length > 0) {
			ns = nsData;
			if (!evidence.includes('ns')) evidence.push('ns');
		}
		if (answersOfType(resp, RecordType.SOA).length > 0 && !evidence.includes('soa')) {
			evidence.push('soa');
		}
	}
	if (evidence.length > 0) return { state: 'registered', ns, evidence };

	// 2. A truncated answer is never conclusive in either direction.
	if (responses.some((r) => r.TC)) return { state: 'unknown', reason: 'truncated' };

	// 3. NXDOMAIN — the ONLY path to an "unregistered" claim.
	if (responses.some((r) => r.Status === RCODE_NXDOMAIN)) return { state: 'unregistered' };

	// 4. Explicit resolver-side failures.
	if (responses.some((r) => r.Status === RCODE_SERVFAIL)) return { state: 'unknown', reason: 'servfail' };
	if (responses.some((r) => r.Status === RCODE_REFUSED)) return { state: 'unknown', reason: 'refused' };

	// 5. Nothing answered at all.
	if (responses.length === 0 && transportFailures > 0) {
		return { state: 'unknown', reason: sawTimeout ? 'timeout' : 'network' };
	}

	// 6. NOERROR with no answers. The name may be an empty non-terminal, so one
	//    escalation to A before abstaining.
	try {
		const aResp = await queryDns(domain, 'A', false, opts);
		if (answersOfType(aResp, RecordType.A).length > 0) {
			return { state: 'registered', ns: [], evidence: ['a'] };
		}
		if (aResp.Status === RCODE_NXDOMAIN) return { state: 'unregistered' };
	} catch {
		// Escalation is best-effort; fall through to `unknown`.
	}

	return { state: 'unknown', reason: 'empty_noerror' };
}

/**
 * Resolve whether a domain is registered.
 *
 * When a `cache` is provided, deduplicates concurrent lookups for the same
 * domain and ensures two tools scanning overlapping domains cannot report
 * contradictory registration facts within one run.
 *
 * Never throws: transport failures are folded into `{ state: 'unknown' }`.
 */
export async function resolveRegistration(domain: string, opts?: QueryDnsOptions, cache?: RegistrationCache): Promise<RegistrationState> {
	if (!cache) return resolveRegistrationUncached(domain, opts);
	const key = domain.toLowerCase();
	const existing = cache.get(key);
	if (existing) return existing;
	const promise = resolveRegistrationUncached(domain, opts);
	cache.set(key, promise);
	return promise;
}
