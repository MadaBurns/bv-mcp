// SPDX-License-Identifier: BUSL-1.1

/**
 * DNS RCODE (RFC 1035 §4.1.1) classification — the ONE place that decides whether an
 * empty answer set is a measurement or a measurement failure.
 *
 * A DoH endpoint answers HTTP 200 for SERVFAIL and REFUSED exactly as it does for
 * NOERROR, carrying the response code only in the JSON `Status` field. Nothing throws,
 * so any projection that keeps only the answer data (`DNSQueryFunction`'s `string[]`,
 * `queryDnsRecords`' `string[]`) renders a resolver that could not answer as byte-identical
 * to a name that genuinely publishes no such record. A check reading that projection then
 * files a confident absence — `missingControl` — for a control it never observed, which
 * zeroes a scored category from underneath the `checkStatus` / `isCheckMeasured`
 * abstention discipline (the discipline is not wrong; it is simply never told).
 *
 * The rule, in one line: **NOERROR and NXDOMAIN are conclusions; every other rcode is not.**
 *
 * NXDOMAIN is deliberately conclusive — "this name does not exist" IS a measurement, and
 * it is the strongest form of absence there is. Everything else (SERVFAIL, REFUSED, and the
 * rarer FORMERR / NOTIMP / RFC 8914-era codes) means the resolver declined or failed to
 * answer the question, so the only honest verdict is abstention.
 */

import { buildNotAssessedResult, createFinding } from './check-utils';
import type { CheckCategory, CheckResult } from './types';

/** DNS response codes (RFC 1035 §4.1.1) this codebase names explicitly. */
export const DNS_RCODE = {
	NOERROR: 0,
	FORMERR: 1,
	SERVFAIL: 2,
	NXDOMAIN: 3,
	NOTIMP: 4,
	REFUSED: 5,
} as const;

const RCODE_NAMES: Record<number, string> = {
	[DNS_RCODE.NOERROR]: 'NOERROR',
	[DNS_RCODE.FORMERR]: 'FORMERR',
	[DNS_RCODE.SERVFAIL]: 'SERVFAIL',
	[DNS_RCODE.NXDOMAIN]: 'NXDOMAIN',
	[DNS_RCODE.NOTIMP]: 'NOTIMP',
	[DNS_RCODE.REFUSED]: 'REFUSED',
};

/**
 * `true` when the response code means the resolver reached a conclusion about the
 * question — NOERROR (with or without answers) or NXDOMAIN. An empty answer set under
 * one of these IS evidence of absence.
 */
export function isConclusiveRcode(status: number | undefined): boolean {
	return status === DNS_RCODE.NOERROR || status === DNS_RCODE.NXDOMAIN;
}

/**
 * `true` when the response code means the resolver could NOT answer, so an empty answer
 * set is not evidence of anything.
 *
 * `undefined` is NOT inconclusive: a hand-built response, or an adapter with no rcode
 * channel, simply has nothing to say, and the caller's prior behaviour must stand rather
 * than degrade into a blanket abstention (the same contract `RawDNSResponse.Status` states).
 */
export function isInconclusiveRcode(status: number | undefined): status is number {
	return status !== undefined && !isConclusiveRcode(status);
}

/** Human-readable rcode name for finding prose, falling back to `RCODE <n>`. */
export function describeRcode(status: number): string {
	return RCODE_NAMES[status] ?? `RCODE ${status}`;
}

/**
 * Map an inconclusive rcode onto the repo's EXISTING abstention shape, so no caller has
 * to hand-roll a second one: `checkStatus: 'error'` + `partial: true` + score 0 +
 * `passed: false`, carrying the `inconclusive` / `errorKind: 'dns_error'` finding markers
 * that `isDnsErrorFinding` and `control-presence` already filter on.
 *
 * Deliberately sets NO `missingControl` (the #638 law): the probe never concluded, so
 * nothing may be claimed absent. `controlPresent` is likewise left undefined — "could not
 * be determined" — rather than `false`.
 *
 * `confidence: 'heuristic'` disarms the prose leg of `scoreIndicatesMissingControl`, so a
 * consumer that reads findings without gating on `isCheckMeasured` still cannot read this
 * abstention as a missing control.
 *
 * `label` is the human-readable control name used in the finding title, matching
 * `buildDnsErrorResult`'s `'<label> check error'` convention (e.g. 'DMARC', 'TLS-RPT').
 */
export function buildRcodeAbstentionResult(
	category: CheckCategory,
	label: string,
	domain: string,
	recordType: string,
	status: number,
): CheckResult {
	const finding = createFinding(
		category,
		`${label} check error`,
		'high',
		`Check failed: DNS query for ${recordType} records of ${domain} returned ${describeRcode(status)}; the resolver could not answer, so ${label} was not measured.`,
		{ inconclusive: true, errorKind: 'dns_error', confidence: 'heuristic', dnsRcode: status },
	);
	return buildNotAssessedResult(category, finding, 'error');
}
