// SPDX-License-Identifier: BUSL-1.1

/**
 * MX record check.
 * Validates presence and quality of MX records for a domain.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { CheckResult, DNSQueryFunction, Finding } from '../types';
import { buildNotAssessedResult, buildCheckResult, createFinding } from '../check-utils';
import { buildRcodeAbstentionResult, isInconclusiveRcode, queryWithRcode } from '../dns-rcode';
import {
	getInvalidMxExchangeFinding,
	getIpTargetFindings,
	getLoopbackMxFinding,
	getNullMxFinding,
	getPresenceFinding,
	getSingleMxFinding,
	isInvalidMxExchange,
	isLoopbackMxRecord,
	isNullMxRecord,
	parseMxRecords,
} from './mx-analysis';

/**
 * Verdict for a domain with NO usable mail exchange — either no MX at all, or an MX
 * set whose every exchange is syntactically invalid (#1114). Scoring is
 * SPF-CONTEXT-dependent, NOT an unconditional missing control.
 * NIST SP 800-177r1 §4.4.2 — a non-mail domain SHOULD publish "v=spf1 -all";
 * when it does, that is the correct posture (reward, do not penalize). Only a
 * domain with no usable MX AND no/soft SPF is genuinely spoofable (the real gap).
 *
 * `leadingFindings` are reported ahead of the SPF-context verdict (the invalid-exchange note).
 */
async function buildNoMailResult(
	domain: string,
	queryDNS: DNSQueryFunction,
	timeout: number,
	leadingFindings: Finding[] = [],
): Promise<CheckResult> {
	let spf = '';
	try {
		const txtOutcome = await queryWithRcode(queryDNS, domain, 'TXT', timeout);
		spf = (txtOutcome.records.find((r) => r.toLowerCase().startsWith('v=spf1')) ?? '').toLowerCase();
		// An unanswered SPF probe is not "no SPF": the no-MX verdict below cannot be
		// reached from a TXT lookup that never concluded.
		if (!spf && isInconclusiveRcode(txtOutcome.rcode)) {
			return buildRcodeAbstentionResult('mx', 'MX', domain, 'TXT', txtOutcome.rcode);
		}
	} catch {
		return buildNotAssessedResult(
			'mx',
			createFinding(
				'mx',
				'MX records not assessed',
				'info',
				`Could not query the SPF (TXT) record for ${domain} due to a transient DNS failure, so the no-MX posture could not be classified; this control was not assessed.`,
				{ inconclusive: true, errorKind: 'dns_error' },
			),
		);
	}

	let finding: Finding;
	// Anchored to the `all` TERM: a substring test matched `include:-all.example`.
	if (spf.split(/\s+/).includes('-all')) {
		finding = createFinding(
			'mx',
			'Correctly-configured non-mail domain',
			'info',
			`No MX records, and SPF publishes "-all" (hard fail). Per NIST SP 800-177r1 §4.4.2 this is the recommended posture for a domain that does not handle email.`,
		);
	} else if (spf) {
		finding = createFinding(
			'mx',
			'Non-mail domain SPF not hard-fail',
			'medium',
			`No MX records and an SPF record that does not use "-all". Non-mail domains should publish "v=spf1 -all" to fully prevent spoofing.`,
		);
	} else {
		finding = createFinding(
			'mx',
			'No MX and no SPF — domain spoofable',
			'medium',
			`No mail exchange records and no SPF policy. The domain can be spoofed; publish "v=spf1 -all" (and a null MX per RFC 7505) if it does not handle email.`,
			{ missingControl: true },
		);
	}
	// No usable MX → mail control definitively absent (controlPresent: false).
	return buildCheckResult('mx', [...leadingFindings, finding], false);
}

/**
 * Check MX record configuration for a domain.
 * Validates MX records exist, checks for null MX, IP targets, dangling records,
 * and single MX (no redundancy).
 *
 * Note: Provider detection from the original check is omitted here as it depends
 * on external provider signature files. Consumers can implement provider detection
 * as a post-processing step.
 */
export async function checkMX(domain: string, queryDNS: DNSQueryFunction, options?: { timeout?: number }): Promise<CheckResult> {
	const timeout = options?.timeout ?? 5000;
	let answers: string[];
	try {
		const mxOutcome = await queryWithRcode(queryDNS, domain, 'MX', timeout);
		// SERVFAIL/REFUSED arrive as an EMPTY answer set, byte-identical to a name that
		// publishes no MX. Concluding "no MX" from it would file a spoofable-domain
		// missingControl for a lookup that never concluded (SQ-279).
		if (isInconclusiveRcode(mxOutcome.rcode)) {
			return buildRcodeAbstentionResult('mx', 'MX', domain, 'MX', mxOutcome.rcode);
		}
		answers = mxOutcome.records;
	} catch {
		// Transient resolver failure — we could not MEASURE the mail-exchange posture. Mark the
		// category INCONCLUSIVE (checkStatus) so the scoring engine renormalizes over the remaining
		// categories instead of penalizing a possibly-healthy domain with a scored deficiency.
		return buildNotAssessedResult(
			'mx',
			createFinding(
				'mx',
				'MX records not assessed',
				'info',
				`Could not query mail-exchange (MX) records for ${domain} due to a transient DNS failure; this control was not assessed.`,
			),
		);
	}

	if (!answers || answers.length === 0) {
		return buildNoMailResult(domain, queryDNS, timeout);
	}

	const findings: Finding[] = [];

	const mxRecords = parseMxRecords(answers);

	// Check for null MX (RFC 7505: priority 0, exchange ".")
	const nullMx = mxRecords.find(isNullMxRecord);
	if (nullMx) {
		findings.push(getNullMxFinding());
		// Null MX is an explicit "does not accept mail" declaration → not a mail control.
		return buildCheckResult('mx', findings, false);
	}

	// Syntactically invalid exchange (`300 ~.`, `10 *.`; #1114) — not an RFC 1123 hostname, so
	// it can route nothing. Classified AFTER null MX and loopback (`::1` is not a valid hostname
	// but is a loopback defect, #944). One info finding names the literals; the records are then
	// dropped from every pass below so they can never read as "MX records found" or as a
	// "Dangling MX record" (that title is reserved for valid names that do not resolve).
	const invalidRecords = mxRecords.filter((r) => !isLoopbackMxRecord(r) && isInvalidMxExchange(r));
	const usableRecords = mxRecords.filter((r) => !invalidRecords.includes(r));
	if (usableRecords.length === 0) {
		// EVERY exchange is garbage: no mail exchange exists, so take the no-MX (SPF-context)
		// verdict — controlPresent:false — with the invalid-exchange note leading.
		return buildNoMailResult(domain, queryDNS, timeout, [getInvalidMxExchangeFinding(invalidRecords)]);
	}

	findings.push(getPresenceFinding(usableRecords));
	if (invalidRecords.length > 0) {
		findings.push(getInvalidMxExchangeFinding(invalidRecords));
	}

	// Loopback MX (`0 localhost.`, `10 127.0.0.1`, `::1`) — a misconfiguration, NOT an
	// RFC 7505 no-mail declaration (#944; the measurement and the reasoning live in the
	// `isNullMxRecord` decision record). Reported once for the whole set, and the
	// loopback records are then EXCLUDED from the IP-target and dangling-MX passes
	// below: severity penalties are additive and `mx` has no cap, so letting one
	// condition pay two or three mediums would zero a category over a single defect.
	// This finding REPLACES those, keeping the measured population at one `medium`.
	const loopbackRecords = usableRecords.filter(isLoopbackMxRecord);
	if (loopbackRecords.length > 0) {
		findings.push(getLoopbackMxFinding(loopbackRecords));
	}
	const routableRecords = usableRecords.filter((r) => !isLoopbackMxRecord(r));

	findings.push(...getIpTargetFindings(routableRecords));

	// Check for dangling MX records (hostnames that don't resolve)
	const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
	const hostnameRecords = routableRecords.filter((r) => !ipPattern.test(r.exchange));
	const resolutions = await Promise.all(
		hostnameRecords.map(async (r) => {
			// A lookup that THREW or answered SERVFAIL/REFUSED measured nothing about the target, so
			// it can only support "resolves" — never "dangling" (SQ-279; a timeout is not absence).
			const probe = async (type: 'A' | 'AAAA'): Promise<{ resolved: boolean; unmeasured: boolean }> => {
				try {
					const outcome = await queryWithRcode(queryDNS, r.exchange, type, timeout);
					return { resolved: outcome.records.length > 0, unmeasured: isInconclusiveRcode(outcome.rcode) };
				} catch {
					return { resolved: false, unmeasured: true };
				}
			};
			const [a, aaaa] = await Promise.all([probe('A'), probe('AAAA')]);
			return { record: r, resolved: a.resolved || aaaa.resolved, unmeasured: a.unmeasured || aaaa.unmeasured };
		}),
	);
	for (const { record, resolved, unmeasured } of resolutions) {
		if (!resolved && !unmeasured) {
			findings.push(
				createFinding(
					'mx',
					'Dangling MX record',
					'medium',
					`MX target "${record.exchange}" does not resolve to any A or AAAA record. Mail delivery to this host will fail.`,
				),
			);
		}
	}

	// Check for single MX (no redundancy).
	//
	// Deliberately counts every non-invalid record (loopback included), not `routableRecords` (#944 review). Two
	// reasons, both load-bearing — do not "tidy" this to `routableRecords`:
	//   1. It would MOVE SCORES on the very population this change is about. The
	//      measured shape is a lone `0 localhost.`; filtering leaves zero routable
	//      records, `getSingleMxFinding` returns null on `length !== 1`, and the
	//      domain scores 85 instead of the 80 it scores today — a silent leniency
	//      change wearing the costume of a cleanup.
	//   2. The behaviour predates #944 (it counted every record before loopback
	//      classification existed), so leaving it is preservation, not oversight.
	//
	// Known residual, also pre-#944 and deliberately not fixed here: a zone
	// publishing one real exchange BESIDE a loopback one has no actual redundancy
	// but escapes this finding, because the raw count is 2. Correcting that is a
	// scoring change in its own right and belongs in its own PR with its own
	// version bump, not smuggled in beside a false-positive fix.
	const singleMxFinding = getSingleMxFinding(usableRecords);
	if (singleMxFinding) {
		findings.push(singleMxFinding);
	}

	// Real mail-routing MX records present → mail control present.
	return buildCheckResult('mx', findings, true);
}
