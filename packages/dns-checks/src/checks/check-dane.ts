// SPDX-License-Identifier: BUSL-1.1

/**
 * DANE (DNS-Based Authentication of Named Entities) check — EMAIL ONLY.
 * Validates TLSA records for MX servers (_25._tcp.{mx-host}).
 * HTTPS DANE (_443._tcp) is handled by the dedicated check-dane-https.ts.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { CheckResult, DNSQueryFunction, Finding, RawDNSQueryFunction, RawDNSResponse } from '../types';
import { buildCheckResult, createFinding } from '../check-utils';
import { analyzeTlsaRecords } from './dane-analysis';

/**
 * DNS rcodes (RFC 1035 §4.1.1) that mean "the resolver could not answer" rather than
 * "no such record exists". A DoH endpoint returns HTTP 200 carrying one of these with
 * an EMPTY answer set, so nothing throws and the `DNSQueryFunction` (`string[]`)
 * projection renders them indistinguishable from a genuine NODATA.
 *
 * NXDOMAIN (3) is deliberately NOT here: "this name does not exist" IS a measurement,
 * and a name that does not exist accepts no mail.
 */
const RCODE_SERVFAIL = 2;
const RCODE_REFUSED = 5;

/**
 * Corroborate an EMPTY MX answer before claiming SMTP DANE is not applicable (#639).
 *
 * Returns normally when the empty answer is a MEASUREMENT (the domain genuinely
 * publishes no usable MX). THROWS when it is a measurement FAILURE, so the caller
 * files the check INCONCLUSIVE instead of awarding a perfect score for a control it
 * never actually evaluated.
 *
 * Costs one extra DNS query, and only on the branch that was already about to make a
 * not-applicable claim — the happy path (a domain with real MX hosts) never reaches
 * here, so no cleanly-resolving mail domain pays for it.
 *
 * Degrades honestly: a consumer that supplies no `rawQueryDNS` has no rcode channel at
 * all, so there is nothing to corroborate against and the prior behaviour stands. The
 * Worker wrapper (`src/tools/check-dane.ts`) always supplies one.
 */
async function assertEmptyMxIsAMeasurement(domain: string, rawQueryDNS: RawDNSQueryFunction | undefined, timeout: number): Promise<void> {
	if (!rawQueryDNS) return;

	let response: RawDNSResponse;
	try {
		response = await rawQueryDNS(domain, 'MX', false, { timeout });
	} catch {
		// The primary lookup returned an ambiguous empty set and the corroborating probe
		// failed outright — we still cannot tell "no mail" from "could not resolve".
		// Prefix per sanitizeErrorMessage/buildDnsErrorResult's allowlist.
		throw new Error(`DNS query for MX records of ${domain} failed; SMTP DANE applicability could not be determined`);
	}

	if (response.Status === RCODE_SERVFAIL || response.Status === RCODE_REFUSED) {
		const rcode = response.Status === RCODE_SERVFAIL ? 'SERVFAIL' : 'REFUSED';
		throw new Error(
			`DNS query for MX records of ${domain} returned ${rcode}; the zone could not be resolved, so SMTP DANE applicability is undetermined`,
		);
	}
}

/**
 * Parse MX records from raw DNS response strings.
 */
function parseMxFromRaw(answers: string[]): Array<{ exchange: string }> {
	return answers.map((answer) => {
		const parts = answer.split(' ');
		const exchange = (parts.slice(1).join(' ') || '').replace(/\.$/, '').toLowerCase();
		return { exchange };
	});
}

/**
 * Check DANE TLSA records for a domain's MX servers (email DANE only).
 *
 * Emits exactly one of THREE states, which this check previously collapsed (#639):
 *
 * - **NOT APPLICABLE** — the MX lookup succeeded and the domain publishes no usable MX
 *   (none, or an RFC 7505 null MX), so there is no SMTP endpoint to DANE-pin. An `info`
 *   finding; `scan_domain` reports the category `n/a` via `notApplicableCategories`.
 * - **INCONCLUSIVE** — the MX lookup could not be made (it threw, or the resolver
 *   answered SERVFAIL/REFUSED). This function THROWS; the caller — the Worker wrapper's
 *   `buildDnsErrorResult`, or `scan_domain`'s `safeCheck` — converts it to a
 *   `checkStatus: 'error'` result that scoring EXCLUDES as a transient failure.
 *   Previously this was swallowed into a `low` finding scoring 95, i.e. a failed
 *   measurement presented as a near-perfect one.
 * - **MISSING** — the domain accepts mail but publishes no TLSA. A `medium` finding.
 *
 * @throws when the domain's MX records could not be resolved (the INCONCLUSIVE state).
 */
export async function checkDANE(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number; rawQueryDNS?: RawDNSQueryFunction },
): Promise<CheckResult> {
	const timeout = options?.timeout ?? 5000;
	const rawQueryDNS = options?.rawQueryDNS;
	const findings: Finding[] = [];
	let hasMxTlsa = false;
	let realMxHosts = 0;

	// Query MX records and check TLSA for each MX host.
	// Per RFC 7672 §3.1.3, SMTP DANE security requires DNSSEC on the MX host's zone —
	// not the sending domain. We check the AD flag per MX host, not the main domain.
	//
	// A throw from THIS query is deliberately not caught: it is a measurement failure,
	// and the only honest thing to report is that we could not measure. The per-host
	// TLSA/AD queries below keep their own `catch` — those are genuinely best-effort
	// enrichment of a lookup that already succeeded.
	const mxAnswers = await queryDNS(domain, 'MX', { timeout });
	const mxRecords = parseMxFromRaw(mxAnswers);

	for (const mx of mxRecords) {
		const mxHost = mx.exchange;
		// Empty exchange or RFC 7505 null MX ("0 .") = the domain explicitly does
		// not accept inbound mail. Such hosts carry no SMTP endpoint to DANE-pin.
		if (!mxHost || mxHost === '.') continue;
		realMxHosts++;

		// Check DNSSEC on the MX host's zone (RFC 7672 §3.1.3)
		let mxHasDnssec = false;
		if (rawQueryDNS) {
			try {
				const resp = await rawQueryDNS(mxHost, 'A', true, { timeout });
				mxHasDnssec = resp.AD === true;
			} catch {
				// DNSSEC check for MX host failed — treat as unsigned
			}
		}

		const tlsaName = `_25._tcp.${mxHost}`;
		try {
			const tlsaRecords = await queryDNS(tlsaName, 'TLSA', { timeout });
			if (tlsaRecords.length > 0) {
				hasMxTlsa = true;
				findings.push(...analyzeTlsaRecords(tlsaRecords, tlsaName, mxHasDnssec));
			}
		} catch {
			// Individual MX TLSA query failed — skip this host
		}
	}

	// Step 3: classify absence. Branch on whether the domain actually accepts mail
	// (DANE-email-1): a domain with no MX (or only a null MX) does not receive email,
	// so SMTP DANE is not applicable — that is an INFO note (score 100), NOT a medium
	// deficiency. Only a mail-accepting domain that omits TLSA is a real gap (medium →
	// 85). This mirrors the MTA-STS no-inbound-mail fork and prevents parked/web-only
	// domains from being dinged for an email control they don't need.
	if (!hasMxTlsa && findings.every((f) => f.severity !== 'medium' || !f.title.includes('Malformed'))) {
		if (realMxHosts === 0) {
			// An EMPTY MX answer is not self-evidently a measurement — SERVFAIL and REFUSED
			// both arrive here looking identical to NODATA. Corroborate before claiming
			// not-applicable; this throws (→ INCONCLUSIVE) when it cannot be corroborated.
			await assertEmptyMxIsAMeasurement(domain, rawQueryDNS, timeout);
			findings.push(
				createFinding(
					'dane',
					'SMTP DANE not applicable (no inbound mail)',
					'info',
					`${domain} publishes no usable MX records (none, or an RFC 7505 null MX), so it does not accept inbound email. SMTP DANE (TLSA at _25._tcp) is therefore not applicable.`,
				),
			);
		} else {
			findings.push(
				createFinding(
					'dane',
					'No DANE TLSA for MX servers',
					'medium',
					'No TLSA records found for MX server SMTP ports (_25._tcp). DANE pins TLS certificates to DNS, preventing CA misissuance attacks on email delivery.',
				),
			);
		}
	}

	// Step 5: Handle case where all DNS queries failed
	if (findings.length === 0) {
		findings.push(
			createFinding(
				'dane',
				'DANE check inconclusive',
				'medium',
				`DNS queries for DANE TLSA records failed for ${domain}. Unable to determine DANE status.`,
			),
		);
	}

	return buildCheckResult('dane', findings);
}
