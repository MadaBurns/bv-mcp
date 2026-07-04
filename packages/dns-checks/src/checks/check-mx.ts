// SPDX-License-Identifier: BUSL-1.1

/**
 * MX record check.
 * Validates presence and quality of MX records for a domain.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { CheckResult, DNSQueryFunction, Finding } from '../types';
import { buildCheckResult, createFinding } from '../check-utils';
import { getIpTargetFindings, getNullMxFinding, getPresenceFinding, getSingleMxFinding, isNullMxRecord, parseMxRecords } from './mx-analysis';

/**
 * Check MX record configuration for a domain.
 * Validates MX records exist, checks for null MX, IP targets, dangling records,
 * and single MX (no redundancy).
 *
 * Note: Provider detection from the original check is omitted here as it depends
 * on external provider signature files. Consumers can implement provider detection
 * as a post-processing step.
 */
export async function checkMX(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number },
): Promise<CheckResult> {
	const timeout = options?.timeout ?? 5000;
	let answers: string[];
	try {
		answers = await queryDNS(domain, 'MX', { timeout });
	} catch {
		return buildCheckResult('mx', [createFinding('mx', 'DNS query failed', 'medium', 'MX record lookup failed')]);
	}

	if (!answers || answers.length === 0) {
		// No MX: scoring is SPF-CONTEXT-dependent, NOT an unconditional missing control.
		// NIST SP 800-177r1 §4.4.2 — a non-mail domain SHOULD publish "v=spf1 -all";
		// when it does, that is the correct posture (reward, do not penalize). Only a
		// domain with no MX AND no/soft SPF is genuinely spoofable (the real gap).
		let spf = '';
		try {
			const txtRecords = await queryDNS(domain, 'TXT', { timeout });
			spf = (txtRecords.find((r) => r.toLowerCase().startsWith('v=spf1')) ?? '').toLowerCase();
		} catch {
			// TXT query failed — treat as no SPF.
		}

		let finding: Finding;
		if (spf.includes('-all')) {
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
		// No MX records → mail control definitively absent (controlPresent: false).
		return buildCheckResult('mx', [finding], false);
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

	findings.push(getPresenceFinding(mxRecords));

	findings.push(...getIpTargetFindings(mxRecords));

	// Check for dangling MX records (hostnames that don't resolve)
	const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
	const hostnameRecords = mxRecords.filter((r) => !ipPattern.test(r.exchange));
	const resolutions = await Promise.all(
		hostnameRecords.map(async (r) => {
			try {
				const [a, aaaa] = await Promise.all([
					queryDNS(r.exchange, 'A', { timeout }).catch(() => []),
					queryDNS(r.exchange, 'AAAA', { timeout }).catch(() => []),
				]);
				return { record: r, resolved: a.length > 0 || aaaa.length > 0 };
			} catch {
				return { record: r, resolved: false };
			}
		}),
	);
	for (const { record, resolved } of resolutions) {
		if (!resolved) {
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

	// Check for single MX (no redundancy)
	const singleMxFinding = getSingleMxFinding(mxRecords);
	if (singleMxFinding) {
		findings.push(singleMxFinding);
	}

	// Real mail-routing MX records present → mail control present.
	return buildCheckResult('mx', findings, true);
}
