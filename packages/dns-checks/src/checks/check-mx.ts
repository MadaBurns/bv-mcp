// SPDX-License-Identifier: BUSL-1.1

/**
 * MX record check.
 * Validates presence and quality of MX records for a domain.
 *
 * Copyright (c) 2023-2026 BlackVeil Security Ltd.
 * Licensed under BSL 1.1
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
		const findings: Finding[] = [
			createFinding(
				'mx',
				'No MX records found',
				'medium',
				'No mail exchange records present. If this domain does not handle email, consider publishing a null MX record (RFC 7505).',
				{ missingControl: true },
			),
		];
		// Non-mail domains should publish v=spf1 -all to explicitly reject all mail
		try {
			const txtRecords = await queryDNS(domain, 'TXT', { timeout });
			const spfRecords = txtRecords.filter((r) => r.toLowerCase().startsWith('v=spf1'));
			if (spfRecords.length === 0) {
				findings.push(
					createFinding(
						'mx',
						'Missing SPF reject-all for non-mail domain',
						'medium',
						`No SPF record found. Non-mail domains should publish "v=spf1 -all" to explicitly prevent email spoofing.`,
					),
				);
			} else {
				const spf = spfRecords[0].toLowerCase();
				if (!spf.includes('-all')) {
					findings.push(
						createFinding(
							'mx',
							'SPF not set to reject-all for non-mail domain',
							'low',
							`SPF record found but does not use "-all" (hard fail). Non-mail domains should publish "v=spf1 -all" to explicitly reject all email.`,
						),
					);
				}
			}
		} catch {
			// DNS query failed — skip SPF check for non-mail domain
		}
		return buildCheckResult('mx', findings);
	}

	const findings: Finding[] = [];

	const mxRecords = parseMxRecords(answers);

	// Check for null MX (RFC 7505: priority 0, exchange ".")
	const nullMx = mxRecords.find(isNullMxRecord);
	if (nullMx) {
		findings.push(getNullMxFinding());
		return buildCheckResult('mx', findings);
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

	return buildCheckResult('mx', findings);
}
