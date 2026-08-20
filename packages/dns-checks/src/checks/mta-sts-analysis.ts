// SPDX-License-Identifier: BUSL-1.1

/**
 * MTA-STS analysis helpers.
 * Pure functions for analyzing MTA-STS TXT records, policy files, and TLS-RPT records.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { Finding } from '../types';
import { createFinding } from '../check-utils';

/**
 * MTA_STS_ABSENCE_IS_GRADED_NOT_ZEROING — why no MTA-STS absence path sets `missingControl: true`.
 *
 * A `missingControl: true` finding zeroes its whole category (`passed` false, score 0).
 * That is the right shape for a control whose absence genuinely distinguishes domains.
 * MTA-STS is not one: measured over a 1,000-domain corpus (2026-08-03), the `mta_sts`
 * category had a mean score of 3.3 with **96.5% of the 687 measured domains scoring
 * exactly 0**. A control ~nobody deploys separates nobody — it is a flat constant
 * penalty consuming 3 of the ~80 base points on almost every domain, not a discriminator.
 * Independent review also found no documented incident attributable to a missing MTA-STS
 * policy, against a ~29.6% misconfiguration rate among the domains that do adopt it.
 *
 * So MTA-STS absence is now a GRADED finding (severity `medium`/`low`, ordinary severity
 * penalty) rather than a category-zeroing missing control — the same treatment CAA,
 * SVCB-HTTPS and TLS-RPT already get for exactly this reason.
 *
 * The weight (3, protective tier) is deliberately UNCHANGED.
 */

/**
 * MTA_STS_PARTIAL_DEPLOYMENT_BEATS_NONE — why every DEPLOYED-BUT-BROKEN policy finding is
 * graded `medium` with an explicit `penaltyOverride`, and never `high`.
 *
 * A domain that published an MTA-STS policy and got one RFC-required field wrong has
 * strictly better posture than one that never deployed at all. Until 2026-08-20 the scoring
 * said the opposite, and it was MEASURED end-to-end:
 *
 *     no MTA-STS at all ............ 85 / passed
 *     `mode: none` (protection OFF)  85 / passed
 *     policy does not cover its MX . 75 / passed
 *     policy omits `max_age` ....... **0 / FAILED**
 *
 * Cause: the four policy-defect findings below carry the word "missing" in their TITLE, and
 * `MISSING_CONTROL_REGEX` (`scoring/model.ts`) matches title OR detail. At `high` severity
 * with `deterministic` confidence that ZEROES the whole category instead of deducting. It
 * was an accident of prose, not a decision — the MX-not-covered branch is the same class of
 * defect at the same severity and escaped only because its wording happens to say "is not
 * matched by any mx: entry" rather than "missing".
 *
 * This block previously asserted that those findings "already carry no `missingControl`".
 * That statement was FALSE for four of them, and load-bearing: it is what let the defect
 * survive review. It is replaced here, and the guarantee has been moved OUT of prose.
 *
 * The graded ladder, pinned by test:
 *
 *     valid enforce 100 > testing 95 > MX-coverage gap 90 > RFC-invalid policy 88
 *                       > `mode: none` 85 = no MTA-STS at all 85
 *
 * `mode: none` is deliberately left TIED with silence rather than pushed below it: RFC 8461
 * §5 designates `mode: none` as the sanctioned graceful-withdrawal path for an existing
 * policy, so scoring it worse than absence would penalise the RFC-prescribed removal
 * procedure.
 *
 * `medium` is load-bearing TWICE. It sits below the severity floor
 * `scoreIndicatesMissingControl` requires, which also disarms the interpolation hazard:
 * these findings interpolate the scanned domain and its MX hostnames into their text, so at
 * `high` a domain merely NAMED `missing*` / `required*` had its category zeroed by its own
 * name (measured 2026-08-20 — an unfetchable policy scored 75 for `example.com` and 0 for
 * `missingkids.org`). `penaltyOverride` then restores triage granularity that the coarse
 * severity ladder (5/15/25) cannot express, exactly as documented on
 * `computeCategoryScore`.
 *
 * THE GUARANTEE IS THE TEST, NOT THIS COMMENT:
 * `src/__tests__/checks/mta-sts-scoring-ladder.test.ts` pins the ordering, asserts
 * `scoreIndicatesMissingControl([finding]) === false` for every finding emitted here and in
 * `check-mta-sts.ts`, proves the score does not move with the scanned domain's name, and
 * plants a positive control so a guard that stops finding violations cannot pass unnoticed.
 *
 * Known and intentional: a policy failing EVERY RFC-required field stacks these deductions
 * and lands below the absence baseline. A published policy body that is wholly invalid is
 * misleading rather than merely incomplete; any SINGLE defect stays strictly above it.
 */

/**
 * Deduction for a policy that is published but not RFC 8461-valid (bad `version:`, no
 * `mode:`, no `mx:`, no `max_age:`) or not retrievable. Conforming senders ignore such a
 * policy, so the control is non-functional — but the operator ran the DNS record and the
 * HTTPS host, which absence does not. Sized to sit just above the graded-absence baseline
 * of 85. See MTA_STS_PARTIAL_DEPLOYMENT_BEATS_NONE.
 */
export const MTA_STS_POLICY_DEFECT_PENALTY = 12;

/**
 * Deduction for a VALID, enforcing policy that leaves one of the domain's own MX hosts
 * outside its `mx:` coverage. Strictly less than {@link MTA_STS_POLICY_DEFECT_PENALTY}:
 * the control is live and protecting the covered hosts, whereas an RFC-invalid policy
 * protects nothing. The mail-delivery consequence is carried by the finding text, not by
 * a category zeroing. See MTA_STS_PARTIAL_DEPLOYMENT_BEATS_NONE.
 */
export const MTA_STS_MX_COVERAGE_GAP_PENALTY = 10;

/**
 * Parse the `_mta-sts` TXT RRset into findings. Reports absence, duplicate records, and a
 * missing `id=` tag; the caller supplies the domain-specific detail via
 * {@link finalizeMissingMtaStsRecordFinding}.
 */
export function getMtaStsTxtFindings(records: string[]): { findings: Finding[]; hasTxtRecord: boolean } {
	const findings: Finding[] = [];
	const mtaStsRecords = records.filter((record) => /^v=stsv1[;\s]/i.test(record));

	if (mtaStsRecords.length === 0) {
		// NO `missingControl: true` — see MTA_STS_ABSENCE_IS_GRADED_NOT_ZEROING above.
		// Absence is a graded `medium`, not a category-zeroing missing control.
		return {
			findings: [createFinding('mta_sts', 'No MTA-STS record found', 'medium', '')],
			hasTxtRecord: false,
		};
	}

	if (mtaStsRecords.length > 1) {
		findings.push(
			createFinding('mta_sts', 'Multiple MTA-STS records', 'medium', `Found ${mtaStsRecords.length} MTA-STS records. Only one should exist.`),
		);
	}

	if (!mtaStsRecords[0].includes('id=')) {
		findings.push(
			createFinding(
				'mta_sts',
				'MTA-STS missing id tag',
				'medium',
				'MTA-STS record is missing the "id=" tag. This tag is required for policy versioning.',
			),
		);
	}

	return { findings, hasTxtRecord: true };
}

/**
 * Re-emits the placeholder "No MTA-STS record found" finding with the domain-specific
 * detail text. Carries NO `missingControl` — see MTA_STS_ABSENCE_IS_GRADED_NOT_ZEROING.
 */
export function finalizeMissingMtaStsRecordFinding(findings: Finding[], domain: string): Finding[] {
	return findings.map((finding) =>
		finding.title === 'No MTA-STS record found'
			? createFinding(
					'mta_sts',
					'No MTA-STS record found',
					'medium',
					`No MTA-STS TXT record found at _mta-sts.${domain}. MTA-STS enforces TLS for incoming email, preventing downgrade attacks.`,
				)
			: finding,
	);
}

export function getMtaStsPolicyFindings(body: string, policyUrl: string): Finding[] {
	const findings: Finding[] = [];
	const versionMatch = body.match(/version:\s*(\S+)/i);
	if (!versionMatch || versionMatch[1] !== 'STSv1') {
		findings.push(
			createFinding(
				'mta_sts',
				'MTA-STS policy missing or invalid version',
				'medium',
				'The MTA-STS policy must contain "version: STSv1" as required by RFC 8461.',
				{ penaltyOverride: MTA_STS_POLICY_DEFECT_PENALTY },
			),
		);
	}

	const modeMatch = body.match(/mode:\s*(enforce|testing|none)/i);

	if (!modeMatch) {
		findings.push(
			createFinding('mta_sts', 'MTA-STS policy missing mode', 'medium', 'MTA-STS policy file does not contain a valid "mode:" directive.', {
				penaltyOverride: MTA_STS_POLICY_DEFECT_PENALTY,
			}),
		);
	} else {
		const mode = modeMatch[1].toLowerCase();
		if (mode === 'testing') {
			findings.push(
				createFinding('mta_sts', 'MTA-STS in testing mode', 'low', 'MTA-STS policy is in "testing" mode. Consider switching to "enforce" once verified.'),
			);
		} else if (mode === 'none') {
			findings.push(
				createFinding('mta_sts', 'MTA-STS policy disabled', 'medium', 'MTA-STS policy mode is "none", effectively disabling MTA-STS protection.'),
			);
		}
	}

	if (!body.includes('mx:')) {
		findings.push(
			createFinding(
				'mta_sts',
				'MTA-STS policy missing MX entries',
				'medium',
				'MTA-STS policy file does not contain any "mx:" entries. At least one MX pattern is required.',
				{ penaltyOverride: MTA_STS_POLICY_DEFECT_PENALTY },
			),
		);
	}

	const maxAgeMatch = body.match(/max_age:\s*(\d+)/i);
	if (!maxAgeMatch) {
		findings.push(
			createFinding(
				'mta_sts',
				'MTA-STS policy missing max_age',
				'medium',
				'The max_age directive is required by RFC 8461. Without it, the policy is technically invalid.',
				{ penaltyOverride: MTA_STS_POLICY_DEFECT_PENALTY },
			),
		);
	} else {
		const maxAge = parseInt(maxAgeMatch[1], 10);
		if (maxAge < 86400) {
			findings.push(
				createFinding(
					'mta_sts',
					'MTA-STS max_age too short',
					'low',
					`MTA-STS max_age is ${maxAge} seconds (less than 1 day). A short max_age reduces the effectiveness of MTA-STS protection.`,
				),
			);
		} else if (maxAge > 31557600) {
			findings.push(
				createFinding(
					'mta_sts',
					'MTA-STS max_age exceeds one year',
					'info',
					`MTA-STS max_age is ${maxAge} seconds (more than 1 year). This is acceptable but noted.`,
				),
			);
		}
	}

	if (findings.length === 0) {
		return [];
	}

	// `finding.metadata` MUST be forwarded: this re-emit carries the `penaltyOverride` that
	// sizes the deduction (see MTA_STS_PARTIAL_DEPLOYMENT_BEATS_NONE). Dropping it silently
	// reverted these two findings to the coarse severity default.
	return findings.map((finding) =>
		finding.title === 'MTA-STS policy missing mode' || finding.title === 'MTA-STS policy missing MX entries'
			? createFinding(
					'mta_sts',
					finding.title,
					finding.severity,
					finding.detail.replace('MTA-STS policy file', `MTA-STS policy file at ${policyUrl}`),
					finding.metadata,
				)
			: finding,
	);
}

export function extractPolicyMxPatterns(body: string): string[] {
	return [...body.matchAll(/mx:\s*(\S+)/gi)].map((match) => match[1].toLowerCase());
}

export function matchesMxPattern(hostname: string, pattern: string): boolean {
	if (pattern.startsWith('*.')) {
		const suffix = pattern.slice(1);
		return hostname.endsWith(suffix) || hostname === pattern.slice(2);
	}

	return hostname === pattern;
}

export function getUncoveredMxHostFindings(mxHosts: string[], policyMxPatterns: string[]): Finding[] {
	return mxHosts.flatMap((mxHost) => {
		const hostname = mxHost.toLowerCase();
		const covered = policyMxPatterns.some((pattern) => matchesMxPattern(hostname, pattern));
		if (covered) {
			return [];
		}

		// `medium`, not `high`: both the title and the detail interpolate `mxHost`, a
		// hostname this scanner does not control. At `high` an MX named `mail.missing*`
		// would zero the whole category via `MISSING_CONTROL_REGEX`. See
		// MTA_STS_PARTIAL_DEPLOYMENT_BEATS_NONE.
		return [
			createFinding(
				'mta_sts',
				`MTA-STS policy does not cover MX host ${mxHost}`,
				'medium',
				`The MX host ${mxHost} is not matched by any mx: entry in the MTA-STS policy. Mail delivered to this MX will fail MTA-STS validation.`,
				{ penaltyOverride: MTA_STS_MX_COVERAGE_GAP_PENALTY },
			),
		];
	});
}

export function hasValidTlsRptRecord(records: string[]): boolean {
	return records.some((record) => record.toLowerCase().startsWith('v=tlsrptv1'));
}

export function getTlsRptRecordFindings(records: string[]): { findings: Finding[]; hasTlsRptRecord: boolean } {
	const validRecords = records.filter((record) => record.toLowerCase().startsWith('v=tlsrptv1'));
	if (validRecords.length === 0) {
		return {
			findings: [
				createFinding(
					'mta_sts',
					'TLS-RPT record missing',
					'low',
					'',
				),
			],
			hasTlsRptRecord: false,
		};
	}

	const tlsrptRecord = validRecords[0];
	const ruaMatch = tlsrptRecord.match(/rua\s*=\s*([^;\s]+)/i);
	if (!ruaMatch) {
		return {
			findings: [
				createFinding(
					'mta_sts',
					'TLS-RPT missing rua directive',
					'low',
					'TLS-RPT record does not contain a "rua=" directive. The rua URI is needed to receive TLS failure reports.',
				),
			],
			hasTlsRptRecord: true,
		};
	}

	const ruaValue = ruaMatch[1];
	const isValidMailto = /^mailto:[^@\s]+@[^@\s]+\.[^@\s]+$/.test(ruaValue);
	const isValidHttps = /^https:\/\/.+/.test(ruaValue);
	if (!isValidMailto && !isValidHttps) {
		return {
			findings: [
				createFinding(
					'mta_sts',
					'TLS-RPT invalid rua format',
					'medium',
					`TLS-RPT rua value "${ruaValue}" is not a valid mailto: or https: URI.`,
				),
			],
			hasTlsRptRecord: true,
		};
	}

	return { findings: [], hasTlsRptRecord: true };
}

export function finalizeMissingTlsRptRecordFinding(findings: Finding[], domain: string): Finding[] {
	return findings.map((finding) =>
		finding.title === 'TLS-RPT record missing'
			? createFinding(
					'mta_sts',
					'TLS-RPT record missing',
					'low',
					`No TLS-RPT record found at _smtp._tls.${domain}. Consider adding a TLS-RPT record for reporting SMTP TLS issues.`,
				)
			: finding,
	);
}

export function shouldSummarizeMissingMailProtections(findings: Finding[], hasTxtRecord: boolean, tlsRptChecked: boolean, hasTlsRptRecord: boolean): boolean {
	const hasDnsErrorFindings = findings.some((finding) => finding.title.includes('DNS query failed'));
	return !hasTxtRecord && tlsRptChecked && !hasTlsRptRecord && !hasDnsErrorFindings;
}
