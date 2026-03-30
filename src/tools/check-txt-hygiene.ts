// SPDX-License-Identifier: BUSL-1.1

/**
 * TXT Record Hygiene check tool.
 *
 * Audits TXT records for governance and security concerns including:
 * - Geopolitical jurisdiction risks (Yandex/Baidu on government domains)
 * - Record accumulation and clutter
 * - Stale service integrations
 * - Misplaced DMARC records
 * - Cross-domain trust delegation
 */

import { queryTxtRecords } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import { getEffectiveTld } from '../lib/public-suffix';
import { validateDomain } from '../lib/sanitize';
import type { CheckResult, Finding } from '../lib/scoring';
import { buildCheckResult, createFinding } from '../lib/scoring';
import { type VerificationCategory, VERIFICATION_PATTERNS, SERVICE_SPF_DOMAINS } from './txt-hygiene-analysis';

// ─── Government TLD detection ────────────────────────────────────────────────

const GOVERNMENT_TLDS = new Set([
	'govt.nz',
	'gov.au',
	'gov.uk',
	'gov.za',
	'gov.in',
	'go.jp',
	'gov.sg',
	'gov',
	'mil',
	'edu',
	'ac.nz',
	'ac.uk',
	'ac.jp',
]);

function isGovernmentDomain(domain: string): boolean {
	const tld = getEffectiveTld(domain);
	if (!tld) return false;
	return GOVERNMENT_TLDS.has(tld);
}

// ─── SPF include extraction ─────────────────────────────────────────────────

function extractSpfIncludes(txtRecords: string[]): string[] {
	const spfRecord = txtRecords.find((r) => r.toLowerCase().startsWith('v=spf1'));
	if (!spfRecord) return [];
	const includes: string[] = [];
	const regex = /\binclude:(\S+)/gi;
	let match: RegExpExecArray | null;
	while ((match = regex.exec(spfRecord)) !== null) {
		includes.push(match[1].toLowerCase());
	}
	return includes;
}

// ─── Hygiene rating ──────────────────────────────────────────────────────────

function getHygieneRating(recordCount: number): string {
	if (recordCount >= 15) return 'Excessive';
	if (recordCount >= 10) return 'Cluttered';
	if (recordCount >= 5) return 'Moderate';
	return 'Clean';
}

// ─── Main check function ─────────────────────────────────────────────────────

/**
 * Check TXT record hygiene for a domain.
 *
 * Audits root TXT records for governance concerns including jurisdiction
 * risks, record accumulation, stale integrations, and misplaced records.
 */
export async function checkTxtHygiene(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	const findings: Finding[] = [];

	// Defense-in-depth: validate domain even though upstream dispatch already validates
	const validation = validateDomain(domain);
	if (!validation.valid) {
		return buildCheckResult('txt_hygiene', [
			createFinding('txt_hygiene', 'Invalid domain', 'info', `Domain validation failed: ${validation.error ?? 'invalid input'}.`),
		]);
	}

	// Step 1: Fetch root TXT and _dmarc TXT in parallel (allSettled to tolerate partial failure)
	const [rootResult, dmarcResult] = await Promise.allSettled([
		queryTxtRecords(domain, dnsOptions),
		queryTxtRecords(`_dmarc.${domain}`, dnsOptions),
	]);
	const rootTxtRecords = rootResult.status === 'fulfilled' ? rootResult.value : [];
	const dmarcTxtRecords = dmarcResult.status === 'fulfilled' ? dmarcResult.value : [];

	// Handle no TXT records
	if (rootTxtRecords.length === 0) {
		findings.push(
			createFinding(
				'txt_hygiene',
				'No TXT records found',
				'info',
				`No TXT records found for ${domain}. This is unusual but not necessarily a problem.`,
			),
		);
		findings.push(
			createFinding(
				'txt_hygiene',
				'TXT record hygiene summary',
				'info',
				`TXT record hygiene rating: Clean (0 records). No governance concerns detected.`,
			),
		);
		return buildCheckResult('txt_hygiene', findings);
	}

	// Step 2: Pattern match TXT records
	interface MatchedService {
		service: string;
		category: VerificationCategory;
		jurisdiction?: string;
		prefix: string;
		record: string;
	}

	const matchedServices: MatchedService[] = [];

	for (const record of rootTxtRecords) {
		// Skip SPF records — they are expected, not verification
		if (record.toLowerCase().startsWith('v=spf1')) continue;

		for (const pattern of VERIFICATION_PATTERNS) {
			if (record.startsWith(pattern.prefix) || record.toLowerCase().startsWith(pattern.prefix.toLowerCase())) {
				matchedServices.push({
					service: pattern.service,
					category: pattern.category,
					jurisdiction: pattern.jurisdiction,
					prefix: pattern.prefix,
					record,
				});
				break; // Only match first pattern per record
			}
		}
	}

	// Step 3: Generate findings

	// --- Geopolitical jurisdiction findings ---
	const govDomain = isGovernmentDomain(domain);
	const domainTld = getEffectiveTld(domain);

	for (const match of matchedServices) {
		if (match.jurisdiction === 'RU') {
			// Don't flag on native .ru domains
			if (domainTld === 'ru') continue;

			if (govDomain) {
				findings.push(
					createFinding(
						'txt_hygiene',
						'Russian jurisdiction service on government domain',
						'high',
						`${match.service} verification record found on government domain ${domain}. This service operates under Russian jurisdiction and may pose data sovereignty concerns.`,
						{ service: match.service, jurisdiction: 'RU', category: match.category },
					),
				);
			} else {
				findings.push(
					createFinding(
						'txt_hygiene',
						'Russian jurisdiction service verification detected',
						'medium',
						`${match.service} verification record found for ${domain}. This service operates under Russian jurisdiction. Consider whether this aligns with your organization's data governance policies.`,
						{ service: match.service, jurisdiction: 'RU', category: match.category },
					),
				);
			}
		} else if (match.jurisdiction === 'CN') {
			// Don't flag on native .cn domains
			if (domainTld === 'cn') continue;

			if (govDomain) {
				findings.push(
					createFinding(
						'txt_hygiene',
						'Chinese jurisdiction service on government domain',
						'high',
						`${match.service} verification record found on government domain ${domain}. This service operates under Chinese jurisdiction and may pose data sovereignty concerns.`,
						{ service: match.service, jurisdiction: 'CN', category: match.category },
					),
				);
			} else {
				findings.push(
					createFinding(
						'txt_hygiene',
						'Chinese jurisdiction service verification detected',
						'medium',
						`${match.service} verification record found for ${domain}. This service operates under Chinese jurisdiction. Consider whether this aligns with your organization's data governance policies.`,
						{ service: match.service, jurisdiction: 'CN', category: match.category },
					),
				);
			}
		}
	}

	// --- Record accumulation ---
	const recordCount = rootTxtRecords.length;
	if (recordCount >= 25) {
		findings.push(
			createFinding(
				'txt_hygiene',
				'Excessive TXT record accumulation',
				'medium',
				`Found ${recordCount} TXT records for ${domain}. Excessive records increase DNS response size, risk UDP truncation, and suggest poor lifecycle management. Review and remove unused verification records.`,
				{ recordCount },
			),
		);
	} else if (recordCount >= 15) {
		findings.push(
			createFinding(
				'txt_hygiene',
				'Elevated TXT record count',
				'low',
				`Found ${recordCount} TXT records for ${domain}. While common for large organizations, consider auditing for stale or unnecessary records to prevent future DNS response size issues.`,
				{ recordCount },
			),
		);
	} else if (recordCount >= 10) {
		findings.push(
			createFinding(
				'txt_hygiene',
				'TXT record accumulation',
				'low',
				`Found ${recordCount} TXT records for ${domain}. Consider auditing for stale or unnecessary records to prevent future DNS response size issues.`,
				{ recordCount },
			),
		);
	}

	// --- Duplicate verification records (consolidated into a single finding) ---
	const prefixCounts = new Map<string, { service: string; count: number }>();
	for (const match of matchedServices) {
		const existing = prefixCounts.get(match.prefix);
		if (existing) {
			existing.count++;
		} else {
			prefixCounts.set(match.prefix, { service: match.service, count: 1 });
		}
	}
	const duplicates: { service: string; count: number }[] = [];
	for (const [, { service, count }] of prefixCounts) {
		if (count >= 2) {
			duplicates.push({ service, count });
		}
	}
	if (duplicates.length > 0) {
		const details = duplicates.map((d) => `${d.service} (${d.count}x)`).join(', ');
		findings.push(
			createFinding(
				'txt_hygiene',
				'Duplicate verification records detected',
				'low',
				`Duplicate verification records found: ${details}. Duplicate records are unnecessary and may indicate incomplete migrations or stale configurations. Remove extras to reduce DNS clutter.`,
				{ duplicates },
			),
		);
	}

	// --- DMARC misplaced at root ---
	const dmarcAtRoot = rootTxtRecords.some((r) => r.toLowerCase().startsWith('v=dmarc1'));
	if (dmarcAtRoot) {
		const dmarcAtSubdomain = dmarcTxtRecords.some((r) => r.toLowerCase().startsWith('v=dmarc1'));
		findings.push(
			createFinding(
				'txt_hygiene',
				'DMARC record misplaced at root',
				'medium',
				`A DMARC record (v=DMARC1) was found at the root domain instead of the correct location (_dmarc.${domain}). ${dmarcAtSubdomain ? 'A properly placed record also exists at _dmarc — the root record is redundant and should be removed.' : 'Mail receivers query _dmarc.${domain}, so a root-level DMARC record has no effect.'}`,
			),
		);
	}

	// --- TrustedForDomainSharing ---
	const hasTrustedSharing = matchedServices.some((m) => m.prefix === 'TrustedForDomainSharing=');
	if (hasTrustedSharing) {
		findings.push(
			createFinding(
				'txt_hygiene',
				'Cross-domain trust delegation detected',
				'medium',
				`TrustedForDomainSharing record found for ${domain}. This delegates trust across domains and could be exploited if the trusted domain is compromised. Verify this delegation is intentional and actively needed.`,
			),
		);
	}

	// --- Stale integration detection (SPF cross-reference) ---
	const spfIncludes = extractSpfIncludes(rootTxtRecords);
	for (const match of matchedServices) {
		const spfDomains = SERVICE_SPF_DOMAINS[match.service];
		if (!spfDomains) continue;

		const hasSpfInclude = spfDomains.some((spfDomain) =>
			spfIncludes.some((include) => include.includes(spfDomain.toLowerCase())),
		);

		if (!hasSpfInclude) {
			findings.push(
				createFinding(
					'txt_hygiene',
					`Possible stale service integration: ${match.service}`,
					'low',
					`${match.service} verification record found but no corresponding SPF include detected. This may indicate the service is no longer actively used for email sending. Review and remove if the integration has been decommissioned.`,
					{ service: match.service, category: match.category },
				),
			);
		}
	}

	// --- Multiple MS= records (tenant migration residue) ---
	const msRecords = rootTxtRecords.filter((r) => r.startsWith('MS='));
	if (msRecords.length > 1) {
		findings.push(
			createFinding(
				'txt_hygiene',
				'Possible Microsoft tenant migration residue',
				'low',
				`Found ${msRecords.length} MS= verification records. Multiple MS= records typically indicate incomplete Microsoft 365 tenant migrations. Only the current tenant's record is needed.`,
				{ msRecordCount: msRecords.length },
			),
		);
	}

	// --- Info findings for each detected platform ---
	for (const match of matchedServices) {
		// Skip DMARC at root — already flagged above
		if (match.category === 'email_auth' && match.service === 'DMARC') continue;
		// Skip TrustedForDomainSharing — already flagged above
		if (match.prefix === 'TrustedForDomainSharing=') continue;

		findings.push(
			createFinding(
				'txt_hygiene',
				`Service verification detected: ${match.service}`,
				'info',
				`${match.service} domain verification record found (${match.category} category).`,
				{ service: match.service, category: match.category },
			),
		);
	}

	// --- Hygiene summary ---
	const rating = getHygieneRating(recordCount);
	findings.push(
		createFinding(
			'txt_hygiene',
			'TXT record hygiene summary',
			'info',
			`TXT record hygiene rating: ${rating} (${recordCount} records). ${matchedServices.length} service verification(s) detected.`,
			{ rating, recordCount, serviceCount: matchedServices.length },
		),
	);

	return buildCheckResult('txt_hygiene', findings);
}
