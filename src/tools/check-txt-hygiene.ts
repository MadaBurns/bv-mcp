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

	// Counts scored findings suppressed by per-service consolidation (jurisdiction +
	// stale integration). Reported as a single `info` notice at the end so the
	// de-duplication is VISIBLE rather than silent — mirrors the DKIM precedent
	// (`consolidateSelectorProbeKeyStrengthFindings` in dns-checks).
	let consolidatedScoredFindings = 0;

	// --- Geopolitical jurisdiction findings, ONE per distinct service (#642) ---
	// Previously this loop iterated `matchedServices` per RECORD, so a domain
	// publishing two Yandex verification records took the `medium` penalty TWICE
	// (-30) for a SINGLE governance condition. The penalty scaled with how many
	// copies of a record exist, not with how many distinct problems the domain has —
	// and record duplication is ALREADY charged separately by the `low` "Duplicate
	// verification records detected" finding below, so it was billed twice.
	// One scored finding per distinct service; multiplicity moves to metadata.
	// Distinct services still each accrue their own penalty (e.g. Yandex + Baidu
	// remain two findings) — only same-service repeats collapse.
	const govDomain = isGovernmentDomain(domain);
	const domainTld = getEffectiveTld(domain);

	const jurisdictionServices = new Map<string, { jurisdiction: string; category: VerificationCategory; records: string[] }>();
	for (const match of matchedServices) {
		if (match.jurisdiction !== 'RU' && match.jurisdiction !== 'CN') continue;
		// Don't flag on native .ru / .cn domains
		if (match.jurisdiction === 'RU' && domainTld === 'ru') continue;
		if (match.jurisdiction === 'CN' && domainTld === 'cn') continue;

		const existing = jurisdictionServices.get(match.service);
		if (existing) {
			existing.records.push(match.record);
			consolidatedScoredFindings++;
		} else {
			jurisdictionServices.set(match.service, {
				jurisdiction: match.jurisdiction,
				category: match.category,
				records: [match.record],
			});
		}
	}

	for (const [service, { jurisdiction, category, records }] of jurisdictionServices) {
		const jurisdictionLabel = jurisdiction === 'RU' ? 'Russian' : 'Chinese';
		const recordCount = records.length;
		// Keep the single-record phrasing byte-identical to the pre-#642 wording; the
		// multi-record variant states the count (individual records live in metadata).
		const foundClause = recordCount > 1 ? `${service} verification records found` : `${service} verification record found`;
		const countClause = recordCount > 1 ? ` (${recordCount} such records are published)` : '';
		const metadata = { service, jurisdiction, category, recordCount, records };

		if (govDomain) {
			findings.push(
				createFinding(
					'txt_hygiene',
					`${jurisdictionLabel} jurisdiction service on government domain`,
					'high',
					`${foundClause} on government domain ${domain}${countClause}. This service operates under ${jurisdictionLabel} jurisdiction and may pose data sovereignty concerns.`,
					metadata,
				),
			);
		} else {
			findings.push(
				createFinding(
					'txt_hygiene',
					`${jurisdictionLabel} jurisdiction service verification detected`,
					'medium',
					`${foundClause} for ${domain}${countClause}. This service operates under ${jurisdictionLabel} jurisdiction. Consider whether this aligns with your organization's data governance policies.`,
					metadata,
				),
			);
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
	// ONE finding per distinct stale service (#642) — the stale verdict depends only
	// on the service (its SPF domains vs the published includes), so N copies of the
	// same verification record described the SAME stale integration and deducted
	// N x 5. Multiplicity now travels in metadata; a second genuinely-stale service
	// still emits its own finding.
	const spfIncludes = extractSpfIncludes(rootTxtRecords);
	const staleServices = new Map<string, { category: VerificationCategory; records: string[] }>();
	for (const match of matchedServices) {
		const spfDomains = SERVICE_SPF_DOMAINS[match.service];
		if (!spfDomains) continue;

		const hasSpfInclude = spfDomains.some((spfDomain) => spfIncludes.some((include) => include.includes(spfDomain.toLowerCase())));
		if (hasSpfInclude) continue;

		const existing = staleServices.get(match.service);
		if (existing) {
			existing.records.push(match.record);
			consolidatedScoredFindings++;
		} else {
			staleServices.set(match.service, { category: match.category, records: [match.record] });
		}
	}

	for (const [service, { category, records }] of staleServices) {
		const recordCount = records.length;
		const foundClause =
			recordCount > 1
				? `${service} verification records found (${recordCount} such records are published)`
				: `${service} verification record found`;
		findings.push(
			createFinding(
				'txt_hygiene',
				`Possible stale service integration: ${service}`,
				'low',
				`${foundClause} but no corresponding SPF include detected. This may indicate the service is no longer actively used for email sending. Review and remove if the integration has been decommissioned.`,
				{ service, category, recordCount, records },
			),
		);
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

	// --- Info findings, ONE per distinct detected platform ---
	// A domain publishing N verification records for the same service (e.g. github.com's
	// 3x MS= and 2x google-site-verification=) previously emitted N byte-identical findings
	// ALONGSIDE the "Duplicate verification records detected" finding above — the duplicate
	// count is already reported there, so repeating the per-record note is pure noise.
	// Collapse to one finding per service and carry the record count in detail/metadata.
	// Score-neutral by construction: these are `info` (SEVERITY_PENALTIES.info === 0).
	const detectedServices = new Map<string, { category: VerificationCategory; recordCount: number }>();
	for (const match of matchedServices) {
		// Skip DMARC at root — already flagged above
		if (match.category === 'email_auth' && match.service === 'DMARC') continue;
		// Skip TrustedForDomainSharing — already flagged above
		if (match.prefix === 'TrustedForDomainSharing=') continue;

		const existing = detectedServices.get(match.service);
		if (existing) {
			existing.recordCount++;
		} else {
			detectedServices.set(match.service, { category: match.category, recordCount: 1 });
		}
	}

	for (const [service, { category, recordCount }] of detectedServices) {
		findings.push(
			createFinding(
				'txt_hygiene',
				`Service verification detected: ${service}`,
				'info',
				recordCount > 1
					? `${service} domain verification record found (${category} category). ${recordCount} such records are published.`
					: `${service} domain verification record found (${category} category).`,
				{ service, category, recordCount },
			),
		);
	}

	// --- Consolidation notice (#642) ---
	// Emitted only when consolidation actually suppressed a scored finding, so the
	// score change is auditable from the report itself rather than being silent.
	// `info` => zero penalty (SEVERITY_PENALTIES.info === 0).
	if (consolidatedScoredFindings > 0) {
		findings.push(
			createFinding(
				'txt_hygiene',
				'Duplicate TXT hygiene findings consolidated',
				'info',
				`Consolidated ${consolidatedScoredFindings} duplicate scored TXT hygiene finding(s) so a single condition published across several TXT records is penalised once. Every affected record is listed in the "records" metadata of its finding; repeated publication itself is graded separately by the duplicate-verification finding.`,
				{ consolidatedFindings: consolidatedScoredFindings },
			),
		);
	}

	// --- Hygiene summary ---
	// `serviceCount` is the DISTINCT-service count, not the matched-record count
	// (#642, cosmetic half): the old wording read "5 service verification(s)
	// detected" next to 2 service findings once the per-record info findings were
	// collapsed. The raw record tally is retained as `verificationRecordCount`.
	const rating = getHygieneRating(recordCount);
	const distinctServiceCount = new Set(matchedServices.map((m) => m.service)).size;
	const serviceClause =
		matchedServices.length > distinctServiceCount
			? `${distinctServiceCount} distinct service verification(s) detected across ${matchedServices.length} record(s).`
			: `${distinctServiceCount} service verification(s) detected.`;
	findings.push(
		createFinding(
			'txt_hygiene',
			'TXT record hygiene summary',
			'info',
			`TXT record hygiene rating: ${rating} (${recordCount} records). ${serviceClause}`,
			{ rating, recordCount, serviceCount: distinctServiceCount, verificationRecordCount: matchedServices.length },
		),
	);

	return buildCheckResult('txt_hygiene', findings);
}
