// SPDX-License-Identifier: MIT

/**
 * SPF (Sender Policy Framework) check tool.
 * Queries TXT records for SPF and validates the policy.
 * Implements recursive include expansion per RFC 7208 §4.6.4.
 */

import { queryTxtRecords } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import type { CheckResult, Finding } from '../lib/scoring';
import { buildCheckResult, createFinding } from '../lib/scoring';
import { parseDmarcTags } from './dmarc-utils';
import {
	RISKY_MECHANISMS,
	checkBroadIpRanges,
	countRecursiveLookups,
	extractSpfSignalDomains,
	type RecursiveState,
} from './spf-analysis';
import { analyzeTrustSurface } from './spf-trust-surface';

interface TrustSurfaceDmarcContext {
	corroboratedByWeakDmarc: boolean;
	dmarcPolicy?: string;
	dmarcAlignmentMode?: string;
}

async function getTrustSurfaceDmarcContext(domain: string, dnsOptions?: QueryDnsOptions): Promise<TrustSurfaceDmarcContext> {
	try {
		const dmarcRecords = await queryTxtRecords(`_dmarc.${domain}`, dnsOptions);
		const dmarcRecord = dmarcRecords.find((record) => record.toLowerCase().startsWith('v=dmarc1'));

		if (!dmarcRecord) {
			return {
				corroboratedByWeakDmarc: true,
				dmarcPolicy: 'missing',
				dmarcAlignmentMode: 'missing',
			};
		}

		const tags = parseDmarcTags(dmarcRecord);
		const policy = tags.get('p') ?? 'none';
		const pct = tags.get('pct') ?? '100';
		const aspf = tags.get('aspf') ?? 'r';
		const adkim = tags.get('adkim') ?? 'r';
		const enforcementWeak = policy !== 'reject' || pct !== '100';
		const alignmentWeak = aspf !== 's' || adkim !== 's';
		const alignmentMode = aspf === 's' && adkim === 's' ? 'strict' : 'relaxed';

		return {
			corroboratedByWeakDmarc: enforcementWeak && alignmentWeak,
			dmarcPolicy: pct === '100' ? policy : `${policy}; pct=${pct}`,
			dmarcAlignmentMode: alignmentMode,
		};
	} catch {
		return {
			corroboratedByWeakDmarc: false,
			dmarcPolicy: 'unknown',
			dmarcAlignmentMode: 'unknown',
		};
	}
}

/**
 * Check SPF records for a domain.
 * Looks for v=spf1 TXT records and validates their configuration.
 * Recursively expands include chains to compute true DNS lookup count.
 */
export async function checkSpf(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	const findings: Finding[] = [];
	const txtRecords = await queryTxtRecords(domain, dnsOptions);

	// Filter for SPF records
	const spfRecords = txtRecords.filter((r) => r.toLowerCase().startsWith('v=spf1'));

	if (spfRecords.length === 0) {
		findings.push(
			createFinding(
				'spf',
				'No SPF record found',
				'critical',
				`No SPF (v=spf1) TXT record found for ${domain}. Without SPF, any server can send email claiming to be from your domain.`,
			),
		);
		return buildCheckResult('spf', findings);
	}

	if (spfRecords.length > 1) {
		findings.push(
			createFinding(
				'spf',
				'Multiple SPF records',
				'high',
				`Found ${spfRecords.length} SPF records. RFC 7208 requires exactly one SPF record per domain. Multiple records cause unpredictable behavior.`,
			),
		);
	}

	const spf = spfRecords[0];
	const spfSignals = extractSpfSignalDomains(spf);
	const spfMetadata = {
		signalType: 'spf',
		includeDomains: spfSignals.includeDomains,
		...(spfSignals.redirectDomain ? { redirectDomain: spfSignals.redirectDomain } : {}),
	};

	// Check for redirect= — determines whether missing 'all' is an issue
	const hasRedirect = /\bredirect=/i.test(spf);

	// Check for overly permissive +all or ?all
	const allMechanism = spf.match(/[+?~-]all/i);
	if (allMechanism) {
		const qualifier = allMechanism[0];
		if (RISKY_MECHANISMS.includes(qualifier.toLowerCase())) {
			findings.push(
				createFinding(
					'spf',
					`Permissive SPF: ${qualifier}`,
					'critical',
					`SPF record uses "${qualifier}" which allows any server to send email as ${domain}. Use "-all" (hard fail) or "~all" (soft fail) instead.`,
					spfMetadata,
				),
			);
		} else if (qualifier.toLowerCase() === '~all') {
			findings.push(
				createFinding(
					'spf',
					'SPF soft fail (~all)',
					'low',
					`SPF record uses "~all" (soft fail). Consider upgrading to "-all" (hard fail) for stricter enforcement once you've verified all legitimate senders are included.`,
					spfMetadata,
				),
			);
		}
		// -all is the recommended setting, no finding needed
	} else if (!hasRedirect) {
		// RFC 7208 §6.1: redirect= replaces the entire record, making 'all' irrelevant
		findings.push(
			createFinding(
				'spf',
				"No 'all' mechanism",
				'medium',
				`SPF record does not end with an "all" mechanism. Without it, the default behavior is neutral, which provides weak protection.`,
				spfMetadata,
			),
		);
	}

	// Check for overly broad IP ranges
	findings.push(...checkBroadIpRanges(spf, spfMetadata));

	// Recursive DNS lookup budget (RFC 7208 §4.6.4)
	const state: RecursiveState = {
		totalQueries: 0,
		visited: new Set([domain]),
		cache: new Map(),
		findings: [],
		circularDetected: false,
	};
	const recursiveLookupCount = await countRecursiveLookups(spf, 0, state, dnsOptions);

	// Add any circular-include findings from recursive expansion
	findings.push(...state.findings);

	if (recursiveLookupCount > 10) {
		findings.push(
			createFinding(
				'spf',
				'Too many DNS lookups',
				'critical',
				`SPF record requires ${recursiveLookupCount} DNS lookups (limit: 10). Receivers may return PermError and reject legitimate mail.`,
				{ ...spfMetadata, lookupCount: recursiveLookupCount },
			),
		);
	} else if (recursiveLookupCount >= 9) {
		findings.push(
			createFinding(
				'spf',
				'SPF lookup budget near limit',
				'high',
				`SPF record requires ${recursiveLookupCount}/10 DNS lookups. Any future sender additions may push this domain into permanent SPF failures.`,
				{ ...spfMetadata, lookupCount: recursiveLookupCount },
			),
		);
	}

	// Check for deprecated ptr mechanism
	if (/\bptr\b/i.test(spf)) {
		findings.push(
			createFinding(
				'spf',
				'Deprecated ptr mechanism',
				'medium',
				`SPF record uses the "ptr" mechanism which is deprecated in RFC 7208 due to performance and reliability issues.`,
				spfMetadata,
			),
		);
	}

	// Trust surface analysis — flag multi-tenant SaaS platform includes
	const trustSurfaceContext = await getTrustSurfaceDmarcContext(domain, dnsOptions);
	const trustSurfaceFindings = analyzeTrustSurface(spf, trustSurfaceContext);
	findings.push(...trustSurfaceFindings);

	// Informational trust-surface findings should not suppress the clean SPF status.
	const issueFindings = findings.filter((f) => !(f.metadata?.trustSurface && f.severity === 'info'));
	if (issueFindings.length === 0) {
		findings.push(
			createFinding(
				'spf',
				'SPF record configured',
				'info',
				`SPF record found and properly configured: ${spf.substring(0, 100)}${spf.length > 100 ? '...' : ''}`,
				spfMetadata,
			),
		);
	}

	return buildCheckResult('spf', findings);
}
