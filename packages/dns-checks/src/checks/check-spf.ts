// SPDX-License-Identifier: BUSL-1.1

/**
 * SPF (Sender Policy Framework) check.
 * Queries TXT records for SPF and validates the policy.
 * Implements recursive include expansion per RFC 7208 §4.6.4.
 *
 * Copyright (c) 2023-2026 BlackVeil Security Ltd.
 * Licensed under BSL 1.1
 */

import type { CheckResult, DNSQueryFunction, Finding } from '../types';
import { buildCheckResult, createFinding } from '../check-utils';
import { parseDmarcTags } from './dmarc-utils';
import {
	RISKY_MECHANISMS,
	checkBroadIpRanges,
	countRecursiveLookups,
	extractSpfSignalDomains,
	type RecursiveState,
} from './spf-analysis';
import { analyzeTrustSurface } from './spf-trust-surface';

/** Detect no-send SPF policy: -all or ~all with zero authorizing mechanisms */
function isNoSendPolicy(spf: string): boolean {
	const allMatch = spf.match(/[+?~-]all/i);
	if (!allMatch) return false;
	const qualifier = allMatch[0][0];
	if (qualifier !== '-' && qualifier !== '~') return false;
	const hasAuthorizing = /\b(include:|a[:/\s]|a$|mx[:/\s]|mx$|ip4:|ip6:|redirect=|exists:)/i.test(spf);
	return !hasAuthorizing;
}

interface TrustSurfaceDmarcContext {
	corroboratedByWeakDmarc: boolean;
	dmarcPolicy?: string;
	dmarcAlignmentMode?: string;
}

async function getTrustSurfaceDmarcContext(
	domain: string,
	queryDNS: DNSQueryFunction,
	timeout?: number,
): Promise<TrustSurfaceDmarcContext> {
	try {
		const dmarcRecords = await queryDNS(`_dmarc.${domain}`, 'TXT', { timeout });
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
export async function checkSPF(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number },
): Promise<CheckResult> {
	const timeout = options?.timeout ?? 5000;
	const findings: Finding[] = [];
	const txtRecords = await queryDNS(domain, 'TXT', { timeout });

	// Concatenate all TXT records to handle cases where SPF data is split across multiple records
	const concatenatedTxt = txtRecords.join('');

	// Extract SPF record from concatenated TXT data
	const spfMatch = concatenatedTxt.match(/v=spf1[^]*/i);
	const spfRecords = spfMatch ? [spfMatch[0]] : [];

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

	// Pre-fetch DMARC context once — reused by both ~all severity and trust surface analysis
	const trustSurfaceContext = await getTrustSurfaceDmarcContext(domain, queryDNS, timeout);
	const dmarcPolicyToken = trustSurfaceContext.dmarcPolicy?.split(';')[0].trim();
	const dmarcEnforcing = dmarcPolicyToken === 'reject' || dmarcPolicyToken === 'quarantine';

	// Check for multiple SPF records in the concatenated data
	const spfMatches = concatenatedTxt.match(/v=spf1/gi);
	if (spfMatches && spfMatches.length > 1) {
		findings.push(
			createFinding(
				'spf',
				'Multiple SPF records',
				'high',
				`Found ${spfMatches.length} SPF records in TXT data. RFC 7208 requires exactly one SPF record per domain. Multiple records cause unpredictable behavior.`,
			),
		);
	}

	const spf = spfRecords[0];
	const spfSignals = extractSpfSignalDomains(spf);
	const spfMetadata: Record<string, unknown> = {
		signalType: 'spf',
		includeDomains: spfSignals.includeDomains,
		...(spfSignals.redirectDomain ? { redirectDomain: spfSignals.redirectDomain } : {}),
	};

	// Detect no-send policy (e.g., v=spf1 -all with no authorizing mechanisms)
	if (isNoSendPolicy(spf)) {
		spfMetadata.noSendPolicy = true;
	}

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
			// ~all is the recommended setting when DMARC enforcement is active.
			// -all causes rejection at SMTP level before DMARC can verify DKIM.
			// See RFC 7489 §10.1, https://www.mailhardener.com/kb/spf
			if (dmarcEnforcing) {
				findings.push(
					createFinding(
						'spf',
						'SPF soft fail (~all) with DMARC enforcement',
						'info',
						`SPF record uses "~all" (soft fail) which is the recommended setting when DMARC enforcement is active. The DMARC policy ensures unauthorized mail is rejected after DKIM verification, while ~all avoids premature rejection at the SMTP level.`,
						spfMetadata,
					),
				);
			} else {
				findings.push(
					createFinding(
						'spf',
						'SPF soft fail (~all)',
						'low',
						`SPF record uses "~all" (soft fail). Consider upgrading to "-all" (hard fail) for stricter enforcement, or deploy DMARC with p=reject to handle authentication via DKIM alignment.`,
						spfMetadata,
					),
				);
			}
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
	const recursiveLookupCount = await countRecursiveLookups(spf, 0, state, queryDNS, timeout);

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
